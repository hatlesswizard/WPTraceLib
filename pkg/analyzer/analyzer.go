package analyzer

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"github.com/hatlesswizard/wptracelib/pkg/config"
	"github.com/hatlesswizard/wptracelib/pkg/models"
	"golang.org/x/sync/errgroup"

	wpast "github.com/hatlesswizard/wptracelib/pkg/ast"
)

// fileBufferPool is a sync.Pool for reusing file read buffers
// This significantly reduces memory allocations when reading many PHP files
var fileBufferPool = sync.Pool{
	New: func() interface{} {
		// Start with 64KB buffer - will grow if needed
		buf := make([]byte, 64*1024)
		return &buf
	},
}

const (
	defaultWorkers = 10
)

// ChainMode specifies how call chain analysis should be performed
type ChainMode int

const (
	// ChainModeNone skips call chain analysis entirely (default, fastest)
	ChainModeNone ChainMode = iota
	// ChainModeFlat builds flat call lists (legacy behavior, used internally)
	ChainModeFlat
	// ChainModeHierarchical builds hierarchical call trees for human/JSON output
	ChainModeHierarchical
)

// Analyzer performs static analysis on WordPress plugins
type Analyzer struct {
	workers   int
	config    *config.Config
	chainMode ChainMode
}

// Option is a functional option for configuring the Analyzer
type Option func(*Analyzer)

// WithWorkers sets the number of concurrent workers
func WithWorkers(n int) Option {
	return func(a *Analyzer) {
		if n > 0 {
			a.workers = n
		}
	}
}

// WithConfig sets the analyzer configuration.
// If not provided, a default configuration is used.
func WithConfig(cfg *config.Config) Option {
	return func(a *Analyzer) {
		if cfg != nil {
			a.config = cfg
			// Propagate configuration to the auth subsystem
			SetAuthConfig(cfg)
		}
	}
}

// WithMinimalConfig sets a minimal configuration with only WordPress core patterns.
// This uses generic detection without any custom profiles.
func WithMinimalConfig() Option {
	return func(a *Analyzer) {
		cfg := config.NewMinimal()
		a.config = cfg
		SetAuthConfig(cfg)
	}
}

// WithChainMode sets the call chain analysis mode.
// ChainModeNone: Skip call chain analysis (default, fastest)
// ChainModeFlat: Build flat call lists (legacy)
// ChainModeHierarchical: Build hierarchical call trees
func WithChainMode(mode ChainMode) Option {
	return func(a *Analyzer) {
		a.chainMode = mode
	}
}

// New creates a new Analyzer instance
func New(opts ...Option) *Analyzer {
	a := &Analyzer{
		workers: defaultWorkers,
		config:  nil, // Will use default config from auth.go init()
	}

	for _, opt := range opts {
		opt(a)
	}

	// If no config was explicitly set, ensure we're using the default
	if a.config == nil {
		a.config = config.New()
		SetAuthConfig(a.config)
	}

	return a
}

// Config returns the current configuration
func (a *Analyzer) Config() *config.Config {
	return a.config
}

// SetConfig updates the analyzer configuration
func (a *Analyzer) SetConfig(cfg *config.Config) {
	if cfg != nil {
		a.config = cfg
		SetAuthConfig(cfg)
	}
}

// ChainMode returns the current chain analysis mode
func (a *Analyzer) ChainMode() ChainMode {
	return a.chainMode
}

// AnalyzePlugin analyzes a single plugin directory for endpoints
func (a *Analyzer) AnalyzePlugin(ctx context.Context, pluginDir string) (*models.PluginAnalysis, error) {
	// Extract plugin slug from directory name
	pluginSlug := filepath.Base(pluginDir)

	analysis := &models.PluginAnalysis{
		PluginSlug: pluginSlug,
		Endpoints:  make([]models.Endpoint, 0),
		Errors:     make([]string, 0),
	}

	// Find all PHP files
	phpFiles, err := a.findPHPFiles(pluginDir)
	if err != nil {
		return nil, fmt.Errorf("failed to find PHP files: %w", err)
	}

	analysis.FilesCount = len(phpFiles)

	// PASS 1: Discover hook wrapper functions/methods in this plugin
	// This scans all files to find methods that wrap add_action() calls
	wrapperRegistry := BuildPluginWrapperRegistry(pluginDir)

	// PASS 2: Build plugin-wide call graph for recursive function analysis
	// This reads all PHP files, strips comments ONCE, and builds an index
	// MEMORY OPTIMIZATION: Cache stripped content to avoid re-stripping in Pass 3
	// NOTE: We always build the stripped content cache even if call graph is skipped,
	// to avoid race conditions in Pass 3 where multiple goroutines might try to
	// read/write the cache concurrently.
	strippedContentCache := make(map[string]string, len(phpFiles))
	var pluginCallGraph *PluginCallGraph
	if a.chainMode != ChainModeNone {
		// Build call graph AND populate cache
		pluginCallGraph = a.buildPluginCallGraphWithCache(phpFiles, strippedContentCache)
	} else {
		// Just populate the cache without building call graph (faster)
		a.populateStrippedContentCache(phpFiles, strippedContentCache)
	}

	// PASS 2.5: Tree-sitter AST analysis for cross-file resolution
	astCtx := a.buildASTContext(pluginDir)

	// PASS 3: Analyze files concurrently using standard patterns + discovered wrappers
	// MEMORY OPTIMIZATION: Reuse stripped content from Pass 2 cache
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(a.workers)

	// We'll store content for enrichment - reusing the cache from Pass 2
	var fileContentsMu sync.Mutex

	for _, file := range phpFiles {
		file := file // capture for goroutine
		g.Go(func() error {
			endpoints, errs, content := a.analyzeFileWithCache(ctx, file, pluginSlug, pluginDir, wrapperRegistry, strippedContentCache, astCtx)

			mu.Lock()
			analysis.Endpoints = append(analysis.Endpoints, endpoints...)
			analysis.Errors = append(analysis.Errors, errs...)
			mu.Unlock()

			// Store content for enrichment if we found endpoints and it wasn't already cached
			if len(endpoints) > 0 && content != "" {
				fileContentsMu.Lock()
				if _, exists := strippedContentCache[file]; !exists {
					strippedContentCache[file] = content
				}
				fileContentsMu.Unlock()
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// PASS 3.4: Detect direct PHP file access endpoints (files accessible via URL without WP bootstrap)
	directEndpoints := DetectDirectPHPEndpointsWithAST(pluginDir, pluginSlug, astCtx)
	analysis.Endpoints = append(analysis.Endpoints, directEndpoints...)

	// PASS 3.5: Resolve dynamic action names via foreach-based cross-file data flow.
	// Endpoints whose route contains {placeholder} are either expanded into concrete
	// endpoints (when the foreach source can be traced) or annotated as
	// [dynamic:unresolved:…] so they are never silently dropped.
	if len(analysis.Endpoints) > 0 {
		analysis.Endpoints = resolveUnresolvedEndpoints(analysis.Endpoints, strippedContentCache, pluginDir)
	}

	// DETERMINISM: Sort endpoints before deduplication so that goroutine
	// scheduling order doesn't affect which endpoint wins during dedup.
	// Sort by Route + Method + Type + SourceFile + Callback for stable ordering.
	sort.Slice(analysis.Endpoints, func(i, j int) bool {
		a, b := analysis.Endpoints[i], analysis.Endpoints[j]
		if a.Route != b.Route {
			return a.Route < b.Route
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Callback < b.Callback
	})

	// Deduplicate endpoints (same route, method, type within a plugin)
	analysis.Endpoints = deduplicateEndpoints(analysis.Endpoints)

	// PASS 4: Enrich endpoints with call graph analysis
	// CONDITIONAL: Only enrich if chain analysis is enabled
	// This uses the plugin-wide function index to follow calls across all files
	// MEMORY OPTIMIZATION: Reuse strippedContentCache instead of separate fileContents
	if a.chainMode != ChainModeNone && pluginCallGraph != nil && len(analysis.Endpoints) > 0 {
		if a.chainMode == ChainModeHierarchical {
			// Build hierarchical call trees for -chain-human or -chain-json output
			a.enrichEndpointsWithHierarchicalCallGraph(analysis.Endpoints, pluginCallGraph, strippedContentCache, pluginDir)
		} else {
			// Build flat call lists (legacy behavior)
			a.enrichEndpointsRecursively(analysis.Endpoints, pluginCallGraph, strippedContentCache, pluginDir)
		}
	}

	// Memory optimization: Clear cache - no longer needed after enrichment
	// This allows GC to reclaim memory earlier
	for k := range strippedContentCache {
		delete(strippedContentCache, k)
	}
	strippedContentCache = nil

	// Memory optimization: Clear pluginCallGraph - no longer needed after enrichment
	pluginCallGraph = nil

	// Try to extract plugin name and version from main plugin file
	a.extractPluginMetadata(pluginDir, analysis)

	return analysis, nil
}

// buildASTContext runs the full 7-layer AST pipeline for cross-file resolution.
// Returns an ASTContext with Available=false if parsing fails or plugin has no PHP files.
func (a *Analyzer) buildASTContext(pluginDir string) *wpast.ASTContext {
	pluginAST, err := wpast.ParsePlugin(pluginDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ast: plugin parse failed for %s: %v\n", pluginDir, err)
		return &wpast.ASTContext{Available: false}
	}
	if len(pluginAST.Files) == 0 {
		return &wpast.ASTContext{Available: false}
	}

	st := wpast.BuildSymbolTable(pluginAST)
	h := wpast.BuildClassHierarchy(st)
	df := wpast.NewDataFlowAnalyzer(st, h)
	cg := wpast.BuildCallGraph(st, pluginAST)
	ta := wpast.NewTaintAnalyzer(st, h, cg, pluginAST)
	aa := wpast.NewAuthAnalyzer(st, h, pluginAST)
	resolver := wpast.NewResolver(st, h, df, ta, aa)

	return &wpast.ASTContext{
		Resolver:  resolver,
		Available: true,
	}
}

// buildPluginCallGraph builds a plugin-wide function index from all PHP files
func (a *Analyzer) buildPluginCallGraph(phpFiles []string) *PluginCallGraph {
	files := make(map[string]string)

	for _, filepath := range phpFiles {
		content, err := a.readFileContent(filepath)
		if err != nil {
			continue
		}
		// Strip comments for cleaner parsing
		files[filepath] = StripPHPComments(content)
	}

	if len(files) == 0 {
		return nil
	}

	return BuildPluginCallGraphFromFiles(files)
}

// buildPluginCallGraphWithCache builds call graph and caches stripped content for reuse
// MEMORY OPTIMIZATION: Strips comments once and stores result for Pass 3
func (a *Analyzer) buildPluginCallGraphWithCache(phpFiles []string, cache map[string]string) *PluginCallGraph {
	files := make(map[string]string, len(phpFiles))

	for _, filepath := range phpFiles {
		content, err := a.readFileContent(filepath)
		if err != nil {
			continue
		}
		// Strip comments ONCE and cache for reuse
		stripped := StripPHPComments(content)
		files[filepath] = stripped
		cache[filepath] = stripped // Store in cache for Pass 3
	}

	if len(files) == 0 {
		return nil
	}

	return BuildPluginCallGraphFromFiles(files)
}

// populateStrippedContentCache populates the cache with stripped content without building call graph
// This is used when chain mode is disabled but we still want to avoid re-stripping in Pass 3
func (a *Analyzer) populateStrippedContentCache(phpFiles []string, cache map[string]string) {
	for _, filepath := range phpFiles {
		content, err := a.readFileContent(filepath)
		if err != nil {
			continue
		}
		// Strip comments and store in cache
		cache[filepath] = StripPHPComments(content)
	}
}

// analyzeFileWithCache analyzes a file using cached stripped content when available
// MEMORY OPTIMIZATION: Avoids re-stripping comments if content was cached in Pass 2
func (a *Analyzer) analyzeFileWithCache(ctx context.Context, filepath string, pluginSlug string, pluginDir string, wrapperRegistry *WrapperRegistry, cache map[string]string, astCtx *wpast.ASTContext) ([]models.Endpoint, []string, string) {
	// Pre-allocate with estimated capacity to reduce slice growth allocations
	endpoints := make([]models.Endpoint, 0, 16)
	errors := make([]string, 0, 2)

	// Check if we have cached stripped content from Pass 2
	strippedContent, hasCached := cache[filepath]

	if !hasCached {
		// Need to read and strip the file
		file, err := os.Open(filepath)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to open %s: %v", filepath, err))
			return endpoints, errors, ""
		}

		stat, err := file.Stat()
		if err != nil {
			file.Close()
			errors = append(errors, fmt.Sprintf("failed to stat %s: %v", filepath, err))
			return endpoints, errors, ""
		}
		fileSize := int(stat.Size())

		// Get buffer from pool
		bufPtr := fileBufferPool.Get().(*[]byte)
		buf := *bufPtr

		if cap(buf) < fileSize {
			buf = make([]byte, fileSize)
		} else {
			buf = buf[:fileSize]
		}

		n, err := io.ReadFull(file, buf)
		file.Close()
		if err != nil && err != io.ErrUnexpectedEOF {
			*bufPtr = buf
			fileBufferPool.Put(bufPtr)
			errors = append(errors, fmt.Sprintf("failed to read %s: %v", filepath, err))
			return endpoints, errors, ""
		}
		buf = buf[:n]

		// Use unsafe string conversion
		contentStr := unsafe.String(unsafe.SliceData(buf), len(buf))

		// Strip comments and create our own copy
		strippedContent = StripPHPComments(contentStr)

		// Return buffer to pool
		*bufPtr = buf
		fileBufferPool.Put(bufPtr)
	}

	// Make filepath relative to plugin directory for cleaner output
	relPath, err := makeRelativePath(filepath, pluginDir)
	if err != nil {
		relPath = filepath
	}

	// Detect REST endpoints (use stripped content for better matching)
	restEndpoints := DetectRESTEndpointsWithAST(strippedContent, relPath, pluginSlug, astCtx)
	endpoints = append(endpoints, restEndpoints...)

	// Detect AJAX endpoints (use stripped content for better matching)
	ajaxEndpoints := DetectAJAXEndpointsWithAST(strippedContent, relPath, pluginSlug, astCtx)
	endpoints = append(endpoints, ajaxEndpoints...)

	// Detect direct AJAX handlers (use stripped content for better matching)
	directAjaxEndpoints := DetectDirectAJAXHandlers(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, directAjaxEndpoints...)

	// Detect foreach loop AJAX handlers (common pattern in WooCommerce and similar plugins)
	foreachAjaxEndpoints := DetectForeachLoopAJAXHandlers(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, foreachAjaxEndpoints...)

	// Detect admin pages (use stripped content for better matching)
	adminEndpoints := DetectAdminPages(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, adminEndpoints...)

	// Detect shortcode endpoints (form handlers, POST/GET processing)
	shortcodeEndpoints := DetectShortcodes(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, shortcodeEndpoints...)

	// Detect widget endpoints (WP_Widget classes)
	widgetEndpoints := DetectWidgets(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, widgetEndpoints...)

	// Detect Gutenberg block endpoints
	blockEndpoints := DetectBlocks(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, blockEndpoints...)

	// Detect hook input endpoints (direct POST/GET in hooks)
	hookInputEndpoints := DetectHookInputEndpointsWithAST(strippedContent, relPath, pluginSlug, astCtx)
	endpoints = append(endpoints, hookInputEndpoints...)

	// Detect framework-specific endpoints (use stripped content for better matching)
	frameworkEndpoints := DetectFrameworkEndpoints(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, frameworkEndpoints...)

	// Detect endpoints via dynamically discovered wrappers (two-pass detection)
	if wrapperRegistry != nil && len(wrapperRegistry.Wrappers) > 0 {
		wrapperEndpoints := DetectWrapperCalls(strippedContent, relPath, pluginSlug, wrapperRegistry)
		endpoints = append(endpoints, wrapperEndpoints...)
	}

	return endpoints, errors, strippedContent
}

// readFileContent reads a file's content using the buffer pool
func (a *Analyzer) readFileContent(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return "", err
	}
	fileSize := int(stat.Size())

	// Get buffer from pool
	bufPtr := fileBufferPool.Get().(*[]byte)
	buf := *bufPtr

	// Ensure buffer is large enough
	if cap(buf) < fileSize {
		buf = make([]byte, fileSize)
	} else {
		buf = buf[:fileSize]
	}

	// Read file into buffer
	n, err := io.ReadFull(file, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		*bufPtr = buf
		fileBufferPool.Put(bufPtr)
		return "", err
	}
	buf = buf[:n]

	// Make a copy of the content before returning buffer to pool
	content := string(buf)

	// Return buffer to pool
	*bufPtr = buf
	fileBufferPool.Put(bufPtr)

	return content, nil
}

// enrichEndpointsRecursively enriches all endpoints with recursive call graph analysis (flat list)
func (a *Analyzer) enrichEndpointsRecursively(endpoints []models.Endpoint, callGraph *PluginCallGraph, fileContents map[string]string, pluginDir string) {
	for i := range endpoints {
		if endpoints[i].Callback == "" {
			continue
		}

		// Get the file content for this endpoint
		fullPath := filepath.Join(pluginDir, endpoints[i].File)
		content, ok := fileContents[fullPath]
		if !ok {
			// Try to read the file
			var err error
			content, err = a.readFileContent(fullPath)
			if err != nil {
				continue
			}
			content = StripPHPComments(content)
		}

		// Get recursive calls using the plugin-wide call graph
		calls := GetRecursiveCallsForCallback(callGraph, endpoints[i].Callback, content)
		if len(calls) > 0 {
			endpoints[i].FunctionCalls = calls
		}
	}
}

// enrichEndpointsWithHierarchicalCallGraph enriches endpoints with hierarchical call trees
// This is used when -chain-human or -chain-json flags are specified
func (a *Analyzer) enrichEndpointsWithHierarchicalCallGraph(endpoints []models.Endpoint, callGraph *PluginCallGraph, fileContents map[string]string, pluginDir string) {
	// Memoization cache: avoid rebuilding identical trees for endpoints sharing the same callback
	chainCache := make(map[string][]*models.CallChainNode)

	for i := range endpoints {
		if endpoints[i].Callback == "" {
			continue
		}

		// Check memoization cache first
		cacheKey := endpoints[i].Callback
		if cached, ok := chainCache[cacheKey]; ok {
			if len(cached) > 0 {
				endpoints[i].CallChain = cached
			}
			continue
		}

		// Get the file content for this endpoint
		fullPath := filepath.Join(pluginDir, endpoints[i].File)
		content, ok := fileContents[fullPath]
		if !ok {
			// Try to read the file
			var err error
			content, err = a.readFileContent(fullPath)
			if err != nil {
				chainCache[cacheKey] = nil
				continue
			}
			content = StripPHPComments(content)
		}

		// Get hierarchical call chain using the plugin-wide call graph.
		// Per-path visited + maxNodes cap in buildCallTree bounds tree size.
		chain := GetHierarchicalCallsForCallback(callGraph, endpoints[i].Callback, content)
		chainCache[cacheKey] = chain
		if len(chain) > 0 {
			endpoints[i].CallChain = chain
		}
	}
}

// deduplicateEndpoints removes duplicate endpoints based on (route, method, type)
// When duplicates exist, prefer the one with:
// 1. Higher auth level (more restrictive = more accurate detection)
// 2. More complete callback information (non-"inline", non-"unknown")
func deduplicateEndpoints(endpoints []models.Endpoint) []models.Endpoint {
	seen := make(map[string]int) // key -> index in result
	result := make([]models.Endpoint, 0, len(endpoints))

	for _, ep := range endpoints {
		// Create a unique key based on route, method, and type
		key := ep.Route + "|" + ep.Method + "|" + string(ep.Type)
		if existingIdx, exists := seen[key]; !exists {
			seen[key] = len(result)
			result = append(result, ep)
		} else {
			// Compare and keep the better detection
			existing := result[existingIdx]

			// Prefer higher auth level (more restrictive = more accurate)
			// But don't downgrade from Unauthenticated if that's explicitly detected
			shouldReplace := false
			if ep.AuthLevel > existing.AuthLevel && existing.AuthLevel != models.Unauthenticated {
				shouldReplace = true
			}

			// Prefer more informative callbacks over generic ones
			genericCallbacks := map[string]bool{
				"inline": true, "unknown": true, "closure": true,
				"anonymous": true, "anonymous_function": true,
			}
			if !shouldReplace && genericCallbacks[existing.Callback] && !genericCallbacks[ep.Callback] {
				shouldReplace = true
			}

			if shouldReplace {
				result[existingIdx] = ep
			}
		}
	}

	return result
}

// AnalyzeAll analyzes all plugins in a directory
func (a *Analyzer) AnalyzeAll(ctx context.Context, pluginsDir string) ([]models.PluginAnalysis, error) {
	// List all subdirectories (each is a plugin)
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugins directory: %w", err)
	}

	// Count directories for pre-allocation (Issue 5 fix)
	dirCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			dirCount++
		}
	}

	var mu sync.Mutex
	analyses := make([]models.PluginAnalysis, 0, dirCount)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(a.workers)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pluginDir := filepath.Join(pluginsDir, entry.Name())
		g.Go(func() error {
			analysis, err := a.AnalyzePlugin(ctx, pluginDir)
			if err != nil {
				// Don't fail the entire operation for one plugin
				mu.Lock()
				analyses = append(analyses, models.PluginAnalysis{
					PluginSlug: entry.Name(),
					Errors:     []string{err.Error()},
				})
				mu.Unlock()
				return nil
			}

			mu.Lock()
			analyses = append(analyses, *analysis)
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return analyses, nil
}

// findPHPFiles finds all PHP files in a directory recursively.
// It skips vendor/third-party directories based on the analyzer's config.
func (a *Analyzer) findPHPFiles(dir string) ([]string, error) {
	var files []string

	// Build skip set from config for O(1) lookups
	vendorCfg := a.config.VendorDirs
	if vendorCfg == nil {
		vendorCfg = config.DefaultVendorDirConfig()
	}
	skipSet := make(map[string]struct{}, len(vendorCfg.SkipPatterns))
	for _, p := range vendorCfg.SkipPatterns {
		skipSet[p] = struct{}{}
	}

	// Resolve the root directory for the composer.json heuristic
	// so we don't skip the plugin's own root
	absRoot, _ := filepath.Abs(dir)

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip directories we can't access
		}

		if d.IsDir() {
			name := d.Name()

			// Check against skip patterns
			if _, skip := skipSet[name]; skip {
				return filepath.SkipDir
			}

			// Heuristic: skip subdirectories that contain their own composer.json
			// (embedded vendor packages), but not the plugin root itself
			if vendorCfg.SkipComposerDirs {
				absPath, _ := filepath.Abs(path)
				if absPath != absRoot {
					composerPath := filepath.Join(path, "composer.json")
					if _, err := os.Stat(composerPath); err == nil {
						return filepath.SkipDir
					}
				}
			}

			return nil
		}

		// Only process PHP files
		if strings.HasSuffix(strings.ToLower(path), ".php") {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}

// analyzeFile analyzes a single PHP file for endpoints (legacy interface)
func (a *Analyzer) analyzeFile(ctx context.Context, filepath string, pluginSlug string, pluginDir string, wrapperRegistry *WrapperRegistry) ([]models.Endpoint, []string) {
	endpoints, errors, _ := a.analyzeFileWithContent(ctx, filepath, pluginSlug, pluginDir, wrapperRegistry)
	return endpoints, errors
}

// analyzeFileWithContent analyzes a single PHP file for endpoints and returns the content
func (a *Analyzer) analyzeFileWithContent(ctx context.Context, filepath string, pluginSlug string, pluginDir string, wrapperRegistry *WrapperRegistry) ([]models.Endpoint, []string, string) {
	// Pre-allocate with estimated capacity to reduce slice growth allocations
	endpoints := make([]models.Endpoint, 0, 16)
	errors := make([]string, 0, 2)

	// Open file to get size and read with pooled buffer
	file, err := os.Open(filepath)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to open %s: %v", filepath, err))
		return endpoints, errors, ""
	}

	// Get file size for buffer sizing
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		errors = append(errors, fmt.Sprintf("failed to stat %s: %v", filepath, err))
		return endpoints, errors, ""
	}
	fileSize := int(stat.Size())

	// Get buffer from pool
	bufPtr := fileBufferPool.Get().(*[]byte)
	buf := *bufPtr

	// Ensure buffer is large enough
	if cap(buf) < fileSize {
		// Need a larger buffer - allocate new one
		buf = make([]byte, fileSize)
	} else {
		// Resize to exact file size
		buf = buf[:fileSize]
	}

	// Read file into buffer
	n, err := io.ReadFull(file, buf)
	file.Close()
	if err != nil && err != io.ErrUnexpectedEOF {
		// Return buffer to pool before returning
		*bufPtr = buf
		fileBufferPool.Put(bufPtr)
		errors = append(errors, fmt.Sprintf("failed to read %s: %v", filepath, err))
		return endpoints, errors, ""
	}
	buf = buf[:n]

	// Use unsafe string conversion to avoid memory copy (Issue 4 fix)
	// This is safe because we will copy the content before returning buffer to pool
	contentStr := unsafe.String(unsafe.SliceData(buf), len(buf))

	// Create a comment-stripped version for pattern matching
	// IMPORTANT: StripPHPComments creates a COPY of the content, so after this
	// call we can safely return the buffer to the pool
	strippedContent := StripPHPComments(contentStr)

	// Return buffer to pool NOW - strippedContent has its own copy
	*bufPtr = buf
	fileBufferPool.Put(bufPtr)

	// Make filepath relative to plugin directory for cleaner output
	relPath, err := makeRelativePath(filepath, pluginDir)
	if err != nil {
		relPath = filepath
	}

	// Detect REST endpoints (use stripped content for better matching)
	restEndpoints := DetectRESTEndpointsWithAST(strippedContent, relPath, pluginSlug, nil)
	endpoints = append(endpoints, restEndpoints...)

	// Detect AJAX endpoints (use stripped content for better matching)
	ajaxEndpoints := DetectAJAXEndpointsWithAST(strippedContent, relPath, pluginSlug, nil)
	endpoints = append(endpoints, ajaxEndpoints...)

	// Detect direct AJAX handlers (use stripped content for better matching)
	directAjaxEndpoints := DetectDirectAJAXHandlers(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, directAjaxEndpoints...)

	// Detect foreach loop AJAX handlers (common pattern in WooCommerce and similar plugins)
	foreachAjaxEndpoints := DetectForeachLoopAJAXHandlers(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, foreachAjaxEndpoints...)

	// Detect admin pages (use stripped content for better matching)
	adminEndpoints := DetectAdminPages(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, adminEndpoints...)

	// Detect shortcode endpoints (form handlers, POST/GET processing)
	shortcodeEndpoints := DetectShortcodes(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, shortcodeEndpoints...)

	// Detect widget endpoints (WP_Widget classes)
	widgetEndpoints := DetectWidgets(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, widgetEndpoints...)

	// Detect Gutenberg block endpoints
	blockEndpoints := DetectBlocks(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, blockEndpoints...)

	// Detect hook input endpoints (direct POST/GET in hooks)
	hookInputEndpoints := DetectHookInputEndpointsWithAST(strippedContent, relPath, pluginSlug, nil)
	endpoints = append(endpoints, hookInputEndpoints...)

	// Detect framework-specific endpoints (use stripped content for better matching)
	frameworkEndpoints := DetectFrameworkEndpoints(strippedContent, relPath, pluginSlug)
	endpoints = append(endpoints, frameworkEndpoints...)

	// Detect endpoints via dynamically discovered wrappers (two-pass detection)
	if wrapperRegistry != nil && len(wrapperRegistry.Wrappers) > 0 {
		wrapperEndpoints := DetectWrapperCalls(strippedContent, relPath, pluginSlug, wrapperRegistry)
		endpoints = append(endpoints, wrapperEndpoints...)
	}

	// NOTE: Call graph enrichment is now done at the plugin level in AnalyzePlugin
	// using the plugin-wide function index for recursive cross-file analysis

	return endpoints, errors, strippedContent
}

// extractPluginMetadata extracts name and version from the main plugin file
func (a *Analyzer) extractPluginMetadata(pluginDir string, analysis *models.PluginAnalysis) {
	// Try to find the main plugin file
	pluginSlug := filepath.Base(pluginDir)
	mainFile := filepath.Join(pluginDir, pluginSlug+".php")

	// If not found, try to find any PHP file with plugin headers
	if _, err := os.Stat(mainFile); os.IsNotExist(err) {
		entries, err := os.ReadDir(pluginDir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".php") {
				mainFile = filepath.Join(pluginDir, entry.Name())
				break
			}
		}
	}

	// Open file to read with pooled buffer
	file, err := os.Open(mainFile)
	if err != nil {
		return
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return
	}
	fileSize := int(stat.Size())

	// Get buffer from pool
	bufPtr := fileBufferPool.Get().(*[]byte)
	buf := *bufPtr

	// Ensure buffer is large enough
	if cap(buf) < fileSize {
		buf = make([]byte, fileSize)
	} else {
		buf = buf[:fileSize]
	}

	// Read file into buffer
	n, err := io.ReadFull(file, buf)
	file.Close()
	if err != nil && err != io.ErrUnexpectedEOF {
		*bufPtr = buf
		fileBufferPool.Put(bufPtr)
		return
	}
	buf = buf[:n]

	// Use unsafe string conversion
	contentStr := unsafe.String(unsafe.SliceData(buf), len(buf))

	// Extract plugin name - clone the result to ensure it doesn't share backing array
	if name := extractHeaderValue(contentStr, "Plugin Name"); name != "" {
		analysis.PluginName = string([]byte(name)) // Clone to independent string
	}

	// Extract version - clone the result
	if version := extractHeaderValue(contentStr, "Version"); version != "" {
		analysis.Version = string([]byte(version)) // Clone to independent string
	}

	// Return buffer to pool
	*bufPtr = buf
	fileBufferPool.Put(bufPtr)
}

// extractHeaderValue extracts a header value from plugin file content
// Uses line-by-line iteration to avoid creating a slice of all lines (Issue 13 fix)
func extractHeaderValue(content, header string) string {
	// WordPress plugin headers are in format: * Header Name: Value
	headerPrefix := header + ":"
	remaining := content

	for len(remaining) > 0 {
		// Find the next newline
		idx := strings.Index(remaining, "\n")
		var line string
		if idx >= 0 {
			line = remaining[:idx]
			remaining = remaining[idx+1:]
		} else {
			line = remaining
			remaining = ""
		}

		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") || strings.HasPrefix(line, "//") {
			line = strings.TrimPrefix(line, "*")
			line = strings.TrimPrefix(line, "//")
			line = strings.TrimSpace(line)

			if strings.HasPrefix(line, headerPrefix) {
				value := strings.TrimPrefix(line, headerPrefix)
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

// makeRelativePath makes a path relative to a base directory
func makeRelativePath(path, basePath string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return "", err
	}
	return filepath.Rel(absBase, absPath)
}

// StripPHPComments removes PHP comments while preserving line structure
// This is important for pattern matching where comments might interfere
// Line numbers are preserved by replacing comment content with spaces
func StripPHPComments(content string) string {
	result := []byte(content)

	// State tracking
	i := 0
	for i < len(result) {
		// Check for multi-line comment start /*
		if i+1 < len(result) && result[i] == '/' && result[i+1] == '*' {
			start := i
			i += 2
			// Find closing */
			for i+1 < len(result) {
				if result[i] == '*' && result[i+1] == '/' {
					// Replace comment with spaces, keeping newlines
					for j := start; j < i+2; j++ {
						if result[j] != '\n' {
							result[j] = ' '
						}
					}
					i += 2
					break
				}
				i++
			}
			continue
		}

		// Check for single-line comment //
		if i+1 < len(result) && result[i] == '/' && result[i+1] == '/' {
			start := i
			i += 2
			// Find end of line
			for i < len(result) && result[i] != '\n' {
				i++
			}
			// Replace comment with spaces
			for j := start; j < i; j++ {
				result[j] = ' '
			}
			continue
		}

		// Check for hash comment #
		if result[i] == '#' {
			start := i
			i++
			// Find end of line
			for i < len(result) && result[i] != '\n' {
				i++
			}
			// Replace comment with spaces
			for j := start; j < i; j++ {
				result[j] = ' '
			}
			continue
		}

		// Skip strings to avoid removing // or /* inside strings
		if result[i] == '"' || result[i] == '\'' {
			quote := result[i]
			i++
			for i < len(result) && result[i] != quote {
				if result[i] == '\\' && i+1 < len(result) {
					i += 2
					continue
				}
				i++
			}
			if i < len(result) {
				i++
			}
			continue
		}

		i++
	}

	return string(result)
}

// CollectAllEndpoints collects all endpoints from multiple analyses
func CollectAllEndpoints(analyses []models.PluginAnalysis) []models.Endpoint {
	// Pre-calculate total capacity to avoid reallocations (Issue 5 fix)
	totalEndpoints := 0
	for _, analysis := range analyses {
		totalEndpoints += len(analysis.Endpoints)
	}

	endpoints := make([]models.Endpoint, 0, totalEndpoints)
	for _, analysis := range analyses {
		endpoints = append(endpoints, analysis.Endpoints...)
	}
	return endpoints
}

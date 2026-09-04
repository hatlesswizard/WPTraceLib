package analyzer

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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

	// PASS 3.44: A register_rest_route written in a base class is one live
	// registration per concrete subclass, and only the base's copy was emitted.
	if len(analysis.Endpoints) > 0 {
		analysis.Endpoints = append(analysis.Endpoints,
			expandInheritedRESTEndpoints(analysis.Endpoints, astCtx, strippedContentCache, pluginDir)...)
	}

	// PASS 3.45: Entry points driven by code outside the tree.
	//
	// This one is plugin-wide rather than per-file, because deciding that
	// nothing calls a method means asking every file, and deciding that a class
	// is completed from outside means following its parents across files.
	frameworkEndpoints := DetectFrameworkEntryPoints(
		relativeContentIndex(strippedContentCache, pluginDir), pluginSlug)
	analysis.Endpoints = append(analysis.Endpoints, frameworkEndpoints...)

	// PASS 3.5: Resolve dynamic action names via foreach-based cross-file data flow.
	// Endpoints whose route contains {placeholder} are either expanded into concrete
	// endpoints (when the foreach source can be traced) or annotated as
	// [dynamic:unresolved:…] so they are never silently dropped.
	if len(analysis.Endpoints) > 0 {
		analysis.Endpoints = resolveUnresolvedEndpoints(analysis.Endpoints, strippedContentCache, pluginDir)
	}

	// DETERMINISM: Sort endpoints before merging so that goroutine scheduling
	// order does not affect which registration represents a merged group.
	//
	// Line and AuthLevel belong in the ordering, and their absence mattered.
	// The old key stopped at Callback and sort.Slice is not stable, so two
	// registrations agreeing on route, method, type, file and callback -- about
	// 98% of the twins in a 143-plugin corpus -- were ordered arbitrarily. That
	// was harmless for every field except the one that decides the answer.
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
		if a.Callback != b.Callback {
			return a.Callback < b.Callback
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.AuthLevel < b.AuthLevel
	})

	// Merge registrations that describe the same dispatch target
	analysis.Endpoints = mergeEndpoints(analysis.Endpoints)

	// PASS 3.7: REST Coverage Audit
	// Compare detected REST endpoints against register_rest_route() calls in source
	coverageReport := AuditRESTCoverage(pluginDir, analysis.Endpoints, strippedContentCache)
	if coverageReport != nil {
		analysis.CoverageReport = coverageReport
	}

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

// restRoutePlaceholderPattern matches the {property} markers cleanRouteString
// leaves behind when a route is built from $this->rest_base or $this->namespace.
var restRoutePlaceholderPattern = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// restThisCallbackPattern matches the array( $this, 'method' ) callbacks a
// register_rest_route call names, in any of its arms.
var restThisCallbackPattern = regexp.MustCompile(`(?:\[|array\s*\()\s*\$this\s*,\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)

// expandInheritedRESTEndpoints adds, for a register_rest_route written in a base
// class, the endpoints its subclasses register.
//
// PHP resolves $this->update_item() and reads $this->rest_base on the runtime
// object, and a class that does not redeclare register_routes() inherits its
// parent's verbatim. WordPress calls register_routes() once per controller it
// instantiates. So one textual register_rest_route in an abstract base is N live
// registrations with N route strings and, wherever a subclass overrides, N
// different method bodies -- and the analyzer, being a per-file text scan with
// no notion of subclasses, reported exactly one, attributed to the base. Every
// overriding subclass was then reachable from no endpoint at all: 46 classes
// across 8 of 143 trees inherit register_routes() without declaring it.
//
// Clones are added, never substituted. The base's own record stays, because the
// base may be instantiated through a concrete leaf the hierarchy missed.
//
// Only subclasses that genuinely register something different are cloned:
//
//   - the subclass overrides the handler this endpoint names, or
//   - it overrides one of the other methods the registration names -- its
//     permission callback, most importantly, and
//   - it gives one of the route's {property} placeholders a value of its own.
//
// A subclass that overrides none of those registers a route this endpoint
// already describes, and cloning it would add a record with the same route, the
// same gate and a body that is literally the base's. That bound matters: a base
// class in the corpus has as many as 31 transitive descendants in a tree with 85
// register_rest_route calls, and clone-per-descendant is a four-figure endpoint
// count in one plugin, each clone paying its own graph walks.
//
// A clone's callback carries the subclass's name so that it survives beside the
// base's record -- the merge keys on the callback -- and so that the walk starts
// from the subclass's own file. Consumers that match on a bare method name are
// unaffected: they strip everything before "::".
func expandInheritedRESTEndpoints(endpoints []models.Endpoint, astCtx *wpast.ASTContext,
	fileContents map[string]string, pluginDir string) []models.Endpoint {

	if astCtx == nil || !astCtx.Available || astCtx.Resolver == nil || astCtx.Resolver.SymTable == nil {
		return nil
	}

	// Classes by file, so an endpoint's line can be attributed to the class
	// whose body encloses it.
	byFile := make(map[string][]*wpast.ClassSymbol, len(astCtx.Resolver.SymTable.Classes))
	for _, cls := range astCtx.Resolver.SymTable.Classes {
		byFile[cls.File] = append(byFile[cls.File], cls)
	}

	var clones []models.Endpoint
	for _, ep := range endpoints {
		if ep.Type != models.EndpointTypeREST {
			continue
		}
		method, ok := thisCallbackMethod(ep.Callback)
		if !ok {
			continue
		}
		absFile := filepath.Join(pluginDir, ep.File)
		owner := enclosingClass(byFile[absFile], ep.Line)
		if owner == nil {
			continue
		}
		subclasses := astCtx.Resolver.GetSubclasses(owner.FQN)
		if len(subclasses) == 0 {
			continue
		}

		named := registrationCallbackNames(fileContents[absFile], ep.Line, ep.RawCode)
		placeholders := restRoutePlaceholderPattern.FindAllStringSubmatch(ep.Route, -1)

		for _, subFQN := range subclasses {
			sub := astCtx.Resolver.SymTable.Classes[subFQN]
			if sub == nil {
				continue
			}

			route, routeDiffers := substituteRouteProperties(ep.Route, placeholders, owner.FQN, subFQN, astCtx.Resolver)

			overridden := make([]string, 0, 2)
			if _, ok := sub.Methods[method]; ok {
				overridden = append(overridden, method)
			}
			for _, n := range named {
				if n == method {
					continue
				}
				if _, ok := sub.Methods[n]; ok {
					overridden = append(overridden, n)
				}
			}
			if len(overridden) == 0 && !routeDiffers {
				continue
			}

			// The level. Copying the base's is right only when the subclass
			// leaves the registration's gates alone; when it overrides one, the
			// gate that runs is the subclass's, and a level read off the base
			// would be a privilege this code has not been shown to require. So
			// each override is re-read against the subclass and the weakest
			// answer wins -- which also means an unreadable override answers
			// unauthenticated rather than inheriting a restriction.
			level := ep.AuthLevel
			for _, n := range overridden {
				resolved := astCtx.Resolver.ResolvePermissionCallback(wpast.CallbackRef{
					Type:       "static_method",
					ClassName:  subFQN,
					MethodName: n,
					File:       sub.File,
				})
				if resolved < level {
					level = resolved
				}
			}

			relFile, err := makeRelativePath(sub.File, pluginDir)
			if err != nil {
				relFile = ep.File
			}
			clones = append(clones, models.Endpoint{
				PluginSlug: ep.PluginSlug,
				Type:       ep.Type,
				Route:      route,
				Method:     ep.Method,
				AuthLevel:  level,
				Callback:   shortClassName(subFQN) + "::" + method,
				File:       relFile,
				Line:       sub.Line,
				RawCode:    ep.RawCode,
				Namespace:  ep.Namespace,
			})
		}
	}
	return clones
}

// thisCallbackMethod reports the method an endpoint callback names when it is
// written against the current object, which is the shape a base class's
// registration always has.
func thisCallbackMethod(callback string) (string, bool) {
	for _, prefix := range []string{"this::", "self::", "static::"} {
		if strings.HasPrefix(callback, prefix) {
			name := strings.TrimPrefix(callback, prefix)
			if name != "" && !strings.ContainsAny(name, "$()[]") {
				return name, true
			}
		}
	}
	return "", false
}

// enclosingClass returns the class whose declaration most closely precedes line.
func enclosingClass(classes []*wpast.ClassSymbol, line int) *wpast.ClassSymbol {
	var best *wpast.ClassSymbol
	for _, cls := range classes {
		if cls.Line > line {
			continue
		}
		if best == nil || cls.Line > best.Line {
			best = cls
		}
	}
	return best
}

// registrationCallbackNames lists the methods a register_rest_route call names
// as array( $this, '...' ) -- handlers and permission callbacks alike.
//
// The call is re-read from the file rather than from Endpoint.RawCode, which is
// truncated: a multi-arm registration loses its later arms there, and the later
// arms are where the writing gates live.
func registrationCallbackNames(content string, line int, rawCode string) []string {
	src := rawCode
	if content != "" {
		if start := offsetOfLine(content, line); start >= 0 {
			if idx := strings.Index(content[start:], "register_rest_route"); idx >= 0 {
				open := strings.Index(content[start+idx:], "(")
				if open >= 0 {
					if block := extractParenBlock(content, start+idx+open); block != "" {
						src = block
					}
				}
			}
		}
	}
	seen := make(map[string]bool)
	var out []string
	for _, m := range restThisCallbackPattern.FindAllStringSubmatch(src, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}

// offsetOfLine returns the byte offset where the 1-based line begins.
func offsetOfLine(content string, line int) int {
	if line <= 1 {
		return 0
	}
	offset := 0
	for n := 1; n < line; n++ {
		i := strings.IndexByte(content[offset:], '\n')
		if i < 0 {
			return -1
		}
		offset += i + 1
	}
	return offset
}

// substituteRouteProperties fills a route's {property} markers with the
// subclass's own values, and reports whether any of them differs from the
// base's -- which is by itself a different registration.
func substituteRouteProperties(route string, placeholders [][]string, baseFQN, subFQN string,
	resolver *wpast.Resolver) (string, bool) {

	differs := false
	for _, ph := range placeholders {
		subValue, ok := resolver.ResolveProperty(subFQN, ph[1])
		if !ok || subValue == "" {
			continue
		}
		baseValue, _ := resolver.ResolveProperty(baseFQN, ph[1])
		if subValue != baseValue {
			differs = true
		}
		route = strings.Replace(route, ph[0], subValue, 1)
	}
	return route, differs
}

// shortClassName drops the namespace from a fully qualified name, matching the
// key the call graph stores a method under.
func shortClassName(fqn string) string {
	if i := strings.LastIndex(fqn, `\`); i >= 0 {
		return fqn[i+1:]
	}
	return fqn
}

// relativeContentIndex re-keys the stripped-content cache by plugin-relative
// path, which is the form every endpoint's File carries. The contents are
// shared, not copied.
func relativeContentIndex(cache map[string]string, pluginDir string) map[string]string {
	out := make(map[string]string, len(cache))
	for path, content := range cache {
		rel, err := makeRelativePath(path, pluginDir)
		if err != nil {
			rel = path
		}
		out[rel] = content
	}
	return out
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

	// Detect REST endpoints via REST wrappers (register_rest_route inside wrapper methods)
	if wrapperRegistry != nil && len(wrapperRegistry.RESTWrappers) > 0 {
		restWrapperEndpoints := DetectRESTWrapperCalls(strippedContent, relPath, pluginSlug, wrapperRegistry)
		endpoints = append(endpoints, restWrapperEndpoints...)
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

// mergeEndpoints removes records that make the same claim, keyed on
// (route, method, type, callback, auth level).
//
// It replaces a rule that keyed on (route, method, type) alone and, on a
// collision, kept the record with the HIGHER auth level, discarding the other.
// Both halves of that rule were wrong, and each was wrong in the direction that
// hides a vulnerability.
//
// The level. The privilege an endpoint requires is the privilege of the
// cheapest request that reaches it: an attacker takes the arm that costs least,
// so the requirement for a route is the MINIMUM over the records that describe
// it. Keeping only the maximum reported a gate no attacker has to pass, which
// is the over-restriction failure -- a real, reachable bug looks gated and is
// dismissed. Measured over a 143-plugin corpus, 9 collisions in 8 trees kept a
// level strictly above their group's minimum, and because the pre-merge sort
// did not order on AuthLevel while sort.Slice is unstable, which level survived
// a fully tied pair was not even decided: ~98% of twin pairs tie on every field
// the old sort compared.
//
// This function does not impose that minimum, it stops destroying it. Every
// consumer of an endpoint list already reduces with a minimum when it asks what
// an attacker needs -- that is the only question the list is used to answer --
// and a library that answers it in advance, by deleting the cheaper record,
// leaves the consumer no way to disagree. Keeping both records also keeps the
// stricter one, which a consumer computing a maximum for a sensitivity check
// still needs; the old rule kept exactly one of the two and it was the wrong
// one.
//
// The key. formatAjaxRoute maps wp_ajax_X and wp_ajax_nopriv_X onto one URL,
// which is right: admin-ajax.php is one URL and core picks the arm on
// is_user_logged_in(). But the two arms may bind DIFFERENT callbacks, and then
// they are not two guesses at one thing -- they are two handlers, one of which
// an anonymous caller reaches and one of which it does not. Merging them threw
// a callback away, and Endpoint.Callback is the only seed the reachability walk
// has, so the discarded handler became reachable from nothing: 899 records
// discarded corpus-wide, 129 of them naming a callback the survivor did not.
// Attributing the surviving record's level to the union of the two handlers
// would be just as wrong in the other direction, since a handler bound only to
// the priv arm is not anonymously reachable; keeping the records apart is what
// keeps both facts.
//
// The file is deliberately NOT part of the key. A registration's identity is
// the handler it binds, not the file the registering line sits in, and some
// detectors report one hook once per file in the plugin: keying on the file
// turned a single ActionScheduler registration into 248 records on one tree,
// all naming the same callback. Each surviving record still carries a file of
// its own, so the (callback, file) pair the reachability walk seeds from stays
// a pair that really occurs.
//
// Nothing is dropped any more for having an uninformative callback name. The
// old rule let a named callback evict a "closure" or "inline" record on the
// same route, reasoning that the name was the better detection. That stopped
// being true once an anonymous callback's walk learned to seed from its own
// file: the evicted record carries a file, the file carries a body, and the
// body reaches code the named record does not.
func mergeEndpoints(endpoints []models.Endpoint) []models.Endpoint {
	seen := make(map[string]bool, len(endpoints))
	result := make([]models.Endpoint, 0, len(endpoints))

	for _, ep := range endpoints {
		// The callback and the level are part of a record's claim, not
		// incidental detail. Two records that name different handlers describe
		// two bodies of code, each reachable on its own terms; two that give
		// one handler different levels are two different answers to the
		// question the caller is asking, and the caller, not this function,
		// decides between them.
		key := ep.Route + "|" + ep.Method + "|" + string(ep.Type) + "|" +
			ep.Callback + "|" + ep.AuthLevel.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, ep)
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

	// Detect REST endpoints via REST wrappers (register_rest_route inside wrapper methods)
	if wrapperRegistry != nil && len(wrapperRegistry.RESTWrappers) > 0 {
		restWrapperEndpoints := DetectRESTWrapperCalls(strippedContent, relPath, pluginSlug, wrapperRegistry)
		endpoints = append(endpoints, restWrapperEndpoints...)
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

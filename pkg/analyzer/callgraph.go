package analyzer

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// CallGraph represents the call relationships for a callback function
type CallGraph struct {
	// Callees are functions called BY this callback (forward direction)
	Callees []string `json:"callees,omitempty"`
	// Callers are functions that CALL this callback (backward direction)
	Callers []string `json:"callers,omitempty"`
}

// FunctionDef represents a PHP function or method definition
type FunctionDef struct {
	Name       string // Function or method name
	ClassName  string // Empty for standalone functions
	FilePath   string // Relative path within plugin where this function is defined
	StartLine  int    // Line where function starts
	EndLine    int    // Line where function ends
	IsMethod   bool   // True if it's a class method
	Visibility string // public, private, protected (for methods)
	// Note: Body field removed for memory optimization.
	// Use CallsFrom map instead of storing/re-extracting function bodies.
}

// HookRegistration records a callback registered for a WordPress hook
type HookRegistration struct {
	Callback string // Resolved callback name
	File     string // File where add_action/add_filter was called
}

// HookRegistry maps hook names to their registered callbacks.
// Built during call graph construction to link do_action/apply_filters to add_action/add_filter.
type HookRegistry struct {
	Hooks       map[string][]HookRegistration
	PrefixHooks map[string][]HookRegistration
	mu          sync.RWMutex
}

// NewHookRegistry creates a new empty hook registry
func NewHookRegistry() *HookRegistry {
	return &HookRegistry{
		Hooks:       make(map[string][]HookRegistration),
		PrefixHooks: make(map[string][]HookRegistration),
	}
}

// PluginCallGraph holds call graph data for an entire plugin
type PluginCallGraph struct {
	// Functions maps function/method names to their definitions
	Functions map[string]*FunctionDef
	// CallsFrom maps a function name to functions it calls
	CallsFrom map[string][]string
	// CallsTo maps a function name to functions that call it
	CallsTo map[string][]string
	// AmbiguousFuncs maps a bare function name to all file-qualified keys
	// e.g. "display" -> ["admin/controllers/Submissions_fm.php::display", "frontend/controllers/FMControllerForm_maker_preview.php::display"]
	// This tracks standalone functions that share the same name across different files.
	AmbiguousFuncs map[string][]string
	// IncludesFrom maps source file path to files it includes/requires
	IncludesFrom map[string][]string
	// ClassToFile maps class name (and FQN with namespace) to file path
	ClassToFile map[string]string
	// FilesByBasename maps file basename to full relative paths for include resolution
	FilesByBasename map[string][]string
	// AllFiles tracks every PHP file path passed to BuildCallGraph
	AllFiles map[string]bool
	// DynIncluders maps function names that contain variable includes to directory hints
	DynIncluders map[string][]string
	// AutoloadBaseDirs holds PSR-4 base directories from spl_autoload_register / composer
	AutoloadBaseDirs []string
	// HookRegistry links WordPress hook names to registered callbacks
	HookRegistry *HookRegistry
	mu           sync.RWMutex
}

// NewPluginCallGraph creates a new empty call graph
func NewPluginCallGraph() *PluginCallGraph {
	return &PluginCallGraph{
		Functions:       make(map[string]*FunctionDef),
		CallsFrom:       make(map[string][]string),
		CallsTo:         make(map[string][]string),
		AmbiguousFuncs:  make(map[string][]string),
		IncludesFrom:    make(map[string][]string),
		ClassToFile:     make(map[string]string),
		FilesByBasename: make(map[string][]string),
		AllFiles:         make(map[string]bool),
		DynIncluders:     make(map[string][]string),
		AutoloadBaseDirs: make([]string, 0),
		HookRegistry:     NewHookRegistry(),
	}
}

// Package-level compiled regex patterns for call graph analysis
var (
	// Pattern to find function definitions
	// Matches: function name(...) { or function name(...):type {
	funcDefPattern = regexp.MustCompile(
		`(?m)^[\t ]*(?:(?:public|private|protected|static|final|abstract)\s+)*` +
			`function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)` +
			`(?:\s*:\s*[?]?[a-zA-Z_][a-zA-Z0-9_|\\]*)?` +
			`\s*\{`,
	)

	// Pattern to find class definitions
	// Matches: class ClassName { or class ClassName extends Parent {
	classDefPattern = regexp.MustCompile(
		`(?m)^[\t ]*(?:(?:abstract|final)\s+)?class\s+([a-zA-Z_][a-zA-Z0-9_]*)` +
			`(?:\s+extends\s+[a-zA-Z_][a-zA-Z0-9_\\]*)?` +
			`(?:\s+implements\s+[a-zA-Z_][a-zA-Z0-9_\\,\s]*)?` +
			`\s*\{`,
	)

	// Pattern for direct function calls: function_name(...)
	directCallPattern = regexp.MustCompile(
		`\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern for method calls: $this->method(...), $var->method(...)
	methodCallPattern = regexp.MustCompile(
		`\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern for $this->method calls specifically
	thisMethodCallPattern = regexp.MustCompile(
		`\$this\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern for static method calls: ClassName::method(...), self::method(...), static::method(...)
	staticCallPattern = regexp.MustCompile(
		`([a-zA-Z_][a-zA-Z0-9_]*|self|static|parent)\s*::\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern for call_user_func variants
	callUserFuncPattern = regexp.MustCompile(
		`call_user_func(?:_array)?\s*\(\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // Simple string callback
			`|` +
			`\[\s*[^,]+,\s*['"]([^'"]+)['"]` + // Array callback [obj, 'method']
			`|` +
			`array\s*\(\s*[^,]+,\s*['"]([^'"]+)['"]` + // array(obj, 'method')
			`)`,
	)

	// Pattern for do_action and apply_filters (WordPress hooks that trigger callbacks)
	wpHookCallPattern = regexp.MustCompile(
		`(?:do_action|apply_filters)\s*\(\s*['"]([^'"]+)['"]`,
	)

	// Pre-compiled patterns for ResolveCallback (memory optimization)
	cleanFunctionNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	arrayMethodNamePattern   = regexp.MustCompile(`['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)

	// Pattern for include/require file path extraction
	// Group 1: simple string literal
	// Group 2: __DIR__/dirname relative path
	// Group 3: any expression (constant, variable, property) + literal .php path
	includePattern = regexp.MustCompile(
		`(?:include|include_once|require|require_once)\s*` +
			`(?:\(\s*)?` +
			`(?:` +
			`['"]([^'"]+\.php)['"]` +
			`|(?:__DIR__|dirname\s*\(\s*__FILE__\s*\))\s*\.\s*['"]([^'"]+)['"]` +
			`|[a-zA-Z_$][a-zA-Z0-9_:>$\-]*[^'"]*['"]([^'"]*\.php)['"]` +
			`)`,
	)

	// Pattern for multi-segment concatenated includes with DIRECTORY_SEPARATOR
	// Extracts all string fragments that look like path segments from include statements
	includeFragmentPattern = regexp.MustCompile(
		`(?:include|include_once|require|require_once)\s*(?:\(\s*)?([^;]+)`,
	)

	// Pattern for namespace declaration
	namespacePattern = regexp.MustCompile(`(?m)^namespace\s+([a-zA-Z_][a-zA-Z0-9_\\]*)\s*;`)

	// Pattern for add_action/add_filter with static hook name
	// Callback group captures array syntax [...], array(...), or simple expression
	hookRegistrationPattern = regexp.MustCompile(
		`\b(?:add_action|add_filter)\s*\(\s*['"]([^'"]+)['"]\s*,\s*` +
			`(\[[^\]]*\]|array\s*\([^)]*\)|[^,)]+)`,
	)

	// Pattern for add_action/add_filter with concatenated hook: 'prefix_' . $var
	hookRegistrationDynamicPattern = regexp.MustCompile(
		`\b(?:add_action|add_filter)\s*\(\s*['"]([^'"]+)['"]\s*\.\s*[^,]+,\s*` +
			`(\[[^\]]*\]|array\s*\([^)]*\)|[^,)]+)`,
	)

	// Pattern for add_shortcode('tag', callback)
	shortcodeRegistrationPattern = regexp.MustCompile(
		`\badd_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*` +
			`(\[[^\]]*\]|array\s*\([^)]*\)|[^,)]+)`,
	)

	// Pattern for PHP trait usage inside class bodies
	traitUsePattern = regexp.MustCompile(
		`(?m)^\s+use\s+([A-Z][a-zA-Z0-9_\\]+(?:\s*,\s*[A-Z][a-zA-Z0-9_\\]+)*)\s*[;{]`,
	)

	// Pattern to extract class name from callback expressions like ClassName::class
	hookCallbackClassPattern = regexp.MustCompile(`([A-Z][a-zA-Z0-9_]*)::class|['"]([A-Z][a-zA-Z0-9_]*)['"]`)

	// Detects include/require with a variable path (not a string literal)
	dynamicIncludeVarPattern = regexp.MustCompile(
		`(?:include|include_once|require|require_once)\s*(?:\(\s*)?\$[a-zA-Z_]`,
	)

	// Captures function calls with string literal first argument
	funcWithStringArgPattern = regexp.MustCompile(
		`(?:` +
			`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*['"]([^'"]+)['"]` + // Groups 1,2: func('arg')
			`|` +
			`\$(?:this|self)\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*['"]([^'"]+)['"]` + // Groups 3,4: $this->func('arg')
			`|` +
			`([A-Z][a-zA-Z0-9_]*)\s*::\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*['"]([^'"]+)['"]` + // Groups 5,6,7: Class::func('arg')
			`)`,
	)

	// Extracts string literals containing directory separators (for directory hints)
	dirHintPattern = regexp.MustCompile(`['"]([^'"]*[/\\][^'"]*)['"]`)

	// PHP keywords that look like function calls but aren't
	phpKeywords = map[string]bool{
		"if": true, "else": true, "elseif": true, "while": true, "for": true,
		"foreach": true, "switch": true, "case": true, "return": true,
		"echo": true, "print": true, "die": true, "exit": true,
		"include": true, "include_once": true, "require": true, "require_once": true,
		"new": true, "clone": true, "throw": true, "catch": true, "try": true,
		"finally": true, "use": true, "namespace": true, "class": true,
		"interface": true, "trait": true, "extends": true, "implements": true,
		"public": true, "private": true, "protected": true, "static": true,
		"final": true, "abstract": true, "const": true, "function": true,
		"array": true, "list": true, "isset": true, "unset": true, "empty": true,
		"eval": true, "global": true, "var": true, "declare": true,
		"enddeclare": true, "endfor": true, "endforeach": true, "endif": true,
		"endswitch": true, "endwhile": true, "as": true, "default": true,
		"break": true, "continue": true, "goto": true, "match": true,
		"fn": true, "yield": true, "from": true, "insteadof": true,
	}

	// Common WordPress core functions (we don't need to recurse into these)
	wpCoreFunctions = map[string]bool{
		// Database
		"wpdb": true, "$wpdb": true,
		// Options
		"get_option": true, "update_option": true, "delete_option": true, "add_option": true,
		"get_site_option": true, "update_site_option": true, "delete_site_option": true,
		"get_transient": true, "set_transient": true, "delete_transient": true,
		// Posts
		"get_post": true, "get_posts": true, "wp_insert_post": true, "wp_update_post": true,
		"wp_delete_post": true, "get_post_meta": true, "update_post_meta": true,
		"delete_post_meta": true, "add_post_meta": true,
		// Users
		"get_user_by": true, "get_userdata": true, "get_current_user_id": true,
		"wp_get_current_user": true, "get_user_meta": true, "update_user_meta": true,
		"wp_create_user": true, "wp_insert_user": true, "wp_update_user": true,
		// Security/Auth
		"current_user_can": true, "is_user_logged_in": true, "wp_verify_nonce": true,
		"check_ajax_referer": true, "wp_create_nonce": true, "is_admin": true,
		"is_super_admin": true, "user_can": true,
		// AJAX/JSON responses
		"wp_send_json": true, "wp_send_json_success": true, "wp_send_json_error": true,
		"wp_die": true,
		// Sanitization
		"sanitize_text_field": true, "sanitize_email": true, "sanitize_title": true,
		"sanitize_file_name": true, "sanitize_key": true, "sanitize_user": true,
		"sanitize_html_class": true, "sanitize_option": true,
		"wp_kses": true, "wp_kses_post": true, "esc_html": true, "esc_attr": true,
		"esc_url": true, "esc_sql": true, "absint": true, "intval": true,
		// Validation
		"is_email": true, "wp_validate_boolean": true,
		// Hooks
		"add_action": true, "add_filter": true, "remove_action": true, "remove_filter": true,
		"do_action": true, "apply_filters": true, "has_action": true, "has_filter": true,
		// Queries
		"WP_Query": true, "WP_User_Query": true, "get_terms": true, "get_term": true,
		// REST
		"register_rest_route": true, "rest_ensure_response": true,
		// Admin
		"add_menu_page": true, "add_submenu_page": true, "add_options_page": true,
		// Capabilities
		"map_meta_cap": true, "add_cap": true, "remove_cap": true,
		// Misc
		"__": true, "_e": true, "esc_html__": true, "esc_attr__": true,
		"wp_enqueue_script": true, "wp_enqueue_style": true,
		"wp_localize_script": true, "wp_register_script": true,
		"admin_url": true, "home_url": true, "site_url": true, "plugins_url": true,
		"plugin_dir_path": true, "plugin_dir_url": true,
		"wp_redirect": true, "wp_safe_redirect": true,
		"wp_remote_get": true, "wp_remote_post": true, "wp_remote_request": true,
		"wp_upload_dir": true, "wp_handle_upload": true,
	}
)

// BuildCallGraph builds a call graph for all PHP files in a plugin
// Memory-optimized: extracts calls inline during discovery, avoiding body storage
// DETERMINISM: Files are processed in sorted order to ensure consistent results
//
// Three sub-passes:
//
//	A: Build hook registry + extract file includes + register class-to-file mappings
//	B: Discover functions and extract calls (with hook resolution via registry)
//	C: Resolve trait usage — alias trait methods to using classes
func BuildCallGraph(files map[string]string) *PluginCallGraph {
	cg := NewPluginCallGraph()

	// Sort file paths for deterministic processing order
	sortedPaths := make([]string, 0, len(files))
	for fp := range files {
		sortedPaths = append(sortedPaths, fp)
	}
	sort.Strings(sortedPaths)

	// Register all files and build basename index early (needed for resolution in Sub-pass B)
	for _, fp := range sortedPaths {
		cg.AllFiles[fp] = true
	}
	cg.buildFileIndex()

	// Sub-pass A: Build hook registry, extract includes, register classes, detect dynamic includers
	for _, fp := range sortedPaths {
		cg.extractHookRegistrations(files[fp], fp)
		cg.extractFileIncludes(files[fp], fp)
		cg.extractClassToFileMap(files[fp], fp)
		cg.extractDynIncluders(files[fp], fp)
		cg.extractAutoloadHints(files[fp], fp)
	}

	// Sub-pass B: Discover functions, extract calls (with hook resolution), resolve dynamic include edges
	for _, fp := range sortedPaths {
		cg.discoverFunctionsAndCalls(files[fp], fp)
		cg.extractDynIncludeEdges(files[fp], fp)
	}

	// Sub-pass C: Resolve trait usage
	for _, fp := range sortedPaths {
		classRanges := findClassRanges(files[fp])
		cg.discoverTraitUsage(files[fp], classRanges)
	}

	return cg
}

// discoverFunctionsAndCalls finds all function definitions and extracts their calls in one pass
// Memory-optimized: extracts calls immediately without storing function bodies
func (cg *PluginCallGraph) discoverFunctionsAndCalls(content, filePath string) {
	// Find class boundaries first
	classRanges := findClassRanges(content)

	// Find all function definitions
	matches := funcDefPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		funcName := content[match[2]:match[3]]
		startPos := match[0]
		startLine := countNewlines(content[:startPos])

		// Find the matching closing brace
		bodyStart := match[1] - 1 // Position of opening brace
		endPos := findMatchingBrace(content, bodyStart)
		if endPos < 0 {
			continue
		}
		endLine := countNewlines(content[:endPos])

		// Extract function body temporarily for call extraction
		body := content[bodyStart:endPos]

		// Determine if this is a method (inside a class)
		// DETERMINISM: Find the innermost containing class (smallest range)
		// instead of breaking on first map iteration hit
		className := ""
		isMethod := false
		smallestRange := int(^uint(0) >> 1) // max int
		for cn, bounds := range classRanges {
			if startPos > bounds[0] && startPos < bounds[1] {
				rangeSize := bounds[1] - bounds[0]
				if rangeSize < smallestRange {
					smallestRange = rangeSize
					className = cn
					isMethod = true
				}
			}
		}

		// Create a unique key for the function
		key := funcName
		if className != "" {
			key = className + "::" + funcName
		}

		// Extract calls from the body immediately (memory-optimized: don't store body)
		calls := cg.extractCalls(body)

		funcDef := &FunctionDef{
			Name:      funcName,
			ClassName: className,
			FilePath:  filePath,
			StartLine: startLine,
			EndLine:   endLine,
			IsMethod:  isMethod,
		}

		cg.mu.Lock()
		cg.Functions[key] = funcDef
		// Also store without class prefix for lookups
		if className != "" && cg.Functions[funcName] == nil {
			cg.Functions[funcName] = funcDef
		}

		// DETERMINISM: For standalone functions (no class), track ambiguity
		// when multiple files define the same function name.
		// Store each implementation under a file-qualified key so buildCallTree
		// can resolve all implementations for ambiguous names.
		if className == "" {
			// Create a file-qualified key: "basename.php::funcName"
			fileBase := filepath.Base(filePath)
			fileQualifiedKey := fileBase + "::" + funcName
			if _, alreadyExists := cg.CallsFrom[funcName]; alreadyExists {
				// Collision: another file already defined this function
				cg.AmbiguousFuncs[funcName] = append(cg.AmbiguousFuncs[funcName], fileQualifiedKey)
				// Store the file-qualified version separately
				cg.CallsFrom[fileQualifiedKey] = calls
				cg.Functions[fileQualifiedKey] = funcDef
			} else {
				// First time seeing this function name — store normally
				cg.CallsFrom[funcName] = calls
			}
		} else {
			cg.CallsFrom[key] = calls
		}

		for _, callee := range calls {
			cg.CallsTo[callee] = append(cg.CallsTo[callee], key)
		}
		cg.mu.Unlock()
	}
}

// findClassRanges finds the start and end positions of all classes in content
func findClassRanges(content string) map[string][2]int {
	ranges := make(map[string][2]int)

	matches := classDefPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		className := content[match[2]:match[3]]

		// Find the opening brace of the class
		bracePos := strings.Index(content[match[1]:], "{")
		if bracePos < 0 {
			continue
		}
		openBrace := match[1] + bracePos

		// Find the matching closing brace
		closeBrace := findMatchingBrace(content, openBrace)
		if closeBrace < 0 {
			continue
		}

		ranges[className] = [2]int{openBrace, closeBrace}
	}

	return ranges
}

// findMatchingBrace finds the position of the closing brace matching the one at pos
func findMatchingBrace(content string, pos int) int {
	if pos >= len(content) || content[pos] != '{' {
		return -1
	}

	depth := 1
	inString := false
	stringChar := byte(0)
	inComment := false
	inLineComment := false

	for i := pos + 1; i < len(content); i++ {
		c := content[i]

		// Handle line comments
		if inLineComment {
			if c == '\n' {
				inLineComment = false
			}
			continue
		}

		// Handle multi-line comments
		if inComment {
			if c == '*' && i+1 < len(content) && content[i+1] == '/' {
				inComment = false
				i++
			}
			continue
		}

		// Check for comment start
		if !inString && c == '/' && i+1 < len(content) {
			if content[i+1] == '/' {
				inLineComment = true
				continue
			}
			if content[i+1] == '*' {
				inComment = true
				continue
			}
		}

		// Handle strings
		if !inString {
			if c == '"' || c == '\'' {
				inString = true
				stringChar = c
				continue
			}
		} else {
			if c == '\\' && i+1 < len(content) {
				i++ // Skip escaped character
				continue
			}
			if c == stringChar {
				inString = false
			}
			continue
		}

		// Count braces
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}

	return -1
}

// countNewlines counts the number of newlines in a string
func countNewlines(s string) int {
	return strings.Count(s, "\n") + 1
}

// extractCalls extracts all function/method calls from a code block
func (cg *PluginCallGraph) extractCalls(code string) []string {
	calls := make(map[string]bool)

	// Extract direct function calls
	matches := directCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			name := match[1]
			if !phpKeywords[name] && !wpCoreFunctions[name] {
				calls[name] = true
			}
		}
	}

	// Extract $this->method() calls
	matches = thisMethodCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			calls["$this->"+match[1]] = true
		}
	}

	// Extract other method calls $var->method()
	matches = methodCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			calls["->"+match[1]] = true
		}
	}

	// Extract static calls Class::method()
	matches = staticCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 2 {
			calls[match[1]+"::"+match[2]] = true
		}
	}

	// Extract call_user_func callbacks
	matches = callUserFuncPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				calls[match[i]] = true
				break
			}
		}
	}

	// Resolve do_action/apply_filters through hook registry
	if cg.HookRegistry != nil {
		hookMatches := wpHookCallPattern.FindAllStringSubmatch(code, -1)
		for _, match := range hookMatches {
			if len(match) > 1 {
				hookName := match[1]

				cg.HookRegistry.mu.RLock()
				if regs, ok := cg.HookRegistry.Hooks[hookName]; ok {
					for _, reg := range regs {
						calls[reg.Callback] = true
					}
				}
				for prefix, regs := range cg.HookRegistry.PrefixHooks {
					if strings.HasPrefix(hookName, prefix) {
						for _, reg := range regs {
							calls[reg.Callback] = true
						}
					}
				}
				cg.HookRegistry.mu.RUnlock()
			}
		}
	}

	// Convert to sorted slice for deterministic order
	result := make([]string, 0, len(calls))
	for call := range calls {
		result = append(result, call)
	}
	sort.Strings(result)

	return result
}

// GetCallees returns all functions called by the given callback, recursively
func (cg *PluginCallGraph) GetCallees(callback string) []string {
	visited := make(map[string]bool)
	result := make([]string, 0)

	cg.getCalleesRecursive(callback, visited, &result)

	return result
}

// getCalleesRecursive is the recursive helper for GetCallees
func (cg *PluginCallGraph) getCalleesRecursive(funcName string, visited map[string]bool, result *[]string) {
	if visited[funcName] {
		return
	}
	visited[funcName] = true

	cg.mu.RLock()
	calls, ok := cg.CallsFrom[funcName]
	cg.mu.RUnlock()

	if !ok {
		return
	}

	for _, callee := range calls {
		*result = append(*result, callee)
		cg.getCalleesRecursive(callee, visited, result)
	}
}

// GetCallers returns all functions that call the given callback
func (cg *PluginCallGraph) GetCallers(callback string) []string {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	callers, ok := cg.CallsTo[callback]
	if !ok {
		return nil
	}

	// Return a copy
	result := make([]string, len(callers))
	copy(result, callers)
	return result
}

// AnalyzeCallback analyzes a callback function and returns its call graph
func (cg *PluginCallGraph) AnalyzeCallback(callback string) *CallGraph {
	callees := cg.GetCallees(callback)
	callers := cg.GetCallers(callback)

	return &CallGraph{
		Callees: callees,
		Callers: callers,
	}
}

// ExtractFunctionCalls extracts function calls from a single code snippet
// This is a simpler version for quick analysis without building a full call graph
func ExtractFunctionCalls(code string) []string {
	calls := make(map[string]bool)

	// Remove comments first
	code = StripPHPComments(code)

	// Extract direct function calls
	matches := directCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			name := match[1]
			if !phpKeywords[name] {
				calls[name] = true
			}
		}
	}

	// Extract $this->method() calls
	matches = thisMethodCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			calls[match[1]] = true
		}
	}

	// Extract static calls
	matches = staticCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 2 {
			calls[match[2]] = true
		}
	}

	// Convert to sorted slice for deterministic order
	result := make([]string, 0, len(calls))
	for call := range calls {
		result = append(result, call)
	}
	sort.Strings(result)

	return result
}

// ResolveCallback attempts to resolve a callback string to its actual function
// Handles cases like:
// - "function_name" -> function_name
// - "ClassName::method" -> ClassName::method
// - "$this->method" -> looks up in current class context
// - "array($this, 'method')" -> extracts method name
// Memory-optimized: uses pre-compiled patterns
func ResolveCallback(callback, currentClass string) string {
	callback = strings.TrimSpace(callback)

	// Already a clean function name
	if cleanFunctionNamePattern.MatchString(callback) {
		return callback
	}

	// Static method call ClassName::method
	if strings.Contains(callback, "::") {
		return callback
	}

	// $this->method
	if strings.HasPrefix(callback, "$this->") {
		method := strings.TrimPrefix(callback, "$this->")
		if currentClass != "" {
			return currentClass + "::" + method
		}
		return method
	}

	// Array callback extraction
	if strings.Contains(callback, "[") || strings.Contains(callback, "array(") {
		// Extract method name from array callback
		methodMatch := arrayMethodNamePattern.FindStringSubmatch(callback)
		if len(methodMatch) > 1 {
			return methodMatch[1]
		}
	}

	return callback
}

// AnalyzeCallbackInFile analyzes a callback function within a single file
// This is a lightweight analysis that finds the callback's function body and extracts its calls
// Returns the list of functions called by the callback (first level only for performance)
func AnalyzeCallbackInFile(fileContent, callback string) []string {
	if callback == "" || callback == "unknown" || callback == "inline" || callback == "closure" {
		return nil
	}

	// Clean up the callback name
	callback = ResolveCallback(callback, "")

	// Skip if callback looks like a variable or expression
	if strings.HasPrefix(callback, "$") || strings.Contains(callback, "(") {
		return nil
	}

	// Find the function body in the file
	body := lookupFunctionBody(fileContent, callback)
	if body == "" {
		return nil
	}

	// Extract function calls from the body
	return ExtractFunctionCalls(body)
}

// lookupFunctionBody locates a function/method by name and returns its body
// Memory-optimized: uses string operations instead of dynamic regex compilation
func lookupFunctionBody(content, funcName string) string {
	// Handle Class::method format
	methodOnly := funcName
	if idx := strings.LastIndex(funcName, "::"); idx >= 0 {
		methodOnly = funcName[idx+2:]
	}

	// Search for "function methodName" pattern using string operations
	searchPattern := "function " + methodOnly
	searchStart := 0

	for {
		idx := strings.Index(content[searchStart:], searchPattern)
		if idx < 0 {
			return ""
		}
		pos := searchStart + idx

		// Verify this is followed by whitespace and '('
		afterFunc := pos + len(searchPattern)
		if afterFunc >= len(content) {
			searchStart = afterFunc
			continue
		}

		// Skip whitespace after function name
		i := afterFunc
		for i < len(content) && (content[i] == ' ' || content[i] == '\t' || content[i] == '\n' || content[i] == '\r') {
			i++
		}

		// Must be followed by '('
		if i >= len(content) || content[i] != '(' {
			searchStart = i
			continue
		}

		// Find the opening brace after the parameter list
		bracePos := strings.Index(content[i:], "{")
		if bracePos < 0 {
			searchStart = i
			continue
		}

		braceStart := i + bracePos

		// Find matching closing brace
		endPos := findMatchingBrace(content, braceStart)
		if endPos < 0 {
			return ""
		}

		return content[braceStart:endPos]
	}
}

// EnrichEndpointsWithCallGraph adds function call information to endpoints
// This analyzes each endpoint's callback within the given file content (single-file, non-recursive)
func EnrichEndpointsWithCallGraph(endpoints []models.Endpoint, fileContent string) {
	for i := range endpoints {
		if endpoints[i].Callback == "" {
			continue
		}

		calls := AnalyzeCallbackInFile(fileContent, endpoints[i].Callback)
		if len(calls) > 0 {
			endpoints[i].FunctionCalls = calls
		}
	}
}

// EnrichEndpointsWithPluginCallGraph adds RECURSIVE function call information to endpoints
// This analyzes each endpoint's callback using the plugin-wide function index,
// following calls across ALL files in the plugin.
func EnrichEndpointsWithPluginCallGraph(endpoints []models.Endpoint, callGraph *PluginCallGraph, fileContent string) {
	if callGraph == nil {
		// Fall back to single-file analysis
		EnrichEndpointsWithCallGraph(endpoints, fileContent)
		return
	}

	for i := range endpoints {
		if endpoints[i].Callback == "" {
			continue
		}

		// Get recursive calls using the plugin-wide call graph
		calls := GetRecursiveCallsForCallback(callGraph, endpoints[i].Callback, fileContent)
		if len(calls) > 0 {
			endpoints[i].FunctionCalls = calls
		}
	}
}

// GetRecursiveCallsForCallback gets all functions called by a callback recursively
// across the entire plugin codebase
// Memory-optimized: uses pre-computed CallsFrom map instead of re-parsing bodies
func GetRecursiveCallsForCallback(cg *PluginCallGraph, callback, fileContent string) []string {
	if callback == "" || callback == "unknown" || callback == "inline" || callback == "closure" {
		return nil
	}

	// Clean up the callback name
	callback = ResolveCallback(callback, "")

	// Skip if callback looks like a variable or expression
	if strings.HasPrefix(callback, "$") || strings.Contains(callback, "(") {
		return nil
	}

	// Track visited functions to prevent infinite recursion
	visited := make(map[string]bool)
	allCalls := make([]string, 0)

	// First, try to find the callback body in the current file (for local methods like $this->method)
	body := lookupFunctionBody(fileContent, callback)

	// If we found the body in the current file, extract its immediate calls
	if body != "" {
		immediateCalls := ExtractFunctionCalls(body)
		for _, call := range immediateCalls {
			if !visited[call] {
				visited[call] = true
				allCalls = append(allCalls, call)
				// Recursively follow this call using the pre-computed call graph
				recurseCalls(cg, call, visited, &allCalls)
			}
		}
	} else {
		// Try to find in the plugin-wide index using pre-computed calls
		cg.mu.RLock()
		key := callback
		calls, found := cg.CallsFrom[key]
		if !found {
			// Try without class prefix
			methodOnly := callback
			if idx := strings.LastIndex(callback, "::"); idx >= 0 {
				methodOnly = callback[idx+2:]
			}
			calls, found = cg.CallsFrom[methodOnly]
		}
		cg.mu.RUnlock()

		if found {
			for _, call := range calls {
				if !visited[call] {
					visited[call] = true
					allCalls = append(allCalls, call)
					// Recursively follow this call
					recurseCalls(cg, call, visited, &allCalls)
				}
			}
		}
	}

	return allCalls
}

// recurseCalls recursively follows function calls through the plugin-wide index
// Memory-optimized: uses pre-computed CallsFrom map instead of re-parsing bodies
func recurseCalls(cg *PluginCallGraph, funcName string, visited map[string]bool, allCalls *[]string) {
	// Don't recurse into PHP built-ins or WordPress core
	if phpKeywords[funcName] || wpCoreFunctions[funcName] {
		return
	}

	// Look up the pre-computed calls for this function
	cg.mu.RLock()
	calls, found := cg.CallsFrom[funcName]
	if !found {
		// Try without class prefix
		methodOnly := funcName
		if idx := strings.LastIndex(funcName, "::"); idx >= 0 {
			methodOnly = funcName[idx+2:]
		}
		calls, found = cg.CallsFrom[methodOnly]
	}
	cg.mu.RUnlock()

	if !found {
		// External function (WordPress core, PHP built-in, or not found in plugin)
		return
	}

	// Use the pre-computed calls
	for _, call := range calls {
		if !visited[call] {
			visited[call] = true
			*allCalls = append(*allCalls, call)
			// Continue recursion
			recurseCalls(cg, call, visited, allCalls)
		}
	}
}

// BuildPluginCallGraphFromFiles builds a plugin-wide call graph from all PHP file contents
// This is used to enable cross-file recursive call analysis
func BuildPluginCallGraphFromFiles(files map[string]string) *PluginCallGraph {
	return BuildCallGraph(files)
}

// GetHierarchicalCallsForCallback returns a hierarchical tree of function calls
// instead of the flat list returned by GetRecursiveCallsForCallback.
// This is used when -chain-human or -chain-json flags are specified.
func GetHierarchicalCallsForCallback(cg *PluginCallGraph, callback, fileContent string) []*models.CallChainNode {
	if callback == "" || callback == "unknown" || callback == "inline" || callback == "closure" {
		return nil
	}

	// Clean up the callback name
	callback = ResolveCallback(callback, "")

	// Skip if callback looks like a variable or expression
	if strings.HasPrefix(callback, "$") || strings.Contains(callback, "(") {
		return nil
	}

	// Track visited functions to prevent infinite recursion
	// Using a map per recursive path to allow same function in different branches
	visited := make(map[string]bool)

	// First, try to find the callback body in the current file
	body := lookupFunctionBody(fileContent, callback)

	var immediateCalls []string
	if body != "" {
		// Extract calls from the function body
		immediateCalls = ExtractFunctionCalls(body)
	} else {
		// Try to find in the plugin-wide index
		cg.mu.RLock()
		calls, found := cg.CallsFrom[callback]
		ambiguousKeys := cg.AmbiguousFuncs[callback]
		if !found {
			// Try without class prefix
			methodOnly := callback
			if idx := strings.LastIndex(callback, "::"); idx >= 0 {
				methodOnly = callback[idx+2:]
			}
			calls, found = cg.CallsFrom[methodOnly]
			if found {
				ambiguousKeys = cg.AmbiguousFuncs[methodOnly]
			}
		}
		cg.mu.RUnlock()

		if found {
			immediateCalls = calls
			// DETERMINISM: If the root callback is ambiguous, merge all implementations
			if len(ambiguousKeys) > 0 {
				allCalls := make(map[string]bool, len(calls))
				for _, c := range calls {
					allCalls[c] = true
				}
				cg.mu.RLock()
				for _, qualifiedKey := range ambiguousKeys {
					if extraCalls, ok := cg.CallsFrom[qualifiedKey]; ok {
						for _, c := range extraCalls {
							allCalls[c] = true
						}
					}
				}
				cg.mu.RUnlock()
				immediateCalls = make([]string, 0, len(allCalls))
				for c := range allCalls {
					immediateCalls = append(immediateCalls, c)
				}
				sort.Strings(immediateCalls)
			}
		}
	}

	if len(immediateCalls) == 0 {
		return nil
	}

	// Build hierarchical tree from immediate calls
	visited[callback] = true
	result := make([]*models.CallChainNode, 0, len(immediateCalls))
	nodeCount := 0
	const maxNodes = 10000 // Safety limit to prevent unbounded tree growth

	for _, call := range immediateCalls {
		if visited[call] {
			continue
		}
		if nodeCount >= maxNodes {
			break
		}
		node := buildCallTree(cg, call, visited, &nodeCount, maxNodes)
		if node != nil {
			result = append(result, node)
		}
	}

	return result
}

// buildCallTree recursively builds the call tree for a function
func buildCallTree(cg *PluginCallGraph, funcName string, visited map[string]bool, nodeCount *int, maxNodes int) *models.CallChainNode {
	*nodeCount++

	// Circuit breaker: stop expanding if node limit reached
	if *nodeCount >= maxNodes {
		return &models.CallChainNode{
			Function: funcName,
			Calls:    nil,
		}
	}

	// Don't recurse into PHP built-ins or WordPress core
	if phpKeywords[funcName] || wpCoreFunctions[funcName] {
		// Still include the node, just don't recurse
		return &models.CallChainNode{
			Function: funcName,
			Calls:    nil,
		}
	}

	// Create the node
	node := &models.CallChainNode{
		Function: funcName,
		Calls:    nil,
	}

	// Mark as visited on THIS PATH only (ancestor tracking for cycle detection).
	// After processing all children, we remove it so sibling branches can
	// independently expand this function. The maxNodes cap bounds total growth.
	visited[funcName] = true
	defer delete(visited, funcName)

	// Look up the pre-computed calls for this function
	cg.mu.RLock()
	calls, found := cg.CallsFrom[funcName]
	ambiguousKeys := cg.AmbiguousFuncs[funcName]
	if !found {
		// Try without class prefix
		methodOnly := funcName
		if idx := strings.LastIndex(funcName, "::"); idx >= 0 {
			methodOnly = funcName[idx+2:]
		}
		calls, found = cg.CallsFrom[methodOnly]
		if found {
			ambiguousKeys = cg.AmbiguousFuncs[methodOnly]
		}
	}
	cg.mu.RUnlock()

	if !found || len(calls) == 0 {
		return node
	}

	// DETERMINISM: If this function name is ambiguous (multiple standalone
	// implementations across different files), include calls from ALL
	// implementations to ensure complete coverage. This way the output
	// always includes all reachable code paths regardless of file ordering.
	if len(ambiguousKeys) > 0 {
		allCalls := make(map[string]bool, len(calls))
		for _, c := range calls {
			allCalls[c] = true
		}
		cg.mu.RLock()
		for _, qualifiedKey := range ambiguousKeys {
			if extraCalls, ok := cg.CallsFrom[qualifiedKey]; ok {
				for _, c := range extraCalls {
					allCalls[c] = true
				}
			}
		}
		cg.mu.RUnlock()
		// Rebuild calls as a sorted slice for deterministic order
		calls = make([]string, 0, len(allCalls))
		for c := range allCalls {
			calls = append(calls, c)
		}
		sort.Strings(calls)
	}

	// Build child nodes
	node.Calls = make([]*models.CallChainNode, 0, len(calls))
	for _, call := range calls {
		if visited[call] {
			continue // Skip cycles
		}
		if *nodeCount >= maxNodes {
			break
		}
		childNode := buildCallTree(cg, call, visited, nodeCount, maxNodes)
		if childNode != nil {
			node.Calls = append(node.Calls, childNode)
		}
	}

	return node
}

// --- Reachability analysis: include tracking, class mapping, hook registry, traits ---

// extractFileIncludes scans a PHP file for include/require statements and records file-level edges.
func (cg *PluginCallGraph) extractFileIncludes(content, filePath string) {
	sourceDir := filepath.Dir(filePath)
	includes := make([]string, 0, 4)

	// Standard include pattern matching
	for _, match := range includePattern.FindAllStringSubmatch(content, -1) {
		var includedPath string
		switch {
		case match[1] != "":
			includedPath = match[1]
		case match[2] != "":
			includedPath = filepath.Join(sourceDir, match[2])
		case match[3] != "":
			includedPath = match[3]
		}
		if includedPath != "" {
			includedPath = filepath.ToSlash(filepath.Clean(includedPath))
			includes = append(includes, includedPath)
		}
	}

	// Also extract .php path fragments from complex include expressions
	// (e.g., CONSTANT . DIRECTORY_SEPARATOR . 'database' . DIRECTORY_SEPARATOR . 'search-replace.php')
	for _, match := range includeFragmentPattern.FindAllStringSubmatch(content, -1) {
		expr := match[1]
		// Extract all string literals from the include expression
		for _, strMatch := range regexp.MustCompile(`['"]([^'"]+)['"]`).FindAllStringSubmatch(expr, -1) {
			frag := strMatch[1]
			if strings.HasSuffix(frag, ".php") {
				includes = append(includes, filepath.ToSlash(filepath.Clean(frag)))
			}
		}
	}

	if len(includes) > 0 {
		cg.mu.Lock()
		cg.IncludesFrom[filePath] = append(cg.IncludesFrom[filePath], includes...)
		cg.mu.Unlock()
	}

	// Detect Composer autoload inclusion
	if strings.Contains(content, "vendor/autoload.php") {
		cg.mu.Lock()
		cg.AutoloadBaseDirs = append(cg.AutoloadBaseDirs, "vendor")
		cg.mu.Unlock()
	}

	// Parse Composer autoload_psr4.php for namespace→directory mappings
	if strings.HasSuffix(filePath, "vendor/composer/autoload_psr4.php") {
		cg.parseComposerPSR4(content)
	}
}

// parseComposerPSR4 extracts namespace→directory mappings from Composer's autoload_psr4.php
func (cg *PluginCallGraph) parseComposerPSR4(content string) {
	psr4Pat := regexp.MustCompile(`'([^']+\\\\)'\s*=>\s*array\s*\(\s*\$[a-zA-Z]+ \. '([^']+)'`)
	for _, m := range psr4Pat.FindAllStringSubmatch(content, -1) {
		namespace := strings.ReplaceAll(m[1], "\\\\", "\\")
		dir := strings.Trim(m[2], "/")
		cg.mu.Lock()
		cg.AutoloadBaseDirs = append(cg.AutoloadBaseDirs, dir)
		_ = namespace // namespace prefix stored implicitly via directory
		cg.mu.Unlock()
	}
}

// extractClassToFileMap scans a PHP file for class definitions and namespace, then registers mappings.
func (cg *PluginCallGraph) extractClassToFileMap(content, filePath string) {
	classRanges := findClassRanges(content)
	if len(classRanges) == 0 {
		return
	}

	namespace := ""
	if m := namespacePattern.FindStringSubmatch(content); len(m) > 1 {
		namespace = m[1]
	}

	cg.mu.Lock()
	for className := range classRanges {
		cg.ClassToFile[className] = filePath
		if namespace != "" {
			fqn := namespace + "\\" + className
			cg.ClassToFile[fqn] = filePath
		}
	}
	cg.mu.Unlock()
}

// buildFileIndex builds a basename-to-paths index from ALL known PHP files.
func (cg *PluginCallGraph) buildFileIndex() {
	for fp := range cg.AllFiles {
		base := filepath.Base(fp)
		cg.FilesByBasename[base] = append(cg.FilesByBasename[base], fp)
	}
}

// extractHookRegistrations scans a PHP file for add_action, add_filter, add_shortcode calls.
func (cg *PluginCallGraph) extractHookRegistrations(content, filePath string) {
	classRanges := findClassRanges(content)

	// Static hook registrations: add_action('hook', callback)
	for _, match := range hookRegistrationPattern.FindAllStringSubmatchIndex(content, -1) {
		hookName := content[match[2]:match[3]]
		callbackExpr := strings.TrimSpace(content[match[4]:match[5]])
		className := findEnclosingClass(match[0], classRanges)

		resolved := resolveHookCallback(callbackExpr, className)
		if resolved == "" {
			continue
		}

		cg.HookRegistry.mu.Lock()
		cg.HookRegistry.Hooks[hookName] = append(cg.HookRegistry.Hooks[hookName], HookRegistration{
			Callback: resolved,
			File:     filePath,
		})
		cg.HookRegistry.mu.Unlock()
	}

	// Dynamic/concatenated hook registrations: add_action('prefix_' . $var, callback)
	for _, match := range hookRegistrationDynamicPattern.FindAllStringSubmatchIndex(content, -1) {
		prefix := content[match[2]:match[3]]
		callbackExpr := strings.TrimSpace(content[match[4]:match[5]])
		className := findEnclosingClass(match[0], classRanges)

		resolved := resolveHookCallback(callbackExpr, className)
		if resolved == "" {
			continue
		}

		cg.HookRegistry.mu.Lock()
		cg.HookRegistry.PrefixHooks[prefix] = append(cg.HookRegistry.PrefixHooks[prefix], HookRegistration{
			Callback: resolved,
			File:     filePath,
		})
		cg.HookRegistry.mu.Unlock()
	}

	// Shortcode registrations: add_shortcode('tag', callback)
	for _, match := range shortcodeRegistrationPattern.FindAllStringSubmatchIndex(content, -1) {
		tag := content[match[2]:match[3]]
		callbackExpr := strings.TrimSpace(content[match[4]:match[5]])
		className := findEnclosingClass(match[0], classRanges)

		resolved := resolveHookCallback(callbackExpr, className)
		if resolved == "" {
			continue
		}

		hookName := "shortcode::" + tag
		cg.HookRegistry.mu.Lock()
		cg.HookRegistry.Hooks[hookName] = append(cg.HookRegistry.Hooks[hookName], HookRegistration{
			Callback: resolved,
			File:     filePath,
		})
		cg.HookRegistry.mu.Unlock()
	}
}

// resolveHookCallback resolves a callback expression to a function/method name.
func resolveHookCallback(expr, currentClass string) string {
	expr = strings.TrimSpace(expr)

	// String callback: 'function_name'
	if (strings.HasPrefix(expr, "'") || strings.HasPrefix(expr, "\"")) &&
		(strings.HasSuffix(expr, "'") || strings.HasSuffix(expr, "\"")) {
		return strings.Trim(expr, "'\"")
	}

	// Array callback with $this: [$this, 'method'] or array($this, 'method')
	if strings.Contains(expr, "$this") {
		methodMatch := arrayMethodNamePattern.FindStringSubmatch(expr)
		if len(methodMatch) > 1 && currentClass != "" {
			return currentClass + "::" + methodMatch[1]
		}
		if len(methodMatch) > 1 {
			return methodMatch[1]
		}
	}

	// self/static: [self::class, 'method']
	if strings.Contains(expr, "self") || strings.Contains(expr, "static::") {
		methodMatch := arrayMethodNamePattern.FindStringSubmatch(expr)
		if len(methodMatch) > 1 && currentClass != "" {
			return currentClass + "::" + methodMatch[1]
		}
	}

	// Array/static callback: [ClassName::class, 'method'] or ['ClassName', 'method']
	if strings.Contains(expr, "::class") || strings.Contains(expr, "[") || strings.Contains(expr, "array(") {
		parts := arrayMethodNamePattern.FindAllStringSubmatch(expr, -1)
		if len(parts) >= 1 {
			method := parts[len(parts)-1][1]
			classMatch := hookCallbackClassPattern.FindStringSubmatch(expr)
			if len(classMatch) > 1 {
				cls := classMatch[1]
				if cls == "" {
					cls = classMatch[2]
				}
				if cls != "" {
					return cls + "::" + method
				}
			}
			return method
		}
	}

	// Variable callback — skip
	if strings.HasPrefix(expr, "$") {
		return ""
	}

	// Bare function name
	if cleanFunctionNamePattern.MatchString(expr) {
		return expr
	}

	return ""
}

// findEnclosingClass determines which class (if any) contains a given byte position.
func findEnclosingClass(pos int, classRanges map[string][2]int) string {
	className := ""
	smallestRange := int(^uint(0) >> 1)
	for cn, bounds := range classRanges {
		if pos > bounds[0] && pos < bounds[1] {
			rangeSize := bounds[1] - bounds[0]
			if rangeSize < smallestRange {
				smallestRange = rangeSize
				className = cn
			}
		}
	}
	return className
}

// discoverTraitUsage finds `use TraitName;` inside class bodies and aliases
// the trait's methods as class methods in the call graph.
func (cg *PluginCallGraph) discoverTraitUsage(content string, classRanges map[string][2]int) {
	matches := traitUsePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		traitList := content[match[2]:match[3]]
		className := findEnclosingClass(match[0], classRanges)
		if className == "" {
			continue
		}

		traits := strings.Split(traitList, ",")
		for _, trait := range traits {
			traitName := strings.TrimSpace(trait)
			if idx := strings.LastIndex(traitName, "\\"); idx >= 0 {
				traitName = traitName[idx+1:]
			}

			cg.mu.Lock()
			for key, calls := range cg.CallsFrom {
				if strings.HasPrefix(key, traitName+"::") {
					methodName := key[len(traitName)+2:]
					classKey := className + "::" + methodName
					if _, hasOwn := cg.CallsFrom[classKey]; !hasOwn {
						cg.CallsFrom[classKey] = calls
						if funcDef, ok := cg.Functions[key]; ok {
							cg.Functions[classKey] = funcDef
						}
					}
				}
			}
			cg.mu.Unlock()
		}
	}
}

// GetReachableFiles returns the set of file paths reachable from an endpoint callback.
// It follows function calls, class references, and include/require edges transitively.
func (cg *PluginCallGraph) GetReachableFiles(callback, callbackFile string) map[string]bool {
	reachable := make(map[string]bool)
	reachable[callbackFile] = true

	callback = ResolveCallback(callback, "")
	if callback == "" || callback == "unknown" || callback == "inline" || callback == "closure" {
		return reachable
	}

	visited := make(map[string]bool)
	cg.collectReachableFiles(callback, visited, reachable)

	// Also collect files from hook registry callbacks reachable via the call chain
	cg.HookRegistry.mu.RLock()
	for _, reg := range cg.HookRegistry.allHookCallbackFiles() {
		if visited[reg.Callback] {
			reachable[reg.File] = true
		}
	}
	cg.HookRegistry.mu.RUnlock()

	cg.followIncludes(reachable)

	return reachable
}

// collectReachableFiles recursively follows the call graph adding files of reached functions.
func (cg *PluginCallGraph) collectReachableFiles(funcName string, visited map[string]bool, reachable map[string]bool) {
	if visited[funcName] || phpKeywords[funcName] {
		return
	}
	visited[funcName] = true

	// Strip PHP namespace prefix for call graph lookup (e.g., "YayExtra\\plugins_loaded" -> "plugins_loaded")
	bareName := funcName
	if idx := strings.LastIndex(funcName, "\\"); idx >= 0 {
		bareName = funcName[idx+1:]
	}

	cg.mu.RLock()

	// Add file where this function is defined (try FQN first, then bare name)
	if def, ok := cg.Functions[funcName]; ok && def.FilePath != "" {
		reachable[def.FilePath] = true
	} else if bareName != funcName {
		if def, ok := cg.Functions[bareName]; ok && def.FilePath != "" {
			reachable[def.FilePath] = true
		}
	}

	// Resolve class-to-file for Class::method patterns
	if idx := strings.Index(bareName, "::"); idx > 0 {
		className := bareName[:idx]
		if file, ok := cg.ClassToFile[className]; ok {
			reachable[file] = true
		}
	}
	// Also check bare name as a class (from `new ClassName()` calls)
	if file, ok := cg.ClassToFile[bareName]; ok {
		reachable[file] = true
	}
	if bareName != funcName {
		if file, ok := cg.ClassToFile[funcName]; ok {
			reachable[file] = true
		}
	}
	// PSR-4 autoload resolution for namespaced references (uses locked state)
	if strings.Contains(funcName, "\\") {
		resolved := cg.resolvePSR4Locked(funcName)
		if resolved != "" {
			reachable[resolved] = true
		}
	}

	// Get calls from this function (try FQN, then bare name, then method-only)
	calls, found := cg.CallsFrom[funcName]
	if !found && bareName != funcName {
		calls, found = cg.CallsFrom[bareName]
	}
	if !found {
		methodOnly := bareName
		if idx := strings.LastIndex(bareName, "::"); idx >= 0 {
			methodOnly = bareName[idx+2:]
		}
		if methodOnly != bareName {
			calls, found = cg.CallsFrom[methodOnly]
		}
	}

	// Also check ambiguous implementations
	ambiguousKeys := cg.AmbiguousFuncs[funcName]
	if len(ambiguousKeys) == 0 && bareName != funcName {
		ambiguousKeys = cg.AmbiguousFuncs[bareName]
	}

	cg.mu.RUnlock()

	if found {
		for _, call := range calls {
			cg.collectReachableFiles(call, visited, reachable)
		}
	}

	// Follow ambiguous implementations too
	for _, qualKey := range ambiguousKeys {
		cg.mu.RLock()
		if def, ok := cg.Functions[qualKey]; ok && def.FilePath != "" {
			reachable[def.FilePath] = true
		}
		extraCalls := cg.CallsFrom[qualKey]
		cg.mu.RUnlock()

		for _, call := range extraCalls {
			cg.collectReachableFiles(call, visited, reachable)
		}
	}
}

// followIncludes performs BFS through include edges from all reachable files.
func (cg *PluginCallGraph) followIncludes(reachable map[string]bool) {
	queue := make([]string, 0, len(reachable))
	for f := range reachable {
		queue = append(queue, f)
	}

	cg.mu.RLock()
	defer cg.mu.RUnlock()

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, inc := range cg.IncludesFrom[current] {
			// Always try to resolve to an actual file in the plugin
			resolved := cg.resolveIncludePath(inc)
			if resolved != "" {
				if !reachable[resolved] {
					reachable[resolved] = true
					queue = append(queue, resolved)
				}
			} else if !reachable[inc] {
				// Store raw path for downstream matching
				reachable[inc] = true
				queue = append(queue, inc)
			}
		}
	}
}

// resolveIncludePath tries to match an include path to a known file via basename + suffix matching.
func (cg *PluginCallGraph) resolveIncludePath(path string) string {
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimPrefix(path, "./")
	base := filepath.Base(path)
	candidates := cg.FilesByBasename[base]

	// Try exact suffix match first
	for _, candidate := range candidates {
		if strings.HasSuffix(candidate, "/"+path) || candidate == path {
			return candidate
		}
	}
	// Fall back to basename-only match if there's exactly one candidate
	if len(candidates) == 1 {
		return candidates[0]
	}
	return ""
}

// allHookCallbackFiles returns all hook registrations from both exact and prefix maps.
func (cg *HookRegistry) allHookCallbackFiles() []HookRegistration {
	var all []HookRegistration
	for _, regs := range cg.Hooks {
		all = append(all, regs...)
	}
	for _, regs := range cg.PrefixHooks {
		all = append(all, regs...)
	}
	return all
}

// wpCoreHTTPHooks are WordPress hooks that fire on every HTTP request.
// Callbacks registered for these are implicitly reachable.
var wpCoreHTTPHooks = map[string]bool{
	"plugins_loaded": true, "muplugins_loaded": true,
	"init": true, "wp_loaded": true, "wp": true,
	"admin_init": true, "admin_menu": true, "admin_bar_menu": true,
	"rest_api_init": true, "parse_request": true,
	"template_redirect": true, "template_include": true,
	"wp_head": true, "wp_footer": true, "admin_head": true, "admin_footer": true,
	"wp_enqueue_scripts": true, "admin_enqueue_scripts": true,
	"widgets_init": true, "after_setup_theme": true,
	"shutdown": true, "wp_ajax_": true,
	"woocommerce_init": true, "woocommerce_loaded": true,
	"elementor/widgets/register": true, "elementor/init": true,
	"acf/init": true, "acf/include_field_types": true,
}

// GetAllHTTPReachableFiles returns files reachable from detected endpoints AND
// WordPress core hooks that fire on every HTTP request.
func (cg *PluginCallGraph) GetAllHTTPReachableFiles(endpoints []models.Endpoint) map[string]bool {
	reachable := make(map[string]bool)

	// Start from all endpoint callbacks
	for _, ep := range endpoints {
		epReachable := cg.GetReachableFiles(ep.Callback, ep.File)
		for f := range epReachable {
			reachable[f] = true
		}
	}

	// Start from WordPress core hooks — callbacks registered for these are always reachable
	cg.HookRegistry.mu.RLock()
	for hookName, regs := range cg.HookRegistry.Hooks {
		if wpCoreHTTPHooks[hookName] {
			for _, reg := range regs {
				hookReachable := cg.GetReachableFiles(reg.Callback, reg.File)
				for f := range hookReachable {
					reachable[f] = true
				}
			}
		}
	}
	// Also check prefix hooks (e.g., add_action('wp_ajax_' . $action, ...))
	for prefix, regs := range cg.HookRegistry.PrefixHooks {
		for coreHook := range wpCoreHTTPHooks {
			if strings.HasPrefix(prefix, coreHook) || strings.HasPrefix(coreHook, prefix) {
				for _, reg := range regs {
					hookReachable := cg.GetReachableFiles(reg.Callback, reg.File)
					for f := range hookReachable {
						reachable[f] = true
					}
				}
				break
			}
		}
	}
	cg.HookRegistry.mu.RUnlock()

	// Mark all files included from the plugin root file(s) as reachable
	// (main plugin file is always loaded by WordPress)
	for fp := range cg.AllFiles {
		if !strings.Contains(fp, "/") {
			reachable[fp] = true
		}
	}
	cg.followIncludes(reachable)

	return reachable
}

// --- Dynamic includer detection and function-arg-to-file resolution ---

// extractDynIncluders scans for functions whose body contains variable includes.
func (cg *PluginCallGraph) extractDynIncluders(content, filePath string) {
	classRanges := findClassRanges(content)
	matches := funcDefPattern.FindAllStringSubmatchIndex(content, -1)

	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		funcName := content[match[2]:match[3]]
		bodyStart := match[1] - 1
		endPos := findMatchingBrace(content, bodyStart)
		if endPos < 0 {
			continue
		}
		body := content[bodyStart:endPos]

		if !dynamicIncludeVarPattern.MatchString(body) {
			continue
		}

		className := findEnclosingClass(match[0], classRanges)
		key := funcName
		if className != "" {
			key = className + "::" + funcName
		}

		hints := extractDirHints(body, filePath)

		cg.mu.Lock()
		cg.DynIncluders[key] = hints
		if className != "" {
			cg.DynIncluders[funcName] = hints
		}
		cg.mu.Unlock()
	}
}

func extractDirHints(body, filePath string) []string {
	hints := make([]string, 0, 4)
	matches := dirHintPattern.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		hint := filepath.ToSlash(m[1])
		hint = strings.Trim(hint, "/")
		if hint != "" && !strings.HasPrefix(hint, "http") && !strings.HasPrefix(hint, "//") {
			hints = append(hints, hint)
		}
	}
	hints = append(hints, filepath.ToSlash(filepath.Dir(filePath)))
	return hints
}

// extractDynIncludeEdges scans file content for calls to dynamic includers with string args.
func (cg *PluginCallGraph) extractDynIncludeEdges(content, filePath string) {
	matches := funcWithStringArgPattern.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		var funcName, arg string
		switch {
		case m[1] != "" && m[2] != "":
			funcName, arg = m[1], m[2]
		case m[3] != "" && m[4] != "":
			funcName, arg = m[3], m[4]
		case m[5] != "" && m[6] != "" && m[7] != "":
			funcName = m[5] + "::" + m[6]
			arg = m[7]
		default:
			continue
		}

		cg.mu.RLock()
		hints, isIncluder := cg.DynIncluders[funcName]
		cg.mu.RUnlock()
		if !isIncluder {
			continue
		}

		resolved := cg.resolveArgToFile(arg, hints)
		if resolved != "" {
			cg.mu.Lock()
			cg.IncludesFrom[filePath] = append(cg.IncludesFrom[filePath], resolved)
			cg.mu.Unlock()
		}
	}
}

func (cg *PluginCallGraph) resolveArgToFile(arg string, dirHints []string) string {
	arg = strings.TrimSpace(arg)

	candidates := []string{arg}
	if !strings.HasSuffix(arg, ".php") {
		candidates = append(candidates, arg+".php")
		candidates = append(candidates, arg+".html.php")
	}

	cg.mu.RLock()
	defer cg.mu.RUnlock()

	for _, candidate := range candidates {
		base := filepath.Base(candidate)
		paths := cg.FilesByBasename[base]

		if len(paths) == 1 {
			return paths[0]
		}

		normalizedCandidate := filepath.ToSlash(candidate)
		for _, hint := range dirHints {
			suffixPath := filepath.ToSlash(filepath.Join(hint, normalizedCandidate))
			for _, p := range paths {
				if strings.HasSuffix(p, "/"+suffixPath) || p == suffixPath {
					return p
				}
			}
			for _, p := range paths {
				if strings.HasSuffix(p, "/"+normalizedCandidate) {
					return p
				}
			}
		}

		for fp := range cg.AllFiles {
			if strings.HasSuffix(fp, "/"+normalizedCandidate) || fp == normalizedCandidate {
				return fp
			}
		}
	}
	return ""
}

func (cg *PluginCallGraph) extractAutoloadHints(content, filePath string) {
	if !strings.Contains(content, "spl_autoload_register") {
		return
	}

	baseDirPat := regexp.MustCompile(
		`\$[a-zA-Z_]+\s*=\s*(?:__DIR__|dirname\s*\([^)]+\))\s*\.\s*['"]([^'"]+)['"]`,
	)
	for _, m := range baseDirPat.FindAllStringSubmatch(content, -1) {
		if m[1] != "" {
			dir := filepath.ToSlash(strings.Trim(m[1], "/"))
			baseDir := filepath.ToSlash(filepath.Join(filepath.Dir(filePath), dir))
			cg.mu.Lock()
			cg.AutoloadBaseDirs = append(cg.AutoloadBaseDirs, baseDir)
			cg.mu.Unlock()
		}
	}

	cg.mu.Lock()
	cg.AutoloadBaseDirs = append(cg.AutoloadBaseDirs, filepath.ToSlash(filepath.Dir(filePath)))
	cg.mu.Unlock()
}

func (cg *PluginCallGraph) resolvePSR4(fqn string) string {
	cg.mu.RLock()
	defer cg.mu.RUnlock()
	return cg.resolvePSR4Locked(fqn)
}

// resolvePSR4Locked converts a FQN to a file path. Caller must hold cg.mu.RLock.
// Handles both namespace\Class and Prefix_Underscore_Class conventions.
func (cg *PluginCallGraph) resolvePSR4Locked(fqn string) string {
	// Try namespace-to-directory (PSR-4): Vendor\Package\Class -> Vendor/Package/Class.php
	relPath := strings.ReplaceAll(fqn, "\\", "/") + ".php"

	for _, baseDir := range cg.AutoloadBaseDirs {
		candidate := filepath.ToSlash(filepath.Join(baseDir, relPath))
		if cg.AllFiles[candidate] {
			return candidate
		}
		if idx := strings.Index(relPath, "/"); idx > 0 {
			stripped := relPath[idx+1:]
			candidate = filepath.ToSlash(filepath.Join(baseDir, stripped))
			if cg.AllFiles[candidate] {
				return candidate
			}
			if idx2 := strings.Index(stripped, "/"); idx2 > 0 {
				candidate = filepath.ToSlash(filepath.Join(baseDir, stripped[idx2+1:]))
				if cg.AllFiles[candidate] {
					return candidate
				}
			}
		}
	}

	// Namespace-to-directory basename match
	parts := strings.Split(relPath, "/")
	className := parts[len(parts)-1]
	if paths, ok := cg.FilesByBasename[className]; ok {
		if len(paths) == 1 {
			return paths[0]
		}
		for segs := len(parts); segs >= 2; segs-- {
			suffix := strings.Join(parts[len(parts)-segs:], "/")
			for _, p := range paths {
				if strings.HasSuffix(p, "/"+suffix) || p == suffix {
					return p
				}
			}
		}
	}

	// WordPress convention: underscore-to-directory (Prefix_Module_Class -> Prefix/Module/Class.php)
	if strings.Contains(fqn, "_") && !strings.Contains(fqn, "\\") {
		underscorePath := strings.ReplaceAll(fqn, "_", "/") + ".php"
		for _, baseDir := range cg.AutoloadBaseDirs {
			candidate := filepath.ToSlash(filepath.Join(baseDir, underscorePath))
			if cg.AllFiles[candidate] {
				return candidate
			}
		}
		// Also try with "classes/" prefix (common Visualizer pattern)
		uParts := strings.Split(underscorePath, "/")
		uClassName := uParts[len(uParts)-1]
		if paths, ok := cg.FilesByBasename[uClassName]; ok {
			if len(paths) == 1 {
				return paths[0]
			}
			for segs := len(uParts); segs >= 2; segs-- {
				suffix := strings.Join(uParts[len(uParts)-segs:], "/")
				for _, p := range paths {
					if strings.HasSuffix(p, "/"+suffix) || p == suffix {
						return p
					}
				}
			}
		}
	}

	// Kebab-case convention: Underscore_Name -> underscore-name.php
	if strings.Contains(fqn, "_") {
		lastPart := fqn
		if idx := strings.LastIndex(fqn, "\\"); idx >= 0 {
			lastPart = fqn[idx+1:]
		}
		kebab := strings.ToLower(strings.ReplaceAll(lastPart, "_", "-")) + ".php"
		if paths, ok := cg.FilesByBasename[kebab]; ok {
			if len(paths) == 1 {
				return paths[0]
			}
		}
	}

	return ""
}

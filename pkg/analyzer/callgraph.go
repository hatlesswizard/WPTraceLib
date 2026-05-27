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
	StartLine  int    // Line where function starts
	EndLine    int    // Line where function ends
	IsMethod   bool   // True if it's a class method
	Visibility string // public, private, protected (for methods)
	// Note: Body field removed for memory optimization.
	// Use CallsFrom map instead of storing/re-extracting function bodies.
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
	mu             sync.RWMutex
}

// NewPluginCallGraph creates a new empty call graph
func NewPluginCallGraph() *PluginCallGraph {
	return &PluginCallGraph{
		Functions:      make(map[string]*FunctionDef),
		CallsFrom:      make(map[string][]string),
		CallsTo:        make(map[string][]string),
		AmbiguousFuncs: make(map[string][]string),
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
func BuildCallGraph(files map[string]string) *PluginCallGraph {
	cg := NewPluginCallGraph()

	// Sort file paths for deterministic processing order
	sortedPaths := make([]string, 0, len(files))
	for fp := range files {
		sortedPaths = append(sortedPaths, fp)
	}
	sort.Strings(sortedPaths)

	// Process files in deterministic order
	for _, fp := range sortedPaths {
		cg.discoverFunctionsAndCalls(files[fp], fp)
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

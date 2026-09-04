package analyzer

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// WrapperDefinition represents a discovered add_action wrapper function/method
type WrapperDefinition struct {
	ClassName      string // Empty for standalone functions
	MethodName     string
	IsStatic       bool
	HookParamIndex int    // Which parameter is the hook name (0-indexed), -1 if unknown
	HookPrefix     string // Prefix the wrapper adds (e.g., "wp_ajax_" if wrapper does add_action('wp_ajax_' . $param, ...))
	SourceFile     string // File where this wrapper was defined
}

// RESTWrapperDefinition represents a wrapper that internally calls register_rest_route()
type RESTWrapperDefinition struct {
	ClassName          string // Class containing the wrapper method
	MethodName         string // Method name (e.g., "init_rest_api_endpoint")
	IsStatic           bool
	SourceFile         string
	ParamNames         []string // method parameter names, ordered
	RouteParamIndex    int      // which param flows into route (-1 if hardcoded)
	MethodsParamIndex  int      // which param flows into HTTP methods (-1 if hardcoded)
	CallbackParamIndex int      // which param flows into callback (-1 if hardcoded)
	// ArgsParamIndex is the parameter that becomes the whole third argument of
	// register_rest_route -- the endpoint descriptor. A wrapper shaped that way
	// says nothing about the route's methods, callback or permission callback:
	// they are written at the CALL SITE, in the array the caller passes.
	ArgsParamIndex int
	// RouteLiteral is the route the wrapper hardcodes, for a wrapper that
	// parameterises something other than the route.
	RouteLiteral      string
	UsesThisNamespace bool   // body references $this->namespace for the namespace arg
	PermCallbackBody  string // extracted permission_callback body (for auth inference)
}

// WrapperRegistry holds all discovered wrappers for a plugin
type WrapperRegistry struct {
	Wrappers     []WrapperDefinition
	RESTWrappers []RESTWrapperDefinition
}

// PHP identifier grammar, used wherever this file has to recognise the name of
// a declaration. The language's rule is [a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*
// -- no case rule at all, and every byte from 0x80 up is a letter -- which in
// UTF-8 source is every non-ASCII rune.
const (
	phpIdentifier    = `[a-zA-Z_\x{0080}-\x{10FFFF}][a-zA-Z0-9_\x{0080}-\x{10FFFF}]*`
	phpQualifiedName = `\\?` + phpIdentifier + `(?:\\` + phpIdentifier + `)*`
)

// Compiled patterns for wrapper discovery (Pass 1)
var (
	// Pattern to find class-like declarations and the body they open.
	//
	// The name is matched with PHP's own identifier grammar rather than with
	// `[A-Z]...`. Capitalising a class name is a convention of some projects,
	// not a rule of the language, and requiring it made every method of the
	// 1,300-odd lowercase- or underscore-initial classes in a third of the
	// corpus's trees invisible to wrapper discovery.
	//
	// Traits and interfaces open an extent for the same reason a class does: a
	// method declared inside one is not a top-level function, and calling it a
	// top-level function makes the analyzer hunt its call sites under the wrong
	// spelling.
	wrapperClassDeclPattern = regexp.MustCompile(
		`(?:\b(?:abstract|final|readonly)\s+)*\b(?:class|trait|interface)\s+(` + phpIdentifier + `)\s*` +
			`(?:extends\s+` + phpQualifiedName + `(?:\s*,\s*` + phpQualifiedName + `)*\s*)?` +
			`(?:implements\s+[^{;]*)?\{`,
	)

	// Pattern to find method declarations with modifiers
	// public static function methodName(...) or function methodName(...)
	wrapperMethodDeclPattern = regexp.MustCompile(
		`(?:(?:public|protected|private)\s+)?(?:(static)\s+)?function\s+(` + phpIdentifier + `)\s*\(([^)]*)\)`,
	)

	// Pattern to find standalone function declarations (not inside a class)
	wrapperFunctionDeclPattern = regexp.MustCompile(
		`(?:^|\n)\s*function\s+(` + phpIdentifier + `)\s*\(([^)]*)\)`,
	)

	// Pattern to find add_action calls inside function body
	wrapperAddActionCallPattern = regexp.MustCompile(
		`\badd_action\s*\(\s*\$([a-zA-Z_][a-zA-Z0-9_]*)`,
	)

	// Pattern to find add_filter calls inside function body (filters can also be hooks)
	wrapperAddFilterCallPattern = regexp.MustCompile(
		`\badd_filter\s*\(\s*\$([a-zA-Z_][a-zA-Z0-9_]*)`,
	)

	// Patterns for wrappers that use concatenation: add_action('wp_ajax_' . $param, ...)
	// These wrappers internally prepend the AJAX prefix
	wrapperConcatAjaxPattern = regexp.MustCompile(
		`\badd_action\s*\(\s*['"]wp_ajax_['"]\s*\.\s*\$([a-zA-Z_][a-zA-Z0-9_]*)`,
	)
	wrapperConcatAjaxNoprivPattern = regexp.MustCompile(
		`\badd_action\s*\(\s*['"]wp_ajax_nopriv_['"]\s*\.\s*\$([a-zA-Z_][a-zA-Z0-9_]*)`,
	)
	wrapperConcatAdminPostPattern = regexp.MustCompile(
		`\badd_action\s*\(\s*['"]admin_post_['"]\s*\.\s*\$([a-zA-Z_][a-zA-Z0-9_]*)`,
	)
	wrapperConcatAdminPostNoprivPattern = regexp.MustCompile(
		`\badd_action\s*\(\s*['"]admin_post_nopriv_['"]\s*\.\s*\$([a-zA-Z_][a-zA-Z0-9_]*)`,
	)
	// Pattern for wc_ajax_ (WooCommerce AJAX) wrappers
	wrapperConcatWcAjaxPattern = regexp.MustCompile(
		`\badd_action\s*\(\s*['"]wc_ajax_['"]\s*\.\s*\$([a-zA-Z_][a-zA-Z0-9_]*)`,
	)
)

// wrapperClassExtent is one class, trait or interface declaration together with
// the region its body actually covers.
type wrapperClassExtent struct {
	name string
	open int // offset of the body's '{'
	end  int // offset one past the matching '}'
}

// findWrapperClassExtents locates every class-like declaration in content and
// the extent of its body.
//
// The extent runs to the matching brace, not to the start of the next
// declaration. Ending a class where the next one begins is wrong twice over:
// nested declarations lose their real bounds, and every top-level function
// declared after the last class in its file -- 1,270 of them across 316 files
// in a 143-plugin corpus -- was attributed to that class. That attribution is
// not harmless: a wrapper believed to be a method is hunted at call sites as
// `$var->name(`, so a wrapper that is really a plain function matches nothing.
func findWrapperClassExtents(content string) []wrapperClassExtent {
	matches := wrapperClassDeclPattern.FindAllStringSubmatchIndex(content, -1)
	out := make([]wrapperClassExtent, 0, len(matches))
	for _, m := range matches {
		// The pattern ends with `\{`, so the match already consumed the body's
		// opening brace.
		open := m[1] - 1
		if open < 0 || open >= len(content) || content[open] != '{' {
			continue
		}
		end := matchBrace(content, open)
		if end < 0 {
			// Unbalanced: we cannot say where this declaration ends. Omitting
			// it lets its methods fall through to the standalone branch, whose
			// call-site pattern is the broader of the two, so the failure is in
			// the direction that finds more rather than less.
			continue
		}
		out = append(out, wrapperClassExtent{name: content[m[2]:m[3]], open: open, end: end})
	}
	return out
}

// classAt names the innermost class-like extent containing pos, or "" when pos
// is at the top level of the file.
//
// Innermost, not first in document order: brace-matched extents nest, and a
// declaration inside a class declared inside another belongs to the inner one.
func classAt(extents []wrapperClassExtent, pos int) string {
	name := ""
	best := -1
	for _, e := range extents {
		if pos <= e.open || pos >= e.end {
			continue
		}
		if size := e.end - e.open; best < 0 || size < best {
			best = size
			name = e.name
		}
	}
	return name
}

// declBodyOpen returns the offset of the '{' opening the body of a declaration
// whose parameter list ends at parenEnd, or -1 when the declaration has no body.
//
// An abstract or interface method ends in ';'. Scanning forward for the next
// '{' found a LATER declaration's body and read it as this one's, so a class
// with an abstract method could be credited with a body it does not have.
func declBodyOpen(content string, parenEnd int) int {
	for i := parenEnd; i < len(content); i++ {
		switch content[i] {
		case '{':
			return i
		case ';':
			return -1
		}
	}
	return -1
}

// DiscoverWrappers scans a file for function/method definitions containing add_action
// This is PASS 1 - discovering wrapper definitions
func DiscoverWrappers(content, filepath string) []WrapperDefinition {
	var wrappers []WrapperDefinition

	// Step 1: Find every class-like declaration and the extent of its body
	classes := findWrapperClassExtents(content)

	// Step 2: Find all method declarations
	methodMatches := wrapperMethodDeclPattern.FindAllStringSubmatchIndex(content, -1)

	for _, match := range methodMatches {
		methodPos := match[0]
		isStatic := match[2] != -1 && match[3] != -1 // Group 1: static keyword
		methodName := ""
		params := ""

		if match[4] != -1 && match[5] != -1 {
			methodName = content[match[4]:match[5]]
		}
		if match[6] != -1 && match[7] != -1 {
			params = content[match[6]:match[7]]
		}

		if methodName == "" {
			continue
		}

		// Find which class this method belongs to
		className := classAt(classes, methodPos)

		// Skip if not in a class (will be handled by standalone function detection)
		if className == "" {
			continue
		}

		// Step 3: Extract the method body (find matching braces)
		bodyStart := declBodyOpen(content, match[1])
		if bodyStart == -1 {
			continue
		}

		body := extractBraceBlock(content, bodyStart)
		if body == "" {
			continue
		}

		// Step 4: Check if body contains add_action patterns
		hookParamVar, hookPrefix := findWrapperAddActionPattern(body)
		if hookParamVar == "" {
			continue
		}

		// Step 5: Determine which parameter maps to the hook name
		hookParamIndex := findParameterIndex(params, hookParamVar)

		// Only add if we successfully identified the hook parameter
		// Wrappers with HookParamIndex == -1 are unreliable and cause false positives
		if hookParamIndex >= 0 {
			wrapper := WrapperDefinition{
				ClassName:      className,
				MethodName:     methodName,
				IsStatic:       isStatic,
				HookParamIndex: hookParamIndex,
				HookPrefix:     hookPrefix,
				SourceFile:     filepath,
			}
			wrappers = append(wrappers, wrapper)
		}
	}

	// Step 3b: Find standalone functions (not in any class)
	funcMatches := wrapperFunctionDeclPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range funcMatches {
		funcPos := match[0]
		funcName := ""
		params := ""

		if match[2] != -1 && match[3] != -1 {
			funcName = content[match[2]:match[3]]
		}
		if match[4] != -1 && match[5] != -1 {
			params = content[match[4]:match[5]]
		}

		if funcName == "" {
			continue
		}

		// Check if this function is inside any class (skip if so)
		if classAt(classes, funcPos) != "" {
			continue
		}

		// Extract function body
		bodyStart := declBodyOpen(content, match[1])
		if bodyStart == -1 {
			continue
		}

		body := extractBraceBlock(content, bodyStart)
		if body == "" {
			continue
		}

		// Check for add_action/add_filter patterns
		hookParamVar, hookPrefix := findWrapperAddActionPattern(body)
		if hookParamVar == "" {
			continue
		}

		hookParamIndex := findParameterIndex(params, hookParamVar)

		// Only add if we successfully identified the hook parameter
		if hookParamIndex >= 0 {
			wrapper := WrapperDefinition{
				ClassName:      "", // Standalone function
				MethodName:     funcName,
				IsStatic:       false,
				HookParamIndex: hookParamIndex,
				HookPrefix:     hookPrefix,
				SourceFile:     filepath,
			}
			wrappers = append(wrappers, wrapper)
		}
	}

	return wrappers
}

// findWrapperAddActionPattern checks a function body for add_action patterns
// Returns: (variableName, hookPrefix) - hookPrefix is empty for generic wrappers
// For concatenation patterns like add_action('wp_ajax_' . $param, ...), returns ("param", "wp_ajax_")
func findWrapperAddActionPattern(body string) (string, string) {
	// First check for concatenation patterns (more specific)
	// These are wrappers that internally add the AJAX prefix

	// wp_ajax_nopriv_ must be checked before wp_ajax_ to avoid partial matches
	if match := wrapperConcatAjaxNoprivPattern.FindStringSubmatch(body); match != nil {
		return match[1], "wp_ajax_nopriv_"
	}
	if match := wrapperConcatAjaxPattern.FindStringSubmatch(body); match != nil {
		return match[1], "wp_ajax_"
	}
	if match := wrapperConcatAdminPostNoprivPattern.FindStringSubmatch(body); match != nil {
		return match[1], "admin_post_nopriv_"
	}
	if match := wrapperConcatAdminPostPattern.FindStringSubmatch(body); match != nil {
		return match[1], "admin_post_"
	}
	if match := wrapperConcatWcAjaxPattern.FindStringSubmatch(body); match != nil {
		return match[1], "wc_ajax_"
	}

	// Check for generic variable patterns: add_action($hook, ...)
	if match := wrapperAddActionCallPattern.FindStringSubmatch(body); match != nil {
		return match[1], ""
	}
	if match := wrapperAddFilterCallPattern.FindStringSubmatch(body); match != nil {
		return match[1], ""
	}

	return "", ""
}

// extractBraceBlock extracts content between { and matching }
func extractBraceBlock(content string, startPos int) string {
	end := matchBrace(content, startPos)
	if end < 0 {
		return ""
	}
	return content[startPos : end+1]
}

// matchBrace returns the offset of the '}' closing the '{' at startPos, or -1
// when the block is unbalanced.
//
// Strings AND comments are skipped. Skipping comments is not cosmetic: an
// apostrophe in a // comment -- "don't", which appears in ordinary WordPress
// source constantly -- opened a string that ran to the next quote character
// anywhere in the file, and every brace between the two vanished from the
// count. A block scanned over raw source therefore ended early, or not at all.
func matchBrace(content string, startPos int) int {
	if startPos >= len(content) || content[startPos] != '{' {
		return -1
	}
	depth := 0
	for i := startPos; i < len(content); i++ {
		switch content[i] {
		case '\'', '"':
			i = skipPHPString(content, i)
		case '/':
			if i+1 < len(content) && (content[i+1] == '/' || content[i+1] == '*') {
				i = skipPHPComment(content, i)
			}
		case '#':
			// `#[` opens a PHP 8 attribute, which is code; a bare `#` opens a
			// comment.
			if i+1 >= len(content) || content[i+1] != '[' {
				i = skipPHPComment(content, i)
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// skipPHPString returns the offset of the quote closing the literal that opens
// at start, or the end of the content when it never closes.
func skipPHPString(content string, start int) int {
	quote := content[start]
	for i := start + 1; i < len(content); i++ {
		if content[i] == '\\' {
			i++ // the escaped character cannot close the literal
			continue
		}
		if content[i] == quote {
			return i
		}
	}
	return len(content)
}

// skipPHPComment returns the offset of the last character of the comment that
// opens at start.
func skipPHPComment(content string, start int) int {
	if start+1 < len(content) && content[start] == '/' && content[start+1] == '*' {
		if end := strings.Index(content[start+2:], "*/"); end >= 0 {
			return start + 2 + end + 1
		}
		return len(content)
	}
	// // and # run to the end of the line.
	if end := strings.IndexByte(content[start:], '\n'); end >= 0 {
		return start + end - 1
	}
	return len(content)
}

// findParameterIndex finds the 0-based index of a parameter by variable name
func findParameterIndex(params, varName string) int {
	// Parse parameters: $tag, $class, $method = '__invoke', ...
	params = strings.TrimSpace(params)
	if params == "" {
		return -1
	}

	// Split by comma, handling default values
	paramList := splitParameters(params)

	for i, param := range paramList {
		param = strings.TrimSpace(param)
		// Extract variable name: $varName or type $varName or $varName = default
		if strings.Contains(param, "$"+varName) {
			// Make sure it's exactly this variable, not $varNameSuffix
			varPattern := regexp.MustCompile(`\$` + regexp.QuoteMeta(varName) + `(?:\s*=|\s*,|\s*$|\s*\))`)
			if varPattern.MatchString(param + " ") {
				return i
			}
		}
	}

	return -1
}

// splitParameters splits parameter string by commas, respecting nested structures
func splitParameters(params string) []string {
	var result []string
	var current strings.Builder
	depth := 0
	inString := false
	stringChar := byte(0)

	for i := 0; i < len(params); i++ {
		c := params[i]

		if !inString && (c == '"' || c == '\'') {
			inString = true
			stringChar = c
			current.WriteByte(c)
			continue
		}
		if inString {
			current.WriteByte(c)
			if c == stringChar && (i == 0 || params[i-1] != '\\') {
				inString = false
			}
			continue
		}

		if c == '(' || c == '[' || c == '{' {
			depth++
			current.WriteByte(c)
		} else if c == ')' || c == ']' || c == '}' {
			depth--
			current.WriteByte(c)
		} else if c == ',' && depth == 0 {
			result = append(result, current.String())
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}

// BuildPluginWrapperRegistry scans all PHP files in a plugin and builds a registry
func BuildPluginWrapperRegistry(pluginPath string) *WrapperRegistry {
	registry := &WrapperRegistry{
		Wrappers:     make([]WrapperDefinition, 0),
		RESTWrappers: make([]RESTWrapperDefinition, 0),
	}

	// Walk all .php files
	filepath.WalkDir(pluginPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Skip vendor and node_modules
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process PHP files
		if !strings.HasSuffix(strings.ToLower(path), ".php") {
			return nil
		}

		// Read file
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Discover wrappers in this file.
		//
		// Comments are removed first. This walk is the one place in the
		// pipeline that reads raw bytes -- every other pass is handed content
		// that analyzeFileWithCache already stripped -- so a class declaration
		// or an add_action written inside a commented-out block was real here
		// and nowhere else. StripPHPComments overwrites with spaces and keeps
		// newlines, so every offset and line number is unchanged.
		contentStr := StripPHPComments(string(content))
		wrappers := DiscoverWrappers(contentStr, path)
		registry.Wrappers = append(registry.Wrappers, wrappers...)

		// Discover REST wrappers in this file
		restWrappers := DiscoverRESTWrappers(contentStr, path)
		registry.RESTWrappers = append(registry.RESTWrappers, restWrappers...)

		return nil
	})

	return registry
}

// Compiled patterns for wrapper usage detection (Pass 2)
var (
	// Pattern for static method calls: ClassName::methodName(...)
	// Built dynamically based on discovered wrappers
	wrapperStaticCallTemplate = `%s\s*::\s*%s\s*\(`

	// Pattern for instance method calls: $var->methodName(...)
	// We can't know the variable name, so we use a generic pattern
	wrapperInstanceCallTemplate = `\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*%s\s*\(`

	// Pattern for function calls: functionName(...)
	wrapperFunctionCallTemplate = `\b%s\s*\(`
)

// DetectWrapperCalls finds calls to discovered wrappers and extracts AJAX endpoints
// This is PASS 2 - using discovered wrappers to find endpoints
func DetectWrapperCalls(content, filePath, pluginSlug string, registry *WrapperRegistry) []models.Endpoint {
	var endpoints []models.Endpoint

	if registry == nil || len(registry.Wrappers) == 0 {
		return endpoints
	}

	for _, wrapper := range registry.Wrappers {
		var callPattern *regexp.Regexp

		if wrapper.ClassName != "" {
			if wrapper.IsStatic {
				// Static method call: ClassName::methodName(
				pattern := regexp.QuoteMeta(wrapper.ClassName) + `\s*::\s*` + regexp.QuoteMeta(wrapper.MethodName) + `\s*\(`
				callPattern = regexp.MustCompile(pattern)
			} else {
				// Instance method call: $var->methodName(
				// Could be $this->methodName( or $instance->methodName(
				pattern := `\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*` + regexp.QuoteMeta(wrapper.MethodName) + `\s*\(`
				callPattern = regexp.MustCompile(pattern)
			}
		} else {
			// Standalone function call: functionName(
			pattern := `\b` + regexp.QuoteMeta(wrapper.MethodName) + `\s*\(`
			callPattern = regexp.MustCompile(pattern)
		}

		// Find all calls to this wrapper
		matches := callPattern.FindAllStringIndex(content, -1)

		for _, match := range matches {
			callStart := match[0]

			// Extract the arguments to the wrapper call
			argsStart := strings.Index(content[callStart:], "(")
			if argsStart == -1 {
				continue
			}
			argsStart += callStart

			// Find the closing parenthesis
			args := extractParenBlock(content, argsStart)
			if args == "" {
				continue
			}

			// Remove the outer parentheses
			if len(args) > 2 {
				args = args[1 : len(args)-1]
			}

			// Split arguments
			argList := splitParameters(args)

			// Get the hook name from the appropriate parameter
			hookParamIdx := wrapper.HookParamIndex
			if hookParamIdx < 0 {
				hookParamIdx = 0 // Default to first parameter
			}
			if hookParamIdx >= len(argList) {
				continue
			}

			hookArg := strings.TrimSpace(argList[hookParamIdx])

			// Extract the hook name (handle both string literals and expressions)
			hookName := extractHookName(hookArg)
			if hookName == "" {
				continue
			}

			// If the wrapper has a HookPrefix, prepend it to the extracted hook name
			// This handles wrappers like registerAjaxEndpoint($action, ...) that internally do
			// add_action('wp_ajax_' . $action, ...)
			if wrapper.HookPrefix != "" {
				// Only prepend if the hook doesn't already have an AJAX prefix
				if !strings.HasPrefix(hookName, "wp_ajax_") &&
					!strings.HasPrefix(hookName, "admin_post_") &&
					!strings.HasPrefix(hookName, "admin_action_") &&
					!strings.HasPrefix(hookName, "wc_ajax_") {
					hookName = wrapper.HookPrefix + hookName
				}
			}

			// Only process AJAX hooks
			if !strings.Contains(hookName, "wp_ajax_") &&
				!strings.Contains(hookName, "admin_post_") &&
				!strings.Contains(hookName, "admin_action_") &&
				!strings.Contains(hookName, "wc_ajax_") {
				continue
			}

			// Determine authentication level
			isNopriv := strings.Contains(hookName, "nopriv_")
			authLevel := models.Subscriber
			if isNopriv {
				authLevel = models.Unauthenticated
			}

			// Extract callback
			callback := "wrapper_callback"
			if len(argList) > hookParamIdx+1 {
				callback = extractCallbackName(strings.TrimSpace(argList[hookParamIdx+1]))
			}

			// Clean up the hook name for display
			displayHook := hookName
			displayHook = strings.Trim(displayHook, "'\"")

			// Calculate line number
			lineNum := strings.Count(content[:callStart], "\n") + 1

			endpoint := models.Endpoint{
				Route:      formatAjaxRoute(displayHook),
				Method:     "POST",
				Type:       models.EndpointTypeAJAX,
				AuthLevel:  authLevel,
				Callback:   callback,
				File:       filePath,
				Line:       lineNum,
				PluginSlug: pluginSlug,
				RawCode:    displayHook,
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// extractParenBlock extracts content between ( and matching )
func extractParenBlock(content string, startPos int) string {
	if startPos >= len(content) || content[startPos] != '(' {
		return ""
	}

	depth := 0
	inString := false
	stringChar := byte(0)

	for i := startPos; i < len(content); i++ {
		c := content[i]

		// Handle string literals
		if !inString && (c == '"' || c == '\'') {
			inString = true
			stringChar = c
			continue
		}
		if inString {
			if c == stringChar && (i == 0 || content[i-1] != '\\') {
				inString = false
			}
			continue
		}

		// Count parentheses
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 {
				return content[startPos : i+1]
			}
		}
	}

	return ""
}

// extractHookName extracts the hook name from an argument
func extractHookName(arg string) string {
	arg = strings.TrimSpace(arg)

	// Handle string literal: 'wp_ajax_action' or "wp_ajax_action"
	if (strings.HasPrefix(arg, "'") && strings.HasSuffix(arg, "'")) ||
		(strings.HasPrefix(arg, "\"") && strings.HasSuffix(arg, "\"")) {
		return strings.Trim(arg, "'\"")
	}

	// Handle concatenation: 'wp_ajax_' . $action or 'wp_ajax_' . self::CONSTANT
	if strings.Contains(arg, ".") {
		// Try to extract string parts
		var parts []string
		for _, part := range strings.Split(arg, ".") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "'") || strings.HasPrefix(part, "\"") {
				parts = append(parts, strings.Trim(part, "'\""))
			} else if strings.Contains(part, "::") {
				// Class constant: ClassName::CONSTANT -> {CONSTANT}
				constParts := strings.Split(part, "::")
				if len(constParts) == 2 {
					parts = append(parts, "{"+strings.TrimSpace(constParts[1])+"}")
				}
			} else if strings.HasPrefix(part, "$this->") {
				// Property: $this->property -> {property}
				prop := strings.TrimPrefix(part, "$this->")
				parts = append(parts, "{"+prop+"}")
			} else if strings.HasPrefix(part, "$") {
				// Variable: $var -> {var}
				varName := strings.TrimPrefix(part, "$")
				parts = append(parts, "{"+varName+"}")
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "")
		}
	}

	// If it's just a variable, return with placeholder
	if strings.HasPrefix(arg, "$") {
		return "wp_ajax_{" + strings.TrimPrefix(arg, "$") + "}"
	}

	return arg
}

// extractCallbackName extracts the callback function/method name from an argument
func extractCallbackName(arg string) string {
	arg = strings.TrimSpace(arg)

	// Simple string: 'callback_function'
	if (strings.HasPrefix(arg, "'") && strings.HasSuffix(arg, "'")) ||
		(strings.HasPrefix(arg, "\"") && strings.HasSuffix(arg, "\"")) {
		return strings.Trim(arg, "'\"")
	}

	// Array notation: [$this, 'method'] or array($this, 'method')
	if strings.HasPrefix(arg, "[") || strings.HasPrefix(arg, "array(") {
		// Find method name in quotes
		if idx := strings.LastIndex(arg, "'"); idx != -1 {
			start := strings.LastIndex(arg[:idx], "'")
			if start != -1 && start < idx {
				return arg[start+1 : idx]
			}
		}
		if idx := strings.LastIndex(arg, "\""); idx != -1 {
			start := strings.LastIndex(arg[:idx], "\"")
			if start != -1 && start < idx {
				return arg[start+1 : idx]
			}
		}
	}

	// ClassName::class pattern: Extract class name
	if strings.Contains(arg, "::class") {
		parts := strings.Split(arg, "::")
		if len(parts) >= 1 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Variable or complex expression
	if strings.HasPrefix(arg, "$") {
		return "dynamic_callback"
	}

	// Function or closure
	if strings.HasPrefix(arg, "function") {
		return "closure"
	}

	return "callback"
}

// --- REST Wrapper Detection ---

// Compiled patterns for REST wrapper discovery
var (
	// Detects register_rest_route() inside a method body
	wrapperRegisterRestRoutePattern = regexp.MustCompile(
		`\bregister_rest_route\s*\(`,
	)

	// Extracts use() clause variables from a closure
	wrapperClosureUsePattern = regexp.MustCompile(
		`function\s*\([^)]*\)\s*use\s*\(\s*([^)]+)\)`,
	)

	// Extracts the three arguments of register_rest_route(namespace, route, args).
	//
	// The third argument may be a variable as well as a literal array. Requiring
	// a literal there discarded every wrapper that takes the endpoint
	// descriptor as a parameter and forwards it -- a route factory by any
	// reading, and one whose callback is perfectly resolvable, because it is
	// written out at the call site.
	wrapperRestRouteArgsPattern = regexp.MustCompile(
		`register_rest_route\s*\(\s*` +
			`([^,]+?)\s*,\s*` +
			`([^,]+?)\s*,\s*` +
			`(\[|array\s*\(|\$` + phpIdentifier + `)`,
	)

	// Extracts permission_callback value from args array
	// Handles: '__return_true', array($this, 'method'), [$this, 'method']
	wrapperPermCallbackPattern = regexp.MustCompile(
		`['"]permission_callback['"]\s*=>\s*` +
			`(?:` +
			`(array\s*\([^)]+\))` + // array(...) notation (group 1)
			`|` +
			`(\[[^\]]+\])` + // [...] notation (group 2)
			`|` +
			`([^,\]\n]+)` + // simple value like '__return_true' (group 3)
			`)`,
	)

	// Extracts methods key from args array
	wrapperMethodsKeyPattern = regexp.MustCompile(
		`['"]methods['"]\s*=>\s*([^,\]]+)`,
	)

	// Extracts callback key from args array
	wrapperCallbackKeyPattern = regexp.MustCompile(
		`['"]callback['"]\s*=>\s*([^,\]]+)`,
	)

	// Methods to skip — these are WP_REST_Controller overrides, not wrappers
	restWrapperSkipMethods = map[string]bool{
		"register_routes":     true,
		"register_rest_route": true,
	}
)

// DiscoverRESTWrappers scans a file for methods that wrap register_rest_route()
func DiscoverRESTWrappers(content, filepath string) []RESTWrapperDefinition {
	var wrappers []RESTWrapperDefinition

	// Find every class-like declaration and the extent of its body
	classes := findWrapperClassExtents(content)

	// Find all method declarations (reuse existing pattern)
	methodMatches := wrapperMethodDeclPattern.FindAllStringSubmatchIndex(content, -1)

	for _, match := range methodMatches {
		methodPos := match[0]
		isStatic := match[2] != -1 && match[3] != -1
		methodName := ""
		params := ""

		if match[4] != -1 && match[5] != -1 {
			methodName = content[match[4]:match[5]]
		}
		if match[6] != -1 && match[7] != -1 {
			params = content[match[6]:match[7]]
		}

		if methodName == "" {
			continue
		}

		// Skip known WP_REST_Controller methods
		if restWrapperSkipMethods[methodName] {
			continue
		}

		// Find which class this method belongs to
		className := classAt(classes, methodPos)

		// Extract method body
		bodyStart := declBodyOpen(content, match[1])
		if bodyStart == -1 {
			continue
		}
		body := extractBraceBlock(content, bodyStart)
		if body == "" {
			continue
		}

		// Check if body contains register_rest_route
		if !wrapperRegisterRestRoutePattern.MatchString(body) {
			continue
		}

		// Parse method parameter names
		paramNames := extractParamNames(params)
		if len(paramNames) == 0 {
			continue
		}

		// Determine which parameters flow into register_rest_route.
		//
		// Every registration in the body is considered, not just the first: a
		// method that registers two routes is two route factories, and the
		// second one's callback is as reachable as the first one's.
		for _, wrapper := range analyzeRESTWrapperBodies(body, paramNames) {
			// A method is a route factory when ANY of the registration's
			// arguments comes from a parameter of its own. The old test asked
			// only about the route, so a wrapper that hardcodes the route and
			// takes the callback -- or takes the whole descriptor -- was
			// dropped, and with it every endpoint it registers: not merely
			// mislevelled, absent.
			if wrapper.RouteParamIndex < 0 && wrapper.MethodsParamIndex < 0 &&
				wrapper.CallbackParamIndex < 0 && wrapper.ArgsParamIndex < 0 {
				continue
			}
			// A hardcoded route is only usable if we managed to read it.
			if wrapper.RouteParamIndex < 0 && wrapper.RouteLiteral == "" {
				continue
			}

			wrapper.ClassName = className
			wrapper.MethodName = methodName
			wrapper.IsStatic = isStatic
			wrapper.SourceFile = filepath
			wrapper.ParamNames = paramNames

			wrappers = append(wrappers, *wrapper)
		}
	}

	return wrappers
}

// extractParamNames extracts parameter variable names from a PHP function signature
func extractParamNames(params string) []string {
	paramList := splitParameters(params)
	var names []string
	for _, p := range paramList {
		p = strings.TrimSpace(p)
		// Handle type hints: string $param, ?int $param, ClassName $param
		// Also handle default values: $param = 'default'
		dollarIdx := strings.Index(p, "$")
		if dollarIdx < 0 {
			continue
		}
		rest := p[dollarIdx+1:]
		// Extract just the variable name (stop at space, =, comma, etc.)
		name := ""
		for _, ch := range rest {
			if ch == ' ' || ch == '=' || ch == ',' || ch == ')' {
				break
			}
			name += string(ch)
		}
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// analyzeRESTWrapperBodies analyzes a method body to determine how its
// parameters flow into the register_rest_route() calls it makes -- one
// descriptor per call.
func analyzeRESTWrapperBodies(body string, paramNames []string) []*RESTWrapperDefinition {
	// Determine which variables are accessible to register_rest_route
	// Two patterns: direct call or closure with use() clause
	accessibleVars := make(map[string]bool)

	// Check for closure use() pattern
	useMatch := wrapperClosureUsePattern.FindStringSubmatch(body)
	if useMatch != nil {
		// Parse the use() clause variables
		useVars := strings.Split(useMatch[1], ",")
		for _, v := range useVars {
			v = strings.TrimSpace(v)
			v = strings.TrimPrefix(v, "$")
			if v != "" {
				accessibleVars[v] = true
			}
		}
	} else {
		// Direct pattern — all method params are directly accessible
		for _, name := range paramNames {
			accessibleVars[name] = true
		}
	}

	// paramCarrying reports which parameter, if any, an argument expression is
	// built from.
	paramCarrying := func(expr string) int {
		for i, name := range paramNames {
			if accessibleVars[name] && containsPHPVar(expr, name) {
				return i
			}
		}
		return -1
	}

	var out []*RESTWrapperDefinition
	for _, argsMatch := range wrapperRestRouteArgsPattern.FindAllStringSubmatchIndex(body, -1) {
		if len(argsMatch) < 8 {
			continue
		}
		wrapper := &RESTWrapperDefinition{
			RouteParamIndex:    -1,
			MethodsParamIndex:  -1,
			CallbackParamIndex: -1,
			ArgsParamIndex:     -1,
		}

		namespaceExpr := strings.TrimSpace(body[argsMatch[2]:argsMatch[3]])
		routeExpr := strings.TrimSpace(body[argsMatch[4]:argsMatch[5]])
		argsStart := body[argsMatch[6]:argsMatch[7]]

		// Check namespace for $this->namespace
		if strings.Contains(namespaceExpr, "$this->namespace") ||
			strings.Contains(namespaceExpr, "self::") ||
			strings.Contains(namespaceExpr, "static::") {
			wrapper.UsesThisNamespace = true
		}

		// Map route parameter, or read the route the wrapper hardcodes.
		wrapper.RouteParamIndex = paramCarrying(routeExpr)
		if wrapper.RouteParamIndex < 0 {
			if lit := stringLiteralOf(routeExpr); lit != "" {
				wrapper.RouteLiteral = lit
			}
		}

		if strings.HasPrefix(argsStart, "$") {
			// The descriptor is a variable. When it is a parameter of this
			// method, the caller writes the methods, the callback and the
			// permission callback, and DetectRESTWrapperCalls reads them from
			// the call site. When it is a local, there is nothing to read here
			// and the registration's shape is simply unknown -- which is not a
			// reason to discard the route.
			wrapper.ArgsParamIndex = paramCarrying(argsStart)
			out = append(out, wrapper)
			continue
		}

		// Extract the full args array for methods/callback/permission analysis
		argsBlock := extractBraceBlockOrBracket(body, argsMatch[6])

		// Map methods parameter
		if v := descriptorValue(argsBlock, "methods"); v != "" {
			wrapper.MethodsParamIndex = paramCarrying(v)
		}

		// Map callback parameter
		if v := descriptorValue(argsBlock, "callback"); v != "" {
			wrapper.CallbackParamIndex = paramCarrying(v)
		}

		// Extract permission_callback for auth inference
		wrapper.PermCallbackBody = descriptorValue(argsBlock, "permission_callback")

		out = append(out, wrapper)
	}

	return out
}

// descriptorValue returns the value expression an endpoint-descriptor array
// gives for key, or "" when the key is absent.
//
// The value is read with balanced brackets rather than with a regex that stops
// at the first comma. `'callback' => [ $endpoint, 'get' ]` is the ordinary way
// to write a method callback, and stopping at the comma inside the array
// yielded "[ $endpoint" -- from which no callback name can be recovered, so
// every route registered that way reported the sentinel "callback" and reached
// nothing.
func descriptorValue(src, key string) string {
	for i := 0; i+len(key)+2 < len(src); i++ {
		if src[i] != '\'' && src[i] != '"' {
			continue
		}
		end := skipPHPString(src, i)
		if end >= len(src) || src[i+1:end] != key {
			i = end
			continue
		}
		j := end + 1
		for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' || src[j] == '\r') {
			j++
		}
		if j+1 >= len(src) || src[j] != '=' || src[j+1] != '>' {
			i = end
			continue
		}
		j += 2
		for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' || src[j] == '\r') {
			j++
		}
		return strings.TrimSpace(src[j:valueEnd(src, j)])
	}
	return ""
}

// valueEnd returns the offset one past the value expression starting at start:
// the first comma at nesting depth zero, or the end of the enclosing bracket.
func valueEnd(src string, start int) int {
	depth := 0
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '\'', '"':
			i = skipPHPString(src, i)
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		case ',':
			if depth == 0 {
				return i
			}
		}
	}
	return len(src)
}

// containsPHPVar reports whether expr uses the PHP variable $name, as opposed
// to a longer variable that merely starts with it: $route must not match
// $route_args.
func containsPHPVar(expr, name string) bool {
	for i := 0; ; {
		j := strings.Index(expr[i:], "$"+name)
		if j < 0 {
			return false
		}
		end := i + j + 1 + len(name)
		if end >= len(expr) || !isPHPNameByte(expr[end]) {
			return true
		}
		i = end
	}
}

func isPHPNameByte(c byte) bool {
	return c == '_' || c >= 0x80 || (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// stringLiteralOf returns the constant string an expression denotes, or "" when
// the expression is anything else. Only a plain quoted literal counts: a
// concatenation or an interpolation is not a constant, and guessing at one
// would invent a route.
func stringLiteralOf(expr string) string {
	expr = strings.TrimSpace(expr)
	if len(expr) >= 2 && (expr[0] == '\'' || expr[0] == '"') && expr[len(expr)-1] == expr[0] {
		inner := expr[1 : len(expr)-1]
		if !strings.ContainsAny(inner, "'\"$") {
			return inner
		}
	}
	return ""
}

// extractBraceBlockOrBracket extracts content from [ to ] or ( to ) with nesting
func extractBraceBlockOrBracket(content string, startPos int) string {
	if startPos >= len(content) {
		return ""
	}

	openChar := content[startPos]
	var closeChar byte
	switch openChar {
	case '[':
		closeChar = ']'
	case '(':
		closeChar = ')'
	case '{':
		closeChar = '}'
	default:
		// Try to find array( pattern
		if startPos+5 < len(content) && content[startPos:startPos+5] == "array" {
			pIdx := strings.Index(content[startPos:], "(")
			if pIdx >= 0 {
				startPos += pIdx
				openChar = '('
				closeChar = ')'
			} else {
				return ""
			}
		} else {
			return ""
		}
	}

	depth := 0
	inString := false
	stringChar := byte(0)
	for i := startPos; i < len(content); i++ {
		c := content[i]
		if inString {
			if c == stringChar && (i == 0 || content[i-1] != '\\') {
				inString = false
			}
			continue
		}
		switch c {
		case '"', '\'':
			inString = true
			stringChar = c
		case openChar:
			depth++
		case closeChar:
			depth--
			if depth == 0 {
				return content[startPos : i+1]
			}
		}
	}
	// Fallback: return up to 2000 chars
	end := startPos + 2000
	if end > len(content) {
		end = len(content)
	}
	return content[startPos:end]
}

// DetectRESTWrapperCalls finds calls to discovered REST wrappers and creates REST endpoints
func DetectRESTWrapperCalls(content, filePath, pluginSlug string, registry *WrapperRegistry) []models.Endpoint {
	var endpoints []models.Endpoint

	if registry == nil || len(registry.RESTWrappers) == 0 {
		return endpoints
	}

	for _, wrapper := range registry.RESTWrappers {
		var callPattern *regexp.Regexp

		if wrapper.ClassName != "" {
			if wrapper.IsStatic {
				pattern := regexp.QuoteMeta(wrapper.ClassName) + `\s*::\s*` + regexp.QuoteMeta(wrapper.MethodName) + `\s*\(`
				callPattern = regexp.MustCompile(pattern)
			} else {
				pattern := `\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*` + regexp.QuoteMeta(wrapper.MethodName) + `\s*\(`
				callPattern = regexp.MustCompile(pattern)
			}
		} else {
			pattern := `\b` + regexp.QuoteMeta(wrapper.MethodName) + `\s*\(`
			callPattern = regexp.MustCompile(pattern)
		}

		matches := callPattern.FindAllStringIndex(content, -1)

		for _, match := range matches {
			callStart := match[0]

			// Extract call arguments
			argsStart := strings.Index(content[callStart:], "(")
			if argsStart == -1 {
				continue
			}
			argsStart += callStart

			args := extractParenBlock(content, argsStart)
			if args == "" || len(args) < 2 {
				continue
			}

			argList := splitParameters(args[1 : len(args)-1])

			// Resolve route: from the argument the wrapper takes it from, or
			// from the route the wrapper itself hardcodes.
			route := wrapper.RouteLiteral
			if wrapper.RouteParamIndex >= 0 {
				if wrapper.RouteParamIndex >= len(argList) {
					continue
				}
				route = strings.TrimSpace(argList[wrapper.RouteParamIndex])
				route = strings.Trim(route, "'\"")
			}
			if route == "" {
				continue
			}
			// Ensure route starts with /
			if !strings.HasPrefix(route, "/") {
				route = "/" + route
			}

			// A wrapper that forwards a descriptor parameter registers whatever
			// the CALLER wrote, so the methods, the callback and the permission
			// callback are read from the array at the call site. The wrapper
			// body has nothing to say about them.
			descriptor := ""
			if wrapper.ArgsParamIndex >= 0 && wrapper.ArgsParamIndex < len(argList) {
				descriptor = argList[wrapper.ArgsParamIndex]
			}

			// Resolve methods
			methods := []string{"GET"}
			if wrapper.MethodsParamIndex >= 0 && wrapper.MethodsParamIndex < len(argList) {
				methodArg := strings.TrimSpace(argList[wrapper.MethodsParamIndex])
				methods = resolveRESTWrapperMethods(methodArg)
			} else if v := descriptorValue(descriptor, "methods"); v != "" {
				methods = resolveRESTWrapperMethods(v)
			}

			// Resolve callback
			callback := "wrapper_callback"
			if wrapper.CallbackParamIndex >= 0 && wrapper.CallbackParamIndex < len(argList) {
				callbackArg := strings.TrimSpace(argList[wrapper.CallbackParamIndex])
				callback = extractCallbackName(callbackArg)
			} else if v := descriptorValue(descriptor, "callback"); v != "" {
				callback = extractCallbackName(v)
			}

			// Resolve namespace
			namespace := resolveRESTWrapperNamespace(wrapper, content, pluginSlug)

			// Determine auth level from the permission callback, wherever it was
			// written.
			permCallback := wrapper.PermCallbackBody
			if descriptor != "" {
				permCallback = descriptorValue(descriptor, "permission_callback")
			}

			// No permission callback means no gate. register_rest_route is
			// served to anyone when the descriptor omits permission_callback --
			// core has warned about that since 5.5 but still serves the route --
			// so unauthenticated is what the code says, not a guess.
			authLevel := models.Unauthenticated
			if permCallback != "" {
				authLevel = inferRESTWrapperAuthLevel(permCallback, content)
			}

			lineNum := strings.Count(content[:callStart], "\n") + 1
			rawCode := truncateCode(content[callStart:min(callStart+200, len(content))], 500)

			for _, method := range methods {
				ep := models.Endpoint{
					PluginSlug: pluginSlug,
					Type:       models.EndpointTypeREST,
					Route:      combineRoute(namespace, route),
					Method:     method,
					AuthLevel:  authLevel,
					Callback:   NormalizeCallback(callback),
					File:       filePath,
					Line:       lineNum,
					RawCode:    rawCode,
					Namespace:  namespace,
				}
				endpoints = append(endpoints, ep)
			}
		}
	}

	return endpoints
}

// resolveRESTWrapperMethods resolves HTTP methods from a wrapper call argument
func resolveRESTWrapperMethods(arg string) []string {
	arg = strings.TrimSpace(arg)

	// Handle WP_REST_Server constants and common patterns
	if strings.Contains(arg, "CREATABLE") {
		return []string{"POST"}
	}
	if strings.Contains(arg, "READABLE") || strings.Contains(arg, "READ") {
		return []string{"GET"}
	}
	if strings.Contains(arg, "EDITABLE") {
		return []string{"POST", "PUT", "PATCH"}
	}
	if strings.Contains(arg, "DELETABLE") {
		return []string{"DELETE"}
	}
	if strings.Contains(arg, "ALLMETHODS") {
		return []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	}

	// String literal method
	cleaned := strings.Trim(arg, "'\"")
	if cleaned != "" {
		return parseMethodString(cleaned)
	}

	return []string{"GET"}
}

// resolveRESTWrapperNamespace resolves the namespace for a REST wrapper endpoint
func resolveRESTWrapperNamespace(wrapper RESTWrapperDefinition, content, pluginSlug string) string {
	if !wrapper.UsesThisNamespace {
		return pluginSlug + "/v1"
	}

	// Try to resolve $this->namespace from the current file
	// Look for property declaration: protected $namespace = 'value';
	if match := classNamespacePropertyPattern.FindStringSubmatch(content); len(match) >= 2 {
		return match[1]
	}
	// Look for assignment: $this->namespace = 'value';
	if match := classNamespaceAssignPattern.FindStringSubmatch(content); len(match) >= 2 {
		return match[1]
	}
	// Look for concatenation pattern: $this->namespace = CONSTANT . '/v1'
	// This handles KIRKI_COMPONENT_LIBRARY_APP_PREFIX . '/v1' cases
	concatPattern := regexp.MustCompile(`\$this\s*->\s*namespace\s*=\s*([A-Z][A-Z0-9_]*)\s*\.\s*['"]([^'"]+)['"]`)
	if match := concatPattern.FindStringSubmatch(content); len(match) >= 3 {
		constName := match[1]
		suffix := match[2]
		// Try to resolve the constant from define() in this file
		definePattern := regexp.MustCompile(`define\s*\(\s*['"]` + regexp.QuoteMeta(constName) + `['"]\s*,\s*['"]([^'"]+)['"]`)
		if defMatch := definePattern.FindStringSubmatch(content); len(defMatch) >= 2 {
			return defMatch[1] + suffix
		}
		return "{" + constName + "}" + suffix
	}

	return pluginSlug + "/v1"
}

// inferRESTWrapperAuthLevel determines the auth level from a permission callback reference
func inferRESTWrapperAuthLevel(permCallbackBody, content string) models.AuthLevel {
	permCallbackBody = strings.TrimSpace(permCallbackBody)

	// Direct __return_true → Unauthenticated
	if strings.Contains(permCallbackBody, "__return_true") {
		return models.Unauthenticated
	}

	// Array callback referencing a method → look up the method body
	// Pattern: array( $this, 'method_name' ) or [ $this, 'method_name' ]
	methodPattern := regexp.MustCompile(`['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)
	methodMatch := methodPattern.FindStringSubmatch(permCallbackBody)
	if methodMatch != nil {
		methodName := methodMatch[1]
		// Find the method body in the content
		funcBodyPattern := regexp.MustCompile(
			`function\s+` + regexp.QuoteMeta(methodName) + `\s*\([^)]*\)\s*\{`)
		if funcLoc := funcBodyPattern.FindStringIndex(content); funcLoc != nil {
			bracePos := strings.Index(content[funcLoc[0]:], "{")
			if bracePos >= 0 {
				funcBody := extractBraceBlock(content, funcLoc[0]+bracePos)
				if strings.Contains(funcBody, "return true") {
					return models.Unauthenticated
				}
				return InferAuthLevel(funcBody)
			}
		}
	}

	// The permission callback exists but could not be read -- it is in another
	// file, or it is a variable, or the name resolves to nothing here.
	//
	// Answering Subscriber for that was inventing a gate. It is not a fact
	// about the code, it is an admission that the code was not read, and a
	// privilege the analyzer has not seen the code require is a privilege that
	// makes a reachable bug look gated. An unknown gate is reported as no gate,
	// which costs a wasted look and never costs a missed one.
	//
	// The cost of this choice is that "unauthenticated" now covers two
	// different states -- core says public, and we could not tell -- which a
	// consumer cannot distinguish. Recording which one it is needs a field on
	// models.Endpoint that does not exist yet.
	return models.Unauthenticated
}

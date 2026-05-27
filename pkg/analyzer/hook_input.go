package analyzer

import (
	"regexp"
	"strings"

	wpast "github.com/hatlesswizard/wptracelib/pkg/ast"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Hooks where plugins commonly handle direct POST/GET input
var hookInputTargetHooks = []string{
	"init",
	"admin_init",
	"wp",
	"wp_loaded",
	"template_redirect",
	"send_headers",
	"parse_request",
	"plugins_loaded",
	"setup_theme",
	"after_setup_theme",
}

// Package-level compiled regex patterns for hook input detection
var (
	// Patterns to detect direct superglobal access in callbacks
	// $_POST['field'], $_GET['field'], $_REQUEST['field'], $_SERVER['REQUEST_URI'], etc.
	hookSuperglobalAccessPattern = regexp.MustCompile(
		`\$_(POST|GET|REQUEST|SERVER)\s*\[\s*['"]([^'"]+)['"]\s*\]`,
	)

	// get_query_var('var') - WordPress function for accessing query variables
	hookGetQueryVarPattern = regexp.MustCompile(
		`get_query_var\s*\(`,
	)

	// filter_input(INPUT_POST, 'field'), filter_input(INPUT_GET, 'field')
	hookFilterInputAccessPattern = regexp.MustCompile(
		`filter_input\s*\(\s*INPUT_(POST|GET|REQUEST)\s*,\s*['"]([^'"]+)['"]`,
	)

	// $_SERVER['REQUEST_METHOD'] === 'POST' check
	hookRequestMethodPattern = regexp.MustCompile(
		`\$_SERVER\s*\[\s*['"]REQUEST_METHOD['"]\s*\]\s*===?\s*['"](POST|GET)['"]`,
	)

	// Direct $_POST or $_GET variable check (without field)
	hookDirectSuperglobalPattern = regexp.MustCompile(
		`(?:isset|empty|!empty)\s*\(\s*\$_(POST|GET|REQUEST)\s*\)`,
	)
)

// buildHookPatterns creates compiled regex patterns for a specific hook
func buildHookPatterns(hookName string) []*regexp.Regexp {
	quotedHook := regexp.QuoteMeta(hookName)

	patterns := []*regexp.Regexp{
		// Pattern 1: add_action('hook', 'function_name')
		regexp.MustCompile(
			`add_action\s*\(\s*['"]` + quotedHook + `['"]\s*,\s*['"]([^'"]+)['"]`,
		),

		// Pattern 2: add_action('hook', [$this, 'method'])
		regexp.MustCompile(
			`add_action\s*\(\s*['"]` + quotedHook + `['"]\s*,\s*\[\s*\$this\s*,\s*['"]([^'"]+)['"]`,
		),

		// Pattern 3: add_action('hook', array($this, 'method'))
		regexp.MustCompile(
			`add_action\s*\(\s*['"]` + quotedHook + `['"]\s*,\s*array\s*\(\s*\$this\s*,\s*['"]([^'"]+)['"]`,
		),

		// Pattern 4: add_action('hook', [__CLASS__, 'method'])
		regexp.MustCompile(
			`add_action\s*\(\s*['"]` + quotedHook + `['"]\s*,\s*(?:\[|array\s*\()\s*__CLASS__\s*,\s*['"]([^'"]+)['"]`,
		),

		// Pattern 5: add_action('hook', 'ClassName::method')
		regexp.MustCompile(
			`add_action\s*\(\s*['"]` + quotedHook + `['"]\s*,\s*['"]([A-Za-z_][A-Za-z0-9_\\]*::[\$a-zA-Z_][a-zA-Z0-9_]*)['"]`,
		),
	}

	return patterns
}

// DetectHookInputEndpoints finds callbacks on common hooks that directly access POST/GET input.
// These are often security-sensitive because they run early in WordPress lifecycle
// and may not have proper authentication checks.
func DetectHookInputEndpoints(content, filepath, pluginSlug string) []models.Endpoint {
	var endpoints []models.Endpoint

	type hookMatch struct {
		hookName string
		callback string
	}

	var matches []hookMatch

	// Check each target hook
	for _, hookName := range hookInputTargetHooks {
		patterns := buildHookPatterns(hookName)

		for _, pattern := range patterns {
			for _, m := range pattern.FindAllStringSubmatch(content, -1) {
				if len(m) >= 2 {
					matches = append(matches, hookMatch{
						hookName: hookName,
						callback: m[1],
					})
				}
			}
		}

		// Also check for anonymous functions
		anonPattern := regexp.MustCompile(
			`add_action\s*\(\s*['"]` + regexp.QuoteMeta(hookName) + `['"]\s*,\s*function\s*\(`,
		)
		if anonPattern.MatchString(content) {
			matches = append(matches, hookMatch{
				hookName: hookName,
				callback: "anonymous",
			})
		}
	}

	// Deduplicate and analyze each callback
	seen := make(map[string]bool)
	for _, hm := range matches {
		key := hm.hookName + ":" + hm.callback
		if seen[key] {
			continue
		}
		seen[key] = true

		// Find callback body
		var callbackBody string
		if hm.callback == "anonymous" {
			callbackBody = extractAnonHookBody(content, hm.hookName)
		} else {
			// Extract method name if it's a static call
			methodName := hm.callback
			if idx := strings.LastIndex(hm.callback, "::"); idx != -1 {
				methodName = hm.callback[idx+2:]
			}
			callbackBody = findFunctionBody(methodName, content)
		}

		if callbackBody == "" {
			continue
		}

		// Check if callback accesses POST/GET input
		fields := extractHookInputFields(callbackBody)
		hasRequestMethodCheck := hookRequestMethodPattern.MatchString(callbackBody)
		hasDirectSuperglobal := hookDirectSuperglobalPattern.MatchString(callbackBody)
		hasGetQueryVar := hookGetQueryVarPattern.MatchString(callbackBody)

		if len(fields) == 0 && !hasRequestMethodCheck && !hasDirectSuperglobal && !hasGetQueryVar {
			continue // Skip callbacks that don't handle input
		}

		// Infer auth level from callback body
		authLevel := InferAuthLevel(callbackBody)

		// Build field info string for display
		fieldInfo := ""
		if len(fields) > 0 {
			fieldInfo = "[" + strings.Join(fields, ", ") + "]"
		}

		endpoints = append(endpoints, models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeHookInput,
			Route:      hm.hookName + ":" + hm.callback,
			Method:     "POST/GET",
			AuthLevel:  authLevel,
			Callback:   hm.callback,
			File:       filepath,
			RawCode:    fieldInfo, // Store extracted fields
		})
	}

	return endpoints
}

// extractHookInputFields extracts all POST/GET/REQUEST field names from hook callback code
func extractHookInputFields(code string) []string {
	fields := make(map[string]bool)

	// $_POST['field'], $_GET['field'], $_REQUEST['field']
	for _, m := range hookSuperglobalAccessPattern.FindAllStringSubmatch(code, -1) {
		if len(m) >= 3 {
			fields[m[1]+":"+m[2]] = true
		}
	}

	// filter_input(INPUT_POST, 'field')
	for _, m := range hookFilterInputAccessPattern.FindAllStringSubmatch(code, -1) {
		if len(m) >= 3 {
			fields[m[1]+":"+m[2]] = true
		}
	}

	// Convert to slice
	result := make([]string, 0, len(fields))
	for f := range fields {
		result = append(result, f)
	}
	return result
}

// extractAnonHookBody extracts the body of an anonymous function registered on a hook
func extractAnonHookBody(content, hookName string) string {
	// Find: add_action('hook', function(...) { ... })
	pattern := regexp.MustCompile(
		`add_action\s*\(\s*['"]` + regexp.QuoteMeta(hookName) + `['"]\s*,\s*function\s*\([^)]*\)\s*\{`,
	)

	loc := pattern.FindStringIndex(content)
	if loc == nil {
		return ""
	}

	// Find the opening brace
	braceStart := strings.Index(content[loc[0]:], "{")
	if braceStart == -1 {
		return ""
	}

	startPos := loc[0] + braceStart
	return extractBracedContent(content, startPos)
}

// DetectHookInputEndpointsWithAST wraps DetectHookInputEndpoints with AST-backed
// cross-file callback resolution, taint analysis, and auth guard detection.
func DetectHookInputEndpointsWithAST(content, filepath, pluginSlug string, astCtx *wpast.ASTContext) []models.Endpoint {
	endpoints := DetectHookInputEndpoints(content, filepath, pluginSlug)

	if astCtx == nil || !astCtx.Available {
		return endpoints
	}

	for _, hookName := range hookInputTargetHooks {
		patterns := buildHookPatterns(hookName)

		for _, pattern := range patterns {
			for _, m := range pattern.FindAllStringSubmatch(content, -1) {
				if len(m) < 2 {
					continue
				}
				callbackName := m[1]

				alreadyDetected := false
				for _, ep := range endpoints {
					if ep.Callback == callbackName && strings.HasPrefix(ep.Route, hookName+":") {
						alreadyDetected = true
						break
					}
				}
				if alreadyDetected {
					continue
				}

				ref := wpast.CallbackRef{
					Type:     "function",
					FuncName: callbackName,
					File:     filepath,
				}
				if strings.Contains(callbackName, "::") {
					parts := strings.SplitN(callbackName, "::", 2)
					ref = wpast.CallbackRef{
						Type:       "static_method",
						ClassName:  parts[0],
						MethodName: parts[1],
						File:       filepath,
					}
				}

				_, fn, err := astCtx.Resolver.ResolveCallback(ref)
				if err != nil {
					continue
				}

				funcFQN := callbackName
				if fn != nil {
					funcFQN = fn.FQN
				}

				if !astCtx.Resolver.FunctionAccessesUserInput(funcFQN) {
					continue
				}

				authLevel := models.Unauthenticated
				hasGuard, level := astCtx.Resolver.HasAuthGuardBeforeInput(funcFQN)
				if hasGuard {
					authLevel = level
				}

				endpoints = append(endpoints, models.Endpoint{
					PluginSlug: pluginSlug,
					Type:       models.EndpointTypeHookInput,
					Route:      hookName + ":" + callbackName,
					Method:     "POST/GET",
					AuthLevel:  authLevel,
					Callback:   callbackName,
					File:       filepath,
					RawCode:    "[AST:cross-file resolution]",
				})
			}
		}
	}

	return endpoints
}

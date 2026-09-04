package analyzer

import (
	"regexp"
	"sort"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/config"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// getFrameworkConfig returns the current framework configuration.
// This is shared with auth.go's authConfig for consistency.
func getFrameworkConfig() *config.Config {
	return GetAuthConfig()
}

// Package-level compiled regex patterns for generic framework detection
var (
	// Laravel-style Route:: patterns (generic, not plugin-specific)
	// Route::get('/path', 'Controller@method')
	// Route::post('/path', [Controller::class, 'method'])
	laravelRoutePattern = regexp.MustCompile(
		`Route::(get|post|put|delete|patch|any|match)\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // route path
			`(?:['"]([^'"]+)['"]|\[([^\]]+)\])\s*\)`, // callback
	)

	// Generic framework hook registration pattern
	// SomeFramework::addRoute('method', 'path', 'callback')
	genericFrameworkRoutePattern = regexp.MustCompile(
		`[A-Z][a-zA-Z0-9_]*::(addRoute|registerRoute|route|addEndpoint|registerEndpoint)\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // first arg
			`['"]([^'"]+)['"]\s*,?\s*` + // second arg
			`(?:['"]([^'"]+)['"])?\s*\)`, // optional third arg
	)

	// WordPress REST controller class pattern
	// class MyController extends WP_REST_Controller
	// register_routes() method with $this->namespace, $this->rest_base
	wpRestControllerPattern = regexp.MustCompile(
		`class\s+([A-Za-z_][A-Za-z0-9_]*)\s+extends\s+WP_REST_Controller`,
	)

	// Generic action hook with prefix patterns (for custom frameworks)
	// $this->add_action('wp_ajax_' . $prefix . '_action', [$this, 'handler'])
	genericPrefixedAjaxPattern = regexp.MustCompile(
		`(?:add_action|->addAction)\s*\(\s*` +
			`['"]wp_ajax_(nopriv_)?['"]\s*\.\s*` +
			`[^,]+\s*\.\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // suffix action name
			`([^)]+)\)`,
	)

	// Middleware-based auth detection patterns (generic)
	middlewareAdminPattern  = regexp.MustCompile(`middleware\s*\(\s*['"](?:admin|userCan:[^'"]*manage|auth:admin)['"]\s*\)`)
	middlewareUserPattern   = regexp.MustCompile(`middleware\s*\(\s*['"](?:auth|userCan|logged_in|user)['"]\s*\)`)
	middlewarePublicPattern = regexp.MustCompile(`middleware\s*\(\s*['"](?:public|guest|noauth)['"]\s*\)`)

	// userCan capability extraction pattern (for middleware-based auth)
	userCanCapPattern = regexp.MustCompile(`userCan:([a-z_]+)`)

	// withPolicy pattern indicates auth requirement (generic)
	withPolicyPattern = regexp.MustCompile(`withPolicy\s*\(\s*['"]([^'"]+)['"]\s*\)`)

	// REST namespace property pattern (generic)
	// public $namespace = 'myplugin/v1';
	restNamespacePropertyPattern = regexp.MustCompile(
		`(?:public|protected|private)?\s*\$namespace\s*=\s*['"]([^'"]+)['"]`,
	)

	// Slim Framework route pattern (generic micro-framework pattern)
	// $app->get('/route', Controller::class)
	// $app->post('/route', [Callback::class, 'method'])
	// $router->get('/route', 'callback')
	slimFrameworkRoutePattern = regexp.MustCompile(
		`\$(app|router)\s*->\s*(get|post|put|delete|patch|options|any|map)\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // route path
			`([^)]+)\)`, // callback (can be class::class, array, string, closure)
	)

	// FastRoute/nikic pattern (used internally by Slim and others)
	// $r->addRoute('GET', '/route', 'handler')
	// $r->get('/route', 'handler')
	fastRoutePattern = regexp.MustCompile(
		`\$r\s*->\s*(?:addRoute\s*\(\s*['"]?(GET|POST|PUT|DELETE|PATCH)['"]?\s*,\s*|(get|post|put|delete|patch)\s*\()\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // route path
			`([^)]+)\)`, // callback
	)

	// WordPress add_rewrite_rule() pattern
	// add_rewrite_rule('pattern', 'query', 'position')
	// Creates custom URL endpoints
	addRewriteRulePattern = regexp.MustCompile(
		`add_rewrite_rule\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // regex pattern
			`['"]([^'"]+)['"]\s*,?\s*` + // query (index.php?...)
			`(?:['"]([^'"]+)['"])?\s*\)`, // position (optional)
	)

	// add_rewrite_tag() - defines query vars used with rewrite rules
	addRewriteTagPattern = regexp.MustCompile(
		`add_rewrite_tag\s*\(\s*` +
			`['"]%([^%'"]+)%['"]\s*,\s*` + // tag name
			`['"]([^'"]+)['"]`, // regex
	)

	// add_rewrite_endpoint() - simpler custom endpoint definition
	// add_rewrite_endpoint('endpoint', EP_ALL)
	addRewriteEndpointPattern = regexp.MustCompile(
		`add_rewrite_endpoint\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // endpoint name
			`([^)]+)\)`, // endpoint mask (EP_ALL, EP_PERMALINK, etc.)
	)

	// template_redirect hook - used to intercept requests before template loading
	// add_action('template_redirect', 'my_handler')
	// add_action('template_redirect', [$this, 'handle_request'])
	templateRedirectPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]template_redirect['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	// parse_request hook - even earlier hook for custom request handling
	// add_action('parse_request', 'my_parser')
	parseRequestPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]parse_request['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	// init hook with query var check - common pattern for custom endpoints
	// add_action('init', 'my_init') combined with $_GET['my_action'] check
	initHookPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]init['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	// XML-RPC methods filter - plugins add custom XML-RPC methods
	// add_filter('xmlrpc_methods', 'my_methods_filter')
	xmlrpcMethodsPattern = regexp.MustCompile(
		`add_filter\s*\(\s*['"]xmlrpc_methods['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	// XML-RPC method definition within a filter callback
	// $methods['my.method'] = [$this, 'handler']
	xmlrpcMethodDefPattern = regexp.MustCompile(
		`\$methods\s*\[\s*['"]([^'"]+)['"]\s*\]\s*=\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name
			`|` +
			`(\[[^\]]+\])` + // array notation
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	// register_post_type() with show_in_rest - exposes CPT via REST API
	// register_post_type('my_cpt', array('show_in_rest' => true, ...))
	registerPostTypePattern = regexp.MustCompile(
		`(?s)register_post_type\s*\(\s*['"]([^'"]+)['"]\s*,\s*` +
			`(?:array\s*\(|\[)([^)}\]]*show_in_rest[^)}\]]*)`,
	)

	// register_taxonomy() with show_in_rest - exposes taxonomy via REST API
	registerTaxonomyPattern = regexp.MustCompile(
		`(?s)register_taxonomy\s*\(\s*['"]([^'"]+)['"]\s*,\s*` +
			`[^,]+\s*,\s*` + // object types
			`(?:array\s*\(|\[)([^)}\]]*show_in_rest[^)}\]]*)`,
	)

	// Show in REST patterns within args
	showInRestTruePattern  = regexp.MustCompile(`['"]show_in_rest['"]\s*=>\s*true`)
	showInRestFalsePattern = regexp.MustCompile(`['"]show_in_rest['"]\s*=>\s*false`)

	// rest_base pattern - custom REST base slug
	restBasePattern = regexp.MustCompile(`['"]rest_base['"]\s*=>\s*['"]([^'"]+)['"]`)
)

// DetectFrameworkEndpoints detects endpoints from various PHP frameworks
// Framework detection can be enabled/disabled via configuration
func DetectFrameworkEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Get framework configuration
	cfg := getFrameworkConfig()
	var frameworkCfg *config.FrameworkConfig
	if cfg != nil {
		frameworkCfg = cfg.Framework
	}

	// If no config, use minimal defaults (only generic patterns enabled)
	enableLaravelStyle := true
	enableGenericRouters := true

	if frameworkCfg != nil {
		enableLaravelStyle = frameworkCfg.EnableLaravelStyle
		enableGenericRouters = frameworkCfg.EnableGenericRouters
	}

	// Detect Laravel-style Route:: endpoints (if enabled)
	if enableLaravelStyle {
		laravelEndpoints := detectLaravelRouteEndpoints(content, filepath, pluginSlug)
		endpoints = append(endpoints, laravelEndpoints...)
	}

	// Detect generic framework endpoints (if enabled)
	if enableGenericRouters {
		genericEndpoints := detectGenericFrameworkEndpoints(content, filepath, pluginSlug)
		endpoints = append(endpoints, genericEndpoints...)
	}

	// Detect Slim Framework endpoints (always enabled - very common pattern)
	slimEndpoints := detectSlimFrameworkEndpoints(content, filepath, pluginSlug)
	endpoints = append(endpoints, slimEndpoints...)

	// Detect FastRoute endpoints
	fastRouteEndpoints := detectFastRouteEndpoints(content, filepath, pluginSlug)
	endpoints = append(endpoints, fastRouteEndpoints...)

	// Detect WordPress rewrite rule endpoints (always enabled)
	rewriteEndpoints := detectRewriteRuleEndpoints(content, filepath, pluginSlug)
	endpoints = append(endpoints, rewriteEndpoints...)

	// Detect template_redirect and parse_request hook-based endpoints
	hookEndpoints := detectHookBasedEndpoints(content, filepath, pluginSlug)
	endpoints = append(endpoints, hookEndpoints...)

	// Detect XML-RPC custom methods
	xmlrpcEndpoints := detectXMLRPCEndpoints(content, filepath, pluginSlug)
	endpoints = append(endpoints, xmlrpcEndpoints...)

	// Detect custom post types and taxonomies exposed via REST API
	cptEndpoints := detectCPTRestEndpoints(content, filepath, pluginSlug)
	endpoints = append(endpoints, cptEndpoints...)

	return endpoints
}

// detectLaravelRouteEndpoints detects Laravel-style Route:: patterns
func detectLaravelRouteEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	matches := laravelRoutePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}

		fullMatch := content[match[0]:match[1]]
		httpMethod := strings.ToUpper(content[match[2]:match[3]])
		routePath := content[match[4]:match[5]]

		// Extract callback from either string or array notation
		var callback string
		if len(match) >= 8 && match[6] >= 0 && match[7] > match[6] {
			callback = content[match[6]:match[7]]
		} else if len(match) >= 10 && match[8] >= 0 && match[9] > match[8] {
			callback = content[match[8]:match[9]]
		}

		lineNum := countLines(content[:match[0]]) + 1

		// Handle special methods
		if httpMethod == "MATCH" || httpMethod == "ANY" {
			httpMethod = "GET,POST"
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      routePath,
			Method:     httpMethod,
			AuthLevel:  models.Subscriber, // Default
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
		}
		endpoints = append(endpoints, ep)
	}

	return endpoints
}

// detectGenericFrameworkEndpoints detects generic framework patterns
func detectGenericFrameworkEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	matches := genericFrameworkRoutePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 8 {
			continue
		}

		fullMatch := content[match[0]:match[1]]
		// method := content[match[2]:match[3]] // addRoute, registerRoute, etc.
		arg1 := content[match[4]:match[5]]
		arg2 := content[match[6]:match[7]]

		var arg3 string
		if len(match) >= 10 && match[8] >= 0 && match[9] > match[8] {
			arg3 = content[match[8]:match[9]]
		}

		lineNum := countLines(content[:match[0]]) + 1

		// Try to determine what's the route and what's the callback
		var routePath, callback string
		httpMethod := "GET"

		// Common pattern: addRoute('METHOD', 'path', 'callback')
		if isHTTPMethod(arg1) {
			httpMethod = strings.ToUpper(arg1)
			routePath = arg2
			callback = arg3
		} else {
			// Pattern: addRoute('path', 'callback')
			routePath = arg1
			callback = arg2
		}

		if routePath == "" || callback == "" {
			continue
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      routePath,
			Method:     httpMethod,
			AuthLevel:  models.Subscriber, // Default
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
		}
		endpoints = append(endpoints, ep)
	}

	return endpoints
}

// inferFrameworkAuthLevel infers authentication level from framework-specific patterns
func inferFrameworkAuthLevel(code string) models.AuthLevel {
	// Check for admin middleware patterns
	if middlewareAdminPattern.MatchString(code) {
		return models.Admin
	}

	// Check for user middleware patterns
	if middlewareUserPattern.MatchString(code) {
		return models.Subscriber
	}

	// Check for public/guest middleware
	if middlewarePublicPattern.MatchString(code) {
		return models.Unauthenticated
	}

	// Check for userCan middleware
	if strings.Contains(code, "userCan:") {
		// Extract capability (using pre-compiled pattern)
		capMatch := userCanCapPattern.FindStringSubmatch(code)
		if len(capMatch) >= 2 {
			cap := capMatch[1]
			initCapabilityLevels()
			if level, ok := capabilityLevels[cap]; ok {
				return level
			}
			// If it's a custom capability, assume Admin
			if strings.Contains(cap, "manage") || strings.Contains(cap, "admin") {
				return models.Admin
			}
		}
		return models.Subscriber
	}

	// Check withPolicy pattern
	if withPolicyPattern.MatchString(code) {
		policyMatch := withPolicyPattern.FindStringSubmatch(code)
		if len(policyMatch) >= 2 {
			policy := strings.ToLower(policyMatch[1])
			if strings.Contains(policy, "public") {
				return models.Unauthenticated
			}
			if strings.Contains(policy, "admin") || strings.Contains(policy, "settings") {
				return models.Admin
			}
		}
		return models.Subscriber
	}

	// Check for csrf middleware (implies some auth)
	if strings.Contains(code, "csrf") || strings.Contains(code, "nonce") {
		return models.Subscriber
	}

	// Default based on standard auth patterns
	return InferAuthLevel(code)
}

// isHTTPMethod checks if a string is an HTTP method
func isHTTPMethod(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "ANY":
		return true
	default:
		return false
	}
}

// cptRestOperation defines a standard REST operation for CPT/taxonomy endpoints
type cptRestOperation struct {
	routeSuffix string
	method      string
	authLevel   models.AuthLevel
	callback    string
}

// postTypeOperations defines standard REST operations for custom post types
var postTypeOperations = []cptRestOperation{
	{"", "GET", models.Unauthenticated, "get_items"},        // List
	{"/{id}", "GET", models.Unauthenticated, "get_item"},    // Read single
	{"", "POST", models.Contributor, "create_item"},         // Create
	{"/{id}", "PUT,PATCH", models.Contributor, "update_item"}, // Update
	{"/{id}", "DELETE", models.Contributor, "delete_item"},  // Delete
}

// taxonomyOperations defines standard REST operations for taxonomies
var taxonomyOperations = []cptRestOperation{
	{"", "GET", models.Unauthenticated, "get_items"}, // List terms
	{"", "POST", models.Editor, "create_item"},       // Create term
}

// createCPTRestEndpoints creates standard REST endpoints for a custom post type
func createCPTRestEndpoints(restBase, controller, pluginSlug, filepath string, lineNum int, rawCode string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0, len(postTypeOperations))
	for _, op := range postTypeOperations {
		endpoints = append(endpoints, models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      "/wp-json/wp/v2/" + restBase + op.routeSuffix,
			Method:     op.method,
			AuthLevel:  op.authLevel,
			Callback:   controller + "::" + op.callback,
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
			Namespace:  "wp/v2",
		})
	}
	return endpoints
}

// createTaxonomyRestEndpoints creates standard REST endpoints for a taxonomy
func createTaxonomyRestEndpoints(restBase, pluginSlug, filepath string, lineNum int, rawCode string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0, len(taxonomyOperations))
	for _, op := range taxonomyOperations {
		endpoints = append(endpoints, models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      "/wp-json/wp/v2/" + restBase + op.routeSuffix,
			Method:     op.method,
			AuthLevel:  op.authLevel,
			Callback:   "WP_REST_Terms_Controller::" + op.callback,
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
			Namespace:  "wp/v2",
		})
	}
	return endpoints
}

// detectSlimFrameworkEndpoints detects Slim Framework and similar micro-framework routes
// Pattern: $app->get('/route', Controller::class) or $router->post('/route', 'callback')
func detectSlimFrameworkEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	matches := slimFrameworkRoutePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 10 {
			continue
		}

		fullMatch := content[match[0]:match[1]]
		// variable := content[match[2]:match[3]] // app or router
		httpMethod := strings.ToUpper(content[match[4]:match[5]]) // get, post, etc.
		routePath := content[match[6]:match[7]]
		callback := strings.TrimSpace(content[match[8]:match[9]])

		// Skip vendor files
		if strings.Contains(filepath, "/vendor/") {
			continue
		}

		lineNum := countLines(content[:match[0]]) + 1

		// Handle special methods
		if httpMethod == "ANY" || httpMethod == "MAP" {
			httpMethod = "GET,POST"
		}

		// Clean up callback
		callback = strings.Trim(callback, " \t\n\r")

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      routePath,
			Method:     httpMethod,
			AuthLevel:  models.Subscriber, // Default to User - these are typically behind AJAX auth
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
			Namespace:  "slim-framework",
		}
		endpoints = append(endpoints, ep)
	}

	return endpoints
}

// detectFastRouteEndpoints detects FastRoute/nikic routing patterns
// Pattern: $r->addRoute('GET', '/route', 'handler') or $r->get('/route', 'handler')
func detectFastRouteEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	matches := fastRoutePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 10 {
			continue
		}

		fullMatch := content[match[0]:match[1]]

		// Extract method - could be in group 2 (addRoute) or group 4 (shorthand)
		var httpMethod string
		if match[2] >= 0 && match[3] > match[2] {
			httpMethod = strings.ToUpper(content[match[2]:match[3]])
		} else if match[4] >= 0 && match[5] > match[4] {
			httpMethod = strings.ToUpper(content[match[4]:match[5]])
		}

		routePath := content[match[6]:match[7]]
		callback := strings.TrimSpace(content[match[8]:match[9]])

		// Skip vendor files
		if strings.Contains(filepath, "/vendor/") {
			continue
		}

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      routePath,
			Method:     httpMethod,
			AuthLevel:  models.Subscriber, // Default
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
			Namespace:  "fastroute",
		}
		endpoints = append(endpoints, ep)
	}

	return endpoints
}

// detectRewriteRuleEndpoints detects WordPress add_rewrite_rule() endpoints
// These create custom URL patterns that map to WordPress queries
// Pattern: add_rewrite_rule('regex', 'query', 'position')
func detectRewriteRuleEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Skip vendor files
	if strings.Contains(filepath, "/vendor/") {
		return endpoints
	}

	// Detect add_rewrite_rule() patterns
	matches := addRewriteRulePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}

		fullMatch := content[match[0]:match[1]]
		regexPattern := content[match[2]:match[3]]
		query := content[match[4]:match[5]]

		lineNum := countLines(content[:match[0]]) + 1

		// Clean up the regex pattern to make it more readable as a route
		// ^my-endpoint/?$ -> /my-endpoint
		routePath := cleanRewritePattern(regexPattern)

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      routePath,
			Method:     "GET",
			AuthLevel:  InferAuthLevel(fullMatch), // Infer from surrounding code
			Callback:   extractQueryCallback(query),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
			Namespace:  "rewrite-rule",
		}

		// If no auth check found in the immediate code, check surrounding context
		if ep.AuthLevel == models.Unauthenticated {
			// Check if there's an auth check in the file near this rewrite rule
			contextStart := match[0] - 500
			if contextStart < 0 {
				contextStart = 0
			}
			contextEnd := match[1] + 500
			if contextEnd > len(content) {
				contextEnd = len(content)
			}
			surroundingContext := content[contextStart:contextEnd]
			ep.AuthLevel = InferAuthLevel(surroundingContext)
		}

		endpoints = append(endpoints, ep)
	}

	// Detect add_rewrite_endpoint() patterns
	endpointMatches := addRewriteEndpointPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range endpointMatches {
		if len(match) < 6 {
			continue
		}

		fullMatch := content[match[0]:match[1]]
		endpointName := content[match[2]:match[3]]
		mask := strings.TrimSpace(content[match[4]:match[5]])

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      "/" + endpointName,
			Method:     "GET",
			AuthLevel:  InferAuthLevel(fullMatch),
			Callback:   "endpoint:" + endpointName,
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
			Namespace:  "rewrite-endpoint:" + mask,
		}

		endpoints = append(endpoints, ep)
	}

	return endpoints
}

// cleanRewritePattern converts a WordPress rewrite regex to a readable route path
// ^my-endpoint/?$ -> /my-endpoint
// ^api/v1/([^/]+)/?$ -> /api/v1/{param}
func cleanRewritePattern(pattern string) string {
	route := pattern

	// Remove anchors
	route = strings.TrimPrefix(route, "^")
	route = strings.TrimSuffix(route, "$")

	// Remove optional trailing slash
	route = strings.TrimSuffix(route, "/?")
	route = strings.TrimSuffix(route, "/")

	// Convert capture groups to {param}
	capturePattern := regexp.MustCompile(`\([^)]+\)`)
	paramNum := 0
	route = capturePattern.ReplaceAllStringFunc(route, func(match string) string {
		paramNum++
		return "{param" + string(rune('0'+paramNum)) + "}"
	})

	// Ensure leading slash
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}

	return route
}

// extractQueryCallback extracts the handler from a WordPress rewrite query string
// 'index.php?pagename=my-page&action=$matches[1]' -> 'my-page'
func extractQueryCallback(query string) string {
	// Look for pagename or page parameter
	if match := regexp.MustCompile(`pagename=([^&]+)`).FindStringSubmatch(query); len(match) >= 2 {
		return "page:" + match[1]
	}
	if match := regexp.MustCompile(`page=([^&]+)`).FindStringSubmatch(query); len(match) >= 2 {
		return "page:" + match[1]
	}
	// Look for custom query vars
	if match := regexp.MustCompile(`([a-z_]+)=`).FindStringSubmatch(query); len(match) >= 2 {
		return "query:" + match[1]
	}
	return query
}

// detectHookBasedEndpoints detects endpoints created via template_redirect, parse_request hooks
// These hooks are used by plugins to create custom endpoints outside of the REST API
func detectHookBasedEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Skip vendor files
	if strings.Contains(filepath, "/vendor/") {
		return endpoints
	}

	// Detect template_redirect hooks
	matches := templateRedirectPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		fullMatch := content[match[0]:match[1]]

		// Extract callback from one of the capture groups
		var callback string
		for i := 2; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] > match[i] {
				callback = content[match[i]:match[i+1]]
				break
			}
		}

		lineNum := countLines(content[:match[0]]) + 1

		// Look for the handler function to understand what endpoint it creates
		route := extractEndpointFromHandler(callback, content)
		if route == "" {
			route = "/template-redirect:" + NormalizeCallback(callback)
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      route,
			Method:     "GET",
			AuthLevel:  InferAuthLevel(fullMatch),
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
			Namespace:  "template-redirect",
		}

		// Check surrounding context for auth
		if ep.AuthLevel == models.Unauthenticated {
			contextStart := match[0] - 500
			if contextStart < 0 {
				contextStart = 0
			}
			contextEnd := match[1] + 500
			if contextEnd > len(content) {
				contextEnd = len(content)
			}
			ep.AuthLevel = InferAuthLevel(content[contextStart:contextEnd])
		}

		endpoints = append(endpoints, ep)
	}

	// Detect parse_request hooks
	parseMatches := parseRequestPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range parseMatches {
		if len(match) < 2 {
			continue
		}

		fullMatch := content[match[0]:match[1]]

		// Extract callback from one of the capture groups
		var callback string
		for i := 2; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] > match[i] {
				callback = content[match[i]:match[i+1]]
				break
			}
		}

		lineNum := countLines(content[:match[0]]) + 1

		// Look for the handler function to understand what endpoint it creates
		route := extractEndpointFromHandler(callback, content)
		if route == "" {
			route = "/parse-request:" + NormalizeCallback(callback)
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      route,
			Method:     "GET",
			AuthLevel:  InferAuthLevel(fullMatch),
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
			Namespace:  "parse-request",
		}

		endpoints = append(endpoints, ep)
	}

	return endpoints
}

// extractEndpointFromHandler tries to find the actual endpoint from the handler function
// by looking for query var checks or other patterns that indicate the endpoint
func extractEndpointFromHandler(callback, content string) string {
	// Normalize the callback name
	normalized := NormalizeCallback(callback)
	parts := strings.Split(normalized, "::")
	funcName := parts[len(parts)-1]

	// Find the function body
	funcBody := findFunctionBody(funcName, content)
	if funcBody == "" {
		return ""
	}

	// Look for common patterns that indicate the endpoint
	// $_GET['action'], $_REQUEST['endpoint'], get_query_var('my_var')
	getPattern := regexp.MustCompile(`\$_(?:GET|REQUEST|POST)\s*\[\s*['"]([^'"]+)['"]\s*\]`)
	if match := getPattern.FindStringSubmatch(funcBody); len(match) >= 2 {
		return "/?action=" + match[1]
	}

	queryVarPattern := regexp.MustCompile(`get_query_var\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	if match := queryVarPattern.FindStringSubmatch(funcBody); len(match) >= 2 {
		return "/" + match[1]
	}

	return ""
}

// detectCPTRestEndpoints detects custom post types and taxonomies exposed via REST API
// register_post_type('cpt', array('show_in_rest' => true)) creates /wp-json/wp/v2/cpt
func detectCPTRestEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Skip vendor files
	if strings.Contains(filepath, "/vendor/") {
		return endpoints
	}

	// Detect register_post_type with show_in_rest
	cptMatches := registerPostTypePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range cptMatches {
		if len(match) < 6 {
			continue
		}

		postType := content[match[2]:match[3]]
		args := content[match[4]:match[5]]
		fullMatch := content[match[0]:match[1]]

		// Check if show_in_rest is true
		if !showInRestTruePattern.MatchString(args) {
			continue
		}

		// Skip if explicitly false (shouldn't happen but be safe)
		if showInRestFalsePattern.MatchString(args) {
			continue
		}

		// Get rest_base if specified, otherwise use post type slug
		restBase := postType
		if baseMatch := restBasePattern.FindStringSubmatch(args); len(baseMatch) >= 2 {
			restBase = baseMatch[1]
		}

		lineNum := countLines(content[:match[0]]) + 1

		// Create standard REST endpoints for the CPT
		rawCode := truncateCode(fullMatch, 300)
		cptEndpoints := createCPTRestEndpoints(restBase, "WP_REST_Posts_Controller", pluginSlug, filepath, lineNum, rawCode)
		endpoints = append(endpoints, cptEndpoints...)
	}

	// Detect register_taxonomy with show_in_rest
	taxMatches := registerTaxonomyPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range taxMatches {
		if len(match) < 6 {
			continue
		}

		taxonomy := content[match[2]:match[3]]
		args := content[match[4]:match[5]]
		fullMatch := content[match[0]:match[1]]

		// Check if show_in_rest is true
		if !showInRestTruePattern.MatchString(args) {
			continue
		}

		// Skip if explicitly false
		if showInRestFalsePattern.MatchString(args) {
			continue
		}

		// Get rest_base if specified, otherwise use taxonomy slug
		restBase := taxonomy
		if baseMatch := restBasePattern.FindStringSubmatch(args); len(baseMatch) >= 2 {
			restBase = baseMatch[1]
		}

		lineNum := countLines(content[:match[0]]) + 1

		// Create standard REST endpoints for the taxonomy
		rawCode := truncateCode(fullMatch, 300)
		taxEndpoints := createTaxonomyRestEndpoints(restBase, pluginSlug, filepath, lineNum, rawCode)
		endpoints = append(endpoints, taxEndpoints...)
	}

	return endpoints
}

// detectXMLRPCEndpoints detects XML-RPC methods added via xmlrpc_methods filter
// WordPress plugins can extend XML-RPC by adding custom methods
func detectXMLRPCEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Skip vendor files
	if strings.Contains(filepath, "/vendor/") {
		return endpoints
	}

	// First, find xmlrpc_methods filter registrations
	filterMatches := xmlrpcMethodsPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range filterMatches {
		if len(match) < 2 {
			continue
		}

		fullMatch := content[match[0]:match[1]]

		// Extract callback
		var callback string
		for i := 2; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] > match[i] {
				callback = content[match[i]:match[i+1]]
				break
			}
		}

		// Find the callback function body to extract method definitions
		normalized := NormalizeCallback(callback)
		parts := strings.Split(normalized, "::")
		funcName := parts[len(parts)-1]

		funcBody := findFunctionBody(funcName, content)
		if funcBody != "" {
			// Look for method definitions within the callback
			methodMatches := xmlrpcMethodDefPattern.FindAllStringSubmatch(funcBody, -1)
			for _, methodMatch := range methodMatches {
				if len(methodMatch) < 2 {
					continue
				}

				methodName := methodMatch[1]
				var methodCallback string
				for i := 2; i < len(methodMatch); i++ {
					if methodMatch[i] != "" {
						methodCallback = methodMatch[i]
						break
					}
				}

				lineNum := countLines(content[:match[0]]) + 1

				ep := models.Endpoint{
					PluginSlug: pluginSlug,
					Type:       models.EndpointTypeREST,
					Route:      "/xmlrpc.php:" + methodName,
					Method:     "POST",
					AuthLevel:  models.Subscriber, // XML-RPC typically requires auth by default
					Callback:   NormalizeCallback(methodCallback),
					File:       filepath,
					Line:       lineNum,
					RawCode:    truncateCode(fullMatch, 300),
					Namespace:  "xmlrpc",
				}

				// Check if the handler has specific auth requirements
				if methodCallback != "" {
					handlerBody := findFunctionBody(NormalizeCallback(methodCallback), content)
					if handlerBody != "" {
						ep.AuthLevel = InferAuthLevel(handlerBody)
						// XML-RPC minimum is Subscriber unless explicitly unauthenticated
						if ep.AuthLevel == models.Unauthenticated {
							// Check if it has explicit __return_true or similar
							if !strings.Contains(handlerBody, "__return_true") &&
								!strings.Contains(handlerBody, "return true") {
								ep.AuthLevel = models.Subscriber
							}
						}
					}
				}

				endpoints = append(endpoints, ep)
			}
		}

		// If no method definitions found in callback, register the filter itself as an endpoint
		if len(endpoints) == 0 {
			lineNum := countLines(content[:match[0]]) + 1
			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeREST,
				Route:      "/xmlrpc.php:custom",
				Method:     "POST",
				AuthLevel:  models.Subscriber,
				Callback:   NormalizeCallback(callback),
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode(fullMatch, 300),
				Namespace:  "xmlrpc-filter",
			}
			endpoints = append(endpoints, ep)
		}
	}

	// Also scan for direct method definitions outside of known callbacks
	// $methods['prefix.method'] = [$this, 'callback']
	directMatches := xmlrpcMethodDefPattern.FindAllStringSubmatchIndex(content, -1)
	methodsSeen := make(map[string]bool)

	// Mark methods we already found via filter callbacks
	for _, ep := range endpoints {
		methodsSeen[ep.Route] = true
	}

	for _, match := range directMatches {
		if len(match) < 4 {
			continue
		}

		methodName := content[match[2]:match[3]]
		route := "/xmlrpc.php:" + methodName

		// Skip if already found
		if methodsSeen[route] {
			continue
		}
		methodsSeen[route] = true

		fullMatch := content[match[0]:match[1]]

		// Extract callback
		var callback string
		for i := 4; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] > match[i] {
				callback = content[match[i]:match[i+1]]
				break
			}
		}

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      route,
			Method:     "POST",
			AuthLevel:  models.Subscriber,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
			Namespace:  "xmlrpc",
		}

		endpoints = append(endpoints, ep)
	}

	return endpoints
}

// --- Entry points driven by code outside the analysed tree ---

// endpointTypeFramework labels an entry point whose caller is not in the tree.
//
// It is spelled here rather than added to pkg/models because that package is
// not this change's to edit; the string is what every consumer reads either
// way, and it is deliberately not "direct", which already means a PHP file
// reachable by URL without the WordPress bootstrap.
const endpointTypeFramework = models.EndpointType("framework")

var (
	// A class declaration together with the parent it names. Only the parent
	// matters here; a class with no parent is completed by nothing outside the
	// tree. PHP's identifier grammar has no case rule and permits a namespace
	// path with or without a leading separator.
	frameworkClassParentPattern = regexp.MustCompile(
		`(?:\b(?:abstract|final|readonly)\s+)*\bclass\s+(` + phpIdentifier + `)\s+extends\s+(` + phpQualifiedName + `)`)

	// Every declaration of a function or method, used both to enumerate a
	// class's own methods and to know which names the tree declares at all.
	frameworkDeclPattern = regexp.MustCompile(
		`(?:(public|protected|private)\s+)?(?:(?:static|final|abstract)\s+)*function\s+(` + phpIdentifier + `)\s*\(`)

	// A call that PHP resolves on the current object: inside a class body,
	// these are the only spellings that can denote a method of that class.
	frameworkSelfCallPattern = regexp.MustCompile(
		`(?:\$this\s*->|self\s*::|static\s*::)\s*(` + phpIdentifier + `)\s*\(`)

	// parent::m() denotes a method of an ANCESTOR, so it keeps that ancestor's
	// method alive rather than the calling class's.
	frameworkParentCallPattern = regexp.MustCompile(
		`parent\s*::\s*(` + phpIdentifier + `)\s*\(`)

	// [ $this, 'm' ] and array( $this, 'm' ): a method handed to something else
	// to call. The receiver is required, because a bare 'm' string says nothing
	// about which class it belongs to.
	frameworkThisCallbackPattern = regexp.MustCompile(
		`(?:\[|array\s*\()\s*(?:\$this|self::class|static::class|__CLASS__)\s*,\s*['"](` + phpIdentifier + `)['"]`)

	// Name::m(, [ Name::class, 'm' ], array( 'Name', 'm' ): a call site that
	// names the class explicitly, so it can be resolved without knowing where
	// it appears.
	frameworkStaticCallPattern = regexp.MustCompile(
		`(` + phpIdentifier + `)\s*::\s*(` + phpIdentifier + `)\s*\(`)
	frameworkClassCallbackPattern = regexp.MustCompile(
		`(?:\[|array\s*\()\s*(?:['"](` + phpIdentifier + `)['"]|(` + phpIdentifier + `)\s*::\s*class)\s*,\s*['"](` + phpIdentifier + `)['"]`)

	// A body that reaches nothing cannot make anything reachable.
	frameworkIncludePattern   = regexp.MustCompile(`\b(?:include|require)(?:_once)?\b`)
	frameworkCallTokenPattern = regexp.MustCompile(`\b(` + phpIdentifier + `)\s*\(`)
)

// frameworkMethod is one method declaration inside a class-like extent.
type frameworkMethod struct {
	name       string
	visibility string
	file       string
	line       int
	bodyStart  int
	bodyEnd    int
}

// frameworkClass is what is known about one class declaration.
type frameworkClass struct {
	name      string
	parent    string // last segment, lowercased; "" when the class extends nothing
	file      string
	methods   []frameworkMethod
	selfRefs  map[string]bool // methods this body calls on $this / self / static
	parentRef map[string]bool // methods this body calls via parent::
}

// DetectFrameworkEntryPoints reports the methods that only code outside the
// analysed tree can be calling.
//
// Two facts about PHP, and nothing about any framework:
//
//   - A method body runs only when something calls it. If no call site anywhere
//     in the analysed source can denote it, the caller is outside the analysed
//     source.
//   - A class that extends a name the analysed source does not declare is
//     completed by code that is not here, and that code is what invokes the
//     methods the class overrides.
//
// Together they say that a non-private method of a class whose inheritance
// chain leaves the tree, which the tree never calls, is an entry point driven
// by an external caller. That is true of a page-builder widget's render(), of a
// WP_List_Table subclass's column_*(), of a WP_REST_Controller subclass and of
// a payment gateway's process_payment() equally, and the rule names none of
// them.
//
// Before this pass nothing modelled such a method as an entry point at all: the
// widget detector keys on WP_Widget specifically, and no other detector treats
// an uncalled method as a root. In a 143-plugin corpus, 42 trees declare a class
// extending a *Widget_Base that is not WP_Widget and 47 declare a WP_List_Table
// subclass -- and for the widget-heavy ones the product IS those classes, so the
// analyzer reported a couple of dozen endpoints for a plugin whose entire
// surface is several hundred widget files, and the vulnerable code was reachable
// from nothing.
//
// The level is Unauthenticated, deliberately. Who drives an unknown external
// framework is not knowable from the tree, and the bottom of the lattice is the
// answer that can never hide a bug behind a privilege the code was never shown
// to require. It costs exactness: a WP_List_Table's column_* methods really are
// admin-only, and this pass will call them public.
func DetectFrameworkEntryPoints(files map[string]string, pluginSlug string) []models.Endpoint {
	classes, declaredNames := frameworkScan(files)
	if len(classes) == 0 {
		return nil
	}

	// PHP class names are case-insensitive, so every lookup is lowercased.
	byName := make(map[string]*frameworkClass, len(classes))
	for _, c := range classes {
		if _, dup := byName[strings.ToLower(c.name)]; !dup {
			byName[strings.ToLower(c.name)] = c
		}
	}
	children := make(map[string][]*frameworkClass, len(classes))
	for _, c := range classes {
		if c.parent != "" {
			children[c.parent] = append(children[c.parent], c)
		}
	}

	staticPairs := frameworkStaticReferences(files)

	out := make([]models.Endpoint, 0, 64)
	for _, c := range classes {
		if !frameworkManaged(c, byName) {
			continue
		}
		// The call sites that can denote a method of c.
		//
		// $this->m() anywhere in c's inheritance closure can be c's m: PHP
		// resolves it on the runtime object, so a base calling $this->m()
		// reaches the most-derived implementation, and a subclass calling
		// $this->m() reaches the one it inherited.
		//
		// parent::m() is different, and the difference matters. It denotes an
		// ANCESTOR's m, never the calling class's own, so it may only suppress
		// c when the call site is in a strict descendant. Counting it for the
		// calling class too would delete exactly the entry point this pass
		// exists to find: a subclass that overrides render() and opens with
		// parent::render() is the commonest override shape there is, and it is
		// the subclass's render that the framework calls.
		related, descendants := frameworkClosure(c, byName, children)
		called := make(map[string]bool)
		for _, rel := range related {
			for m := range rel.selfRefs {
				called[m] = true
			}
		}
		for _, d := range descendants {
			for m := range d.parentRef {
				called[m] = true
			}
		}

		content := files[c.file]
		lowerClass := strings.ToLower(c.name)
		for _, m := range c.methods {
			if m.visibility == "private" || strings.HasPrefix(m.name, "__") {
				continue
			}
			if called[m.name] || staticPairs[lowerClass+"::"+strings.ToLower(m.name)] {
				continue
			}
			if m.bodyEnd <= m.bodyStart || m.bodyEnd > len(content) {
				continue
			}
			body := content[m.bodyStart:m.bodyEnd]
			if !frameworkReachesCode(body, m.name, declaredNames) {
				// A body that calls nothing the tree declares and includes no
				// file cannot root a walk: an endpoint for it would widen the
				// reported surface without widening what is examined.
				continue
			}
			qualified := c.name + "::" + m.name
			out = append(out, models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       endpointTypeFramework,
				Route:      "framework:" + qualified,
				Method:     "GET",
				AuthLevel:  models.Unauthenticated,
				Callback:   qualified,
				File:       c.file,
				Line:       m.line,
				RawCode:    "class " + c.name + " extends " + c.parent,
			})
		}
	}
	return out
}

// frameworkScan reads every file once and records the classes, their methods,
// and the call sites that resolve on the current object.
func frameworkScan(files map[string]string) ([]*frameworkClass, map[string]bool) {
	classes := make([]*frameworkClass, 0, 64)
	declaredNames := make(map[string]bool, 1024)

	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		content := files[path]
		if !strings.Contains(content, "class ") {
			for _, d := range frameworkDeclPattern.FindAllStringSubmatch(content, -1) {
				declaredNames[strings.ToLower(d[2])] = true
			}
			continue
		}

		parents := make(map[string]string)
		for _, m := range frameworkClassParentPattern.FindAllStringSubmatch(content, -1) {
			parent := m[2]
			if i := strings.LastIndex(parent, "\\"); i >= 0 {
				parent = parent[i+1:]
			}
			parents[strings.ToLower(m[1])] = strings.ToLower(parent)
		}

		extents := findWrapperClassExtents(content)
		byExtent := make(map[string]*frameworkClass, len(extents))
		for _, e := range extents {
			c := &frameworkClass{
				name:      e.name,
				parent:    parents[strings.ToLower(e.name)],
				file:      path,
				selfRefs:  make(map[string]bool),
				parentRef: make(map[string]bool),
			}
			body := content[e.open:e.end]
			for _, s := range frameworkSelfCallPattern.FindAllStringSubmatch(body, -1) {
				c.selfRefs[s[1]] = true
			}
			for _, s := range frameworkThisCallbackPattern.FindAllStringSubmatch(body, -1) {
				c.selfRefs[s[1]] = true
			}
			for _, s := range frameworkParentCallPattern.FindAllStringSubmatch(body, -1) {
				c.parentRef[s[1]] = true
			}
			byExtent[e.name] = c
			classes = append(classes, c)
		}

		for _, d := range frameworkDeclPattern.FindAllStringSubmatchIndex(content, -1) {
			name := content[d[4]:d[5]]
			declaredNames[strings.ToLower(name)] = true

			owner := classAt(extents, d[0])
			if owner == "" {
				continue
			}
			c := byExtent[owner]
			if c == nil {
				continue
			}
			open := declBodyOpen(content, d[1])
			if open < 0 {
				continue
			}
			end := matchBrace(content, open)
			if end < 0 {
				continue
			}
			visibility := ""
			if d[2] >= 0 {
				visibility = content[d[2]:d[3]]
			}
			c.methods = append(c.methods, frameworkMethod{
				name:       name,
				visibility: visibility,
				file:       path,
				line:       strings.Count(content[:d[0]], "\n") + 1,
				bodyStart:  open,
				bodyEnd:    end,
			})
		}
	}
	return classes, declaredNames
}

// frameworkStaticReferences collects every call site that names its class:
// Name::method(, [ Name::class, 'method' ] and array( 'Name', 'method' ).
func frameworkStaticReferences(files map[string]string) map[string]bool {
	out := make(map[string]bool, 256)
	for _, content := range files {
		for _, m := range frameworkStaticCallPattern.FindAllStringSubmatch(content, -1) {
			out[strings.ToLower(m[1])+"::"+strings.ToLower(m[2])] = true
		}
		for _, m := range frameworkClassCallbackPattern.FindAllStringSubmatch(content, -1) {
			cls := m[1]
			if cls == "" {
				cls = m[2]
			}
			out[strings.ToLower(cls)+"::"+strings.ToLower(m[3])] = true
		}
	}
	return out
}

// frameworkManaged reports whether c's inheritance chain terminates outside the
// analysed tree.
func frameworkManaged(c *frameworkClass, byName map[string]*frameworkClass) bool {
	seen := make(map[string]bool, 4)
	for cur := c; ; {
		if cur.parent == "" {
			return false
		}
		next, ok := byName[cur.parent]
		if !ok {
			return true
		}
		if seen[cur.parent] {
			// A cycle cannot happen in valid PHP, but a name collision between
			// two files can produce one; treat it as in-tree, which emits
			// nothing.
			return false
		}
		seen[cur.parent] = true
		cur = next
	}
}

// frameworkClosure returns c together with every in-tree class it inherits from
// or that inherits from it -- the classes whose $this can denote a method of c
// -- and separately the strict descendants, whose parent:: calls denote c's.
func frameworkClosure(c *frameworkClass, byName map[string]*frameworkClass,
	children map[string][]*frameworkClass) (related, descendants []*frameworkClass) {

	related = []*frameworkClass{c}
	seen := map[*frameworkClass]bool{c: true}

	for cur := c; cur.parent != ""; {
		next, ok := byName[cur.parent]
		if !ok || seen[next] {
			break
		}
		seen[next] = true
		related = append(related, next)
		cur = next
	}

	queue := []*frameworkClass{c}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, child := range children[strings.ToLower(cur.name)] {
			if seen[child] {
				continue
			}
			seen[child] = true
			related = append(related, child)
			descendants = append(descendants, child)
			queue = append(queue, child)
		}
	}
	return related, descendants
}

// frameworkReachesCode reports whether a method body can root a walk: it
// includes a file, or it calls a name the tree declares somewhere.
func frameworkReachesCode(body, own string, declaredNames map[string]bool) bool {
	if frameworkIncludePattern.MatchString(body) {
		return true
	}
	// parent::m() is a call to a different declaration even when m is this
	// method's own name -- that is what overriding means -- so it is not
	// covered by the self-call exclusion below.
	if frameworkParentCallPattern.MatchString(body) {
		return true
	}
	for _, m := range frameworkCallTokenPattern.FindAllStringSubmatch(body, -1) {
		name := strings.ToLower(m[1])
		if name == strings.ToLower(own) {
			continue
		}
		if declaredNames[name] {
			return true
		}
	}
	return false
}

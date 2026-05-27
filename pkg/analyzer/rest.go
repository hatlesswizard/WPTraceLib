package analyzer

import (
	"regexp"
	"strings"
	"unicode"

	wpast "github.com/hatlesswizard/wptracelib/pkg/ast"
	"github.com/hatlesswizard/wptracelib/pkg/config"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// getRESTConfig returns the current REST configuration.
// This is shared with auth.go's authConfig for consistency.
func getRESTConfig() *config.Config {
	return GetAuthConfig()
}

// Package-level compiled regex patterns for REST detection
var (
	// Patterns for extractCallback
	restCallbackStringPattern   = regexp.MustCompile(`['"]callback['"]\s*=>\s*['"]([^'"]+)['"]`)
	restCallbackArrayPattern    = regexp.MustCompile(`['"]callback['"]\s*=>\s*(\[[^\]]+\])`)
	restCallbackArrayAltPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*(array\s*\([^)]+\))`)

	// Pattern for __CLASS__ . '::method' concatenation callbacks
	// Matches: 'callback' => __CLASS__ . '::method_name'
	restCallbackClassConcatPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*__CLASS__\s*\.\s*['"]::([^'"]+)['"]`)

	// Pattern for __NAMESPACE__ . '\function' concatenation callbacks
	// Matches: 'callback' => __NAMESPACE__ . '\function_name'
	// Common in namespaced WordPress plugins
	restCallbackNamespaceConcatPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*__NAMESPACE__\s*\.\s*['"]\\([^'"]+)['"]`)

	// Pattern for static class method callbacks
	// Matches: 'callback' => 'ClassName::method' or "ClassName::method"
	restCallbackStaticPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*['"]([A-Za-z_][A-Za-z0-9_\\]*::[\$a-zA-Z_][a-zA-Z0-9_]*)['"]`)

	// Pattern for array callbacks with method extraction
	// Matches: 'callback' => array( $this, 'method' ) or [ $this, 'method' ]
	restCallbackArrayMethodPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*(?:array\s*\(|\[)\s*\$(?:this|self|class)\s*,\s*['"]([^'"]+)['"]\s*(?:\)|\])`)

	// Pattern for static::method or self::method callbacks
	// Matches: 'callback' => array( static::class, 'method' )
	restCallbackStaticClassPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*(?:array\s*\(|\[)\s*(?:static|self)::class\s*,\s*['"]([^'"]+)['"]\s*(?:\)|\])`)

	// Pattern for closure/anonymous function
	restCallbackClosurePattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*(function\s*\()`)

	// Pattern for PHP 7.4+ arrow functions (short closures)
	// Matches: 'callback' => fn( $request ) => ...
	restCallbackArrowFnPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*fn\s*\(`)

	// Pattern for variable callbacks
	// Matches: 'callback' => $callback or $this->callback
	restCallbackVariablePattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*(\$[a-zA-Z_][a-zA-Z0-9_]*(?:->[a-zA-Z_][a-zA-Z0-9_]*)?)(?:\s*[,\]\)])`)

	// Pattern for method call callbacks that return callables
	// Matches: 'callback' => $this->get_callback() or $this->method_name()
	// Common in WooCommerce and modern WordPress plugins
	restCallbackMethodCallPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*\$this\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)`)

	// Pattern for method call callbacks with arguments
	// Matches: 'callback' => $this->callback( $arg1, 'arg2' )
	// Common in framework-based plugins (SureCart, etc.)
	restCallbackMethodWithArgsPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*\$this\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]+\)`)

	// Pattern for ClassName::class combined with method
	// Matches: 'callback' => [ ClassName::class, 'method' ]
	restCallbackClassConstPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*(?:array\s*\(|\[)\s*([A-Za-z_][A-Za-z0-9_\\]*)::class\s*,\s*['"]([^'"]+)['"]\s*(?:\)|\])`)

	// Pattern for array callbacks with function call as first element
	// Matches: 'callback' => array( FunctionCall(), 'method' )
	// Also handles: array( ClassName::getInstance(), 'method' ), array( $obj->method(), 'callback' )
	// Key: uses [^,]+ instead of [^)]+ to handle nested parentheses in function calls
	restCallbackFunctionArrayPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*array\s*\([^,]+,\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)

	// Pattern for bracket callbacks with function call as first element
	// Matches: 'callback' => [ FunctionCall(), 'method' ]
	restCallbackFunctionBracketPattern = regexp.MustCompile(`['"]callback['"]\s*=>\s*\[[^,]+,\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)

	// Pattern for global constant namespace (e.g., PLUGIN_REST_URL, PLUGIN_REST_NS)
	// Matches: register_rest_route(CONSTANT_NAME, '/route', [...])
	// Uses (?s) flag for multiline matching (handles newlines between arguments)
	restGlobalConstNamespacePattern = regexp.MustCompile(
		`(?s)register_rest_route\s*\(\s*` +
			`([A-Z][A-Z0-9_]*)\s*,\s*` + // CONSTANT_NAME (uppercase only)
			`['"]([^'"]+)['"]\s*,\s*` + // route
			`(array\s*\(|\[)`, // start of args
	)

	// Pattern for wrapper method calls: $this->register_route('route', [...])
	// Uses (?s) flag for multiline matching
	restWrapperMethodPattern = regexp.MustCompile(
		`(?s)\$this\s*->\s*register_route\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // route
			`(array\s*\(|\[)`, // start of args
	)

	// Pattern for static wrapper calls: self::register_route('/route', ...)
	// Uses (?s) flag for multiline matching
	restStaticWrapperPattern = regexp.MustCompile(
		`(?s)(?:self|static)\s*::\s*register_route\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // route
			`['"]?([^'"]+?)['"]?\s*,\s*` + // callback method or WP_REST_Server constant
			`(WP_REST_Server::[A-Z]+|['"][^'"]+['"])`, // method
	)

	// Pattern for new REST_Route() class instantiation
	// new REST_Route('route/path', [...])
	// Uses (?s) flag for multiline matching
	restRouteClassPattern = regexp.MustCompile(
		`(?s)new\s+REST_Route\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // route
			`(array\s*\(|\[)`, // start of args
	)

	// Pattern for wrapper method: $this->_register_route('/route', [...], $auth)
	// Uses (?s) flag for multiline matching
	wrapperRegisterRoutePattern = regexp.MustCompile(
		`(?s)\$this\s*->\s*_register_route\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // route (group 1)
			`(\[|array\s*\()`, // start of args (group 2)
	)

	// Pattern for register_rest_route with untrailingslashit wrapper
	// register_rest_route(untrailingslashit('namespace/v1/' . $this->prefix), '/route', [...])
	// Uses (?s) for multiline and handles flexible whitespace
	restUntrailingslashitPattern = regexp.MustCompile(
		`(?s)register_rest_route\s*\(\s*` +
			`untrailingslashit\s*\(\s*['"]([^'"]+)['"]` + // namespace base inside untrailingslashit (group 1)
			`[^)]*\)` + // rest of untrailingslashit call (ends at closing paren)
			`\s*,\s*` + // comma after namespace
			`.*?` + // route (non-greedy, can contain parens)
			`\s*,\s*` + // comma after route
			`(array\s*\(|\[)`, // start of args (group 2)
	)

	// Pattern for property-based wrapper: $this->property->register_rest_route('/route', [...])
	restPropertyWrapperPattern = regexp.MustCompile(
		`(?s)\$this\s*->\s*[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*register_rest_route\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // route (group 1)
			`(\[|array\s*\()`, // start of args (group 2)
	)

	// Pattern for array-based route definitions: ROUTE_PATH => '/path'
	restArrayRoutePattern = regexp.MustCompile(
		`(?:ROUTE_PATH|path|route)\s*=>\s*['"]([^'"]+)['"]`,
	)

	// Pattern for define() constants to help resolve namespace values
	phpDefineConstPattern = regexp.MustCompile(
		`define\s*\(\s*['"]([A-Z][A-Z0-9_]*)['"]` + // constant name
			`\s*,\s*['"]([^'"]+)['"]`, // value
	)

	// Extended patterns for variable/constant namespace detection
	// Only matches the start - args are extracted with bracket matching
	restVarNamespacePattern = regexp.MustCompile(
		`register_rest_route\s*\(\s*` +
			`(\$[a-zA-Z_][a-zA-Z0-9_]*(?:->(?:[a-zA-Z_][a-zA-Z0-9_]*))?|` + // $var or $this->prop
			`(?:self|static)::[a-zA-Z_][a-zA-Z0-9_]*|` + // self::const or static::CONST (case-insensitive)
			`[A-Za-z_][A-Za-z0-9_]*::[a-zA-Z_][a-zA-Z0-9_]*)` + // ClassName::const
			`\s*,\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // route (literal)
			`(\[|array\s*\()`, // start of args array
	)

	// Pattern for REST route with concatenated route argument
	// Captures: namespace (literal or constant), route (concatenated expression)
	restConcatRoutePattern = regexp.MustCompile(
		`register_rest_route\s*\(\s*` +
			`(?:['"]([^'"]+)['"]|` + // namespace literal (group 1)
			`((?:self|static)::[a-zA-Z_][a-zA-Z0-9_]*)|` + // self::const (group 2)
			`(\$[a-zA-Z_][a-zA-Z0-9_]*(?:->(?:[a-zA-Z_][a-zA-Z0-9_]*))?)` + // $var (group 3)
			`)` +
			`\s*,\s*` +
			`(['"][^'"]*['"]\s*\.\s*(?:self|static)::[a-zA-Z_][a-zA-Z0-9_]*(?:\s*\.\s*['"][^'"]*['"])?(?:\s*\.\s*(?:self|static)::[a-zA-Z_][a-zA-Z0-9_]*)?(?:\s*\.\s*['"][^'"]*['"])?)` + // concatenated route (group 4)
			`\s*,\s*` +
			`(\[|array\s*\()`, // start of args array (group 5)
	)

	// Pattern for both variable namespace and route
	restFullVarPattern = regexp.MustCompile(
		`register_rest_route\s*\(\s*` +
			`([^,]+?)\s*,\s*` + // namespace (any)
			`([^,]+?)\s*,\s*` + // route (any)
			`(\[|array\s*\()`, // start of args array
	)

	// Pattern for register_rest_route with variable args (third argument is a variable)
	// Example: register_rest_route( Main::API_V1_NAMESPACE, self::ROUTE, $route_args );
	// This pattern captures the variable name so we can find its definition
	restVarArgsPattern = regexp.MustCompile(
		`(?:register_rest_route|\\\\register_rest_route)\s*\(\s*` +
			`([^,]+?)\s*,\s*` + // namespace (group 1)
			`([^,]+?)\s*,\s*` + // route (group 2)
			`(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*\)`, // args variable (group 3) - ends with )
	)

	// Pattern for register_rest_route with property-based args (e.g., $this->options)
	// Example: register_rest_route($this->namespace, "/{$uri}", $this->options);
	restPropertyArgsPattern = regexp.MustCompile(
		`(?:register_rest_route|\\\\register_rest_route)\s*\(\s*` +
			`([^,]+?)\s*,\s*` + // namespace (group 1) - can be $this->property or variable
			`([^,]+?)\s*,\s*` + // route (group 2) - can be interpolated string
			`(\$(?:this|self)->(?:[a-zA-Z_][a-zA-Z0-9_]*))\s*\)`, // args property (group 3) - $this->prop or $self->prop
	)

	// Pattern to find variable array assignment: $route_args = [...]
	varArrayAssignPattern = regexp.MustCompile(
		`(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(\[|array\s*\()`,
	)

	// Pattern for common REST wrapper methods like registerGetRoute, registerPostRoute
	// These are used by frameworks/plugins that wrap register_rest_route
	// Example: $api->registerGetRoute('/path', Endpoint::class);
	restWrapperMethodCallPattern = regexp.MustCompile(
		`(?:\$[a-zA-Z_][a-zA-Z0-9_]*(?:->(?:[a-zA-Z_][a-zA-Z0-9_]*))*|` + // variable/property chain
		`\$this|self|static)\s*->\s*` + // or $this/self/static
		`register(Get|Post|Put|Patch|Delete)Route\s*\(\s*` + // method name - captures HTTP method (group 1)
		`['"]([^'"]+)['"]\s*,?\s*` + // route (group 2)
		`([^)]+)?`, // optional additional args (group 3)
	)

	// Pattern for register_rest_route with sprintf in route argument
	// Example: register_rest_route($this->namespace, sprintf('/%s/(?P<id>\d+)', $base), [...])
	// Uses (?s) flag for multiline matching
	restSprintfRoutePattern = regexp.MustCompile(
		`(?s)register_rest_route\s*\(\s*` +
			`([^,]+?)\s*,\s*` + // namespace (group 1) - any expression
			`sprintf\s*\(\s*` + // sprintf call
			`['"]([^'"]+)['"]\s*` + // format string (group 2)
			`(?:,\s*([^)]+))?\s*\)` + // optional sprintf args (group 3)
			`\s*,\s*` +
			`(\[|array\s*\()`, // start of args array (group 4)
	)

	// Pattern for WP_REST_Controller subclass with getRoutePath method
	// This is a common WordPress pattern where routes are defined in child classes
	// function getRoutePath() :string { return '/path'; } or
	// public function getRoutePath(): string { return 'path'; }
	wpRestControllerRoutePattern = regexp.MustCompile(
		`(?:public\s+)?function\s+getRoutePath\s*\([^)]*\)\s*(?::\s*string)?\s*\{[^}]*return\s+['"]([^'"]+)['"]`,
	)

	// Pattern to detect WP_REST_Controller extension (to confirm the class is a REST route)
	wpRestControllerExtendPattern = regexp.MustCompile(
		`class\s+([A-Za-z_][A-Za-z0-9_]*)\s+extends\s+(?:[A-Za-z_\\][A-Za-z0-9_\\]*)?(?:WP_REST_Controller|RouteBase|Rest_Controller|Base)`,
	)

	// Pre-compiled patterns for frequently called functions (moved from function scope)
	// splitMultipleRouteDefinitions
	innerArrayPattern = regexp.MustCompile(`(^|\s|,)(array\s*\(|\[)`)

	// resolveSprintfRoute
	sprintfPlaceholderPattern = regexp.MustCompile(`%(\d+\$)?[sdfu]`)

	// findClassNamespace - get_namespace patterns
	classGetNamespacePattern = regexp.MustCompile(
		`function\s+get_namespace\s*\([^)]*\)[^{]*\{[^}]*return\s+['"]([^'"]+)['"]`)
	classGetNamespaceInterpolatedPattern = regexp.MustCompile(
		`function\s+get_namespace\s*\([^)]*\)[^{]*\{[^}]*return\s+"([^"]+)"`)
	classGetSlugPattern = regexp.MustCompile(
		`function\s+get_slug\s*\([^)]*\)[^{]*\{[^}]*return\s+['"]([^'"]+)['"]`)
	classNamespacePropertyPattern = regexp.MustCompile(
		`(?:protected|public|private)\s+\$namespace\s*=\s*['"]([^'"]+)['"]`)
	classNamespaceAssignPattern = regexp.MustCompile(
		`\$this\s*->\s*namespace\s*=\s*['"]([^'"]+)['"]`)

	// findClassNamespaceFromConstant
	namespaceConstPatterns = []*regexp.Regexp{
		regexp.MustCompile(`const\s+(?:REST_API_)?NAMESPACE\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`define\s*\(\s*['"][A-Z_]*REST[A-Z_]*NAMESPACE['"]` + `\s*,\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`define\s*\(\s*['"][A-Z_]*API[A-Z_]*NAMESPACE['"]` + `\s*,\s*['"]([^'"]+)['"]`),
	}
	restRouteConstPattern = regexp.MustCompile(
		`const\s+(?:REST_)?ROUTE\s*=\s*['"]([^'"]+)['"]`)

	// findRESTRootConstant
	restRootPatterns = []*regexp.Regexp{
		regexp.MustCompile(`const\s+REST_ROOT\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`REST_ROOT\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`define\s*\(\s*['"][A-Z_]*REST_ROOT['"]` + `\s*,\s*['"]([^'"]+)['"]`),
	}

	// findPropertyNamespace
	propertyNamespacePatterns = []*regexp.Regexp{
		regexp.MustCompile(`\$route_namespace\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`route_namespace\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`private\s+string\s+\$route_namespace\s*=\s*['"]([^'"]+)['"]`),
	}

	// extractAPINamespace
	apiNamespaceConstPattern  = regexp.MustCompile(`const\s+API_NAMESPACE\s*=\s*['"]([^'"]+)['"]`)
	apiNamespaceDefinePattern = regexp.MustCompile(`define\s*\(\s*['"]API_NAMESPACE['"]` + `\s*,\s*['"]([^'"]+)['"]`)

	// extractWPRestControllerNamespace - camelCase getNamespace variant
	wpRestGetNamespaceCamelPattern = regexp.MustCompile(
		`function\s+getNamespace\s*\([^)]*\)\s*(?::\s*string)?\s*\{[^}]*return\s+['"]([^'"]+)['"]`)
	// extractWPRestControllerNamespace - snake_case get_namespace variant
	wpRestGetNamespacePattern = regexp.MustCompile(
		`function\s+get_namespace\s*\([^)]*\)\s*(?::\s*string)?\s*\{[^}]*return\s+['"]([^'"]+)['"]`)
	wpRestBuildNamespacePattern = regexp.MustCompile(
		`function\s+buildNamespace\s*\([^)]*\)[^{]*\{[^}]*sprintf\s*\(\s*['"]([^'"]+)['"]`)
	// Property/const patterns for namespace extraction in WP_REST_Controller
	wpRestControllerNamespacePatterns = []*regexp.Regexp{
		regexp.MustCompile(`protected\s+\$namespace\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`const\s+NAMESPACE\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`const\s+REST_NAMESPACE\s*=\s*['"]([^'"]+)['"]`),
	}

	// extractWPRestControllerMethod
	routeMethodConstPattern = regexp.MustCompile(
		`const\s+ROUTE_METHOD\s*=\s*(?:\\?WP_REST_Server::)?([A-Z_]+)`)
	routeMethodArrayPattern = regexp.MustCompile(
		`function\s+getRouteMethods\s*\([^)]*\)[^{]*\{[^}]*return\s+\[['"]([^'"]+)['"]`)

	// extractNearbyMethod
	nearbyMethodPattern = regexp.MustCompile(`(?:ROUTE_METHODS|methods)\s*=>\s*['"]([^'"]+)['"]`)

	// extractWPRestControllerAuth
	userCapPattern = regexp.MustCompile(`['"]user_cap['"]\s*=>\s*['"]([^'"]+)['"]`)

	// extractClassName
	extractClassNamePattern = regexp.MustCompile(`class\s+([A-Za-z_][A-Za-z0-9_]*)\s+extends`)

	// Class constant resolution pattern (e.g., "Endpoint::class")
	classConstResolvePattern = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_\\]*)\s*::\s*class`)
)

// RESTEndpointPattern matches register_rest_route calls - just the start
// The args are extracted using bracket matching for proper nested structure support
var RESTEndpointPattern = regexp.MustCompile(
	`register_rest_route\s*\(\s*` +
		`['"]([^'"]+)['"]\s*,\s*` + // namespace (group 1)
		`['"]([^'"]+)['"]\s*,\s*` + // route (group 2)
		`(\[|array\s*\()`, // start of args array (group 3)
)

// MethodPattern matches the methods key in REST route args
// Handles WP_REST_Server::CONSTANT, \WP_REST_Server::CONSTANT, Server::CONSTANT, and custom TransportMethods::CONSTANT
var MethodPattern = regexp.MustCompile(
	`['"]methods?['"]\s*=>\s*(?:` +
		`['"]([^'"]+)['"]` + // string value (group 1)
		`|` +
		`(?:\\?(?:WP_REST_Server|TransportMethods|Methods|Server)::)?([A-Z_]+)` + // constant (group 2)
		`)`,
)

// Patterns for cleaning PHP interpolation from REST routes
var (
	restRouteThisBracePattern     = regexp.MustCompile(`\{\$this->([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	restRouteVarBracePattern      = regexp.MustCompile(`\{\$([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	restRouteThisNoBracePattern   = regexp.MustCompile(`\$this->([a-zA-Z_][a-zA-Z0-9_]*)`)
	restRouteVarNoBracePattern    = regexp.MustCompile(`\$([a-z][a-zA-Z0-9_]*)`)
	restRouteMethodCallPattern    = regexp.MustCompile(`\{\$this->([a-zA-Z_][a-zA-Z0-9_]*)\(\)\}`)
	restRouteMethodNoBracePattern = regexp.MustCompile(`\$this->([a-zA-Z_][a-zA-Z0-9_]*)\(\)`)
	// Pattern for {dynamic:...} placeholders - extract the meaningful part
	restRouteDynamicPattern = regexp.MustCompile(`\{dynamic:([a-zA-Z_][a-zA-Z0-9_()]*)\}`)
)

// cleanRouteString cleans PHP interpolation syntax from REST route strings
// Converts {$this->prop} -> {prop}, {$var} -> {var}, $this->method() -> {method}
// Also cleans {dynamic:...} placeholders to simpler forms
func cleanRouteString(route string) string {
	// Replace {$this->method()} with {method}
	route = restRouteMethodCallPattern.ReplaceAllString(route, "{$1}")

	// Replace {$this->prop} with {prop}
	route = restRouteThisBracePattern.ReplaceAllString(route, "{$1}")

	// Replace {$var} with {var}
	route = restRouteVarBracePattern.ReplaceAllString(route, "{$1}")

	// Replace $this->method() with {method}
	route = restRouteMethodNoBracePattern.ReplaceAllString(route, "{$1}")

	// Replace $this->prop with {prop}
	route = restRouteThisNoBracePattern.ReplaceAllString(route, "{$1}")

	// Replace $var with {var} (only lowercase-starting vars to avoid superglobals)
	route = restRouteVarNoBracePattern.ReplaceAllString(route, "{$1}")

	// Clean up {dynamic:...} placeholders
	// {dynamic:this_namespace} -> {namespace}
	// {dynamic:static_namespace} -> {namespace}
	// {dynamic:Route_NAMESPACE} -> {NAMESPACE}
	route = restRouteDynamicPattern.ReplaceAllStringFunc(route, func(match string) string {
		submatches := restRouteDynamicPattern.FindStringSubmatch(match)
		if len(submatches) > 1 {
			name := submatches[1]
			// Strip common prefixes
			name = strings.TrimPrefix(name, "this_")
			name = strings.TrimPrefix(name, "self_")
			name = strings.TrimPrefix(name, "static_")
			// Strip class name prefixes like "Route_"
			if idx := strings.LastIndex(name, "_"); idx > 0 {
				suffix := name[idx+1:]
				// If suffix is all caps, it's likely NAMESPACE, VERSION, etc.
				if strings.ToUpper(suffix) == suffix && len(suffix) > 2 {
					name = suffix
				}
			}
			// Remove method call parens
			name = strings.TrimSuffix(name, "()")
			return "{" + name + "}"
		}
		return match
	})

	return route
}

// findArgsStartPos calculates the starting position for extracting args from a PHP array.
// argsStart is the matched string ("[" or "array("), matchStart/matchEnd are the match indices.
// For "[", returns matchStart directly. For "array(", finds the opening paren.
func findArgsStartPos(content, argsStart string, matchStart, matchEnd int) int {
	if argsStart == "[" {
		return matchStart
	}
	// array( - find the opening paren
	parenPos := strings.LastIndex(content[matchStart:matchEnd+5], "(")
	if parenPos >= 0 {
		return matchStart + parenPos
	}
	return matchStart
}

// DetectRESTEndpoints finds all REST API endpoints in PHP code
func DetectRESTEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	// Pre-allocate with estimated capacity to reduce slice growth allocations
	endpoints := make([]models.Endpoint, 0, 8)
	processedPositions := make(map[int]bool)

	// Build symbol table for the file
	symbolTable := NewSymbolTable(content)

	// 1. First, try the standard pattern (string literals)
	matches := RESTEndpointPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 8 {
			continue
		}

		processedPositions[match[0]] = true
		namespace := content[match[2]:match[3]]
		route := content[match[4]:match[5]]
		argsStart := content[match[6]:match[7]]

		argsStartPos := findArgsStartPos(content, argsStart, match[6], match[7])
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		eps := createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content, match[0])
		endpoints = append(endpoints, eps...)
	}

	// 2. Try pattern with variable/constant namespace
	varMatches := restVarNamespacePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range varMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		namespaceRef := strings.TrimSpace(content[match[2]:match[3]])
		route := content[match[4]:match[5]]
		argsStart := content[match[6]:match[7]]

		argsStartPos := findArgsStartPos(content, argsStart, match[6], match[7])

		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		// Try to resolve namespace
		namespace := resolveNamespaceRef(namespaceRef, symbolTable, content, match[0])

		eps := createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content, match[0])
		endpoints = append(endpoints, eps...)
	}

	// 3. Try pattern specifically for concatenated routes
	concatMatches := restConcatRoutePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range concatMatches {
		if len(match) < 12 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true

		// Determine namespace from groups 1, 2, or 3
		var namespace string
		if match[2] >= 0 && match[3] > match[2] {
			namespace = content[match[2]:match[3]] // literal namespace
		} else if match[4] >= 0 && match[5] > match[4] {
			namespaceRef := content[match[4]:match[5]] // self::CONST
			if val, ok := symbolTable.ResolveReference(namespaceRef); ok {
				namespace = val
			} else {
				namespace = "{" + sanitizeForRoute(namespaceRef) + "}"
			}
		} else if match[6] >= 0 && match[7] > match[6] {
			namespaceRef := content[match[6]:match[7]] // $var
			if val, ok := symbolTable.ResolveReference(namespaceRef); ok {
				namespace = val
			} else {
				namespace = "{" + sanitizeForRoute(namespaceRef) + "}"
			}
		}

		// Get concatenated route expression (group 4)
		routeExpr := ""
		if match[8] >= 0 && match[9] > match[8] {
			routeExpr = content[match[8]:match[9]]
		}

		// Get args using bracket matching (group 5 is just the start)
		argsStartPos := match[10]
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		// Resolve the concatenated route
		route := resolveConcatenatedRoute(routeExpr, symbolTable, content, match[0])

		eps := createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content, match[0])
		endpoints = append(endpoints, eps...)
	}

	// 4. Try generic pattern to catch all register_rest_route calls
	genericMatches := restFullVarPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range genericMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		namespaceExpr := strings.TrimSpace(content[match[2]:match[3]])
		routeExpr := strings.TrimSpace(content[match[4]:match[5]])

		// Skip if namespace expression looks like an array (common false positive)
		if strings.HasPrefix(namespaceExpr, "[") || strings.HasPrefix(namespaceExpr, "array") {
			continue
		}

		// Get args using bracket matching
		argsStartPos := match[6]
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		// Resolve namespace
		namespace := resolveExpression(namespaceExpr, symbolTable, content, match[0])
		// Resolve route
		route := resolveExpression(routeExpr, symbolTable, content, match[0])

		// Skip if we couldn't get meaningful values
		if namespace == "" || namespace == namespaceExpr {
			// Use a dynamic marker if we can't resolve
			if strings.HasPrefix(namespaceExpr, "$") || strings.Contains(namespaceExpr, "::") {
				namespace = "{dynamic:" + sanitizeForRoute(namespaceExpr) + "}"
			} else if isGlobalConstant(namespaceExpr) {
				// Try to resolve global constant
				namespace = resolveGlobalConstant(namespaceExpr, content)
			} else {
				continue // Skip completely unresolvable
			}
		}

		if route == "" || (route == routeExpr && !strings.HasPrefix(routeExpr, "'") && !strings.HasPrefix(routeExpr, "\"")) {
			if strings.HasPrefix(routeExpr, "$") || strings.Contains(routeExpr, "::") || strings.Contains(routeExpr, ".") {
				route = "/{dynamic}"
			}
		}

		eps := createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content, match[0])
		endpoints = append(endpoints, eps...)
	}

	// 5. Detect global constant namespace pattern: register_rest_route(CONSTANT_NAME, '/route', [...])
	globalConstMatches := restGlobalConstNamespacePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range globalConstMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		constName := content[match[2]:match[3]]
		route := content[match[4]:match[5]]
		argsStart := content[match[6]:match[7]]

		// Try to resolve the constant value from define() statements
		namespace := resolveGlobalConstant(constName, content)

		argsStartPos := findArgsStartPos(content, argsStart, match[6], match[7])
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		eps := createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content, match[0])
		endpoints = append(endpoints, eps...)
	}

	// 6. Detect wrapper method pattern: $this->register_route('route', [...])
	wrapperMethodMatches := restWrapperMethodPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range wrapperMethodMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		route := content[match[2]:match[3]]
		argsStart := content[match[4]:match[5]]

		// Try to find namespace from class context
		namespace := findClassNamespace(content, match[0], pluginSlug)

		argsStartPos := findArgsStartPos(content, argsStart, match[4], match[5])
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		eps := createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content, match[0])
		endpoints = append(endpoints, eps...)
	}

	// 7. Detect static wrapper pattern: self::register_route('/route', 'method', WP_REST_Server::EDITABLE)
	staticWrapperMatches := restStaticWrapperPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range staticWrapperMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		route := content[match[2]:match[3]]
		callback := strings.Trim(content[match[4]:match[5]], "'\"")
		methodStr := content[match[6]:match[7]]

		// Try to find namespace from class constant
		namespace := findClassNamespaceFromConstant(content, pluginSlug)

		// Create basic args for method extraction
		fullMatch := content[match[0]:match[1]]

		// Parse method
		methods := []string{"GET"}
		if strings.Contains(methodStr, "EDITABLE") {
			methods = []string{"POST", "PUT", "PATCH"}
		} else if strings.Contains(methodStr, "CREATABLE") {
			methods = []string{"POST"}
		} else if strings.Contains(methodStr, "DELETABLE") {
			methods = []string{"DELETE"}
		}

		lineNum := countLines(content[:match[0]]) + 1

		for _, method := range methods {
			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeREST,
				Route:      combineRoute(namespace, route),
				Method:     method,
				AuthLevel:  models.Admin, // Static wrapper typically means admin-only
				Callback:   callback,
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode(fullMatch, 500),
				Namespace:  namespace,
			}
			endpoints = append(endpoints, ep)
		}
	}

	// 8. Detect new REST_Route() class instantiation
	restRouteClassMatches := restRouteClassPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range restRouteClassMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		route := content[match[2]:match[3]]
		argsStart := content[match[4]:match[5]]

		// Try to find namespace from REST_ROOT constant
		namespace := findRESTRootConstant(content, pluginSlug)

		argsStartPos := findArgsStartPos(content, argsStart, match[4], match[5])
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		eps := createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content, match[0])
		endpoints = append(endpoints, eps...)
	}

	// 9. Detect wrapper _register_route pattern
	// $this->_register_route('/route', [...], $auth)
	wrapperMatches := wrapperRegisterRoutePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range wrapperMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		route := content[match[2]:match[3]]
		argsStart := content[match[4]:match[5]]

		// Try to find namespace from class context
		namespace := findClassNamespace(content, match[0], pluginSlug)

		argsStartPos := findArgsStartPos(content, argsStart, match[4], match[5])
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		// Wrapper patterns typically require admin capabilities
		methods := extractMethods(args)
		callback := extractCallback(args)
		lineNum := countLines(content[:match[0]]) + 1

		for _, method := range methods {
			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeREST,
				Route:      combineRoute(namespace, route),
				Method:     method,
				AuthLevel:  models.Admin, // Wrapper endpoints typically require admin caps
				Callback:   NormalizeCallback(callback),
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode(fullMatch, 500),
				Namespace:  namespace,
			}
			endpoints = append(endpoints, ep)
		}
	}

	// 10. Detect untrailingslashit wrapper pattern
	// register_rest_route(untrailingslashit('namespace/v1/' . $this->prefix), '/route', [...])
	untrailingslashitMatches := restUntrailingslashitPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range untrailingslashitMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		namespaceBase := content[match[2]:match[3]] // e.g., "elementskit/v1/"
		argsStart := content[match[4]:match[5]]

		// Clean up namespace - remove trailing slash for base
		namespace := strings.TrimSuffix(namespaceBase, "/")

		argsStartPos := findArgsStartPos(content, argsStart, match[4], match[5])
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		// For dynamic route patterns, use a placeholder
		route := "/{dynamic}"

		// Extract methods and callback from args
		methods := extractMethods(args)
		callback := extractCallback(args)

		// Check for permission_callback in args to determine auth level
		permCallback, authLevel := ParsePermissionCallbackWithContext(args, content)
		if permCallback == "" {
			authLevel = InferAuthLevel(args)
		}

		lineNum := countLines(content[:match[0]]) + 1

		for _, method := range methods {
			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeREST,
				Route:      combineRoute(namespace, route),
				Method:     method,
				AuthLevel:  authLevel,
				Callback:   NormalizeCallback(callback),
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode(fullMatch, 500),
				Namespace:  namespace,
			}
			endpoints = append(endpoints, ep)
		}
	}

	// 11. Detect property-based wrapper pattern
	// $this->util->rest_api_server->register_rest_route('/route', [...])
	propertyWrapperMatches := restPropertyWrapperPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range propertyWrapperMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		route := content[match[2]:match[3]]
		argsStart := content[match[4]:match[5]]

		// Try to find namespace from class property
		namespace := findPropertyNamespace(content, pluginSlug)

		argsStartPos := findArgsStartPos(content, argsStart, match[4], match[5])
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		// Extract methods and callback
		methods := extractMethods(args)
		callback := extractCallback(args)

		// Property-based wrappers typically add permission_callback in the wrapper class
		// Default to Admin since these are typically admin-only API endpoints
		// Unless explicit permission_callback is found in args
		permCallback, authLevel := ParsePermissionCallbackWithContext(args, content)
		if permCallback == "" {
			// No explicit permission_callback in args - wrapper likely adds it
			// Default to Admin for property-based wrappers
			authLevel = models.Admin
		}

		lineNum := countLines(content[:match[0]]) + 1

		for _, method := range methods {
			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeREST,
				Route:      combineRoute(namespace, route),
				Method:     method,
				AuthLevel:  authLevel,
				Callback:   NormalizeCallback(callback),
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode(fullMatch, 500),
				Namespace:  namespace,
			}
			endpoints = append(endpoints, ep)
		}
	}

	// 12. Detect register_rest_route with variable args
	// Example: register_rest_route( Main::API_V1_NAMESPACE, self::ROUTE, $route_args );
	// This pattern is used when the args array is stored in a variable
	varArgsMatches := restVarArgsPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range varArgsMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		namespaceRef := strings.TrimSpace(content[match[2]:match[3]])
		routeRef := strings.TrimSpace(content[match[4]:match[5]])
		varName := content[match[6]:match[7]] // e.g., $route_args

		// Find the variable's array assignment above this position
		args := findVariableArrayValue(content, varName, match[0])
		if args == "" {
			continue // Couldn't find the variable definition
		}

		// Try to resolve namespace
		namespace := resolveNamespaceRef(namespaceRef, symbolTable, content, match[0])

		// Try to resolve route (might be a constant)
		route := routeRef
		if strings.Contains(routeRef, "::") {
			// It's a class constant reference
			if resolved, ok := symbolTable.ResolveReference(routeRef); ok {
				route = resolved
			} else {
				// Use dynamic placeholder with the constant name
				constName := routeRef
				if parts := strings.Split(routeRef, "::"); len(parts) == 2 {
					constName = parts[1]
				}
				route = "{dynamic:" + constName + "}"
			}
		}
		route = strings.Trim(route, "'\"")

		fullMatch := content[match[0]:match[1]]

		eps := createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content, match[0])
		endpoints = append(endpoints, eps...)
	}

	// 12b. Detect register_rest_route with property-based args (e.g., $this->options)
	// Example: register_rest_route($this->namespace, "/{$uri}", $this->options);
	// Common in framework-based plugins
	propertyArgsMatches := restPropertyArgsPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range propertyArgsMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		namespaceRef := strings.TrimSpace(content[match[2]:match[3]])
		routeRef := strings.TrimSpace(content[match[4]:match[5]])
		argsProperty := content[match[6]:match[7]] // e.g., $this->options

		// Try to resolve namespace
		namespace := resolveNamespaceRef(namespaceRef, symbolTable, content, match[0])

		// Try to resolve route (might be interpolated string like "/{$uri}")
		route := routeRef
		route = strings.Trim(route, "'\"")
		// Keep interpolated parts as dynamic markers
		if strings.Contains(route, "{$") {
			// Extract the variable pattern - it's a dynamic route
			route = "{dynamic:" + sanitizeForRoute(route) + "}"
		}

		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Since we can't resolve the $this->options array, check the surrounding code
		// for permission callback patterns
		nearbyCode := extractNearbyContext(content, match[0], 500)
		authLevel := InferAuthLevel(nearbyCode)

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      combineRoute(namespace, route),
			Method:     "GET", // Default, since we can't determine from property
			AuthLevel:  authLevel,
			Callback:   "property:" + argsProperty,
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
			Namespace:  namespace,
		}
		endpoints = append(endpoints, ep)
	}

	// 13. Detect array-based route definitions
	// Look for patterns with API_NAMESPACE constant and ROUTE_PATH in arrays
	if strings.Contains(content, "API_NAMESPACE") && strings.Contains(content, "ROUTE_PATH") {
		// Extract namespace from API_NAMESPACE constant
		namespace := extractAPINamespace(content, pluginSlug)

		// Find all ROUTE_PATH definitions
		routeMatches := restArrayRoutePattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range routeMatches {
			if len(match) < 4 {
				continue
			}

			route := content[match[2]:match[3]]
			lineNum := countLines(content[:match[0]]) + 1

			// Try to extract method from nearby ROUTE_METHODS
			method := extractNearbyMethod(content, match[0])

			// Array-defined routes often have permission callbacks
			authLevel := models.Admin // Default to Admin for API routes

			// Check for permission callback pattern near this route
			nearbyCode := extractNearbyContext(content, match[0], 200)
			if strings.Contains(nearbyCode, "__return_true") ||
				strings.Contains(nearbyCode, "return true") {
				authLevel = models.Unauthenticated
			}

			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeREST,
				Route:      combineRoute(namespace, route),
				Method:     method,
				AuthLevel:  authLevel,
				Callback:   "array_defined",
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode(nearbyCode, 500),
				Namespace:  namespace,
			}
			endpoints = append(endpoints, ep)
		}
	}

	// 14. Detect common wrapper method calls like registerGetRoute, registerPostRoute
	// These are used by frameworks that wrap register_rest_route
	wrapperCallMatches := restWrapperMethodCallPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range wrapperCallMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		httpMethod := strings.ToUpper(content[match[2]:match[3]]) // Get, Post, Put, Patch, Delete
		route := content[match[4]:match[5]]                       // The route path

		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Try to infer namespace from the class/file
		namespace := inferNamespaceFromContext(content, match[0], pluginSlug)

		// Check nearby code for auth patterns
		nearbyCode := extractNearbyContext(content, match[0], 500)
		authLevel := InferAuthLevel(nearbyCode)

		// Extract callback from additional args if present
		callback := "wrapper_method"
		if len(match) >= 8 && match[6] >= 0 && match[7] > match[6] {
			additionalArgs := strings.TrimSpace(content[match[6]:match[7]])
			// Try to extract class name from args like "Endpoint::class" (using pre-compiled pattern)
			if strings.Contains(additionalArgs, "::class") {
				if classMatch := classConstResolvePattern.FindStringSubmatch(additionalArgs); len(classMatch) >= 2 {
					callback = classMatch[1]
				}
			}
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      combineRoute(namespace, route),
			Method:     httpMethod,
			AuthLevel:  authLevel,
			Callback:   callback,
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
			Namespace:  namespace,
		}
		endpoints = append(endpoints, ep)
	}

	// 15. Detect register_rest_route with sprintf in route argument
	// Example: register_rest_route($this->namespace, sprintf('/%s/(?P<id>\d+)', $base), [...])
	sprintfRouteMatches := restSprintfRoutePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range sprintfRouteMatches {
		if len(match) < 10 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		namespaceExpr := strings.TrimSpace(content[match[2]:match[3]])
		formatString := content[match[4]:match[5]] // The sprintf format string
		argsStart := content[match[8]:match[9]]    // "[" or "array("

		// Resolve namespace
		namespace := resolveNamespaceRef(namespaceExpr, symbolTable, content, match[0])

		// Build route from sprintf format - replace %s, %d, %1$s patterns with dynamic markers
		route := resolveSprintfRoute(formatString)

		argsStartPos := findArgsStartPos(content, argsStart, match[8], match[9])
		args := extractArgsWithBracketMatching(content, argsStartPos)
		fullMatch := content[match[0]:min(match[0]+len(args)+200, len(content))]

		eps := createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content, match[0])
		endpoints = append(endpoints, eps...)
	}

	// 16. Detect WP_REST_Controller subclass patterns
	// Many plugins define routes in classes that extend WP_REST_Controller
	// with getRoutePath() method returning the route path
	if wpRestControllerExtendPattern.MatchString(content) {
		// This file contains a class extending WP_REST_Controller or similar
		routeMatches := wpRestControllerRoutePattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range routeMatches {
			if len(match) < 4 {
				continue
			}

			routePath := content[match[2]:match[3]]
			lineNum := countLines(content[:match[0]]) + 1

			// Try to extract namespace from the class or nearby code
			namespace := extractWPRestControllerNamespace(content, pluginSlug)

			// Try to extract HTTP method from ROUTE_METHOD constant or getRouteMethods
			method := extractWPRestControllerMethod(content)

			// Determine auth level from permission callback or authorization patterns
			authLevel := extractWPRestControllerAuth(content)

			// Extract class name for callback
			className := extractClassName(content)

			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeREST,
				Route:      combineRoute(namespace, routePath),
				Method:     method,
				AuthLevel:  authLevel,
				Callback:   className + "::getRoutePath",
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode(content[match[0]:min(match[1]+50, len(content))], 300),
				Namespace:  namespace,
			}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// resolveConcatenatedRoute resolves a concatenated route expression like '/' . self::API_BASE . '/status'
func resolveConcatenatedRoute(expr string, st *SymbolTable, content string, position int) string {
	localST := ExtractLocalContext(content, position, 50)

	// Merge symbol tables
	for k, v := range st.Constants {
		localST.Constants[k] = v
	}
	for k, v := range st.Properties {
		localST.Properties[k] = v
	}

	return localST.ResolveConcatenation(expr)
}

// resolveNamespaceRef resolves a namespace reference to its value
func resolveNamespaceRef(ref string, st *SymbolTable, content string, position int) string {
	// Try file-level symbol table first
	if val, ok := st.ResolveReference(ref); ok {
		return val
	}

	// Try local context
	localST := ExtractLocalContext(content, position, 50)
	if val, ok := localST.ResolveReference(ref); ok {
		return val
	}

	// Return a dynamic marker
	return "{" + sanitizeForRoute(ref) + "}"
}

// inferNamespaceFromContext tries to infer the REST API namespace from the surrounding code
func inferNamespaceFromContext(content string, position int, pluginSlug string) string {
	// Look for common namespace constant patterns
	patterns := []string{
		`const\s+PREFIX\s*=\s*['"]([^'"]+)['"]`,
		`const\s+REST_NAMESPACE\s*=\s*['"]([^'"]+)['"]`,
		`const\s+NAMESPACE\s*=\s*['"]([^'"]+)['"]`,
		`const\s+API_NAMESPACE\s*=\s*['"]([^'"]+)['"]`,
		`private\s+const\s+PREFIX\s*=\s*['"]([^'"]+)['"]`,
		`self::PREFIX\s*=\s*['"]([^'"]+)['"]`,
	}

	// Search before the position
	searchStart := 0
	if position > 2000 {
		searchStart = position - 2000
	}
	searchContent := content[searchStart:position]

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if match := re.FindStringSubmatch(searchContent); len(match) >= 2 {
			return match[1]
		}
	}

	// Default namespace based on plugin slug
	return pluginSlug + "/v1"
}

// resolveExpression resolves a PHP expression (string literal, variable, concatenation)
func resolveExpression(expr string, st *SymbolTable, content string, position int) string {
	expr = strings.TrimSpace(expr)

	// Check for concatenation FIRST - before treating as string literal
	// Expressions like '/' . $this->base . '/suffix' start/end with quotes but are concatenations
	// Look for ` . ` pattern which indicates PHP concatenation
	if strings.Contains(expr, " . ") || strings.Contains(expr, "' .") || strings.Contains(expr, ". '") ||
		strings.Contains(expr, "\" .") || strings.Contains(expr, ". \"") {
		localST := ExtractLocalContext(content, position, 50)
		// Merge with file-level symbols
		for k, v := range st.Constants {
			localST.Constants[k] = v
		}
		for k, v := range st.Properties {
			localST.Properties[k] = v
		}
		return localST.ResolveConcatenation(expr)
	}

	// String literal (only if NOT a concatenation)
	if strings.HasPrefix(expr, "'") && strings.HasSuffix(expr, "'") {
		// Single-quoted string - no interpolation
		return strings.Trim(expr, "'")
	}
	if strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"") {
		// Double-quoted string - may contain interpolation
		inner := strings.Trim(expr, "\"")
		// Check for PHP interpolation patterns
		if strings.Contains(inner, "$") || strings.Contains(inner, "{$") {
			localST := ExtractLocalContext(content, position, 50)
			// Merge with file-level symbols
			for k, v := range st.Constants {
				localST.Constants[k] = v
			}
			for k, v := range st.Properties {
				localST.Properties[k] = v
			}
			return localST.ResolveInterpolatedString(inner)
		}
		return inner
	}

	// Contains other concatenation patterns (like $var.suffix)
	if strings.Contains(expr, ".") {
		localST := ExtractLocalContext(content, position, 50)
		// Merge with file-level symbols
		for k, v := range st.Constants {
			localST.Constants[k] = v
		}
		for k, v := range st.Properties {
			localST.Properties[k] = v
		}
		return localST.ResolveConcatenation(expr)
	}

	// Simple reference
	if val, ok := st.ResolveReference(expr); ok {
		return val
	}

	// Try local context
	localST := ExtractLocalContext(content, position, 50)
	if val, ok := localST.ResolveReference(expr); ok {
		return val
	}

	return expr
}

// sanitizeForRoute removes characters that shouldn't be in route markers
func sanitizeForRoute(s string) string {
	s = strings.ReplaceAll(s, "$", "")
	s = strings.ReplaceAll(s, "->", "_")
	s = strings.ReplaceAll(s, "::", "_")
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "\"", "")
	return s
}

// createRESTEndpoints creates endpoint objects from parsed REST route data
func createRESTEndpoints(namespace, route, args, fullMatch, filepath, pluginSlug, content string, position int) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Build symbol table for resolving concatenations
	symbolTable := NewSymbolTable(content)

	// Resolve route if it contains concatenation
	if strings.Contains(route, ".") && strings.Contains(route, "::") {
		route = resolveRouteConcat(route, symbolTable, content, position)
	}

	// Calculate line number
	lineNum := countLines(content[:position]) + 1

	// Check if args contains multiple route definitions (array of arrays pattern)
	// WordPress allows: register_rest_route('ns', '/route', array( array(...), array(...) ))
	// where each inner array defines a different HTTP method handler
	routeDefs := splitMultipleRouteDefinitions(args)

	if len(routeDefs) > 1 {
		// Multiple route definitions found - process each separately
		for _, routeDef := range routeDefs {
			methods := extractMethods(routeDef)
			callback := extractCallback(routeDef)

			permCallback, authLevel := ParsePermissionCallbackWithContext(routeDef, content)
			if permCallback == "" {
				if !hasPermissionCallback(routeDef) {
					// permission_callback key is completely absent from args.
					// WordPress 5.5+ logs _doing_it_wrong but still serves the endpoint.
					authLevel = models.Unauthenticated
				} else {
					authLevel = InferAuthLevel(routeDef)
				}
			}
			// W5 fix: follow deeper delegation chains for permission callbacks
			// that resolved only to Subscriber via naming heuristics
			if permCallback != "" && authLevel == models.Subscriber {
				enhanced := EnhancePermissionCallback(permCallback, content, nil)
				if enhanced > authLevel {
					authLevel = enhanced
				}
			}
			authLevel = applyRouteAuthHeuristics(route, namespace, authLevel, routeDef)

			for _, method := range methods {
				ep := models.Endpoint{
					PluginSlug: pluginSlug,
					Type:       models.EndpointTypeREST,
					Route:      combineRoute(namespace, route),
					Method:     method,
					AuthLevel:  authLevel,
					Callback:   NormalizeCallback(callback),
					File:       filepath,
					Line:       lineNum,
					RawCode:    truncateCode(fullMatch, 500),
					Namespace:  namespace,
				}
				endpoints = append(endpoints, ep)
			}
		}
		return endpoints
	}

	// Single route definition - process normally
	methods := extractMethods(args)
	callback := extractCallback(args)

	// Extract permission callback and determine auth level
	// Use ParsePermissionCallbackWithContext to analyze actual callback function body
	permCallback, authLevel := ParsePermissionCallbackWithContext(args, content)
	if permCallback == "" {
		if !hasPermissionCallback(args) {
			// permission_callback key is completely absent from args.
			// WordPress 5.5+ logs _doing_it_wrong but still serves the endpoint.
			authLevel = models.Unauthenticated
		} else {
			authLevel = InferAuthLevel(args)
		}
	}
	// W5 fix: follow deeper delegation chains for permission callbacks
	// that resolved only to Subscriber via naming heuristics
	if permCallback != "" && authLevel == models.Subscriber {
		enhanced := EnhancePermissionCallback(permCallback, content, nil)
		if enhanced > authLevel {
			authLevel = enhanced
		}
	}

	// Apply route-based auth heuristics
	// Routes containing "admin" in the path likely require admin access
	authLevel = applyRouteAuthHeuristics(route, namespace, authLevel, args)

	// Create endpoint for each method
	for _, method := range methods {
		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeREST,
			Route:      combineRoute(namespace, route),
			Method:     method,
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
			Namespace:  namespace,
		}
		endpoints = append(endpoints, ep)
	}

	// Filter out blocked endpoints (those with __return_false or similar)
	// These are inaccessible to everyone and should not be included in security analysis
	filteredEndpoints := make([]models.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		if !IsExplicitlyBlocked(ep.RawCode) {
			filteredEndpoints = append(filteredEndpoints, ep)
		}
	}

	return filteredEndpoints
}

// splitMultipleRouteDefinitions detects and splits multiple route definitions within args
// WordPress register_rest_route allows: array( array('methods'=>...), array('methods'=>...) )
// This returns a slice of individual route definitions
func splitMultipleRouteDefinitions(args string) []string {
	// First, check if this looks like an array of arrays pattern
	// Count how many 'methods' keys exist in the args
	methodsCount := strings.Count(args, "'methods'") + strings.Count(args, "\"methods\"")
	if methodsCount <= 1 {
		// Single or no methods key - not a multi-definition structure
		return []string{args}
	}

	result := make([]string, 0)

	// Skip the outer array wrapper
	content := strings.TrimSpace(args)
	if strings.HasPrefix(content, "[") {
		content = content[1:]
		if strings.HasSuffix(content, "]") {
			content = content[:len(content)-1]
		}
	} else if strings.HasPrefix(content, "array(") {
		content = strings.TrimPrefix(content, "array(")
		if strings.HasSuffix(content, ")") {
			content = content[:len(content)-1]
		}
	}

	content = strings.TrimSpace(content)

	// Find positions of inner arrays using pre-compiled regex
	// Pattern matches: array( or [ at start of an inner definition
	// We need to match at the very start or after commas
	matches := innerArrayPattern.FindAllStringIndex(content, -1)

	for _, matchIdx := range matches {
		// Find the actual start of the array bracket
		startPos := matchIdx[0]
		// Skip comma and whitespace if present
		for startPos < len(content) && (content[startPos] == ',' || content[startPos] == ' ' || content[startPos] == '\t' || content[startPos] == '\n' || content[startPos] == '\r') {
			startPos++
		}

		// Now find the matching closing bracket
		if startPos >= len(content) {
			continue
		}

		// Determine opening bracket type
		var openChar, closeChar byte
		if strings.HasPrefix(content[startPos:], "array") {
			// Find the ( after array
			parenPos := strings.Index(content[startPos:], "(")
			if parenPos < 0 {
				continue
			}
			startPos += parenPos
			openChar = '('
			closeChar = ')'
		} else if content[startPos] == '[' {
			openChar = '['
			closeChar = ']'
		} else {
			continue
		}

		// Extract the full inner array using bracket matching
		depth := 0
		inString := false
		stringChar := byte(0)
		endPos := -1

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
					endPos = i
				}
			}

			if endPos >= 0 {
				break
			}
		}

		if endPos > startPos {
			innerArray := content[startPos : endPos+1]
			// Check if this inner array has a 'methods' key
			if strings.Contains(innerArray, "'methods'") || strings.Contains(innerArray, "\"methods\"") {
				result = append(result, innerArray)
			}
		}
	}

	if len(result) == 0 {
		// Couldn't parse - return original
		return []string{args}
	}

	return result
}

// resolveRouteConcat resolves concatenation in route strings
func resolveRouteConcat(route string, st *SymbolTable, content string, position int) string {
	// Handle strings like: '/' . self::API_BASE . '/status'
	localST := ExtractLocalContext(content, position, 50)

	// Merge symbol tables
	for k, v := range st.Constants {
		localST.Constants[k] = v
	}
	for k, v := range st.Properties {
		localST.Properties[k] = v
	}

	return localST.ResolveConcatenation(route)
}

// extractMethods extracts HTTP methods from REST route args
func extractMethods(args string) []string {
	matches := MethodPattern.FindStringSubmatch(args)

	if len(matches) >= 3 {
		// Check string value first
		if matches[1] != "" {
			return parseMethodString(matches[1])
		}
		// Check constant
		if matches[2] != "" {
			return parseMethodConstant(matches[2])
		}
	}

	// Default to GET if no methods specified
	return []string{"GET"}
}

// parseMethodString parses a comma-separated method string
func parseMethodString(s string) []string {
	methods := make([]string, 0)
	parts := strings.Split(s, ",")
	for _, part := range parts {
		method := strings.TrimSpace(strings.ToUpper(part))
		if method != "" {
			methods = append(methods, method)
		}
	}
	if len(methods) == 0 {
		return []string{"GET"}
	}
	return methods
}

// parseMethodConstant parses WP_REST_Server constants and common aliases
func parseMethodConstant(constant string) []string {
	switch strings.ToUpper(constant) {
	case "READABLE", "READ":
		return []string{"GET"}
	case "CREATABLE":
		return []string{"POST"}
	case "EDITABLE":
		return []string{"POST", "PUT", "PATCH"}
	case "DELETABLE":
		return []string{"DELETE"}
	case "ALLMETHODS":
		return []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	default:
		return []string{constant}
	}
}

// extractCallback extracts the callback function from REST route args
func extractCallback(args string) string {
	// Try __CLASS__ concatenation pattern first (most specific)
	// Pattern: 'callback' => __CLASS__ . '::method_name'
	if matches := restCallbackClassConcatPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return "__CLASS__::" + matches[1]
	}

	// Try __NAMESPACE__ concatenation pattern
	// Pattern: 'callback' => __NAMESPACE__ . '\function_name'
	if matches := restCallbackNamespaceConcatPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return "__NAMESPACE__\\" + matches[1]
	}

	// Try ClassName::class pattern with method
	// Pattern: 'callback' => [ ClassName::class, 'method' ]
	if matches := restCallbackClassConstPattern.FindStringSubmatch(args); len(matches) >= 3 {
		return matches[1] + "::" + matches[2]
	}

	// Try static::class or self::class patterns
	// Pattern: 'callback' => array( static::class, 'method' )
	if matches := restCallbackStaticClassPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return "static::" + matches[1]
	}

	// Try array method pattern with $this/$self
	// Pattern: 'callback' => array( $this, 'method' )
	if matches := restCallbackArrayMethodPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return "this::" + matches[1]
	}

	// Try array callbacks with function call as first element
	// Pattern: 'callback' => array( FunctionCall(), 'method' )
	// Handles nested parentheses by matching up to the comma
	if matches := restCallbackFunctionArrayPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return matches[1]
	}

	// Try bracket callbacks with function call as first element
	// Pattern: 'callback' => [ FunctionCall(), 'method' ]
	if matches := restCallbackFunctionBracketPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return matches[1]
	}

	// Try static class method string pattern
	// Pattern: 'callback' => 'ClassName::method'
	if matches := restCallbackStaticPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return matches[1]
	}

	// Try simple string callback pattern
	// Pattern: 'callback' => 'function_name'
	if matches := restCallbackStringPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return matches[1]
	}

	// Try closure pattern
	if matches := restCallbackClosurePattern.FindStringSubmatch(args); len(matches) >= 2 {
		return "closure"
	}

	// Try arrow function pattern (PHP 7.4+)
	if restCallbackArrowFnPattern.MatchString(args) {
		return "arrow_fn"
	}

	// Try method call callback pattern (returns callable)
	// Pattern: 'callback' => $this->get_callback()
	if matches := restCallbackMethodCallPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return "this::" + matches[1]
	}

	// Try method call with arguments pattern
	// Pattern: 'callback' => $this->callback( $controller, 'method' )
	if matches := restCallbackMethodWithArgsPattern.FindStringSubmatch(args); len(matches) >= 2 {
		return "this::" + matches[1]
	}

	// Try variable callback pattern
	if matches := restCallbackVariablePattern.FindStringSubmatch(args); len(matches) >= 2 {
		return "var:" + matches[1]
	}

	// Try array patterns (less specific - extracts full array)
	if matches := restCallbackArrayPattern.FindStringSubmatch(args); len(matches) >= 2 {
		// Try to extract method name from array like [ $this, 'method' ] (using pre-compiled pattern from auth.go)
		arrayContent := matches[1]
		methodMatch := normalizeMethodExtractPattern.FindStringSubmatch(arrayContent)
		if len(methodMatch) >= 2 {
			if strings.Contains(arrayContent, "$this") {
				return "this::" + methodMatch[1]
			}
			return methodMatch[1]
		}
		return matches[1]
	}

	if matches := restCallbackArrayAltPattern.FindStringSubmatch(args); len(matches) >= 2 {
		// Try to extract method name from array( $this, 'method' ) (using pre-compiled pattern from auth.go)
		arrayContent := matches[1]
		methodMatch := normalizeMethodExtractPattern.FindStringSubmatch(arrayContent)
		if len(methodMatch) >= 2 {
			if strings.Contains(arrayContent, "$this") {
				return "this::" + methodMatch[1]
			}
			return methodMatch[1]
		}
		return matches[1]
	}

	return "unknown"
}

// combineRoute combines namespace and route into a full WordPress REST API path
func combineRoute(namespace, route string) string {
	// Trim any existing leading/trailing slashes from namespace
	namespace = strings.Trim(namespace, "/")

	// Ensure route starts with /
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}

	// Combine with /wp-json/ prefix for actual WordPress REST API URL
	result := "/wp-json/" + namespace + route

	// Remove any double slashes (except after protocol like http://)
	for strings.Contains(result, "//") && !strings.Contains(result, "://") {
		result = strings.ReplaceAll(result, "//", "/")
	}

	// Clean PHP interpolation syntax from the route
	result = cleanRouteString(result)

	return result
}

// countLines counts the number of newlines in a string
func countLines(s string) int {
	return strings.Count(s, "\n")
}

// extractArgsWithBracketMatching extracts the full arguments array using bracket matching
// This properly handles nested arrays and functions
func extractArgsWithBracketMatching(content string, startPos int) string {
	if startPos >= len(content) {
		return ""
	}

	// Determine the bracket type
	openChar := content[startPos]
	if openChar != '[' && openChar != '(' {
		// Not a bracket, try to find array( pattern
		if startPos+5 < len(content) && content[startPos:startPos+5] == "array" {
			parenPos := strings.Index(content[startPos:], "(")
			if parenPos >= 0 {
				startPos += parenPos
				openChar = '('
			} else {
				return ""
			}
		} else {
			return ""
		}
	}

	bracketDepth := 0
	parenDepth := 0
	inString := false
	stringChar := byte(0)

	for i := startPos; i < len(content); i++ {
		c := content[i]

		// Handle string literals
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
		case '[':
			bracketDepth++
		case ']':
			bracketDepth--
		case '(':
			parenDepth++
		case ')':
			parenDepth--
		}

		// Check if we've closed the original opening bracket
		if openChar == '[' && bracketDepth == 0 && c == ']' {
			return content[startPos : i+1]
		}
		if openChar == '(' && parenDepth == 0 && c == ')' {
			return content[startPos : i+1]
		}
	}

	// If we couldn't find matching bracket, return up to 5000 chars
	maxLen := startPos + 5000
	if maxLen > len(content) {
		maxLen = len(content)
	}
	return content[startPos:maxLen]
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// applyRouteAuthHeuristics applies route-based heuristics to adjust auth level
// Routes containing certain patterns likely require specific auth levels
func applyRouteAuthHeuristics(route, namespace string, currentLevel models.AuthLevel, args string) models.AuthLevel {
	// Check for explicit unauthenticated patterns first - don't override these
	if isExplicitlyUnauthenticated(args) {
		return models.Unauthenticated
	}

	fullRoute := strings.ToLower(namespace + "/" + route)
	lowerNamespace := strings.ToLower(namespace)

	// Get configuration
	cfg := getRESTConfig()

	// ============================================
	// ADMIN NAMESPACE DETECTION (from configuration only)
	// No hardcoded plugin namespaces - users add their own via config
	// ============================================
	if cfg != nil && cfg.REST != nil && len(cfg.REST.AdminNamespaces) > 0 {
		for _, adminNS := range cfg.REST.AdminNamespaces {
			if strings.Contains(lowerNamespace, strings.ToLower(adminNS)) {
				// This namespace is admin-only, upgrade to Admin if not already
				if currentLevel == models.Subscriber || currentLevel == models.Unauthenticated {
					return models.Admin
				}
				return currentLevel
			}
		}
	}

	// If namespace is dynamic (unresolved), use more aggressive route-based heuristics
	if strings.Contains(lowerNamespace, "{dynamic") || strings.Contains(lowerNamespace, "{") {
		// Dynamic namespace - apply stronger route heuristics
		if currentLevel == models.Subscriber && isLikelyAdminRoute(fullRoute) {
			return models.Admin
		}
	}

	// ============================================
	// PUBLIC INDICATORS (from configuration or defaults)
	// ============================================
	var publicIndicators []string
	if cfg != nil && cfg.REST != nil && len(cfg.REST.PublicIndicators) > 0 {
		publicIndicators = cfg.REST.PublicIndicators
	} else {
		// Default public indicators
		publicIndicators = []string{
			"/public/",
			"/embed/",
			"/widget/",
			"/oembed",
		}
	}

	for _, indicator := range publicIndicators {
		if strings.Contains(fullRoute, indicator) {
			return models.Unauthenticated
		}
	}

	// ============================================
	// USER ROUTE PATTERNS (from configuration or defaults)
	// ============================================
	var userRoutePatterns []string
	if cfg != nil && cfg.REST != nil && len(cfg.REST.UserRoutePatterns) > 0 {
		userRoutePatterns = cfg.REST.UserRoutePatterns
	} else {
		// Default user route patterns
		userRoutePatterns = []string{
			"/user/",
			"/me/",
			"/me",
			"/profile/",
			"/account/",
		}
	}

	for _, indicator := range userRoutePatterns {
		if strings.Contains(fullRoute, indicator) {
			if currentLevel == models.Unauthenticated {
				return models.Subscriber
			}
			return currentLevel
		}
	}

	// ============================================
	// ADMIN ROUTE PATTERNS (from configuration or defaults)
	// ============================================
	var adminRoutePatterns []string
	if cfg != nil && cfg.REST != nil && len(cfg.REST.AdminRoutePatterns) > 0 {
		adminRoutePatterns = cfg.REST.AdminRoutePatterns
	} else {
		// Default admin route patterns
		adminRoutePatterns = []string{
			"/admin/",
			"/admin-",
			"-admin/",
			"/settings",
			"/options",
			"/config",
			"/manage",
			"/dashboard",
		}
	}

	// If current level is Unauthenticated or User, upgrade to Admin for admin routes
	if currentLevel == models.Unauthenticated || currentLevel == models.Subscriber {
		for _, indicator := range adminRoutePatterns {
			if strings.Contains(fullRoute, indicator) {
				return models.Admin
			}
		}
	}

	// Specific pattern: route path ends with "/admin" or contains "/admin/"
	if strings.Contains(fullRoute, "/admin") && (currentLevel == models.Unauthenticated || currentLevel == models.Subscriber) {
		return models.Admin
	}

	// If permission callback exists but we couldn't determine auth level, and it's User,
	// check if route pattern suggests admin access
	if currentLevel == models.Subscriber && isLikelyAdminRoute(fullRoute) {
		return models.Admin
	}

	return currentLevel
}

// isLikelyAdminRoute checks if a route pattern suggests admin-level access
func isLikelyAdminRoute(route string) bool {
	// Patterns that often indicate admin-only routes
	adminPatterns := []string{
		"bulk",
		"batch",
		"/create",
		"/delete",
		"/update",
		"/save",
		"/edit",
		"/remove",
		"/clear",
		"/flush",
		"/reset",
		"/rebuild",
		"/regenerate",
		"/scan",
		"/audit",
		"/logs",
		"/debug",
		"/test",
		"sync",
		"/connect",
		"/disconnect",
		"/authorize",
		"/tokens",
		"/credentials",
		"/modules",
		"/plugins",
		"/themes",
		"/tools",
		"/utilities",
		"/send",
		"/publish",
		"/draft",
		"/trash",
		"/restore",
	}

	for _, pattern := range adminPatterns {
		if strings.Contains(route, pattern) {
			// Exception: check for user-facing patterns
			if isUserFacingRoutePattern(route) {
				return false
			}
			return true
		}
	}

	return false
}

// isUserFacingRoutePattern checks if a route is user-facing even though it has admin-like keywords
func isUserFacingRoutePattern(route string) bool {
	userFacingPatterns := []string{
		"/form",
		"/submit",
		"/post",
		"/comment",
		"/reply",
		"/message",
		"/contact",
		"/subscription",
		"/newsletter",
		"/register",
		"/login",
		"/auth",
		"/password",
		"/bookmark",
		"/favorite",
		"/wishlist",
		"/rating",
		"/vote",
		"/like",
		"/share",
		"/search",
		"/filter",
		"/cart",
		"/checkout",
		"/order",
		"/payment",
		"/shipping",
		"/address",
	}

	for _, pattern := range userFacingPatterns {
		if strings.Contains(route, pattern) {
			return true
		}
	}

	return false
}

// truncateCode truncates code to maxLen characters
// Uses single-pass whitespace normalization to avoid creating intermediate slice
func truncateCode(code string, maxLen int) string {
	// Normalize whitespace using strings.Builder for single-pass processing
	var sb strings.Builder
	sb.Grow(len(code)) // Pre-allocate estimated size

	inWhitespace := true // Start as true to skip leading whitespace
	for _, r := range code {
		if unicode.IsSpace(r) {
			if !inWhitespace {
				sb.WriteByte(' ')
				inWhitespace = true
			}
		} else {
			sb.WriteRune(r)
			inWhitespace = false
		}
	}

	result := strings.TrimRight(sb.String(), " ") // Remove trailing space
	if len(result) > maxLen {
		return result[:maxLen] + "..."
	}
	return result
}

// isGlobalConstant checks if a string looks like a PHP global constant
// Global constants are typically uppercase with underscores (e.g., PLUGIN_REST_URL)
func isGlobalConstant(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Must start with uppercase letter
	if s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	// Must be all uppercase letters, digits, and underscores
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// resolveGlobalConstant attempts to resolve a global constant value from define() statements
// It searches for define('CONSTANT_NAME', 'value') patterns
func resolveGlobalConstant(constName string, content string) string {
	// Look for define() statement in current content
	matches := phpDefineConstPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 && match[1] == constName {
			return match[2]
		}
	}

	// Common WordPress plugin REST namespace constant patterns
	constNameLower := strings.ToLower(constName)

	// Pattern: PLUGIN_REST_URL or PLUGIN_REST_NS or PLUGIN_REST_API_NAMESPACE
	// Extract plugin name from constant and create standard namespace
	if strings.Contains(constNameLower, "rest") || strings.Contains(constNameLower, "api") {
		// Get configuration for constant namespace mappings
		cfg := getRESTConfig()

		// Check configuration for constant namespace mappings first
		if cfg != nil && cfg.REST != nil && cfg.REST.ConstantNamespaceMappings != nil {
			if ns, ok := cfg.REST.ConstantNamespaceMappings[constName]; ok {
				return ns
			}
		}

		// Try to infer from constant name pattern
		// Remove common suffixes to get plugin identifier
		name := constName
		for _, suffix := range []string{"_REST_URL", "_REST_API", "_REST_NAMESPACE", "_API_NAMESPACE", "_REST_NS", "_REST"} {
			if strings.HasSuffix(name, suffix) {
				name = strings.TrimSuffix(name, suffix)
				break
			}
		}
		// Convert to lowercase and add /v1
		name = strings.ToLower(name)
		name = strings.ReplaceAll(name, "_", "-")
		return name + "/v1"
	}

	return "{" + constName + "}"
}

// findClassNamespace attempts to find the REST namespace for a class using $this->register_route
// It looks for get_namespace() method or $namespace property
func findClassNamespace(content string, position int, pluginSlug string) string {
	// Use pre-compiled pattern for get_namespace method returning string
	if match := classGetNamespacePattern.FindStringSubmatch(content); len(match) >= 2 {
		return match[1]
	}

	// Use pre-compiled pattern for get_namespace method with interpolated string
	if match := classGetNamespaceInterpolatedPattern.FindStringSubmatch(content); len(match) >= 2 {
		// Handle {$this->get_slug()} style
		ns := match[1]
		if strings.Contains(ns, "get_slug") {
			// Extract slug from class using pre-compiled pattern
			if slugMatch := classGetSlugPattern.FindStringSubmatch(content); len(slugMatch) >= 2 {
				ns = strings.Replace(ns, "{$this->get_slug()}", slugMatch[1], 1)
				ns = strings.Replace(ns, "$this->get_slug()", slugMatch[1], 1)
			} else {
				// Use plugin slug as fallback
				ns = strings.Replace(ns, "{$this->get_slug()}", pluginSlug, 1)
				ns = strings.Replace(ns, "$this->get_slug()", pluginSlug, 1)
			}
		}
		return ns
	}

	// Use pre-compiled pattern for $namespace property
	if match := classNamespacePropertyPattern.FindStringSubmatch(content); len(match) >= 2 {
		return match[1]
	}

	// Use pre-compiled pattern for $this->namespace assignment
	if match := classNamespaceAssignPattern.FindStringSubmatch(content); len(match) >= 2 {
		return match[1]
	}

	// Return a placeholder based on plugin slug
	return pluginSlug + "/v1"
}

// findClassNamespaceFromConstant finds the namespace from class constant definitions
// Used for static wrapper patterns like self::register_route()
func findClassNamespaceFromConstant(content string, pluginSlug string) string {
	// Look for REST_API_NAMESPACE or similar constants using pre-compiled patterns
	for _, pattern := range namespaceConstPatterns {
		if match := pattern.FindStringSubmatch(content); len(match) >= 2 {
			return match[1]
		}
	}

	// Look for register_rest_route call with constant to infer namespace using pre-compiled pattern
	if match := restRouteConstPattern.FindStringSubmatch(content); len(match) >= 2 {
		constName := match[1]
		// Try to find the constant definition (dynamic pattern - must compile per constName)
		constDefPattern := regexp.MustCompile(
			`define\s*\(\s*['"]` + regexp.QuoteMeta(constName) + `['"]` + `\s*,\s*['"]([^'"]+)['"]`,
		)
		if constMatch := constDefPattern.FindStringSubmatch(content); len(constMatch) >= 2 {
			return constMatch[1]
		}
	}

	// Return placeholder
	return pluginSlug + "/v1"
}

// findRESTRootConstant finds the REST_ROOT constant
func findRESTRootConstant(content string, pluginSlug string) string {
	// Look for REST_ROOT constant using pre-compiled patterns
	for _, pattern := range restRootPatterns {
		if match := pattern.FindStringSubmatch(content); len(match) >= 2 {
			return match[1]
		}
	}

	// Return placeholder
	return pluginSlug + "/v1"
}

// findPropertyNamespace finds the namespace from a property-based wrapper class
func findPropertyNamespace(content string, pluginSlug string) string {
	// Look for route_namespace property using pre-compiled patterns
	for _, pattern := range propertyNamespacePatterns {
		if match := pattern.FindStringSubmatch(content); len(match) >= 2 {
			return match[1]
		}
	}

	// Return placeholder based on plugin slug
	return pluginSlug + "/v1"
}

// findVariableArrayValue finds the array value assigned to a variable before a given position
// This is used for patterns like:
//
//	$route_args = [ 'methods' => 'POST', 'callback' => [...], 'permission_callback' => [...] ];
//	register_rest_route( Main::API_V1_NAMESPACE, self::ROUTE, $route_args );
func findVariableArrayValue(content, varName string, beforePosition int) string {
	// Only look at content before the register_rest_route call
	searchContent := content[:beforePosition]

	// Build pattern to find: $varName = [...] or $varName = array(...)
	varNameEscaped := regexp.QuoteMeta(varName)
	pattern := regexp.MustCompile(varNameEscaped + `\s*=\s*(\[|array\s*\()`)

	// Find all matches and get the last one (closest to the call)
	matches := pattern.FindAllStringSubmatchIndex(searchContent, -1)
	if len(matches) == 0 {
		return ""
	}

	// Use the last match (most recent assignment before the call)
	lastMatch := matches[len(matches)-1]
	if len(lastMatch) < 4 {
		return ""
	}

	// Get the array start position
	argsStartPos := lastMatch[2]
	argsStart := searchContent[lastMatch[2]:lastMatch[3]]

	// Find the actual bracket position for extraction
	if argsStart != "[" {
		// array( - find the opening paren
		parenPos := strings.Index(searchContent[lastMatch[2]:], "(")
		if parenPos >= 0 {
			argsStartPos = lastMatch[2] + parenPos
		}
	}

	// Extract the full array using bracket matching
	return extractArgsWithBracketMatching(searchContent, argsStartPos)
}

// extractAPINamespace extracts namespace from API_NAMESPACE constant
func extractAPINamespace(content string, pluginSlug string) string {
	// Look for const API_NAMESPACE = 'value' using pre-compiled pattern
	if match := apiNamespaceConstPattern.FindStringSubmatch(content); len(match) >= 2 {
		return match[1]
	}

	// Look for define() using pre-compiled pattern
	if match := apiNamespaceDefinePattern.FindStringSubmatch(content); len(match) >= 2 {
		return match[1]
	}

	return pluginSlug + "/v1"
}

// extractNearbyMethod extracts HTTP method from ROUTE_METHODS near a route definition
func extractNearbyMethod(content string, position int) string {
	// Look for ROUTE_METHODS => 'METHOD' near the position
	start := position - 200
	if start < 0 {
		start = 0
	}
	end := position + 200
	if end > len(content) {
		end = len(content)
	}

	nearbyContent := content[start:end]

	// Use pre-compiled pattern
	if match := nearbyMethodPattern.FindStringSubmatch(nearbyContent); len(match) >= 2 {
		return strings.ToUpper(match[1])
	}

	return "GET"
}

// extractNearbyContext extracts code context around a position
func extractNearbyContext(content string, position int, radius int) string {
	start := position - radius
	if start < 0 {
		start = 0
	}
	end := position + radius
	if end > len(content) {
		end = len(content)
	}

	return content[start:end]
}

// resolveSprintfRoute converts a sprintf format string into a route with dynamic markers
// Example: "/%s/(?P<id>\d+)" -> "/{dynamic}/(?P<id>\d+)"
// Example: "/%1$s/(?P<slug>%2$s)" -> "/{dynamic}/(?P<slug>{dynamic})"
func resolveSprintfRoute(formatStr string) string {
	// Replace format specifiers with dynamic markers using pre-compiled pattern
	result := sprintfPlaceholderPattern.ReplaceAllString(formatStr, "{dynamic}")

	// Clean up any double slashes that might result
	result = strings.ReplaceAll(result, "//", "/")

	return result
}

// extractWPRestControllerNamespace extracts the REST namespace from a WP_REST_Controller subclass
func extractWPRestControllerNamespace(content string, pluginSlug string) string {
	// Look for getNamespace method (using pre-compiled pattern)
	if match := wpRestGetNamespaceCamelPattern.FindStringSubmatch(content); len(match) >= 2 {
		return match[1]
	}

	// Look for namespace property or constant using pre-compiled patterns
	for _, re := range wpRestControllerNamespacePatterns {
		if match := re.FindStringSubmatch(content); len(match) >= 2 {
			return match[1]
		}
	}

	// Look for buildNamespace method with sprintf pattern (using pre-compiled pattern)
	if match := wpRestBuildNamespacePattern.FindStringSubmatch(content); len(match) >= 2 {
		// Extract base namespace from sprintf format (e.g., '%s/v%s' -> use first part)
		format := match[1]
		// Replace %s with plugin slug
		format = strings.Replace(format, "%s", pluginSlug, 1)
		format = strings.Replace(format, "%s", "1", 1) // version
		return format
	}

	// Default based on plugin slug
	return pluginSlug + "/v1"
}

// extractWPRestControllerMethod extracts the HTTP method from a WP_REST_Controller subclass
func extractWPRestControllerMethod(content string) string {
	// Look for ROUTE_METHOD constant (using pre-compiled pattern)
	if match := routeMethodConstPattern.FindStringSubmatch(content); len(match) >= 2 {
		return parseMethodConstant(match[1])[0]
	}

	// Look for getRouteMethods returning array (using pre-compiled pattern)
	if match := routeMethodArrayPattern.FindStringSubmatch(content); len(match) >= 2 {
		return strings.ToUpper(match[1])
	}

	// Default to GET
	return "GET"
}

// extractWPRestControllerAuth extracts the auth level from a WP_REST_Controller subclass
func extractWPRestControllerAuth(content string) models.AuthLevel {
	// Look for verifyPermission or permission_callback patterns
	// Check for user_cap in authorization
	if strings.Contains(content, "user_cap") {
		// Check what capability is required (using pre-compiled pattern)
		if match := userCapPattern.FindStringSubmatch(content); len(match) >= 2 {
			cap := match[1]
			initCapabilityLevels()
			if level, ok := capabilityLevels[cap]; ok {
				return level
			}
			if strings.Contains(cap, "manage") || strings.Contains(cap, "admin") {
				return models.Admin
			}
		}
		return models.Subscriber
	}

	// Check for current_user_can
	if strings.Contains(content, "current_user_can") {
		return InferAuthLevel(content)
	}

	// Check for authorization array
	if strings.Contains(content, "'authorization'") || strings.Contains(content, "\"authorization\"") {
		return models.Subscriber
	}

	// Default to User for REST controller routes (they typically require auth)
	return models.Subscriber
}

// extractClassName extracts the class name from PHP code
func extractClassName(content string) string {
	// Use pre-compiled pattern
	if match := extractClassNamePattern.FindStringSubmatch(content); len(match) >= 2 {
		return match[1]
	}
	return "unknown"
}

// DetectRESTEndpointsWithAST wraps DetectRESTEndpoints with AST-backed cross-file
// permission_callback resolution.
func DetectRESTEndpointsWithAST(content, filepath string, pluginSlug string, astCtx *wpast.ASTContext) []models.Endpoint {
	endpoints := DetectRESTEndpoints(content, filepath, pluginSlug)

	if astCtx == nil || !astCtx.Available {
		return endpoints
	}

	for i := range endpoints {
		ep := &endpoints[i]
		if ep.Callback == "" {
			continue
		}

		callbackRef := parseCallbackToRef(ep.Callback, ep.File)
		if callbackRef.Type == "" {
			continue
		}

		astLevel := astCtx.Resolver.ResolvePermissionCallback(callbackRef)
		if astLevel < ep.AuthLevel {
			ep.AuthLevel = astLevel
		}
	}

	return endpoints
}

func parseCallbackToRef(callback, filePath string) wpast.CallbackRef {
	if strings.Contains(callback, "::") {
		parts := strings.SplitN(callback, "::", 2)
		return wpast.CallbackRef{
			Type:       "static_method",
			ClassName:  parts[0],
			MethodName: parts[1],
			File:       filePath,
		}
	}
	if callback != "" && !strings.ContainsAny(callback, "()[]$") {
		return wpast.CallbackRef{
			Type:     "function",
			FuncName: callback,
			File:     filePath,
		}
	}
	return wpast.CallbackRef{}
}

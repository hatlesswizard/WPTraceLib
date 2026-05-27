package analyzer

import (
	"regexp"
	"strings"

	wpast "github.com/hatlesswizard/wptracelib/pkg/ast"
	"github.com/hatlesswizard/wptracelib/pkg/config"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// ajaxConfig holds the current AJAX configuration.
// This is shared with auth.go's authConfig for consistency.
func getAJAXConfig() *config.Config {
	return GetAuthConfig()
}

// Package-level compiled regex patterns for AJAX detection (Issue 2 fix)
var (
	// Pattern for extractFunctionName - array notation
	ajaxArrayNotationPattern = regexp.MustCompile(`(?:\[|\barray\s*\()[^,]+,\s*['"]([^'"]+)['"]`)

	// Patterns for DetectDirectAJAXHandlers
	ajaxDirectHandlerPattern1 = regexp.MustCompile(`\$_(POST|GET|REQUEST)\s*\[\s*['"]action['"]\s*\]\s*===?\s*['"]([^'"]+)['"]`)
	ajaxDirectHandlerPattern2 = regexp.MustCompile(`['"]([^'"]+)['"]\s*===?\s*\$_(POST|GET|REQUEST)\s*\[\s*['"]action['"]\s*\]`)

	// Dynamic AJAX patterns with concatenation
	// add_action('wp_ajax_' . $this->identifier, ...)
	ajaxConcatAuthPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]wp_ajax_['"]\s*\.\s*` +
			`([^,]+?)\s*,\s*` +
			`([^,)]+)`,
	)

	// add_action('wp_ajax_nopriv_' . $this->identifier, ...)
	ajaxConcatNoprivPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]wp_ajax_nopriv_['"]\s*\.\s*` +
			`([^,]+?)\s*,\s*` +
			`([^,)]+)`,
	)

	// Interpolated string pattern: add_action("wp_ajax_{$action}", ...)
	// Curly brace syntax for complex expressions
	ajaxInterpolatedAuthPattern = regexp.MustCompile(
		`add_action\s*\(\s*"wp_ajax_\{\$([a-zA-Z_][a-zA-Z0-9_]*)\}"\s*,\s*` +
			`([^,)]+)`,
	)

	ajaxInterpolatedNoprivPattern = regexp.MustCompile(
		`add_action\s*\(\s*"wp_ajax_nopriv_\{\$([a-zA-Z_][a-zA-Z0-9_]*)\}"\s*,\s*` +
			`([^,)]+)`,
	)

	// Simple interpolation pattern: add_action("wp_ajax_$action", ...)
	// No curly braces - direct variable interpolation
	ajaxSimpleInterpolatedAuthPattern = regexp.MustCompile(
		`add_action\s*\(\s*"wp_ajax_\$([a-zA-Z_][a-zA-Z0-9_]*)"\s*,\s*` +
			`([^,)]+)`,
	)

	ajaxSimpleInterpolatedNoprivPattern = regexp.MustCompile(
		`add_action\s*\(\s*"wp_ajax_nopriv_\$([a-zA-Z_][a-zA-Z0-9_]*)"\s*,\s*` +
			`([^,)]+)`,
	)

	// Class property action: $this->action property used in add_action
	ajaxThisActionPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]wp_ajax_['"]\s*\.\s*\$this\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*` +
			`([^,)]+)`,
	)

	ajaxThisActionNoprivPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]wp_ajax_nopriv_['"]\s*\.\s*\$this\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*` +
			`([^,)]+)`,
	)

	// Anonymous function callback patterns
	// add_action('wp_ajax_{action}', function() { ... });
	ajaxAnonFuncAuthPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]wp_ajax_([^'"]+)['"]\s*,\s*function\s*\(`,
	)

	// add_action('wp_ajax_nopriv_{action}', function() { ... });
	ajaxAnonFuncNoprivPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]wp_ajax_nopriv_([^'"]+)['"]\s*,\s*function\s*\(`,
	)

	// admin_post_* patterns - WordPress form submission handlers
	// add_action('admin_post_{action}', ...) - requires login (admin_post_ prefix)
	// add_action('admin_post_nopriv_{action}', ...) - no login required
	adminPostAuthPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]admin_post_([^'"]+)['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	adminPostNoprivPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]admin_post_nopriv_([^'"]+)['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	// admin_action_* patterns - WordPress admin action handlers
	// These fire on admin-post.php when $_REQUEST['action'] matches
	// add_action('admin_action_{action}', ...) - requires login (admin context)
	// add_action('admin_action_nopriv_{action}', ...) - no login required
	adminActionPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]admin_action_([^'"]+)['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	adminActionNoprivPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]admin_action_nopriv_([^'"]+)['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	// admin_action_ with dynamic action name via concatenation
	// add_action('admin_action_' . self::CONSTANT, ...)
	adminActionConcatPattern = regexp.MustCompile(
		`add_action\s*\(\s*['"]admin_action_['"]\s*\.\s*` +
			`([^,]+?)\s*,\s*` +
			`([^,)]+)`,
	)

	// Heartbeat API patterns - WordPress's real-time communication system
	// heartbeat_received - fires when heartbeat is received (requires login by default)
	// heartbeat_send - fires when sending heartbeat data
	// heartbeat_nopriv_received / heartbeat_nopriv_send - no-login versions
	heartbeatReceivedPattern = regexp.MustCompile(
		`add_filter\s*\(\s*['"]heartbeat_received['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	heartbeatNoprivReceivedPattern = regexp.MustCompile(
		`add_filter\s*\(\s*['"]heartbeat_nopriv_received['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	heartbeatSendPattern = regexp.MustCompile(
		`add_filter\s*\(\s*['"]heartbeat_send['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	heartbeatNoprivSendPattern = regexp.MustCompile(
		`add_filter\s*\(\s*['"]heartbeat_nopriv_send['"]\s*,\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // function name string
			`|` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`)`,
	)

	// Pattern to find array of string literals (for foreach-based AJAX detection)
	// Matches: $ajax_events = array('action1', 'action2', ...); or $ajax_events = ['action1', 'action2', ...]
	phpStringArrayPattern = regexp.MustCompile(
		`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:array\s*\(|\[)\s*` +
			`(['"][a-z_][a-z0-9_]*['"]` +
			`(?:\s*,\s*['"][a-z_][a-z0-9_]*['"])*)\s*` +
			`(?:\)|])`,
	)

	// Pattern for foreach declaration (we'll handle the body separately)
	foreachArrayPattern = regexp.MustCompile(
		`foreach\s*\(\s*\$([a-zA-Z_][a-zA-Z0-9_]*)\s+as\s+\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\)`,
	)

	// WordPress Plugin Boilerplate loader patterns
	// These plugins use a custom loader class to defer add_action() calls
	// Pattern: $this->loader->add_action( 'wp_ajax_ACTION', $component, 'callback' )
	// The loader collects hooks and registers them later via run()
	loaderAjaxAuthPattern = regexp.MustCompile(
		`\$this\s*->\s*loader\s*->\s*add_action\s*\(\s*['"]wp_ajax_([^'"]+)['"]\s*,\s*` +
			`[^,]+,\s*` + // $component parameter (skip)
			`['"]([^'"]+)['"]`, // callback method name
	)

	loaderAjaxNoprivPattern = regexp.MustCompile(
		`\$this\s*->\s*loader\s*->\s*add_action\s*\(\s*['"]wp_ajax_nopriv_([^'"]+)['"]\s*,\s*` +
			`[^,]+,\s*` + // $component parameter (skip)
			`['"]([^'"]+)['"]`, // callback method name
	)

	// Also match loader patterns with dynamic action names via concatenation
	// $this->loader->add_action( 'wp_ajax_' . $prefix . $action, ...)
	loaderAjaxConcatAuthPattern = regexp.MustCompile(
		`\$this\s*->\s*loader\s*->\s*add_action\s*\(\s*['"]wp_ajax_['"]\s*\.\s*([^,]+?),`,
	)

	loaderAjaxConcatNoprivPattern = regexp.MustCompile(
		`\$this\s*->\s*loader\s*->\s*add_action\s*\(\s*['"]wp_ajax_nopriv_['"]\s*\.\s*([^,]+?),`,
	)

	// Framework wrapper patterns - some plugins use their own container/app object
	// Pattern: $app->addAction('wp_ajax_ACTION', ...) or $container->addAction(...)
	// Pattern: $this->wp->addAction('wp_ajax_ACTION', ...) - MailPoet style property chain
	// This is a general pattern used by FluentForm and other DI-container-based plugins
	// The auth pattern captures ALL actions - we filter nopriv in code (Go doesn't support negative lookahead)
	// Updated to handle property chains like $this->property->method(...)
	frameworkAddActionPattern = regexp.MustCompile(
		`\$[a-zA-Z_][a-zA-Z0-9_]*(?:\s*->\s*[a-zA-Z_][a-zA-Z0-9_]*)*\s*->\s*addAction\s*\(\s*['"]wp_ajax_(nopriv_)?([^'"]+)['"]\s*,\s*` +
			`([^)]+)`, // callback (can be closure or array)
		// Group 1: "nopriv_" or empty - indicates if unauthenticated
		// Group 2: the action name
		// Group 3: the callback
	)

	// Static method wrapper patterns - plugins using static helper classes
	// Pattern: Hooks::addAction('wp_ajax_ACTION', ClassName::class, 'method')
	// Pattern: Hooks::addAction('wp_ajax_ACTION', ClassName::class)
	// Used by Give plugin and others that use a Hooks helper class
	// Group 1: "nopriv_" or empty, Group 2: action name, Group 3: callback class/method
	staticAddActionPattern = regexp.MustCompile(
		`[A-Z][a-zA-Z0-9_]*\s*::\s*addAction\s*\(\s*['"]wp_ajax_(nopriv_)?([^'"]+)['"]\s*,\s*` +
			`([^)]+)`,
	)

	// Generic wrapper detection pattern for methods that call add_action internally
	// Pattern: $this->endpoints->registerAjaxEndpoint('action', callback)
	// Pattern: $this->registerAjax('action', callback)
	// This captures wrapper methods named like registerAjax, registerAjaxEndpoint, etc.
	// Group 1: method name, Group 2: action name, Group 3: callback
	genericAjaxWrapperPattern = regexp.MustCompile(
		`->\s*(register(?:Ajax|_ajax)(?:Endpoint|Action|Handler)?)\s*\(\s*['"]([^'"]+)['"]\s*,\s*` +
			`([^)]+)`,
	)

	// Elementor AJAX framework patterns
	// Used by Elementor and its addons for registering AJAX actions
	// Pattern: $ajax_manager->register_ajax_action( 'action_name', [ $this, 'callback' ] )
	// Pattern: $ajax->register_ajax_action( 'action_name', function( $data ) { ... } )
	// These actions are typically called via Elementor's AJAX handler (elementor-ajax action)
	// and require user authentication (Elementor checks nonce + user caps internally)
	elementorAjaxActionPattern = regexp.MustCompile(
		`\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*register_ajax_action\s*\(\s*['"]([^'"]+)['"]\s*,\s*` +
			`(?:` +
			`(\[[^\]]+\])` + // array notation [$this, 'method']
			`|` +
			`(array\s*\([^)]+\))` + // array() notation
			`|` +
			`(function\s*\()` + // anonymous function
			`)`,
	)

	// ACF (Advanced Custom Fields) AJAX registration pattern
	// Pattern: acf_register_ajax( 'action_name', 'callback_function', $public );
	// The $public argument determines if authentication is required:
	// - false (default): requires authentication (User level)
	// - true: no authentication required (Unauthenticated)
	acfRegisterAjaxPattern = regexp.MustCompile(
		`acf_register_ajax\s*\(\s*['"]([^'"]+)['"]\s*,\s*` +
			`(['"][^'"]+['"]` + // function name string
			`|` +
			`\[[^\]]+\]` + // array notation
			`)` +
			`(?:\s*,\s*(true|false))?\s*\)`, // optional $public argument
	)

	// Freemius SDK AJAX wrapper patterns
	// The Freemius SDK provides helper methods for registering AJAX actions:
	// - $this->add_ajax_action( 'tag', [ $this, 'callback' ] ) - instance method
	// - Freemius::add_ajax_action_static( 'tag', [ $this, 'callback' ] ) - static method
	// These wrap add_action('wp_ajax_' . dynamic_action, $callback) internally
	// They require authentication by default (admin/subscriber level depending on context)
	// Updated to extract method name from array callbacks with nested elements
	freemiusAddAjaxActionPattern = regexp.MustCompile(
		`(?:\$this\s*->\s*add_ajax_action|Freemius::add_ajax_action_static)\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` + // Group 1: action tag
			`(?:` +
			`['"]([^'"]+)['"]` + // Group 2: simple string callback
			`|` +
			`\[[^,]+,\s*['"]([^'"]+)['"]` + // Group 3: bracket array - extracts method
			`|` +
			`array\s*\([^,]+,\s*['"]([^'"]+)['"]` + // Group 4: array() - extracts method
			`|` +
			`([^,)]+)` + // Group 5: fallback for variable/other
			`)`,
	)

	// Static patterns moved from function scope
	// Used to extract method names from callbacks
	simpleStringQuotePattern = regexp.MustCompile(`['"]([^'"]+)['"]`)
	// Used to extract action names
	actionNamePattern = regexp.MustCompile(`['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)

	// Patterns for cleaning PHP interpolation from action names
	// Note: We exclude superglobals ($_REQUEST, $_POST, $_GET, etc.) from cleaning
	phpInterpolationBraceThisPattern   = regexp.MustCompile(`\{\$this->([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	phpInterpolationBraceVarPattern    = regexp.MustCompile(`\{\$([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	phpInterpolationNoBraceThisPattern = regexp.MustCompile(`\$this->([a-zA-Z_][a-zA-Z0-9_]*)`)
	// Pattern for $var that's NOT a superglobal (not starting with _)
	phpInterpolationNoBraceVarPattern = regexp.MustCompile(`\$([a-z][a-zA-Z0-9_]*)`)
)

// cleanActionName cleans PHP interpolation syntax from action names
// Converts {$this->prop} -> {prop}, {$var} -> {var}, $this->prop -> {prop}, $var -> {var}
// Excludes superglobals like $_REQUEST, $_POST, $_GET
func cleanActionName(action string) string {
	// Replace {$this->prop} with {prop}
	action = phpInterpolationBraceThisPattern.ReplaceAllString(action, "{$1}")

	// Replace {$var} with {var} - but only for regular variables (not superglobals)
	action = phpInterpolationBraceVarPattern.ReplaceAllStringFunc(action, func(match string) string {
		// Don't clean superglobals like {$_REQUEST}
		if strings.Contains(match, "{$_") {
			return match
		}
		submatches := phpInterpolationBraceVarPattern.FindStringSubmatch(match)
		if len(submatches) > 1 {
			return "{" + submatches[1] + "}"
		}
		return match
	})

	// Replace $this->prop with {prop} (when not in braces)
	action = phpInterpolationNoBraceThisPattern.ReplaceAllString(action, "{$1}")

	// Replace $var with {var} (when not in braces) - skip superglobals
	// Only match $lowercase_var (not $_SUPERGLOBALS)
	action = phpInterpolationNoBraceVarPattern.ReplaceAllStringFunc(action, func(match string) string {
		// Skip superglobals (start with $_)
		if strings.HasPrefix(match, "$_") {
			return match
		}
		submatches := phpInterpolationNoBraceVarPattern.FindStringSubmatch(match)
		if len(submatches) > 1 {
			return "{" + submatches[1] + "}"
		}
		return match
	})

	return action
}

// formatAjaxRoute converts an AJAX hook name to its actual WordPress URL
func formatAjaxRoute(hookName string) string {
	// Clean PHP interpolation syntax from the action name
	hookName = cleanActionName(hookName)
	action := hookName

	// Remove known prefixes to extract the action name
	// Order matters: check longer prefixes first
	prefixes := []string{
		"wp_ajax_nopriv_",
		"wp_ajax_",
		"admin_post_nopriv_",
		"admin_post_",
		"admin_action_",
		"wc_ajax_",
		"woocommerce_api_",
		"heartbeat_nopriv_",
		"heartbeat_",
		"direct_ajax_",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(action, prefix) {
			action = strings.TrimPrefix(action, prefix)
			break
		}
	}

	// Map to actual URL based on hook type
	switch {
	case strings.HasPrefix(hookName, "wp_ajax_") ||
		strings.HasPrefix(hookName, "admin_action_") ||
		strings.HasPrefix(hookName, "heartbeat_") ||
		strings.HasPrefix(hookName, "direct_ajax_"):
		return "wp-admin/admin-ajax.php?action=" + action
	case strings.HasPrefix(hookName, "admin_post_"):
		return "wp-admin/admin-post.php?action=" + action
	case strings.HasPrefix(hookName, "wc_ajax_"):
		return "?wc-ajax=" + action
	case strings.HasPrefix(hookName, "woocommerce_api_"):
		return "?wc-api=" + action
	case strings.HasPrefix(hookName, "elementor_ajax:"):
		// Elementor uses its own AJAX system via wp_ajax_elementor_ajax
		return "wp-admin/admin-ajax.php?action=elementor_ajax&actions=" + strings.TrimPrefix(hookName, "elementor_ajax:")
	case strings.HasPrefix(hookName, "acf_ajax:"):
		// ACF uses wp_ajax_acf/[action]
		return "wp-admin/admin-ajax.php?action=acf/" + strings.TrimPrefix(hookName, "acf_ajax:")
	default:
		// Unknown format - return as-is
		return hookName
	}
}

// AJAXAuthPattern matches add_action('wp_ajax_{action}', ...) for authenticated users
// IMPORTANT: This pattern must NOT match nopriv routes - those are handled by AJAXNoprivPattern
// The action name must start with a letter/underscore but NOT 'nopriv_'
// We use a negative lookahead simulation by matching the pattern and filtering in code
// Pattern handles nested parentheses in array callbacks (e.g., array(UM()->form(), 'method'))
// by matching up to the comma and extracting the method name directly
// Also includes fallback patterns for variable callbacks without method names
var AJAXAuthPattern = regexp.MustCompile(
	`add_action\s*\(\s*['"]wp_ajax_([^'"]+)['"]\s*,\s*` +
		`(?:` +
		`['"]([^'"]+)['"]` + // function name string
		`|` +
		`\[[^,]+,\s*['"]([^'"]+)['"]` + // array notation with method - extracts method name
		`|` +
		`array\s*\([^,]+,\s*['"]([^'"]+)['"]` + // array() notation with method - extracts method name
		`|` +
		`(\[[^\]]+\])` + // array notation fallback [$var] - full array
		`|` +
		`(array\s*\([^)]+\))` + // array() fallback - full array (may truncate nested parens)
		`)`,
)

// AJAXNoprivPattern matches add_action('wp_ajax_nopriv_{action}', ...) for unauthenticated users
// Pattern handles nested parentheses in array callbacks by extracting method name directly
// Also includes fallback patterns for variable callbacks without method names
var AJAXNoprivPattern = regexp.MustCompile(
	`add_action\s*\(\s*['"]wp_ajax_nopriv_([^'"]+)['"]\s*,\s*` +
		`(?:` +
		`['"]([^'"]+)['"]` + // function name string
		`|` +
		`\[[^,]+,\s*['"]([^'"]+)['"]` + // array notation with method - extracts method name
		`|` +
		`array\s*\([^,]+,\s*['"]([^'"]+)['"]` + // array() notation with method - extracts method name
		`|` +
		`(\[[^\]]+\])` + // array notation fallback [$var] - full array
		`|` +
		`(array\s*\([^)]+\))` + // array() fallback - full array (may truncate nested parens)
		`)`,
)

// WooCommerce wc_ajax_* pattern - WooCommerce's custom AJAX system
// These are fired via the wc-ajax query parameter and are commonly used
// in WooCommerce core and extensions. They are generally for frontend AJAX
// and require a logged-in user (unless explicitly registered as nopriv).
// Pattern: add_action('wc_ajax_{action}', ...)
// Pattern handles nested parentheses in array callbacks with fallback
var wcAjaxPattern = regexp.MustCompile(
	`add_action\s*\(\s*['"]wc_ajax_([^'"]+)['"]\s*,\s*` +
		`(?:` +
		`['"]([^'"]+)['"]` + // function name string
		`|` +
		`\[[^,]+,\s*['"]([^'"]+)['"]` + // array notation with method - extracts method name
		`|` +
		`array\s*\([^,]+,\s*['"]([^'"]+)['"]` + // array() notation with method - extracts method name
		`|` +
		`(\[[^\]]+\])` + // array notation fallback
		`|` +
		`(array\s*\([^)]+\))` + // array() fallback
		`)`,
)

// WooCommerce API callback pattern - Used for payment gateway webhooks/IPN
// These are fired when a URL contains ?wc-api={endpoint}
// Pattern: add_action('woocommerce_api_{endpoint}', ...)
// These are UNAUTHENTICATED as they're called by external services (PayPal, Stripe, etc.)
// Pattern handles nested parentheses in array callbacks with fallback
var wcAPICallbackPattern = regexp.MustCompile(
	`add_action\s*\(\s*['"]woocommerce_api_([^'"]+)['"]\s*,\s*` +
		`(?:` +
		`['"]([^'"]+)['"]` + // function name string
		`|` +
		`\[[^,]+,\s*['"]([^'"]+)['"]` + // array notation with method - extracts method name
		`|` +
		`array\s*\([^,]+,\s*['"]([^'"]+)['"]` + // array() notation with method - extracts method name
		`|` +
		`(\[[^\]]+\])` + // array notation fallback
		`|` +
		`(array\s*\([^)]+\))` + // array() fallback
		`)`,
)

// WooCommerce API callback with concatenation
// Pattern: add_action('woocommerce_api_' . $this->id, ...)
// or: add_action('woocommerce_api_' . strtolower($endpoint), ...)
var wcAPICallbackConcatPattern = regexp.MustCompile(
	`add_action\s*\(\s*['"]woocommerce_api_['"]\s*\.\s*` +
		`([^,]+?)\s*,\s*` +
		`([^,)]+)`,
)

// DetectAJAXEndpoints finds all AJAX endpoints in PHP code
func DetectAJAXEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	// Pre-allocate with estimated capacity to reduce slice growth allocations
	endpoints := make([]models.Endpoint, 0, 16)
	processedPositions := make(map[int]bool)

	// 1. Find authenticated AJAX endpoints (wp_ajax_*) - literal strings
	// Note: The pattern may match nopriv routes too, so we filter them out
	authMatches := AJAXAuthPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range authMatches {
		// Extract action name and skip if it starts with nopriv_
		// (those are handled by AJAXNoprivPattern)
		if len(match) >= 4 && match[2] >= 0 && match[3] > match[2] {
			action := content[match[2]:match[3]]
			if strings.HasPrefix(action, "nopriv_") {
				continue // Skip nopriv routes - they'll be handled separately
			}
		}
		processedPositions[match[0]] = true
		ep := parseAJAXMatch(content, match, filepath, pluginSlug, false)
		if ep != nil {
			endpoints = append(endpoints, *ep)
		}
	}

	// 2. Find unauthenticated AJAX endpoints (wp_ajax_nopriv_*) - literal strings
	noprivMatches := AJAXNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range noprivMatches {
		processedPositions[match[0]] = true
		ep := parseAJAXMatch(content, match, filepath, pluginSlug, true)
		if ep != nil {
			endpoints = append(endpoints, *ep)
		}
	}

	// 3. Find concatenated auth AJAX: add_action('wp_ajax_' . $var, ...)
	concatAuthMatches := ajaxConcatAuthPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range concatAuthMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varExpr := strings.TrimSpace(content[match[2]:match[3]])
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Skip partial function call matches (e.g., "get_ajax_action_static( $tag" from Freemius SDK)
		// These have unbalanced parentheses because the regex stopped at a comma inside the function
		if strings.Contains(varExpr, "(") && !strings.Contains(varExpr, ")") {
			continue
		}

		// Try to resolve the variable
		action := resolveDynamicAction(varExpr, content)

		// Apply auth heuristics
		authLevel := models.Subscriber
		if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		}

		rawCode := truncateCode(fullMatch, 500)
		if isDynamicPlaceholder(action) {
			rawCode = rawCode + " [dynamic:unresolved:" + varExpr + "]"
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
		}
		endpoints = append(endpoints, ep)
	}

	// 4. Find concatenated nopriv AJAX: add_action('wp_ajax_nopriv_' . $var, ...)
	concatNoprivMatches := ajaxConcatNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range concatNoprivMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varExpr := strings.TrimSpace(content[match[2]:match[3]])
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		action := resolveDynamicAction(varExpr, content)

		rawCode := truncateCode(fullMatch, 500)
		if isDynamicPlaceholder(action) {
			rawCode = rawCode + " [dynamic:unresolved:" + varExpr + "]"
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_nopriv_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
		}
		endpoints = append(endpoints, ep)
	}

	// 5. Find interpolated auth AJAX: add_action("wp_ajax_{$var}", ...)
	interpolatedAuthMatches := ajaxInterpolatedAuthPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range interpolatedAuthMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varName := content[match[2]:match[3]]
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		action := resolveDynamicAction("$"+varName, content)

		authLevel := models.Subscriber
		if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 6. Find interpolated nopriv AJAX (curly brace syntax)
	interpolatedNoprivMatches := ajaxInterpolatedNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range interpolatedNoprivMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varName := content[match[2]:match[3]]
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		action := resolveDynamicAction("$"+varName, content)

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_nopriv_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 6b. Find simple interpolated auth AJAX: add_action("wp_ajax_$action", ...)
	simpleInterpAuthMatches := ajaxSimpleInterpolatedAuthPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range simpleInterpAuthMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varName := content[match[2]:match[3]]
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		action := resolveDynamicAction("$"+varName, content)

		authLevel := models.Subscriber
		if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 6c. Find simple interpolated nopriv AJAX: add_action("wp_ajax_nopriv_$action", ...)
	simpleInterpNoprivMatches := ajaxSimpleInterpolatedNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range simpleInterpNoprivMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varName := content[match[2]:match[3]]
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		action := resolveDynamicAction("$"+varName, content)

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_nopriv_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 7. Find $this->action patterns
	thisActionMatches := ajaxThisActionPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range thisActionMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		propName := content[match[2]:match[3]]
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		action := resolveDynamicAction("$this->"+propName, content)

		authLevel := models.Subscriber
		if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		}

		rawCode := truncateCode(fullMatch, 500)
		if isDynamicPlaceholder(action) {
			rawCode = rawCode + " [dynamic:unresolved:$this->" + propName + "]"
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
		}
		endpoints = append(endpoints, ep)
	}

	// 8. Find $this->action nopriv patterns
	thisActionNoprivMatches := ajaxThisActionNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range thisActionNoprivMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		propName := content[match[2]:match[3]]
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		action := resolveDynamicAction("$this->"+propName, content)

		rawCode := truncateCode(fullMatch, 500)
		if isDynamicPlaceholder(action) {
			rawCode = rawCode + " [dynamic:unresolved:$this->" + propName + "]"
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_nopriv_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
		}
		endpoints = append(endpoints, ep)
	}

	// 9. Find anonymous function AJAX handlers (wp_ajax_*)
	// Note: Pattern may match nopriv routes too, so we filter them out
	anonFuncAuthMatches := ajaxAnonFuncAuthPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range anonFuncAuthMatches {
		if len(match) < 4 || processedPositions[match[0]] {
			continue
		}

		action := content[match[2]:match[3]]
		// Skip nopriv actions - they're handled by anonFuncNoprivPattern
		if strings.HasPrefix(action, "nopriv_") {
			continue
		}

		processedPositions[match[0]] = true
		lineNum := countLines(content[:match[0]]) + 1

		// Extract the anonymous function body for auth analysis
		funcBody := extractAnonFunctionBody(content, match[1])
		authLevel := models.Subscriber // Default for wp_ajax_ (requires login)

		if funcBody != "" {
			inferredLevel := InferAuthLevel(funcBody)
			if inferredLevel > authLevel {
				authLevel = inferredLevel
			}
		}

		// Apply admin heuristics
		if authLevel == models.Subscriber {
			if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
				authLevel = models.Admin
			}
		}

		// Extract raw code (truncated)
		rawCodeEnd := match[1] + 100
		if rawCodeEnd > len(content) {
			rawCodeEnd = len(content)
		}
		rawCode := content[match[0]:rawCodeEnd]

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   "anonymous_function",
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(rawCode, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 10. Find anonymous function AJAX handlers (wp_ajax_nopriv_*)
	anonFuncNoprivMatches := ajaxAnonFuncNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range anonFuncNoprivMatches {
		if len(match) < 4 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		action := content[match[2]:match[3]]
		lineNum := countLines(content[:match[0]]) + 1

		// Extract raw code (truncated)
		rawCodeEnd := match[1] + 100
		if rawCodeEnd > len(content) {
			rawCodeEnd = len(content)
		}
		rawCode := content[match[0]:rawCodeEnd]

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_nopriv_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated, // nopriv means no login required
			Callback:   "anonymous_function",
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(rawCode, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 11. Find admin_post_* handlers (form submission hooks - requires login)
	adminPostAuthMatches := adminPostAuthPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range adminPostAuthMatches {
		if len(match) < 10 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		fullMatch := content[match[0]:match[1]]
		action := content[match[2]:match[3]]

		// Extract callback
		var callback string
		for i := 4; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		// admin_post_ requires login, typically admin-level since it's for admin forms
		authLevel := models.Admin

		// Look for additional auth checks in callback
		callbackBody := findCallbackBody(content, callback)
		if callbackBody != "" {
			inferredLevel := InferAuthLevel(callbackBody)
			if inferredLevel == models.Subscriber {
				// Downgrade to User if callback doesn't have admin capability checks
				authLevel = models.Subscriber
			}
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("admin_post_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 12. Find admin_post_nopriv_* handlers (form submission hooks - no login required)
	adminPostNoprivMatches := adminPostNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range adminPostNoprivMatches {
		if len(match) < 10 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		fullMatch := content[match[0]:match[1]]
		action := content[match[2]:match[3]]

		// Extract callback
		var callback string
		for i := 4; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("admin_post_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated, // nopriv means no login required
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 13. Find WooCommerce wc_ajax_* handlers
	// These are WooCommerce's custom AJAX system used extensively in WC core and extensions
	// By default, wc_ajax actions require a logged-in user
	wcAjaxMatches := wcAjaxPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range wcAjaxMatches {
		if len(match) < 10 || processedPositions[match[0]] {
			continue
		}

		// Don't double-count positions - but WC actions are separate from wp_ajax
		fullMatch := content[match[0]:match[1]]
		action := content[match[2]:match[3]]

		// Extract callback
		var callback string
		for i := 4; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		// WC AJAX by default requires authentication (session-based)
		// Analyze callback for more specific auth level
		authLevel := models.Subscriber
		callbackBody := findCallbackBody(content, callback)
		if callbackBody != "" {
			inferredLevel := InferAuthLevel(callbackBody)
			if inferredLevel > authLevel {
				authLevel = inferredLevel
			}
		}

		// Apply admin heuristics
		if authLevel == models.Subscriber {
			if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
				authLevel = models.Admin
			}
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wc_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 13b. Find WooCommerce API callback handlers (woocommerce_api_*)
	// These are used for payment gateway webhooks/IPN (PayPal, Stripe, Razorpay, etc.)
	// They are UNAUTHENTICATED as they're called by external services
	// Pattern: add_action('woocommerce_api_{endpoint}', ...)
	wcAPIMatches := wcAPICallbackPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range wcAPIMatches {
		if len(match) < 10 || processedPositions[match[0]] {
			continue
		}

		fullMatch := content[match[0]:match[1]]
		action := content[match[2]:match[3]]

		// Extract callback
		var callback string
		for i := 4; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		// WooCommerce API callbacks are UNAUTHENTICATED
		// They're called by external services (payment gateways) with their own verification
		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("woocommerce_api_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated, // External webhooks don't use WP auth
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 13c. Find WooCommerce API callback handlers with concatenation
	// Pattern: add_action('woocommerce_api_' . $this->id, ...)
	wcAPIConcatMatches := wcAPICallbackConcatPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range wcAPIConcatMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varExpr := strings.TrimSpace(content[match[2]:match[3]])
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Try to resolve the variable
		action := resolveDynamicAction(varExpr, content)

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("woocommerce_api_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated, // External webhooks don't use WP auth
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 14. Find admin_action_* handlers (WordPress admin action hooks)
	// These fire on admin-post.php when $_REQUEST['action'] matches
	// Requires login by default since they're in admin context
	adminActionMatches := adminActionPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range adminActionMatches {
		if len(match) < 10 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		fullMatch := content[match[0]:match[1]]
		action := content[match[2]:match[3]]

		// Skip if this is a nopriv variant (handled separately)
		if strings.HasPrefix(action, "nopriv_") {
			continue
		}

		// Skip invalid action names (e.g., WordPress bulk action indicators)
		if action == "-1" || action == "" {
			continue
		}

		// Extract callback
		var callback string
		for i := 4; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		// admin_action_ requires login and is typically admin-level
		authLevel := models.Admin

		// Look for additional auth checks in callback
		callbackBody := findCallbackBody(content, callback)
		if callbackBody != "" {
			inferredLevel := InferAuthLevel(callbackBody)
			if inferredLevel == models.Subscriber {
				// Downgrade to User if callback doesn't have admin capability checks
				authLevel = models.Subscriber
			}
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("admin_action_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 15. Find admin_action_nopriv_* handlers (no login required)
	adminActionNoprivMatches := adminActionNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range adminActionNoprivMatches {
		if len(match) < 10 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		fullMatch := content[match[0]:match[1]]
		action := content[match[2]:match[3]]

		// Extract callback
		var callback string
		for i := 4; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("admin_action_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated, // nopriv means no login required
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 16. Find admin_action_ with dynamic/concatenated action name
	adminActionConcatMatches := adminActionConcatPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range adminActionConcatMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varExpr := strings.TrimSpace(content[match[2]:match[3]])
		callback := strings.TrimSpace(content[match[4]:match[5]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Try to resolve the variable
		action := resolveDynamicAction(varExpr, content)

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("admin_action_" + action),
			Method:     "POST",
			AuthLevel:  models.Admin, // admin context requires login
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 17. Find Heartbeat API handlers (heartbeat_received - requires login by default)
	heartbeatReceivedMatches := heartbeatReceivedPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range heartbeatReceivedMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		fullMatch := content[match[0]:match[1]]

		// Extract callback
		var callback string
		for i := 2; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("heartbeat_received"),
			Method:     "POST",
			AuthLevel:  models.Subscriber, // Heartbeat requires login by default
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 18. Find Heartbeat API nopriv handlers (no login required)
	heartbeatNoprivReceivedMatches := heartbeatNoprivReceivedPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range heartbeatNoprivReceivedMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		fullMatch := content[match[0]:match[1]]

		// Extract callback
		var callback string
		for i := 2; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("heartbeat_nopriv_received"),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated, // nopriv means no login required
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 19. Find Heartbeat send handlers
	heartbeatSendMatches := heartbeatSendPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range heartbeatSendMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		fullMatch := content[match[0]:match[1]]

		// Extract callback
		var callback string
		for i := 2; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("heartbeat_send"),
			Method:     "POST",
			AuthLevel:  models.Subscriber, // Heartbeat requires login by default
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 20. Find Heartbeat nopriv send handlers
	heartbeatNoprivSendMatches := heartbeatNoprivSendPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range heartbeatNoprivSendMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		fullMatch := content[match[0]:match[1]]

		// Extract callback
		var callback string
		for i := 2; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = content[match[i]:match[i+1]]
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("heartbeat_nopriv_send"),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated, // nopriv means no login required
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 21. Find WordPress Plugin Boilerplate loader auth patterns
	// Pattern: $this->loader->add_action( 'wp_ajax_ACTION', $component, 'callback' )
	// Note: Pattern may match nopriv routes too, so we filter them out
	loaderAuthMatches := loaderAjaxAuthPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range loaderAuthMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}

		action := content[match[2]:match[3]]
		// Skip nopriv actions - they're handled by loaderAjaxNoprivPattern
		if strings.HasPrefix(action, "nopriv_") {
			continue
		}

		processedPositions[match[0]] = true
		callback := content[match[4]:match[5]]
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Determine auth level
		authLevel := models.Subscriber
		if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 22. Find WordPress Plugin Boilerplate loader nopriv patterns
	// Pattern: $this->loader->add_action( 'wp_ajax_nopriv_ACTION', $component, 'callback' )
	loaderNoprivMatches := loaderAjaxNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range loaderNoprivMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		action := content[match[2]:match[3]]
		callback := content[match[4]:match[5]]
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_nopriv_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated, // nopriv means no login required
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 23. Find WordPress Plugin Boilerplate loader with concatenated auth patterns
	// Pattern: $this->loader->add_action( 'wp_ajax_' . $prefix . $action, ...)
	loaderConcatAuthMatches := loaderAjaxConcatAuthPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range loaderConcatAuthMatches {
		if len(match) < 4 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varExpr := strings.TrimSpace(content[match[2]:match[3]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Try to resolve the dynamic action
		action := resolveDynamicAction(varExpr, content)

		// Determine auth level
		authLevel := models.Subscriber
		if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   "loader_callback",
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 24. Find WordPress Plugin Boilerplate loader with concatenated nopriv patterns
	loaderConcatNoprivMatches := loaderAjaxConcatNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range loaderConcatNoprivMatches {
		if len(match) < 4 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		varExpr := strings.TrimSpace(content[match[2]:match[3]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Try to resolve the dynamic action
		action := resolveDynamicAction(varExpr, content)

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_nopriv_" + action),
			Method:     "POST",
			AuthLevel:  models.Unauthenticated, // nopriv means no login required
			Callback:   "loader_callback",
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 25. Find framework wrapper patterns: $app->addAction('wp_ajax_[nopriv_]ACTION', ...)
	// This handles DI container / framework patterns used by FluentForm and others
	// Single pattern captures both auth and nopriv - group 1 indicates if nopriv
	frameworkMatches := frameworkAddActionPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range frameworkMatches {
		// Pattern has 3 groups: nopriv indicator, action, callback
		// Indices: 0-1=full, 2-3=nopriv, 4-5=action, 6-7=callback
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		// Check if this is a nopriv action (group 1 matched "nopriv_")
		isNopriv := match[2] >= 0 && match[3] > match[2]

		action := content[match[4]:match[5]]
		callbackRaw := strings.TrimSpace(content[match[6]:match[7]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Extract callback name if possible
		callback := "anonymous"
		if strings.Contains(callbackRaw, "function") {
			callback = "anonymous"
		} else if strings.Contains(callbackRaw, "[") || strings.Contains(callbackRaw, "array") {
			// Try to extract method name from array notation using pre-compiled pattern
			if methodMatch := simpleStringQuotePattern.FindStringSubmatch(callbackRaw); len(methodMatch) >= 2 {
				callback = methodMatch[1]
			}
		}

		// Determine auth level and route prefix
		var authLevel models.AuthLevel
		routePrefix := "wp_ajax_"
		if isNopriv {
			authLevel = models.Unauthenticated
			routePrefix = "wp_ajax_nopriv_"
		} else if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		} else {
			authLevel = models.Subscriber
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute(routePrefix + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 26. Find Elementor AJAX framework patterns
	// Pattern: $ajax_manager->register_ajax_action( 'action_name', [ $this, 'callback' ] )
	// or: $ajax->register_ajax_action( 'action_name', function( $data ) { ... } )
	// These are called via Elementor's AJAX handler and require authentication
	elementorAjaxMatches := elementorAjaxActionPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range elementorAjaxMatches {
		if len(match) < 4 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		action := content[match[2]:match[3]]
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Extract callback - check each group
		callback := "anonymous_function"
		for i := 4; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				cb := content[match[i]:match[i+1]]
				if !strings.HasPrefix(cb, "function") {
					callback = cb
				}
				break
			}
		}

		// Elementor AJAX typically requires user authentication (nonce verified)
		// Default to User level, upgrade to Admin if action name suggests admin
		authLevel := models.Subscriber
		if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("elementor_ajax:" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 27. Find ACF (Advanced Custom Fields) AJAX registration patterns
	// Pattern: acf_register_ajax( 'action_name', 'callback', $public );
	// When $public = true, the action is unauthenticated; otherwise it requires login
	acfAjaxMatches := acfRegisterAjaxPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range acfAjaxMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		action := content[match[2]:match[3]]
		callback := content[match[4]:match[5]]
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Check if $public argument is true (makes it unauthenticated)
		authLevel := models.Subscriber // Default: requires authentication
		if match[6] >= 0 && match[7] > match[6] {
			publicArg := content[match[6]:match[7]]
			if publicArg == "true" {
				authLevel = models.Unauthenticated
			}
		}

		// Upgrade to Admin if action name suggests admin functionality
		if authLevel == models.Subscriber && (isAdminIndicatorAction(action) || isLikelyAdminAction(action)) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("acf_ajax:" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 28. Find Freemius SDK AJAX wrapper patterns
	// Pattern: $this->add_ajax_action( 'tag', [ $this, 'callback' ] )
	// Pattern: Freemius::add_ajax_action_static( 'tag', [ $this, 'callback' ] )
	// These wrap add_action('wp_ajax_' . dynamic_action, $callback) internally
	freemiusAjaxMatches := freemiusAddAjaxActionPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range freemiusAjaxMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		action := content[match[2]:match[3]]
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Extract callback from the first non-empty capture group
		// Groups: 2=string, 3=bracket method, 4=array method, 5=fallback
		var callback string
		for i := 4; i < len(match) && i+1 < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				callback = strings.TrimSpace(content[match[i]:match[i+1]])
				break
			}
		}
		if callback == "" {
			callback = "unknown"
		}

		// Freemius actions require admin authentication by default
		// The action name is prefixed with fs_{module_id}_ at runtime
		authLevel := models.Admin

		// Use the raw action name - Freemius adds its own prefix at runtime
		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_fs_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 29. Find static method wrapper patterns (e.g., Hooks::addAction)
	// Pattern: Hooks::addAction('wp_ajax_ACTION', ClassName::class, 'method')
	// Used by Give plugin and others with a static Hooks helper class
	staticAddActionMatches := staticAddActionPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range staticAddActionMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		// Check if this is a nopriv action (group 1 matched "nopriv_")
		isNopriv := match[2] >= 0 && match[3] > match[2]

		action := content[match[4]:match[5]]
		callbackRaw := strings.TrimSpace(content[match[6]:match[7]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Extract callback name - handle ClassName::class and 'method' args
		callback := extractStaticCallback(callbackRaw)

		// Determine auth level and route prefix
		var authLevel models.AuthLevel
		routePrefix := "wp_ajax_"
		if isNopriv {
			authLevel = models.Unauthenticated
			routePrefix = "wp_ajax_nopriv_"
		} else if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		} else {
			authLevel = models.Subscriber
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute(routePrefix + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// 30. Find generic AJAX wrapper patterns (e.g., $this->endpoints->registerAjaxEndpoint)
	// These are custom wrappers that call add_action('wp_ajax_' . $action) internally
	// Pattern: ->registerAjaxEndpoint('action', callback)
	genericWrapperMatches := genericAjaxWrapperPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range genericWrapperMatches {
		if len(match) < 8 || processedPositions[match[0]] {
			continue
		}
		processedPositions[match[0]] = true

		methodName := content[match[2]:match[3]]
		action := content[match[4]:match[5]]
		callbackRaw := strings.TrimSpace(content[match[6]:match[7]])
		fullMatch := content[match[0]:match[1]]
		lineNum := countLines(content[:match[0]]) + 1

		// Skip if action looks like a hook name we already handle
		if strings.HasPrefix(action, "wp_ajax_") || strings.HasPrefix(action, "wc_ajax_") {
			continue
		}

		// Extract callback
		callback := NormalizeCallback(callbackRaw)

		// registerAjaxEndpoint typically registers wp_ajax_* (authenticated)
		// Default to Subscriber level, upgrade to Admin if action name suggests admin
		authLevel := models.Subscriber
		if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
			authLevel = models.Admin
		}

		// Use method name to determine if this might be a nopriv wrapper
		// (e.g., registerAjaxNoprivEndpoint)
		routePrefix := "wp_ajax_"
		if strings.Contains(strings.ToLower(methodName), "nopriv") {
			authLevel = models.Unauthenticated
			routePrefix = "wp_ajax_nopriv_"
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute(routePrefix + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   callback,
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		endpoints = append(endpoints, ep)
	}

	// Correlate endpoints - some actions have both wp_ajax_ and wp_ajax_nopriv_
	endpoints = correlateAJAXEndpoints(endpoints)

	return endpoints
}

// resolveDynamicAction attempts to resolve a dynamic action variable to a literal value
func resolveDynamicAction(varExpr string, content string) string {
	varExpr = strings.TrimSpace(varExpr)

	// Handle string literals
	if strings.HasPrefix(varExpr, "'") || strings.HasPrefix(varExpr, "\"") {
		return strings.Trim(varExpr, "'\"")
	}

	// Handle $this->property
	if strings.HasPrefix(varExpr, "$this->") {
		propName := strings.TrimPrefix(varExpr, "$this->")
		// Look for property assignment
		propPattern := regexp.MustCompile(`\$this\s*->\s*` + regexp.QuoteMeta(propName) + `\s*=\s*['"]([^'"]+)['"]`)
		if match := propPattern.FindStringSubmatch(content); len(match) > 1 {
			return match[1]
		}
		// Return property name as fallback
		return "{" + propName + "}"
	}

	// Handle simple $variable
	if strings.HasPrefix(varExpr, "$") {
		varName := strings.TrimPrefix(varExpr, "$")
		// Look for variable assignment
		varPattern := regexp.MustCompile(`\$` + regexp.QuoteMeta(varName) + `\s*=\s*['"]([^'"]+)['"]`)
		if match := varPattern.FindStringSubmatch(content); len(match) > 1 {
			return match[1]
		}
		// Return variable name as fallback
		return "{" + varName + "}"
	}

	// Handle self::CONST or static::CONST
	if strings.Contains(varExpr, "::") {
		parts := strings.Split(varExpr, "::")
		if len(parts) == 2 {
			constName := strings.TrimSpace(parts[1])
			// Look for constant definition
			constPattern := regexp.MustCompile(`const\s+` + regexp.QuoteMeta(constName) + `\s*=\s*['"]([^'"]+)['"]`)
			if match := constPattern.FindStringSubmatch(content); len(match) > 1 {
				return match[1]
			}
			return "{" + constName + "}"
		}
	}

	// Return as-is if can't resolve
	return strings.Trim(varExpr, "'\"$")
}

// parseAJAXMatch parses a regex match into an Endpoint
func parseAJAXMatch(content string, match []int, filepath, pluginSlug string, isNopriv bool) *models.Endpoint {
	if len(match) < 10 {
		return nil
	}

	fullMatch := content[match[0]:match[1]]
	action := content[match[2]:match[3]]

	// Extract callback - can be in different positions depending on notation
	var callback string
	for i := 4; i < len(match); i += 2 {
		if match[i] >= 0 && match[i+1] >= 0 {
			callback = content[match[i]:match[i+1]]
			break
		}
	}

	if callback == "" {
		callback = "unknown"
	}

	// Calculate line number
	lineNum := countLines(content[:match[0]]) + 1

	// Determine auth level
	authLevel := models.Subscriber // Default for wp_ajax_ (requires login)
	if isNopriv {
		// wp_ajax_nopriv_* means the endpoint is registered for unauthenticated access.
		// However, the callback function itself may contain auth checks like
		// current_user_can(), is_user_logged_in(), wp_verify_nonce(), etc.
		// Check the callback body for auth patterns (W7 fix).
		authLevel = models.Unauthenticated

		// Check callback body for internal auth checks
		enhancedAuth := InferAuthLevelFromCallback(callback, content, nil)
		if enhancedAuth > models.Unauthenticated {
			authLevel = enhancedAuth
		}
	}

	// Look for additional auth checks in the callback function if we can find it
	// This is a best-effort analysis - ONLY for authenticated endpoints
	if !isNopriv {
		callbackBody := findCallbackBody(content, callback)
		if callbackBody != "" {
			inferredLevel := InferAuthLevel(callbackBody)
			// Only upgrade auth level, never downgrade
			if inferredLevel > authLevel {
				authLevel = inferredLevel
			}
		}

		// For authenticated actions (not nopriv), apply heuristics to detect admin-level actions
		// These heuristics help when capability checks are not easily detectable
		if authLevel == models.Subscriber {
			// Strong indicators in action name
			if isAdminIndicatorAction(action) {
				authLevel = models.Admin
			} else if isLikelyAdminAction(action) {
				// Use aggressive heuristics as fallback
				authLevel = models.Admin
			}
		}
	}

	// Build the route with proper prefix
	route := "wp_ajax_"
	if isNopriv {
		route = "wp_ajax_nopriv_"
	}

	return &models.Endpoint{
		PluginSlug: pluginSlug,
		Type:       models.EndpointTypeAJAX,
		Route:      formatAjaxRoute(route + action),
		Method:     "POST", // AJAX typically uses POST
		AuthLevel:  authLevel,
		Callback:   NormalizeCallback(callback),
		File:       filepath,
		Line:       lineNum,
		RawCode:    truncateCode(fullMatch, 500),
	}
}

// extractAnonFunctionBody extracts the body of an anonymous function starting from a position
// This handles balanced brace counting to find the complete function body
func extractAnonFunctionBody(content string, startPos int) string {
	// Find the opening brace of the function body
	braceStart := strings.Index(content[startPos:], "{")
	if braceStart < 0 {
		return ""
	}
	braceStart += startPos

	// Count balanced braces to find the end
	depth := 1
	pos := braceStart + 1
	inString := false
	stringChar := byte(0)

	for pos < len(content) && depth > 0 {
		ch := content[pos]

		// Handle string literals
		if !inString && (ch == '"' || ch == '\'') {
			inString = true
			stringChar = ch
		} else if inString && ch == stringChar {
			// Check for escape
			escapeCount := 0
			for i := pos - 1; i >= 0 && content[i] == '\\'; i-- {
				escapeCount++
			}
			if escapeCount%2 == 0 {
				inString = false
			}
		} else if !inString {
			if ch == '{' {
				depth++
			} else if ch == '}' {
				depth--
			}
		}
		pos++
	}

	if depth != 0 {
		// Couldn't find balanced braces, return partial body
		endPos := braceStart + 1000
		if endPos > len(content) {
			endPos = len(content)
		}
		return content[braceStart:endPos]
	}

	return content[braceStart:pos]
}

// findCallbackBody attempts to find the body of a callback function
func findCallbackBody(content, callback string) string {
	// Extract function name from callback
	funcName := extractFunctionName(callback)
	if funcName == "" {
		return ""
	}

	// Try to find the function definition
	patterns := []*regexp.Regexp{
		// Regular function
		regexp.MustCompile(`function\s+` + regexp.QuoteMeta(funcName) + `\s*\([^)]*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}`),
		// Method in class
		regexp.MustCompile(`(?:public|private|protected)?\s*function\s+` + regexp.QuoteMeta(funcName) + `\s*\([^)]*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}`),
	}

	for _, re := range patterns {
		matches := re.FindStringSubmatch(content)
		if len(matches) >= 2 {
			return matches[1]
		}
	}

	return ""
}

// extractFunctionName extracts just the function name from callback notation
func extractFunctionName(callback string) string {
	callback = strings.TrimSpace(callback)

	// Handle array notation using pre-compiled package-level pattern
	matches := ajaxArrayNotationPattern.FindStringSubmatch(callback)
	if len(matches) >= 2 {
		return matches[1]
	}

	// Handle string function name (including Class::method notation)
	if !strings.Contains(callback, "[") && !strings.Contains(callback, "array") {
		result := strings.Trim(callback, "'\"")
		// Handle Class::method notation - extract just the method name
		if strings.Contains(result, "::") {
			parts := strings.Split(result, "::")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[len(parts)-1])
			}
		}
		return result
	}

	return ""
}

// extractStaticCallback extracts callback from static wrapper patterns
// Handles: ClassName::class, 'method' or ClassName::class
func extractStaticCallback(callbackRaw string) string {
	callbackRaw = strings.TrimSpace(callbackRaw)

	// Handle ClassName::class pattern (optionally followed by method)
	if strings.Contains(callbackRaw, "::class") {
		// Extract the class name
		parts := strings.Split(callbackRaw, "::class")
		className := strings.TrimSpace(parts[0])
		// Remove any namespace prefix, just keep class name
		if idx := strings.LastIndex(className, "\\"); idx >= 0 {
			className = className[idx+1:]
		}

		// Check if there's a method argument after the class
		if len(parts) > 1 {
			rest := strings.TrimSpace(parts[1])
			// Look for , 'methodName' pattern
			if strings.HasPrefix(rest, ",") {
				methodPart := strings.TrimPrefix(rest, ",")
				methodPart = strings.TrimSpace(methodPart)
				// Extract quoted method name
				if match := simpleStringQuotePattern.FindStringSubmatch(methodPart); len(match) >= 2 {
					return className + "::" + match[1]
				}
			}
		}
		// Default to __invoke for class-only callbacks
		return className + "::__invoke"
	}

	// Handle array callbacks
	if match := simpleStringQuotePattern.FindStringSubmatch(callbackRaw); len(match) >= 2 {
		return match[1]
	}

	return strings.Trim(callbackRaw, "'\"")
}

// correlateAJAXEndpoints marks endpoints that have both auth and nopriv versions
func correlateAJAXEndpoints(endpoints []models.Endpoint) []models.Endpoint {
	// Build map of nopriv actions (extract just the action name)
	// Route format: "wp_ajax_nopriv_ACTION" -> extract "ACTION"
	noprivActions := make(map[string]bool)
	for _, ep := range endpoints {
		if ep.AuthLevel == models.Unauthenticated {
			// Extract action name from route (strip wp_ajax_nopriv_ or wp_ajax_)
			action := ep.Route
			action = strings.TrimPrefix(action, "wp_ajax_nopriv_")
			action = strings.TrimPrefix(action, "wp_ajax_")
			if action != "" {
				noprivActions[action] = true
			}
		}
	}

	// Downgrade auth endpoints that also have nopriv versions to Unauthenticated
	// If an action has both wp_ajax_ and wp_ajax_nopriv_, it means anyone can access it
	// So the effective auth level is Unauthenticated
	for i := range endpoints {
		if endpoints[i].AuthLevel == models.Subscriber || endpoints[i].AuthLevel == models.Admin {
			// Extract action name from auth route (strip wp_ajax_)
			action := strings.TrimPrefix(endpoints[i].Route, "wp_ajax_")
			if noprivActions[action] {
				// This action is accessible without auth via nopriv variant
				// Downgrade to Unauthenticated
				endpoints[i].AuthLevel = models.Unauthenticated
				endpoints[i].RawCode += " [downgraded: has nopriv variant]"
			}
		}
	}

	return endpoints
}

// isAdminIndicatorAction checks if an AJAX action name indicates admin-level functionality
// Based on common naming conventions in WordPress plugins
func isAdminIndicatorAction(action string) bool {
	action = strings.ToLower(action)
	normalizedAction := strings.ReplaceAll(action, "-", "_")

	// Get configuration
	cfg := getAJAXConfig()

	// ============================================
	// WORDPRESS CORE PATTERNS (always active)
	// Strong admin indicators - prefixes that almost always mean admin
	// ============================================
	coreAdminPrefixes := []string{
		"admin_",
		"manage_options",
		"manage_",
	}

	for _, prefix := range coreAdminPrefixes {
		if strings.HasPrefix(normalizedAction, prefix) {
			return true
		}
	}

	// ============================================
	// ADMIN INDICATOR KEYWORDS (from config or defaults)
	// ============================================
	var adminKeywords []string
	if cfg != nil && cfg.AJAX != nil && len(cfg.AJAX.AdminIndicatorKeywords) > 0 {
		adminKeywords = cfg.AJAX.AdminIndicatorKeywords
	} else {
		// Default keywords (backwards compatibility)
		adminKeywords = []string{
			"_admin_", "_admin", "_notice_dismiss", "_dismiss_notice",
			"_settings_save", "_save_settings", "_update_settings",
			"_options_save", "_save_options", "_install_plugin",
			"_activate_plugin", "_deactivate_plugin", "_delete_plugin",
			"_rollback", "_reset_settings", "_reset_options",
			"_import_settings", "_export_settings", "_license_",
			"_onboard", "_wizard", "_migration", "_conflicting_plugin",
		}
	}

	for _, keyword := range adminKeywords {
		if strings.Contains(normalizedAction, keyword) {
			return true
		}
	}

	// ============================================
	// CUSTOM ADMIN PREFIXES (configurable)
	// Users can add their own prefixes via configuration.
	// By default, no custom prefixes are assumed.
	// ============================================
	if cfg != nil && cfg.AJAX != nil && len(cfg.AJAX.CustomAdminPrefixes) > 0 {
		for _, prefix := range cfg.AJAX.CustomAdminPrefixes {
			if strings.HasPrefix(normalizedAction, prefix) {
				return true
			}
		}
	}

	// ============================================
	// ADDITIONAL ADMIN KEYWORDS (with user-facing exceptions)
	// ============================================
	additionalKeywords := []string{
		"_search", "_list", "_log", "_query", "_panel",
		"_page", "_view", "_insight", "_statistic", "_report",
		"_check", "_hide", "_enable", "_disable", "_toggle",
	}

	for _, keyword := range additionalKeywords {
		if strings.Contains(normalizedAction, keyword) {
			// Exception for user-facing patterns
			if !isUserFacingException(normalizedAction) {
				return true
			}
		}
	}

	return false
}

// isLikelyAdminAction is a more aggressive heuristic for likely admin actions
// Used as a fallback when other methods don't detect admin requirements
func isLikelyAdminAction(action string) bool {
	action = strings.ToLower(action)
	normalized := strings.ReplaceAll(action, "-", "_")

	// Common patterns that indicate admin functionality
	likelyAdminPatterns := []string{
		// Settings and configuration
		"save_",
		"_save",
		"update_",
		"_update",
		"edit_",
		"_edit",
		"delete_",
		"_delete",
		"remove_",
		"_remove",
		"create_",
		"_create",
		"new_",
		"_new",
		"add_",

		// Plugin lifecycle
		"install_",
		"_install",
		"uninstall",
		"activate",
		"deactivate",
		"upgrade",
		"downgrade",
		"migrate",
		"reset_",
		"_reset",
		"clear_",
		"_clear",
		"purge_",
		"_purge",
		"flush_",
		"_flush",

		// Admin actions
		"dismiss",
		"notice",
		"review",
		"feedback",
		"survey",
		"promo",
		"banner",
		"notification",
		"widget",
		"metabox",
		"dashboard",
		"screen_options",

		// Configuration
		"config",
		"setting",
		"option",
		"preference",
		"setup",
		"wizard",
		"onboard",

		// Data management
		"import",
		"export",
		"backup",
		"restore",
		"sync",
		"generate",
		"regenerate",
		"build",
		"rebuild",
		"scan",
		"audit",
		"log",
		"debug",

		// Plugin operations
		"license",
		"api_key",
		"apikey",
		"token",
		"connect",
		"disconnect",
		"authorize",
		"authenticate",
	}

	for _, pattern := range likelyAdminPatterns {
		if strings.Contains(normalized, pattern) {
			// Exception: some patterns are also used in user-facing features
			if isUserFacingException(normalized) {
				return false
			}
			return true
		}
	}

	return false
}

// isUserFacingException returns true if the action name indicates a user-facing feature
func isUserFacingException(action string) bool {
	// Get configuration
	cfg := getAJAXConfig()

	var userFacingPatterns []string
	if cfg != nil && cfg.AJAX != nil && len(cfg.AJAX.UserFacingExceptions) > 0 {
		userFacingPatterns = cfg.AJAX.UserFacingExceptions
	} else {
		// Default patterns (backwards compatibility)
		userFacingPatterns = []string{
			"form", "submit", "entry",
			"cart", "checkout", "order", "product", "shop", "store", "payment", "shipping",
			"profile", "account", "comment", "reply", "message", "contact", "post",
			"subscribe", "newsletter",
			"register", "login", "password",
			"bookmark", "favorite", "wishlist", "follow",
			"rating", "vote", "like", "share",
			"search", "filter", "sort", "load_more", "loadmore",
			"quick_view", "quickview", "preview",
			"popup", "modal", "slider",
			"booking", "appointment", "reservation", "calendar", "event",
		}
	}

	for _, pattern := range userFacingPatterns {
		if strings.Contains(action, pattern) {
			return true
		}
	}

	return false
}

// DetectDirectAJAXHandlers finds AJAX handlers that check for specific actions
// These are patterns like: if($_POST['action'] == 'my_action')
func DetectDirectAJAXHandlers(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Use pre-compiled package-level patterns
	patterns := []*regexp.Regexp{
		ajaxDirectHandlerPattern1,
		ajaxDirectHandlerPattern2,
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			if len(match) < 6 {
				continue
			}

			fullMatch := content[match[0]:match[1]]
			var action string
			// Depending on pattern, action might be in different capture group
			if content[match[2]:match[3]] == "POST" ||
				content[match[2]:match[3]] == "GET" ||
				content[match[2]:match[3]] == "REQUEST" {
				action = content[match[4]:match[5]]
			} else {
				action = content[match[2]:match[3]]
			}

			// Skip invalid action names (e.g., WordPress bulk action indicators)
			if action == "-1" || action == "" || action == "false" || action == "0" {
				continue
			}

			lineNum := countLines(content[:match[0]]) + 1

			// These are typically unauthenticated since they're manual checks
			// Look for auth checks nearby
			contextStart := match[0] - 500
			if contextStart < 0 {
				contextStart = 0
			}
			contextEnd := match[1] + 500
			if contextEnd > len(content) {
				contextEnd = len(content)
			}
			context := content[contextStart:contextEnd]

			authLevel := InferAuthLevel(context)

			// Apply admin heuristics if not already admin level
			if authLevel != models.Admin {
				if isAdminIndicatorAction(action) || isLikelyAdminAction(action) {
					authLevel = models.Admin
				}
			}

			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeAJAX,
				Route:      formatAjaxRoute("direct_ajax_" + action),
				Method:     "POST",
				AuthLevel:  authLevel,
				Callback:   "inline",
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode(fullMatch, 300),
			}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// DetectForeachLoopAJAXHandlers finds AJAX handlers registered via foreach loops over arrays
// This is a common pattern in WordPress plugins like WooCommerce:
//
//	$ajax_events = array('action1', 'action2', ...);
//	foreach ($ajax_events as $ajax_event) {
//	    add_action('wp_ajax_' . $prefix . $ajax_event, ...);
//	}
func DetectForeachLoopAJAXHandlers(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Search for the WooCommerce-style pattern
	// where an array of action names is defined, then a foreach loop registers them
	endpoints = append(endpoints, detectWooCommerceStyleAJAX(content, filepath, pluginSlug)...)

	// Search for inline array foreach patterns (used by Wordfence and many other plugins)
	// foreach(array('action1', 'action2', ...) as $func) { add_action('wp_ajax_prefix_' . $func, ...); }
	endpoints = append(endpoints, detectInlineArrayForeachAJAX(content, filepath, pluginSlug)...)

	return endpoints
}

// detectWooCommerceStyleAJAX handles the specific pattern used by WooCommerce and similar plugins
// where an array of action names is defined, then a foreach loop registers them
func detectWooCommerceStyleAJAX(content, filepath, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Find array definitions with action-like variable names
	// Pattern: $ajax_events = array('get_refreshed_fragments', 'apply_coupon', ...)
	arrayDefPattern := regexp.MustCompile(
		`\$([a-zA-Z_]*(?:ajax|events|actions|handlers)[a-zA-Z_]*)\s*=\s*(?:array\s*\(|\[)([^)\]]+)(?:\)|\])`,
	)

	// Find all array definitions
	arrayMatches := arrayDefPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range arrayMatches {
		if len(match) < 6 {
			continue
		}

		varName := content[match[2]:match[3]]
		arrayContent := content[match[4]:match[5]]
		arrayEndPos := match[1]

		// Extract action names from array using pre-compiled pattern
		actionMatches := actionNamePattern.FindAllStringSubmatch(arrayContent, -1)

		if len(actionMatches) == 0 {
			continue
		}

		// Look for foreach using this array in the next ~2000 chars
		searchEnd := arrayEndPos + 2000
		if searchEnd > len(content) {
			searchEnd = len(content)
		}
		afterArray := content[arrayEndPos:searchEnd]

		// Check for foreach pattern: foreach ($varName as $loopVar) or foreach ($varName as $key => $value)
		// Pattern 1: Simple iteration - foreach ($array as $item)
		foreachSimplePattern := regexp.MustCompile(
			`foreach\s*\(\s*\$` + regexp.QuoteMeta(varName) + `\s+as\s+\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\)`,
		)
		// Pattern 2: Associative iteration - foreach ($array as $key => $value)
		foreachAssocPattern := regexp.MustCompile(
			`foreach\s*\(\s*\$` + regexp.QuoteMeta(varName) + `\s+as\s+\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=>\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)`,
		)

		loopVar := ""
		foreachMatch := foreachSimplePattern.FindStringSubmatch(afterArray)
		if foreachMatch != nil && len(foreachMatch) >= 2 {
			loopVar = foreachMatch[1]
		} else {
			foreachMatch = foreachAssocPattern.FindStringSubmatch(afterArray)
			if foreachMatch != nil && len(foreachMatch) >= 2 {
				loopVar = foreachMatch[1] // In associative pattern, the key is the action name
			}
		}

		if loopVar == "" {
			continue
		}

		// Now look for add_action using the loop variable
		// Pattern: add_action('wp_ajax_' . 'prefix_' . $loopVar, ...) or add_action('wp_ajax_prefix_' . $loopVar, ...)
		addActionPattern := regexp.MustCompile(
			`add_action\s*\(\s*['"]wp_ajax_([a-zA-Z_]*)['"]\s*\.\s*\$` + regexp.QuoteMeta(loopVar),
		)

		addActionNoprivPattern := regexp.MustCompile(
			`add_action\s*\(\s*['"]wp_ajax_nopriv_([a-zA-Z_]*)['"]\s*\.\s*\$` + regexp.QuoteMeta(loopVar),
		)

		// Check for auth pattern
		authMatch := addActionPattern.FindStringSubmatch(afterArray)
		noprivMatch := addActionNoprivPattern.FindStringSubmatch(afterArray)

		if authMatch == nil && noprivMatch == nil {
			continue
		}

		// Determine prefix
		prefix := ""
		if authMatch != nil && len(authMatch) >= 2 {
			prefix = authMatch[1]
		} else if noprivMatch != nil && len(noprivMatch) >= 2 {
			prefix = noprivMatch[1]
		}

		// Determine auth level based on presence of nopriv
		isNopriv := noprivMatch != nil

		lineNum := countLines(content[:match[0]]) + 1

		// Create endpoints for each action
		for _, actionM := range actionMatches {
			if len(actionM) < 2 {
				continue
			}

			action := actionM[1]
			fullAction := prefix + action

			authLevel := models.Subscriber
			routePrefix := "wp_ajax_"
			if isNopriv {
				authLevel = models.Unauthenticated
				routePrefix = "wp_ajax_nopriv_"
			} else if isAdminIndicatorAction(fullAction) || isLikelyAdminAction(fullAction) {
				authLevel = models.Admin
			}

			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeAJAX,
				Route:      formatAjaxRoute(routePrefix + fullAction),
				Method:     "POST",
				AuthLevel:  authLevel,
				Callback:   action,
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode("$"+varName+" array iteration: "+action, 300),
			}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// detectInlineArrayForeachAJAX handles the pattern where an inline array is used directly in a foreach
// This is common in plugins like Wordfence:
//
//	foreach(array('action1', 'action2', ...) as $func) {
//	    add_action('wp_ajax_prefix_' . $func, 'callback');
//	}
func detectInlineArrayForeachAJAX(content, filepath, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Pattern to match: foreach(array('item1', 'item2', ...) as $loopVar)
	// or foreach(['item1', 'item2', ...] as $loopVar)
	foreachInlineArrayPattern := regexp.MustCompile(
		`foreach\s*\(\s*(?:array\s*\(|\[)\s*` +
			`((?:['"][a-zA-Z_][a-zA-Z0-9_]*['"]` +
			`(?:\s*,\s*['"][a-zA-Z_][a-zA-Z0-9_]*['"])*\s*,?\s*)+)` +
			`(?:\)|\])\s*as\s*\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\)`,
	)

	foreachMatches := foreachInlineArrayPattern.FindAllStringSubmatchIndex(content, -1)

	for _, match := range foreachMatches {
		if len(match) < 6 {
			continue
		}

		arrayContent := content[match[2]:match[3]]
		loopVar := content[match[4]:match[5]]
		foreachEndPos := match[1]
		lineNum := countLines(content[:match[0]]) + 1

		// Extract action names from the inline array using pre-compiled pattern
		actionMatches := actionNamePattern.FindAllStringSubmatch(arrayContent, -1)

		if len(actionMatches) == 0 {
			continue
		}

		// Look for add_action in the foreach body (within next ~500 chars)
		searchEnd := foreachEndPos + 500
		if searchEnd > len(content) {
			searchEnd = len(content)
		}
		foreachBody := content[foreachEndPos:searchEnd]

		// Pattern: add_action('wp_ajax_prefix_' . $loopVar, ...)
		// The prefix might be a literal string like 'wp_ajax_wordfence_'
		addActionPrefixPattern := regexp.MustCompile(
			`add_action\s*\(\s*['"]wp_ajax_([a-zA-Z0-9_]*)['"]\s*\.\s*\$` + regexp.QuoteMeta(loopVar) + `\s*,\s*([^,)]+)`,
		)

		addActionNoprivPrefixPattern := regexp.MustCompile(
			`add_action\s*\(\s*['"]wp_ajax_nopriv_([a-zA-Z0-9_]*)['"]\s*\.\s*\$` + regexp.QuoteMeta(loopVar) + `\s*,\s*([^,)]+)`,
		)

		authMatch := addActionPrefixPattern.FindStringSubmatch(foreachBody)
		noprivMatch := addActionNoprivPrefixPattern.FindStringSubmatch(foreachBody)

		if authMatch == nil && noprivMatch == nil {
			continue
		}

		// Determine prefix and callback
		prefix := ""
		callback := "unknown"
		isNopriv := false

		if authMatch != nil {
			prefix = authMatch[1]
			callback = strings.TrimSpace(authMatch[2])
		}
		if noprivMatch != nil {
			isNopriv = true
			if prefix == "" {
				prefix = noprivMatch[1]
				callback = strings.TrimSpace(noprivMatch[2])
			}
		}

		// Analyze callback body for auth patterns (e.g., wfUtils::isAdmin())
		// This is crucial for plugins like Wordfence that check admin in the callback
		callbackAuthLevel := models.Subscriber
		if callback != "" && callback != "unknown" {
			// Extract function name from callback (handle Class::method notation)
			funcName := extractFunctionName(callback)
			if funcName == "" {
				// Try direct extraction for simple callbacks like 'wordfence::ajaxReceiver'
				parts := strings.Split(callback, "::")
				if len(parts) >= 2 {
					funcName = strings.Trim(parts[len(parts)-1], "'\" \t")
				}
			}
			if funcName != "" {
				// Use the more robust findFunctionBody from auth.go
				callbackBody := findFunctionBody(funcName, content)
				if callbackBody != "" {
					inferredLevel := InferAuthLevel(callbackBody)
					if inferredLevel > callbackAuthLevel {
						callbackAuthLevel = inferredLevel
					}
				}
			}
		}

		// Create endpoints for each action in the array
		for _, actionM := range actionMatches {
			if len(actionM) < 2 {
				continue
			}

			action := actionM[1]
			fullAction := prefix + action

			// Determine auth level and route prefix
			authLevel := callbackAuthLevel // Start with callback-inferred level
			routePrefix := "wp_ajax_"
			if isNopriv {
				authLevel = models.Unauthenticated
				routePrefix = "wp_ajax_nopriv_"
			} else if isAdminIndicatorAction(fullAction) || isLikelyAdminAction(fullAction) {
				authLevel = models.Admin
			}

			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeAJAX,
				Route:      formatAjaxRoute(routePrefix + fullAction),
				Method:     "POST",
				AuthLevel:  authLevel,
				Callback:   NormalizeCallback(callback),
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode("inline foreach array: "+action, 300),
			}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// DetectAJAXEndpointsWithAST wraps DetectAJAXEndpoints with AST-backed cross-file analysis.
// Finds WP_Background_Process / WP_Async_Request subclasses that auto-register AJAX hooks.
func DetectAJAXEndpointsWithAST(content, filepath string, pluginSlug string, astCtx *wpast.ASTContext) []models.Endpoint {
	endpoints := DetectAJAXEndpoints(content, filepath, pluginSlug)

	if astCtx == nil || !astCtx.Available {
		return endpoints
	}

	bgSubclasses := astCtx.Resolver.GetSubclasses("WP_Background_Process")
	bgSubclasses = append(bgSubclasses, astCtx.Resolver.GetSubclasses("WP_Async_Request")...)

	for _, classFQN := range bgSubclasses {
		actionVal, ok := astCtx.Resolver.ResolveProperty(classFQN, "action")
		if !ok || actionVal == "" {
			continue
		}

		route := "wp_ajax_nopriv_" + actionVal
		alreadyFound := false
		for _, ep := range endpoints {
			if ep.Route == route {
				alreadyFound = true
				break
			}
		}
		if alreadyFound {
			continue
		}

		endpoints = append(endpoints, models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      route,
			Method:     "POST",
			AuthLevel:  models.Unauthenticated,
			Callback:   classFQN + "::handle",
			File:       filepath,
			RawCode:    "[AST:WP_Background_Process subclass]",
		})
	}

	return endpoints
}

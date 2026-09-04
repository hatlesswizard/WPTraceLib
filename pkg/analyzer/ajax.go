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

// hookIsAnonymousDispatch reports whether WordPress core itself runs a handler
// registered on this hook for a request that carries no authentication cookie.
//
// Three hook families qualify, and each is a core routing decision taken before
// any plugin code runs:
//
//   - wp-admin/admin-ajax.php: if ( is_user_logged_in() ) do_action( 'wp_ajax_' . $action );
//     else do_action( 'wp_ajax_nopriv_' . $action );
//   - wp-admin/admin-post.php makes the same split between admin_post_ and
//     admin_post_nopriv_.
//   - heartbeat_nopriv_received and heartbeat_nopriv_send are fired by core's own
//     wp_ajax_nopriv_heartbeat handler, i.e. from the anonymous arm above.
//
// A plugin that writes add_action('wp_ajax_nopriv_X', $cb) has therefore, by
// core routing, made $cb reachable by an anonymous HTTP request, and no property
// of $cb's body can change which hook core fires. What a body check can
// establish is that the handler returns early for some callers; that is a
// property of the handler, not of reachability, and reporting it as privilege
// makes an attacker-reachable vulnerability look gated.
//
// admin_action_nopriv_ is deliberately absent. WordPress defines no such hook:
// wp-admin/admin.php fires admin_action_{$action} after auth_redirect() and
// there is no anonymous counterpart anywhere in core, so a registration on that
// name is a hook nothing ever fires rather than a dispatch fact (measured: zero
// occurrences across the 143 plugin trees). The third-party dispatchers
// (wc_ajax_, woocommerce_api_, acf_ajax:, elementor_ajax:) are absent for the
// same reason: what they route is decided by a plugin, not by core, so the
// levels this file gives them stay inferences and remain liftable.
func hookIsAnonymousDispatch(hook string) bool {
	return strings.HasPrefix(hook, "wp_ajax_nopriv_") ||
		strings.HasPrefix(hook, "admin_post_nopriv_") ||
		strings.HasPrefix(hook, "heartbeat_nopriv_")
}

// ajaxEndpointList accumulates the endpoints DetectAJAXEndpoints emits together
// with the hook family each registration used.
//
// Carrying the hook alongside the endpoint is what lets the dispatch fact above
// be a floor rather than a starting guess. It used to be a default that the very
// next statement could overwrite -- parseAJAXMatch set Unauthenticated for a
// nopriv registration and then raised it again from the callback body -- and
// because the one repair step that took a minimum across the priv/nopriv twin
// identified the anonymous half by its LEVEL, a single raised endpoint also
// stopped its twin from being downgraded. Keeping the registration itself means
// neither of those can happen again.
type ajaxEndpointList struct {
	eps   []models.Endpoint
	hooks []string
}

// add records an endpoint together with the hook family it was registered on.
func (l *ajaxEndpointList) add(ep models.Endpoint, hook string) {
	l.eps = append(l.eps, ep)
	l.hooks = append(l.hooks, hook)
}

// correlateTwins downgrades a privileged registration whose action is ALSO
// registered on the anonymous half of the same core dispatcher. formatAjaxRoute
// maps both halves onto one URL, which is what makes the two comparable.
//
// The downgrade is a claim about a CALLBACK, not about an action name: core
// routes the anonymous request to whatever the nopriv registration bound, and
// that need not be what the privileged one bound. A plugin can point the nopriv
// half at a stub that only says "log in first" while the privileged half does
// the real work: measured over the 143-tree corpus, 29 actions in 10 trees bind
// provably different handlers on the two halves. So the twin is followed only
// when the two registrations cannot be shown to bind different handlers.
func (l *ajaxEndpointList) correlateTwins() {
	anonHandlers := make(map[string][]string)
	for i := range l.eps {
		if hookIsAnonymousDispatch(l.hooks[i]) {
			anonHandlers[l.eps[i].Route] = append(anonHandlers[l.eps[i].Route], l.eps[i].Callback)
		}
	}
	if len(anonHandlers) == 0 {
		return
	}

	for i := range l.eps {
		if l.eps[i].AuthLevel == models.Unauthenticated || hookIsAnonymousDispatch(l.hooks[i]) {
			continue
		}
		for _, anonCallback := range anonHandlers[l.eps[i].Route] {
			if handlersProvablyDiffer(l.eps[i].Callback, anonCallback) {
				continue
			}
			l.eps[i].AuthLevel = models.Unauthenticated
			l.eps[i].RawCode += " [downgraded: has nopriv variant]"
			break
		}
	}
}

// enforceAnonymousDispatchFloor clamps every endpoint whose registration core
// routes to anonymous callers back down to Unauthenticated.
//
// After the callback-body raise was removed from parseAJAXMatch nothing in this
// file raises such an endpoint any more, so this pass is normally a no-op. It
// exists so that the invariant is checked in one place rather than depended on
// at thirty emission sites.
func (l *ajaxEndpointList) enforceAnonymousDispatchFloor() {
	for i := range l.eps {
		if hookIsAnonymousDispatch(l.hooks[i]) && l.eps[i].AuthLevel > models.Unauthenticated {
			l.eps[i].AuthLevel = models.Unauthenticated
			l.eps[i].RawCode += " [floor: core dispatches " + l.hooks[i] + " to anonymous callers]"
		}
	}
}

// handlersProvablyDiffer reports whether two callback strings are known to name
// different handlers.
//
// It answers "no" whenever the answer is not certain. An unresolved expression
// or a sentinel such as "unknown" names nothing that can be compared, and
// treating those as different would re-introduce exactly the over-restriction
// the twin correlation exists to remove. Only the method tail is compared:
// two detectors can spell one method as "handle" and as "this::handle", and PHP
// method names are case-insensitive.
func handlersProvablyDiffer(a, b string) bool {
	nameA, okA := comparableHandlerName(a)
	nameB, okB := comparableHandlerName(b)
	if !okA || !okB {
		return false
	}
	return nameA != nameB
}

// comparableHandlerName reduces a callback to the handler name that can be
// compared with another, reporting false when there is no such name.
func comparableHandlerName(callback string) (string, bool) {
	callback = strings.TrimSpace(callback)
	if idx := strings.LastIndex(callback, "::"); idx >= 0 {
		callback = callback[idx+2:]
	}
	callback = strings.ToLower(strings.TrimSpace(callback))
	if callback == "" {
		return "", false
	}
	switch callback {
	case "unknown", "inline", "closure", "anonymous", "anonymous_function",
		"loader_callback", "array_callback", "callback":
		return "", false
	}
	// Anything still carrying PHP syntax is an expression, not a name.
	if strings.ContainsAny(callback, "${}()[]'\", \t.") {
		return "", false
	}
	return callback, true
}

// DetectAJAXEndpoints finds all AJAX endpoints in PHP code
func DetectAJAXEndpoints(content, filepath string, pluginSlug string) []models.Endpoint {
	// Pre-allocate with estimated capacity to reduce slice growth allocations
	out := ajaxEndpointList{}
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
			out.add(*ep, "wp_ajax_")
		}
	}

	// 2. Find unauthenticated AJAX endpoints (wp_ajax_nopriv_*) - literal strings
	noprivMatches := AJAXNoprivPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range noprivMatches {
		processedPositions[match[0]] = true
		ep := parseAJAXMatch(content, match, filepath, pluginSlug, true)
		if ep != nil {
			out.add(*ep, "wp_ajax_nopriv_")
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
		if isAdminIndicatorAction(action) {
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
		}
		out.add(ep, "wp_ajax_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
		}
		out.add(ep, "wp_ajax_nopriv_")
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
		if isAdminIndicatorAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "wp_ajax_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "wp_ajax_nopriv_")
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
		if isAdminIndicatorAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "wp_ajax_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "wp_ajax_nopriv_")
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
		if isAdminIndicatorAction(action) {
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
		}
		out.add(ep, "wp_ajax_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    rawCode,
		}
		out.add(ep, "wp_ajax_nopriv_")
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

		// Apply admin heuristics.
		//
		// isLikelyAdminAction is deliberately NOT consulted. It matches English
		// verbs and nouns that occur in most action names -- save_, add_,
		// edit_, delete_, dismiss, review, notice, option, setting, widget --
		// and promoted 818 of 3478 logged-in AJAX endpoints across 143 plugins
		// to Admin with no gating capability check anywhere in the file. A name
		// is not a capability check, and over-stating the privilege is the
		// error direction that makes a reachable vulnerability look gated.
		//
		// isAdminIndicatorAction stays: it matches names that quote an actual
		// capability or role.
		if authLevel == models.Subscriber {
			if isAdminIndicatorAction(action) {
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
		out.add(ep, "wp_ajax_")
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
		out.add(ep, "wp_ajax_nopriv_")
	}

	// 11. Find admin_post_* handlers (form submission hooks - requires login)
	adminPostAuthMatches := adminPostAuthPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range adminPostAuthMatches {
		if len(match) < 10 || processedPositions[match[0]] {
			continue
		}

		fullMatch := content[match[0]:match[1]]
		action := content[match[2]:match[3]]

		// admin_post_ is a prefix of admin_post_nopriv_, so this pattern also
		// matches the anonymous half of the pair. Leave those to detector 12 --
		// and leave the position unclaimed, because both patterns anchor on the
		// same `add_action`, so marking it here is what stopped detector 12 from
		// ever running. Measured: all 13 admin_post_nopriv_ registrations in the
		// corpus were being emitted above unauthenticated, 8 of them at admin.
		if strings.HasPrefix(action, "nopriv_") {
			continue
		}
		processedPositions[match[0]] = true

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

		// wp-admin/admin-post.php validates the auth cookie and fires
		// admin_post_{$action} in the logged-in arm. It never calls
		// current_user_can(), so the privilege this hook establishes is "any
		// logged-in user" -- a Subscriber -- and nothing about the hook name
		// implies a capability. Defaulting to Admin made this the largest single
		// over-restriction in the corpus: 63 of the 85 literal admin_post_ /
		// admin_action_ registrations across 143 trees were reported at admin.
		authLevel := models.Subscriber

		// The callback body can only RAISE from here, and only as far as Admin:
		// admin-post.php is a single-site dispatcher, so nothing about it can
		// imply network scope, and a capability that InferAuthLevel maps to
		// SuperAdmin (upload_plugins and upload_themes among them, which are
		// ordinary administrator capabilities on single-site WordPress) must not
		// push the endpoint past the level it reports today.
		callbackBody := findCallbackBody(content, callback)
		if callbackBody != "" {
			inferredLevel := InferAuthLevel(callbackBody)
			if inferredLevel > authLevel {
				authLevel = inferredLevel
			}
			if authLevel > models.Admin {
				authLevel = models.Admin
			}
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("admin_post_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "admin_post_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		// The route is built with the privileged prefix because formatAjaxRoute
		// collapses both halves onto one URL, but the HOOK this endpoint came
		// from is the anonymous one, and that is what the dispatch floor and the
		// twin correlation must see.
		out.add(ep, "admin_post_nopriv_")
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

		// Apply admin heuristics.
		//
		// isLikelyAdminAction is deliberately NOT consulted. It matches English
		// verbs and nouns that occur in most action names -- save_, add_,
		// edit_, delete_, dismiss, review, notice, option, setting, widget --
		// and promoted 818 of 3478 logged-in AJAX endpoints across 143 plugins
		// to Admin with no gating capability check anywhere in the file. A name
		// is not a capability check, and over-stating the privilege is the
		// error direction that makes a reachable vulnerability look gated.
		//
		// isAdminIndicatorAction stays: it matches names that quote an actual
		// capability or role.
		if authLevel == models.Subscriber {
			if isAdminIndicatorAction(action) {
				authLevel = models.Admin
			}
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wc_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "wc_ajax_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "woocommerce_api_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "woocommerce_api_")
	}

	// 14. Find admin_action_* handlers (WordPress admin action hooks)
	// These fire on admin-post.php when $_REQUEST['action'] matches
	// Requires login by default since they're in admin context
	adminActionMatches := adminActionPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range adminActionMatches {
		if len(match) < 10 || processedPositions[match[0]] {
			continue
		}

		fullMatch := content[match[0]:match[1]]
		action := content[match[2]:match[3]]

		// Skip if this is a nopriv variant (handled separately). The position is
		// left unclaimed for the same reason as in detector 11: both patterns
		// anchor on the same `add_action`, so claiming it here would block the
		// detector that is supposed to take over.
		if strings.HasPrefix(action, "nopriv_") {
			continue
		}
		processedPositions[match[0]] = true

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

		// wp-admin/admin.php fires admin_action_{$action} after auth_redirect().
		// The only current_user_can() in that file governs a memory-limit bump,
		// so like admin_post_ the hook establishes "any logged-in user" and no
		// more. Raise-only from the callback body, capped at Admin, for the same
		// reason as detector 11.
		authLevel := models.Subscriber

		callbackBody := findCallbackBody(content, callback)
		if callbackBody != "" {
			inferredLevel := InferAuthLevel(callbackBody)
			if inferredLevel > authLevel {
				authLevel = inferredLevel
			}
			if authLevel > models.Admin {
				authLevel = models.Admin
			}
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("admin_action_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "admin_action_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "admin_action_")
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
			// wp-admin/admin.php gates admin_action_ on auth_redirect() alone,
			// so the WordPress-derived level is Subscriber. This block has no
			// downgrade path at all, which is why the Admin default here was
			// unconditional.
			AuthLevel: models.Subscriber,
			Callback:  normalizeCallbackExpr(callback, content, match[0]),
			File:      filepath,
			Line:      lineNum,
			RawCode:   truncateCode(fullMatch, 500),
		}
		out.add(ep, "admin_action_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "heartbeat_received")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "heartbeat_nopriv_received")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "heartbeat_send")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "heartbeat_nopriv_send")
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
		if isAdminIndicatorAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("wp_ajax_" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "wp_ajax_")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "wp_ajax_nopriv_")
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
		if isAdminIndicatorAction(action) {
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
		out.add(ep, "wp_ajax_")
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
		out.add(ep, "wp_ajax_nopriv_")
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
		} else if isAdminIndicatorAction(action) {
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, routePrefix)
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
		if isAdminIndicatorAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("elementor_ajax:" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "elementor_ajax:")
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
		if authLevel == models.Subscriber && isAdminIndicatorAction(action) {
			authLevel = models.Admin
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute("acf_ajax:" + action),
			Method:     "POST",
			AuthLevel:  authLevel,
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "acf_ajax:")
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, "wp_ajax_fs_")
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
		} else if isAdminIndicatorAction(action) {
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
			Callback:   normalizeCallbackExpr(callback, content, match[0]),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
		}
		out.add(ep, routePrefix)
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
		if isAdminIndicatorAction(action) {
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
		out.add(ep, routePrefix)
	}

	// 31. Registrations whose hook name or callback is written in a shape none of
	// the patterns above spells out. This is evaluation rather than matching, and
	// it only looks at call sites the patterns left unclaimed.
	detectEvaluatedHookRegistrations(content, filepath, pluginSlug, processedPositions, &out)

	// An action registered under both wp_ajax_ and wp_ajax_nopriv_ is reachable
	// anonymously, so the privileged twin describes no privilege either.
	out.correlateTwins()

	// The dispatch fact is enforced last, and in one place, so that it is a floor
	// rather than a starting guess: no inference added to this file later can
	// quietly raise an endpoint that WordPress core routes to anonymous callers.
	out.enforceAnonymousDispatchFloor()

	return out.eps
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

	// The array-with-method alternative of the hook patterns captures only the
	// first quoted fragment, so array( $this, 'ajax_' . 'X' ) arrives here as
	// "ajax_". Re-reading the argument list with a balanced scan recovers the
	// whole callable; the regex result is kept whenever that cannot name one.
	callbackName := normalizeCallbackExpr(callback, content, match[0])
	if open := strings.IndexByte(content[match[0]:], '('); open >= 0 {
		if args, _, ok := phpArgList(content, match[0]+open); ok && len(args) >= 2 {
			scope := enclosingFunctionScope(content, match[0])
			if better := parsePHPCallable(args, nil, content, scope); better != "unknown" {
				callbackName = better
			}
		}
	}

	// Calculate line number
	lineNum := countLines(content[:match[0]]) + 1

	// Determine auth level
	authLevel := models.Subscriber // Default for wp_ajax_ (requires login)
	if isNopriv {
		// wp-admin/admin-ajax.php fires wp_ajax_nopriv_{$action} for every request
		// that does not carry a valid auth cookie, and it decides that before any
		// plugin code runs. The registration is therefore an upper bound on the
		// privilege a caller needs, established by core routing.
		//
		// This used to read the callback body back and raise the level when it
		// found something -- and what it mostly found was a nonce, which is CSRF
		// protection a logged-out visitor can satisfy, because wp_create_nonce()
		// for user 0 is printed into the public page. That raise did double
		// damage: it also hid the endpoint from correlateTwins, which recognised
		// the anonymous half by its level, so one bad guess over-restricted two
		// endpoints. Measured across 143 plugin trees, 48 nopriv registrations in
		// 23 trees were reported above unauthenticated this way.
		//
		// An internal gate is still worth knowing about, but it belongs in the
		// guard analysis, and until that is dominance-aware the endpoint level
		// must reflect the registration rather than the body.
		authLevel = models.Unauthenticated
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
		Callback:   callbackName,
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
	// These quote capability names: manage_options is the capability core itself
	// gates the Settings API on, and manage_ heads a family of real capabilities
	// (manage_categories, manage_links, manage_network...).
	//
	// The bare "admin_" prefix that used to head this list is gone. It quotes
	// nothing: an action named admin_something is a plugin's naming convention
	// for its own admin-side handlers, and WordPress does not read hook names for
	// privilege. Its measured effect on the 143-tree corpus was zero endpoints
	// either way, so this is a correction to the rule rather than to a number --
	// but the rule is what generalises to the plugins the corpus does not contain.
	coreAdminPrefixes := []string{
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

	// There used to be a third tier here: _search, _list, _log, _query, _panel,
	// _page, _view, _insight, _statistic, _report, _check, _hide, _enable,
	// _disable, _toggle -- any of which promoted the endpoint to Admin unless an
	// equally English "user-facing exception" list vetoed it.
	//
	// It is gone because none of those words is a capability. WordPress grants
	// privilege through capabilities checked at runtime; do_action( 'wp_ajax_' .
	// $action ) does not inspect $action for the substring "_view". This is the
	// same argument the file already accepted when it stopped consulting
	// isLikelyAdminAction, applied consistently: the surviving tiers quote
	// capability names (manage_options, manage_) or Settings-API operations that
	// core itself gates on manage_options.
	//
	// Measured over 143 plugin trees: 115 AJAX endpoints in 39 trees were
	// reported at Admin from files containing no capability check of any kind,
	// and this tier was the largest single source of them. Among its victims
	// were a front-end member dashboard tab (via _list), a quick-view popup (via
	// _view) and every action name a plugin happened to spell with _log.
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
				if isAdminIndicatorAction(action) {
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

	// Resolve the iterated table and bind the loop variables, which is the only
	// way to name the handler each entry registers. This runs first so that when
	// the same registration is also found by one of the older detectors below,
	// the entry with the resolved callback is the one deduplication keeps.
	endpoints = append(endpoints, detectHookTableRegistrations(content, filepath, pluginSlug)...)

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
		keysOnly := false
		foreachMatch := foreachSimplePattern.FindStringSubmatch(afterArray)
		if foreachMatch != nil && len(foreachMatch) >= 2 {
			loopVar = foreachMatch[1]
		} else {
			foreachMatch = foreachAssocPattern.FindStringSubmatch(afterArray)
			if foreachMatch != nil && len(foreachMatch) >= 2 {
				loopVar = foreachMatch[1]
				// This pattern binds the KEY, and the registration below is
				// required to concatenate that same variable, so only the keys
				// of this array can be actions. Harvesting every quoted string
				// in the array turned a table of 'ACTION' => 'both' entries into
				// endpoints named "both" and "admin" -- routes no request can
				// ever carry, with callbacks that name nothing.
				keysOnly = true
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
			if keysOnly && !isArrayKey(arrayContent, action) {
				continue
			}
			fullAction := prefix + action

			authLevel := models.Subscriber
			routePrefix := "wp_ajax_"
			if isNopriv {
				authLevel = models.Unauthenticated
				routePrefix = "wp_ajax_nopriv_"
			} else if isAdminIndicatorAction(fullAction) {
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

// isArrayKey reports whether a quoted string appears as a KEY in an array
// literal, i.e. is followed by "=>". PHP binds the key to the first name of a
// `foreach ( $a as $k => $v )` header, so when the registration concatenates
// that name only the keys can be action names.
func isArrayKey(arrayContent, name string) bool {
	for i := 0; i < len(arrayContent); {
		j := strings.Index(arrayContent[i:], name)
		if j < 0 {
			return false
		}
		at := i + j
		i = at + len(name)
		if at == 0 || (arrayContent[at-1] != '\'' && arrayContent[at-1] != '"') {
			continue
		}
		k := i
		if k >= len(arrayContent) || (arrayContent[k] != '\'' && arrayContent[k] != '"') {
			continue
		}
		k = skipSpace(arrayContent, k+1)
		if k+1 < len(arrayContent) && arrayContent[k] == '=' && arrayContent[k+1] == '>' {
			return true
		}
	}
	return false
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
			} else if isAdminIndicatorAction(fullAction) {
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

// ---------------------------------------------------------------------------
// Hook names and callbacks are values, not spellings
// ---------------------------------------------------------------------------
//
// WordPress dispatches on the VALUE of a string: admin-ajax.php runs
// do_action( 'wp_ajax_' . $_REQUEST['action'] ), so 'wp_ajax_um_' . $action and
// "wp_ajax_{$action}" and $full (assigned 'wp_ajax_' . $x a line earlier) are
// the same registration written three ways. PHP has one string type and one
// concatenation operator, and it folds 'a' . 'b' before add_action ever sees it.
//
// A detector built from one regex per spelling is matching syntax where
// WordPress matches value, and it fails in the direction that costs most: an
// unrecognised spelling produces NO endpoint, so the handler behind it is never
// examined at all. The same is true of the callback: whether it is a string, an
// array, a Closure, a static Closure, an arrow function, __CLASS__ . '::m' or a
// variable, the registration is equally real and the hook name is equally
// extractable. Coupling the two means an unrecognised callback discards a known
// entry point.
//
// So the code below evaluates instead of matching. The regex detectors above are
// kept and run first: this pass only looks at call sites none of them claimed,
// which means it can add endpoints but never take one away.

// coreDispatchFamilies are the hook-name prefixes WordPress core itself turns
// into an HTTP entry point, longest first so that the nopriv halves win.
//
//	wp-admin/admin-ajax.php   wp_ajax_{$action} / wp_ajax_nopriv_{$action}
//	wp-admin/admin-post.php   admin_post_{$action} / admin_post_nopriv_{$action}
//	wp-admin/admin.php        admin_action_{$action}
//
// Third-party dispatchers (wc_ajax_, woocommerce_api_ and the rest) are not
// here. They are fired by a plugin, not by core, so "any plugin that writes X
// has created an endpoint" is not a statement anyone can make about them; the
// pattern detectors above keep whatever support they already had.
var coreDispatchFamilies = []string{
	"wp_ajax_nopriv_",
	"wp_ajax_",
	"admin_post_nopriv_",
	"admin_post_",
	"admin_action_",
}

// coreFiltersUnderDispatchPrefix are WordPress core FILTER names that happen to
// begin with one of the dispatch prefixes. Core fires both of these from
// _wp_post_thumbnail_html() to filter markup; neither is a request entry point,
// and a plugin filtering one has registered no endpoint. They are listed here by
// their core names rather than harvested from a corpus.
var coreFiltersUnderDispatchPrefix = map[string]bool{
	"admin_post_thumbnail_html": true,
	"admin_post_thumbnail_size": true,
}

// coreDispatchFamily reports which core dispatcher a folded hook name belongs
// to, if any.
func coreDispatchFamily(hook string) (string, bool) {
	if coreFiltersUnderDispatchPrefix[hook] {
		return "", false
	}
	for _, family := range coreDispatchFamilies {
		if !strings.HasPrefix(hook, family) || len(hook) <= len(family) {
			continue
		}
		// "wp_ajax_nopriv_" with nothing after it is the anonymous family with
		// an empty action, not the privileged family with the action "nopriv_".
		// Reading it the second way would report an anonymous registration at
		// the privileged level, which is the error direction that hides a
		// reachable vulnerability.
		if strings.HasPrefix(hook[len(family):], "nopriv_") {
			continue
		}
		return family, true
	}
	return "", false
}

// dispatchFamilyLevel is the privilege WordPress core requires of a caller to
// reach a handler on this family, and nothing more.
//
// The action name is NOT consulted. It was already spent identifying the family,
// and re-reading it as a privilege signal has no basis in core: do_action does
// not inspect $action for English words. That matters most here, because a name
// recovered by evaluation is exactly the kind that carries a plugin's own
// namespace prefix.
func dispatchFamilyLevel(family string) models.AuthLevel {
	if hookIsAnonymousDispatch(family) {
		return models.Unauthenticated
	}
	return models.Subscriber
}

// skipPHPNonCode advances past a quoted string or a comment beginning at i and
// returns the offset of the first byte after it, or i+1 when i begins neither.
func skipPHPNonCode(content string, i int) int {
	switch content[i] {
	case '\'', '"':
		quote := content[i]
		for j := i + 1; j < len(content); j++ {
			if content[j] == '\\' {
				j++
				continue
			}
			if content[j] == quote {
				return j + 1
			}
		}
		return len(content)
	case '#':
		if k := strings.IndexAny(content[i:], "\r\n"); k >= 0 {
			return i + k
		}
		return len(content)
	case '/':
		if i+1 < len(content) && content[i+1] == '/' {
			if k := strings.IndexAny(content[i:], "\r\n"); k >= 0 {
				return i + k
			}
			return len(content)
		}
		if i+1 < len(content) && content[i+1] == '*' {
			if k := strings.Index(content[i+2:], "*/"); k >= 0 {
				return i + 2 + k + 2
			}
			return len(content)
		}
	}
	return i + 1
}

// maxCallScan bounds the balanced scan of one argument list. The longest
// add_action argument list in the 143-tree corpus is a few hundred bytes; the
// bound exists so that an unbalanced parenthesis in a malformed file costs a
// scan of this length rather than of the file.
const maxCallScan = 20000

// phpArgList splits the argument list whose opening parenthesis is at
// content[open] on its top-level commas, and returns the offset just past the
// closing parenthesis. Quoted strings, comments and nested (), [] and {} are
// skipped, so an argument may itself be an array literal or a closure.
func phpArgList(content string, open int) (args []string, end int, ok bool) {
	if open >= len(content) || content[open] != '(' {
		return nil, 0, false
	}
	limit := open + maxCallScan
	if limit > len(content) {
		limit = len(content)
	}
	depth := 0
	start := open + 1
	for i := open; i < limit; {
		switch content[i] {
		case '\'', '"', '#', '/':
			next := skipPHPNonCode(content, i)
			if next > i {
				i = next
				continue
			}
		}
		switch content[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth <= 0 {
				if content[i] != ')' {
					return nil, 0, false
				}
				args = append(args, strings.TrimSpace(content[start:i]))
				return args, i + 1, true
			}
		case ',':
			if depth == 1 {
				args = append(args, strings.TrimSpace(content[start:i]))
				start = i + 1
			}
		}
		i++
	}
	return nil, 0, false
}

// splitTopLevelConcat splits a PHP expression on the "." operators that are not
// inside a string, a comment or a nested bracket.
func splitTopLevelConcat(expr string) []string {
	terms := make([]string, 0, 4)
	depth := 0
	start := 0
	for i := 0; i < len(expr); {
		switch expr[i] {
		case '\'', '"', '#', '/':
			next := skipPHPNonCode(expr, i)
			if next > i {
				i = next
				continue
			}
		}
		switch expr[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '.':
			// A dot inside a number is not concatenation, and neither is the
			// "?->" null-safe operator's arrow.
			if depth == 0 && (i == 0 || !isPHPDigit(expr[i-1]) || i+1 >= len(expr) || !isPHPDigit(expr[i+1])) {
				terms = append(terms, expr[start:i])
				start = i + 1
			}
		}
		i++
	}
	terms = append(terms, expr[start:])
	return terms
}

func isPHPDigit(b byte) bool { return b >= '0' && b <= '9' }

func isPHPNameByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// foldPHPExpr evaluates a PHP string expression to the value PHP would build.
//
// subst carries bindings that are known from context -- a foreach loop's
// variables, say. Terms that cannot be evaluated are rendered as a {name}
// placeholder and reported by the second return value, so the caller can still
// emit the endpoint and annotate the route as dynamic rather than dropping it.
func foldPHPExpr(expr string, subst map[string]string, content string, scope string) (string, bool) {
	var b strings.Builder
	resolved := true
	for _, term := range splitTopLevelConcat(expr) {
		value, ok := foldPHPTerm(strings.TrimSpace(term), subst, content, scope, 0)
		if !ok {
			resolved = false
		}
		b.WriteString(value)
	}
	return b.String(), resolved
}

// maxFoldDepth bounds how far foldPHPTerm will chase a variable through its
// assignments. Two is enough for the shape this exists for ($full = 'wp_ajax_' .
// $action; add_action($full, ...)) and stops a cyclic assignment dead.
const maxFoldDepth = 2

func foldPHPTerm(term string, subst map[string]string, content, scope string, depth int) (string, bool) {
	if term == "" {
		return "", true
	}

	// A single-quoted literal is its own value; PHP does not interpolate it.
	if len(term) >= 2 && term[0] == '\'' && term[len(term)-1] == '\'' {
		return term[1 : len(term)-1], true
	}

	// A double-quoted literal interpolates. cleanActionName renders $x and
	// {$x} as {x}, which is exactly the placeholder shape used elsewhere, so
	// any binding we do know can then be substituted into it.
	if len(term) >= 2 && term[0] == '"' && term[len(term)-1] == '"' {
		value := cleanActionName(term[1 : len(term)-1])
		value = applySubstitutions(value, subst)
		return value, !strings.Contains(value, "{")
	}

	// $this->property and self::$property: a class property is class-scoped, so
	// the whole file is the right place to look for its assignment.
	if name, ok := propertyTermName(term); ok {
		if value, ok := subst["this->"+name]; ok {
			return value, true
		}
		if value, found := lastStringAssignment(content, "this->"+name); found {
			return value, true
		}
		if value, found := declaredPropertyString(content, name); found {
			return value, true
		}
		return "{" + name + "}", false
	}

	// A plain variable. PHP binds a variable within one function body, so the
	// assignment is looked for in the enclosing function only -- a file-wide
	// backward scan would happily attach an unrelated function's value.
	if len(term) > 1 && term[0] == '$' && isPHPNameByte(term[1]) && !strings.ContainsAny(term, "[]->(") {
		name := term[1:]
		if value, ok := subst[name]; ok {
			// A binding whose value could not be read is bound to SOMETHING,
			// so folding it away to the empty string would silently truncate
			// the hook name -- 'wp_ajax_nopriv_' . $name became the bare family
			// prefix. Report it unresolved instead.
			return value, value != ""
		}
		if value, found := lastStringAssignment(scope, name); found {
			return value, true
		}
		if depth < maxFoldDepth {
			if rhs, found := lastAssignmentRHS(scope, name, 500); found {
				if value, ok := foldNestedExpr(rhs, subst, content, scope, depth+1); ok {
					return value, true
				}
			}
		}
		return "{" + name + "}", false
	}

	// self::CONST, static::CONST, ClassName::CONST. Class constants are
	// file-scoped for our purposes, like properties.
	if idx := strings.Index(term, "::"); idx > 0 && !strings.Contains(term, "(") {
		constName := strings.TrimSpace(term[idx+2:])
		if constName != "" && constName != "class" {
			if value, found := declaredConstantString(content, constName); found {
				return value, true
			}
			return "{" + constName + "}", false
		}
	}

	return "{" + placeholderName(term) + "}", false
}

// foldNestedExpr folds a whole expression at depth, used when a variable's
// assignment is itself a concatenation.
func foldNestedExpr(expr string, subst map[string]string, content, scope string, depth int) (string, bool) {
	var b strings.Builder
	resolved := true
	for _, term := range splitTopLevelConcat(expr) {
		value, ok := foldPHPTerm(strings.TrimSpace(term), subst, content, scope, depth)
		if !ok {
			resolved = false
		}
		b.WriteString(value)
	}
	return b.String(), resolved
}

// applySubstitutions replaces {name} placeholders with any binding we hold.
func applySubstitutions(value string, subst map[string]string) string {
	if len(subst) == 0 || !strings.Contains(value, "{") {
		return value
	}
	for name, bound := range subst {
		value = strings.ReplaceAll(value, "{"+name+"}", bound)
	}
	return value
}

// placeholderName reduces an expression we cannot evaluate to something usable
// as a {placeholder}: the last identifier in it, or "expr".
func placeholderName(term string) string {
	end := len(term)
	for end > 0 && !isPHPNameByte(term[end-1]) {
		end--
	}
	start := end
	for start > 0 && isPHPNameByte(term[start-1]) {
		start--
	}
	if start < end {
		return term[start:end]
	}
	return "expr"
}

// propertyTermName recognises $this->prop, self::$prop and static::$prop.
func propertyTermName(term string) (string, bool) {
	for _, prefix := range []string{"$this->", "self::$", "static::$"} {
		if strings.HasPrefix(term, prefix) {
			name := strings.TrimSpace(term[len(prefix):])
			if name != "" && !strings.ContainsAny(name, "[]->()$") {
				return name, true
			}
			return "", false
		}
	}
	return "", false
}

// lastStringAssignment returns the value of the LAST `$name = 'literal'` in
// window. The last one, not the first: a file that reuses a variable name would
// otherwise be read backwards.
func lastStringAssignment(window, name string) (string, bool) {
	needle := "$" + name
	value := ""
	found := false
	for i := 0; i < len(window); {
		j := strings.Index(window[i:], needle)
		if j < 0 {
			break
		}
		pos := i + j
		i = pos + len(needle)
		if pos > 0 && (isPHPNameByte(window[pos-1]) || window[pos-1] == '$') {
			continue
		}
		if i < len(window) && isPHPNameByte(window[i]) {
			continue
		}
		k := skipSpace(window, i)
		if k >= len(window) || window[k] != '=' {
			continue
		}
		if k+1 < len(window) && (window[k+1] == '=' || window[k+1] == '>') {
			continue
		}
		k = skipSpace(window, k+1)
		if k >= len(window) || (window[k] != '\'' && window[k] != '"') {
			continue
		}
		end := skipPHPNonCode(window, k)
		if end <= k+1 || end > len(window) {
			continue
		}
		// The literal must BE the right-hand side. `$x = 'wp_ajax_' . $y;`
		// starts with a literal too, and taking it would report half a value as
		// if it were the whole one; that expression belongs to the concatenation
		// path instead.
		after := skipSpace(window, end)
		if after < len(window) && window[after] != ';' && window[after] != ',' && window[after] != ')' {
			continue
		}
		value = window[k+1 : end-1]
		found = true
	}
	return value, found
}

// lastAssignmentRHS returns the text of the LAST `$name = ...` right-hand side
// in window, up to the semicolon that closes it. Brackets are tracked, so a
// multi-line array literal comes back whole.
func lastAssignmentRHS(window, name string, limit int) (string, bool) {
	needle := "$" + name
	rhs := ""
	found := false
	for i := 0; i < len(window); {
		j := strings.Index(window[i:], needle)
		if j < 0 {
			break
		}
		pos := i + j
		i = pos + len(needle)
		if pos > 0 && (isPHPNameByte(window[pos-1]) || window[pos-1] == '$') {
			continue
		}
		if i < len(window) && isPHPNameByte(window[i]) {
			continue
		}
		k := skipSpace(window, i)
		if k >= len(window) || window[k] != '=' {
			continue
		}
		if k+1 < len(window) && (window[k+1] == '=' || window[k+1] == '>') {
			continue
		}
		k = skipSpace(window, k+1)
		end := k
		stop := k + limit
		if stop > len(window) {
			stop = len(window)
		}
		depth := 0
		for end < stop {
			switch window[end] {
			case '\'', '"', '#', '/':
				if next := skipPHPNonCode(window, end); next > end {
					end = next
					continue
				}
			}
			if window[end] == ';' && depth == 0 {
				break
			}
			switch window[end] {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth--
				if depth < 0 {
					stop = end
				}
			}
			end++
		}
		if end > k {
			rhs = strings.TrimSpace(window[k:end])
			found = true
		}
	}
	return rhs, found
}

// declaredPropertyString finds `public|protected|private $prop = 'value'`.
func declaredPropertyString(content, name string) (string, bool) {
	for _, keyword := range []string{"public", "protected", "private", "var"} {
		idx := 0
		for {
			j := strings.Index(content[idx:], keyword+" ")
			if j < 0 {
				break
			}
			pos := idx + j
			idx = pos + len(keyword)
			rest := skipSpace(content, pos+len(keyword))
			if value, ok := matchStringAssignmentAt(content, rest, name); ok {
				return value, true
			}
		}
	}
	return "", false
}

// matchStringAssignmentAt checks for `$name = 'value'` starting at pos.
func matchStringAssignmentAt(content string, pos int, name string) (string, bool) {
	needle := "$" + name
	if !strings.HasPrefix(content[pos:], needle) {
		return "", false
	}
	k := pos + len(needle)
	if k < len(content) && isPHPNameByte(content[k]) {
		return "", false
	}
	k = skipSpace(content, k)
	if k >= len(content) || content[k] != '=' {
		return "", false
	}
	k = skipSpace(content, k+1)
	if k >= len(content) || (content[k] != '\'' && content[k] != '"') {
		return "", false
	}
	end := skipPHPNonCode(content, k)
	if end <= k+1 {
		return "", false
	}
	return content[k+1 : end-1], true
}

// declaredConstantString finds `const NAME = 'value'`.
func declaredConstantString(content, name string) (string, bool) {
	idx := 0
	for {
		j := strings.Index(content[idx:], "const ")
		if j < 0 {
			return "", false
		}
		pos := idx + j
		idx = pos + 6
		k := skipSpace(content, idx)
		if !strings.HasPrefix(content[k:], name) {
			continue
		}
		k += len(name)
		if k < len(content) && isPHPNameByte(content[k]) {
			continue
		}
		k = skipSpace(content, k)
		if k >= len(content) || content[k] != '=' {
			continue
		}
		k = skipSpace(content, k+1)
		if k >= len(content) || (content[k] != '\'' && content[k] != '"') {
			continue
		}
		end := skipPHPNonCode(content, k)
		if end > k+1 {
			return content[k+1 : end-1], true
		}
	}
}

// maxScopeLookBack bounds the search for the head of the enclosing function.
// A PHP function longer than this is not something a backward scan should pay
// for on every registration in a large file; the window that remains is still
// narrower than the file, so the failure mode stays under-resolution.
const maxScopeLookBack = 20000

// enclosingFunctionScope returns the slice of content that a plain variable's
// assignment may be looked for in: from the head of the function containing pos
// up to pos itself.
//
// PHP binds a variable within one function body, so this is the scope the
// language actually gives it. A file-wide backward scan would cheerfully attach
// an unrelated function's assignment to this registration and mis-name the
// endpoint, which is worse than leaving it as an unresolved placeholder.
func enclosingFunctionScope(content string, pos int) string {
	if pos > len(content) {
		pos = len(content)
	}
	limit := pos - maxScopeLookBack
	if limit < 0 {
		limit = 0
	}
	for at := pos; at > limit; {
		j := strings.LastIndex(content[limit:at], "function")
		if j < 0 {
			break
		}
		at = limit + j
		if (at == 0 || !isPHPNameByte(content[at-1])) &&
			(at+8 >= len(content) || !isPHPNameByte(content[at+8])) {
			return content[at:pos]
		}
	}
	return content[limit:pos]
}

// parsePHPCallable turns the callback arguments of a registration into a name
// the call graph can key on.
//
// PHP accepts any callable in that position -- a string, an array, a Closure, a
// static Closure, an arrow function, or a variable holding one of those -- and
// the language keeps adding to that list, so this reads the shape rather than
// enumerating spellings. An argument it cannot name still yields an endpoint:
// an endpoint with an unresolved callback is worth strictly more than no
// endpoint at all, and marking it unresolved (rather than passing the raw text
// through) keeps a fragment like "$plugin_admin" from being mistaken downstream
// for a symbol.
func parsePHPCallable(args []string, subst map[string]string, content, scope string) string {
	if len(args) < 2 {
		return "unknown"
	}
	return parseCallableExpr(strings.TrimSpace(args[1]), args, subst, content, scope, 0)
}

// parseCallableExpr names one callable expression. args is passed through only
// so that the loader's (component, 'method') pair can be read; depth bounds the
// chase through a variable that holds the callable.
func parseCallableExpr(expr string, args []string, subst map[string]string, content, scope string, depth int) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "unknown"
	}

	// A closure, static closure or arrow function. "closure" is the sentinel
	// the call graph resolves by reading the file's registration closures, so
	// the body behind it is still walked.
	trimmed := strings.TrimPrefix(expr, "static ")
	trimmed = strings.TrimSpace(trimmed)
	if strings.HasPrefix(trimmed, "function") || strings.HasPrefix(trimmed, "fn(") ||
		strings.HasPrefix(trimmed, "fn (") {
		return "closure"
	}

	// [ $obj, 'method' ] and array( $obj, 'method' ), including the forms whose
	// method name is itself an expression: array( $this, $method . '_callback' ).
	if strings.HasPrefix(expr, "[") || strings.HasPrefix(expr, "array") {
		if folded, ok := foldArrayCallable(expr, subst, content, scope); ok {
			return NormalizeCallback(folded)
		}
		return NormalizeCallback(expr)
	}

	// A bare object variable is a callable only if its class defines __invoke.
	// When a literal method name follows it, the callable is the pair -- that is
	// the WordPress-Plugin-Boilerplate loader's three-argument shape, where
	// argument 1 is the component and argument 2 is the method.
	if len(expr) > 1 && expr[0] == '$' && !strings.ContainsAny(expr, "[]->(.:") {
		if len(args) >= 3 {
			if method, ok := singleQuotedLiteral(strings.TrimSpace(args[2])); ok {
				return NormalizeCallback(method)
			}
		}
		if value, ok := foldPHPExpr(expr, subst, content, scope); ok && value != "" {
			return NormalizeCallback(value)
		}
		// $cb = array( $this, 'handler' ); add_action( 'wp_ajax_x', $cb );
		// The variable holds the callable, so its assignment is the callable.
		if depth < maxFoldDepth {
			if rhs, found := lastAssignmentRHS(scope, expr[1:], 500); found {
				if name := parseCallableExpr(rhs, nil, subst, content, scope, depth+1); name != "unknown" {
					return name
				}
			}
		}
		return "unknown"
	}

	folded, ok := foldPHPExpr(expr, subst, content, scope)
	if !ok || folded == "" || strings.Contains(folded, "{") {
		// __CLASS__ . '::method' and self::class . '::method' fold to a class
		// term we cannot name plus a method we can; keep the method, which is
		// what the call graph keys on anyway.
		if method, ok := trailingScopedMethod(expr); ok {
			return NormalizeCallback(method)
		}
		return "unknown"
	}
	return NormalizeCallback(folded)
}

// normalizeCallbackExpr names a callback expression captured by one of the
// pattern detectors, folding it first.
//
// PHP evaluates 'ajax_' . 'X' to ajax_X before add_action ever sees it, so
// reporting the unevaluated source text as the callback reports a string PHP
// never produced -- and one carrying a quote and a dot inside it, which can key
// no call-graph node. An endpoint whose callback names nothing reaches nothing,
// which for the never-miss objective is indistinguishable from a missed
// registration and worse than one, because it looks like coverage.
//
// When the expression cannot be named the previous result is kept rather than
// replaced by a sentinel, so this can only improve on what a detector reported.
func normalizeCallbackExpr(expr, content string, pos int) string {
	if name := parseCallableExpr(expr, nil, nil, content, enclosingFunctionScope(content, pos), 0); name != "unknown" {
		return name
	}
	return NormalizeCallback(expr)
}

// foldArrayCallable folds the method term of an array callable and rebuilds the
// array so that NormalizeCallback -- which already knows $this, __CLASS__,
// self:: and ClassName::class -- can name it.
func foldArrayCallable(expr string, subst map[string]string, content, scope string) (string, bool) {
	open := strings.IndexAny(expr, "[(")
	if open < 0 {
		return "", false
	}
	var inner string
	if expr[open] == '[' {
		shut := matchingBracket(expr, open)
		if shut < 0 {
			return "", false
		}
		inner = expr[open+1 : shut]
	} else {
		args, _, ok := phpArgList(expr, open)
		if !ok {
			return "", false
		}
		inner = strings.Join(args, ",")
	}
	parts := make([]string, 0, 2)
	for _, part := range splitTopLevelArgs(inner) {
		if strings.TrimSpace(part) != "" {
			parts = append(parts, part)
		}
	}
	// A trailing comma is legal PHP and common in a multi-line array literal,
	// so an empty last element is not a third argument.
	if len(parts) != 2 {
		return "", false
	}
	method, resolved := foldPHPExpr(strings.TrimSpace(parts[1]), subst, content, scope)
	if !resolved || method == "" || strings.ContainsAny(method, "{}$") {
		return "", false
	}
	return "array(" + strings.TrimSpace(parts[0]) + ", '" + method + "')", true
}

// splitTopLevelArgs splits an already-unwrapped argument list on top-level
// commas.
func splitTopLevelArgs(inner string) []string {
	parts := make([]string, 0, 2)
	depth := 0
	start := 0
	for i := 0; i < len(inner); {
		switch inner[i] {
		case '\'', '"', '#', '/':
			next := skipPHPNonCode(inner, i)
			if next > i {
				i = next
				continue
			}
		}
		switch inner[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, inner[start:i])
				start = i + 1
			}
		}
		i++
	}
	parts = append(parts, inner[start:])
	return parts
}

// matchingBracket returns the offset of the ']' closing the '[' at open.
func matchingBracket(s string, open int) int {
	depth := 0
	limit := open + maxCallScan
	if limit > len(s) {
		limit = len(s)
	}
	for i := open; i < limit; {
		switch s[i] {
		case '\'', '"', '#', '/':
			next := skipPHPNonCode(s, i)
			if next > i {
				i = next
				continue
			}
		}
		switch s[i] {
		case '[', '(', '{':
			depth++
		case ']', ')', '}':
			depth--
			if depth == 0 {
				if s[i] != ']' {
					return -1
				}
				return i
			}
		}
		i++
	}
	return -1
}

// trimLeadingPHPTrivia drops whitespace and comments from the front of an
// expression. An array literal is commonly written with a comment above each
// group of entries, and the comment belongs to the source, not to the value.
func trimLeadingPHPTrivia(expr string) string {
	for {
		trimmed := strings.TrimSpace(expr)
		if len(trimmed) < 2 {
			return trimmed
		}
		if trimmed[0] == '#' || (trimmed[0] == '/' && (trimmed[1] == '/' || trimmed[1] == '*')) {
			next := skipPHPNonCode(trimmed, 0)
			if next <= 0 || next >= len(trimmed) {
				return ""
			}
			expr = trimmed[next:]
			continue
		}
		return trimmed
	}
}

// singleQuotedLiteral returns the content of a quoted string argument.
func singleQuotedLiteral(expr string) (string, bool) {
	expr = trimLeadingPHPTrivia(expr)
	if len(expr) >= 2 && (expr[0] == '\'' || expr[0] == '"') && expr[len(expr)-1] == expr[0] {
		value := expr[1 : len(expr)-1]
		if value != "" && !strings.ContainsAny(value, "$'\"") {
			return value, true
		}
	}
	return "", false
}

// trailingScopedMethod picks the method out of __CLASS__ . '::method'.
func trailingScopedMethod(expr string) (string, bool) {
	folded := ""
	for _, term := range splitTopLevelConcat(expr) {
		if value, ok := singleQuotedLiteral(strings.TrimSpace(term)); ok {
			folded += value
		}
	}
	if idx := strings.LastIndex(folded, "::"); idx >= 0 {
		method := folded[idx+2:]
		if method != "" {
			return method, true
		}
	}
	return "", false
}

// registrationCallHeads finds every add_action / add_filter call in content and
// returns the offset of the name and of its opening parenthesis.
//
// A call written $obj->add_action(...) or Klass::add_action(...) is skipped:
// that is some object's own method, not the global function WordPress defines,
// and the detectors above already own the loader and framework shapes it stands
// for. add_filter is included because wp-includes/plugin.php defines add_action
// as `return add_filter( $hook_name, $callback, $priority, $accepted_args );`
// and do_action runs whatever sits in $wp_filter[$hook] regardless of which
// alias put it there -- so for a request-dispatch hook the two are the same
// registration.
func registrationCallHeads(content string) [][2]int {
	heads := make([][2]int, 0, 16)
	for _, name := range []string{"add_action", "add_filter"} {
		idx := 0
		for {
			j := strings.Index(content[idx:], name)
			if j < 0 {
				break
			}
			at := idx + j
			idx = at + len(name)
			if at > 0 && isPHPNameByte(content[at-1]) {
				continue
			}
			before := at
			for before > 0 && (content[before-1] == ' ' || content[before-1] == '\t' ||
				content[before-1] == '\r' || content[before-1] == '\n') {
				before--
			}
			if before >= 2 && (content[before-2:before] == "->" || content[before-2:before] == "::") {
				continue
			}
			open := skipSpace(content, idx)
			if open >= len(content) || content[open] != '(' {
				continue
			}
			heads = append(heads, [2]int{at, open})
		}
	}
	return heads
}

// detectEvaluatedHookRegistrations emits an endpoint for every add_action or
// add_filter call on a core dispatch hook that none of the pattern detectors
// above claimed.
//
// It runs last and only over unclaimed positions, so it can add an endpoint but
// never displace one. What it recovers is the registrations whose hook name is a
// value rather than a single quoted token -- 'wp_ajax_um_' . $action, or a name
// assembled into a variable a line earlier -- and the ones whose callback is
// written in a shape the hook patterns did not enumerate, such as a static
// closure, an arrow function, __CLASS__ . '::method' or a variable.
func detectEvaluatedHookRegistrations(content, filepath, pluginSlug string, processed map[int]bool, out *ajaxEndpointList) {
	for _, head := range registrationCallHeads(content) {
		if processed[head[0]] {
			continue
		}
		args, end, ok := phpArgList(content, head[1])
		if !ok || len(args) < 2 {
			continue
		}

		scope := enclosingFunctionScope(content, head[0])
		hook, resolved := foldPHPExpr(args[0], nil, content, scope)
		family, isDispatch := coreDispatchFamily(hook)
		if !isDispatch {
			continue
		}
		processed[head[0]] = true

		rawCode := truncateCode(content[head[0]:end], 500)
		if !resolved {
			// The route keeps its {placeholder} and the annotation records the
			// expression, so the dataflow pass downstream can still resolve it.
			rawCode += " [dynamic:unresolved:" + strings.TrimSpace(args[0]) + "]"
		}

		out.add(models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAJAX,
			Route:      formatAjaxRoute(hook),
			Method:     "POST",
			AuthLevel:  dispatchFamilyLevel(family),
			Callback:   parsePHPCallable(args, nil, content, scope),
			File:       filepath,
			Line:       countLines(content[:head[0]]) + 1,
			RawCode:    rawCode,
		}, family)
	}
}

// maxTableEntries bounds how many endpoints one iterated table may expand to.
// The largest table in the 143-tree corpus holds 58 entries; the bound is there
// so that a pathological array cannot inflate the graph.
const maxTableEntries = 200

// maxTableEndpointsPerFile bounds the whole pass for one file.
const maxTableEndpointsPerFile = 600

// detectHookTableRegistrations recovers the registrations a plugin makes by
// iterating a table of actions:
//
//	$this->ajax = array( 'astra-sites-api-request' => 'api_request', ... );
//	foreach ( $this->ajax as $ajax_hook => $ajax_callback ) {
//	    add_action( 'wp_ajax_' . $ajax_hook, array( $this, $ajax_callback ) );
//	}
//
// It is one endpoint per table entry, by PHP's own semantics: foreach binds its
// variables to each element before the body runs, and WordPress then dispatches
// admin-ajax.php on the resulting hook name. The two older foreach detectors are
// kept and run after this one, so nothing they find can be lost; what they
// cannot do is read a table held in a class property, take the callback out of
// the table, or bind the key and the value separately.
//
// The bindings are followed rather than guessed. Which loop variable supplies
// the action is decided by which one the hook expression names, and likewise for
// the callback -- "the key is the action" happens to hold for every associative
// table in this corpus, but it is a fact about these plugins, not about PHP, and
// a table that maps label => action would be silently mis-named by it.
func detectHookTableRegistrations(content, filepath, pluginSlug string) []models.Endpoint {
	// Cheap gate before any table resolution: a foreach is only interesting if
	// its body registers something on a core dispatch hook.
	if !strings.Contains(content, "foreach") ||
		(!strings.Contains(content, "wp_ajax_") &&
			!strings.Contains(content, "admin_post_") &&
			!strings.Contains(content, "admin_action_")) {
		return nil
	}

	out := ajaxEndpointList{}
	fallbacks := make([]string, 0, 16)

	for _, loop := range findForeachLoops(content) {
		if len(out.eps) >= maxTableEndpointsPerFile {
			break
		}
		body := content[loop.bodyStart:loop.bodyEnd]
		if !strings.Contains(body, "add_action") && !strings.Contains(body, "add_filter") {
			continue
		}

		registrations := make([][]string, 0, 4)
		for _, head := range registrationCallHeads(body) {
			args, _, ok := phpArgList(body, head[1])
			if ok && len(args) >= 2 {
				registrations = append(registrations, args)
			}
		}
		if len(registrations) == 0 {
			continue
		}

		table, ok := resolveHookTable(loop.source, content, loop.start)
		if !ok || len(table) == 0 {
			continue
		}
		if len(table) > maxTableEntries {
			table = table[:maxTableEntries]
		}

		scope := enclosingFunctionScope(content, loop.start)
		lineNum := countLines(content[:loop.start]) + 1

		for _, entry := range table {
			subst := map[string]string{}
			if loop.keyVar != "" {
				subst[loop.keyVar] = entry[0]
			}
			if loop.valVar != "" {
				subst[loop.valVar] = entry[1]
			}

			for _, args := range registrations {
				hook, resolved := foldPHPExpr(args[0], subst, content, scope)
				family, isDispatch := coreDispatchFamily(hook)
				if !isDispatch || !resolved {
					continue
				}
				action := strings.TrimPrefix(hook, family)

				out.add(models.Endpoint{
					PluginSlug: pluginSlug,
					Type:       models.EndpointTypeAJAX,
					Route:      formatAjaxRoute(hook),
					Method:     "POST",
					AuthLevel:  dispatchFamilyLevel(family),
					Callback:   parsePHPCallable(args, subst, content, scope),
					File:       filepath,
					Line:       lineNum,
					RawCode:    truncateCode(loop.source+" table iteration: "+action, 300),
				}, family)
				fallbacks = append(fallbacks, loopBinding(entry, loop, args[0]))

				if len(out.eps) >= maxTableEndpointsPerFile {
					break
				}
			}
		}
	}

	// A table whose loop body registers both halves of the pair binds the same
	// callback to both, so the privileged half describes no privilege. This is
	// deliberately loop-scoped rather than per-entry: plugins commonly guard the
	// nopriv registration with `if ( $nopriv )` on a flag from the table, and
	// evaluating that flag per entry would raise three quarters of such a table
	// back to Subscriber. Reporting the whole table as anonymously reachable
	// under-restricts, which is the safe direction, and the endpoint carries the
	// "[downgraded: has nopriv variant]" marker so the imprecision is visible.
	out.correlateTwins()
	out.enforceAnonymousDispatchFloor()

	// Only now name the endpoints whose callback expression would not fold. The
	// fallback is the table entry the hook itself was built from, which is what
	// this detector has always reported and which is right whenever a plugin
	// names its handler after its action -- measured, 254 of the 334 endpoints
	// the older foreach detectors emit. A raw unfoldable expression would be
	// worse than that guess, not better.
	//
	// It happens after the correlation on purpose. The fallback is a guess, not
	// a name, and if it were in place during the correlation the two halves of a
	// pair could be read as binding different handlers and the privileged half
	// would keep a privilege the anonymous half disproves.
	for i := range out.eps {
		if _, named := comparableHandlerName(out.eps[i].Callback); named {
			continue
		}
		if i < len(fallbacks) && fallbacks[i] != "" {
			out.eps[i].Callback = NormalizeCallback(fallbacks[i])
		}
	}
	return out.eps
}

// loopBinding returns the table entry half that the hook expression was built
// from, which is the best available guess at the handler's name when the
// callback expression itself will not fold.
func loopBinding(entry [2]string, loop foreachLoop, hookExpr string) string {
	if loop.keyVar != "" && strings.Contains(hookExpr, "$"+loop.keyVar) {
		return entry[0]
	}
	if loop.valVar != "" && strings.Contains(hookExpr, "$"+loop.valVar) {
		return entry[1]
	}
	if entry[0] != "" {
		return entry[0]
	}
	return entry[1]
}

// foreachLoop is the parsed head and body span of one foreach statement.
type foreachLoop struct {
	start     int
	source    string
	keyVar    string
	valVar    string
	bodyStart int
	bodyEnd   int
}

// findForeachLoops parses every foreach statement in content: its iterated
// expression, its bound variable names and the span of its body.
func findForeachLoops(content string) []foreachLoop {
	loops := make([]foreachLoop, 0, 4)
	idx := 0
	for {
		j := strings.Index(content[idx:], "foreach")
		if j < 0 {
			return loops
		}
		at := idx + j
		idx = at + 7
		if at > 0 && isPHPNameByte(content[at-1]) {
			continue
		}
		if idx < len(content) && isPHPNameByte(content[idx]) {
			continue
		}
		open := skipSpace(content, idx)
		if open >= len(content) || content[open] != '(' {
			continue
		}
		args, end, ok := phpArgList(content, open)
		if !ok || len(args) == 0 {
			continue
		}
		source, keyVar, valVar, ok := parseForeachHead(strings.Join(args, ","))
		if !ok {
			continue
		}
		bodyStart, bodyEnd, ok := foreachBodySpan(content, end)
		if !ok {
			continue
		}
		loops = append(loops, foreachLoop{
			start: at, source: source, keyVar: keyVar, valVar: valVar,
			bodyStart: bodyStart, bodyEnd: bodyEnd,
		})
		idx = end
	}
}

// parseForeachHead splits "SRC as $k => $v" (or "SRC as $v") into its parts.
// PHP binds the value in the single-variable form, so valVar is what is always
// set and keyVar only when the pair form is written.
func parseForeachHead(head string) (source, keyVar, valVar string, ok bool) {
	lower := strings.ToLower(head)
	at := -1
	for i := 0; i+4 <= len(lower); i++ {
		if lower[i:i+4] == " as " {
			at = i
			break
		}
	}
	if at < 0 {
		return "", "", "", false
	}
	source = strings.TrimSpace(head[:at])
	bound := strings.TrimSpace(head[at+4:])
	if source == "" || bound == "" {
		return "", "", "", false
	}
	if arrow := strings.Index(bound, "=>"); arrow >= 0 {
		keyVar = foreachVarName(bound[:arrow])
		valVar = foreachVarName(bound[arrow+2:])
	} else {
		valVar = foreachVarName(bound)
	}
	if valVar == "" && keyVar == "" {
		return "", "", "", false
	}
	return source, keyVar, valVar, true
}

// foreachVarName extracts the plain variable name from a foreach binding,
// tolerating the by-reference form &$item. A binding that destructures into a
// list is not a plain name and yields "".
func foreachVarName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "&")
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '$' {
		return ""
	}
	name := s[1:]
	for i := 0; i < len(name); i++ {
		if !isPHPNameByte(name[i]) {
			return ""
		}
	}
	return name
}

// foreachBodySpan returns the span of a foreach body, whether it is braced, the
// alternative endforeach syntax, or a single statement.
func foreachBodySpan(content string, afterHead int) (start, end int, ok bool) {
	i := skipSpace(content, afterHead)
	if i >= len(content) {
		return 0, 0, false
	}
	switch content[i] {
	case '{':
		shut := matchingBrace(content, i)
		if shut < 0 {
			return 0, 0, false
		}
		return i + 1, shut, true
	case ':':
		if k := strings.Index(content[i:], "endforeach"); k >= 0 {
			return i + 1, i + k, true
		}
		return 0, 0, false
	default:
		if k := strings.IndexByte(content[i:], ';'); k >= 0 {
			return i, i + k + 1, true
		}
		return 0, 0, false
	}
}

// matchingBrace returns the offset of the '}' closing the '{' at open.
func matchingBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); {
		switch s[i] {
		case '\'', '"', '#', '/':
			next := skipPHPNonCode(s, i)
			if next > i {
				i = next
				continue
			}
		}
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

// resolveHookTable resolves the expression a foreach iterates to a list of
// (key, value) pairs.
//
// The variable-name filter the older detector used -- the array had to be called
// something containing "ajax", "events", "actions" or "handlers" -- is not
// applied. A variable name is a plugin's convention; what makes a table
// interesting is that its loop registers a core dispatch hook, and that has
// already been tested by the caller.
func resolveHookTable(source, content string, foreachPos int) ([][2]string, bool) {
	source = strings.TrimSpace(source)

	// An array literal written straight into the foreach head, or the array
	// argument of the call that wraps one: apply_filters( 'hook', array( ... ) )
	// is the commonest way a plugin makes its own table filterable.
	if pairs, ok := tablePairsFromExpr(source); ok {
		return pairs, true
	}

	// A class property. Properties are class-scoped, so the whole file is the
	// right window: the declaration and the constructor assignment are both
	// usually far from the loop.
	if name, ok := propertyTermName(source); ok {
		if pairs, ok := tablePairsFromVar(content, "this->"+name); ok {
			return pairs, true
		}
		if pairs, ok := tablePairsFromVar(content, name); ok {
			return pairs, true
		}
		return nil, false
	}

	// A plain variable: PHP binds it inside one function body, so that is where
	// its assignment is looked for. When the loop is not inside a function -- or
	// the assignment sits above the enclosing function's head -- fall back to the
	// positional window the older detector used, which is what it always had.
	if len(source) > 1 && source[0] == '$' {
		name := source[1:]
		for i := 0; i < len(name); i++ {
			if !isPHPNameByte(name[i]) {
				return nil, false
			}
		}
		if pairs, ok := tablePairsFromVar(enclosingFunctionScope(content, foreachPos), name); ok {
			return pairs, true
		}
		back := foreachPos - 2000
		if back < 0 {
			back = 0
		}
		if pairs, ok := tablePairsFromVar(content[back:foreachPos], name); ok {
			return pairs, true
		}
	}

	return nil, false
}

// tablePairsFromVar returns the pairs of the LAST `$name = <array expression>`
// in window.
func tablePairsFromVar(window, name string) ([][2]string, bool) {
	rhs, found := lastAssignmentRHS(window, name, 20000)
	if !found {
		return nil, false
	}
	return tablePairsFromExpr(rhs)
}

// tablePairsFromExpr reads an array literal, or the array argument of the call
// that wraps one.
func tablePairsFromExpr(expr string) ([][2]string, bool) {
	expr = strings.TrimSpace(expr)
	if pairs, ok := arrayLiteralPairs(expr); ok {
		return pairs, true
	}
	if open := strings.IndexByte(expr, '('); open > 0 && !strings.HasPrefix(expr, "(") {
		if args, _, ok := phpArgList(expr, open); ok {
			for _, arg := range args {
				if pairs, ok := arrayLiteralPairs(strings.TrimSpace(arg)); ok {
					return pairs, true
				}
			}
		}
	}
	return nil, false
}

// arrayLiteralPairs parses an array literal into its (key, value) pairs. A key
// or a value that is not a literal comes back empty, which simply means no
// binding is available for that half.
func arrayLiteralPairs(expr string) ([][2]string, bool) {
	expr = strings.TrimSpace(expr)
	var inner string
	switch {
	case strings.HasPrefix(expr, "["):
		shut := matchingBracket(expr, 0)
		if shut < 0 {
			return nil, false
		}
		inner = expr[1:shut]
	case strings.HasPrefix(expr, "array"):
		open := skipSpace(expr, 5)
		if open >= len(expr) || expr[open] != '(' {
			return nil, false
		}
		args, _, ok := phpArgList(expr, open)
		if !ok {
			return nil, false
		}
		inner = strings.Join(args, ",")
	default:
		return nil, false
	}

	pairs := make([][2]string, 0, 8)
	for _, element := range splitTopLevelArgs(inner) {
		element = strings.TrimSpace(element)
		if element == "" {
			continue
		}
		key, value := "", ""
		if arrow := topLevelArrow(element); arrow >= 0 {
			key, _ = singleQuotedLiteral(strings.TrimSpace(element[:arrow]))
			value, _ = singleQuotedLiteral(strings.TrimSpace(element[arrow+2:]))
		} else {
			value, _ = singleQuotedLiteral(element)
		}
		if key == "" && value == "" {
			continue
		}
		pairs = append(pairs, [2]string{key, value})
	}
	if len(pairs) == 0 {
		return nil, false
	}
	return pairs, true
}

// topLevelArrow returns the offset of the "=>" separating a key from a value.
func topLevelArrow(element string) int {
	depth := 0
	for i := 0; i < len(element); {
		switch element[i] {
		case '\'', '"', '#', '/':
			next := skipPHPNonCode(element, i)
			if next > i {
				i = next
				continue
			}
		}
		switch element[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth == 0 && i+1 < len(element) && element[i+1] == '>' {
				return i
			}
		}
		i++
	}
	return -1
}

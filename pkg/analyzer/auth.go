package analyzer

import (
	"regexp"
	"strings"
	"sync"

	wpast "github.com/hatlesswizard/wptracelib/pkg/ast"
	"github.com/hatlesswizard/wptracelib/pkg/config"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// authConfig holds the current authentication configuration.
// This is set at package initialization with defaults.
var authConfig *config.Config

// init initializes the default auth configuration.
func init() {
	authConfig = config.New()
}

// SetAuthConfig sets the authentication configuration.
// This allows customizing capability mappings and admin patterns.
func SetAuthConfig(cfg *config.Config) {
	if cfg != nil {
		authConfig = cfg
	}
}

// GetAuthConfig returns the current authentication configuration.
func GetAuthConfig() *config.Config {
	return authConfig
}

// Package-level compiled regex patterns for auth detection
var (
	// Patterns for isExplicitlyUnauthenticated
	unauthPermissionCallbackTruePattern   = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*['"]__return_true['"]`)
	unauthPermissionCallbackBoolPattern   = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*true`)
	unauthPermissionCallbackInlinePattern = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*function\s*\(\s*\)\s*\{\s*return\s+true\s*;\s*\}`)
	unauthAjaxNoprivPattern               = regexp.MustCompile(`wp_ajax_nopriv_`)

	// Patterns for isExplicitlyBlocked - endpoints with __return_false or similar
	// These endpoints are BLOCKED and should not be included in analysis
	blockedPermissionCallbackFalsePattern   = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*['"]__return_false['"]`)
	blockedPermissionCallbackBoolPattern    = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*false\b`)
	blockedPermissionCallbackInlinePattern  = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*function\s*\([^)]*\)\s*\{\s*return\s+false\s*;\s*\}`)

	// Patterns for extractCapabilityCheck
	capabilityCurrentUserCanPattern    = regexp.MustCompile(`current_user_can\s*\(\s*['"]([a-z_]+)['"]\s*\)`)
	capabilityCurrentUserCanAltPattern = regexp.MustCompile(`current_user_can\s*\(\s*['"]([a-z_]+)['"]`)
	// Pattern for user_can($user, 'capability') - WordPress function with explicit user ID
	// Example: user_can( $current_user, 'manage_options' ), user_can( $user_id, 'edit_posts' )
	capabilityUserCanPattern = regexp.MustCompile(`user_can\s*\([^,]+,\s*['"]([a-z_]+)['"]`)
	capabilityKeyPattern     = regexp.MustCompile(`['"]capability['"]\s*=>\s*['"]([a-z_]+)['"]`)
	capabilityCapKeyPattern            = regexp.MustCompile(`['"]cap['"]\s*=>\s*['"]([a-z_]+)['"]`)
	// Pattern for filtered capabilities: current_user_can(apply_filters('filter_name', 'default_cap'))
	// This captures the DEFAULT capability which is the second argument to apply_filters
	capabilityApplyFiltersPattern = regexp.MustCompile(`current_user_can\s*\(\s*apply_filters\s*\(\s*['"][^'"]+['"]\s*,\s*['"]([a-z_]+)['"]`)

	// Patterns for admin capability checks - WordPress CORE only
	// IMPORTANT: is_admin() is NOT an auth check - it checks LOCATION (admin panel), not privileges!
	// An unauthenticated user visiting /wp-admin/ will have is_admin() === true
	// DO NOT use adminIsAdminPattern for auth level determination!
	adminIsAdminPattern        = regexp.MustCompile(`is_admin\s*\(\s*\)`) // LOCATION CHECK ONLY
	adminIsSuperAdminPattern   = regexp.MustCompile(`is_super_admin\s*\(\s*\)`)
	adminIsNetworkAdminPattern = regexp.MustCompile(`is_network_admin\s*\(\s*\)`)
	adminManageOptionsPattern  = regexp.MustCompile(`current_user_can\s*\(\s*['"]manage_options['"]`)
	adminAdministratorPattern  = regexp.MustCompile(`current_user_can\s*\(\s*['"]administrator['"]`)

	// Role-based admin check patterns
	// Matches: in_array('administrator', $user->roles)
	// Matches: in_array('administrator', $current_user->roles)
	// Matches: in_array('administrator', $user->roles, true)
	adminRoleInArrayPattern = regexp.MustCompile(`in_array\s*\(\s*['"]administrator['"]\s*,\s*\$[a-zA-Z_][a-zA-Z0-9_]*->roles`)

	// Generic admin capability check patterns (not plugin-specific)
	// These are common patterns used across many plugins
	genericAdminCanManagePattern      = regexp.MustCompile(`(?:can_manage|canManage)\s*\(\s*\)`)
	genericAdminIsAdminUserPattern    = regexp.MustCompile(`(?:is_admin_user|isAdminUser)\s*\(\s*\)`)
	genericAdminVerifyCapPattern      = regexp.MustCompile(`verify_(?:admin_)?capability|verifyAdminCapability`)
	genericAdminCheckPermissionPattern = regexp.MustCompile(`check(?:_)?(?:admin)?(?:_)?permission[s]?\s*\(\s*\)`)
	// Static class admin check patterns - common across many plugins
	// Matches: ClassName::isAdmin(), Helper::is_admin(), wfUtils::isAdmin()
	// This pattern is universal - many plugins wrap admin checks in static methods
	genericStaticAdminCheckPattern = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*::(?:is[_]?[Aa]dmin|has_admin_capability|check_admin|checkAdmin|isAdministrator)\s*\(\s*\)`)
	// NOTE: check_admin_referer() is NOT an admin auth check!
	// It's just a nonce verification function - a logged-in Subscriber can pass it.
	// We intentionally do NOT use this for admin auth detection.

	// Patterns for hasUserCheck
	userIsUserLoggedInPattern   = regexp.MustCompile(`is_user_logged_in\s*\(\s*\)`)
	userWpGetCurrentUserPattern = regexp.MustCompile(`wp_get_current_user\s*\(\s*\)`)
	userGetCurrentUserIdPattern = regexp.MustCompile(`get_current_user_id\s*\(\s*\)`)
	// auth_redirect() - Forces login, redirects non-logged-in users to login page
	userAuthRedirectPattern = regexp.MustCompile(`auth_redirect\s*\(\s*\)`)
	userCurrentUserCanPattern   = regexp.MustCompile(`current_user_can\s*\(`)

	// User/Role object has_cap patterns - common auth check pattern
	// Matches: $user->has_cap('capability'), $current_user->has_cap('manage_options')
	// Matches: $role->has_cap('edit_posts'), $roleObject->has_cap('administrator')
	// IMPORTANT: $wpdb->has_cap() is database capability, NOT auth - excluded by var name
	userObjectHasCapPattern = regexp.MustCompile(`\$(?:user|current_user|role|roleObject|this->user)\s*->\s*has_cap\s*\(\s*['"]([^'"]+)['"]`)

	// Static helper has_cap patterns - wraps current_user_can in many plugins
	// Matches: Helper::has_cap('capability'), SomeClass::has_cap('something')
	// This is a general pattern used by Rank Math, and other plugins
	staticHelperHasCapPattern = regexp.MustCompile(`[A-Z][a-zA-Z0-9_]*::\s*has_cap\s*\(\s*['"]([^'"]+)['"]`)

	// Patterns for hasNonceCheck
	nonceWpVerifyPattern  = regexp.MustCompile(`wp_verify_nonce\s*\(`)
	nonceCheckAjaxPattern = regexp.MustCompile(`check_ajax_referer\s*\(`)
	nonceCheckAdminPattern = regexp.MustCompile(`check_admin_referer\s*\(`)

	// Pattern for hasPermissionCallback
	permissionCallbackExistsPattern = regexp.MustCompile(`['"]permission_callback['"]`)

	// Patterns for ParsePermissionCallback
	parsePermCallbackStringPattern   = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*['"]([^'"]+)['"]`)
	parsePermCallbackArrayPattern    = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*\[\s*(?:__CLASS__|self|static|\$[^,]+),\s*['"]([^'"]+)['"]\s*\]`)
	parsePermCallbackArrayAltPattern = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*array\s*\(\s*(?:__CLASS__|self|static|\$[^,]+),\s*['"]([^'"]+)['"]\s*\)`)
	// More flexible pattern to handle variations in whitespace and object notation
	// Handles: array($this, 'method'), array( $this, 'method' ), [$this, 'method'],
	// array(__CLASS__, 'method'), [self, 'method'], etc.
	parsePermCallbackFlexiblePattern = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*(?:array\s*\(|\[)\s*(?:__CLASS__|self|static|\$\w+(?:->\w+)?|new\s+\w+\([^)]*\))\s*,\s*['"]([^'"]+)['"]`)
	// Updated to handle static/anonymous functions - captures function start position
	parsePermCallbackInlinePattern = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*(?:static\s+)?function\s*\([^)]*\)\s*\{`)
	// PHP 7.4+ arrow function pattern: fn($request) => $this->method($request) or fn() => expression
	// Captures the method name if it's a method call pattern
	parsePermCallbackArrowPattern = regexp.MustCompile(
		`['"]permission_callback['"]\s*=>\s*fn\s*\([^)]*\)\s*=>\s*` +
			`(?:\$this(?:->(?:[a-zA-Z_][a-zA-Z0-9_]*))*->([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|` + // $this->method($request) - captures method name
			`([^,\]]+))`, // fallback: capture whole expression
	)
	// Pattern to find current_user_can in permission callback context
	permCallbackCapabilityPattern = regexp.MustCompile(`current_user_can\s*\(\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)
	// Pattern to find user_can($user, 'capability') - WordPress function with explicit user ID
	// The capability is the SECOND argument
	// Example: user_can( $current_user, 'manage_options' )
	permCallbackUserCanPattern = regexp.MustCompile(`user_can\s*\([^,]+,\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)

	// Pattern to detect method delegation in inline permission callbacks
	// Matches: return $this->get_permission_callback($request)
	// Matches: return $this->controller->get_permission_callback($request)
	// This is a common pattern in WordPress REST controllers where the inline function
	// delegates to a method that contains the actual capability check
	permCallbackMethodDelegationPattern = regexp.MustCompile(
		`return\s+\$this(?:->(?:[a-zA-Z_][a-zA-Z0-9_]*))*->([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern to detect STATIC method delegation in inline permission callbacks
	// Matches: return ClassName::method_name($arg)
	// Matches: return Two_Factor_Core::rest_api_can_edit_user_and_update_two_factor_options($request['user_id'])
	// This is common in WordPress plugins where permission checks are centralized in a core class
	permCallbackStaticDelegationPattern = regexp.MustCompile(
		`return\s+([A-Za-z_][A-Za-z0-9_\\]*)::([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern to detect function call delegation in inline permission callbacks
	// Matches: return some_permission_function($args)
	// Matches: return can_do_something()
	// This handles standalone function calls (not method calls)
	permCallbackFunctionDelegationPattern = regexp.MustCompile(
		`return\s+([a-z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern for NormalizeCallback
	normalizeCallbackArrayPattern = regexp.MustCompile(`(?:\[|\barray\s*\()\s*\$?([^,]+),\s*['"]([^'"]+)['"]\s*(?:\]|\))`)
	// ::class constant pattern: [ClassName::class, 'method']
	normalizeClassConstPattern = regexp.MustCompile(`(?:\[|\barray\s*\()\s*\\?([A-Za-z_][A-Za-z0-9_\\]*)::class\s*,\s*['"]([^'"]+)['"]`)
	// Class property callbacks: [$this->handler, 'method']
	normalizeClassPropertyPattern = regexp.MustCompile(`(?:\[|\barray\s*\()\s*\$(?:this|self|static)\s*->\s*([a-zA-Z_][a-zA-Z0-9_>()-]*)\s*,\s*['"]([^'"]+)['"]`)
	// New object callbacks: [new SomeClass(), 'method']
	normalizeNewObjPattern = regexp.MustCompile(`\[\s*new\s+([A-Z][a-zA-Z0-9_\\]*)\s*\([^)]*\)\s*,\s*['"]([^'"]+)['"]`)

	// Patterns for finding function/method definitions
	// Matches: function name(...) { ... } or public function name(...) { ... }
	functionDefPattern = regexp.MustCompile(
		`(?:public|private|protected|static|\s)*\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*(?::\s*[a-zA-Z_][a-zA-Z0-9_|\\]*\s*)?\{`,
	)

	// Pre-compiled patterns for NormalizeCallback (memory optimization)
	normalizeMethodExtractPattern = regexp.MustCompile(`['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)

	// Pre-compiled patterns for findCapabilityInCallChain (memory optimization)
	callChainStaticCallPattern   = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_\\]*)::([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
	callChainInstanceCallPattern = regexp.MustCompile(`\$(?:this|[a-z_][a-zA-Z0-9_]*)(?:->(?:[a-zA-Z_][a-zA-Z0-9_]*))*->([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
	callChainFuncCallPattern     = regexp.MustCompile(`([a-z_][a-zA-Z0-9_]*)\s*\(`)
)

// getCapabilityLevel looks up a capability's auth level from configuration.
// This replaces the hardcoded capabilityLevels map with configuration-based lookup.
func getCapabilityLevel(capability string) (models.AuthLevel, bool) {
	if authConfig != nil {
		return authConfig.GetCapabilityLevel(capability)
	}
	// Fallback to default config if not set
	return config.New().GetCapabilityLevel(capability)
}

// lookupCapabilityAuthLevel looks up a capability and returns the auth level.
// It tries config-based lookup first, then falls back to the initialized capability map.
// Returns the auth level and true if found, or Subscriber and false if unknown.
func lookupCapabilityAuthLevel(capability string) (models.AuthLevel, bool) {
	// Try configuration-based lookup first
	if level, ok := getCapabilityLevel(capability); ok {
		return level, true
	}
	// Fallback to initialized capability levels map
	initCapabilityLevels()
	if level, ok := capabilityLevels[capability]; ok {
		return level, true
	}
	// Unknown capability - requires at least Subscriber
	return models.Subscriber, false
}

// capabilityLevels is kept for backwards compatibility.
// New code should use getCapabilityLevel() which reads from configuration.
// This map is built from the default configuration on first access.
var (
	capabilityLevels     map[string]models.AuthLevel
	capabilityLevelsOnce sync.Once
)

// initCapabilityLevels initializes the capabilityLevels map from configuration.
// This is called lazily to allow configuration changes before first use.
// Thread-safe via sync.Once - can be called from multiple goroutines.
func initCapabilityLevels() {
	capabilityLevelsOnce.Do(func() {
		capabilityLevels = make(map[string]models.AuthLevel)

		// Build from configuration
		cfg := authConfig
		if cfg == nil {
			cfg = config.New()
		}

		if cfg.Capabilities != nil {
			// Add core super admin capabilities
			for _, cap := range cfg.Capabilities.CoreSuperAdmin {
				capabilityLevels[cap] = models.SuperAdmin
			}

			// Add core admin capabilities
			for _, cap := range cfg.Capabilities.CoreAdmin {
				capabilityLevels[cap] = models.Admin
			}

			// Add core editor capabilities
			for _, cap := range cfg.Capabilities.CoreEditor {
				capabilityLevels[cap] = models.Editor
			}

			// Add core author capabilities
			for _, cap := range cfg.Capabilities.CoreAuthor {
				capabilityLevels[cap] = models.Author
			}

			// Add core contributor capabilities
			for _, cap := range cfg.Capabilities.CoreContributor {
				capabilityLevels[cap] = models.Contributor
			}

			// Add core subscriber capabilities
			for _, cap := range cfg.Capabilities.CoreSubscriber {
				capabilityLevels[cap] = models.Subscriber
			}

			// Add extended capabilities (if any were added)
			for cap, level := range cfg.Capabilities.ExtendedCapabilities {
				capabilityLevels[cap] = parseStringToAuthLevel(level)
			}

			// Add custom capabilities (highest priority)
			for cap, level := range cfg.Capabilities.Custom {
				capabilityLevels[cap] = parseStringToAuthLevel(level)
			}
		}

		// Add __return_true as unauthenticated indicator
		capabilityLevels["__return_true"] = models.Unauthenticated
	})
}

// parseStringToAuthLevel converts a string to AuthLevel.
func parseStringToAuthLevel(level string) models.AuthLevel {
	switch level {
	case "superadmin":
		return models.SuperAdmin
	case "admin":
		return models.Admin
	case "editor":
		return models.Editor
	case "author":
		return models.Author
	case "contributor":
		return models.Contributor
	case "subscriber":
		return models.Subscriber
	// Backwards compatibility: "user" maps to Subscriber
	case "user":
		return models.Subscriber
	default:
		return models.Unauthenticated
	}
}

// InferAuthLevel analyzes code to determine the required authentication level.
// Uses the 6-level WordPress role hierarchy:
// SuperAdmin > Admin > Editor > Author > Contributor > Subscriber > Unauthenticated
//
// Priority order:
// 1. Explicit unauthenticated patterns (highest priority - definite public access)
// 2. Capability checks (specific permission requirements mapped to appropriate level)
// 3. Admin-specific capability patterns (NOT is_admin() - that's location check)
// 4. User login checks (is_user_logged_in, etc.) -> Subscriber (lowest auth level)
// 5. Permission callback exists but unanalyzed -> Subscriber (conservative default)
// 6. Nonce verification ALONE does NOT determine auth level (CSRF protection only)
// 7. Default: Unauthenticated (no auth checks found)
func InferAuthLevel(code string) models.AuthLevel {
	// Ensure capability levels are initialized from configuration
	initCapabilityLevels()

	// 1. Check for explicit unauthenticated patterns (highest priority)
	if isExplicitlyUnauthenticated(code) {
		return models.Unauthenticated
	}

	// 2. Check for capability checks - most reliable auth indicator
	capability := extractCapabilityCheck(code)
	if capability != "" {
		// Use configuration-based lookup
		if level, ok := getCapabilityLevel(capability); ok {
			return level
		}
		// Fallback to hardcoded map for backwards compatibility
		if level, ok := capabilityLevels[capability]; ok {
			return level
		}
		// Apply pattern-based heuristics for unknown capabilities
		// This handles dynamically-generated capabilities
		if inferredLevel := inferCapabilityAuthLevel(capability); inferredLevel != models.Unauthenticated {
			return inferredLevel
		}
		// Unknown capability with no pattern match - assume Subscriber (requires login)
		return models.Subscriber
	}

	// 3. Check for admin-specific capability patterns
	// NOTE: This no longer includes is_admin() - that checks location, not auth
	if hasAdminCapabilityCheck(code) {
		return models.Admin
	}

	// 4. Check for is_user_logged_in() or similar explicit login checks
	// This indicates ANY logged-in user is required -> Subscriber level
	if hasUserLoginCheck(code) {
		return models.Subscriber
	}

	// 5. If permission_callback exists but we couldn't analyze it, assume Subscriber
	// This is conservative - better to assume auth required than not
	if hasPermissionCallback(code) {
		return models.Subscriber
	}

	// 6. IMPORTANT: Nonce verification (wp_verify_nonce, check_ajax_referer, etc.)
	// does NOT determine auth level by itself. Nonces are CSRF protection, not auth.
	// A public form can have a nonce without requiring login.
	// We do NOT check hasNonceCheck() here anymore.

	// 7. No auth checks found - endpoint is unauthenticated
	return models.Unauthenticated
}

// isExplicitlyUnauthenticated checks for patterns that indicate public access
func isExplicitlyUnauthenticated(code string) bool {
	return unauthPermissionCallbackTruePattern.MatchString(code) ||
		unauthPermissionCallbackBoolPattern.MatchString(code) ||
		unauthPermissionCallbackInlinePattern.MatchString(code) ||
		unauthAjaxNoprivPattern.MatchString(code)
}

// IsExplicitlyBlocked checks for patterns that indicate blocked/disabled access
// Endpoints with __return_false or similar patterns are inaccessible to ALL users
// including administrators. These endpoints should typically be excluded from analysis.
func IsExplicitlyBlocked(code string) bool {
	return blockedPermissionCallbackFalsePattern.MatchString(code) ||
		blockedPermissionCallbackBoolPattern.MatchString(code) ||
		blockedPermissionCallbackInlinePattern.MatchString(code)
}

// extractCapabilityCheck extracts the capability being checked
func extractCapabilityCheck(code string) string {
	// Use pre-compiled package-level patterns
	capabilityPatterns := []*regexp.Regexp{
		capabilityCurrentUserCanPattern,
		capabilityCurrentUserCanAltPattern,
		// user_can($user, 'capability') - WordPress function with explicit user ID
		capabilityUserCanPattern,
		capabilityKeyPattern,
		capabilityCapKeyPattern,
		// Pattern for filtered capabilities: current_user_can(apply_filters('filter', 'cap'))
		capabilityApplyFiltersPattern,
		// User/Role object has_cap patterns: $user->has_cap('capability')
		userObjectHasCapPattern,
		// Static helper has_cap patterns: Helper::has_cap('capability')
		staticHelperHasCapPattern,
	}

	for _, re := range capabilityPatterns {
		matches := re.FindStringSubmatch(code)
		if len(matches) >= 2 {
			return matches[1]
		}
	}

	return ""
}

// hasAdminCapabilityCheck checks for admin-level CAPABILITY checks only
// IMPORTANT: is_admin() is NOT included here - it checks admin panel LOCATION, not auth level
// An unauthenticated user viewing /wp-admin/ will have is_admin() return true
func hasAdminCapabilityCheck(code string) bool {
	// ============================================
	// WORDPRESS CORE PATTERNS (always active)
	// ============================================

	// is_super_admin() - checks if user is a super admin (multisite)
	if adminIsSuperAdminPattern.MatchString(code) {
		return true
	}
	// is_network_admin() in combination with capability check
	// Note: is_network_admin() alone just checks if in network admin area
	if adminIsNetworkAdminPattern.MatchString(code) && adminManageOptionsPattern.MatchString(code) {
		return true
	}
	// current_user_can('manage_options') - admin capability
	if adminManageOptionsPattern.MatchString(code) {
		return true
	}
	// current_user_can('administrator') - admin role check
	if adminAdministratorPattern.MatchString(code) {
		return true
	}
	// in_array('administrator', $user->roles) - role-based admin check
	// Common pattern across many plugins
	if adminRoleInArrayPattern.MatchString(code) {
		return true
	}
	// NOTE: check_admin_referer() is intentionally NOT checked here.
	// It's a nonce verification, not an admin privilege check.
	// A logged-in Subscriber can pass check_admin_referer() with the right nonce.

	// ============================================
	// GENERIC PATTERNS (always active)
	// These are common patterns used across many plugins
	// ============================================

	// Generic admin capability check wrappers: can_manage(), canManage()
	if genericAdminCanManagePattern.MatchString(code) {
		return true
	}
	// is_admin_user(), isAdminUser()
	if genericAdminIsAdminUserPattern.MatchString(code) {
		return true
	}
	// verify_admin_capability / verifyAdminCapability
	if genericAdminVerifyCapPattern.MatchString(code) {
		return true
	}
	// Generic check_permission/checkPermission patterns
	if genericAdminCheckPermissionPattern.MatchString(code) {
		return true
	}
	// Static class admin check patterns: ClassName::isAdmin(), Helper::is_admin()
	// Universal pattern used across many plugins (Wordfence, etc.)
	if genericStaticAdminCheckPattern.MatchString(code) {
		return true
	}

	// ============================================
	// CONFIGURABLE CUSTOM PATTERNS (from configuration)
	// Users can add their own patterns via config
	// ============================================

	if authConfig != nil && authConfig.AdminPatterns != nil {
		// Custom patterns from configuration
		if len(authConfig.AdminPatterns.CustomPatterns) > 0 {
			for _, pattern := range authConfig.AdminPatterns.CustomPatterns {
				if re, err := regexp.Compile(pattern); err == nil {
					if re.MatchString(code) {
						return true
					}
				}
			}
		}
	}

	return false
}

// hasAdminCheck is DEPRECATED - kept for backwards compatibility
// Use hasAdminCapabilityCheck instead which doesn't include is_admin()
func hasAdminCheck(code string) bool {
	// NOTE: is_admin() removed - it checks location, not authentication
	return adminIsSuperAdminPattern.MatchString(code) ||
		adminIsNetworkAdminPattern.MatchString(code) ||
		adminManageOptionsPattern.MatchString(code) ||
		adminAdministratorPattern.MatchString(code) ||
		adminRoleInArrayPattern.MatchString(code)
}

// hasUserLoginCheck checks for explicit user login requirements
// These patterns directly indicate that a logged-in user is required
func hasUserLoginCheck(code string) bool {
	// is_user_logged_in() - explicit login check
	if userIsUserLoggedInPattern.MatchString(code) {
		return true
	}
	// auth_redirect() - forces login redirect for non-authenticated users
	if userAuthRedirectPattern.MatchString(code) {
		return true
	}
	// get_current_user_id() followed by a comparison/validation
	// Just calling get_current_user_id() doesn't mean auth is required,
	// but using it in a condition like "if (!get_current_user_id())" does
	// For now, we consider its presence as a login indicator
	if userGetCurrentUserIdPattern.MatchString(code) {
		// Additional check: is it being used in a conditional?
		// Patterns like: if (!get_current_user_id()) or get_current_user_id() === 0
		if strings.Contains(code, "!get_current_user_id") ||
			strings.Contains(code, "get_current_user_id() === 0") ||
			strings.Contains(code, "get_current_user_id() == 0") ||
			strings.Contains(code, "get_current_user_id() > 0") ||
			strings.Contains(code, "0 === get_current_user_id") ||
			strings.Contains(code, "0 == get_current_user_id") {
			return true
		}
	}
	return false
}

// hasUserCheck checks for user-level authentication checks
// DEPRECATED: Use hasUserLoginCheck for more accurate detection
func hasUserCheck(code string) bool {
	// NOTE: current_user_can is handled separately by extractCapabilityCheck
	return userIsUserLoggedInPattern.MatchString(code) ||
		userWpGetCurrentUserPattern.MatchString(code) ||
		userGetCurrentUserIdPattern.MatchString(code)
}

// hasNonceCheck checks for nonce verification
func hasNonceCheck(code string) bool {
	return nonceWpVerifyPattern.MatchString(code) ||
		nonceCheckAjaxPattern.MatchString(code) ||
		nonceCheckAdminPattern.MatchString(code)
}

// hasPermissionCallback checks if permission_callback exists
func hasPermissionCallback(code string) bool {
	// Use pre-compiled package-level pattern
	return permissionCallbackExistsPattern.MatchString(code)
}

// inferCapabilityAuthLevel applies pattern-based heuristics to determine auth level
// for capabilities that are not in the known capability list.
// This handles plugin-specific capabilities like manage_woocommerce, manage_elementor, etc.
// Returns Unauthenticated if no pattern matches (caller should then use default User level).
//
// GENERAL-PURPOSE PATTERNS (works across all WordPress plugins):
// - manage_* : Admin level (WordPress pattern for plugin/feature administration)
// - install_*, activate_*, update_*, delete_* + plugins/themes : Admin level
// - *_users (create, edit, delete, promote, remove) : Admin level
// - shop_manager related : Admin level (WooCommerce and similar e-commerce)
func inferCapabilityAuthLevel(capability string) models.AuthLevel {
	capability = strings.ToLower(capability)

	// ============================================
	// ADMIN-LEVEL PATTERNS
	// These patterns indicate administrator-level access requirements
	// ============================================

	// Pattern: manage_* (manage_woocommerce, manage_elementor, manage_bookings, etc.)
	// The manage_ prefix is the standard WordPress pattern for plugin administration
	// capabilities. WordPress core uses manage_options, plugins follow this convention.
	if strings.HasPrefix(capability, "manage_") {
		return models.Admin
	}

	// Pattern: *_plugins or *_themes (install_plugins, activate_plugins, delete_themes, etc.)
	// Any capability ending with _plugins or _themes is admin-level
	if strings.HasSuffix(capability, "_plugins") || strings.HasSuffix(capability, "_themes") {
		return models.Admin
	}

	// Pattern: install_*, activate_*, update_*, delete_* + common entities
	// These are WordPress core patterns for entity management
	adminActionPrefixes := []string{
		"install_",
		"activate_",
		"update_",
		"delete_",
		"unfiltered_",
	}
	for _, prefix := range adminActionPrefixes {
		if strings.HasPrefix(capability, prefix) {
			return models.Admin
		}
	}

	// Pattern: *_users (create_users, edit_users, delete_users, promote_users, remove_users)
	// User management is always admin-level
	if strings.HasSuffix(capability, "_users") {
		return models.Admin
	}

	// Pattern: E-commerce shop capabilities
	// Common in WooCommerce, Easy Digital Downloads, and similar e-commerce plugins
	// Examples: edit_shop_orders, publish_shop_coupons, view_shop_reports, manage_shop_settings
	// Also: shop_manager, shop_admin
	if strings.Contains(capability, "_shop_") ||
		strings.Contains(capability, "shop_") ||
		strings.HasSuffix(capability, "_shop") {
		return models.Admin
	}

	// Pattern: WooCommerce-specific capabilities
	// Examples: view_woocommerce_reports, manage_woocommerce
	if strings.Contains(capability, "woocommerce") {
		return models.Admin
	}

	// Pattern: Backup/restore plugin capabilities
	// Common in BackWPup, UpdraftPlus, and similar backup plugins
	// Examples: backwpup, backwpup_jobs_start, backwpup_restore, updraftplus_*
	backupKeywords := []string{"backwpup", "backup", "restore", "updraft", "migrate", "duplicator"}
	for _, keyword := range backupKeywords {
		if strings.Contains(capability, keyword) {
			return models.Admin
		}
	}

	// Pattern: edit_theme_options, customize_* (Customizer access)
	// These control site appearance and are admin-level
	if strings.HasPrefix(capability, "customize_") ||
		capability == "edit_theme_options" {
		return models.Admin
	}

	// Pattern: setup_* (setup_network, etc.)
	// Setup capabilities are admin-level
	if strings.HasPrefix(capability, "setup_") {
		return models.Admin
	}

	// Pattern: upgrade_* (upgrade_network, etc.)
	// Upgrade capabilities are admin-level
	if strings.HasPrefix(capability, "upgrade_") {
		return models.Admin
	}

	// ============================================
	// EDITOR-LEVEL PATTERNS
	// These patterns indicate editor-level access requirements
	// ============================================

	// Pattern: *_others_* capabilities (edit_others_*, delete_others_*, etc.)
	// Editing/deleting OTHER users' content requires Editor level
	// Examples: edit_others_products, delete_others_watermarks, edit_others_shop_orders
	if strings.Contains(capability, "_others_") {
		return models.Editor
	}

	// Pattern: *_private_* capabilities (read_private_*, edit_private_*, etc.)
	// Accessing private content requires Editor level
	// Examples: read_private_posts, edit_private_pages
	if strings.Contains(capability, "_private_") {
		return models.Editor
	}

	// Pattern: moderate_* (moderate_comments, etc.)
	// Moderation requires Editor level
	if strings.HasPrefix(capability, "moderate_") {
		return models.Editor
	}

	// ============================================
	// NO MATCH - Return Unauthenticated to signal caller should use default
	// ============================================
	return models.Unauthenticated
}

// ParsePermissionCallback extracts and analyzes the permission callback
func ParsePermissionCallback(code string) (string, models.AuthLevel) {
	// Use pre-compiled package-level patterns
	// Order matters: try more specific patterns first, then flexible pattern as fallback
	permCallbackPatterns := []*regexp.Regexp{
		parsePermCallbackStringPattern,
		parsePermCallbackArrayPattern,
		parsePermCallbackArrayAltPattern,
		parsePermCallbackFlexiblePattern, // Flexible pattern catches variations
	}

	for _, re := range permCallbackPatterns {
		matches := re.FindStringSubmatch(code)
		if len(matches) >= 2 {
			callback := matches[1]
			// Note: The callback function analysis is done separately
			// by ParsePermissionCallbackWithContext which has access to full file
			level := InferAuthLevel(code)
			return callback, level
		}
	}

	// Check for inline function using pre-compiled pattern
	matches := parsePermCallbackInlinePattern.FindStringSubmatch(code)
	if len(matches) >= 2 {
		fnBody := matches[1]
		level := InferAuthLevel(fnBody)
		return "anonymous", level
	}

	// Check for PHP 7.4+ arrow function pattern
	arrowMatches := parsePermCallbackArrowPattern.FindStringSubmatch(code)
	if len(arrowMatches) >= 2 {
		// Arrow function exists - method delegation likely requires auth
		methodName := arrowMatches[1]
		if methodName != "" {
			if isStandardPermissionCallback(methodName) {
				return "arrow:" + methodName, models.Subscriber
			}
			return "arrow:" + methodName, models.Subscriber
		}
		return "arrow_expr", models.Subscriber
	}

	return "", models.Unauthenticated
}

// ParsePermissionCallbackWithContext analyzes permission callback with full file context
// This allows finding and analyzing the actual callback function definition
func ParsePermissionCallbackWithContext(code string, fullFileContent string) (string, models.AuthLevel) {
	// Use pre-compiled package-level patterns
	// Order matters: try more specific patterns first, then flexible pattern as fallback
	permCallbackPatterns := []*regexp.Regexp{
		parsePermCallbackStringPattern,
		parsePermCallbackArrayPattern,
		parsePermCallbackArrayAltPattern,
		parsePermCallbackFlexiblePattern, // Flexible pattern catches variations
	}

	for _, re := range permCallbackPatterns {
		matches := re.FindStringSubmatch(code)
		if len(matches) >= 2 {
			callback := matches[1]

			// Check for __return_true which is explicitly unauthenticated
			if callback == "__return_true" {
				return callback, models.Unauthenticated
			}

			// PRIORITY 1: Try to find and analyze the callback function body
			// This is the most reliable method because it directly examines the
			// actual capability check (e.g., current_user_can('manage_woocommerce'))
			// rather than relying on naming conventions
			if funcBody := findFunctionBody(callback, fullFileContent); funcBody != "" {
				level := InferAuthLevel(funcBody)
				// If we found a specific auth level, use it
				if level != models.Unauthenticated {
					return callback, level
				}
				// Even if function body analysis returns Unauthenticated,
				// the presence of a named callback suggests auth is required
				if callback != "" {
					// Check name-based admin indicators as final confirmation
					if isAdminPermissionCallbackName(callback) {
						return callback, models.Admin
					}
					return callback, models.Subscriber
				}
			}

			// PRIORITY 2: Check if callback name indicates admin-level permission check
			// Use this only when function body analysis failed (function not found)
			if isAdminPermissionCallbackName(callback) {
				return callback, models.Admin
			}

			// PRIORITY 3: Check if callback name follows standard WordPress REST API
			// permission patterns. These patterns (like *_permissions_check) require auth.
			// Use this only as fallback when function body is not available.
			if isStandardPermissionCallback(callback) {
				return callback, models.Subscriber
			}

			// PRIORITY 4: Fallback - analyze just the local code context
			level := InferAuthLevel(code)
			// If no explicit auth pattern found but callback exists, assume Subscriber level
			// (a permission_callback was specified, so auth is likely required)
			if level == models.Unauthenticated && callback != "" {
				level = models.Subscriber
			}
			return callback, level
		}
	}

	// Check for inline function (static function or anonymous function)
	// Find the position of the function start
	loc := parsePermCallbackInlinePattern.FindStringIndex(code)
	if loc != nil {
		// Find the opening brace
		bracePos := strings.Index(code[loc[0]:], "{")
		if bracePos >= 0 {
			startPos := loc[0] + bracePos
			// Extract function body using brace matching
			fnBody := extractBracedContent(code, startPos)
			if fnBody != "" {
				// Check for current_user_can in the function body
				capMatches := permCallbackCapabilityPattern.FindStringSubmatch(fnBody)
				if len(capMatches) >= 2 {
					capability := capMatches[1]
					// Use configuration-based lookup first
					if level, ok := getCapabilityLevel(capability); ok {
						return "anonymous", level
					}
					// Fallback to initialized capability levels map
					initCapabilityLevels()
					if level, ok := capabilityLevels[capability]; ok {
						return "anonymous", level
					}
					// Unknown capability, but requires login
					return "anonymous", models.Subscriber
				}

				// Check for user_can($user, 'capability') pattern
				// This is the same as current_user_can but with explicit user ID
				userCanMatches := permCallbackUserCanPattern.FindStringSubmatch(fnBody)
				if len(userCanMatches) >= 2 {
					capability := userCanMatches[1]
					// Use configuration-based lookup first
					if level, ok := getCapabilityLevel(capability); ok {
						return "anonymous", level
					}
					// Fallback to initialized capability levels map
					initCapabilityLevels()
					if level, ok := capabilityLevels[capability]; ok {
						return "anonymous", level
					}
					// Unknown capability, but requires login
					return "anonymous", models.Subscriber
				}

				// Check for method delegation pattern
				// This handles patterns like: return $this->get_permission_callback($request)
				// Common in WordPress REST controllers (WP_REST_Controller subclasses)
				delegationMatches := permCallbackMethodDelegationPattern.FindStringSubmatch(fnBody)
				if len(delegationMatches) >= 2 {
					delegatedMethodName := delegationMatches[1]
					// Try to find and analyze the delegated method
					if delegatedMethodBody := findFunctionBody(delegatedMethodName, fullFileContent); delegatedMethodBody != "" {
						// Analyze the delegated method for capability checks
						delegatedCapMatches := permCallbackCapabilityPattern.FindStringSubmatch(delegatedMethodBody)
						if len(delegatedCapMatches) >= 2 {
							capability := delegatedCapMatches[1]
							if level, ok := getCapabilityLevel(capability); ok {
								return "delegated:" + delegatedMethodName, level
							}
							initCapabilityLevels()
							if level, ok := capabilityLevels[capability]; ok {
								return "delegated:" + delegatedMethodName, level
							}
							return "delegated:" + delegatedMethodName, models.Subscriber
						}
						// Also check for user_can($user, 'capability') pattern
						delegatedUserCanMatches := permCallbackUserCanPattern.FindStringSubmatch(delegatedMethodBody)
						if len(delegatedUserCanMatches) >= 2 {
							capability := delegatedUserCanMatches[1]
							if level, ok := getCapabilityLevel(capability); ok {
								return "delegated:" + delegatedMethodName, level
							}
							initCapabilityLevels()
							if level, ok := capabilityLevels[capability]; ok {
								return "delegated:" + delegatedMethodName, level
							}
							return "delegated:" + delegatedMethodName, models.Subscriber
						}
						// Analyze the full delegated method body
						level := InferAuthLevel(delegatedMethodBody)
						// If no explicit auth pattern found in delegated method,
						// but a delegation pattern exists, assume at least User level
						if level == models.Unauthenticated {
							level = models.Subscriber
						}
						return "delegated:" + delegatedMethodName, level
					}
					// Method name suggests permission check - assume requires auth
					// Check both standard REST API patterns (isStandardPermissionCallback) and
					// general permission check patterns (isPermissionCheckFunctionName)
					// Examples: user_can_view, user_can_manage contain "_can_" pattern
					if isStandardPermissionCallback(delegatedMethodName) || isPermissionCheckFunctionName(delegatedMethodName) {
						return "delegated:" + delegatedMethodName, models.Subscriber
					}
				}

				// Check for STATIC method delegation pattern
				// This handles patterns like: return Two_Factor_Core::rest_api_can_edit_user_and_update_two_factor_options($request['user_id'])
				// Common in WordPress plugins where permission checks are centralized in a core class
				staticDelegationMatches := permCallbackStaticDelegationPattern.FindStringSubmatch(fnBody)
				if len(staticDelegationMatches) >= 3 {
					className := staticDelegationMatches[1]
					methodName := staticDelegationMatches[2]
					fullMethodRef := className + "::" + methodName

					// Try to find the static method in the current file content
					if staticMethodBody := findStaticMethodBody(className, methodName, fullFileContent); staticMethodBody != "" {
						// Recursively analyze the static method for capability checks
						level := findCapabilityInCallChain(staticMethodBody, fullFileContent, 0)
						if level != models.Unauthenticated {
							return "static:" + fullMethodRef, level
						}
					}

					// Method name suggests permission check - assume requires auth
					// Common patterns: can_*, has_*, check_*, verify_*, *_permission*, etc.
					if isPermissionCheckFunctionName(methodName) {
						return "static:" + fullMethodRef, models.Subscriber
					}

					// A static method call in permission_callback that we couldn't analyze
					// is likely a permission check - be conservative and assume requires auth
					return "static:" + fullMethodRef, models.Subscriber
				}

				// Check for standalone function call delegation
				// This handles patterns like: return some_permission_function($args)
				functionDelegationMatches := permCallbackFunctionDelegationPattern.FindStringSubmatch(fnBody)
				if len(functionDelegationMatches) >= 2 {
					funcName := functionDelegationMatches[1]

					// Skip WordPress built-in functions that don't indicate auth
					if !isNonAuthFunction(funcName) {
						// Try to find the function in the current file
						if funcBody := findFunctionBody(funcName, fullFileContent); funcBody != "" {
							level := findCapabilityInCallChain(funcBody, fullFileContent, 0)
							if level != models.Unauthenticated {
								return "function:" + funcName, level
							}
						}

						// Function name suggests permission check
						if isPermissionCheckFunctionName(funcName) {
							return "function:" + funcName, models.Subscriber
						}
					}
				}

				// Analyze the full function body
				level := InferAuthLevel(fnBody)
				return "anonymous", level
			}
		}
	}

	// Check for PHP 7.4+ arrow function pattern: fn($request) => $this->method($request)
	// Arrow functions don't have braces, so we need a different approach
	arrowMatches := parsePermCallbackArrowPattern.FindStringSubmatch(code)
	if len(arrowMatches) >= 2 {
		// Group 1 is the method name if it's a $this->method() call
		// Group 2 is the fallback expression
		methodName := arrowMatches[1]
		if methodName != "" {
			// Try to find and analyze the delegated method
			if delegatedMethodBody := findFunctionBody(methodName, fullFileContent); delegatedMethodBody != "" {
				// Analyze the delegated method for capability checks
				delegatedCapMatches := permCallbackCapabilityPattern.FindStringSubmatch(delegatedMethodBody)
				if len(delegatedCapMatches) >= 2 {
					capability := delegatedCapMatches[1]
					if level, ok := getCapabilityLevel(capability); ok {
						return "arrow:" + methodName, level
					}
					initCapabilityLevels()
					if level, ok := capabilityLevels[capability]; ok {
						return "arrow:" + methodName, level
					}
					return "arrow:" + methodName, models.Subscriber
				}
				// Also check for user_can($user, 'capability') pattern
				delegatedUserCanMatches := permCallbackUserCanPattern.FindStringSubmatch(delegatedMethodBody)
				if len(delegatedUserCanMatches) >= 2 {
					capability := delegatedUserCanMatches[1]
					if level, ok := getCapabilityLevel(capability); ok {
						return "arrow:" + methodName, level
					}
					initCapabilityLevels()
					if level, ok := capabilityLevels[capability]; ok {
						return "arrow:" + methodName, level
					}
					return "arrow:" + methodName, models.Subscriber
				}
				// Analyze the full delegated method body
				level := InferAuthLevel(delegatedMethodBody)
				// If no explicit auth pattern found in delegated method,
				// but a delegation pattern exists, assume at least User level
				if level == models.Unauthenticated {
					level = models.Subscriber
				}
				return "arrow:" + methodName, level
			}
			// Method name suggests permission check - assume requires auth
			// Check both standard REST API patterns and general permission check patterns
			// (consistent with inline function method delegation handling)
			if isStandardPermissionCallback(methodName) || isPermissionCheckFunctionName(methodName) {
				return "arrow:" + methodName, models.Subscriber
			}
			// Named method but couldn't find body - assume User level
			return "arrow:" + methodName, models.Subscriber
		}

		// Fallback: check expression for patterns (group 2)
		if len(arrowMatches) > 2 && arrowMatches[2] != "" {
			expr := arrowMatches[2]
			// Check if expression contains current_user_can
			capMatches := permCallbackCapabilityPattern.FindStringSubmatch(expr)
			if len(capMatches) >= 2 {
				capability := capMatches[1]
				if level, ok := getCapabilityLevel(capability); ok {
					return "arrow_expr", level
				}
				initCapabilityLevels()
				if level, ok := capabilityLevels[capability]; ok {
					return "arrow_expr", level
				}
				return "arrow_expr", models.Subscriber
			}
			// Also check for user_can($user, 'capability') pattern
			userCanMatches := permCallbackUserCanPattern.FindStringSubmatch(expr)
			if len(userCanMatches) >= 2 {
				capability := userCanMatches[1]
				if level, ok := getCapabilityLevel(capability); ok {
					return "arrow_expr", level
				}
				initCapabilityLevels()
				if level, ok := capabilityLevels[capability]; ok {
					return "arrow_expr", level
				}
				return "arrow_expr", models.Subscriber
			}
			// Arrow function exists but couldn't analyze - assume User level
			return "arrow_expr", models.Subscriber
		}
	}

	return "", models.Unauthenticated
}

// findFunctionBody finds a function/method definition and extracts its body
// Returns the function body including the opening brace content
// Optimized: Uses string operations instead of dynamic regex compilation
func findFunctionBody(funcName string, content string) string {
	// Search for "function funcName(" pattern using string operations
	searchPattern := "function " + funcName
	searchStart := 0

	for {
		idx := strings.Index(content[searchStart:], searchPattern)
		if idx < 0 {
			return ""
		}
		pos := searchStart + idx

		// Verify this is a function declaration (followed by optional whitespace and '(')
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

		// Verify it's not part of a larger word (check character before "function")
		if pos > 0 {
			prevChar := content[pos-1]
			// Skip whitespace backwards to find actual previous char
			checkPos := pos - 1
			for checkPos > 0 && (content[checkPos] == ' ' || content[checkPos] == '\t' || content[checkPos] == '\n' || content[checkPos] == '\r') {
				checkPos--
			}
			if checkPos >= 0 {
				prevChar = content[checkPos]
				// Allow modifiers or punctuation before "function"
				if !isValidFunctionPrefix(prevChar) && prevChar != 'c' { // 'c' for "static"
					searchStart = i
					continue
				}
			}
		}

		// Find the opening brace after the parameter list
		bracePos := strings.Index(content[i:], "{")
		if bracePos < 0 {
			searchStart = i
			continue
		}

		startPos := i + bracePos
		return extractBracedContent(content, startPos)
	}
}

// isValidFunctionPrefix checks if a character can precede "function" keyword
func isValidFunctionPrefix(c byte) bool {
	// Valid: whitespace, newline, semicolon, brace, or word chars for modifiers
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
		c == ';' || c == '{' || c == '}' || c == '>' || // punctuation
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') // for modifiers like "public", "static"
}

// extractBracedContent extracts content within matching braces starting at position
func extractBracedContent(content string, startPos int) string {
	if startPos >= len(content) || content[startPos] != '{' {
		return ""
	}

	depth := 0
	inString := false
	stringChar := byte(0)
	endPos := startPos

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
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				endPos = i + 1
				return content[startPos:endPos]
			}
		}
	}

	// If we couldn't find matching brace, return what we have (up to 2000 chars)
	maxLen := startPos + 2000
	if maxLen > len(content) {
		maxLen = len(content)
	}
	return content[startPos:maxLen]
}

// isAdminPermissionCallbackName checks if a permission callback name suggests admin-level access
func isAdminPermissionCallbackName(callback string) bool {
	callback = strings.ToLower(callback)

	// Normalize separators
	normalized := strings.ReplaceAll(callback, "-", "_")
	normalized = strings.ReplaceAll(normalized, "::", "_")

	// Strong indicators of admin permission callbacks
	adminIndicators := []string{
		"admin_permission",
		"check_admin",
		"admin_check",
		"require_admin",
		"is_admin",
		"can_manage",
		"manage_permission",
		"manage_check",
		"permission_admin",
		"editor_permission",
		"current_user_can_manage",
		"verify_admin",
		"check_permission_admin",
	}

	for _, indicator := range adminIndicators {
		if strings.Contains(normalized, indicator) {
			return true
		}
	}

	return false
}

// isStandardPermissionCallback checks if a callback name follows standard WordPress REST API
// permission callback naming conventions that require authentication.
// This is a general-purpose pattern that works across ALL WordPress plugins.
//
// Standard patterns include:
// - *_permissions_check (WP REST API standard: get_items_permissions_check, create_item_permissions_check)
// - *_permission_check (singular form)
// - check_*_permission* (prefix form: check_read_permission, check_edit_permissions)
// - can_* (capability check methods: can_edit, can_delete)
// - verify_* (verification methods usually require auth)
// - has_permission* (permission check methods)
//
// These patterns indicate the endpoint requires authentication (at minimum User level).
func isStandardPermissionCallback(callback string) bool {
	callback = strings.ToLower(callback)

	// Normalize separators
	normalized := strings.ReplaceAll(callback, "-", "_")
	normalized = strings.ReplaceAll(normalized, "::", "_")

	// Standard WordPress REST API permission callback patterns
	// These patterns are used across the entire WordPress ecosystem
	standardPatterns := []string{
		"_permissions_check", // WP REST API: get_items_permissions_check, create_item_permissions_check
		"_permission_check",  // Singular: get_item_permission_check
		"permissions_check",  // Ends with permissions_check
		"permission_check",   // Ends with permission_check
		"check_permission",   // check_permission, check_permissions
		"has_permission",     // has_permission, has_permissions
		"verify_permission",  // verify_permission methods
		"validate_request",   // request validation often includes auth
	}

	for _, pattern := range standardPatterns {
		if strings.Contains(normalized, pattern) {
			return true
		}
	}

	// Also check for patterns that START with certain prefixes (common convention)
	startPatterns := []string{
		"can_",     // can_edit, can_delete, can_view
		"check_",   // check_read, check_write (when followed by action)
		"verify_",  // verify_user, verify_access
		"require_", // require_auth, require_permission
	}

	for _, prefix := range startPatterns {
		if strings.HasPrefix(normalized, prefix) {
			// But exclude certain false positives
			if !strings.Contains(normalized, "nonce") { // can check nonce without auth
				return true
			}
		}
	}

	return false
}

// NormalizeCallback normalizes callback notation to a readable format
func NormalizeCallback(callback string) string {
	callback = strings.TrimSpace(callback)

	// Handle empty or null callbacks
	if callback == "" || callback == "null" || callback == "''" || callback == "\"\"" {
		return "unknown"
	}

	// Strip surrounding quotes from simple string callbacks
	if len(callback) >= 2 {
		if (callback[0] == '\'' && callback[len(callback)-1] == '\'') ||
			(callback[0] == '"' && callback[len(callback)-1] == '"') {
			callback = callback[1 : len(callback)-1]
		}
	}

	// Handle truncated array patterns - try to extract method name
	// Pattern: "array( $this" or "[ $this" or "[$this" or "array($this"
	if strings.HasPrefix(callback, "array(") || strings.HasPrefix(callback, "[") {
		// Try to extract method name from the partial array (using pre-compiled pattern)
		if methodMatch := normalizeMethodExtractPattern.FindStringSubmatch(callback); len(methodMatch) >= 2 {
			if strings.Contains(callback, "$this") {
				return "this::" + methodMatch[1]
			} else if strings.Contains(callback, "__CLASS__") {
				return "__CLASS__::" + methodMatch[1]
			} else if strings.Contains(callback, "self::") || strings.Contains(callback, "static::") {
				return "static::" + methodMatch[1]
			}
			return methodMatch[1]
		}
		// Couldn't extract method - mark as array callback
		if strings.Contains(callback, "$this") {
			return "this::callback"
		}
		return "array_callback"
	}

	// Handle ::class constant pattern using pre-compiled pattern
	classConstMatches := normalizeClassConstPattern.FindStringSubmatch(callback)
	if len(classConstMatches) >= 3 {
		className := classConstMatches[1]
		// Remove leading backslash if present
		className = strings.TrimPrefix(className, "\\")
		return className + "::" + classConstMatches[2]
	}

	// Handle class property callbacks using pre-compiled pattern
	classMatches := normalizeClassPropertyPattern.FindStringSubmatch(callback)
	if len(classMatches) >= 3 {
		// Clean up property reference
		property := strings.ReplaceAll(classMatches[1], "->", "::")
		return property + "::" + classMatches[2]
	}

	// Handle new object callbacks using pre-compiled pattern
	newMatches := normalizeNewObjPattern.FindStringSubmatch(callback)
	if len(newMatches) >= 3 {
		return newMatches[1] + "::" + newMatches[2]
	}

	// Handle array notation using pre-compiled package-level pattern
	matches := normalizeCallbackArrayPattern.FindStringSubmatch(callback)
	if len(matches) >= 3 {
		className := matches[1]
		// Handle ::class suffix if present (fallback for unhandled cases)
		if strings.HasSuffix(className, "::class") {
			className = strings.TrimSuffix(className, "::class")
			className = strings.TrimPrefix(className, "\\")
		}
		return className + "::" + matches[2]
	}

	// Clean up remaining quoted strings
	callback = strings.Trim(callback, "'\"")

	return callback
}

// findStaticMethodBody finds a static method definition in a class and extracts its body.
// It handles patterns like: public static function methodName(...) { ... }
// Optimized: Uses string operations instead of dynamic regex compilation
func findStaticMethodBody(className, methodName, content string) string {
	// Search for "function methodName" pattern, then verify "static" appears before it
	searchPattern := "function " + methodName
	searchStart := 0

	for {
		idx := strings.Index(content[searchStart:], searchPattern)
		if idx < 0 {
			break
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

		// Check for "static" keyword before "function" (within reasonable range)
		// Look back up to 50 characters for modifiers
		lookBack := pos
		if lookBack > 50 {
			lookBack = 50
		}
		prefix := content[pos-lookBack : pos]
		if !strings.Contains(prefix, "static") {
			searchStart = i
			continue
		}

		// Find the opening brace after the parameter list
		bracePos := strings.Index(content[i:], "{")
		if bracePos < 0 {
			searchStart = i
			continue
		}

		startPos := i + bracePos
		return extractBracedContent(content, startPos)
	}

	// Fallback: try finding any function with this name
	return findFunctionBody(methodName, content)
}

// maxRecursionDepth limits how deep we trace function calls
const maxRecursionDepth = 5

// findCapabilityInCallChain recursively searches through function bodies
// to find capability checks like current_user_can(), is_user_logged_in(), etc.
// This handles cases where permission_callback delegates to helper functions
// that in turn call other functions containing the actual capability check.
func findCapabilityInCallChain(funcBody, fullContent string, depth int) models.AuthLevel {
	// Prevent infinite recursion
	if depth > maxRecursionDepth {
		return models.Unauthenticated
	}

	// Priority 1: Direct capability check in this function
	capability := extractCapabilityCheck(funcBody)
	if capability != "" {
		if level, ok := getCapabilityLevel(capability); ok {
			return level
		}
		initCapabilityLevels()
		if level, ok := capabilityLevels[capability]; ok {
			return level
		}
		// Unknown capability - try pattern-based inference
		if level := inferCapabilityAuthLevel(capability); level != models.Unauthenticated {
			return level
		}
		// Unknown capability but it's a capability check - at least Subscriber
		return models.Subscriber
	}

	// Priority 2: Admin-level capability check patterns
	if hasAdminCapabilityCheck(funcBody) {
		return models.Admin
	}

	// Priority 3: User login checks
	if hasUserLoginCheck(funcBody) {
		return models.Subscriber
	}

	// Priority 4: Look for function calls that might contain capability checks
	// Find static method calls: ClassName::method() (using pre-compiled pattern)
	staticMatches := callChainStaticCallPattern.FindAllStringSubmatch(funcBody, -1)
	for _, match := range staticMatches {
		if len(match) >= 3 {
			calledMethod := match[2]
			// Try to find the method body
			if methodBody := findStaticMethodBody(match[1], calledMethod, fullContent); methodBody != "" {
				level := findCapabilityInCallChain(methodBody, fullContent, depth+1)
				if level != models.Unauthenticated {
					return level
				}
			}
			// If method name suggests permission check, treat as authenticated
			if isPermissionCheckFunctionName(calledMethod) {
				return models.Subscriber
			}
		}
	}

	// Find instance method calls: $this->method() or $var->method() (using pre-compiled pattern)
	instanceMatches := callChainInstanceCallPattern.FindAllStringSubmatch(funcBody, -1)
	for _, match := range instanceMatches {
		if len(match) >= 2 {
			calledMethod := match[1]
			// Try to find the method body
			if methodBody := findFunctionBody(calledMethod, fullContent); methodBody != "" {
				level := findCapabilityInCallChain(methodBody, fullContent, depth+1)
				if level != models.Unauthenticated {
					return level
				}
			}
			// If method name suggests permission check, treat as authenticated
			if isPermissionCheckFunctionName(calledMethod) {
				return models.Subscriber
			}
		}
	}

	// Find standalone function calls: function_name() (using pre-compiled pattern)
	funcMatches := callChainFuncCallPattern.FindAllStringSubmatch(funcBody, -1)
	for _, match := range funcMatches {
		if len(match) >= 2 {
			calledFunc := match[1]
			// Skip known non-auth functions and PHP built-ins
			if isNonAuthFunction(calledFunc) {
				continue
			}
			// Try to find the function body
			if funcBodyFound := findFunctionBody(calledFunc, fullContent); funcBodyFound != "" {
				level := findCapabilityInCallChain(funcBodyFound, fullContent, depth+1)
				if level != models.Unauthenticated {
					return level
				}
			}
			// If function name suggests permission check, treat as authenticated
			if isPermissionCheckFunctionName(calledFunc) {
				return models.Subscriber
			}
		}
	}

	return models.Unauthenticated
}

// isPermissionCheckFunctionName checks if a function/method name suggests it performs permission checking.
// This is a GENERAL-PURPOSE check that works across all WordPress plugins.
func isPermissionCheckFunctionName(name string) bool {
	name = strings.ToLower(name)

	// Normalize separators
	normalized := strings.ReplaceAll(name, "-", "_")

	// Patterns that indicate permission checking
	permissionIndicators := []string{
		"can_",           // can_edit, can_delete, can_manage
		"_can_",          // user_can_edit, rest_api_can_
		"has_permission", // has_permission, has_permissions
		"check_permission",
		"verify_permission",
		"permission_check",
		"permissions_check",
		"has_cap",      // has_capability
		"check_cap",    // check_capability
		"verify_cap",   // verify_capability
		"is_allowed",   // is_allowed_to_*
		"can_access",   // can_access_*
		"check_access", // check_access_*
		"user_can",     // user_can_edit, current_user_can
		"require_cap",  // require_capability
	}

	for _, indicator := range permissionIndicators {
		if strings.Contains(normalized, indicator) {
			return true
		}
	}

	// Check for patterns that END with permission indicators
	endPatterns := []string{
		"_permission",
		"_permissions",
		"_capability",
		"_capabilities",
	}

	for _, pattern := range endPatterns {
		if strings.HasSuffix(normalized, pattern) {
			return true
		}
	}

	return false
}

// nonAuthFuncs contains PHP/WordPress built-in functions that do NOT relate to authentication.
// These should be skipped when tracing call chains.
// Package-level initialization avoids recreating the map on each call.
var nonAuthFuncs = map[string]bool{
	// WordPress utility functions
	"apply_filters": true, "do_action": true, "add_action": true, "add_filter": true,
	"esc_html": true, "esc_attr": true, "esc_url": true, "sanitize_text_field": true,
	"wp_json_encode": true, "wp_kses": true, "absint": true, "intval": true,
	"sprintf": true, "printf": true,
	"_": true, "__": true, "_e": true, "esc_html__": true, "esc_attr__": true,
	"_x": true, "_ex": true, "_n": true,
	// PHP built-ins - type checks
	"isset": true, "empty": true, "is_array": true, "is_string": true,
	"is_object": true, "is_numeric": true,
	// PHP built-ins - array functions
	"in_array": true, "array_key": true, "array_merge": true, "array_map": true,
	"array_keys": true, "array_values": true, "array_filter": true, "array_unique": true,
	"array_slice": true, "array_pop": true, "array_shift": true, "array_push": true, "count": true,
	// PHP built-ins - string functions
	"strlen": true, "strpos": true, "substr": true, "trim": true, "strtolower": true,
	"strtoupper": true, "explode": true, "implode": true, "str_replace": true,
	"ucfirst": true, "ucwords": true,
	// PHP built-ins - encoding/decoding
	"json_decode": true, "json_encode": true, "base64_encode": true, "base64_decode": true,
	"urlencode": true, "urldecode": true, "rawurlencode": true, "rawurldecode": true,
	"http_build_query": true, "parse_url": true, "parse_str": true,
	// PHP built-ins - regex and output
	"preg_match": true, "var_export": true, "print_r": true,
	// PHP built-ins - date/time
	"date": true, "time": true,
	// PHP built-ins - reflection and existence checks
	"get_class": true, "method_exists": true, "function_exists": true, "class_exists": true,
	"defined": true, "define": true, "constant": true,
	// PHP built-ins - filesystem
	"file_exists": true, "is_readable": true, "is_writable": true,
	"dirname": true, "basename": true, "realpath": true, "pathinfo": true, "glob": true,
	// PHP built-ins - error handling
	"error_log": true, "trigger_error": true, "set_error_handler": true,
	// PHP built-ins - math
	"min": true, "max": true, "abs": true, "floor": true, "ceil": true, "round": true,
	// PHP built-ins - random and hashing
	"rand": true, "mt_rand": true, "uniqid": true, "md5": true, "sha1": true, "hash": true,
}

// isNonAuthFunction checks if a function name is a known PHP/WordPress built-in
// that does NOT relate to authentication.
func isNonAuthFunction(name string) bool {
	return nonAuthFuncs[name]
}

// InferAuthLevelFromCallback checks the callback function body for auth patterns.
// This handles the case where wp_ajax_nopriv_ endpoints have internal auth checks
// (W7 fix: the #1 cause of false positives at 25-35%).
// It reads the callback body from the file content and scans for auth patterns.
// Returns the highest auth level found, or Unauthenticated if no auth checks detected.
func InferAuthLevelFromCallback(callbackName string, fileContent string, allContents map[string]string) models.AuthLevel {
	// Normalize the callback name to extract the actual method/function name
	funcName := extractCallbackFuncName(callbackName)
	if funcName == "" {
		return models.Unauthenticated
	}

	// Try to find the callback body in the primary file
	funcBody := findFunctionBody(funcName, fileContent)

	// If not found, search all other files
	if funcBody == "" && allContents != nil {
		for _, content := range allContents {
			funcBody = findFunctionBody(funcName, content)
			if funcBody != "" {
				break
			}
		}
	}

	if funcBody == "" {
		return models.Unauthenticated
	}

	// Run InferAuthLevel on the callback body
	level := InferAuthLevel(funcBody)
	if level > models.Unauthenticated {
		return level
	}

	// Nonce verification (wp_verify_nonce, check_ajax_referer) is CSRF protection,
	// not authentication. It does NOT imply the endpoint requires login.
	// Unauthenticated users can obtain nonces via wp_localize_script output.

	// Follow one level of method delegation patterns in the callback body.
	// Patterns: $this->check_auth(), self::validate(), $this->is_valid_call()
	delegatedLevel := followCallbackDelegation(funcBody, fileContent, allContents)
	if delegatedLevel > level {
		level = delegatedLevel
	}

	return level
}

// EnhancePermissionCallback follows permission_callback delegation chains deeper.
// When permission_callback => [$this, 'check_permissions'], it reads check_permissions
// body and follows up to 2 levels of delegation to find actual capability checks (W5 fix).
func EnhancePermissionCallback(callbackName string, fileContent string, allContents map[string]string) models.AuthLevel {
	funcName := extractCallbackFuncName(callbackName)
	if funcName == "" {
		return models.Unauthenticated
	}

	// Try to find the callback body in the primary file
	funcBody := findFunctionBody(funcName, fileContent)

	// If not found, search all other files
	if funcBody == "" && allContents != nil {
		for _, content := range allContents {
			funcBody = findFunctionBody(funcName, content)
			if funcBody != "" {
				// Use this file as the context for deeper analysis
				fileContent = content
				break
			}
		}
	}

	if funcBody == "" {
		return models.Unauthenticated
	}

	// Use findCapabilityInCallChain which already handles recursive delegation
	// up to maxRecursionDepth (5 levels)
	return findCapabilityInCallChain(funcBody, fileContent, 0)
}

// followCallbackDelegation follows method delegation patterns in a callback body.
// Looks for patterns like $this->check_auth(), self::validate(), $this->is_valid_call()
// and analyzes the delegated method for auth checks.
func followCallbackDelegation(funcBody string, fileContent string, allContents map[string]string) models.AuthLevel {
	bestLevel := models.Unauthenticated

	// Check instance method calls: $this->method() or $this->property->method()
	instanceMatches := callChainInstanceCallPattern.FindAllStringSubmatch(funcBody, 5)
	for _, match := range instanceMatches {
		if len(match) < 2 {
			continue
		}
		calledMethod := match[1]
		if isNonAuthFunction(calledMethod) {
			continue
		}

		// Try to find in primary file
		methodBody := findFunctionBody(calledMethod, fileContent)
		// Try other files if not found
		if methodBody == "" && allContents != nil {
			for _, content := range allContents {
				methodBody = findFunctionBody(calledMethod, content)
				if methodBody != "" {
					break
				}
			}
		}

		if methodBody != "" {
			level := InferAuthLevel(methodBody)
			if level > bestLevel {
				bestLevel = level
			}
			// Also check for nonce in delegated method
			if bestLevel == models.Unauthenticated && hasNonceCheck(methodBody) {
				bestLevel = models.Subscriber
			}
		}
	}

	// Check static method calls: ClassName::method()
	staticMatches := callChainStaticCallPattern.FindAllStringSubmatch(funcBody, 5)
	for _, match := range staticMatches {
		if len(match) < 3 {
			continue
		}
		calledMethod := match[2]
		if isNonAuthFunction(calledMethod) {
			continue
		}

		// Try to find the static method in the primary file first
		methodBody := findStaticMethodBody(match[1], calledMethod, fileContent)
		if methodBody == "" {
			methodBody = findFunctionBody(calledMethod, fileContent)
		}
		// Try other files
		if methodBody == "" && allContents != nil {
			for _, content := range allContents {
				methodBody = findStaticMethodBody(match[1], calledMethod, content)
				if methodBody == "" {
					methodBody = findFunctionBody(calledMethod, content)
				}
				if methodBody != "" {
					break
				}
			}
		}

		if methodBody != "" {
			level := InferAuthLevel(methodBody)
			if level > bestLevel {
				bestLevel = level
			}
			if bestLevel == models.Unauthenticated && hasNonceCheck(methodBody) {
				bestLevel = models.Subscriber
			}
		}
	}

	return bestLevel
}

// extractCallbackFuncName extracts the actual function/method name from various callback formats.
// Handles: 'method_name', array($this, 'method'), [$this, 'method'], ClassName::method,
// [ClassName::class, 'method'], 'this::method', NormalizeCallback output like 'this::method'
func extractCallbackFuncName(callback string) string {
	callback = strings.TrimSpace(callback)
	if callback == "" || callback == "unknown" || callback == "anonymous" {
		return ""
	}

	// Handle NormalizeCallback output format: "this::method" or "ClassName::method"
	if strings.Contains(callback, "::") {
		parts := strings.SplitN(callback, "::", 2)
		if len(parts) == 2 {
			method := strings.TrimSpace(parts[1])
			// Remove any trailing content after method name
			method = strings.Trim(method, "'\"")
			if method != "" && method != "callback" && method != "__invoke" {
				return method
			}
		}
	}

	// Handle array notation: array($this, 'method') or [$this, 'method']
	arrayMatch := normalizeCallbackArrayPattern.FindStringSubmatch(callback)
	if len(arrayMatch) >= 3 {
		return arrayMatch[2]
	}

	// Handle ::class constant: [ClassName::class, 'method']
	classConstMatch := normalizeClassConstPattern.FindStringSubmatch(callback)
	if len(classConstMatch) >= 3 {
		return classConstMatch[2]
	}

	// Handle simple quoted string: 'function_name' or "function_name"
	cleaned := strings.Trim(callback, "'\"")
	if cleaned != "" && !strings.ContainsAny(cleaned, " \t\n(){}[],$") {
		return cleaned
	}

	return ""
}

// InferAuthLevelFromCallbackWithAST wraps InferAuthLevelFromCallback with AST-backed
// cross-file resolution for callbacks whose body isn't in the same file.
func InferAuthLevelFromCallbackWithAST(callbackName string, fileContent string, allContents map[string]string, astCtx *wpast.ASTContext) models.AuthLevel {
	level := InferAuthLevelFromCallback(callbackName, fileContent, allContents)

	if astCtx == nil || !astCtx.Available {
		return level
	}

	ref := wpast.CallbackRef{
		Type:     "function",
		FuncName: callbackName,
	}
	if strings.Contains(callbackName, "::") {
		parts := strings.SplitN(callbackName, "::", 2)
		ref = wpast.CallbackRef{
			Type:       "static_method",
			ClassName:  parts[0],
			MethodName: parts[1],
		}
	}

	astLevel := astCtx.Resolver.ResolveAuthLevel(ref)
	if astLevel < level {
		return astLevel
	}

	return level
}

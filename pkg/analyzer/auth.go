package analyzer

import (
	"regexp"
	"sort"
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
	blockedPermissionCallbackFalsePattern  = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*['"]__return_false['"]`)
	blockedPermissionCallbackBoolPattern   = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*false\b`)
	blockedPermissionCallbackInlinePattern = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*function\s*\([^)]*\)\s*\{\s*return\s+false\s*;\s*\}`)

	// Role-based admin check pattern, consumed by guard.go's check table.
	// Matches: in_array('administrator', $user->roles)
	// Matches: in_array('administrator', $current_user->roles)
	// Matches: in_array('administrator', $user->roles, true)
	//
	// WP_User::$roles is populated by core from the site's role map, so this is
	// a membership test in core's own vocabulary rather than a guess from a name.
	adminRoleInArrayPattern = regexp.MustCompile(`in_array\s*\(\s*['"]administrator['"]\s*,\s*\$[a-zA-Z_][a-zA-Z0-9_]*->roles`)

	// NOTE: check_admin_referer(), check_ajax_referer() and wp_verify_nonce()
	// are deliberately absent from this file. wp_create_nonce($action) is
	// wp_hash($tick . '|' . $action . '|' . $uid . '|' . $token), and
	// get_current_user_id() is 0 for every anonymous visitor, so the nonce
	// minted for an action a plugin has declared reachable by uid 0 is the same
	// for all of them and is published in page output by wp_localize_script or
	// wp_nonce_field. A nonce is CSRF provenance; it establishes nothing at all
	// about the caller's role. Two clauses that read Subscriber out of one have
	// been removed from the delegation walk below.

	// NOTE: is_admin() is absent for a different reason. It reports LOCATION --
	// that the request is being served from wp-admin, which includes every
	// admin-ajax.php request, wp_ajax_nopriv_ ones among them -- and core
	// documents it as unsuitable for validating secured requests.

	// NOTE: the five "generic admin" patterns that used to live here are gone:
	// can_manage()/canManage(), is_admin_user()/isAdminUser(),
	// verify_capability, check_permission()/checkPermissions(), and
	// ClassName::isAdmin(). Each read Admin out of an identifier's spelling.
	// WordPress attaches no meaning to a PHP function's name, and the spelling
	// can be wrong in both halves at once: a measured Postman\PostmanUtils
	// ::isAdmin() is `current_user_can( SOME_CONSTANT ) && is_admin()`, whose
	// own docblock quotes core saying is_admin() "is not suitable for
	// validating secured requests". This repository had already measured and
	// removed one rule of this class -- see TestAjaxNameDoesNotPromoteToAdmin,
	// where ~50 English verbs promoted 818 of 3478 logged-in AJAX endpoints.

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
	// NOTE: five patterns that used to sit here are gone with the code that
	// consumed them: two that scraped the first current_user_can/user_can literal
	// out of a callback body regardless of whether it gated anything, and three
	// that recognised `return $this->m()`, `return C::m()` and `return m()` so a
	// name could be guessed from. Delegation is now followed through the call
	// graph in delegatedAuthLevel, which asks whether the call gates rather than
	// what it is called.

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

// InferAuthLevel reports the authentication level the code it is handed
// requires, from the checks that GATE that code.
//
// The rule is a single one: a level comes from a check that stops the request
// when it fails, and from nothing else. What used to sit beside that rule read a
// level out of the mere PRESENCE of something --
//
//	is_super_admin() anywhere in the blob                    -> Admin
//	a method spelled Foo::isAdmin() or check_permission()    -> Admin
//	is_user_logged_in() anywhere, decorative or not          -> Subscriber
//	the string "permission_callback" anywhere                -> Subscriber
//	a capability literal anywhere, in an array or a comment  -> that level
//
// -- and every one of those made a reachable, unguarded sink read as gated,
// which is the error direction that hides a vulnerability rather than merely
// adding noise. Measured: `{ if ( is_super_admin() ) { $extra = 1; }
// update_option( 'o', $_POST['v'] ); }` reported Admin with no gating guard
// anywhere in it.
//
// Worse, the qualifier meant to hold those rules back read backwards. Step 3
// was gated on !hasOnlyNonGatingCapabilityChecks(code), and that helper
// returned FALSE when the guard analysis found nothing at all -- so the
// qualifier passed exactly when the admin signal was one guard.go could not
// see, which is every signal those rules matched.
//
// The predicates that genuinely say something about the caller
// (is_user_logged_in, is_super_admin, auth_redirect, get_current_user_id,
// in_array('administrator', $u->roles)) now go through the same control-flow
// classifier current_user_can goes through, because PHP does not care which
// function produced the boolean. They count when they gate and not when they
// decorate.
//
// Priority order:
//  1. Explicit unauthenticated markers -- wp_ajax_nopriv_, permission_callback
//     => __return_true -- the plugin itself saying the endpoint is public.
//  2. The checks that gate. Among several capability gates the LOWEST wins:
//     passing any one of them is enough to get in, so the weakest is what an
//     attacker needs. A login-level gate is a floor and is consulted only when
//     no capability gate was found, so a defensive `if ( ! is_user_logged_in() )
//     { wp_die(); }` cannot pull a resolved manage_options gate down to
//     Subscriber the way a flat minimum over both pools would.
//  3. Admin patterns the operator configured, if any.
//  4. Default: Unauthenticated.
func InferAuthLevel(code string) models.AuthLevel {
	return InferAuthLevelInFile(code, "")
}

// InferAuthLevelInFile is InferAuthLevel with the enclosing file available, so
// that a capability held in a class constant or a property can be resolved to
// the literal it holds. PHP evaluates current_user_can()'s argument before the
// call, so `private $capability = 'edit_posts'; ... current_user_can(
// $this->capability )` asks exactly what writing the literal inline would ask.
func InferAuthLevelInFile(code string, fileContent string) models.AuthLevel {
	return inferAuthLevel(code, fileContent, ScopeRequest)
}

// InferAuthLevelInScope is InferAuthLevel for a body that is not what WordPress
// dispatched. In a helper a `return` ends the helper and nothing else, so a
// check whose only consequence is a return does not gate the helper's caller.
func InferAuthLevelInScope(code string, fileContent string, scope BodyScope) models.AuthLevel {
	return inferAuthLevel(code, fileContent, scope)
}

func inferAuthLevel(code string, fileContent string, scope BodyScope) models.AuthLevel {
	// Ensure capability levels are initialized from configuration
	initCapabilityLevels()

	if isExplicitlyUnauthenticated(code) {
		return models.Unauthenticated
	}

	if level, ok := gatedAuthLevel(code, fileContent, scope); ok {
		return level
	}

	// An operator analysing a codebase they know can name their own admin
	// wrappers here. This is the one presence-based rule left in the file; it is
	// empty by default, and it is opt-in precisely because presence is not
	// authorization.
	if authConfig != nil && authConfig.AdminPatterns != nil {
		for _, pattern := range authConfig.AdminPatterns.CustomPatterns {
			if re, err := regexp.Compile(pattern); err == nil && re.MatchString(code) {
				return models.Admin
			}
		}
	}

	// Nonce verification is deliberately not consulted. Nonces are CSRF
	// protection, not authentication: a public form can carry one.
	return models.Unauthenticated
}

// gatedAuthLevel resolves the checks that gate a body into the level a caller
// needs in order to get past them.
func gatedAuthLevel(code string, fileContent string, scope BodyScope) (models.AuthLevel, bool) {
	guards, selfContained := analyseGuards(code, scope)
	if !selfContained {
		// The blob holds whole function declarations, so the checks inside it
		// gate those functions and say nothing about the blob. Answering from
		// them would attribute one function's guard to code it never protected
		// -- and would make the answer depend on how wide a slice the caller
		// happened to take.
		return 0, false
	}

	capBest := models.AuthLevel(-1)
	capGated := false
	loginBest := models.AuthLevel(-1)

	for _, g := range guards {
		if g.Kind != GuardFunction && g.Kind != GuardAlternative {
			continue
		}
		if g.IsIdentity {
			if g.Kind == GuardFunction {
				if loginBest < 0 || g.Implied < loginBest {
					loginBest = g.Implied
				}
			}
			continue
		}
		capGated = true
		if g.Kind != GuardFunction {
			// Gated, but the same condition names another way past that we
			// cannot resolve, so the capability is not what entry costs.
			continue
		}
		if lvl, ok := capabilityGuardLevel(g, code, fileContent); ok {
			if capBest < 0 || lvl < capBest {
				capBest = lvl
			}
		}
	}

	if capGated {
		if capBest >= 0 {
			return capBest, true
		}
		// Gated, but by a capability held in a symbol that nothing in reach
		// resolves. Something is required; Subscriber is the floor, because
		// current_user_can() on a logged-out WP_User(0) is false for every
		// capability except 'exist'.
		return models.Subscriber, true
	}
	if loginBest >= 0 {
		return loginBest, true
	}
	return 0, false
}

// capabilityGuardLevel resolves one capability gate, following a symbol to the
// literal it holds when the code in reach makes that unambiguous.
func capabilityGuardLevel(g CapabilityGuard, body string, fileContent string) (models.AuthLevel, bool) {
	if g.Capability != "" {
		return resolveCapabilityForSubject(g.Capability, g.HasSubjectArg)
	}
	if g.CapabilityExpr == "" {
		return 0, false
	}
	best := models.AuthLevel(-1)
	for _, lit := range symbolLiterals(g.CapabilityExpr, body, fileContent) {
		lvl, ok := resolveCapabilityForSubject(lit, g.HasSubjectArg)
		if !ok {
			continue
		}
		// Several candidate literals mean several ways in, and the cheapest is
		// what an attacker needs.
		if best < 0 || lvl < best {
			best = lvl
		}
	}
	if best < 0 {
		return 0, false
	}
	return best, true
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

// hasPermissionCallback checks if permission_callback exists
func hasPermissionCallback(code string) bool {
	// Use pre-compiled package-level pattern
	return permissionCallbackExistsPattern.MatchString(code)
}

// ParsePermissionCallback extracts and analyzes the permission callback from a
// route definition when no wider file context is available.
//
// Without a body to read there is nothing to say, because a callback's NAME
// carries no privilege: core's own
// WP_REST_Posts_Controller::get_items_permissions_check() returns true for
// anonymous readers of a public post type, so even a name that follows core's
// convention exactly tells you nothing. Callers holding the file should use
// ParsePermissionCallbackWithContext.
func ParsePermissionCallback(code string) (string, models.AuthLevel) {
	return ParsePermissionCallbackWithContext(code, code)
}

// ParsePermissionCallbackWithContext identifies a route's permission_callback
// and resolves the level it enforces, reading the callback's body out of the
// file the route is registered in.
//
// Everything here answers from what the callback DOES. The name-shaped
// fallbacks that used to stand behind the body lookup are gone:
//
//	a name containing "check_admin" / "can_manage" / "is_admin"  -> Admin
//	a name starting can_ / check_ / verify_ / require_           -> Subscriber
//	any callback at all whose body could not be found            -> Subscriber
//
// The first is an over-restriction machine: the identical body
// `return ! empty( $request->get_param('token') );` reported Admin when it lived
// in another file and Unauthenticated when it lived in this one, purely because
// of how the method was spelled. The other two report Subscriber for callbacks
// that may assert nothing -- measured over the corpus, 46% of the
// permission-callback methods declared outside the registering file check no
// identity whatsoever.
//
// When the body cannot be found the answer is Unauthenticated. That
// under-restricts a callback whose real check lives in a file this function
// cannot reach, which is noise; reporting Subscriber over-restricts one that
// checks nothing, which hides a reachable endpoint. Recovering the exactness
// needs cross-file resolution through the class hierarchy, which belongs to the
// caller that owns the plugin's file map, not here.
func ParsePermissionCallbackWithContext(code string, fullFileContent string) (string, models.AuthLevel) {
	// Order matters: try more specific patterns first, then the flexible one.
	for _, re := range []*regexp.Regexp{
		parsePermCallbackStringPattern,
		parsePermCallbackArrayPattern,
		parsePermCallbackArrayAltPattern,
		parsePermCallbackFlexiblePattern,
	} {
		matches := re.FindStringSubmatch(code)
		if len(matches) < 2 {
			continue
		}
		callback := matches[1]
		if callback == "__return_true" {
			return callback, models.Unauthenticated
		}
		body := findFunctionBody(callback, fullFileContent)
		return callback, permissionCallbackBodyLevel(body, fullFileContent)
	}

	// An inline closure: 'permission_callback' => function ( $r ) { ... }
	if loc := parsePermCallbackInlinePattern.FindStringIndex(code); loc != nil {
		if bracePos := strings.Index(code[loc[0]:], "{"); bracePos >= 0 {
			if fnBody := extractBracedContent(code, loc[0]+bracePos); fnBody != "" {
				return "anonymous", permissionCallbackBodyLevel(fnBody, fullFileContent)
			}
		}
	}

	// An arrow function: 'permission_callback' => fn( $r ) => $this->m( $r )
	if arrowMatches := parsePermCallbackArrowPattern.FindStringSubmatch(code); len(arrowMatches) >= 2 {
		if methodName := arrowMatches[1]; methodName != "" {
			body := findFunctionBody(methodName, fullFileContent)
			return "arrow:" + methodName, permissionCallbackBodyLevel(body, fullFileContent)
		}
		// The whole arrow body is one expression and core reads its value, so
		// the expression is the gate. This branch used to return Subscriber for
		// every arrow function regardless of what it said.
		if len(arrowMatches) > 2 && strings.TrimSpace(arrowMatches[2]) != "" {
			if lvl, ok := predicateLevel(arrowMatches[2]); ok {
				return "arrow_expr", lvl
			}
			return "arrow_expr", models.Unauthenticated
		}
	}

	return "", models.Unauthenticated
}

// permissionCallbackBodyLevel resolves what a permission callback enforces.
//
// A permission callback refuses in two ways and both are read here. It may
// terminate -- `if ( ! current_user_can( X ) ) { return new WP_Error(...); }` --
// which is the ordinary gating analysis. Or it may simply RETURN the verdict:
// WP_REST_Server::dispatch_request() calls the callback and, on a falsy result
// or a WP_Error, answers rest_forbidden without ever invoking the route's own
// callback. So `return current_user_can( 'manage_options' );` requires
// manage_options exactly as the terminating form does, with core rather than
// the plugin doing the refusing. That is core behaviour and therefore holds for
// every plugin; it is also why this is the one place a returned check may raise
// a level, and why InferAuthLevel does not do the same for a handler that
// merely computes a boolean.
func permissionCallbackBodyLevel(funcBody string, fullFileContent string) models.AuthLevel {
	return resolvePermissionBodyLevel(funcBody, fullFileContent, nil, 0)
}

// resolvePermissionBodyLevel resolves a permission-callback-shaped body: the
// checks that gate it, the verdict it returns, or a check one call away that
// this body's own control flow depends on.
func resolvePermissionBodyLevel(funcBody, fileContent string, allContents map[string]string, depth int) models.AuthLevel {
	if funcBody == "" || depth > maxRecursionDepth {
		return models.Unauthenticated
	}
	if level := InferAuthLevelInFile(funcBody, fileContent); level != models.Unauthenticated {
		return level
	}
	if level, ok := permissionCallbackLevel(funcBody); ok {
		return level
	}
	// The body asserts nothing about who is calling. Trust that.
	//
	// This used to fall through to Subscriber on the reasoning that "the
	// presence of a named callback suggests auth is required". It does not. A
	// permission callback is free to check anything, and plenty check something
	// that is not identity at all:
	//
	//   public function impersonate_user_permissions_check( $request ) {
	//       $name  = $request->get_param( 'username' );
	//       $token = $request->get_param( 'multi_manager_wp_login_token' );
	//       if ( empty( $name ) || empty( $token ) ) { return new WP_Error(...); }
	//       return $this->impersonate_token_check( $name, $token );
	//   }
	//
	// Everything it inspects comes from the request, so it establishes no
	// privilege whatsoever -- which is precisely why CVE-2024-11028 is
	// exploitable unauthenticated. Reporting Subscriber there overstates the
	// privilege an attacker needs, which is the error direction that makes a
	// real, reachable vulnerability look gated and get dismissed.
	//
	// A callback that delegates its real check elsewhere is still followed,
	// because that is a case where the identity assertion exists and simply
	// lives one call away.
	return delegatedAuthLevel(funcBody, fileContent, allContents, delegationInPermissionCallback, depth)
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

// findCapabilityInCallChain follows a permission callback's delegation chain,
// answering only from the bodies it can actually read.
//
// It used to answer from names as well. A callee whose name contained "can_",
// "_can_", "has_cap", "is_allowed", "can_access", "check_access" or ended in
// "_permission" produced Subscriber; a body that merely mentioned
// manage_options anywhere produced Admin; a body that merely mentioned
// is_user_logged_in produced Subscriber. All three are the presence rule
// wearing another costume, and the record of what the first one costs is one
// function away in this file: impersonate_user_permissions_check is called in a
// gating position, is spelled exactly like a permission check, and inspects
// only request parameters.
func findCapabilityInCallChain(funcBody, fullContent string, depth int) models.AuthLevel {
	return resolvePermissionBodyLevel(funcBody, fullContent, nil, depth)
}

// delegationContext says what a call's RESULT means in the body that makes it.
type delegationContext int

const (
	// delegationInHandler: the body is an endpoint callback. Returning a
	// delegate's boolean ends the handler; it refuses nothing.
	delegationInHandler delegationContext = iota
	// delegationInPermissionCallback: the body's return value is the verdict
	// core acts on, so `return $this->check( $r );` makes check() the gate.
	delegationInPermissionCallback
)

// delegatedAuthLevel follows the calls a body makes and reports the level of
// the ones that actually gate it.
//
// A delegate's level transfers to its caller only when failing the delegate
// stops the caller, and there are exactly two ways for that to happen:
//
//   - The CALL SITE gates. `if ( ! $this->check() ) { wp_die(); }`, or -- in a
//     permission callback, whose return value core reads as the verdict --
//     `return $this->check( $request );`. The caller's own control flow does
//     the refusing, so whatever the delegate asserts is the requirement.
//
//   - The DELEGATE ends the request itself: its guard finishes in wp_die, exit,
//     throw or wp_send_json_*, which stop the request from any call depth. A
//     guard whose only consequence is `return` does not qualify, because
//     `return` hands control back to the caller, which carries on:
//
//     function handle() { save( $_POST['v'] ); $this->render_admin_notice(); }
//     function render_admin_notice() { if ( ! current_user_can('manage_options') ) return; echo 'hi'; }
//
//     That handler is completely unguarded and used to report Admin, because
//     the delegate's level was inherited for any call appearing anywhere in the
//     body -- not only calls before the sink, and not only calls whose result
//     was consumed.
//
// Among the delegates that do gate, the MINIMUM wins. Sequential gates are
// conjunctive, so the exact answer would be their maximum; but the maximum is
// the over-restricting direction, and this walk collects up to five calls that
// may not all be gates. The minimum is the cheapest way in that we can see.
//
// A delegate that resolves to the very body we started from is skipped.
// findFunctionBody matches on the bare method name, so
// `$this->file_manager->temp_file_delete( $id )` inside temp_file_delete()
// re-finds temp_file_delete() and the handler inherits its own checks. The test
// is body identity rather than name equality, so a genuine same-named delegate
// on a collaborator class -- Foo::check() calling $this->guard->check() -- is
// still followed.
func delegatedAuthLevel(funcBody, fileContent string, allContents map[string]string, ctx delegationContext, depth int) models.AuthLevel {
	if funcBody == "" || depth >= maxRecursionDepth {
		return models.Unauthenticated
	}
	mask := maskNonCode(funcBody)
	decls := FindFunctionDeclarations(mask)

	best := models.AuthLevel(-1)
	consider := func(callStart, parenClose int, methodBody string) {
		if methodBody == "" || methodBody == funcBody {
			return
		}
		var level models.AuthLevel
		if callSiteGates(mask, decls, callStart, parenClose, ctx) {
			level = resolvePermissionBodyLevel(methodBody, fileContent, allContents, depth+1)
		} else {
			// The call is unconditional, so only a delegate that ends the
			// request on its own can gate anything here.
			level = InferAuthLevelInScope(methodBody, fileContent, ScopeHelper)
		}
		if level == models.Unauthenticated {
			return
		}
		if best < 0 || level < best {
			best = level
		}
	}

	// Instance method calls: $this->method() or $this->property->method().
	for _, m := range callChainInstanceCallPattern.FindAllStringSubmatchIndex(mask, 5) {
		calledMethod := mask[m[2]:m[3]]
		if isNonAuthFunction(calledMethod) {
			continue
		}
		parenClose := matchDelimiter(mask, m[1]-1, '(', ')')
		if parenClose < 0 {
			continue
		}
		body, _ := findCallbackBodyAcross(calledMethod, fileContent, allContents)
		consider(m[0], parenClose, body)
	}

	// Static method calls: ClassName::method().
	for _, m := range callChainStaticCallPattern.FindAllStringSubmatchIndex(mask, 5) {
		className, calledMethod := mask[m[2]:m[3]], mask[m[4]:m[5]]
		if isNonAuthFunction(calledMethod) {
			continue
		}
		parenClose := matchDelimiter(mask, m[1]-1, '(', ')')
		if parenClose < 0 {
			continue
		}
		body := findStaticMethodBody(className, calledMethod, fileContent)
		if body == "" {
			body, _ = findCallbackBodyAcross(calledMethod, fileContent, allContents)
		}
		consider(m[0], parenClose, body)
	}

	if best < 0 {
		return models.Unauthenticated
	}
	return best
}

// callSiteGates reports whether the caller's control flow depends on this
// call's result.
func callSiteGates(mask string, decls []FuncDecl, callStart, parenClose int, ctx delegationContext) bool {
	if classifyCheck(mask, decls, callStart, parenClose, ScopeRequest) == GuardFunction {
		return true
	}
	if ctx != delegationInPermissionCallback {
		return false
	}
	// `return $this->check( $r );` -- core turns a falsy return into
	// rest_forbidden, so the delegate's answer is the route's answer. A negated
	// or compound return is not accepted: negation inverts the verdict, and a
	// compound one admits callers the delegate would have refused.
	prefix := strings.TrimSpace(mask[statementStart(mask, callStart):callStart])
	return strings.EqualFold(prefix, "return")
}

// followCallbackDelegation follows the delegation a handler body performs.
func followCallbackDelegation(funcBody string, fileContent string, allContents map[string]string) models.AuthLevel {
	return delegatedAuthLevel(funcBody, fileContent, allContents, delegationInHandler, 0)
}

// findCallbackBodyAcross resolves a function body, preferring the file that
// registered the callback.
//
// The fallback across the other files iterates in sorted order. A Go map's
// iteration order is randomised per run, so the previous `for _, content :=
// range allContents { ... break }` resolved a name declared in two files to a
// different body on each run -- and 72 of 215 distinct permission-callback
// method names in the corpus have two or more declarations in the same plugin.
func findCallbackBodyAcross(funcName, fileContent string, allContents map[string]string) (body, content string) {
	if b := findFunctionBody(funcName, fileContent); b != "" {
		return b, fileContent
	}
	names := make([]string, 0, len(allContents))
	for name := range allContents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if b := findFunctionBody(funcName, allContents[name]); b != "" {
			return b, allContents[name]
		}
	}
	return "", fileContent
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

// InferAuthLevelFromCallback checks an endpoint callback's body for the checks
// that gate it.
//
// This is the path a wp_ajax_nopriv_ registration takes: the plugin has said
// uid 0 may reach the action, and the question is whether the handler itself
// refuses anyone.
func InferAuthLevelFromCallback(callbackName string, fileContent string, allContents map[string]string) models.AuthLevel {
	funcName := extractCallbackFuncName(callbackName)
	if funcName == "" {
		return models.Unauthenticated
	}

	funcBody, content := findCallbackBodyAcross(funcName, fileContent, allContents)
	if funcBody == "" {
		return models.Unauthenticated
	}

	if level := InferAuthLevelInFile(funcBody, content); level > models.Unauthenticated {
		return level
	}

	// The body itself asserts nothing, so the check may live one call away --
	// but only a call this body's control flow depends on, or a delegate that
	// ends the request itself, gates anything here.
	//
	// A nonce found down that path used to raise the answer to Subscriber, and
	// it cannot. check_ajax_referer() proves the request carries a token minted
	// for this action and this identity; for an action registered with
	// wp_ajax_nopriv_ the plugin has declared uid 0 may reach it, so the nonce
	// is by construction obtainable by uid 0 and is printed into public page
	// HTML by wp_localize_script or wp_nonce_field. The rule also made handlers
	// promote themselves: findFunctionBody resolves a delegate by bare name, so
	// `$this->file_manager->temp_file_delete( $id )` inside temp_file_delete()
	// found the handler again, and the handler's own check_ajax_referer() came
	// back as a delegated identity assertion.
	return delegatedAuthLevel(funcBody, content, allContents, delegationInHandler, 0)
}

// EnhancePermissionCallback follows a permission_callback's delegation chain,
// reading each body it can resolve.
func EnhancePermissionCallback(callbackName string, fileContent string, allContents map[string]string) models.AuthLevel {
	funcName := extractCallbackFuncName(callbackName)
	if funcName == "" {
		return models.Unauthenticated
	}

	funcBody, content := findCallbackBodyAcross(funcName, fileContent, allContents)
	if funcBody == "" {
		return models.Unauthenticated
	}

	return resolvePermissionBodyLevel(funcBody, content, allContents, 0)
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

// resolveCapabilityLevel maps a capability string onto the ladder.
func resolveCapabilityLevel(capability string) (models.AuthLevel, bool) {
	return resolveCapabilityForSubject(capability, false)
}

// resolveCapabilityForSubject maps a capability onto the ladder, given whether
// the check named the object it is testing against.
//
// The precedence is: what the operator configured, then what map_meta_cap does
// with the capability, then the core table, then the floor.
//
// The pattern heuristics that used to end this function are gone. They raised
// any unrecognised capability from the shape of its name -- manage_* and
// *_users to Admin, *_others_* and *_private_* to Editor, and anything
// containing "shop_", "woocommerce", "backup", "restore", "updraft" or
// "duplicator" to Admin. WordPress assigns no meaning to the shape of a
// capability name: WP_User::get_role_caps() builds $allcaps by merging the
// capability arrays of whatever roles the site's wp_user_roles option holds,
// and map_meta_cap's default branch is `$caps[] = $cap` with no name parsing
// whatsoever. Core contradicts the shapes directly -- manage_categories and
// manage_links belong to the editor role, delete_posts to the contributor role
// -- and a capability a plugin registers through register_post_type's
// capability_type is granted to nobody until the plugin grants it, which it
// frequently does below Admin. events-manager, to take a measured case, grants
// manage_bookings and delete_events to contributors and read_private_events to
// subscribers, while the shapes called them Admin, Admin and Editor. Escalating
// them makes an attacker-reachable endpoint read as gated.
//
// The floor is Subscriber, and that is exact rather than merely cautious: a
// logged-out WP_User(0) holds no capability key at all except 'exist', so any
// current_user_can() on a real capability requires a login.
func resolveCapabilityForSubject(capability string, hasSubjectArg bool) (models.AuthLevel, bool) {
	if capability == "" {
		return 0, false
	}
	initCapabilityLevels()

	// An operator who has configured a capability explicitly outranks
	// everything below, including core's own meta-capability mapping.
	if authConfig != nil && authConfig.Capabilities != nil {
		if lvl, ok := authConfig.Capabilities.Custom[capability]; ok {
			return parseStringToAuthLevel(lvl), true
		}
		if lvl, ok := authConfig.Capabilities.ExtendedCapabilities[capability]; ok {
			return parseStringToAuthLevel(lvl), true
		}
	}

	level, have := metaCapPrimitiveLevel(capability)
	if !have {
		if lvl, ok := getCapabilityLevel(capability); ok {
			level, have = lvl, true
		} else if lvl, ok := capabilityLevels[capability]; ok {
			level, have = lvl, true
		}
	}
	if !have {
		level = models.Subscriber
	}

	if lvl, ok := metaCapFloorLevel(capability, hasSubjectArg); ok && lvl < level {
		level = lvl
	}
	return level, true
}

// metaCapPrimitiveLevel is the level of the primitive capability map_meta_cap
// substitutes for a meta capability, for the cases where core's switch body is
// a literal `$caps[] = '<primitive>'` with no indirection and no branch on the
// arguments.
//
// A meta capability is not a key in anyone's capability map. current_user_can()
// runs it through map_meta_cap() first, and WP_User::has_cap() then tests the
// PRIMITIVE capabilities that come back. Treating a meta capability as if it
// were a primitive is how setup_network and upload_plugins came to read
// SuperAdmin -- core maps them to manage_options and install_plugins on a
// single-site install, which is Admin -- and how manage_post_tags read Admin,
// when core maps it to manage_categories, an editor capability.
//
// This table sits ahead of the core capability list so it can correct that list
// where the two disagree. Five entries do RAISE a level relative to the
// Subscriber floor -- promote_user, remove_user, deactivate_plugin,
// resume_plugin and resume_theme -- because core maps each to an
// administrator-only primitive and nothing else in this file does. That is a
// deliberate raise, recorded here so a reader of the diff is not surprised to
// see privilege going up in a change whose purpose is to bring it down.
func metaCapPrimitiveLevel(capability string) (models.AuthLevel, bool) {
	lvl, ok := metaCapPrimitives[capability]
	return lvl, ok
}

var metaCapPrimitives = map[string]models.AuthLevel{
	// $caps[] = 'promote_users' / 'remove_users'
	"promote_user": models.Admin,
	"remove_user":  models.Admin,

	// $caps[] = 'activate_plugins' / 'resume_plugins' / 'resume_themes'
	"activate_plugin":   models.Admin,
	"deactivate_plugin": models.Admin,
	"resume_plugin":     models.Admin,
	"resume_theme":      models.Admin,

	// $caps[] = 'install_plugins' / 'install_themes' on a single site, which is
	// Admin. Both were listed as SuperAdmin capabilities.
	"upload_plugins": models.Admin,
	"upload_themes":  models.Admin,

	// setup_network resolves to manage_options unless the install is multisite.
	"setup_network": models.Admin,

	// $caps[] = 'update_core'
	"update_php":   models.Admin,
	"update_https": models.Admin,

	// $caps[] = 'manage_categories', which core grants to the editor role.
	"manage_post_tags":  models.Editor,
	"edit_categories":   models.Editor,
	"edit_post_tags":    models.Editor,
	"delete_categories": models.Editor,
	"delete_post_tags":  models.Editor,

	// $caps[] = 'edit_posts', which core grants to the contributor role.
	"assign_categories": models.Contributor,
	"assign_post_tags":  models.Contributor,
}

// metaCapFloorLevel is the LOWEST primitive map_meta_cap can produce for a meta
// capability whose mapping depends on something this analysis cannot see -- the
// object the check names, or the capability map a register_post_type() or
// register_taxonomy() call chose.
//
// It may only LOWER a level, never raise one, because the low end of that range
// is what an attacker needs and the high end is a guess about a registration we
// have not read.
//
// edit_user is the case that matters most, and it is exact rather than
// conservative. map_meta_cap contains
//
//	if ( $user_id < 1 ) { $caps[] = 'do_not_allow'; break; }
//	if ( 'edit_user' === $cap && isset( $args[0] ) && $user_id === (int) $args[0] ) { break; }
//
// -- it breaks with $caps still EMPTY for the self case, and WP_User::has_cap()
// then runs `foreach ( (array) $caps as $cap )` over nothing and returns true.
// So any logged-in user passes current_user_can('edit_user', $their_own_id),
// while the same check with no object argument falls through to
// $caps[] = 'edit_users' and really is Admin. The $user_id < 1 guard above it
// is why the floor is Subscriber and not Unauthenticated.
func metaCapFloorLevel(capability string, hasSubjectArg bool) (models.AuthLevel, bool) {
	if hasSubjectArg {
		if lvl, ok := metaCapWithObject[capability]; ok {
			return lvl, true
		}
	}
	lvl, ok := metaCapFloors[capability]
	return lvl, ok
}

// metaCapWithObject holds the meta capabilities whose mapping breaks with an
// empty capability set when the object named is the caller themselves.
var metaCapWithObject = map[string]models.AuthLevel{
	"edit_user": models.Subscriber,

	// map_meta_cap( 'edit_user', $user_id, $args[0] ) for all of these.
	"edit_user_meta":       models.Subscriber,
	"add_user_meta":        models.Subscriber,
	"delete_user_meta":     models.Subscriber,
	"create_app_password":  models.Subscriber,
	"list_app_passwords":   models.Subscriber,
	"read_app_password":    models.Subscriber,
	"edit_app_password":    models.Subscriber,
	"delete_app_password":  models.Subscriber,
	"delete_app_passwords": models.Subscriber,
}

// metaCapFloors holds the meta capabilities core routes through a post type's
// or a taxonomy's own capability map. The value is the level of the DEFAULT
// that register_post_type() and register_taxonomy() supply, which is the lowest
// a caller can need; a registration is free to demand more, and registrations
// are not read here.
var metaCapFloors = map[string]models.AuthLevel{
	// $tax->cap->assign_terms, whose register_taxonomy default is 'edit_posts'.
	"assign_term": models.Contributor,

	// map_meta_cap( 'edit_post', ... ) on the comment's post, floored by that
	// post type's edit_posts.
	"edit_comment": models.Contributor,
}

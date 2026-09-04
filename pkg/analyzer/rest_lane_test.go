package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// findEndpoint returns the first endpoint whose callback matches, or nil.
func findEndpoint(eps []models.Endpoint, callback string) *models.Endpoint {
	for i := range eps {
		if eps[i].Callback == callback {
			return &eps[i]
		}
	}
	return nil
}

func countType(eps []models.Endpoint, t models.EndpointType) int {
	n := 0
	for _, ep := range eps {
		if ep.Type == t {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// A route string may not add privilege
// ---------------------------------------------------------------------------

// TestRouteStringDoesNotInventPrivilege pins the core rule: WordPress decides
// what a route requires from its permission_callback and from nothing else.
// A route with no permission_callback at all is served to everyone -- core only
// emits _doing_it_wrong() -- so it is unauthenticated no matter how it is spelt.
// This registration used to be reported as Admin purely because the path
// contains "/settings".
func TestRouteStringDoesNotInventPrivilege(t *testing.T) {
	content := `<?php
class API {
	public function register() {
		register_rest_route( 'x/v1', '/settings', array(
			'methods'  => 'POST',
			'callback' => array( $this, 'save' ),
		) );
	}
	public function save( $r ) { return true; }
}
`
	eps := DetectRESTEndpoints(content, "api.php", "p")
	ep := findEndpoint(eps, "this::save")
	if ep == nil {
		t.Fatalf("no endpoint for the handler; got %d endpoints", len(eps))
	}
	if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: no permission_callback was registered", ep.AuthLevel)
	}
}

// TestIdenticalPermissionCallbacksGiveIdenticalLevels is the unanchored-substring
// case. The two registrations differ only in their path, and one of them
// contains "/me" inside the word "media". Their permission callback is
// byte-identical, so WordPress requires exactly the same privilege for both.
func TestIdenticalPermissionCallbacksGiveIdenticalLevels(t *testing.T) {
	content := `<?php
class T {
	public function register() {
		register_rest_route( 'x/v1', '/media/import', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'import_a' ),
			'permission_callback' => array( $this, 'check_token' ),
		) );
		register_rest_route( 'x/v1', '/thing/import', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'import_b' ),
			'permission_callback' => array( $this, 'check_token' ),
		) );
	}
	public function check_token( $r ) {
		$t = $r->get_param( 'token' );
		if ( empty( $t ) ) { return new WP_Error( 'no', 'no' ); }
		return true;
	}
}
`
	eps := DetectRESTEndpoints(content, "api.php", "p")
	a := findEndpoint(eps, "this::import_a")
	b := findEndpoint(eps, "this::import_b")
	if a == nil || b == nil {
		t.Fatalf("expected both handlers; got %d endpoints", len(eps))
	}
	if a.AuthLevel != b.AuthLevel {
		t.Errorf("/media/import = %s but /thing/import = %s; the permission callback is the same text",
			a.AuthLevel, b.AuthLevel)
	}
	if a.AuthLevel != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: the callback inspects only request data", a.AuthLevel)
	}
}

// TestPermissionCallbackStillDecidesLevel is the negative test that pins the
// bound. Removing the route-string heuristic must NOT stop a real capability
// check from being reported: this route is spelt exactly like the one above and
// its permission callback genuinely requires manage_options, so it must still
// come out Admin.
func TestPermissionCallbackStillDecidesLevel(t *testing.T) {
	content := `<?php
class API {
	public function register() {
		register_rest_route( 'x/v1', '/settings', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'save' ),
			'permission_callback' => array( $this, 'can_manage' ),
		) );
	}
	public function can_manage( $r ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'forbidden', 'no' );
		}
		return true;
	}
}
`
	eps := DetectRESTEndpoints(content, "api.php", "p")
	ep := findEndpoint(eps, "this::save")
	if ep == nil {
		t.Fatalf("no endpoint for the handler; got %d endpoints", len(eps))
	}
	if ep.AuthLevel != models.Admin {
		t.Errorf("level = %s, want admin: the permission callback gates on manage_options", ep.AuthLevel)
	}
}

// TestDeclaredPublicRouteStillLowers pins the one route-string arm that is
// kept. It can only lower a level, which is the safe direction, so it stays.
func TestDeclaredPublicRouteStillLowers(t *testing.T) {
	if got := applyDeclaredPublicRoute("/public/feed", "x/v1", models.Admin, ""); got != models.Unauthenticated {
		t.Errorf("public indicator gave %s, want unauthenticated", got)
	}
	// ... and the same arm must not raise anything.
	if got := applyDeclaredPublicRoute("/settings", "x/v1", models.Unauthenticated, ""); got != models.Unauthenticated {
		t.Errorf("a route named /settings was promoted to %s; route spelling may not add privilege", got)
	}
	if got := applyDeclaredPublicRoute("/media", "x/v1", models.Unauthenticated, ""); got != models.Unauthenticated {
		t.Errorf("a route named /media was promoted to %s by the unanchored \"/me\" test", got)
	}
}

// ---------------------------------------------------------------------------
// The permission callback is itself an entry point
// ---------------------------------------------------------------------------

// TestPermissionCallbackIsItsOwnEndpoint: WP_REST_Server::dispatch calls the
// permission callback with the request before any authorization exists, so its
// body runs for an anonymous attacker on every request to the route.
func TestPermissionCallbackIsItsOwnEndpoint(t *testing.T) {
	content := `<?php
class T {
	public function register() {
		register_rest_route( 'x/v1', '/t', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'handle' ),
			'permission_callback' => array( $this, 'check_bearer' ),
		) );
	}
	public function handle( $r ) { return true; }
	public function check_bearer( $r ) {
		$k = $r->get_header( 'x_auth' );
		return $k === get_option( 'k' );
	}
}
`
	eps := DetectRESTEndpoints(content, "api.php", "p")

	handler := findEndpoint(eps, "this::handle")
	if handler == nil {
		t.Fatalf("the handler endpoint disappeared; got %d endpoints", len(eps))
	}
	perm := findEndpoint(eps, "this::check_bearer")
	if perm == nil {
		t.Fatalf("the permission callback is reachable from no endpoint; got %d endpoints", len(eps))
	}
	if perm.Type != EndpointTypeRESTPermission {
		t.Errorf("permission endpoint type = %s, want %s", perm.Type, EndpointTypeRESTPermission)
	}
	if perm.AuthLevel != models.Unauthenticated {
		t.Errorf("permission endpoint level = %s, want unauthenticated: it runs before any check",
			perm.AuthLevel)
	}
	// deduplicateEndpoints keys on (Route, Method, Type) and keeps one endpoint
	// per key. If these two shared a key, one of them would be silently deleted.
	if perm.Route == handler.Route && perm.Method == handler.Method && perm.Type == handler.Type {
		t.Errorf("the permission endpoint shares a dedup key with the handler (%s|%s|%s)",
			perm.Route, perm.Method, perm.Type)
	}
	// The line must be the callback's own declaration, not the registration:
	// crediting the registration line would assert that the HANDLER's line range
	// contains anonymously reachable code, which is a different claim.
	wantLine := strings.Count(content[:strings.Index(content, "public function check_bearer")], "\n") + 1
	if perm.Line != wantLine {
		t.Errorf("permission endpoint line = %d, want %d (its own declaration)", perm.Line, wantLine)
	}
}

// TestCorePermissionHelpersAreNotEndpoints is the negative test. __return_true
// and its siblings are declared by WordPress core, not by the plugin, so they
// are not plugin code a scanner should look at.
func TestCorePermissionHelpersAreNotEndpoints(t *testing.T) {
	content := `<?php
register_rest_route( 'x/v1', '/t', array(
	'methods'             => 'GET',
	'callback'            => 'handle_it',
	'permission_callback' => '__return_true',
) );
`
	eps := DetectRESTEndpoints(content, "api.php", "p")
	if n := countType(eps, EndpointTypeRESTPermission); n != 0 {
		t.Errorf("got %d permission endpoints for __return_true, want 0", n)
	}
	if ep := findEndpoint(eps, "handle_it"); ep == nil {
		t.Fatalf("the handler endpoint disappeared")
	} else if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated", ep.AuthLevel)
	}
}

// TestPermissionCallbackSymbolForms checks the name each callable form resolves
// to, because the call graph can only follow a name it recognises.
func TestPermissionCallbackSymbolForms(t *testing.T) {
	cases := []struct {
		name       string
		permReturn string
		args       string
		want       string
	}{
		{"array with $this", "check", `'permission_callback' => array( $this, 'check' )`, "this::check"},
		{"plain string", "my_check", `'permission_callback' => 'my_check'`, "my_check"},
		{"static delegation", "static:Gate::allow", `'permission_callback' => function(){ return Gate::allow(); }`, "Gate::allow"},
		{"method delegation", "delegated:allow", `'permission_callback' => function(){ return $this->allow(); }`, "this::allow"},
		{"arrow delegation", "arrow:allow", `'permission_callback' => fn($r) => $this->allow($r)`, "this::allow"},
		{"function delegation", "function:allow", `'permission_callback' => function(){ return allow(); }`, "allow"},
		{"unattributed closure", "anonymous", `'permission_callback' => function(){ return true; }`, "closure"},
		{"nothing", "", `'callback' => 'x'`, ""},
	}
	for _, c := range cases {
		if got := permissionCallbackSymbol(c.permReturn, c.args); got != c.want {
			t.Errorf("%s: symbol = %q, want %q", c.name, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Route descriptors written away from the call site
// ---------------------------------------------------------------------------

// TestRouteDescriptorOutsideCallIsFound is the WP_REST_Controller table idiom: a
// subclass fills a property and a base class loops over it. WordPress reads the
// route's behaviour out of whatever array reaches register_rest_route, and PHP
// does not care where that array literal was written.
func TestRouteDescriptorOutsideCallIsFound(t *testing.T) {
	content := `<?php
class Sub extends Base {
	public function register_routes() {
		$this->routes = array(
			'/' => array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_content' ),
					'permission_callback' => '__return_true',
				),
			),
		);
		parent::register_routes();
	}
	public function get_content( $r ) { echo $_GET['x']; }
}
`
	eps := DetectRESTEndpoints(content, "sub.php", "p")
	ep := findEndpoint(eps, "this::get_content")
	if ep == nil {
		t.Fatalf("the route table is invisible; got %d endpoints", len(eps))
	}
	if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: the descriptor declares __return_true", ep.AuthLevel)
	}
	if ep.File != "sub.php" {
		t.Errorf("file = %s, want sub.php: the callback is declared here", ep.File)
	}
}

// TestDescriptorLevelIsNeverAboveSubscriber is a bound, not a feature. A block
// found outside any register_rest_route call has not been proven to be
// registered at all, and its missing keys are supplied by a consuming call site
// this pass has not read. It may therefore never assert a level that would make
// a reachable handler look gated.
func TestDescriptorLevelIsNeverAboveSubscriber(t *testing.T) {
	content := `<?php
class Table {
	public function get_routes() {
		return array(
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'wipe' ),
				'permission_callback' => function () { return current_user_can( 'manage_options' ); },
			),
		);
	}
	public function wipe( $r ) { return true; }
}
`
	eps := DetectRESTEndpoints(content, "table.php", "p")
	ep := findEndpoint(eps, "this::wipe")
	if ep == nil {
		t.Fatalf("the descriptor was not found; got %d endpoints", len(eps))
	}
	if ep.AuthLevel > models.Subscriber {
		t.Errorf("level = %s; a descriptor found outside a call may not assert above subscriber", ep.AuthLevel)
	}
}

// TestDescriptorPassDoesNotDuplicateTheCallSite is the first negative test. An
// args array written where WordPress expects it is already handled by the
// lexical passes; the descriptor pass must not emit a second endpoint for it.
func TestDescriptorPassDoesNotDuplicateTheCallSite(t *testing.T) {
	content := `<?php
register_rest_route( 'x/v1', '/t', array(
	'methods'             => 'GET',
	'callback'            => 'handle_it',
	'permission_callback' => '__return_true',
) );
`
	eps := DetectRESTEndpoints(content, "api.php", "p")
	n := 0
	for _, ep := range eps {
		if ep.Callback == "handle_it" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("got %d endpoints for one registration, want 1", n)
	}
}

// TestForwardedVariableIsNotDuplicated is the same bound for the shape where the
// args array is assigned to a variable that the call then forwards.
func TestForwardedVariableIsNotDuplicated(t *testing.T) {
	content := `<?php
$route_args = array(
	'methods'             => 'GET',
	'callback'            => 'handle_it',
	'permission_callback' => '__return_true',
);
register_rest_route( 'x/v1', '/t', $route_args );
`
	eps := DetectRESTEndpoints(content, "api.php", "p")
	n := 0
	for _, ep := range eps {
		if ep.Callback == "handle_it" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("got %d endpoints for one registration, want 1", n)
	}
}

// TestNonRESTArraysAreNotDescriptors is the second negative test, and it is the
// one that keeps the rule tied to WordPress core. The identifying evidence is
// 'callback' beside 'methods' or 'permission_callback' -- a key combination that
// only register_rest_route's args array uses. An array with only one half of it,
// and an array belonging to a different core registration API, must both be
// rejected.
func TestNonRESTArraysAreNotDescriptors(t *testing.T) {
	content := `<?php
class Other {
	public function boot() {
		// wp_register_ability: permission_callback, but the handler key is
		// execute_callback, so this is not a REST route descriptor.
		wp_register_ability( 'x/do', array(
			'label'               => 'Do',
			'execute_callback'    => array( $this, 'do_it' ),
			'permission_callback' => array( $this, 'can_do' ),
		) );

		// A lone 'callback' key with no REST sibling: not a route descriptor.
		$this->hooks = array(
			'callback' => array( $this, 'on_save' ),
			'priority' => 10,
		);
	}
}
`
	eps := discoverRouteDescriptors(content, "other.php", "p")
	if len(eps) != 0 {
		t.Errorf("got %d descriptor endpoints, want 0: %+v", len(eps), eps)
	}
}

// TestDescriptorRoutesAreUniquePerCallback pins the property that makes the pass
// survive deduplicateEndpoints, which keys on (Route, Method, Type) and keeps
// exactly one endpoint per key. Two descriptors in one file must not collide.
func TestDescriptorRoutesAreUniquePerCallback(t *testing.T) {
	content := `<?php
class Table {
	public function get_routes() {
		return array(
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'alpha' ),
				'permission_callback' => '__return_true',
			),
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'beta' ),
				'permission_callback' => '__return_true',
			),
		);
	}
}
`
	eps := discoverRouteDescriptors(content, "table.php", "p")
	if len(eps) < 2 {
		t.Fatalf("got %d endpoints, want both descriptors: %+v", len(eps), eps)
	}
	seen := map[string]string{}
	for _, ep := range eps {
		key := ep.Route + "|" + ep.Method + "|" + string(ep.Type)
		if prev, ok := seen[key]; ok && prev != ep.Callback {
			t.Errorf("descriptors for %s and %s share the dedup key %s; one would be deleted",
				prev, ep.Callback, key)
		}
		seen[key] = ep.Callback
	}
}

// ---------------------------------------------------------------------------
// The four-argument register_rest_route form
// ---------------------------------------------------------------------------

// TestFourArgumentRegisterRestRoute: core's signature is
// register_rest_route($namespace, $route, $args = array(), $override = false).
// A call that passes the fourth argument used to be invisible whenever the third
// was a variable.
func TestFourArgumentRegisterRestRoute(t *testing.T) {
	content := `<?php
class Api {
	public function init() {
		$route_args = array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'handle' ),
			'permission_callback' => '__return_true',
		);
		register_rest_route( 'x/v1', '/thing', $route_args, true );
	}
	public function handle( $r ) { return true; }
}
`
	eps := DetectRESTEndpoints(content, "api.php", "p")
	ep := findEndpoint(eps, "this::handle")
	if ep == nil {
		t.Fatalf("the four-argument call produced no endpoint; got %d endpoints", len(eps))
	}
	// The route is whatever the variable-args pass makes of the namespace
	// expression; what this test pins is that the call is seen at all and that
	// its real callback and level come out of the resolved array.
	if !strings.Contains(ep.Route, "/thing") {
		t.Errorf("route = %s, want it to carry the registered path", ep.Route)
	}
	if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated", ep.AuthLevel)
	}
}

// TestThreeArgumentVariableFormStillWorks is the negative bound on the previous
// test: relaxing the pattern must not break the form it already handled.
func TestThreeArgumentVariableFormStillWorks(t *testing.T) {
	content := `<?php
class Api {
	public function init() {
		$route_args = array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'handle' ),
			'permission_callback' => '__return_true',
		);
		register_rest_route( 'x/v1', '/thing', $route_args );
	}
	public function handle( $r ) { return true; }
}
`
	eps := DetectRESTEndpoints(content, "api.php", "p")
	if ep := findEndpoint(eps, "this::handle"); ep == nil {
		t.Fatalf("the three-argument variable form regressed; got %d endpoints", len(eps))
	}
}

// TestPropertyArgsAreResolved: a property holding the args array is assigned by
// a constructor or a setter, which may sit either side of the registration. PHP
// does not care about source order for a property.
func TestPropertyArgsAreResolved(t *testing.T) {
	content := `<?php
class Api {
	public function init() {
		register_rest_route( $this->namespace, '/thing', $this->options );
	}
	public function __construct() {
		$this->namespace = 'x/v1';
		$this->options = array(
			'methods'             => 'DELETE',
			'callback'            => array( $this, 'wipe' ),
			'permission_callback' => '__return_true',
		);
	}
	public function wipe( $r ) { return true; }
}
`
	eps := DetectRESTEndpoints(content, "api.php", "p")
	ep := findEndpoint(eps, "this::wipe")
	if ep == nil {
		t.Fatalf("the property args array was not resolved; got %d endpoints", len(eps))
	}
	if ep.Method != "DELETE" {
		t.Errorf("method = %s, want DELETE from the resolved array", ep.Method)
	}
}

// ---------------------------------------------------------------------------
// register_rest_field
// ---------------------------------------------------------------------------

// TestRESTFieldCallbacksAreEndpoints: register_rest_field writes its callables
// into core's field registry, and the wp/v2 controllers invoke get_callback
// while preparing every response and update_callback while handling every write.
// The plugin registers no route of its own, so nothing else in this analyzer
// could see the code.
func TestRESTFieldCallbacksAreEndpoints(t *testing.T) {
	content := `<?php
class Fields {
	public function init() {
		register_rest_field( 'post', 'x', array(
			'get_callback'    => array( $this, 'get_x' ),
			'update_callback' => array( $this, 'set_x' ),
		) );
	}
	public function get_x( $o ) { return 1; }
	public function set_x( $v, $o ) { return true; }
}
`
	eps := DetectRESTEndpoints(content, "fields.php", "p")
	get := findEndpoint(eps, "this::get_x")
	set := findEndpoint(eps, "this::set_x")
	if get == nil || set == nil {
		t.Fatalf("register_rest_field produced %d endpoints, want both callbacks: %+v", len(eps), eps)
	}
	if get.Method != "GET" {
		t.Errorf("get_callback method = %s, want GET", get.Method)
	}
	if set.Method != "POST" {
		t.Errorf("update_callback method = %s, want POST", set.Method)
	}
	if get.AuthLevel != models.Unauthenticated || set.AuthLevel != models.Unauthenticated {
		t.Errorf("levels = %s/%s, want unauthenticated for both", get.AuthLevel, set.AuthLevel)
	}
	// The route must not be a pluralisation guess: a post type's REST base is
	// whatever register_post_type declared, and 'user' and 'comment' are not post
	// types at all.
	if strings.Contains(get.Route, "/posts/") {
		t.Errorf("route = %s: the object type must be recorded verbatim, not pluralised", get.Route)
	}
	if get.Route == set.Route && get.Method == set.Method {
		t.Errorf("the two field callbacks share a dedup key; one would be deleted")
	}
}

// TestTwoFieldsOnOneObjectTypeBothSurvive is the negative bound: 21 of the 60
// measured register_rest_field call sites share an object-type literal with
// another site in the same tree, so a route naming only the object type would
// keep one field per type and drop the rest.
func TestTwoFieldsOnOneObjectTypeBothSurvive(t *testing.T) {
	content := `<?php
register_rest_field( 'post', 'a', array( 'get_callback' => 'field_a' ) );
register_rest_field( 'post', 'b', array( 'get_callback' => 'field_b' ) );
`
	eps := detectRESTFieldEndpoints(content, "fields.php", "p")
	if len(eps) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(eps))
	}
	if eps[0].Route == eps[1].Route && eps[0].Method == eps[1].Method {
		t.Errorf("both fields landed on %s|%s; one would be deduplicated away",
			eps[0].Route, eps[0].Method)
	}
}

// TestRegisterRestFieldWithoutCallbacksIsIgnored is the other negative bound.
func TestRegisterRestFieldWithoutCallbacksIsIgnored(t *testing.T) {
	content := `<?php
register_rest_field( 'post', 'x', array( 'schema' => array( 'type' => 'string' ) ) );
`
	if eps := detectRESTFieldEndpoints(content, "fields.php", "p"); len(eps) != 0 {
		t.Errorf("got %d endpoints, want 0: %+v", len(eps), eps)
	}
}

// ---------------------------------------------------------------------------
// Coverage audit
// ---------------------------------------------------------------------------

// TestCoverageAuditMatchesSubdirectoryEndpoints. An endpoint's File comes from
// filepath.Rel, so on Windows it carries backslashes, while the audit builds its
// key with filepath.ToSlash. Comparing the two forms directly reported every
// endpoint in a subdirectory as a gap -- lists that were 100% false positives.
func TestCoverageAuditMatchesSubdirectoryEndpoints(t *testing.T) {
	endpoints := []models.Endpoint{
		{
			Type:  models.EndpointTypeREST,
			Route: "/wp-json/ns/v1/items",
			File:  `src\Controllers\Routes.php`,
			Line:  2,
		},
	}
	cache := map[string]string{
		`src\Controllers\Routes.php`: "<?php\nregister_rest_route('ns/v1', '/items', array('methods' => 'GET', 'callback' => 'get_items'));",
	}
	report := AuditRESTCoverage("", endpoints, cache)
	if len(report.Gaps) != 0 {
		t.Errorf("got %d gaps for a call that produced an endpoint: %+v", len(report.Gaps), report.Gaps)
	}
}

// TestCoverageAuditStillReportsRealGap is the negative bound: normalising the
// key must not make every call look covered.
func TestCoverageAuditStillReportsRealGap(t *testing.T) {
	cache := map[string]string{
		`src\Controllers\Routes.php`: "<?php\nregister_rest_route($ns, $route, $args);",
	}
	report := AuditRESTCoverage("", nil, cache)
	if len(report.Gaps) != 1 {
		t.Errorf("got %d gaps, want 1", len(report.Gaps))
	}
}

// TestCoverageGapsAreOrdered: strippedCache is a map, so the scan visits files
// in a random order. A report that is logged and diffed between runs has to be
// stable.
func TestCoverageGapsAreOrdered(t *testing.T) {
	cache := map[string]string{
		"c.php": "<?php register_rest_route($a, $b, $c);",
		"a.php": "<?php register_rest_route($a, $b, $c);",
		"b.php": "<?php register_rest_route($a, $b, $c);",
	}
	for i := 0; i < 10; i++ {
		report := AuditRESTCoverage("", nil, cache)
		if len(report.Gaps) != 3 {
			t.Fatalf("got %d gaps, want 3", len(report.Gaps))
		}
		if report.Gaps[0].File != "a.php" || report.Gaps[1].File != "b.php" || report.Gaps[2].File != "c.php" {
			t.Fatalf("gaps out of order: %s, %s, %s",
				report.Gaps[0].File, report.Gaps[1].File, report.Gaps[2].File)
		}
	}
}

// ---------------------------------------------------------------------------
// The bracket walk that finds an enclosing array literal
// ---------------------------------------------------------------------------

// TestEnclosingArrayLiteralSkipsStrings. A bracket inside a quoted string is not
// a bracket, and skipString returns the index of the CLOSING quote -- treating
// that as the start of the next string inverts every boundary after it, which is
// how this walk first failed to find any literal at all.
func TestEnclosingArrayLiteralSkipsStrings(t *testing.T) {
	content := `<?php $x = 'a[b'; $c = array( 'note' => 'it]s fine', 'callback' => 'go' );`
	pos := strings.Index(content, "'callback'")
	start, end := enclosingArrayLiteral(content, pos)
	if start < 0 {
		t.Fatalf("no enclosing literal found")
	}
	got := content[start:end]
	if !strings.HasPrefix(got, "array(") || !strings.HasSuffix(got, ")") {
		t.Errorf("extracted %q, want the whole array( ... ) literal", got)
	}
	if !strings.Contains(got, "'callback' => 'go'") {
		t.Errorf("extracted %q, which does not contain the callback key", got)
	}
}

// TestEnclosingArrayLiteralAtTopLevel is the negative bound: a key that is not
// inside any array literal must yield nothing rather than a wild guess.
func TestEnclosingArrayLiteralAtTopLevel(t *testing.T) {
	content := `<?php $callback = 'go';`
	if start, _ := enclosingArrayLiteral(content, len(content)-1); start >= 0 {
		t.Errorf("found an enclosing literal at %d where there is none", start)
	}
}

// TestFindDeclarationLine pins what counts as a declaration. A call site, and a
// name that is only a fragment of a longer identifier, are not declarations: a
// permission-callback endpoint that pointed at either would claim a line the
// symbol is not declared on.
func TestFindDeclarationLine(t *testing.T) {
	content := "<?php\n" + // 1
		"class A {\n" + // 2
		"  public function boot() {\n" + // 3
		"    $this->check_it();\n" + // 4  <- a call, not a declaration
		"  }\n" + // 5
		"  private function precheck_it() { return 1; }\n" + // 6  <- longer name
		"  public function check_it( $r ) { return true; }\n" + // 7  <- the declaration
		"}\n"
	if got := findDeclarationLine(content, "check_it"); got != 7 {
		t.Errorf("line = %d, want 7", got)
	}
	if got := findDeclarationLine(content, "not_here"); got != 0 {
		t.Errorf("line = %d for an absent symbol, want 0", got)
	}
	if got := findDeclarationLine(content, ""); got != 0 {
		t.Errorf("line = %d for an empty name, want 0", got)
	}
}

// TestDescriptorWithUnresolvablePermissionIsUnauthenticated. A plugin-side table
// says nothing about who may reach it: its permission_callback is often supplied
// by the consuming loop, which this pass has not read. Core's "an absent
// permission_callback means public" rule is a fact about the array that reaches
// register_rest_route, not about a table, so the answer here is the floor.
func TestDescriptorWithUnresolvablePermissionIsUnauthenticated(t *testing.T) {
	content := `<?php
class Table {
	public function get_routes() {
		return array(
			array(
				'endpoint' => '/entries',
				'methods'  => 'POST',
				'callback' => 'list_entries',
			),
		);
	}
}
`
	eps := discoverRouteDescriptors(content, "table.php", "p")
	ep := findEndpoint(eps, "list_entries")
	if ep == nil {
		t.Fatalf("the descriptor was not found; got %d endpoints", len(eps))
	}
	if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated", ep.AuthLevel)
	}
}

// TestDescriptorPassIsDeterministic. The pass walks the file left to right and
// touches no map iteration, so the same input must give the same endpoints in
// the same order every time. This package already carries a determinism test for
// the call graph because the codebase has been bitten by map order before.
func TestDescriptorPassIsDeterministic(t *testing.T) {
	content := `<?php
class Table {
	public function get_routes() {
		return array(
			array( 'methods' => 'GET',  'callback' => array( $this, 'a' ), 'permission_callback' => '__return_true' ),
			array( 'methods' => 'POST', 'callback' => array( $this, 'b' ), 'permission_callback' => array( $this, 'gate' ) ),
			array( 'methods' => 'PUT',  'callback' => 'c', 'permission_callback' => 'other_gate' ),
		);
	}
	public function gate( $r ) { return is_user_logged_in(); }
}
`
	first := discoverRouteDescriptors(content, "table.php", "p")
	if len(first) == 0 {
		t.Fatalf("no descriptors found")
	}
	for i := 0; i < 20; i++ {
		again := discoverRouteDescriptors(content, "table.php", "p")
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d endpoints, first run produced %d", i, len(again), len(first))
		}
		for j := range again {
			a, b := again[j], first[j]
			if a.Route != b.Route || a.Method != b.Method || a.Type != b.Type ||
				a.Callback != b.Callback || a.AuthLevel != b.AuthLevel || a.Line != b.Line {
				t.Fatalf("run %d differs at %d: %+v vs %+v", i, j, a, b)
			}
		}
	}
}

// TestDescriptorPassSurvivesMalformedInput. The analyzer runs over whatever is
// on disk, including truncated files, files with an unterminated string or
// comment, and minified output. The backward bracket walk must terminate and
// must not panic on any of them.
func TestDescriptorPassSurvivesMalformedInput(t *testing.T) {
	cases := []string{
		`<?php $a = array( 'methods' => 'GET', 'callback' => 'go'`, // unterminated array
		`<?php /* 'callback' => 'go'`,                              // unterminated block comment
		`<?php $a = [ 'callback' => 'go', 'x' => 'unterminated`,    // unterminated string
		`<?php ` + strings.Repeat("array( ", 200) + `'callback' => 'go', 'methods' => 'GET'`,
		`<?php register_rest_route( 'a', 'b', array( 'callback' => 'go', 'methods' => 'GET'`, // unbalanced call
		"<?php $a = array( 'callback' => 'go', 'methods' => 'GET' ); # 'callback' => 'no'",
		`<?php`,
		``,
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			discoverRouteDescriptors(c, "x.php", "p")
			detectRESTFieldEndpoints(c, "x.php", "p")
			DetectRESTEndpoints(c, "x.php", "p")
		}()
	}
}

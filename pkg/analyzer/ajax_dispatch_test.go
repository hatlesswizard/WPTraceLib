package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// levelOf returns the level reported for one route, and whether the route was
// found at all. Where a route is registered twice the lowest level wins, which
// is what a caller of the library sees after deduplication.
func levelOf(eps []models.Endpoint, route string) (models.AuthLevel, bool) {
	found := false
	level := models.SuperAdmin
	for _, ep := range eps {
		if ep.Route == route {
			found = true
			if ep.AuthLevel < level {
				level = ep.AuthLevel
			}
		}
	}
	return level, found
}

// callbackListFor returns every callback reported for one route.
func callbackListFor(eps []models.Endpoint, route string) []string {
	out := []string{}
	for _, ep := range eps {
		if ep.Route == route {
			out = append(out, ep.Callback)
		}
	}
	return out
}

// routeHasCallback checks a callback against ONE route. widget_test.go has a
// hasCallback that checks the whole endpoint list regardless of route; the two
// grew in parallel worktrees and only shared a name.
func routeHasCallback(eps []models.Endpoint, route, callback string) bool {
	for _, cb := range callbackListFor(eps, route) {
		if strings.EqualFold(cb, callback) {
			return true
		}
	}
	return false
}

func detectAll(content string) []models.Endpoint {
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	return append(eps, DetectForeachLoopAJAXHandlers(content, "a.php", "testplugin")...)
}

// TestNoprivRegistrationIsNotRaisedByItsCallbackBody
//
// wp-admin/admin-ajax.php fires wp_ajax_nopriv_{$action} for every request with
// no valid auth cookie, and it does so before any plugin code runs. The
// registration is a fact about who reaches the callback; the callback's own body
// cannot change which hook core fires. parseAJAXMatch used to read the body back
// and raise the level, and what it usually found was a nonce -- CSRF protection
// a logged-out visitor can satisfy, because wp_create_nonce() for user 0 is
// printed into the public page.
//
// Shape taken from ht-contactform 2.2.1 admin/Includes/Ajax.php:52-86
// (CVE-2025-7341), where the delegation to a same-named method is what tripped
// the nonce rule.
func TestNoprivRegistrationIsNotRaisedByItsCallbackBody(t *testing.T) {
	content := `<?php
class A {
	public function __construct() {
		add_action('wp_ajax_tmp_delete',        array($this,'tmp_delete'));
		add_action('wp_ajax_nopriv_tmp_delete', array($this,'tmp_delete'));
	}
	public function tmp_delete() {
		check_ajax_referer('nonce','_wpnonce');
		$id = sanitize_text_field( wp_unslash($_POST['id']) );
		if ( $this->file_manager->tmp_delete($id) ) { wp_send_json_success(); }
	}
}
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	level, ok := levelOf(eps, "wp-admin/admin-ajax.php?action=tmp_delete")
	if !ok {
		t.Fatalf("the registration produced no endpoint at all; got %+v", eps)
	}
	if level != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: core routes the nopriv half to an anonymous caller", level)
	}
	for _, ep := range eps {
		if ep.AuthLevel != models.Unauthenticated {
			t.Errorf("endpoint at line %d reports %s; the twin proves the action is anonymously reachable", ep.Line, ep.AuthLevel)
		}
	}
}

// TestWpAjaxWithoutANoprivTwinKeepsTheSubscriberFloor is the bound the fix above
// must not cross. wp_ajax_ alone is fired only in the logged-in arm, so it still
// requires a Subscriber; lowering every AJAX endpoint to unauthenticated would
// turn the library into a constant.
func TestWpAjaxWithoutANoprivTwinKeepsTheSubscriberFloor(t *testing.T) {
	content := `<?php
class A {
	public function __construct() {
		add_action('wp_ajax_tmp_delete', array($this,'tmp_delete'));
	}
	public function tmp_delete() {
		check_ajax_referer('nonce','_wpnonce');
		unlink( $_POST['id'] );
	}
}
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	level, ok := levelOf(eps, "wp-admin/admin-ajax.php?action=tmp_delete")
	if !ok {
		t.Fatalf("no endpoint; got %+v", eps)
	}
	if level != models.Subscriber {
		t.Errorf("level = %s, want subscriber: there is no nopriv registration here", level)
	}
}

// TestNoprivTwinDoesNotDowngradeADifferentCallback
//
// The dispatch fact is about the CALLBACK, not about the action name. When a
// plugin points the anonymous half of a pair at a "you must log in" stub, the
// privileged half is still privileged, and downgrading it would claim an
// attacker reaches a function core never routes to them.
//
// Shape taken from kali-forms 2.4.9 Inc/Backend/class-hooks.php:97-104.
func TestNoprivTwinDoesNotDowngradeADifferentCallback(t *testing.T) {
	content := `<?php
class A {
	public function __construct() {
		add_action('wp_ajax_set_theme',        array($this,'set_form_theme'));
		add_action('wp_ajax_nopriv_set_theme', array($this,'denied'));
	}
	public function set_form_theme() { update_option('theme', $_POST['t']); }
	public function denied() { wp_send_json_error('login required'); }
}
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	sawPriv, sawAnon := false, false
	for _, ep := range eps {
		switch {
		case strings.Contains(strings.ToLower(ep.Callback), "set_form_theme"):
			sawPriv = true
			if ep.AuthLevel != models.Subscriber {
				t.Errorf("set_form_theme reports %s, want subscriber: only 'denied' is registered for anonymous callers", ep.AuthLevel)
			}
		case strings.Contains(strings.ToLower(ep.Callback), "denied"):
			sawAnon = true
			if ep.AuthLevel != models.Unauthenticated {
				t.Errorf("denied reports %s, want unauthenticated", ep.AuthLevel)
			}
		}
	}
	if !sawPriv || !sawAnon {
		t.Fatalf("expected both halves of the pair; got %+v", eps)
	}
}

// TestNoprivTwinDowngradesAnUnnameableCallback is the other side of that bound.
// When one half's callback cannot be named there is no evidence that the two
// bind different handlers, and guessing "different" would restore the
// over-restriction the correlation exists to remove.
func TestNoprivTwinDowngradesAnUnnameableCallback(t *testing.T) {
	content := `<?php
add_action('wp_ajax_thing',        'handle_thing');
add_action('wp_ajax_nopriv_thing', function () { handle_thing(); });
function handle_thing() { echo $_POST['x']; }
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	level, ok := levelOf(eps, "wp-admin/admin-ajax.php?action=thing")
	if !ok {
		t.Fatalf("no endpoint; got %+v", eps)
	}
	if level != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated", level)
	}
	for _, ep := range eps {
		if ep.Callback == "handle_thing" && ep.AuthLevel != models.Unauthenticated {
			t.Errorf("handle_thing reports %s: the closure registered for anonymous callers cannot be shown to be a different handler", ep.AuthLevel)
		}
	}
}

// TestAdminPostNoprivIsUnauthenticated
//
// wp-admin/admin-post.php makes the same is_user_logged_in() split as
// admin-ajax.php. admin_post_ is a prefix of admin_post_nopriv_, and the pattern
// for the privileged half was claiming the anonymous half's position as well, so
// the detector meant to emit it never ran. All 13 admin_post_nopriv_
// registrations in the 143-tree corpus were being reported above unauthenticated.
//
// Shape taken from ht-contactform 2.2.1 admin/Includes/ShortCode.php:90-91.
func TestAdminPostNoprivIsUnauthenticated(t *testing.T) {
	content := `<?php
class A {
	public function __construct() {
		add_action('admin_post_submit_nojs',        array($this,'handle_submission'));
		add_action('admin_post_nopriv_submit_nojs', array($this,'handle_submission'));
	}
	public function handle_submission() { echo $_POST['x']; }
}
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	level, ok := levelOf(eps, "wp-admin/admin-post.php?action=submit_nojs")
	if !ok {
		t.Fatalf("no endpoint; got %+v", eps)
	}
	if level != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: admin-post.php fires the nopriv half for a logged-out caller", level)
	}
	if len(eps) < 2 {
		t.Errorf("expected both halves of the pair to be emitted; got %d endpoints", len(eps))
	}
	// Both halves, not just the anonymous one. formatAjaxRoute collapses them
	// onto one URL, so the privileged half is only downgraded if the endpoint
	// carries the hook it was actually registered on rather than the prefix its
	// route was built from.
	for _, ep := range eps {
		if ep.AuthLevel != models.Unauthenticated {
			t.Errorf("endpoint at line %d reports %s; its twin binds the same handler for anonymous callers", ep.Line, ep.AuthLevel)
		}
	}
}

// TestAdminPostDefaultsToSubscriber
//
// wp-admin/admin-post.php validates the auth cookie and fires
// admin_post_{$action} in the logged-in arm; it never calls current_user_can().
// wp-admin/admin.php fires admin_action_{$action} after auth_redirect(), and its
// one current_user_can() governs a memory-limit bump. Neither hook implies a
// capability, so the WordPress-derived default is Subscriber. Both callbacks
// here live in another file, so no body inference can apply.
func TestAdminPostDefaultsToSubscriber(t *testing.T) {
	content := `<?php
add_action('admin_post_view', array($this, 'view_log_item'));
add_action('admin_action_dup', array($this, 'duplicate_post'));
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	for _, route := range []string{
		"wp-admin/admin-post.php?action=view",
		"wp-admin/admin-ajax.php?action=dup",
	} {
		level, ok := levelOf(eps, route)
		if !ok {
			t.Fatalf("route %q produced no endpoint; got %+v", route, eps)
		}
		if level != models.Subscriber {
			t.Errorf("route %q reports %s, want subscriber: neither dispatcher checks a capability", route, level)
		}
	}
}

// TestAdminPostRaisesOnARealCapabilityCheck is one bound on the default above:
// a genuine gate in the callback body must still be honoured.
func TestAdminPostRaisesOnARealCapabilityCheck(t *testing.T) {
	content := `<?php
add_action('admin_post_x', 'f');
function f(){ if(!current_user_can('manage_options')) wp_die(); update_option('a', $_POST['b']); }
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	level, ok := levelOf(eps, "wp-admin/admin-post.php?action=x")
	if !ok {
		t.Fatalf("no endpoint; got %+v", eps)
	}
	if level != models.Admin {
		t.Errorf("level = %s, want admin: the body gates on manage_options", level)
	}
}

// TestAdminPostRaiseIsCappedAtAdmin is the other bound, and the one an adversary
// found. Turning the old "downgrade only" adjustment into a raise admits every
// level InferAuthLevel can return, and it returns SuperAdmin for capabilities
// that are ordinary administrator capabilities on single-site WordPress
// (upload_plugins among them). Nothing about admin-post.php implies network
// scope, so the raise must not go past the level this hook reported before.
func TestAdminPostRaiseIsCappedAtAdmin(t *testing.T) {
	content := `<?php
add_action('admin_post_upl', 'upl_h');
function upl_h(){ if (!current_user_can('upload_plugins')) wp_die('no'); do_upload(); }
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	level, ok := levelOf(eps, "wp-admin/admin-post.php?action=upl")
	if !ok {
		t.Fatalf("no endpoint; got %+v", eps)
	}
	if level > models.Admin {
		t.Errorf("level = %s: admin-post.php is a single-site dispatcher and cannot imply network scope", level)
	}
	if level != models.Admin {
		t.Errorf("level = %s, want admin", level)
	}
}

// TestActionNameDoesNotPromoteToAdmin
//
// WordPress grants privilege through capabilities checked at runtime;
// do_action( 'wp_ajax_' . $action ) does not inspect $action for English words.
// isAdminIndicatorAction used to promote on _search, _list, _log, _view, _page,
// _report, _check, _toggle and eight more, which between them accounted for the
// largest share of the 115 endpoints reported at Admin from files containing no
// capability check at all.
//
// One promotion of the same kind survives and is not listed here: the keyword
// "_admin_" reaches this file from config.DefaultAJAXConfig(), so an action
// named pfx_admin_meta_box is still reported at Admin. It names no capability
// either, but the list it lives in is outside this file.
func TestActionNameDoesNotPromoteToAdmin(t *testing.T) {
	for _, action := range []string{
		"grw_dashboard_listing_tab", // _list  -- a front-end member dashboard tab
		"send_email_user_view",      // _view
		"charitable_report_export",  // _report
		"wp_statistics_close_notice",
		"breeze_file_permission_check", // _check
		"download_media_log",           // _log
		"pfx_feature_toggle",           // _toggle
	} {
		content := `<?php
add_action( 'wp_ajax_` + action + `', array( $this, 'handler' ) );
class C {
	public function handler() { echo $_POST['v']; }
}
`
		eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
		for _, ep := range eps {
			if ep.AuthLevel == models.Admin {
				t.Errorf("action %q was promoted to Admin with no capability check in sight", action)
			}
		}
	}
}

// TestSettingsMutationKeywordStillPromotes pins the bound of that deletion. The
// surviving keywords name Settings-API operations that core itself gates on
// manage_options, so they are not deleted along with the English ones.
func TestSettingsMutationKeywordStillPromotes(t *testing.T) {
	content := `<?php
add_action( 'wp_ajax_pfx_export_settings', array( $this, 'handler' ) );
class C {
	public function handler() { echo 1; }
}
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	level, ok := levelOf(eps, "wp-admin/admin-ajax.php?action=pfx_export_settings")
	if !ok {
		t.Fatalf("no endpoint; got %+v", eps)
	}
	if level != models.Admin {
		t.Errorf("level = %s, want admin: _export_settings is still an admin indicator", level)
	}
}

// TestHookNameIsEvaluatedNotMatched
//
// PHP has one string type and one concatenation operator, and WordPress
// dispatches on the VALUE: do_action( 'wp_ajax_' . $_REQUEST['action'] ). A
// detector that accepts only one spelling of a string expression is matching
// syntax where WordPress matches value, and the registrations it misses produce
// no endpoint at all.
func TestHookNameIsEvaluatedNotMatched(t *testing.T) {
	content := `<?php
class T {
	const P = 'pfx_';
	function __construct() {
		add_action('admin_post_' . self::P . 'go', array($this, 'g'));
		$full = 'wp_ajax_' . 'assembled';
		add_action($full, array($this, 'k'));
	}
	function g() {}
	function k() {}
}
`
	eps := detectAll(content)
	for _, want := range []struct {
		route    string
		callback string
		level    models.AuthLevel
	}{
		{"wp-admin/admin-post.php?action=pfx_go", "this::g", models.Subscriber},
		{"wp-admin/admin-ajax.php?action=assembled", "this::k", models.Subscriber},
	} {
		level, ok := levelOf(eps, want.route)
		if !ok {
			t.Errorf("route %q produced no endpoint; got %+v", want.route, eps)
			continue
		}
		if level != want.level {
			t.Errorf("route %q reports %s, want %s", want.route, level, want.level)
		}
		if !routeHasCallback(eps, want.route, want.callback) {
			t.Errorf("route %q callbacks = %v, want %q", want.route, callbackListFor(eps, want.route), want.callback)
		}
	}
}

// TestEvaluatorIgnoresHooksCoreDoesNotDispatch pins the bound of the evaluator.
// Not every add_action is an entry point, and add_filter widens the surface
// further -- add_action() is literally `return add_filter(...)` in
// wp-includes/plugin.php, so both spellings register the same thing. Two core
// FILTERS begin with a dispatch prefix and are not entry points at all.
func TestEvaluatorIgnoresHooksCoreDoesNotDispatch(t *testing.T) {
	content := `<?php
add_action('init', 'boot');
add_action('admin_enqueue_scripts', array($this, 'scripts'));
add_filter('admin_post_thumbnail_html', array($this, 'filter_html'));
add_filter('admin_post_thumbnail_size', array($this, 'filter_size'));
add_action('wp_ajax_' . 'real_one', 'handler');
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	if len(eps) != 1 {
		t.Fatalf("expected exactly one endpoint (the wp_ajax_ registration); got %+v", eps)
	}
	if eps[0].Route != "wp-admin/admin-ajax.php?action=real_one" {
		t.Errorf("route = %q, want the wp_ajax_ one", eps[0].Route)
	}
}

// TestAddFilterRegistersARequestHook: wp-includes/plugin.php defines add_action
// as a direct call to add_filter with the same arguments, and do_action runs
// whatever sits in $wp_filter[$hook] regardless of which alias put it there.
//
// Shape taken from melapress-login-security 2.1.1
// app/helpers/class-user-importer.php:35-36.
func TestAddFilterRegistersARequestHook(t *testing.T) {
	content := `<?php
class A {
	public function __construct() {
		add_filter('wp_ajax_mls_export_users', array($this, 'export_users'), 10, 1);
	}
	public function export_users() { echo $_POST['x']; }
}
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	if !routeHasCallback(eps, "wp-admin/admin-ajax.php?action=mls_export_users", "this::export_users") {
		t.Errorf("add_filter registration was not seen; got %+v", eps)
	}
}

// TestCallbackShapeDoesNotGateRegistration
//
// The hook name and the callback are independent arguments. PHP accepts any
// callable in the second position -- a string, an array, a Closure, a static
// Closure (5.4), an arrow function (7.4) or a variable holding one -- and the
// language keeps adding to that list. An unrecognised callback used to discard
// the whole registration, which is the worst possible trade: the endpoint's
// existence is what the never-miss objective protects.
func TestCallbackShapeDoesNotGateRegistration(t *testing.T) {
	content := `<?php
class A {
	public function __construct() {
		add_action('wp_ajax_c1', static function () { echo 1; });
		add_action('wp_ajax_c2', fn() => 1);
		add_action('wp_ajax_c3', __CLASS__ . '::handler');
		$cb = array($this, 'handler2');
		add_action('wp_ajax_c4', $cb);
	}
}
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	for route, want := range map[string]string{
		"wp-admin/admin-ajax.php?action=c1": "closure",
		"wp-admin/admin-ajax.php?action=c2": "closure",
		"wp-admin/admin-ajax.php?action=c3": "handler",
		"wp-admin/admin-ajax.php?action=c4": "this::handler2",
	} {
		if _, ok := levelOf(eps, route); !ok {
			t.Errorf("route %q produced no endpoint; got %+v", route, eps)
			continue
		}
		if !routeHasCallback(eps, route, want) {
			t.Errorf("route %q callbacks = %v, want %q", route, callbackListFor(eps, route), want)
		}
	}
}

// TestLoaderRegistrationKeepsItsMethodName is the bound an adversary found on
// the fix above. The WordPress-Plugin-Boilerplate loader passes the component
// object in argument 1 and the method name in argument 2; a bare object variable
// is a callable only if its class defines __invoke, so the callable is the pair.
// Reporting "$plugin_admin" as the callback would manufacture an endpoint that
// looks like coverage and reaches nothing -- and this shape occurs 189 times in
// the corpus.
func TestLoaderRegistrationKeepsItsMethodName(t *testing.T) {
	content := `<?php
class L {
	function define_admin_hooks() {
		$plugin_admin = new Admin();
		$this->loader->add_action( 'wp_ajax_do_x', $plugin_admin, 'do_thing' );
		$this->loader->add_action( 'wp_ajax_nopriv_do_x', $plugin_admin, 'do_thing' );
	}
}
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	if !routeHasCallback(eps, "wp-admin/admin-ajax.php?action=do_x", "do_thing") {
		t.Errorf("the loader's method name was lost; callbacks = %v", callbackListFor(eps, "wp-admin/admin-ajax.php?action=do_x"))
	}
	for _, ep := range eps {
		if strings.Contains(ep.Callback, "$") {
			t.Errorf("callback %q is an expression, not a name", ep.Callback)
		}
	}
}

// TestConcatenatedCallbackIsFolded
//
// PHP evaluates 'ajax_' . 'X' to ajax_X before add_action ever sees it. The
// unevaluated text was being reported as the callback -- a string carrying a
// quote and a dot inside it, which can key no call-graph node. That is worse
// than a missed registration, because it looks like coverage.
//
// Shape taken from booking 9.9 includes/_capacity/create_booking.php:169-170
// (CVE-2024-1207), whose handler is declared in the same file.
func TestConcatenatedCallbackIsFolded(t *testing.T) {
	content := `<?php
add_action( 'wp_ajax_nopriv_' . 'AAA', 'ajax_' . 'AAA' );
add_action( 'wp_ajax_'        . 'AAA', 'ajax_' . 'AAA' );
function ajax_AAA() { echo $_POST['x']; }
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	level, ok := levelOf(eps, "wp-admin/admin-ajax.php?action=AAA")
	if !ok {
		t.Fatalf("no endpoint; got %+v", eps)
	}
	if level != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated", level)
	}
	if !routeHasCallback(eps, "wp-admin/admin-ajax.php?action=AAA", "ajax_AAA") {
		t.Errorf("callbacks = %v, want ajax_AAA", callbackListFor(eps, "wp-admin/admin-ajax.php?action=AAA"))
	}
	for _, ep := range eps {
		if strings.ContainsAny(ep.Callback, "'\".") {
			t.Errorf("callback %q still carries PHP syntax", ep.Callback)
		}
	}
}

// TestArrayCallbackWithConcatenatedMethodIsFolded covers the second way an
// unevaluated callback used to escape: the array-with-method alternative of the
// hook patterns captures only the first quoted fragment, so this arrived as
// "ajax_".
func TestArrayCallbackWithConcatenatedMethodIsFolded(t *testing.T) {
	content := `<?php
add_action('wp_ajax_avail', array($this, 'ajax_' . 'AVAIL'));
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	if !routeHasCallback(eps, "wp-admin/admin-ajax.php?action=avail", "this::ajax_AVAIL") {
		t.Errorf("callbacks = %v, want this::ajax_AVAIL", callbackListFor(eps, "wp-admin/admin-ajax.php?action=avail"))
	}
}

// TestHookTableBindsBothLoopVariables
//
// foreach ( $t as $k => $v ) binds BOTH names, and which one supplies the action
// is decided by which one the hook expression concatenates -- not by position.
// Here the key is the action and the VALUE is the handler, so a rule that took
// keys only would name thirty real handlers after their actions and resolve none
// of them.
//
// Shape taken from buddypress 14.3.3
// bp-templates/bp-legacy/buddypress-functions.php:188-191.
func TestHookTableBindsBothLoopVariables(t *testing.T) {
	content := `<?php
function bp_legacy_setup() {
	$actions = array(
		'delete_activity'     => 'bp_legacy_theme_delete_activity',
		'messages_send_reply' => 'bp_legacy_theme_messages_send_reply',
	);
	foreach ( $actions as $name => $function ) {
		add_action( 'wp_ajax_'        . $name, $function );
		add_action( 'wp_ajax_nopriv_' . $name, $function );
	}
}
function bp_legacy_theme_delete_activity() { echo $_POST['id']; }
function bp_legacy_theme_messages_send_reply() { echo $_POST['id']; }
`
	eps := DetectForeachLoopAJAXHandlers(content, "a.php", "testplugin")
	for route, want := range map[string]string{
		"wp-admin/admin-ajax.php?action=delete_activity":     "bp_legacy_theme_delete_activity",
		"wp-admin/admin-ajax.php?action=messages_send_reply": "bp_legacy_theme_messages_send_reply",
	} {
		level, ok := levelOf(eps, route)
		if !ok {
			t.Errorf("route %q produced no endpoint; got %+v", route, eps)
			continue
		}
		if level != models.Unauthenticated {
			t.Errorf("route %q reports %s, want unauthenticated: the loop registers a nopriv half", route, level)
		}
		if !routeHasCallback(eps, route, want) {
			t.Errorf("route %q callbacks = %v, want %q -- the handler is the table's VALUE", route, callbackListFor(eps, route), want)
		}
	}
}

// TestHookTableFollowsTheValueWhenTheHookNamesIt is the bound on that rule. It is
// stated over PHP's binding semantics rather than over the loop's form, so a
// table that maps label => action must yield the actions, not the labels. This
// shape occurs zero times in the 143-tree corpus, which is exactly why a
// positional rule would have survived it.
func TestHookTableFollowsTheValueWhenTheHookNamesIt(t *testing.T) {
	content := `<?php
function boot() {
	$map = array('label_one' => 'act_one', 'label_two' => 'act_two');
	foreach ($map as $label => $act) {
		add_action('wp_ajax_' . $act, 'cb_' . $act);
	}
}
`
	eps := DetectForeachLoopAJAXHandlers(content, "a.php", "testplugin")
	for route, want := range map[string]string{
		"wp-admin/admin-ajax.php?action=act_one": "cb_act_one",
		"wp-admin/admin-ajax.php?action=act_two": "cb_act_two",
	} {
		if !routeHasCallback(eps, route, want) {
			t.Errorf("route %q callbacks = %v, want %q", route, callbackListFor(eps, route), want)
		}
	}
	for _, ep := range eps {
		if strings.Contains(ep.Route, "label_") {
			t.Errorf("endpoint %q names a table KEY; PHP registers the value the hook expression concatenates", ep.Route)
		}
	}
}

// TestHookTableTakesNoPhantomActionsFromValues
//
// A registration that concatenates the KEY says nothing about the values, and
// harvesting quoted strings from the array indiscriminately turned a table of
// 'ACTION' => 'both' entries into endpoints named "both" and "admin".
//
// Shape taken from booking 9.9 core/lib/wpbc-ajax.php:433-465.
func TestHookTableTakesNoPhantomActionsFromValues(t *testing.T) {
	content := `<?php
function wpbc_boot() {
	$actions_list = array( 'ONE' => 'both', 'TWO' => 'admin' );
	foreach ($actions_list as $action_name => $action_where) {
		add_action( 'wp_ajax_' . $action_name, 'wpbc_ajax_' . $action_name );
	}
}
function wpbc_ajax_ONE() {}
function wpbc_ajax_TWO() {}
`
	eps := detectAll(content)
	for _, ep := range eps {
		action := strings.TrimPrefix(ep.Route, "wp-admin/admin-ajax.php?action=")
		if action == "both" || action == "admin" {
			t.Errorf("emitted a phantom endpoint %q taken from a table VALUE", ep.Route)
		}
	}
	if !routeHasCallback(eps, "wp-admin/admin-ajax.php?action=ONE", "wpbc_ajax_ONE") {
		t.Errorf("callbacks = %v, want wpbc_ajax_ONE", callbackListFor(eps, "wp-admin/admin-ajax.php?action=ONE"))
	}
}

// TestClassPropertyHookTable
//
// The table is held in a class property and the callback comes out of the table,
// which is the dominant real shape and the one no previous detector could match:
// the older one required the array's VARIABLE NAME to contain "ajax", "events",
// "actions" or "handlers", and required a bare $var rather than $this->prop.
//
// Shape taken from astra-sites inc/classes/class-astra-sites.php:155-173
// (CVE-2025-13065).
func TestClassPropertyHookTable(t *testing.T) {
	content := `<?php
class Ajax {
	private $handlers = array( 'save_form' => 'handle_save_form', 'delete_form' => 'handle_delete_form' );
	public function init() {
		foreach ( $this->handlers as $action => $method ) {
			add_action( 'wp_ajax_myplug_' . $action, array( $this, $method ) );
			add_action( 'wp_ajax_nopriv_myplug_' . $action, array( $this, $method ) );
		}
	}
	public function handle_save_form() { echo $_POST['a']; }
	public function handle_delete_form() { echo $_POST['b']; }
}
`
	eps := DetectForeachLoopAJAXHandlers(content, "a.php", "testplugin")
	for route, want := range map[string]string{
		"wp-admin/admin-ajax.php?action=myplug_save_form":   "this::handle_save_form",
		"wp-admin/admin-ajax.php?action=myplug_delete_form": "this::handle_delete_form",
	} {
		level, ok := levelOf(eps, route)
		if !ok {
			t.Errorf("route %q produced no endpoint; got %+v", route, eps)
			continue
		}
		if level != models.Unauthenticated {
			t.Errorf("route %q reports %s, want unauthenticated", route, level)
		}
		if !routeHasCallback(eps, route, want) {
			t.Errorf("route %q callbacks = %v, want %q", route, callbackListFor(eps, route), want)
		}
	}
}

// TestHookTableWithConditionalNoprivStaysAnonymous
//
// A table of action => bool whose nopriv half is registered inside `if ($nopriv)`
// is common. The flag is not evaluated per entry, so the whole table is reported
// as anonymously reachable. That under-restricts the entries whose flag is false,
// which is the safe direction, and it is what keeps the entries whose flag is
// true correct.
//
// Shape taken from user-registration 5.1.2 modules/membership/includes/AJAX.php,
// whose four evidence rows are the whole of CVE-2026-1492's prediction.
func TestHookTableWithConditionalNoprivStaysAnonymous(t *testing.T) {
	content := `<?php
class AJAX {
	public static function add_ajax_events() {
		$ajax_events = array(
			'create_member'   => false,
			'register_member' => true,
		);
		foreach ( $ajax_events as $ajax_event => $nopriv ) {
			add_action( 'wp_ajax_pfx_' . $ajax_event, array( __CLASS__, $ajax_event ) );
			if ( $nopriv ) {
				add_action(
					'wp_ajax_nopriv_pfx_' . $ajax_event,
					array(
						__CLASS__,
						$ajax_event,
					)
				);
			}
		}
	}
	public static function register_member() { echo $_POST['x']; }
	public static function create_member() { echo $_POST['x']; }
}
`
	eps := DetectForeachLoopAJAXHandlers(content, "a.php", "testplugin")
	route := "wp-admin/admin-ajax.php?action=pfx_register_member"
	level, ok := levelOf(eps, route)
	if !ok {
		t.Fatalf("route %q produced no endpoint; got %+v", route, eps)
	}
	if level != models.Unauthenticated {
		t.Errorf("route %q reports %s, want unauthenticated", route, level)
	}
	if !routeHasCallback(eps, route, "__CLASS__::register_member") {
		t.Errorf("route %q callbacks = %v, want __CLASS__::register_member", route, callbackListFor(eps, route))
	}
}

// TestHookTableFallsBackToTheEntryName is the bound on the callback rule. When
// the callback expression will not fold, the table entry the hook itself was
// built from is the guess this detector has always made, and it is right
// whenever a plugin names its handler after its action -- 254 of the 334
// endpoints the older foreach detectors emit. A raw unfoldable expression would
// be worse than that guess, because it can key no graph node at all.
func TestHookTableFallsBackToTheEntryName(t *testing.T) {
	content := `<?php
function boot() {
	$events = array('post_update', 'get_more');
	foreach ($events as $event) {
		add_action('wp_ajax_' . $event, array($this->handlers[$event], $this->method));
	}
}
`
	eps := DetectForeachLoopAJAXHandlers(content, "a.php", "testplugin")
	for route, want := range map[string]string{
		"wp-admin/admin-ajax.php?action=post_update": "post_update",
		"wp-admin/admin-ajax.php?action=get_more":    "get_more",
	} {
		if !routeHasCallback(eps, route, want) {
			t.Errorf("route %q callbacks = %v, want the fallback %q", route, callbackListFor(eps, route), want)
		}
	}
	for _, ep := range eps {
		if strings.ContainsAny(ep.Callback, "$[]()") {
			t.Errorf("callback %q is a raw expression; it can key no call-graph node", ep.Callback)
		}
	}
}

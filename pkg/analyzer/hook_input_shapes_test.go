package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

func hookRoutes(eps []models.Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, ep := range eps {
		out = append(out, ep.Route)
	}
	return out
}

// TestHookCallbackShapes covers the callback spellings the detector could not
// see. [$obj,'m'], [&$obj,'m'], ['Cls','m'] and [Cls::class,'m'] are the same PHP
// callable type and PHP invokes them identically, so recognising one spelling and
// not the others was matching text rather than semantics. array(&$this,'m') alone
// is 432 registrations in 37 of the 143 corpus plugins.
func TestHookCallbackShapes(t *testing.T) {
	cases := []struct {
		name         string
		php          string
		wantCallback string
	}{
		{
			"plain function name",
			`<?php add_action( 'init', 'lane_handle' ); function lane_handle() { echo 1; }`,
			"lane_handle",
		},
		{
			"array with $this, qualified by the enclosing class",
			`<?php
class Lane {
	function boot() { add_action( 'init', array( $this, 'handle' ) ); }
	function handle() { echo 1; }
}`,
			"Lane::handle",
		},
		{
			"array with a reference sigil before $this",
			`<?php
class Lane {
	function boot() { add_action( 'init', array( &$this, 'handle' ) ); }
	function handle() { echo 1; }
}`,
			"Lane::handle",
		},
		{
			"short array with $this",
			`<?php
class Lane {
	function boot() { add_action( 'init', [ $this, 'handle' ] ); }
	function handle() { echo 1; }
}`,
			"Lane::handle",
		},
		{
			"__CLASS__",
			`<?php
class Lane {
	function boot() { add_action( 'init', array( __CLASS__, 'handle' ) ); }
	static function handle() { echo 1; }
}`,
			"Lane::handle",
		},
		{
			"self::class",
			`<?php
class Lane {
	function boot() { add_action( 'init', [ self::class, 'handle' ] ); }
	static function handle() { echo 1; }
}`,
			"Lane::handle",
		},
		{
			"quoted class name",
			`<?php add_action( 'wp_loaded', array( 'Lane_Notice', 'hide' ) ); class Lane_Notice { static function hide() { echo 1; } }`,
			"Lane_Notice::hide",
		},
		{
			"Cls::class",
			`<?php add_action( 'init', [ Lane_Notice::class, 'hide' ] ); class Lane_Notice { static function hide() { echo 1; } }`,
			"Lane_Notice::hide",
		},
		{
			"Class::method written as one string",
			`<?php add_action( 'init', 'Lane_Notice::hide' ); class Lane_Notice { static function hide() { echo 1; } }`,
			"Lane_Notice::hide",
		},
		{
			// The receiving object cannot be named, so the bare method name is
			// all this file can offer as a graph key.
			"object held in a variable",
			`<?php add_action( 'init', array( $loader, 'run' ) ); function run() { echo 1; }`,
			"run",
		},
		{
			"object held in a property",
			`<?php
class Lane {
	function boot() { add_action( 'init', [ $this->loader, 'run' ] ); }
}`,
			"run",
		},
		{
			"singleton accessor",
			`<?php add_action( 'init', array( Lane::instance(), 'run' ) );`,
			"run",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eps := DetectHookInputEndpoints(c.php, "a.php", "p")
			if len(eps) != 1 {
				t.Fatalf("want exactly 1 endpoint, got %d: %v", len(eps), hookRoutes(eps))
			}
			if eps[0].Callback != c.wantCallback {
				t.Errorf("callback = %q, want %q", eps[0].Callback, c.wantCallback)
			}
			if eps[0].AuthLevel != models.Unauthenticated {
				t.Errorf("level = %s, want unauthenticated", eps[0].AuthLevel)
			}
			if eps[0].Line <= 0 {
				t.Errorf("line = %d, want a real line number", eps[0].Line)
			}
		})
	}
}

// TestHookCallbackWithoutSuperglobalStillSeeds is the reachability fix. The hook
// fires whether or not the callback body mentions $_POST, and the data may arrive
// as a hook argument or one call deeper in another file; requiring a superglobal
// in the same file turned a triage heuristic into a reachability criterion.
func TestHookCallbackWithoutSuperglobalStillSeeds(t *testing.T) {
	php := `<?php
class Lane {
	public function __construct() { add_action( 'init', array( $this, 'boot' ) ); }
	public function boot() { lane_deep_sink(); }
}`
	eps := DetectHookInputEndpoints(php, "lane.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint for a delegating callback, got %d: %v", len(eps), hookRoutes(eps))
	}
	if eps[0].Callback != "Lane::boot" {
		t.Errorf("callback = %q, want Lane::boot", eps[0].Callback)
	}

	// A callback whose body is not in this file at all must still seed.
	php = `<?php add_action( 'init', 'lane_elsewhere' );`
	eps = DetectHookInputEndpoints(php, "lane.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint for a cross-file callback, got %d: %v", len(eps), hookRoutes(eps))
	}
	if eps[0].AuthLevel != models.Unauthenticated {
		t.Errorf("cross-file seed level = %s, want unauthenticated", eps[0].AuthLevel)
	}
}

// TestHookSeedDoesNotInheritBodyGuard is the negative test that bounds the
// reachability fix, and the one the adversarial review turned on.
//
// A callback newly admitted by that fix must be emitted at Unauthenticated, not
// at the level of a capability check inside its body. The hook fires for anyone;
// a guard inside the body restricts what runs NEXT rather than who may call it.
// Reading the guard as the endpoint's level is how a lifecycle-hook callback
// became the sole evidence for a vulnerability whose truth is unauthenticated,
// and 99 of the newly admitted callbacks in 57 corpus plugins contain such a
// check.
func TestHookSeedDoesNotInheritBodyGuard(t *testing.T) {
	php := `<?php
class Lane {
	public function __construct() { add_action( 'init', array( $this, 'boot' ) ); }
	public function boot() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		$this->maybe_import();
	}
	public function maybe_import() { lane_sink(); }
}`
	eps := DetectHookInputEndpoints(php, "lane.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), hookRoutes(eps))
	}
	if eps[0].AuthLevel != models.Unauthenticated {
		t.Errorf("newly admitted seed = %s, want unauthenticated", eps[0].AuthLevel)
	}
}

// TestLegacyHookAnswerIsUnchanged is the other side of that bound. An endpoint
// that this detector already produced -- one of the original ten hooks, one of
// the original five spellings, registered with add_action, whose body really does
// read request input -- keeps its inferred level, so no hook_input answer already
// in the benchmark moves and the widening's delta stays attributable.
func TestLegacyHookAnswerIsUnchanged(t *testing.T) {
	php := `<?php
add_action( 'admin_init', 'lane_update_settings' );
function lane_update_settings() {
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'no' ); }
	update_option( 'lane', $_POST['value'] );
}`
	eps := DetectHookInputEndpoints(php, "lane.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), hookRoutes(eps))
	}
	if eps[0].AuthLevel != models.Admin {
		t.Errorf("legacy input-handling callback = %s, want admin", eps[0].AuthLevel)
	}

	// The same body on a hook the widening added is a new endpoint, so it is a
	// seed at Unauthenticated: nothing in the benchmark depended on it.
	php = strings.Replace(php, "'admin_init'", "'the_content'", 1)
	eps = DetectHookInputEndpoints(php, "lane.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), hookRoutes(eps))
	}
	if eps[0].AuthLevel != models.Unauthenticated {
		t.Errorf("newly covered hook = %s, want unauthenticated", eps[0].AuthLevel)
	}

	// So is the same body reached through a spelling the widening added.
	php = `<?php
class Lane {
	function boot() { add_action( 'admin_init', array( &$this, 'update_settings' ) ); }
	function update_settings() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'no' ); }
		update_option( 'lane', $_POST['value'] );
	}
}`
	eps = DetectHookInputEndpoints(php, "lane.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), hookRoutes(eps))
	}
	if eps[0].AuthLevel != models.Unauthenticated {
		t.Errorf("newly covered spelling = %s, want unauthenticated", eps[0].AuthLevel)
	}
}

// TestAddFilterRegistersLikeAddAction pins the core fact that add_action() is
// `return add_filter( ... )` in wp-includes/plugin.php: the two spellings register
// the same callback on the same hook, so a detector anchored on one of them is
// matching text rather than semantics.
func TestAddFilterRegistersLikeAddAction(t *testing.T) {
	php := `<?php add_filter( 'init', 'lane_f' ); function lane_f() { echo 1; }`
	eps := DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 1 || !strings.HasPrefix(eps[0].Route, "init:lane_f@") {
		t.Fatalf("add_filter on init -> %v, want one init:lane_f endpoint", hookRoutes(eps))
	}
}

// TestFrontEndHooksAreEndpoints covers the hooks WordPress fires while rendering a
// page for an anonymous visitor. A plugin whose entire user-facing surface is a
// the_content filter used to have no endpoint at all.
func TestFrontEndHooksAreEndpoints(t *testing.T) {
	for _, hook := range []string{"the_content", "wp_footer", "template_include", "pre_get_posts", "login_form", "comment_post", "widgets_init"} {
		t.Run(hook, func(t *testing.T) {
			php := `<?php add_filter( '` + hook + `', 'lane_render' ); function lane_render( $c ) { return $c . $_GET['q']; }`
			eps := DetectHookInputEndpoints(php, "a.php", "p")
			if len(eps) != 1 {
				t.Fatalf("want 1 endpoint on %s, got %v", hook, hookRoutes(eps))
			}
			if eps[0].AuthLevel != models.Unauthenticated {
				t.Errorf("%s -> %s, want unauthenticated", hook, eps[0].AuthLevel)
			}
		})
	}
}

// TestHooksDeliberatelyExcluded is the negative test on the hook table. Each of
// these fails the membership rule, and each was proposed at some point:
//
//   - admin_enqueue_scripts and admin_notices fire only after wp-admin/admin.php
//     has run auth_redirect() and the screen's own capability test, so their
//     cheapest path is not public;
//   - wp_enqueue_scripts is public but is a pure asset hook of enormous volume,
//     kept out on cost;
//   - muplugins_loaded is fired by wp-settings.php BEFORE the loop that includes
//     regularly activated plugins, so a plugin callback cannot be attached when it
//     fires and a registration on it seeds nothing.
func TestHooksDeliberatelyExcluded(t *testing.T) {
	for _, hook := range []string{"admin_enqueue_scripts", "admin_notices", "wp_enqueue_scripts", "muplugins_loaded", "shutdown", "save_post"} {
		t.Run(hook, func(t *testing.T) {
			php := `<?php add_action( '` + hook + `', 'lane_h' ); function lane_h() { echo $_GET['q']; }`
			if eps := DetectHookInputEndpoints(php, "a.php", "p"); len(eps) != 0 {
				t.Errorf("%s produced %v, want no endpoint", hook, hookRoutes(eps))
			}
		})
	}
}

// TestAdminScreenHookLevels covers the hooks core fires only while drawing a
// wp-admin screen. wp-admin/edit.php wp_die()s unless the caller holds the post
// type's edit_posts, which for a core post type is Contributor; for a custom post
// type it is that type's own mapped capability, which this file cannot see, so the
// answer falls back to the floor every wp-admin screen shares.
func TestAdminScreenHookLevels(t *testing.T) {
	cases := []struct {
		name string
		hook string
		want models.AuthLevel
	}{
		{"fixed-name list table hook", `'post_row_actions'`, models.Contributor},
		{"fixed-name editor hook", `'add_meta_boxes'`, models.Contributor},
		{"core post type spelled out", `'manage_post_posts_custom_column'`, models.Contributor},
		{"core screen id spelled out", `'manage_edit-post_columns'`, models.Contributor},
		{"post type computed with sprintf", `sprintf( 'manage_%s_posts_custom_column', $this->post_type )`, models.Subscriber},
		{"post type interpolated", `"manage_{$this->screen_id}_columns"`, models.Subscriber},
		{"post type concatenated", `'manage_' . $type . '_posts_custom_column'`, models.Subscriber},
		{"a custom post type spelled out", `'manage_lane_event_posts_custom_column'`, models.Subscriber},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			php := `<?php
class Lane {
	function boot() { add_action( ` + c.hook + `, [ $this, 'render_col' ], 10, 2 ); }
	function render_col( $col, $id ) { echo get_post_meta( $id, $col, true ); }
}`
			eps := DetectHookInputEndpoints(php, "a.php", "p")
			if len(eps) != 1 {
				t.Fatalf("want 1 endpoint, got %v", hookRoutes(eps))
			}
			if eps[0].AuthLevel != c.want {
				t.Errorf("%s -> %s, want %s", c.name, eps[0].AuthLevel, c.want)
			}
			if eps[0].Callback != "Lane::render_col" {
				t.Errorf("callback = %q, want Lane::render_col", eps[0].Callback)
			}
		})
	}
}

// TestMediaPipelineHooksAreUnauthenticated pins the family whose level cannot be
// argued from a wp-admin gate. delete_attachment fires inside wp_delete_attachment()
// and wp_check_filetype_and_ext inside _wp_handle_upload(); both are ordinary public
// functions, so the hook fires wherever they are called -- including from an
// anonymous front-end upload handler in this plugin, another plugin, or the theme.
// Claiming the wp-admin caller's capability there would be over-restriction over
// code an anonymous path reaches.
func TestMediaPipelineHooksAreUnauthenticated(t *testing.T) {
	for _, hook := range []string{"delete_attachment", "wp_check_filetype_and_ext", "add_attachment", "wp_handle_upload"} {
		t.Run(hook, func(t *testing.T) {
			php := `<?php
class Lane {
	function boot() { add_action( '` + hook + `', [ $this, 'purge' ], 10, 2 ); }
	function purge( $id ) { unlink( get_post_meta( $id, 'p', true ) ); }
}`
			eps := DetectHookInputEndpoints(php, "a.php", "p")
			if len(eps) != 1 {
				t.Fatalf("want 1 endpoint on %s, got %v", hook, hookRoutes(eps))
			}
			if eps[0].AuthLevel != models.Unauthenticated {
				t.Errorf("%s -> %s, want unauthenticated", hook, eps[0].AuthLevel)
			}
		})
	}
}

// TestSelfFiredScreenHookGetsUnauthenticatedCompanion covers the one loophole in
// "core fires this hook only from a gated screen": a plugin may fire it itself,
// from wherever it likes. Core is the only other firer, so "core's gate, unless
// this plugin fires it too" is exhaustive, and emitting both lets
// min-over-endpoints pick the cheaper. 7 of the 143 corpus plugins do this.
func TestSelfFiredScreenHookGetsUnauthenticatedCompanion(t *testing.T) {
	php := `<?php
class Lane {
	function boot() { add_action( 'add_meta_boxes', [ $this, 'boxes' ] ); }
	function boxes( $type, $post ) { echo 1; }
	function render_public_editor( $post ) { do_action( 'add_meta_boxes', 'lane', $post ); }
}`
	eps := DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 2 {
		t.Fatalf("want the screen endpoint and its self-fire companion, got %v", hookRoutes(eps))
	}
	levels := map[models.AuthLevel]bool{}
	for _, ep := range eps {
		levels[ep.AuthLevel] = true
		if ep.Callback != "Lane::boxes" {
			t.Errorf("callback = %q, want Lane::boxes", ep.Callback)
		}
	}
	if !levels[models.Contributor] || !levels[models.Unauthenticated] {
		t.Errorf("levels = %v, want both contributor and unauthenticated", hookRoutes(eps))
	}

	// The bound: without the self-fire there is no companion, or every screen
	// hook would silently become an unauthenticated seed.
	php = strings.Replace(php, "do_action( 'add_meta_boxes', 'lane', $post );", "echo 2;", 1)
	if eps := DetectHookInputEndpoints(php, "a.php", "p"); len(eps) != 1 {
		t.Fatalf("want only the screen endpoint without a self-fire, got %v", hookRoutes(eps))
	}
}

// TestHookRouteIsFileQualified stops the widening from ending in a discovery
// loss. deduplicateEndpoints keys on (route, method, type) across the whole
// plugin and keeps the higher auth level, so an unqualified "init:init" route --
// which 166 (hook, method) pairs in 75 of the 143 corpus plugins produce from more
// than one file -- would collapse several distinct callbacks onto one endpoint and
// raise the survivor's level into the bargain.
func TestHookRouteIsFileQualified(t *testing.T) {
	php := `<?php
class Lane {
	function boot() { add_action( 'init', [ $this, 'init' ] ); }
	function init() { echo 1; }
}`
	a := DetectHookInputEndpoints(php, "one.php", "p")
	b := DetectHookInputEndpoints(php, "two.php", "p")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("want one endpoint per file, got %v and %v", hookRoutes(a), hookRoutes(b))
	}
	if a[0].Route == b[0].Route {
		t.Errorf("routes from different files collide: %q", a[0].Route)
	}
	if got := deduplicateEndpoints(append(a, b...)); len(got) != 2 {
		t.Errorf("deduplicateEndpoints collapsed %v to %d endpoints, want 2", hookRoutes(append(a, b...)), len(got))
	}
}

// TestEachClosureGetsItsOwnEndpoint covers the last of the shapes. Matching the
// closure pattern once per (hook, file) and then extracting the FIRST closure in
// the file reported one endpoint carrying one body no matter how many were
// registered; 147 registrations in 50 corpus plugins are inline closures.
func TestEachClosureGetsItsOwnEndpoint(t *testing.T) {
	php := `<?php
add_action( 'init', function () { lane_first(); } );
add_action( 'init', function () { lane_second(); } );`
	eps := DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 2 {
		t.Fatalf("want one endpoint per closure, got %v", hookRoutes(eps))
	}
	for _, ep := range eps {
		// "closure" is the sentinel GetRecursiveCallsForCallback recognises, which
		// is what lets the walk fall back to this file's registered closures.
		if ep.Callback != "closure" {
			t.Errorf("closure callback = %q, want \"closure\"", ep.Callback)
		}
		if ep.Line <= 0 {
			t.Errorf("closure endpoint has no line number")
		}
	}
	if eps[0].Route == eps[1].Route {
		t.Errorf("two closures share the route %q", eps[0].Route)
	}
}

// TestNormalizeHookName pins the reduction that lets a computed hook name be
// looked up at all, including the case that must NOT reduce: a hook name held
// entirely in a variable names no hook this file can classify.
func TestNormalizeHookName(t *testing.T) {
	cases := []struct{ in, want string }{
		{`'init'`, "init"},
		{`"init"`, "init"},
		{`sprintf( "manage_%s_posts_custom_column", $this->post_type )`, "manage_*_posts_custom_column"},
		{`sprintf( 'manage_%1$s_columns', $screen )`, "manage_*_columns"},
		{`"manage_{$this->screen_id}_columns"`, "manage_*_columns"},
		{`'manage_' . $post_type . '_posts_columns'`, "manage_*_posts_columns"},
		{`"manage_edit-{$type}_columns"`, "manage_edit-*_columns"},
		{`$this->hook_name`, ""},
		{`$hook`, ""},
	}
	for _, c := range cases {
		if got := normalizeHookName(c.in); got != c.want {
			t.Errorf("normalizeHookName(%s) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestHookNameFromLocalVariable covers the shape the screen-hook families are
// almost always written in: the name is built into a variable, because the same
// string is wanted again for did_action() or remove_action(), and only then
// registered. PHP evaluates the argument, so this registers on exactly the hook
// the inline spelling would.
func TestHookNameFromLocalVariable(t *testing.T) {
	php := `<?php
class Lane {
	public function register(): void {
		$action = sprintf( "manage_%s_posts_custom_column", $this->post_type );
		if ( did_action( $action ) ) {
			throw new RuntimeException( 'too late' );
		}
		add_action( $action, [ $this, 'render_value' ], $this->priority, 2 );
	}
	public function render_value( $column, $id ) { echo get_post_meta( $id, $column, true ); }
}`
	eps := DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %v", hookRoutes(eps))
	}
	if eps[0].Callback != "Lane::render_value" || eps[0].AuthLevel != models.Subscriber {
		t.Errorf("got %s / %s, want Lane::render_value / subscriber", eps[0].Callback, eps[0].AuthLevel)
	}

	// The literal case must still work, and a hook this file models as public
	// must come through the variable at its own level, not the screen floor.
	php = `<?php $h = 'init'; add_action( $h, 'lane_go' ); function lane_go() { echo 1; }`
	eps = DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 1 || eps[0].AuthLevel != models.Unauthenticated {
		t.Fatalf("variable holding a literal hook -> %v", hookRoutes(eps))
	}

	// The bound: with nothing to resolve the variable to, there is no hook and
	// therefore no endpoint. Guessing would attach a callback to a hook the
	// plugin never registered it on.
	php = `<?php class Lane { function boot() { add_action( $this->hook_name, [ $this, 'go' ] ); } function go() { echo 1; } }`
	if eps := DetectHookInputEndpoints(php, "a.php", "p"); len(eps) != 0 {
		t.Errorf("unresolvable hook produced %v, want nothing", hookRoutes(eps))
	}
	php = `<?php add_action( $undefined_hook, 'lane_go' ); function lane_go() { echo 1; }`
	if eps := DetectHookInputEndpoints(php, "a.php", "p"); len(eps) != 0 {
		t.Errorf("variable with no assignment produced %v, want nothing", hookRoutes(eps))
	}
}

// TestHookCallbackWithoutSurroundingSpaces is a regression test for the argument
// parser. parseBalancedArgs declined to OPEN a string literal that began the
// region it was asked to parse, so the array elements of array('Cls','method')
// came back as one element and the registration was dropped -- while the same
// call written array( 'Cls', 'method' ) parsed fine, because the leading space
// moved the quote off offset zero.
func TestHookCallbackWithoutSurroundingSpaces(t *testing.T) {
	php := `<?php
class Lane {
	function boot() {
		add_action('wp_loaded', array('Lane_Notice','hide'));
		add_action('init', ['Lane_Notice','other']);
	}
}`
	eps := DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %v", hookRoutes(eps))
	}
	for _, ep := range eps {
		if !strings.HasPrefix(ep.Callback, "Lane_Notice::") {
			t.Errorf("callback = %q, want a Lane_Notice method", ep.Callback)
		}
	}
}

// TestHookEndpointLineNumbers pins the line each registration is reported at.
// Every endpoint this detector emitted used to carry Line 0, which makes the
// benchmark's declaration evidence tier unreachable for all of them. The count is
// accumulated across matches rather than recomputed from the start of the file,
// so an off-by-one here would drift with each further registration.
func TestHookEndpointLineNumbers(t *testing.T) {
	php := "<?php\n" + // 1
		"add_action( 'init', 'lane_a' );\n" + // 2
		"\n" + // 3
		"\n" + // 4
		"add_filter( 'the_content', 'lane_b' );\n" + // 5
		"\n" + // 6
		"add_action( 'wp_footer', 'lane_c' );\n" // 7
	want := map[string]int{"lane_a": 2, "lane_b": 5, "lane_c": 7}
	eps := DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 3 {
		t.Fatalf("want 3 endpoints, got %v", hookRoutes(eps))
	}
	for _, ep := range eps {
		if got := want[ep.Callback]; ep.Line != got {
			t.Errorf("%s reported at line %d, want %d", ep.Callback, ep.Line, got)
		}
	}
}

// TestClosureEndpointIsAlwaysASeed is the bound on the closure enumeration. The
// old pattern reported one endpoint per (hook, file) and then read the FIRST
// closure in the file, so the level it inferred often came from a different
// closure's body. Enumerating them properly must not turn that into a raise: a
// closure endpoint is a reachability seed at the hook's own level.
func TestClosureEndpointIsAlwaysASeed(t *testing.T) {
	php := `<?php
add_action( 'admin_init', function () {
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'no' ); }
	update_option( 'lane', $_POST['v'] );
} );`
	eps := DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %v", hookRoutes(eps))
	}
	if eps[0].AuthLevel != models.Unauthenticated {
		t.Errorf("closure endpoint = %s, want unauthenticated", eps[0].AuthLevel)
	}
}

// TestNamespacedFunctionCallback keeps a qualified function name usable. Every
// walk downstream keys on the bare tail, so the qualifier is stripped rather than
// read as a class name: '\Lane\boot' is a function called boot.
func TestNamespacedFunctionCallback(t *testing.T) {
	php := `<?php add_action( 'init', '\Lane\Boot\run' ); `
	eps := DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 1 || eps[0].Callback != "run" {
		t.Fatalf("namespaced function callback -> %v", hookRoutes(eps))
	}

	// The bound: a genuine Class::method string still yields the class.
	php = `<?php add_action( 'init', 'Lane\Boot::run' ); `
	eps = DetectHookInputEndpoints(php, "a.php", "p")
	if len(eps) != 1 || eps[0].Callback != `Lane\Boot::run` {
		t.Fatalf("static string callback -> %v (cb %q)", hookRoutes(eps), eps[0].Callback)
	}
}

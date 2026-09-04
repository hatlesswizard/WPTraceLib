package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// findAdminEndpoint returns the endpoint whose route contains want, so a test
// can name a page by its menu slug without restating formatAdminRoute.
func findAdminEndpoint(t *testing.T, eps []models.Endpoint, want string) models.Endpoint {
	t.Helper()
	for _, ep := range eps {
		if ep.Type == models.EndpointTypeAdmin && strings.Contains(ep.Route, want) {
			return ep
		}
	}
	routes := make([]string, 0, len(eps))
	for _, ep := range eps {
		routes = append(routes, string(ep.Type)+" "+ep.Route)
	}
	t.Fatalf("no admin endpoint matching %q; got %v", want, routes)
	return models.Endpoint{}
}

// TestAdminPageKeepsDeclaredCapabilityLevel is the whole of the ladder fix.
//
// WordPress refuses the page before the callback runs when the caller lacks the
// declared capability, so the level of an admin page is at least the level of
// that capability. The if-chain this replaces knew only Admin, Subscriber and
// Unauthenticated, so every mid-tier capability fell through to Unauthenticated
// -- and only when the callback was declared in the same file, which is why each
// case here declares one.
func TestAdminPageKeepsDeclaredCapabilityLevel(t *testing.T) {
	cases := []struct {
		capability string
		want       models.AuthLevel
	}{
		{"read", models.Subscriber},
		{"edit_posts", models.Contributor},
		{"publish_posts", models.Author},
		{"upload_files", models.Author},
		{"edit_others_posts", models.Editor},
		{"moderate_comments", models.Editor},
		{"manage_options", models.Admin},
	}
	for _, c := range cases {
		t.Run(c.capability, func(t *testing.T) {
			php := `<?php
add_menu_page( 'T', 'T', '` + c.capability + `', 'lane_slug', 'lane_render' );
function lane_render() { echo 'hi'; }`
			ep := findAdminEndpoint(t, DetectAdminPages(php, "a.php", "p"), "lane_slug")
			if ep.AuthLevel != c.want {
				t.Errorf("capability %q -> %s, want %s", c.capability, ep.AuthLevel, c.want)
			}
		})
	}
}

// TestAdminPageCallbackRaisesAboveDeclaredCapability pins the other half of the
// maximum: a callback that really does gate its body may demand more than the
// menu does, and that must still come through.
func TestAdminPageCallbackRaisesAboveDeclaredCapability(t *testing.T) {
	php := `<?php
add_menu_page( 'T', 'T', 'edit_posts', 'lane_slug', 'lane_render' );
function lane_render() {
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'no' ); }
	echo 'admin only';
}`
	ep := findAdminEndpoint(t, DetectAdminPages(php, "a.php", "p"), "lane_slug")
	if ep.AuthLevel != models.Admin {
		t.Errorf("gated callback over an edit_posts menu -> %s, want admin", ep.AuthLevel)
	}
}

// TestAdminPageCallbackDoesNotRaiseOnNonGatingCheck is the negative test the
// soundness review asked for. is_super_admin() is not in capCheckPattern, so
// FindCapabilityGuards cannot see it and cannot classify it as non-gating;
// InferAuthLevel's admin-shaped-assertion step would therefore answer Admin for
// a body that only uses it to decide what to draw. Deriving the callback's
// contribution from StrongestGuard alone is what keeps a UI toggle from
// promoting an edit_posts page four levels.
func TestAdminPageCallbackDoesNotRaiseOnNonGatingCheck(t *testing.T) {
	php := `<?php
add_menu_page( 'T', 'T', 'edit_posts', 'lane_slug', 'lane_render' );
function lane_render() {
	if ( is_super_admin() ) { echo '<a href="#">network tools</a>'; }
	echo esc_html( $_GET['a'] );
}`
	ep := findAdminEndpoint(t, DetectAdminPages(php, "a.php", "p"), "lane_slug")
	if ep.AuthLevel != models.Contributor {
		t.Errorf("non-gating is_super_admin over an edit_posts menu -> %s, want contributor", ep.AuthLevel)
	}
}

// TestAdminPageCallbackDoesNotRaiseOnAmbiguousBody is the second negative test.
// findFunctionBody takes the FIRST "function <name>(" in the file, so when two
// classes declare a method of the same name the body it returns may belong to
// the other one. Raising a page's level on a guard from an unrelated class is
// over-restriction manufactured from a name collision, so the maximum is only
// taken when the name resolves to exactly one declaration.
func TestAdminPageCallbackDoesNotRaiseOnAmbiguousBody(t *testing.T) {
	php := `<?php
class Front {
	public function render() { echo do_shortcode( $_GET['tpl'] ); }
}
class Tools {
	public function render() {
		if ( ! current_user_can( 'moderate_comments' ) ) { return; }
		echo 'tools';
	}
}
add_menu_page( 'T', 'T', 'read', 'lane_slug', array( $front, 'render' ) );`
	ep := findAdminEndpoint(t, DetectAdminPages(php, "a.php", "p"), "lane_slug")
	if ep.AuthLevel != models.Subscriber {
		t.Errorf("ambiguous callback name over a read menu -> %s, want subscriber", ep.AuthLevel)
	}

	// With the collision removed the same guard must raise, or the guard above
	// would be indistinguishable from simply ignoring the callback.
	php = strings.Replace(php, "class Front {\n\tpublic function render() { echo do_shortcode( $_GET['tpl'] ); }\n}\n", "", 1)
	ep = findAdminEndpoint(t, DetectAdminPages(php, "a.php", "p"), "lane_slug")
	if ep.AuthLevel != models.Editor {
		t.Errorf("unambiguous gated callback over a read menu -> %s, want editor", ep.AuthLevel)
	}
}

// TestAdminPageSuperAdminNotSynthesisedByCombination pins the bound the
// soundness review put on the maximum. A page whose declared capability is a
// network capability and whose callback is resolvable must not be promoted six
// levels on the strength of one string: Admin is the ceiling the combination can
// produce.
func TestAdminPageSuperAdminNotSynthesisedByCombination(t *testing.T) {
	php := `<?php
add_menu_page( 'T', 'T', 'manage_network_options', 'lane_slug', 'lane_render' );
function lane_render() { echo 'hi'; }`
	ep := findAdminEndpoint(t, DetectAdminPages(php, "a.php", "p"), "lane_slug")
	if ep.AuthLevel != models.Admin {
		t.Errorf("manage_network_options with a resolvable callback -> %s, want admin", ep.AuthLevel)
	}
}

// TestUnknownAdminCapabilityIsSubscriberNotAdmin covers the other direction of
// error in this file. An unresolved capability argument is not evidence of
// administrator privilege; it is evidence of nothing beyond "this is a wp-admin
// screen", and wp-admin/admin.php calls auth_redirect() before any screen
// renders. Answering Admin there manufactured an over-restriction at 704 sites
// in 81 of the 143 corpus plugins.
func TestUnknownAdminCapabilityIsSubscriberNotAdmin(t *testing.T) {
	cases := []struct {
		name string
		php  string
		want models.AuthLevel
	}{
		{
			"capability held in a property",
			`<?php
class P {
	public function menu() {
		add_menu_page( 'T', 'T', $this->cap, 'lane_slug', array( $this, 'render' ) );
	}
	public function render() { echo 'hi'; }
}`,
			models.Subscriber,
		},
		{
			"capability held in a constant",
			`<?php add_menu_page( 'T', 'T', LANE_CAP, 'lane_slug', 'lane_render' ); function lane_render() { echo 'hi'; }`,
			models.Subscriber,
		},
		{
			// This case expected Admin when it was written, because a heuristic
			// then read the manage_ prefix as a core convention. That heuristic
			// is gone, and the expectation changed with it rather than the
			// behaviour being reinstated to satisfy the test.
			//
			// WordPress assigns no meaning to the shape of a capability name.
			// WP_User::get_role_caps() merges whatever arrays the site's roles
			// hold, and map_meta_cap's default branch is `$caps[] = $cap` with
			// no parsing at all. Core contradicts this particular convention
			// outright: manage_categories and manage_links are granted to the
			// EDITOR role, not to administrator. And manage_lane_widgets is a
			// plugin-defined capability, which core grants to nobody until the
			// plugin grants it -- frequently below Admin.
			//
			// Reading it as Admin was measured raising the privilege of
			// plugin-defined capabilities in 44 of 143 corpus trees on no
			// evidence, which is the direction that makes a reachable
			// vulnerability look gated. What the evidence does support is that
			// this is a wp-admin screen, and wp-admin/admin.php calls
			// auth_redirect() before any screen renders.
			"unrecognised capability whose name merely resembles a core convention",
			`<?php add_menu_page( 'T', 'T', 'manage_lane_widgets', 'lane_slug', 'lane_render' ); function lane_render() { echo 'hi'; }`,
			models.Subscriber,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ep := findAdminEndpoint(t, DetectAdminPages(c.php, "a.php", "p"), "lane_slug")
			if ep.AuthLevel != c.want {
				t.Errorf("%s -> %s, want %s", c.name, ep.AuthLevel, c.want)
			}
		})
	}
}

// TestAdminPageArrayCallbackIsNotTruncated covers the callback-capture half.
// The literal-string patterns capture the callback as ([^,)]+), which stops at
// the first comma, so a PHP array callable used to reach NormalizeCallback as
// "array( $this" and came out as the placeholder "this::callback". The harness
// treats that placeholder as unusable, so the page was discovered and then led
// nowhere -- 373 of the corpus's 1,968 admin endpoints.
func TestAdminPageArrayCallbackIsNotTruncated(t *testing.T) {
	cases := []struct {
		name string
		php  string
		want string
	}{
		{
			"add_menu_page with an array callable",
			`<?php add_menu_page( 'T', 'T', 'manage_options', 'lane_slug', array( $this, 'render_entries' ) );`,
			"this::render_entries",
		},
		{
			"add_menu_page with a short-array callable",
			`<?php add_menu_page( 'T', 'T', 'manage_options', 'lane_slug', [ $this, 'render_entries' ] );`,
			"this::render_entries",
		},
		{
			// add_submenu_page carries a leading parent_slug, so its callback is
			// the sixth argument, not the fifth.
			"add_submenu_page with an array callable",
			`<?php add_submenu_page( 'parent', 'T', 'T', 'manage_options', 'lane_slug', array( $this, 'render_entries' ) );`,
			"this::render_entries",
		},
		{
			"add_options_page with an array callable",
			`<?php add_options_page( 'T', 'T', 'manage_options', 'lane_slug', array( $this, 'render_entries' ) );`,
			"this::render_entries",
		},
		{
			// The bound: a plain string callback was never truncated and must
			// pass through untouched.
			"plain string callback",
			`<?php add_menu_page( 'T', 'T', 'manage_options', 'lane_slug', 'lane_render' );`,
			"lane_render",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ep := findAdminEndpoint(t, DetectAdminPages(c.php, "a.php", "p"), "lane_slug")
			if ep.Callback != c.want {
				t.Errorf("%s -> callback %q, want %q", c.name, ep.Callback, c.want)
			}
		})
	}
}

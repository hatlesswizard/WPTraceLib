package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// writeFakePlugin lays a plugin tree out on disk so a test can exercise the
// whole pipeline, merge included, rather than one detector in isolation.
func writeFakePlugin(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "myplug")
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func analyzeFake(t *testing.T, files map[string]string) []models.Endpoint {
	t.Helper()
	dir := writeFakePlugin(t, files)
	a := New(WithWorkers(2))
	res, err := a.AnalyzePlugin(context.Background(), dir)
	if err != nil {
		t.Fatalf("AnalyzePlugin: %v", err)
	}
	return res.Endpoints
}

// minLevelFor is the reduction every consumer of an endpoint list performs when
// it asks what an attacker needs: the weakest requirement among the records
// that describe the route.
func minLevelFor(eps []models.Endpoint, route string) (models.AuthLevel, bool) {
	out := models.SuperAdmin
	found := false
	for _, ep := range eps {
		if ep.Route != route {
			continue
		}
		if !found || ep.AuthLevel < out {
			out = ep.AuthLevel
		}
		found = true
	}
	return out, found
}

func callbacksFor(eps []models.Endpoint, route string) map[string]bool {
	out := map[string]bool{}
	for _, ep := range eps {
		if ep.Route == route {
			out[ep.Callback] = true
		}
	}
	return out
}

func levelsFor(eps []models.Endpoint, route string) map[models.AuthLevel]bool {
	out := map[models.AuthLevel]bool{}
	for _, ep := range eps {
		if ep.Route == route {
			out[ep.AuthLevel] = true
		}
	}
	return out
}

// TestBothAjaxArmsSurviveAsSeparateRecords pins the reachability half of the
// merge fix.
//
// admin-ajax.php is one URL and core chooses between wp_ajax_X and
// wp_ajax_nopriv_X on is_user_logged_in(), so formatAjaxRoute is right to map
// both hooks onto one route string. But the two hooks have independent callback
// lists, and here they bind different handlers. Keying the merge on the route
// alone kept one of the two and discarded the other, and since Endpoint.Callback
// is the only seed the reachability walk has, the discarded handler became
// reachable from nothing at all.
func TestBothAjaxArmsSurviveAsSeparateRecords(t *testing.T) {
	eps := analyzeFake(t, map[string]string{
		"plugin.php": `<?php
class P {
	function __construct() {
		add_action( 'wp_ajax_do_thing', array( $this, 'handle_admin' ) );
		add_action( 'wp_ajax_nopriv_do_thing', array( $this, 'handle_public' ) );
	}
	function handle_admin() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
	}
	function handle_public() {
		echo 'hi';
	}
}
`,
	})

	const route = "wp-admin/admin-ajax.php?action=do_thing"
	cbs := callbacksFor(eps, route)
	for _, want := range []string{"handle_admin", "handle_public"} {
		if !cbs[want] {
			t.Errorf("callback %q has no endpoint; the route's records are %v", want, cbs)
		}
	}

	// The route is anonymously dispatchable, so the requirement an attacker
	// faces is the weakest of its records.
	got, ok := minLevelFor(eps, route)
	if !ok {
		t.Fatalf("no endpoint on %s", route)
	}
	if got != models.Unauthenticated {
		t.Errorf("min over the route's records = %s, want unauthenticated", got)
	}
}

// TestAdminPageKeepsEveryRegisteredCapability pins the level half.
//
// A page slug registered twice with two capabilities is two facts about that
// page. The old rule kept only the stricter one, which is the over-restriction
// failure: it reports a gate that the other registration does not impose. The
// merge must surface both and let the caller decide, because whether the truth
// is the conjunction (two registrations under one parent, where core's
// $_wp_submenu_nopriv marker denies) or the weaker one (registrations under
// different parents, only one of which admin.php?page=slug resolves to) is not
// something the route string can tell.
func TestAdminPageKeepsEveryRegisteredCapability(t *testing.T) {
	eps := analyzeFake(t, map[string]string{
		"plugin.php": `<?php
class P {
	function __construct() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
	}
	function menu() {
		add_menu_page( 'T', 'T', 'manage_options', 'myslug', array( $this, 'render_a' ) );
		add_submenu_page( 'myslug', 'T', 'T', 'edit_posts', 'myslug', array( $this, 'render_b' ) );
	}
	function render_a() { echo 'a'; }
	function render_b() { echo 'b'; }
}
`,
	})

	const route = "wp-admin/admin.php?page=myslug"
	levels := levelsFor(eps, route)
	if !levels[models.Admin] {
		t.Errorf("manage_options registration lost; levels on %s are %v", route, levels)
	}
	if !levels[models.Contributor] {
		t.Errorf("edit_posts registration lost; levels on %s are %v", route, levels)
	}
	if got, _ := minLevelFor(eps, route); got != models.Contributor {
		t.Errorf("min over the route's records = %s, want contributor (edit_posts)", got)
	}
}

// TestMergeKeepsTheCheaperClaim is the unit-level statement of the same rule:
// when two records give one handler two levels, the cheaper one must reach the
// output, because it is the one an attacker can satisfy.
func TestMergeKeepsTheCheaperClaim(t *testing.T) {
	in := []models.Endpoint{
		{Route: "r", Method: "POST", Type: models.EndpointTypeAJAX,
			Callback: "handle", AuthLevel: models.Admin, File: "a.php", Line: 10},
		{Route: "r", Method: "POST", Type: models.EndpointTypeAJAX,
			Callback: "handle", AuthLevel: models.Unauthenticated, File: "b.php", Line: 20},
	}
	out := mergeEndpoints(in)
	if len(out) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(out), out)
	}
	seen := map[models.AuthLevel]bool{}
	for _, ep := range out {
		seen[ep.AuthLevel] = true
	}
	if !seen[models.Unauthenticated] {
		t.Error("the unauthenticated record was discarded; that is the over-restriction the merge exists to stop")
	}
	if !seen[models.Admin] {
		t.Error("the admin record was discarded; a consumer computing a maximum still needs it")
	}
}

// TestMergeDropsRecordsThatMakeTheSameClaim is the negative case that pins the
// bound. Widening the key must not turn the merge into a no-op: two detectors
// reporting one registration identically is still one fact, and only one record
// may survive it.
func TestMergeDropsRecordsThatMakeTheSameClaim(t *testing.T) {
	in := []models.Endpoint{
		{Route: "r", Method: "POST", Type: models.EndpointTypeAJAX,
			Callback: "handle", AuthLevel: models.Subscriber, File: "a.php", Line: 10},
		{Route: "r", Method: "POST", Type: models.EndpointTypeAJAX,
			Callback: "handle", AuthLevel: models.Subscriber, File: "a.php", Line: 12},
		{Route: "r", Method: "POST", Type: models.EndpointTypeAJAX,
			Callback: "handle", AuthLevel: models.Subscriber, File: "z.php", Line: 99},
	}
	out := mergeEndpoints(in)
	if len(out) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(out), out)
	}
	if out[0].File != "a.php" || out[0].Line != 10 {
		t.Errorf("survivor is %s:%d, want the first record in input order (a.php:10)", out[0].File, out[0].Line)
	}
}

// TestMergeKeepsAnonymousCallbackBesideNamedOne pins the removal of the
// "prefer the more informative callback" clause.
//
// A record whose callback is a sentinel used to be evicted by any named record
// on the same route. That was defensible only while an anonymous callback
// reached nothing; it now seeds its walk from the registrations in its own file,
// so evicting it deletes a real body -- and the file it names need not be the
// file the named record names.
func TestMergeKeepsAnonymousCallbackBesideNamedOne(t *testing.T) {
	in := []models.Endpoint{
		{Route: "r", Method: "GET", Type: models.EndpointTypeREST,
			Callback: "closure", AuthLevel: models.Unauthenticated, File: "routes.php", Line: 4},
		{Route: "r", Method: "GET", Type: models.EndpointTypeREST,
			Callback: "handle", AuthLevel: models.Unauthenticated, File: "other.php", Line: 8},
	}
	out := mergeEndpoints(in)
	if len(out) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(out), out)
	}
}

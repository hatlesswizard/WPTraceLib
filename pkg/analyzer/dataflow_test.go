package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// ---------------------------------------------------------------------------
// isDynamicRoute / extractPlaceholderFromRoute
// ---------------------------------------------------------------------------

func TestIsDynamicRoute(t *testing.T) {
	cases := []struct {
		route string
		want  bool
	}{
		{"wp-admin/admin-ajax.php?action={_action}", true},
		{"wp-admin/admin-ajax.php?action={action}", true},
		{"wp-admin/admin-ajax.php?action=filtersFrontend", false},
		{"wp-admin/admin-ajax.php?action=", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isDynamicRoute(tc.route)
		if got != tc.want {
			t.Errorf("isDynamicRoute(%q) = %v, want %v", tc.route, got, tc.want)
		}
	}
}

func TestExtractPlaceholderFromRoute(t *testing.T) {
	cases := []struct {
		route string
		want  string
	}{
		{"wp-admin/admin-ajax.php?action={_action}", "_action"},
		{"wp-admin/admin-ajax.php?action={action}", "action"},
		{"wp-admin/admin-ajax.php?action=filtersFrontend", ""},
	}
	for _, tc := range cases {
		got := extractPlaceholderFromRoute(tc.route)
		if got != tc.want {
			t.Errorf("extractPlaceholderFromRoute(%q) = %q, want %q", tc.route, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// extractArrayStringLiterals
// ---------------------------------------------------------------------------

func TestExtractArrayStringLiterals(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{`array('filtersFrontend', 'otherAction')`, []string{"filtersFrontend", "otherAction"}},
		{`['filtersFrontend']`, []string{"filtersFrontend"}},
		{`'filtersFrontend', 'woofilters_get'`, []string{"filtersFrontend", "woofilters_get"}},
		{``, nil},
	}
	for _, tc := range cases {
		got := extractArrayStringLiterals(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("extractArrayStringLiterals(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i, g := range got {
			if g != tc.want[i] {
				t.Errorf("extractArrayStringLiterals(%q)[%d] = %q, want %q", tc.input, i, g, tc.want[i])
			}
		}
	}
}

// ---------------------------------------------------------------------------
// resolveFromForeach — same file, inline literal array
// ---------------------------------------------------------------------------

func TestResolveFromForeach_InlineArray_DirectProp(t *testing.T) {
	fileContent := `
class FrameWpf {
    public function registerActions() {
        foreach (array('filtersFrontend', 'getOptions') as $this->_action) {
            add_action('wp_ajax_nopriv_' . $this->_action, array($this, $this->_action));
        }
    }
}
`
	got := resolveFromForeach("_action", fileContent, nil)
	want := []string{"filtersFrontend", "getOptions"}
	assertStringSliceEqual(t, "resolveFromForeach direct prop inline array", got, want)
}

func TestResolveFromForeach_InlineArray_AssignedFromLoopVar(t *testing.T) {
	fileContent := `
class FrameWpf {
    public function registerActions() {
        foreach (array('filtersFrontend', 'getOptions') as $action) {
            $this->_action = $action;
            add_action('wp_ajax_nopriv_' . $this->_action, array($this, $this->_action));
        }
    }
}
`
	got := resolveFromForeach("_action", fileContent, nil)
	want := []string{"filtersFrontend", "getOptions"}
	assertStringSliceEqual(t, "resolveFromForeach assigned from loop var", got, want)
}

func TestResolveFromForeach_VariableArray(t *testing.T) {
	fileContent := `
class FrameWpf {
    public function registerActions() {
        $actions = array('filtersFrontend', 'getOptions');
        foreach ($actions as $this->_action) {
            add_action('wp_ajax_nopriv_' . $this->_action, array($this, $this->_action));
        }
    }
}
`
	got := resolveFromForeach("_action", fileContent, nil)
	want := []string{"filtersFrontend", "getOptions"}
	assertStringSliceEqual(t, "resolveFromForeach variable array", got, want)
}

// ---------------------------------------------------------------------------
// resolveFromForeach — cross-file method call
// ---------------------------------------------------------------------------

func TestResolveFromForeach_CrossFile_MethodCall(t *testing.T) {
	frameContent := `
class FrameWpf {
    public function registerActions($mod) {
        foreach ($mod->getActions() as $action) {
            $this->_action = $action;
            add_action('wp_ajax_nopriv_' . $this->_action, array($mod->getController(), $this->_action));
        }
    }
}
`
	modContent := `
class WoofiltersModWpf {
    public function getActions() {
        $actions = array();
        return array_merge($actions, array('filtersFrontend'));
    }
}
`
	allContents := map[string]string{
		"/plugin/modules/woofilters/mod.php": modContent,
	}

	got := resolveFromForeach("_action", frameContent, allContents)
	if len(got) == 0 {
		t.Fatal("resolveFromForeach cross-file: got empty result, want ['filtersFrontend']")
	}
	if !containsString(got, "filtersFrontend") {
		t.Errorf("resolveFromForeach cross-file: got %v, want to contain 'filtersFrontend'", got)
	}
}

// ---------------------------------------------------------------------------
// extractMethodReturnStrings
// ---------------------------------------------------------------------------

func TestExtractMethodReturnStrings_SimpleReturn(t *testing.T) {
	content := `
class Mod {
    public function getActions() {
        return array('filtersFrontend', 'getOptions');
    }
}
`
	got := extractMethodReturnStrings("getActions", content, nil)
	if !containsString(got, "filtersFrontend") {
		t.Errorf("extractMethodReturnStrings: got %v, want to contain 'filtersFrontend'", got)
	}
	if !containsString(got, "getOptions") {
		t.Errorf("extractMethodReturnStrings: got %v, want to contain 'getOptions'", got)
	}
}

func TestExtractMethodReturnStrings_ArrayMerge(t *testing.T) {
	content := `
class Mod {
    public function getActions() {
        $base = array();
        return array_merge($base, array('filtersFrontend'));
    }
}
`
	got := extractMethodReturnStrings("getActions", content, nil)
	if !containsString(got, "filtersFrontend") {
		t.Errorf("extractMethodReturnStrings array_merge: got %v, want to contain 'filtersFrontend'", got)
	}
}

func TestExtractMethodReturnStrings_NotFound(t *testing.T) {
	content := `class Mod { public function otherMethod() { return true; } }`
	got := extractMethodReturnStrings("getActions", content, nil)
	if len(got) != 0 {
		t.Errorf("extractMethodReturnStrings not found: got %v, want empty", got)
	}
}

func TestExtractMethodReturnStrings_CrossFile(t *testing.T) {
	currentFileContent := `class FrameWpf { public function registerActions() {} }`
	allContents := map[string]string{
		"/plugin/mod.php": `
class Mod {
    public function getActions() {
        return array('filtersFrontend', 'woofilters_count');
    }
}
`,
	}
	got := extractMethodReturnStrings("getActions", currentFileContent, allContents)
	if !containsString(got, "filtersFrontend") {
		t.Errorf("extractMethodReturnStrings cross-file: got %v, want to contain 'filtersFrontend'", got)
	}
}

// ---------------------------------------------------------------------------
// resolveUnresolvedEndpoints — full integration
// ---------------------------------------------------------------------------

func TestResolveUnresolvedEndpoints_ExpandsCorrectly(t *testing.T) {
	ep := models.Endpoint{
		PluginSlug: "woo-product-filter",
		Type:       models.EndpointTypeAJAX,
		Route:      "wp-admin/admin-ajax.php?action={_action}",
		Method:     "POST",
		AuthLevel:  models.Unauthenticated,
		Callback:   "filtersFrontend",
		File:       "classes/frame.php",
		RawCode:    "add_action('wp_ajax_nopriv_' . $this->_action, ...) [dynamic:unresolved:$this->_action]",
	}

	frameContent := `
class FrameWpf {
    public function registerActions($mod) {
        foreach (array('filtersFrontend', 'getOptions') as $action) {
            $this->_action = $action;
            add_action('wp_ajax_nopriv_' . $this->_action, array($mod->getController(), $this->_action));
        }
    }
}
`
	allContents := map[string]string{
		"/plugin/classes/frame.php": frameContent,
	}

	result := resolveUnresolvedEndpoints([]models.Endpoint{ep}, allContents, "/plugin")

	if len(result) < 2 {
		t.Fatalf("resolveUnresolvedEndpoints: got %d endpoints, want >= 2; routes: %v", len(result), routesOf(result))
	}

	routes := routesOf(result)
	if !containsString(routes, "wp-admin/admin-ajax.php?action=filtersFrontend") {
		t.Errorf("resolveUnresolvedEndpoints: routes %v missing filtersFrontend", routes)
	}
	if !containsString(routes, "wp-admin/admin-ajax.php?action=getOptions") {
		t.Errorf("resolveUnresolvedEndpoints: routes %v missing getOptions", routes)
	}
	for _, r := range result {
		if r.AuthLevel != models.Unauthenticated {
			t.Errorf("expanded endpoint %q has wrong auth level %v", r.Route, r.AuthLevel)
		}
	}
}

func TestResolveUnresolvedEndpoints_AnnotatesWhenUnresolvable(t *testing.T) {
	ep := models.Endpoint{
		PluginSlug: "myplugin",
		Type:       models.EndpointTypeAJAX,
		Route:      "wp-admin/admin-ajax.php?action={_action}",
		Method:     "POST",
		AuthLevel:  models.Unauthenticated,
		File:       "classes/frame.php",
		RawCode:    "add_action(...)",
	}

	allContents := map[string]string{
		"/plugin/classes/frame.php": `class FrameWpf { public function doSomethingElse() {} }`,
	}

	result := resolveUnresolvedEndpoints([]models.Endpoint{ep}, allContents, "/plugin")

	if len(result) != 1 {
		t.Fatalf("unresolvable: got %d endpoints, want 1", len(result))
	}
	if !strings.Contains(result[0].RawCode, "[dynamic:unresolved") {
		t.Errorf("unresolvable: RawCode %q missing [dynamic:unresolved] annotation", result[0].RawCode)
	}
	if !isDynamicRoute(result[0].Route) {
		t.Errorf("unresolvable: route %q should still be dynamic", result[0].Route)
	}
}

func TestResolveUnresolvedEndpoints_PassesThroughResolvedEndpoints(t *testing.T) {
	ep := models.Endpoint{
		PluginSlug: "myplugin",
		Type:       models.EndpointTypeAJAX,
		Route:      "wp-admin/admin-ajax.php?action=filtersFrontend",
		Method:     "POST",
		AuthLevel:  models.Unauthenticated,
		File:       "classes/frame.php",
	}

	result := resolveUnresolvedEndpoints([]models.Endpoint{ep}, nil, "/plugin")

	if len(result) != 1 {
		t.Fatalf("pass-through: got %d endpoints, want 1", len(result))
	}
	if result[0].Route != ep.Route {
		t.Errorf("pass-through: route changed from %q to %q", ep.Route, result[0].Route)
	}
}

func TestResolveUnresolvedEndpoints_CrossFileMethodCall(t *testing.T) {
	ep := models.Endpoint{
		PluginSlug: "woo-product-filter",
		Type:       models.EndpointTypeAJAX,
		Route:      "wp-admin/admin-ajax.php?action={_action}",
		Method:     "POST",
		AuthLevel:  models.Unauthenticated,
		File:       "classes/frame.php",
		RawCode:    "add_action('wp_ajax_nopriv_' . $this->_action, ...) [dynamic:unresolved:$this->_action]",
	}

	frameContent := `
class FrameWpf {
    public function registerActions($mod) {
        foreach ($mod->getActions() as $action) {
            $this->_action = $action;
            add_action('wp_ajax_nopriv_' . $this->_action, array($mod->getController(), $this->_action));
        }
    }
}
`
	modContent := `
class WoofiltersModWpf {
    public function getActions() {
        $actions = array();
        return array_merge($actions, array('filtersFrontend'));
    }
}
`
	allContents := map[string]string{
		"/plugin/classes/frame.php":          frameContent,
		"/plugin/modules/woofilters/mod.php": modContent,
	}

	result := resolveUnresolvedEndpoints([]models.Endpoint{ep}, allContents, "/plugin")

	routes := routesOf(result)
	if !containsString(routes, "wp-admin/admin-ajax.php?action=filtersFrontend") {
		t.Errorf("cross-file: routes %v missing filtersFrontend", routes)
	}
}

// ---------------------------------------------------------------------------
// End-to-end: DetectAJAXEndpoints produces annotated dynamic endpoints
// ---------------------------------------------------------------------------

func TestDetectAJAXEndpoints_DynamicNoprivAnnotated(t *testing.T) {
	content := `<?php
class FrameWpf {
    protected $_action;
    public function registerActions($mod) {
        foreach ($mod->getActions() as $action) {
            $this->_action = $action;
            add_action('wp_ajax_nopriv_' . $this->_action, array($mod->getController(), $this->_action));
            add_action('wp_ajax_' . $this->_action, array($mod->getController(), $this->_action));
        }
    }
}
`
	endpoints := DetectAJAXEndpoints(content, "classes/frame.php", "woo-product-filter")

	if len(endpoints) == 0 {
		t.Fatal("DetectAJAXEndpoints: expected at least one endpoint, got none")
	}

	hasDynamic := false
	for _, ep := range endpoints {
		if isDynamicRoute(ep.Route) {
			hasDynamic = true
			if !strings.Contains(ep.RawCode, "[dynamic:unresolved") {
				t.Errorf("dynamic endpoint %q missing [dynamic:unresolved] in RawCode: %q", ep.Route, ep.RawCode)
			}
			break
		}
	}
	if !hasDynamic {
		t.Errorf("DetectAJAXEndpoints: no dynamic routes found; endpoints: %v", routesOf(endpoints))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertStringSliceEqual(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: len=%d got=%v want=%v", name, len(got), got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d]: got=%q want=%q", name, i, got[i], want[i])
		}
	}
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func routesOf(eps []models.Endpoint) []string {
	routes := make([]string, len(eps))
	for i, ep := range eps {
		routes[i] = ep.Route
	}
	return routes
}

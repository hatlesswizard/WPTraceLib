package analyzer

import (
	"strings"
	"sync"
	"testing"
)

// assertChain verifies that every consecutive pair in a returned path is an
// edge the graph actually holds, so a test asserts a ROUTE and not a list of
// names that happen to appear in the right order.
//
// The first hop is exempt when fileContent was passed: callbackStart seeds a
// declared callback from ExtractFunctionCalls as well as from the graph, and
// those text tokens are deliberately not graph edges.
func assertChain(t *testing.T, cg *PluginCallGraph, path []string, fromBody bool) {
	t.Helper()
	start := 0
	if fromBody {
		start = 1
	}
	for i := start; i+1 < len(path); i++ {
		calls, aliases := cg.OutgoingCalls(path[i])
		found := false
		for _, c := range append(calls, aliases...) {
			if c == path[i+1] {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("path hop %d is not an edge: %q -> %q (full path %v)", i, path[i], path[i+1], path)
		}
	}
}

func TestPathFromCallbackFindsAndMissesCorrectly(t *testing.T) {
	files := map[string]string{
		"entry.php": `<?php
function cb_handle() { step_one(); }
function step_one() { target_sink(); }
function other_fn() { unrelated_sink(); }
`,
	}
	cg := BuildCallGraph(files)

	path, ok := cg.PathFromCallback("cb_handle", "target_sink")
	if !ok {
		t.Fatal("expected to reach target_sink")
	}
	want := []string{"cb_handle", "step_one", "target_sink"}
	if strings.Join(path, ">") != strings.Join(want, ">") {
		t.Errorf("path = %v, want %v", path, want)
	}
	assertChain(t, cg, path, false)

	if path, ok := cg.PathFromCallback("cb_handle", "unrelated_sink"); ok {
		t.Errorf("unrelated_sink is not reachable from cb_handle, got %v", path)
	} else if path != nil {
		t.Errorf("a miss should return a nil path, got %v", path)
	}
}

// TestPathAgreesWithTheCalleeSet is the invariant that keeps the path API and
// the callee walk honest: both start from callbackStart, so a path exists
// exactly when the callee set contains the target.
func TestPathAgreesWithTheCalleeSet(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		callback string
		bodyFile string
		targets  []string
	}{
		{
			name: "receiver and inheritance",
			files: map[string]string{
				"entry.php": `<?php
class Controller {
	public function handle() { $this->save(); }
	public function save() { $this->persist(); }
	public function persist() { persist_sink(); }
}
`,
			},
			callback: "Controller::handle",
			bodyFile: "entry.php",
			targets:  []string{"persist_sink", "persist", "Controller::persist", "nothing_here"},
		},
		{
			name: "hook edge",
			files: map[string]string{
				"hooks.php": `<?php
add_action( 'my_plugin_do', 'handle_it' );
function cb() { fire_it(); }
function fire_it() { do_action( 'my_plugin_do' ); }
function handle_it() { hook_sink(); }
`,
			},
			callback: "cb",
			bodyFile: "hooks.php",
			targets:  []string{"handle_it", "hook_sink", "my_plugin_do", "absent_fn"},
		},
		{
			name: "ambiguous bare name",
			files: map[string]string{
				"a.php":    `<?php function dup() { a_tail(); }`,
				"b.php":    `<?php function dup() { b_tail(); }`,
				"main.php": `<?php function cb() { dup(); }`,
			},
			callback: "cb",
			bodyFile: "main.php",
			targets:  []string{"a_tail", "b_tail", "dup", "c_tail"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg := BuildCallGraph(tc.files)
			content := tc.files[tc.bodyFile]
			for _, target := range tc.targets {
				_, ok := cg.PathFromCallbackInFile(tc.callback, target, tc.bodyFile, content)
				inSet := reaches(cg, tc.callback, content, target)
				if ok != inSet {
					t.Errorf("target %q: path says %v, callee set says %v", target, ok, inSet)
				}
			}
		})
	}
}

func TestPathFromCallbackTakesTheShorterRoute(t *testing.T) {
	files := map[string]string{
		"s.php": `<?php
function cb() { long_a(); quick(); }
function long_a() { long_b(); }
function long_b() { sink(); }
function quick() { sink(); }
`,
	}
	cg := BuildCallGraph(files)

	path, ok := cg.PathFromCallback("cb", "sink")
	if !ok {
		t.Fatal("expected to reach sink")
	}
	want := []string{"cb", "quick", "sink"}
	if strings.Join(path, ">") != strings.Join(want, ">") {
		t.Errorf("path = %v, want the shorter route %v", path, want)
	}
}

// TestPathThroughAHookNamesNoHook pins a documented limitation. extractCalls
// records a registered callback as a callee of the function that fires the
// hook, so the hook name is not a node and cannot appear on a route. If this
// test ever fails because the hook IS named, the graph started recording edge
// provenance and the doc comment is owed an update.
func TestPathThroughAHookNamesNoHook(t *testing.T) {
	files := map[string]string{
		"h.php": `<?php
add_action( 'my_plugin_do', 'handle_it' );
function cb() { fire_it(); }
function fire_it() { do_action( 'my_plugin_do' ); }
function handle_it() { hook_sink(); }
`,
	}
	cg := BuildCallGraph(files)

	path, ok := cg.PathFromCallback("cb", "hook_sink")
	if !ok {
		t.Fatalf("expected to reach hook_sink through the hook")
	}
	want := []string{"cb", "fire_it", "handle_it", "hook_sink"}
	if strings.Join(path, ">") != strings.Join(want, ">") {
		t.Errorf("path = %v, want %v", path, want)
	}
	for _, n := range path {
		if n == "my_plugin_do" || n == "do_action" {
			t.Errorf("a hook-mediated edge should name neither the hook nor do_action, got %v", path)
		}
	}
	assertChain(t, cg, path, false)
}

// TestPathPrefersTheQualifiedSpelling is the only test of pathNodeRank, and
// without it the API ships routes full of $this-> prefixes: one $this->step()
// site emits step, $this->step and Klass::step at the same depth, and $ sorts
// ahead of letters.
func TestPathPrefersTheQualifiedSpelling(t *testing.T) {
	files := map[string]string{
		"k.php": `<?php
class Klass {
	public function entry() { $this->step(); }
	public function step() { pref_sink(); }
}
`,
	}
	cg := BuildCallGraph(files)

	path, ok := cg.PathFromCallbackInFile("Klass::entry", "pref_sink", "k.php", files["k.php"])
	if !ok {
		t.Fatal("expected to reach pref_sink")
	}
	for _, n := range path {
		if strings.HasPrefix(n, "$this->") || strings.HasPrefix(n, "->") {
			t.Errorf("path reports a receiver-prefixed spelling: %v", path)
		}
	}
	if path[len(path)-1] != "pref_sink" {
		t.Errorf("path should end at the target, got %v", path)
	}
}

// TestPathTargetMatchesBareAndQualifiedSpellings covers both directions. The
// qualified-target-against-a-bare-token direction is the necessary one:
// extractCalls strips the class prefix at most call sites, so the bare token is
// frequently the only spelling on the route.
func TestPathTargetMatchesBareAndQualifiedSpellings(t *testing.T) {
	files := map[string]string{
		"entry.php": `<?php
class Controller {
	public function handle() { $svc = new Customer(); $svc->save(); }
}
`,
		"model.php": `<?php
class Customer {
	public function save() { $this->persist(); }
	public function persist() { }
}
`,
	}
	cg := BuildCallGraph(files)

	for _, target := range []string{"persist", "Customer::persist"} {
		path, ok := cg.PathFromCallbackInFile("Controller::handle", target, "entry.php", files["entry.php"])
		if !ok {
			t.Errorf("target %q: expected to reach it", target)
			continue
		}
		if path[0] != "Controller::handle" {
			t.Errorf("target %q: path should start at the resolved callback, got %v", target, path)
		}
		if got := pathMethodPart(path[len(path)-1]); !strings.EqualFold(got, "persist") {
			t.Errorf("target %q: path should end at the target, got %v", target, path)
		}
	}
}

func TestPathTerminatesOnCyclesAndSelfRecursion(t *testing.T) {
	files := map[string]string{
		"c.php": `<?php
function cb() { a_fn(); }
function a_fn() { b_fn(); }
function b_fn() { a_fn(); deep_sink(); }
function cb2() { cb2(); sink2(); }
`,
	}
	cg := BuildCallGraph(files)

	path, ok := cg.PathFromCallback("cb", "deep_sink")
	if !ok {
		t.Fatal("expected to reach deep_sink through a cycle")
	}
	if want := "cb>a_fn>b_fn>deep_sink"; strings.Join(path, ">") != want {
		t.Errorf("path = %v, want %s", path, want)
	}

	path, ok = cg.PathFromCallback("cb2", "sink2")
	if !ok {
		t.Fatal("expected to reach sink2 from a self-recursive callback")
	}
	seen := 0
	for _, n := range path {
		if n == "cb2" {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("the root should appear exactly once, got %v", path)
	}
}

// TestPathFromAFileCallback covers the direct-endpoint shape, including the
// "file:<relpath>" spelling direct.go emits and a backslash endpointFile
// against a slash-keyed graph.
func TestPathFromAFileCallback(t *testing.T) {
	files := map[string]string{
		"one/handler.php": `<?php one_sink();`,
		"two/handler.php": `<?php two_sink();`,
	}
	cg := BuildCallGraph(files)

	path, ok := cg.PathFromCallbackInFile("handler.php", "two_sink", "two/handler.php", "")
	if !ok {
		t.Fatal("expected to reach two_sink through the endpoint's own file")
	}
	if want := "two/handler.php>two_sink"; strings.Join(path, ">") != want {
		t.Errorf("path = %v, want %s", path, want)
	}

	// The spelling a direct endpoint actually carries.
	if _, ok := cg.PathFromCallbackInFile("file:two/handler.php", "two_sink", "two/handler.php", ""); !ok {
		t.Error("the file: spelling should resolve through the endpoint's own path")
	}

	// A separator the graph was not keyed with.
	if _, ok := cg.PathFromCallbackInFile("handler.php", "two_sink", `two\handler.php`, ""); !ok {
		t.Error("a backslash endpointFile should normalise against a slash-keyed graph")
	}

	// An ambiguous basename with no file must pick neither.
	if path, ok := cg.PathFromCallback("handler.php", "two_sink"); ok {
		t.Errorf("an ambiguous basename should not resolve to a file, got %v", path)
	}
}

func TestPathFromAnAnonymousCallback(t *testing.T) {
	files := map[string]string{
		"r.php": `<?php
register_rest_route( 'ns/v1', '/t', array(
	'callback' => function ( $req ) { return closure_step( $req ); },
) );
function closure_step( $req ) { closure_sink(); }
`,
	}
	cg := BuildCallGraph(files)

	path, ok := cg.PathFromCallbackInFile("closure", "closure_sink", "r.php", files["r.php"])
	if !ok {
		t.Fatal("expected to reach closure_sink from the registration closure")
	}
	if want := "closure>closure_step>closure_sink"; strings.Join(path, ">") != want {
		t.Errorf("path = %v, want %s", path, want)
	}

	// Without the file there is no closure body to read.
	if _, ok := cg.PathFromCallback("closure", "closure_sink"); ok {
		t.Error("an anonymous callback with no file content should reach nothing")
	}
}

// TestPathReachesBehindAPluginDeclaredCoreName covers testing the target before
// applying the stopping guard. Without that order a plugin's own update_option
// would be reported unreachable.
func TestPathReachesBehindAPluginDeclaredCoreName(t *testing.T) {
	declared := map[string]string{
		"d.php": `<?php
function cb() { update_option( 'x', 1 ); }
function update_option( $k, $v ) { core_named_sink(); }
`,
	}
	cg := BuildCallGraph(declared)

	path, ok := cg.PathFromCallbackInFile("cb", "core_named_sink", "d.php", declared["d.php"])
	if !ok {
		t.Fatal("a plugin's own update_option should be expanded")
	}
	if want := "cb>update_option>core_named_sink"; strings.Join(path, ">") != want {
		t.Errorf("path = %v, want %s", path, want)
	}

	// The guarded name is itself findable as a target.
	if path, ok := cg.PathFromCallbackInFile("cb", "update_option", "d.php", declared["d.php"]); !ok {
		t.Error("the target should be tested before the stopping guard")
	} else if want := "cb>update_option"; strings.Join(path, ">") != want {
		t.Errorf("path = %v, want %s", path, want)
	}

	// The negative twin: WordPress's update_option is not expanded.
	core := map[string]string{
		"d.php": `<?php function cb() { update_option( 'x', 1 ); }`,
	}
	cg = BuildCallGraph(core)
	if path, ok := cg.PathFromCallbackInFile("cb", "core_named_sink", "d.php", core["d.php"]); ok {
		t.Errorf("WordPress's update_option should not be walked into, got %v", path)
	}
}

func TestPathThroughATraitMethod(t *testing.T) {
	files := map[string]string{
		"t.php": `<?php
trait Saver { public function save() { trait_sink(); } }
class Repo {
	use Saver;
	public function handle() { $this->save(); }
}
`,
	}
	cg := BuildCallGraph(files)

	path, ok := cg.PathFromCallbackInFile("Repo::handle", "trait_sink", "t.php", files["t.php"])
	if !ok {
		t.Fatal("expected to reach a trait method's body")
	}
	if path[len(path)-1] != "trait_sink" {
		t.Errorf("path should end at trait_sink, got %v", path)
	}
	assertChain(t, cg, path, true)
}

// TestPathForAnAmbiguousNameIsNotLengthened: outgoingCalls merges a losing
// declaration's callees into the bare name's edges, so the route to either
// implementation's tail is the same length. The alias is also a valid target,
// and terminates a path.
func TestPathForAnAmbiguousNameIsNotLengthened(t *testing.T) {
	files := map[string]string{
		"a.php":    `<?php function dup() { a_tail(); }`,
		"b.php":    `<?php function dup() { b_tail(); }`,
		"main.php": `<?php function cb() { dup(); }`,
	}
	cg := BuildCallGraph(files)

	for _, target := range []string{"a_tail", "b_tail"} {
		path, ok := cg.PathFromCallback("cb", target)
		if !ok {
			t.Errorf("target %q: expected to reach it", target)
			continue
		}
		if len(path) != 3 {
			t.Errorf("target %q: an alias should not lengthen the path, got %v", target, path)
		}
	}

	// A qualified alias is a valid target. What comes back ends at a spelling
	// of it, which on this route is the bare token the call site actually says
	// -- the method-part clause of matchesPathTarget, and the trade-off its doc
	// comment names. A caller who needs to know which declaration it got reads
	// the last element; here that is the honest answer, because the call site
	// names no class at all.
	_, aliases := cg.OutgoingCalls("dup")
	if len(aliases) == 0 {
		t.Skip("fixture produced no alias; nothing to assert")
	}
	path, ok := cg.PathFromCallback("cb", aliases[0])
	if !ok {
		t.Fatalf("the alias %q should be reachable as a target", aliases[0])
	}
	if got, want := pathMethodPart(path[len(path)-1]), pathMethodPart(aliases[0]); got != want {
		t.Errorf("path should end at a spelling of %q, got %v", aliases[0], path)
	}
	if len(path) != 2 {
		t.Errorf("the alias is one hop from the callback, got %v", path)
	}
}

func TestPathIsStableAcrossRunsAndBuilds(t *testing.T) {
	files := map[string]string{
		"t.php": `<?php
function cb() { a_route(); b_route(); }
function a_route() { sink(); }
function b_route() { sink(); }
`,
	}

	want := ""
	for build := 0; build < 10; build++ {
		cg := BuildCallGraph(files)
		for call := 0; call < 5; call++ {
			path, ok := cg.PathFromCallback("cb", "sink")
			if !ok {
				t.Fatal("expected to reach sink")
			}
			got := strings.Join(path, ">")
			if want == "" {
				want = got
				continue
			}
			if got != want {
				t.Fatalf("path differs on build %d call %d: want %s, got %s", build, call, want, got)
			}
		}
	}
	if want != "cb>a_route>sink" {
		t.Errorf("unexpected stable path %q", want)
	}
}

// TestPathIsConcurrentSafe proves there is no data race and no lock-order
// inversion between cg.mu and HookRegistry.mu across the three walks.
//
// It cannot prove the absence of a deadlock from a nested RLock: nothing writes
// the graph after BuildCallGraph returns, so a nested acquisition would not
// block here. That the BFS holds no lock while calling outgoingCalls is a
// property of how it is written, not something this test establishes.
func TestPathIsConcurrentSafe(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php function dup() { a_tail(); }`,
		"b.php": `<?php function dup() { b_tail(); }`,
		"main.php": `<?php
add_action( 'ready', 'on_ready' );
trait H { public function h() { helped(); } }
class S {
	use H;
	public function run() { $this->h(); dup(); do_action( 'ready' ); }
}
function on_ready() { ready_sink(); }
`,
	}
	cg := BuildCallGraph(files)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cg.PathFromCallbackInFile("S::run", "ready_sink", "main.php", files["main.php"])
			cg.PathFromCallback("dup", "b_tail")
			cg.OutgoingCalls("S::run")
			GetRecursiveCallsForCallback(cg, "S::run", files["main.php"])
			cg.GetReachableFiles("S::run", "main.php")
		}()
	}
	wg.Wait()
}

func TestPathDegenerateAndRejectedInputs(t *testing.T) {
	files := map[string]string{
		"d.php": `<?php function cb() { tail(); }
function tail() { }
`,
	}
	cg := BuildCallGraph(files)

	// The callback is its own target.
	path, ok := cg.PathFromCallback("cb", "cb")
	if !ok {
		t.Fatal("a callback should reach itself")
	}
	if len(path) != 1 || path[0] != "cb" {
		t.Errorf("expected a one-element path, got %v", path)
	}

	for _, tc := range []struct{ callback, target string }{
		{"", "tail"},
		{"cb", ""},
		{"$cb", "tail"},
		{"foo(1)", "tail"},
	} {
		if path, ok := cg.PathFromCallback(tc.callback, tc.target); ok {
			t.Errorf("callback %q target %q should be rejected, got %v", tc.callback, tc.target, path)
		}
	}

	// A widget callback's empty argument list is trimmed, not rejected.
	wf := map[string]string{
		"w.php": `<?php class W { public function widget( $a, $b ) { widget_tail(); } }`,
	}
	wcg := BuildCallGraph(wf)
	if path, ok := wcg.PathFromCallbackInFile("W::widget()", "widget_tail", "w.php", wf["w.php"]); !ok {
		t.Error("a widget callback should resolve")
	} else if path[0] != "W::widget" {
		t.Errorf("path should start at the trimmed callback, got %v", path)
	}
}

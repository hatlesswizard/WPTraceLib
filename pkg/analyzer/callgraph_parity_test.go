package analyzer

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// treeNames is the set of functions a call chain names, at any depth.
//
// The truncation sentinel carries no function name and is skipped: it records
// that a sibling list was cut, not that anything was reached.
func treeNames(nodes []*models.CallChainNode) map[string]bool {
	out := make(map[string]bool)
	var walk func([]*models.CallChainNode)
	walk = func(ns []*models.CallChainNode) {
		for _, n := range ns {
			if n == nil {
				continue
			}
			if n.Function != "" {
				out[n.Function] = true
			}
			walk(n.Calls)
		}
	}
	walk(nodes)
	return out
}

// treeTruncated reports whether any node in a chain stopped for want of budget.
// A parity assertion over a truncated tree is meaningless, so every parity test
// asserts this is false first.
func treeTruncated(nodes []*models.CallChainNode) bool {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if n.Truncated || treeTruncated(n.Calls) {
			return true
		}
	}
	return false
}

func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	// Deterministic failure messages matter more than speed here.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// mustAgree asserts that the flat walk and the tree walk name exactly the same
// functions for one callback.
//
// This is the only test in the package that fails when one walk is taught
// something and the other is not, which is exactly how the two drifted: the
// flat walk learned hook seeding, outgoingCalls, the exception for a name the
// plugin declares itself, the trailing "()" of a widget callback, the callback
// that names a file, and closure seeding -- and the tree walk learned none of
// them, for two releases, with a green suite. It stayed green because every
// hierarchical test in callgraph_determinism_test.go passes "" for fileContent,
// which is the one input on which the two walks already agreed.
//
// Equality is exact rather than containment, and it is provable. Every name in
// the flat set is reached from the seed by some simple path; the tree walk's
// visited set forbids only repeating a name on the CURRENT path, so it explores
// every simple path and cannot miss one. Every name in the tree is reached by
// real edges from the seed, so the flat walk's closure contains it. The two
// stop expanding at the same names (skipCallee) and treat an alias the same way
// -- named, never expanded, because outgoingCalls has already folded an alias's
// own edges into the call list. The only way out is truncation, asserted away.
func mustAgree(t *testing.T, cg *PluginCallGraph, callback, endpointFile, fileContent string, wantReached ...string) {
	t.Helper()

	flat := GetRecursiveCallsForCallbackInFile(cg, callback, endpointFile, fileContent)
	flatSet := make(map[string]bool, len(flat))
	for _, c := range flat {
		flatSet[c] = true
	}

	tree := GetHierarchicalCallsForCallbackInFile(cg, callback, endpointFile, fileContent)
	if treeTruncated(tree) {
		t.Fatalf("callback %q: tree was truncated, so parity cannot be judged; widen the fixture or the bound", callback)
	}
	treeSet := treeNames(tree)

	for _, want := range wantReached {
		if !flatSet[want] {
			t.Errorf("callback %q: flat walk did not reach %q; got %v", callback, want, sortedNames(flatSet))
		}
		if !treeSet[want] {
			t.Errorf("callback %q: tree walk did not reach %q; got %v", callback, want, sortedNames(treeSet))
		}
	}

	for name := range flatSet {
		if !treeSet[name] {
			t.Errorf("callback %q: %q is in FunctionCalls but in no CallChain node", callback, name)
		}
	}
	for name := range treeSet {
		if !flatSet[name] {
			t.Errorf("callback %q: %q is in a CallChain node but not in FunctionCalls", callback, name)
		}
	}
	if t.Failed() {
		t.Logf("callback %q\n  flat: %v\n  tree: %v", callback, sortedNames(flatSet), sortedNames(treeSet))
	}
}

// TestFlatAndHierarchicalNameTheSameFunctions is the guard against the two
// walks drifting again. Every case sets fileContent to the file that declares
// the callback, because that is the branch the rest of the suite never
// exercises and the branch all six divergences lived in.
func TestFlatAndHierarchicalNameTheSameFunctions(t *testing.T) {
	cases := []struct {
		name        string
		files       map[string]string
		callback    string
		bodyFile    string // which file the endpoint was found in
		wantReached []string
	}{
		{
			name: "plain function",
			files: map[string]string{
				"entry.php": `<?php
add_action( 'wp_ajax_go', 'handle_go' );
function handle_go() { step_one(); }
function step_one() { deep_sink(); }
`,
			},
			callback:    "handle_go",
			bodyFile:    "entry.php",
			wantReached: []string{"step_one", "deep_sink"},
		},
		{
			name: "receiver method across files",
			files: map[string]string{
				"entry.php": `<?php
class Controller {
	public function handle() {
		$svc = new Customer();
		$svc->save();
	}
}
`,
				"model.php": `<?php
class Customer {
	public function save() { $this->persist(); }
	public function persist() { persist_sink(); }
}
`,
			},
			callback:    "Controller::handle",
			bodyFile:    "entry.php",
			wantReached: []string{"persist_sink"},
		},
		{
			name: "trait method",
			files: map[string]string{
				"repo.php": `<?php
trait Persists {
	public function save() { trait_sink(); }
}
class Repo {
	use Persists;
	public function handle() { $this->save(); }
}
`,
			},
			callback:    "Repo::handle",
			bodyFile:    "repo.php",
			wantReached: []string{"trait_sink"},
		},
		{
			name: "namespaced static call",
			files: map[string]string{
				"ns.php": `<?php
namespace Ns;
class Cls {
	public static function m() { ns_sink(); }
}
`,
				"caller.php": `<?php
function ns_entry() { \Ns\Cls::m(); }
`,
			},
			callback:    "ns_entry",
			bodyFile:    "caller.php",
			wantReached: []string{"ns_sink"},
		},
		{
			name: "hook edge at the root",
			files: map[string]string{
				"hooks.php": `<?php
add_action( 'wp_ajax_fire', 'fire_it' );
add_action( 'my_plugin_do', 'handle_it' );
function fire_it() { do_action( 'my_plugin_do' ); }
function handle_it() { hook_sink(); }
`,
			},
			callback:    "fire_it",
			bodyFile:    "hooks.php",
			wantReached: []string{"handle_it", "hook_sink"},
		},
		{
			name: "ambiguous bare name",
			files: map[string]string{
				"a.php":    `<?php function display() { func_a(); }`,
				"b.php":    `<?php function display() { func_b(); }`,
				"main.php": `<?php function entry() { display(); }`,
			},
			callback:    "entry",
			bodyFile:    "main.php",
			wantReached: []string{"display", "func_a", "func_b"},
		},
		{
			name: "plugin declaration shadowing a core name",
			files: map[string]string{
				"shadow.php": `<?php
add_action( 'wp_ajax_s', 'shadow_entry' );
function shadow_entry() { get_option( 'k' ); }
function get_option( $k ) { shadowed_sink(); }
`,
			},
			callback:    "shadow_entry",
			bodyFile:    "shadow.php",
			wantReached: []string{"get_option", "shadowed_sink"},
		},
		{
			name: "widget callback with an empty argument list",
			files: map[string]string{
				"widget.php": `<?php
class MyWidget {
	public function widget( $args, $instance ) { widget_sink(); }
}
`,
			},
			callback:    "MyWidget::widget()",
			bodyFile:    "widget.php",
			wantReached: []string{"widget_sink"},
		},
		{
			name: "callback naming a file",
			files: map[string]string{
				"one/handler.php": `<?php one_sink();`,
				"two/handler.php": `<?php two_sink();`,
			},
			callback:    "handler.php",
			bodyFile:    "two/handler.php",
			wantReached: []string{"two_sink"},
		},
		{
			name: "anonymous callback",
			files: map[string]string{
				"api.php": `<?php
register_rest_route( 'ns/v1', '/t', array(
	'callback' => function ( $req ) { return closure_step(); },
) );
function closure_step() { closure_sink(); }
`,
			},
			callback:    "closure",
			bodyFile:    "api.php",
			wantReached: []string{"closure_step", "closure_sink"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg := BuildCallGraph(tc.files)
			mustAgree(t, cg, tc.callback, tc.bodyFile, tc.files[tc.bodyFile], tc.wantReached...)
		})
	}
}

// TestHierarchicalRootSeedKeepsHookEdges is the reported bug.
//
// The tree's root level was seeded from ExtractFunctionCalls alone, which is a
// package-level function with no call graph and so cannot resolve a do_action to
// the callbacks registered for that hook. Only cg.extractCalls does that, and
// its result lives in CallsFrom. The effect: for every endpoint whose callback
// is declared in the file that registered it -- the ordinary case -- the root
// level of the tree lost every hook edge, while the flat list kept them. On
// contact-form-7 6.2 that put wpcf7_config_validator_update_option in
// FunctionCalls and in no CallChain at all.
func TestHierarchicalRootSeedKeepsHookEdges(t *testing.T) {
	files := map[string]string{
		"rest.php": `<?php
add_action( 'admin_init', 'upgrade_entry' );
add_action( 'plugin_update_option', 'validator_update_option', 10, 3 );
function upgrade_entry() { Plugin::update_option( 'version', '1.0' ); }
class Plugin {
	public static function update_option( $name, $value ) {
		do_action( 'plugin_update_option', $name, $value, null );
	}
}
function validator_update_option( $name, $value, $old ) { validator_sink(); }
`,
	}
	cg := BuildCallGraph(files)

	tree := GetHierarchicalCallsForCallback(cg, "upgrade_entry", files["rest.php"])
	names := treeNames(tree)
	for _, want := range []string{"validator_update_option", "validator_sink"} {
		if !names[want] {
			t.Errorf("hook edge lost from the tree: %q not named; got %v", want, sortedNames(names))
		}
	}

	// The same callback, resolved through the graph alone, must agree.
	mustAgree(t, cg, "upgrade_entry", "rest.php", files["rest.php"],
		"validator_update_option", "validator_sink")
}

// TestHierarchicalRootSeedInventsNoHookEdge bounds the test above: a hook that
// nothing registers for must not acquire callbacks.
func TestHierarchicalRootSeedInventsNoHookEdge(t *testing.T) {
	files := map[string]string{
		"rest.php": `<?php
add_action( 'admin_init', 'upgrade_entry' );
function upgrade_entry() { do_action( 'nobody_listens' ); }
function validator_update_option( $name ) { validator_sink(); }
`,
	}
	cg := BuildCallGraph(files)
	names := treeNames(GetHierarchicalCallsForCallback(cg, "upgrade_entry", files["rest.php"]))
	for _, unwanted := range []string{"validator_update_option", "validator_sink"} {
		if names[unwanted] {
			t.Errorf("tree invented an edge to %q for an unregistered hook; got %v", unwanted, sortedNames(names))
		}
	}
}

// TestHierarchicalFollowsPluginDeclarationShadowingCore covers the guard that
// buildCallTree carried without the exception the other two walks carried, so a
// plugin's own update_option was a followed edge in FunctionCalls and a
// childless leaf in -chain-human for the same endpoint.
func TestHierarchicalFollowsPluginDeclarationShadowingCore(t *testing.T) {
	declared := map[string]string{
		"main.php": `<?php
function entry() { update_option( 'k', 1 ); }
function update_option( $k, $v ) { shadowed_sink(); }
`,
	}
	cg := BuildCallGraph(declared)
	tree := GetHierarchicalCallsForCallback(cg, "entry", declared["main.php"])
	if names := treeNames(tree); !names["shadowed_sink"] {
		t.Errorf("a plugin's own update_option was not expanded; got %v", sortedNames(names))
	}

	// The negative twin. Without the declaration the name is WordPress's, so
	// the node is named and not expanded -- and that is a genuine leaf, not a
	// truncation.
	core := map[string]string{
		"main.php": `<?php
function entry() { update_option( 'k', 1 ); core_tail(); }
function core_tail() { }
`,
	}
	cg = BuildCallGraph(core)
	tree = GetHierarchicalCallsForCallback(cg, "entry", core["main.php"])
	var found *models.CallChainNode
	for _, n := range tree {
		if n.Function == "update_option" {
			found = n
		}
	}
	if found == nil {
		t.Fatalf("expected update_option to be named even though it is not expanded; got %v", sortedNames(treeNames(tree)))
	}
	if len(found.Calls) != 0 {
		t.Errorf("WordPress's update_option should not be expanded, got %d children", len(found.Calls))
	}
	if found.Truncated {
		t.Error("a name the walk declines to expand is a leaf, not a truncation")
	}
}

// TestHierarchicalResolvesReceiverAndTraitMethods covers the divergence that the
// tree read CallsFrom directly: "$this->save", "->save" and a namespaced name
// match no CallsFrom key, so every such call was a childless leaf and no method
// inherited from a trait or a parent was followed. Asserting the GRANDCHILD is
// what proves the walk went THROUGH the resolved declaration rather than merely
// naming it.
func TestHierarchicalResolvesReceiverAndTraitMethods(t *testing.T) {
	files := map[string]string{
		"entry.php": `<?php
class Controller {
	public function handle() { $this->save(); }
	public function save() { $this->persist(); }
	public function persist() { persist_sink(); }
}
`,
		"base.php": `<?php
class Base {
	public function inherited() { inherited_sink(); }
}
class Child extends Base {
	public function go() { $this->inherited(); }
}
`,
	}
	cg := BuildCallGraph(files)

	names := treeNames(GetHierarchicalCallsForCallback(cg, "Controller::handle", files["entry.php"]))
	if !names["persist_sink"] {
		t.Errorf("receiver chain not followed to its end; got %v", sortedNames(names))
	}

	names = treeNames(GetHierarchicalCallsForCallback(cg, "Child::go", files["base.php"]))
	if !names["inherited_sink"] {
		t.Errorf("a method inherited from a parent was not followed; got %v", sortedNames(names))
	}
}

// TestAliasIsALeafAndItsSubtreeIsNotPrintedTwice pins the decision that an alias
// hangs off a node as a leaf.
//
// An alias is another spelling of the thing it hangs off rather than something
// that thing calls, and outgoingCalls has already folded the alias's own edges
// into the call list -- so expanding it as well would print the same subtree
// twice under two names and spend twice the budget. Naming it is still worth a
// node: it is the record of WHICH declaration supplied func_b.
func TestAliasIsALeafAndItsSubtreeIsNotPrintedTwice(t *testing.T) {
	files := map[string]string{
		"a.php":    `<?php function display() { func_a(); }`,
		"b.php":    `<?php function display() { func_b(); }`,
		"main.php": `<?php function entry() { display(); }`,
	}
	cg := BuildCallGraph(files)
	tree := GetHierarchicalCallsForCallback(cg, "entry", "")

	var display *models.CallChainNode
	for _, n := range tree {
		if n.Function == "display" {
			display = n
		}
	}
	if display == nil {
		t.Fatalf("expected a display node; got %v", sortedNames(treeNames(tree)))
	}

	aliases := 0
	for _, child := range display.Calls {
		if !strings.Contains(child.Function, "::") {
			continue
		}
		aliases++
		if len(child.Calls) != 0 {
			t.Errorf("alias %q was expanded (%d children); an alias is a leaf", child.Function, len(child.Calls))
		}
	}
	if aliases == 0 {
		t.Fatalf("expected the qualified declaration to be named as a leaf; children were %v", childNames(display))
	}

	// Both implementations' callees are reached, and neither subtree is doubled.
	serial := serializeTree(tree, 0)
	for _, name := range []string{"func_a", "func_b"} {
		if got := strings.Count(serial, name); got != 1 {
			t.Errorf("expected %q exactly once, got %d:\n%s", name, got, serial)
		}
	}
}

func childNames(n *models.CallChainNode) []string {
	out := make([]string, 0, len(n.Calls))
	for _, c := range n.Calls {
		out = append(out, c.Function)
	}
	return out
}

// TestChainTruncationIsReported drives both bounds and checks that a cut tree
// says it was cut. Before this, a node returned by the circuit breaker was
// byte-identical to a genuine leaf, so an arbitrary depth-first prefix of the
// answer read as the whole answer.
func TestChainTruncationIsReported(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		php := "<?php\n"
		for i := 0; i < 30; i++ {
			php += "function level" + strconv.Itoa(i) + "() { level" + strconv.Itoa(i+1) + "(); }\n"
		}
		php += "function level30() { }\n"

		cg := BuildCallGraph(map[string]string{"main.php": php})
		tree := GetHierarchicalCallsForCallback(cg, "level0", "")
		if !treeTruncated(tree) {
			t.Fatalf("a 30-deep chain against a limit of %d must report truncation", maxChainDepth)
		}
		// The node AT the limit is the one that stopped, and it is the deepest.
		if count := countTreeNodes(tree); count != maxChainDepth {
			t.Errorf("expected %d nodes (level1 through the cut), got %d", maxChainDepth, count)
		}
		if names := treeNames(tree); names["level"+strconv.Itoa(maxChainDepth+1)] {
			t.Error("expansion continued past the depth limit")
		}
	})

	t.Run("shallow chain is not truncated", func(t *testing.T) {
		php := "<?php\n"
		for i := 0; i < 7; i++ {
			php += "function lvl" + strconv.Itoa(i) + "() { lvl" + strconv.Itoa(i+1) + "(); }\n"
		}
		php += "function lvl7() { }\n"

		cg := BuildCallGraph(map[string]string{"main.php": php})
		tree := GetHierarchicalCallsForCallback(cg, "lvl0", "")
		if treeTruncated(tree) {
			t.Errorf("a 7-deep chain sits inside the limit of %d and must not be cut", maxChainDepth)
		}
	})

	t.Run("branch budget", func(t *testing.T) {
		// 200 root callees, so each branch gets minBranchNodes; each branch then
		// wants 100 children, which does not fit.
		php := "<?php\nfunction root() {\n"
		for i := 0; i < 200; i++ {
			php += "\tfunc_" + strconv.Itoa(i) + "();\n"
		}
		php += "}\n"
		for i := 0; i < 200; i++ {
			php += "function func_" + strconv.Itoa(i) + "() {\n"
			for j := 0; j < 100; j++ {
				php += "\tsub_" + strconv.Itoa(i) + "_" + strconv.Itoa(j) + "();\n"
			}
			php += "}\n"
		}

		cg := BuildCallGraph(map[string]string{"main.php": php})
		tree := GetHierarchicalCallsForCallback(cg, "root", "")
		if !treeTruncated(tree) {
			t.Fatalf("200 branches of 101 nodes against a share of %d must report truncation", minBranchNodes)
		}
		// Every branch is bounded by its own share, so the whole forest is too.
		if count, ceiling := countTreeNodes(tree), 200*(minBranchNodes+1); count > ceiling {
			t.Errorf("expected at most %d nodes, got %d", ceiling, count)
		}
	})
}

// TestHierarchicalDirectEndpointCallbackNamesAFile covers the callback that is
// a .php file rather than a function. The tree walk had no topLevelKeyFor at
// all, so every direct endpoint rendered an empty chain.
func TestHierarchicalDirectEndpointCallbackNamesAFile(t *testing.T) {
	files := map[string]string{
		"one/handler.php": `<?php one_sink();`,
		"two/handler.php": `<?php two_sink();`,
	}
	cg := BuildCallGraph(files)

	names := treeNames(GetHierarchicalCallsForCallbackInFile(cg, "handler.php", "two/handler.php", ""))
	if !names["two_sink"] {
		t.Errorf("the endpoint's own file did not resolve; got %v", sortedNames(names))
	}
	if names["one_sink"] {
		t.Errorf("the wrong bootstrap was walked; got %v", sortedNames(names))
	}

	// Without the file, a basename two files share must resolve to neither
	// rather than to an arbitrary one of them.
	names = treeNames(GetHierarchicalCallsForCallback(cg, "handler.php", ""))
	if names["one_sink"] || names["two_sink"] {
		t.Errorf("an ambiguous basename picked a file anyway; got %v", sortedNames(names))
	}
}

// TestHierarchicalAnonymousCallbackIsSeededFromClosures covers the sentinel
// callbacks. Returning nil for them meant every route registered with an inline
// function rendered an empty chain while its flat list was complete.
func TestHierarchicalAnonymousCallbackIsSeededFromClosures(t *testing.T) {
	files := map[string]string{
		"api.php": `<?php
register_rest_route( 'ns/v1', '/thing', array(
	'methods'  => 'POST',
	'callback' => function ( $req ) { return persist_settings( $req ); },
) );
function persist_settings( $req ) { audit_log(); }
`,
	}
	cg := BuildCallGraph(files)

	for _, sentinel := range []string{"closure", "inline", "unknown"} {
		names := treeNames(GetHierarchicalCallsForCallback(cg, sentinel, files["api.php"]))
		for _, want := range []string{"persist_settings", "audit_log"} {
			if !names[want] {
				t.Errorf("callback %q: %q not named; got %v", sentinel, want, sortedNames(names))
			}
		}
	}
}

// TestHierarchicalTreeIsStableAcrossBuilds is what licenses removing the two
// sort.Strings calls the tree walk used to need.
//
// They were there because the old code built a map[string]bool union and had to
// put it back in order. outgoingCalls never iterates an unordered map, and
// BuildCallGraph processes its files in sorted order, so the slices it returns
// are already deterministic. Sorting here would have masked a future
// nondeterminism in BuildCallGraph rather than failing on it.
//
// The fixture carries every shape that could reintroduce map iteration: a name
// two files declare, a hook edge, a trait method and a receiver call.
func TestHierarchicalTreeIsStableAcrossBuilds(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php function shared() { from_a(); }`,
		"b.php": `<?php function shared() { from_b(); }`,
		"main.php": `<?php
add_action( 'plugin_ready', 'on_ready' );
trait Helps { public function help() { helped(); } }
class Svc {
	use Helps;
	public function run() { $this->help(); shared(); do_action( 'plugin_ready' ); }
}
function on_ready() { ready_sink(); }
`,
	}

	want := ""
	for run := 0; run < 20; run++ {
		cg := BuildCallGraph(files)
		got := serializeTree(GetHierarchicalCallsForCallback(cg, "Svc::run", files["main.php"]), 0)
		if run == 0 {
			want = got
			if !strings.Contains(got, "on_ready") || !strings.Contains(got, "helped") {
				t.Fatalf("fixture did not exercise hook and trait edges:\n%s", got)
			}
			continue
		}
		if got != want {
			t.Fatalf("tree differs on run %d:\nfirst:\n%s\nnow:\n%s", run, want, got)
		}
	}
}

// TestOutgoingCallsOrderIsStable pins the invariant underneath the test above.
// If this fails, the tree walk's determinism was resting on luck.
func TestOutgoingCallsOrderIsStable(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php function dup() { a_tail(); }`,
		"b.php": `<?php function dup() { b_tail(); }`,
		"c.php": `<?php function dup() { c_tail(); }`,
		"main.php": `<?php
add_action( 'fam_one', 'fam_one_cb' );
add_action( 'fam_two', 'fam_two_cb' );
trait T { public function m() { t_tail(); } }
class K {
	use T;
	public function go() { dup(); $this->m(); do_action( 'fam_' . $which ); }
}
function fam_one_cb() { }
function fam_two_cb() { }
`,
	}

	var wantCalls, wantAliases string
	for run := 0; run < 20; run++ {
		cg := BuildCallGraph(files)
		for _, name := range []string{"K::go", "dup"} {
			calls, aliases := cg.outgoingCalls(name)
			c, a := strings.Join(calls, ","), strings.Join(aliases, ",")
			if run == 0 && name == "K::go" {
				wantCalls, wantAliases = c, a
				continue
			}
			if name != "K::go" {
				continue
			}
			if c != wantCalls {
				t.Fatalf("calls for K::go differ on run %d:\n want %s\n  got %s", run, wantCalls, c)
			}
			if a != wantAliases {
				t.Fatalf("aliases for K::go differ on run %d:\n want %s\n  got %s", run, wantAliases, a)
			}
		}
	}
	if wantCalls == "" {
		t.Fatal("fixture produced no edges out of K::go")
	}
}

// TestEnrichmentIsKeyedOnCallbackAndFile covers the memoisation key.
//
// A tree depends on the callback AND on the file its body is looked up in,
// because callbackStart reads the declaration out of that file and seeds the
// root with what it finds there. The hierarchical enricher keyed on the callback
// alone, so the first endpoint's tree was served to every later endpoint
// sharing the name -- and endpoints share callbacks constantly.
//
// The two endpoints below differ only in their file. The one whose file declares
// handle must name get_option, which can only come from the body:
// ExtractFunctionCalls keeps WordPress core names and extractCalls drops them,
// so get_option is in no CallsFrom entry. The other must not name it. Under a
// callback-only key one of those two assertions fails whichever endpoint is
// computed first, so the test does not depend on endpoint order.
func TestEnrichmentIsKeyedOnCallbackAndFile(t *testing.T) {
	const pluginDir = "/plugin"
	rel := map[string]string{
		"one/a.php": `<?php
add_action( 'wp_ajax_alpha', 'handle' );
function handle() { get_option( 'k' ); alpha_sink(); }
`,
		"two/b.php": `<?php
add_action( 'wp_ajax_beta', 'handle' );
`,
	}

	files := make(map[string]string, len(rel))
	for name, src := range rel {
		files[filepath.Join(pluginDir, name)] = src
	}
	cg := BuildCallGraph(files)

	endpoints := []models.Endpoint{
		{Type: models.EndpointTypeAJAX, Route: "alpha", Callback: "handle", File: "one/a.php"},
		{Type: models.EndpointTypeAJAX, Route: "beta", Callback: "handle", File: "two/b.php"},
	}

	a := New(WithWorkers(1), WithChainMode(ChainModeHierarchical))
	a.enrichEndpointsWithHierarchicalCallGraph(endpoints, cg, files, pluginDir)

	alpha := treeNames(endpoints[0].CallChain)
	beta := treeNames(endpoints[1].CallChain)

	if !alpha["get_option"] {
		t.Errorf("the endpoint whose own file declares handle should name get_option from the body; got %v", sortedNames(alpha))
	}
	if beta["get_option"] {
		t.Errorf("the endpoint whose file does not declare handle reused the other's tree; got %v", sortedNames(beta))
	}
	// Both still reach what the graph knows.
	for i, names := range []map[string]bool{alpha, beta} {
		if !names["alpha_sink"] {
			t.Errorf("endpoint %d lost the graph edge to alpha_sink; got %v", i, sortedNames(names))
		}
	}
}

// TestEnrichmentPassesTheEndpointFile covers a callback that names a .php file.
//
// Both enrichers had already computed the endpoint's full path and then called
// the three-argument form, which passes "" for it. topLevelKeyFor therefore
// never got its path candidate in production and fell back to the
// unique-basename rule, so a direct endpoint sharing a basename with another
// file in the tree resolved to nothing -- 164 of the corpus's 618 such files.
func TestEnrichmentPassesTheEndpointFile(t *testing.T) {
	const pluginDir = "/plugin"
	rel := map[string]string{
		"one/handler.php": `<?php one_sink();`,
		"two/handler.php": `<?php two_sink();`,
	}
	files := make(map[string]string, len(rel))
	for name, src := range rel {
		files[filepath.Join(pluginDir, name)] = src
	}
	cg := BuildCallGraph(files)

	newEndpoints := func() []models.Endpoint {
		return []models.Endpoint{
			{Type: models.EndpointTypeDirect, Route: "/two/handler.php", Callback: "handler.php", File: "two/handler.php"},
		}
	}

	a := New(WithWorkers(1), WithChainMode(ChainModeHierarchical))
	hier := newEndpoints()
	a.enrichEndpointsWithHierarchicalCallGraph(hier, cg, files, pluginDir)
	names := treeNames(hier[0].CallChain)
	if !names["two_sink"] {
		t.Errorf("tree: the endpoint's own file did not resolve; got %v", sortedNames(names))
	}
	if names["one_sink"] {
		t.Errorf("tree: the wrong bootstrap was walked; got %v", sortedNames(names))
	}

	flat := newEndpoints()
	a.enrichEndpointsRecursively(flat, cg, files, pluginDir)
	flatSet := make(map[string]bool, len(flat[0].FunctionCalls))
	for _, c := range flat[0].FunctionCalls {
		flatSet[c] = true
	}
	if !flatSet["two_sink"] {
		t.Errorf("flat: the endpoint's own file did not resolve; got %v", flat[0].FunctionCalls)
	}
	if flatSet["one_sink"] {
		t.Errorf("flat: the wrong bootstrap was walked; got %v", flat[0].FunctionCalls)
	}
}

// TestEndpointFileDoesNotHijackANamedCallback pins the guard on topLevelKeyFor.
//
// topLevelKeyFor tries the endpoint's own path before the callback, so that a
// direct endpoint whose basename is ambiguous resolves to its own file. But the
// path is a disambiguator for a file-naming callback, not a substitute for one:
// without a check that the callback looks like a file at all, every callback
// found in a file that has load-time code resolves to that file's load-time
// node instead of to the function named.
//
// This was invisible while the only production caller passed "" for
// endpointFile. The first run that passed a real path took contact-form-7 from
// 991 distinct functions across its chains to 309, and lost the very chain this
// release exists to restore.
func TestEndpointFileDoesNotHijackANamedCallback(t *testing.T) {
	files := map[string]string{
		"boot.php": `<?php
// Load-time code, so this file has a top-level node of its own.
bootstrap_sink();
add_action( 'wp_ajax_go', 'named_handler' );
function named_handler() { handler_sink(); }
`,
	}
	cg := BuildCallGraph(files)

	if key := cg.topLevelKeyFor("named_handler", "boot.php"); key != "" {
		t.Errorf("a callback that is not file-shaped resolved to the file node %q", key)
	}
	if key := cg.topLevelKeyFor("boot.php", "boot.php"); key == "" {
		t.Error("a callback that names a file should still resolve to that file's node")
	}

	names := treeNames(GetHierarchicalCallsForCallbackInFile(cg, "named_handler", "boot.php", files["boot.php"]))
	if !names["handler_sink"] {
		t.Errorf("the named callback was not expanded; got %v", sortedNames(names))
	}
	if names["bootstrap_sink"] {
		t.Errorf("the callback was resolved to its file's load-time code; got %v", sortedNames(names))
	}

	mustAgree(t, cg, "named_handler", "boot.php", files["boot.php"], "handler_sink")
}

// TestGetCalleesNamesEachCalleeOnceAndResolvesMethods covers the last walk in
// the package that read CallsFrom raw.
//
// Two bugs, both visible in six lines. The visited gate sat below the append,
// so a callee reachable by two paths was listed twice; and keying on the
// declaration's spelling meant "$this->save" resolved to nothing, so no method
// reached through a receiver was followed.
//
// It has no caller inside this module -- AnalyzeCallback, its only one, has none
// either -- so this is for library consumers. It is also the precedent that
// would let the drift back in: after this, no walk in the package reads
// CallsFrom directly except outgoingCalls, topLevelKeyFor and the file walk.
func TestGetCalleesNamesEachCalleeOnceAndResolvesMethods(t *testing.T) {
	diamond := map[string]string{
		"main.php": `<?php
function entry() { left(); right(); }
function left() { shared(); }
function right() { shared(); }
function shared() { tail(); }
function tail() { }
`,
	}
	cg := BuildCallGraph(diamond)

	callees := cg.GetCallees("entry")
	counts := map[string]int{}
	for _, c := range callees {
		counts[c]++
	}
	for name, n := range counts {
		if n > 1 {
			t.Errorf("%q is listed %d times in %v", name, n, callees)
		}
	}
	for _, want := range []string{"left", "right", "shared", "tail"} {
		if counts[want] == 0 {
			t.Errorf("%q missing from %v", want, callees)
		}
	}

	receiver := map[string]string{
		"r.php": `<?php
class Customer {
	public function handle() { $this->save(); }
	public function save() { persisted(); }
}
function persisted() { }
`,
	}
	cg = BuildCallGraph(receiver)
	callees = cg.GetCallees("Customer::handle")
	found := false
	for _, c := range callees {
		if c == "persisted" {
			found = true
		}
	}
	if !found {
		t.Errorf("a receiver call was not resolved: GetCallees(Customer::handle) = %v", callees)
	}
}

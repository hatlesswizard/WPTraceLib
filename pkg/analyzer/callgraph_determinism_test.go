package analyzer

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// TestCallGraphDeterminism verifies that BuildCallGraph produces identical results
// across multiple runs, even when files contain standalone functions with the same name.
// This is a regression test for the non-deterministic map iteration order bug.
func TestCallGraphDeterminism(t *testing.T) {
	// Simulate a plugin with multiple files that define the same standalone function "display"
	files := map[string]string{
		"/plugin/admin/controllers/Submissions.php": `<?php
function display() {
	get_submissions_to_export();
	fopen("export.csv", "w");
	fclose($fh);
}

function get_submissions_to_export() {
	get_var("SELECT * FROM submissions");
}
`,
		"/plugin/frontend/controllers/FormPreview.php": `<?php
function display() {
	is_page();
	get_the_ID();
	all_not_embedded_forms();
}

function all_not_embedded_forms() {
	get_results();
}
`,
		"/plugin/admin/controllers/Manage.php": `<?php
function display() {
	connect_to_paypal();
	payment_information_template();
}

function connect_to_paypal() {
	wp_remote_post("https://paypal.com");
}
`,
		"/plugin/includes/helper.php": `<?php
function execute() {
	display();
	method_exists($obj, "action");
}

function form_maker_ajax() {
	ucfirst($task);
	substr($task, 0, 5);
	execute();
}
`,
	}

	// Run BuildCallGraph multiple times and verify identical output
	const runs = 20
	var firstCallsFrom string
	var firstAmbiguous string

	for i := 0; i < runs; i++ {
		cg := BuildCallGraph(files)

		// Serialize CallsFrom deterministically for comparison
		callsFromStr := serializeCallsFrom(cg)
		ambiguousStr := serializeAmbiguous(cg)

		if i == 0 {
			firstCallsFrom = callsFromStr
			firstAmbiguous = ambiguousStr
		} else {
			if callsFromStr != firstCallsFrom {
				t.Fatalf("CallsFrom differs on run %d:\nFirst:\n%s\n\nGot:\n%s", i+1, firstCallsFrom, callsFromStr)
			}
			if ambiguousStr != firstAmbiguous {
				t.Fatalf("AmbiguousFuncs differs on run %d:\nFirst:\n%s\n\nGot:\n%s", i+1, firstAmbiguous, ambiguousStr)
			}
		}
	}

	// Verify that "display" is marked as ambiguous
	cg := BuildCallGraph(files)
	cg.mu.RLock()
	ambKeys := cg.AmbiguousFuncs["display"]
	cg.mu.RUnlock()

	if len(ambKeys) == 0 {
		t.Fatal("Expected 'display' to be marked as ambiguous, but it has no ambiguous entries")
	}
	// We have 3 files with display(), first goes under bare key, other 2 get file-qualified
	if len(ambKeys) != 2 {
		t.Fatalf("Expected 2 ambiguous entries for 'display' (2nd and 3rd files), got %d: %v", len(ambKeys), ambKeys)
	}
}

// TestBuildCallTreeAmbiguousUnion verifies that buildCallTree includes calls from
// ALL implementations of an ambiguous function, not just one random one.
func TestBuildCallTreeAmbiguousUnion(t *testing.T) {
	files := map[string]string{
		"/plugin/a.php": `<?php
function display() {
	func_a();
}
`,
		"/plugin/b.php": `<?php
function display() {
	func_b();
}
`,
		"/plugin/main.php": `<?php
function entry() {
	display();
}
`,
	}

	cg := BuildCallGraph(files)

	// Build tree for "entry"
	tree := GetHierarchicalCallsForCallback(cg, "entry", "")
	if tree == nil {
		t.Fatal("Expected non-nil tree for 'entry'")
	}

	// Find the "display" node and collect its children
	var childNames []string
	for _, node := range tree {
		if node.Function == "display" {
			for _, child := range node.Calls {
				childNames = append(childNames, child.Function)
			}
			break
		}
	}

	if childNames == nil {
		t.Fatal("Expected to find 'display' node in tree")
	}

	// Both func_a and func_b should be present (union of all implementations)
	childSet := make(map[string]bool, len(childNames))
	for _, name := range childNames {
		childSet[name] = true
	}
	if !childSet["func_a"] {
		t.Error("Expected 'func_a' (from a.php) in display's children, but not found")
	}
	if !childSet["func_b"] {
		t.Error("Expected 'func_b' (from b.php) in display's children, but not found")
	}
}

// TestHierarchicalCallsForCallbackDeterminism checks that GetHierarchicalCallsForCallback
// produces identical results across multiple runs.
func TestHierarchicalCallsForCallbackDeterminism(t *testing.T) {
	files := map[string]string{
		"/plugin/admin/Submissions.php": `<?php
function display() {
	get_submissions_to_export();
	fopen("export.csv", "w");
}
`,
		"/plugin/frontend/FormPreview.php": `<?php
function display() {
	is_page();
	get_the_ID();
}
`,
		"/plugin/main.php": `<?php
function execute() {
	display();
}
function form_maker_ajax() {
	execute();
}
`,
	}

	const runs = 20
	var firstResult string

	for i := 0; i < runs; i++ {
		cg := BuildCallGraph(files)
		tree := GetHierarchicalCallsForCallback(cg, "form_maker_ajax", "")
		result := serializeTree(tree, 0)

		if i == 0 {
			firstResult = result
		} else if result != firstResult {
			t.Fatalf("Hierarchical calls differ on run %d:\nFirst:\n%s\n\nGot:\n%s", i+1, firstResult, result)
		}
	}

	// Verify that the tree includes calls from BOTH display() implementations
	cg := BuildCallGraph(files)
	tree := GetHierarchicalCallsForCallback(cg, "form_maker_ajax", "")
	result := serializeTree(tree, 0)

	if !strings.Contains(result, "get_submissions_to_export") {
		t.Error("Expected 'get_submissions_to_export' in tree (from Submissions.php display)")
	}
	if !strings.Contains(result, "is_page") {
		t.Error("Expected 'is_page' in tree (from FormPreview.php display)")
	}
}

// TestExtractCallsDeterminism verifies that extractCalls returns calls in sorted order.
func TestExtractCallsDeterminism(t *testing.T) {
	code := `{
	alpha();
	zebra();
	middle();
	$this->beta();
	gamma();
}`
	cg := NewPluginCallGraph()
	const runs = 20
	var firstResult string

	for i := 0; i < runs; i++ {
		result := strings.Join(cg.extractCalls(code), ",")
		if i == 0 {
			firstResult = result
		} else if result != firstResult {
			t.Fatalf("extractCalls differs on run %d:\nFirst: %s\nGot:   %s", i+1, firstResult, result)
		}
	}

	// Verify sorted order
	calls := cg.extractCalls(code)
	for i := 1; i < len(calls); i++ {
		if calls[i] < calls[i-1] {
			t.Fatalf("extractCalls not sorted: %v", calls)
		}
	}
}

// TestBuildCallTreePerPathVisited verifies that shared functions ARE expanded
// in each branch independently (per-path visited). The maxNodes cap prevents
// exponential blowup on large DAGs.
func TestBuildCallTreePerPathVisited(t *testing.T) {
	files := map[string]string{
		"/plugin/main.php": `<?php
function root_callback() {
	branch_a();
	branch_b();
}
function branch_a() {
	shared_func();
}
function branch_b() {
	shared_func();
}
function shared_func() {
	deep_call_1();
	deep_call_2();
}
function deep_call_1() { }
function deep_call_2() { }
`,
	}

	cg := BuildCallGraph(files)
	tree := GetHierarchicalCallsForCallback(cg, "root_callback", "")
	if tree == nil {
		t.Fatal("Expected non-nil tree")
	}

	count := countTreeNodes(tree)
	// With per-path visited: shared_func is expanded under BOTH branch_a and branch_b.
	// branch_a -> shared_func -> {deep_call_1, deep_call_2}
	// branch_b -> shared_func -> {deep_call_1, deep_call_2}
	// Total: 8 nodes
	if count != 8 {
		t.Fatalf("Expected exactly 8 nodes (shared_func expanded in both branches), got %d", count)
	}

	// Verify shared_func appears under both branches
	treeStr := serializeTree(tree, 0)
	if strings.Count(treeStr, "shared_func") != 2 {
		t.Fatalf("Expected shared_func to appear twice, got:\n%s", treeStr)
	}
	if !strings.Contains(treeStr, "deep_call_1") {
		t.Error("Expected 'deep_call_1' in tree")
	}
}

// TestBuildCallTreeMutualRecursionBounded verifies that mutual recursion is bounded
// by per-path cycle detection. Each path can't revisit ancestors, so the tree
// is naturally bounded. The maxNodes cap provides an additional safety net.
func TestBuildCallTreeMutualRecursionBounded(t *testing.T) {
	files := map[string]string{
		"/plugin/main.php": `<?php
function func_a() {
	func_b();
	func_c();
}
function func_b() {
	func_a();
	func_c();
}
function func_c() {
	func_a();
	func_b();
}
function entry() {
	func_a();
}
`,
	}

	cg := BuildCallGraph(files)
	tree := GetHierarchicalCallsForCallback(cg, "entry", "")
	if tree == nil {
		t.Fatal("Expected non-nil tree")
	}

	count := countTreeNodes(tree)
	// With per-path visited: func_a -> {func_b -> func_c, func_c -> func_b}.
	// Ancestors are skipped (cycle detection), but siblings expand independently.
	// Nodes: func_a, func_b, func_c, func_c, func_b = 5
	if count != 5 {
		t.Fatalf("Expected exactly 5 nodes for mutual recursion with per-path visited, got %d", count)
	}
}

// TestBuildCallTreeCircuitBreaker verifies the maxNodes safety limit stops tree growth.
func TestBuildCallTreeCircuitBreaker(t *testing.T) {
	// Create a wide call graph: root calls 200 functions, each calling 10 more
	php := "<?php\nfunction root() {\n"
	for i := 0; i < 200; i++ {
		php += "	func_" + strconv.Itoa(i) + "();\n"
	}
	php += "}\n"
	for i := 0; i < 200; i++ {
		php += "function func_" + strconv.Itoa(i) + "() {\n"
		for j := 0; j < 10; j++ {
			php += "	sub_" + strconv.Itoa(i) + "_" + strconv.Itoa(j) + "();\n"
		}
		php += "}\n"
	}

	files := map[string]string{"/plugin/main.php": php}
	cg := BuildCallGraph(files)
	tree := GetHierarchicalCallsForCallback(cg, "root", "")

	count := countTreeNodes(tree)
	// maxNodes is 10000 -- the tree should be capped
	if count > 10000 {
		t.Fatalf("Circuit breaker failed: expected at most 10000 nodes, got %d", count)
	}
}

// TestDeepCallChainsFullyTraversed verifies that deep linear call chains are
// fully traversed without artificial depth limits. With permanent visited marking,
// the tree is naturally bounded by unique functions, not depth.
func TestDeepCallChainsFullyTraversed(t *testing.T) {
	files := map[string]string{
		"/plugin/main.php": `<?php
function level0() { level1(); }
function level1() { level2(); }
function level2() { level3(); }
function level3() { level4(); }
function level4() { level5(); }
function level5() { level6(); }
function level6() { level7(); }
function level7() { }
`,
	}

	cg := BuildCallGraph(files)

	// The full chain should be captured (no depth limit, bounded by visited set)
	tree := GetHierarchicalCallsForCallback(cg, "level0", "")
	if tree == nil {
		t.Fatal("Expected non-nil tree")
	}

	// All 8 levels should be present (level0 is the root callback, level1-7 in tree)
	count := countTreeNodes(tree)
	if count != 7 {
		t.Fatalf("Expected 7 nodes (level1 through level7), got %d", count)
	}

	// Verify the deepest function is present
	treeStr := serializeTree(tree, 0)
	if !strings.Contains(treeStr, "level7") {
		t.Error("Expected 'level7' to be present in fully traversed tree")
	}
}

// Helper: count total nodes in a call chain tree
func countTreeNodes(nodes []*models.CallChainNode) int {
	count := len(nodes)
	for _, n := range nodes {
		count += countTreeNodes(n.Calls)
	}
	return count
}

// Helper: serialize CallsFrom map in deterministic order for comparison
func serializeCallsFrom(cg *PluginCallGraph) string {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	keys := make([]string, 0, len(cg.CallsFrom))
	for k := range cg.CallsFrom {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(cg.CallsFrom[k], ", "))
		sb.WriteString("\n")
	}
	return sb.String()
}

// Helper: serialize AmbiguousFuncs map in deterministic order
func serializeAmbiguous(cg *PluginCallGraph) string {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	keys := make([]string, 0, len(cg.AmbiguousFuncs))
	for k := range cg.AmbiguousFuncs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(cg.AmbiguousFuncs[k], ", "))
		sb.WriteString("\n")
	}
	return sb.String()
}

// Helper: serialize a call chain tree for comparison
func serializeTree(nodes []*models.CallChainNode, depth int) string {
	var sb strings.Builder
	for _, n := range nodes {
		sb.WriteString(strings.Repeat("  ", depth))
		sb.WriteString(n.Function)
		sb.WriteString("\n")
		if len(n.Calls) > 0 {
			sb.WriteString(serializeTree(n.Calls, depth+1))
		}
	}
	return sb.String()
}

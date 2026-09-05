package ast

import (
	"os"
	"path/filepath"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// The three map ranges under ResolvePermissionCallback used to answer with
// whichever candidate Go's randomised map iteration handed over first, so the
// same binary over the same tree could report an endpoint as unauthenticated on
// one run and admin on the next.
//
// No corpus run can hold that fix in place. Across the benchmark corpus the two
// suffix loops in resolveCallbackBody never see a second candidate at all, and
// while analyzeReturnExpression's `$this->m()` scan is genuinely ambiguous (38
// of its 72 resolutions have three candidates, and 19 of them answered out of a
// class the body does not belong to), all three of those bodies score the same
// level, so the endpoint output is identical either way. These fixtures are the
// only thing that exercises the flip, which makes them the only thing that can
// catch its return.
//
// Each test asserts the specific documented winner ipdetRepeats times in one
// process. Every ambiguous fixture below offers exactly two candidates whose
// bodies score differently, so the pre-fix code had an even chance per call: at
// 200 calls a green run on the old code is a 2^-200 event, not a lucky one.
const ipdetRepeats = 200

func ipdetParsePlugin(t *testing.T, files map[string]string) *PluginAST {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	pluginAST, err := ParsePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	return pluginAST
}

func ipdetAuthAnalyzer(t *testing.T, files map[string]string) (*AuthAnalyzer, *PluginAST) {
	t.Helper()
	pluginAST := ipdetParsePlugin(t, files)
	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	return NewAuthAnalyzer(st, h, pluginAST), pluginAST
}

// ipdetStableLevel runs the callback through AnalyzePermissionCallback
// ipdetRepeats times and fails on the first answer that is not want, naming the
// iteration so a flake is not mistaken for a constant.
func ipdetStableLevel(t *testing.T, aa *AuthAnalyzer, ref CallbackRef, want models.AuthLevel) {
	t.Helper()
	for i := 0; i < ipdetRepeats; i++ {
		got := aa.AnalyzePermissionCallback(ref)
		if got != want {
			t.Fatalf("iteration %d: expected %v, got %v", i, want, got)
		}
	}
}

// Two namespaces declare the same function name and the callback string carries
// no namespace, so both bodies match. The documented winner is the
// lexicographically smallest FQN: IpdetFnA\ipdet_perm_probe, whose body is
// `return true` -- Unauthenticated. Picking the other one would report Admin.
func TestResolveCallbackBody_FunctionNameCollision_PicksSmallestFQN(t *testing.T) {
	aa, _ := ipdetAuthAnalyzer(t, map[string]string{
		"fn_a.php": `<?php
namespace IpdetFnA;
function ipdet_perm_probe() { return true; }
`,
		"fn_b.php": `<?php
namespace IpdetFnB;
function ipdet_perm_probe() { return current_user_can('manage_options'); }
`,
	})

	// Both candidates must exist and must score differently, or the test would
	// pass for the wrong reason.
	if len(aa.SymTable.Functions) != 2 {
		t.Fatalf("fixture: expected 2 functions, got %d", len(aa.SymTable.Functions))
	}
	loser := aa.SymTable.Functions[`IpdetFnB\ipdet_perm_probe`]
	if loser == nil {
		t.Fatal("fixture: missing IpdetFnB\\ipdet_perm_probe")
	}
	if lvl := aa.analyzeReturnStatements(loser.BodyNode, aa.sourceForFile(loser.File), 0, ""); lvl != models.Admin {
		t.Fatalf("fixture: the losing candidate should score Admin, got %v", lvl)
	}

	ipdetStableLevel(t, aa, CallbackRef{
		Type:     "function",
		FuncName: "ipdet_perm_probe",
	}, models.Unauthenticated)
}

// Two namespaces declare a class of the same short name and both declare the
// method the callback names. The documented winner is the lexicographically
// smallest class FQN: IpdetNsA\IpdetCtl, returning true -- Unauthenticated.
func TestResolveCallbackBody_ClassNameCollision_PicksSmallestFQN(t *testing.T) {
	aa, _ := ipdetAuthAnalyzer(t, map[string]string{
		"cls_a.php": `<?php
namespace IpdetNsA;
class IpdetCtl { public function handle() { return true; } }
`,
		"cls_b.php": `<?php
namespace IpdetNsB;
class IpdetCtl { public function handle() { return current_user_can('manage_options'); } }
`,
	})

	if len(aa.SymTable.Classes) != 2 {
		t.Fatalf("fixture: expected 2 classes, got %d", len(aa.SymTable.Classes))
	}
	loser := aa.SymTable.Classes[`IpdetNsB\IpdetCtl`]
	if loser == nil {
		t.Fatal("fixture: missing IpdetNsB\\IpdetCtl")
	}
	m := loser.Methods["handle"]
	if m == nil {
		t.Fatal("fixture: IpdetNsB\\IpdetCtl declares no handle()")
	}
	if lvl := aa.analyzeReturnStatements(m.BodyNode, aa.sourceForFile(m.File), 0, loser.FQN); lvl != models.Admin {
		t.Fatalf("fixture: the losing candidate should score Admin, got %v", lvl)
	}

	ipdetStableLevel(t, aa, CallbackRef{
		Type:       "method",
		ClassName:  "IpdetCtl",
		MethodName: "handle",
	}, models.Unauthenticated)
}

// The two suffix guards above only make an arbitrary choice defined; they must
// not change an answer that was never ambiguous. One namespaced function,
// matched by the same suffix path, still resolves to its own body.
func TestResolveCallbackBody_SingleNamespacedFunction_Unchanged(t *testing.T) {
	aa, _ := ipdetAuthAnalyzer(t, map[string]string{
		"fn.php": `<?php
namespace IpdetFnA;
function ipdet_solo_probe() { return current_user_can('manage_options'); }
`,
	})

	ipdetStableLevel(t, aa, CallbackRef{
		Type:     "function",
		FuncName: "ipdet_solo_probe",
	}, models.Admin)
}

// The same for one namespaced class reached by its short name.
func TestResolveCallbackBody_SingleNamespacedClass_Unchanged(t *testing.T) {
	aa, _ := ipdetAuthAnalyzer(t, map[string]string{
		"cls.php": `<?php
namespace IpdetNsA;
class IpdetSolo { public function handle() { return current_user_can('manage_options'); } }
`,
	})

	ipdetStableLevel(t, aa, CallbackRef{
		Type:       "method",
		ClassName:  "IpdetSolo",
		MethodName: "handle",
	}, models.Admin)
}

// $this->m() resolves against the class the body belongs to, not against every
// class in the tree. IpdetAOther sorts before IpdetZHost, so the smallest-FQN
// fallback would answer Unauthenticated here: this asserts the MRO answer
// (Admin) precisely so that the fallback cannot quietly take over.
func TestAnalyzeReturnExpression_ThisUsesEnclosingClass(t *testing.T) {
	aa, _ := ipdetAuthAnalyzer(t, map[string]string{
		"host.php": `<?php
class IpdetZHost {
    public function handle() { return $this->ipdet_inner_probe(); }
    public function ipdet_inner_probe() { return current_user_can('manage_options'); }
}
`,
		"other.php": `<?php
class IpdetAOther {
    public function ipdet_inner_probe() { return true; }
}
`,
	})

	ipdetStableLevel(t, aa, CallbackRef{
		Type:       "method",
		ClassName:  "IpdetZHost",
		MethodName: "handle",
	}, models.Admin)
}

// The same rule through inheritance: the method lives on the parent, so the MRO
// walk finds it there. The unrelated IpdetAOther still sorts first and still
// must not win.
func TestAnalyzeReturnExpression_ThisWalksInheritance(t *testing.T) {
	aa, _ := ipdetAuthAnalyzer(t, map[string]string{
		"base.php": `<?php
class IpdetBase {
    public function ipdet_inner_probe() { return current_user_can('manage_options'); }
}
`,
		"sub.php": `<?php
class IpdetSub extends IpdetBase {
    public function handle() { return $this->ipdet_inner_probe(); }
}
`,
		"other.php": `<?php
class IpdetAOther {
    public function ipdet_inner_probe() { return true; }
}
`,
	})

	ipdetStableLevel(t, aa, CallbackRef{
		Type:       "method",
		ClassName:  "IpdetSub",
		MethodName: "handle",
	}, models.Admin)
}

// A receiver whose ancestry leaves the tree -- here a parent that lives in
// WordPress core -- cannot be answered by the MRO walk. The whole-plugin scan
// still answers it, deliberately: dropping to Subscriber instead would throw
// away the one candidate there is. This pins that decision, not just the code.
func TestAnalyzeReturnExpression_ThisFallsBackWhenAncestryLeavesTheTree(t *testing.T) {
	aa, _ := ipdetAuthAnalyzer(t, map[string]string{
		"child.php": `<?php
class IpdetCoreChild extends WP_REST_Controller {
    public function handle() { return $this->ipdet_outside_probe(); }
}
`,
		"helper.php": `<?php
class IpdetHelper {
    public function ipdet_outside_probe() { return current_user_can('manage_options'); }
}
`,
	})

	ipdetStableLevel(t, aa, CallbackRef{
		Type:       "method",
		ClassName:  "IpdetCoreChild",
		MethodName: "handle",
	}, models.Admin)
}

// A closure reference carries no class, so there is no receiver and the
// whole-plugin scan is all that is left. The documented winner there is the
// smallest class FQN -- IpdetAOther, returning true -- and it has to be the same
// one on every run.
func TestAnalyzeReturnExpression_ThisWithoutReceiver_PicksSmallestFQN(t *testing.T) {
	aa, pluginAST := ipdetAuthAnalyzer(t, map[string]string{
		"host.php": `<?php
class IpdetZHost {
    public function ipdet_inner_probe() { return current_user_can('manage_options'); }
}
`,
		"other.php": `<?php
class IpdetAOther {
    public function ipdet_inner_probe() { return true; }
}
`,
		"routes.php": `<?php
register_rest_route('ipdet/v1', '/probe', array(
    'permission_callback' => function () { return $this->ipdet_inner_probe(); },
));
`,
	})

	closureFile, closureNode := ipdetFindClosure(t, pluginAST)
	ipdetStableLevel(t, aa, CallbackRef{
		Type:        "closure",
		ClosureNode: closureNode,
		File:        closureFile,
	}, models.Unauthenticated)
}

func ipdetFindClosure(t *testing.T, pluginAST *PluginAST) (string, *sitter.Node) {
	t.Helper()
	for path, pf := range pluginAST.Files {
		if node := ipdetSearchClosure(pf.Tree.RootNode()); node != nil {
			return path, node
		}
	}
	t.Fatal("fixture: no closure found")
	return "", nil
}

func ipdetSearchClosure(node *sitter.Node) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "anonymous_function_creation_expression" {
		return node
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if found := ipdetSearchClosure(node.Child(i)); found != nil {
			return found
		}
	}
	return nil
}

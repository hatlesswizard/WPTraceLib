package ast

import (
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

func buildTestResolver(t *testing.T, phpCode string) (*Resolver, *PluginAST) {
	t.Helper()
	pluginAST := parseTestFile(t, phpCode)
	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	df := NewDataFlowAnalyzer(st, h)
	cg := BuildCallGraph(st, pluginAST)
	ta := NewTaintAnalyzer(st, h, cg, pluginAST)
	aa := NewAuthAnalyzer(st, h, pluginAST)
	return NewResolver(st, h, df, ta, aa), pluginAST
}

func TestResolver_ResolveCallback_Function(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
function my_handler() {
    echo $_POST['data'];
}
`)

	ref := CallbackRef{Type: "function", FuncName: "my_handler"}
	_, fn, err := r.ResolveCallback(ref)
	if err != nil {
		t.Fatalf("ResolveCallback failed: %v", err)
	}
	if fn == nil {
		t.Fatal("expected FunctionSymbol, got nil")
	}
	if fn.Name != "my_handler" {
		t.Errorf("expected 'my_handler', got %q", fn.Name)
	}
}

func TestResolver_ResolveCallback_Method(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
class MyPlugin {
    public function handle() {}
}
`)

	ref := CallbackRef{Type: "method", ClassName: "MyPlugin", MethodName: "handle"}
	m, _, err := r.ResolveCallback(ref)
	if err != nil {
		t.Fatalf("ResolveCallback failed: %v", err)
	}
	if m == nil {
		t.Fatal("expected MethodSymbol, got nil")
	}
}

func TestResolver_ResolveCallback_InheritedMethod(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
class Base {
    public function shared_method() {}
}
class Child extends Base {}
`)

	ref := CallbackRef{Type: "method", ClassName: "Child", MethodName: "shared_method"}
	m, _, err := r.ResolveCallback(ref)
	if err != nil {
		t.Fatalf("ResolveCallback failed: %v", err)
	}
	if m == nil {
		t.Fatal("expected inherited MethodSymbol")
	}
	if m.Class != "Base" {
		t.Errorf("expected method from Base, got %s", m.Class)
	}
}

func TestResolver_ResolvePermissionCallback_ReturnsTrue(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
class My_REST {
    public function open_check() {
        return true;
    }
}
`)

	ref := CallbackRef{Type: "method", ClassName: "My_REST", MethodName: "open_check"}
	level := r.ResolvePermissionCallback(ref)
	if level != models.Unauthenticated {
		t.Errorf("open_check returns true: expected Unauthenticated, got %v", level)
	}
}

func TestResolver_FunctionAccessesUserInput(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
function input_handler() {
    $val = $_REQUEST['key'];
}
function safe_handler() {
    echo "safe";
}
`)

	if !r.FunctionAccessesUserInput("input_handler") {
		t.Error("input_handler should access user input")
	}
	if r.FunctionAccessesUserInput("safe_handler") {
		t.Error("safe_handler should NOT access user input")
	}
}

func TestResolver_HasAuthGuardBeforeInput_WithGuard(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
function guarded_handler() {
    if (!current_user_can('manage_options')) { return; }
    $val = $_GET['data'];
}
`)

	hasGuard, level := r.HasAuthGuardBeforeInput("guarded_handler")
	if !hasGuard {
		t.Error("guarded_handler should have auth guard")
	}
	if level != models.Admin {
		t.Errorf("expected Admin level, got %v", level)
	}
}

func TestResolver_HasAuthGuardBeforeInput_NoInput(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
function no_input_func() {
    echo "hello";
}
`)

	hasGuard, level := r.HasAuthGuardBeforeInput("no_input_func")
	if hasGuard {
		t.Error("no_input_func does not process user input, should return false")
	}
	if level != models.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", level)
	}
}

func TestResolver_IsSubclassOf(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
class WP_Background_Process {}
class My_BG extends WP_Background_Process {}
`)

	if !r.IsSubclassOf("My_BG", "WP_Background_Process") {
		t.Error("My_BG should be subclass of WP_Background_Process")
	}
}

func TestResolver_GetSubclasses(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
class Base {}
class Child1 extends Base {}
class Child2 extends Base {}
`)

	subs := r.GetSubclasses("Base")
	if len(subs) < 2 {
		t.Errorf("expected at least 2 subclasses, got %v", subs)
	}
}

func TestResolver_ResolveProperty(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
class Process {
    protected $action = 'my_bg_action';
}
`)

	val, ok := r.ResolveProperty("Process", "action")
	if !ok || val != "my_bg_action" {
		t.Errorf("expected 'my_bg_action', got %q (ok=%v)", val, ok)
	}
}

func TestResolver_ResolveProperty_NotFound(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
class Process {}
`)

	_, ok := r.ResolveProperty("Process", "missing")
	if ok {
		t.Error("expected not found for missing property")
	}
}

func TestResolver_ResolveConstant(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
define('MY_VERSION', '3.0');
class Config {
    const PREFIX = 'myp_';
}
`)

	val, ok := r.ResolveConstant("MY_VERSION", nil)
	if !ok || val != "3.0" {
		t.Errorf("expected '3.0', got %q (ok=%v)", val, ok)
	}

	val, ok = r.ResolveConstant("Config::PREFIX", nil)
	if !ok || val != "myp_" {
		t.Errorf("expected 'myp_', got %q (ok=%v)", val, ok)
	}
}

func TestResolver_ResolveCallback_Closure(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php function stub() {}`)

	ref := CallbackRef{Type: "closure"}
	m, fn, err := r.ResolveCallback(ref)
	if err != nil {
		t.Fatalf("closure ResolveCallback should not error: %v", err)
	}
	if m != nil || fn != nil {
		t.Error("closure should return (nil, nil, nil)")
	}
}

func TestResolver_ResolveCallback_StaticMethod(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
class MyAPI {
    public static function endpoint() {}
}
`)

	ref := CallbackRef{Type: "static_method", ClassName: "MyAPI", MethodName: "endpoint"}
	m, _, err := r.ResolveCallback(ref)
	if err != nil {
		t.Fatalf("ResolveCallback for static_method failed: %v", err)
	}
	if m == nil {
		t.Fatal("expected MethodSymbol for static_method")
	}
}

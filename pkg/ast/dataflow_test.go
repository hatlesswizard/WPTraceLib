package ast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDataFlow_StringLiteral(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function test() {
    $hook = 'wp_ajax_nopriv_foo';
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	df := NewDataFlowAnalyzer(st, h)

	fn := st.Functions["test"]
	if fn == nil {
		t.Fatal("expected function test")
	}

	var source []byte
	for _, pf := range pluginAST.Files {
		source = pf.Source
		break
	}

	scope := df.BuildFunctionScope("test", fn.BodyNode, source, "")

	if val, ok := scope.Variables["$hook"]; !ok {
		t.Error("expected $hook in scope")
	} else if val != "wp_ajax_nopriv_foo" {
		t.Errorf("expected 'wp_ajax_nopriv_foo', got %q", val)
	}
}

func TestDataFlow_Concatenation(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function test() {
    $hook = 'wp_ajax_' . 'nopriv_' . 'foo';
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	df := NewDataFlowAnalyzer(st, h)

	fn := st.Functions["test"]
	if fn == nil {
		t.Fatal("expected function test")
	}

	var source []byte
	for _, pf := range pluginAST.Files {
		source = pf.Source
		break
	}

	scope := df.BuildFunctionScope("test", fn.BodyNode, source, "")

	if val, ok := scope.Variables["$hook"]; !ok {
		t.Error("expected $hook in scope")
	} else if val != "wp_ajax_nopriv_foo" {
		t.Errorf("expected 'wp_ajax_nopriv_foo', got %q", val)
	}
}

func TestDataFlow_VariableConcat(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function register() {
    $prefix = 'wp_ajax_';
    add_action($prefix . 'nopriv_test', 'handler');
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	df := NewDataFlowAnalyzer(st, h)

	fn := st.Functions["register"]
	if fn == nil {
		t.Fatal("expected function register")
	}

	var source []byte
	for _, pf := range pluginAST.Files {
		source = pf.Source
		break
	}

	scope := df.BuildFunctionScope("register", fn.BodyNode, source, "")

	if val, ok := scope.Variables["$prefix"]; !ok || val != "wp_ajax_" {
		t.Errorf("$prefix: expected 'wp_ajax_', got %q (ok=%v)", val, ok)
	}
}

func TestDataFlow_ClassConstant(t *testing.T) {
	dir := t.TempDir()
	content := `<?php
class Config {
    const PREFIX = 'myp_';
    const ACTION = 'do_stuff';
}
class Handler {
    public function register() {
        $hook = 'wp_ajax_' . Config::PREFIX . Config::ACTION;
    }
}
`
	path := filepath.Join(dir, "test.php")
	os.WriteFile(path, []byte(content), 0644)
	pluginAST, err := ParsePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	df := NewDataFlowAnalyzer(st, h)

	cls := st.Classes["Handler"]
	if cls == nil {
		t.Fatal("expected class Handler")
	}
	regMethod := cls.Methods["register"]
	if regMethod == nil {
		t.Fatal("expected method register")
	}

	var source []byte
	for _, pf := range pluginAST.Files {
		source = pf.Source
		break
	}

	scope := df.BuildFunctionScope("Handler::register", regMethod.BodyNode, source, "Handler")

	if val, ok := scope.Variables["$hook"]; !ok {
		t.Error("expected $hook in scope")
	} else if val != "wp_ajax_myp_do_stuff" {
		t.Errorf("expected 'wp_ajax_myp_do_stuff', got %q", val)
	}
}

func TestDataFlow_PropertyAccess(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
class BG_Process {
    protected $action = 'my_bg_process';

    public function dispatch() {
        $hook = 'wp_ajax_nopriv_' . $this->action;
    }
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	df := NewDataFlowAnalyzer(st, h)

	cls := st.Classes["BG_Process"]
	if cls == nil {
		t.Fatal("expected class BG_Process")
	}

	prop, ok := cls.Properties["action"]
	if !ok {
		t.Fatal("expected property 'action'")
	}
	if prop.DefaultValue != "my_bg_process" {
		t.Errorf("expected default 'my_bg_process', got %q", prop.DefaultValue)
	}

	dispatchMethod := cls.Methods["dispatch"]
	if dispatchMethod == nil {
		t.Fatal("expected method dispatch")
	}

	var source []byte
	for _, pf := range pluginAST.Files {
		source = pf.Source
		break
	}

	scope := df.BuildFunctionScope("BG_Process::dispatch", dispatchMethod.BodyNode, source, "BG_Process")

	if val, ok := scope.Variables["$hook"]; !ok {
		t.Error("expected $hook in scope")
	} else if val != "wp_ajax_nopriv_my_bg_process" {
		t.Errorf("expected 'wp_ajax_nopriv_my_bg_process', got %q", val)
	}
}

func TestDataFlow_Sprintf(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function register_hooks() {
    $name = 'my_action';
    add_action(sprintf('wp_ajax_nopriv_%s', $name), 'handle');
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	df := NewDataFlowAnalyzer(st, h)

	fn := st.Functions["register_hooks"]
	if fn == nil {
		t.Fatal("expected function register_hooks")
	}

	var source []byte
	for _, pf := range pluginAST.Files {
		source = pf.Source
		break
	}

	scope := df.BuildFunctionScope("register_hooks", fn.BodyNode, source, "")

	if val, ok := scope.Variables["$name"]; !ok || val != "my_action" {
		t.Errorf("$name: expected 'my_action', got %q", val)
	}
}

func TestDataFlow_UnresolvableParam(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function handle($action) {
    $hook = 'wp_ajax_nopriv_' . $action;
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	df := NewDataFlowAnalyzer(st, h)

	fn := st.Functions["handle"]
	if fn == nil {
		t.Fatal("expected function handle")
	}

	var source []byte
	for _, pf := range pluginAST.Files {
		source = pf.Source
		break
	}

	scope := df.BuildFunctionScope("handle", fn.BodyNode, source, "")

	if val, ok := scope.Variables["$hook"]; !ok {
		t.Error("expected $hook in scope (even if partially resolved)")
	} else {
		if !strings.Contains(val, "wp_ajax_nopriv_") {
			t.Errorf("expected 'wp_ajax_nopriv_' prefix, got %q", val)
		}
		if !strings.Contains(val, "{param:") {
			t.Errorf("expected {param:} placeholder for unresolvable part, got %q", val)
		}
	}
}

func TestDataFlow_DynamicHookName(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
class MyPlugin {
    const AJAX_ACTION = 'my_plugin';

    public function init() {
        $prefix = 'wp_ajax_nopriv_';
        add_action($prefix . self::AJAX_ACTION, [$this, 'handle']);
    }
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	df := NewDataFlowAnalyzer(st, h)

	cls := st.Classes["MyPlugin"]
	if cls == nil {
		t.Fatal("expected class MyPlugin")
	}
	initMethod := cls.Methods["init"]
	if initMethod == nil {
		t.Fatal("expected method init")
	}

	var source []byte
	for _, pf := range pluginAST.Files {
		source = pf.Source
		break
	}

	scope := df.BuildFunctionScope("MyPlugin::init", initMethod.BodyNode, source, "MyPlugin")

	if val, ok := scope.Variables["$prefix"]; !ok || val != "wp_ajax_nopriv_" {
		t.Errorf("$prefix: expected 'wp_ajax_nopriv_', got %q (ok=%v)", val, ok)
	}
}

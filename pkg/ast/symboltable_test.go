package ast

import (
	"os"
	"path/filepath"
	"testing"
)

func parseTestFile(t *testing.T, content string) *PluginAST {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.php")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ast, err := ParsePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ast
}

func TestBuildSymbolTable_ClassWithMethods(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
class MyPlugin {
    const VERSION = '1.0';
    private $action = 'my_action';

    public function init() {}
    protected function handle() {}
    private static function helper() {}
}
`)

	st := BuildSymbolTable(pluginAST)

	cls, ok := st.Classes["MyPlugin"]
	if !ok {
		t.Fatal("expected class MyPlugin in symbol table")
	}
	if len(cls.Methods) != 3 {
		t.Errorf("expected 3 methods, got %d", len(cls.Methods))
	}
	if m, ok := cls.Methods["init"]; !ok {
		t.Error("missing method init")
	} else if m.Visibility != "public" {
		t.Errorf("init visibility: expected public, got %s", m.Visibility)
	}
	if m, ok := cls.Methods["helper"]; !ok {
		t.Error("missing method helper")
	} else if !m.Static {
		t.Error("helper should be static")
	}
	if c, ok := cls.Constants["VERSION"]; !ok {
		t.Error("missing constant VERSION")
	} else if c.ResolvedValue != "1.0" || !c.IsResolved {
		t.Errorf("VERSION: expected resolved '1.0', got %q (resolved=%v)", c.ResolvedValue, c.IsResolved)
	}
	if p, ok := cls.Properties["action"]; !ok {
		t.Error("missing property action")
	} else if p.DefaultValue != "my_action" || !p.IsResolved {
		t.Errorf("action: expected 'my_action', got %q", p.DefaultValue)
	}
}

func TestBuildSymbolTable_Namespace(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
namespace MyVendor\MyPlugin;

use Some\Other\ClassName;

class Widget {
    public function render() {}
}

function helper_func() {}
`)

	st := BuildSymbolTable(pluginAST)

	if _, ok := st.Classes[`MyVendor\MyPlugin\Widget`]; !ok {
		t.Error("expected namespaced class MyVendor\\MyPlugin\\Widget")
		for fqn := range st.Classes {
			t.Logf("  found class: %s", fqn)
		}
	}
	if _, ok := st.Functions[`MyVendor\MyPlugin\helper_func`]; !ok {
		t.Error("expected namespaced function MyVendor\\MyPlugin\\helper_func")
		for fqn := range st.Functions {
			t.Logf("  found function: %s", fqn)
		}
	}
}

func TestBuildSymbolTable_DefineConstant(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
define('MY_PLUGIN_VERSION', '2.5.1');
define('MY_PLUGIN_DIR', __DIR__);
`)

	st := BuildSymbolTable(pluginAST)

	if c, ok := st.Constants["MY_PLUGIN_VERSION"]; !ok {
		t.Error("expected constant MY_PLUGIN_VERSION")
	} else if c.ResolvedValue != "2.5.1" {
		t.Errorf("expected '2.5.1', got %q", c.ResolvedValue)
	}

	// __DIR__ is not a string literal — should be unresolved
	if c, ok := st.Constants["MY_PLUGIN_DIR"]; ok && c.IsResolved {
		t.Error("MY_PLUGIN_DIR should be unresolved (__DIR__ is not a string literal)")
	}
}

func TestBuildSymbolTable_TopLevelFunction(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function my_plugin_activate($network_wide = false) {
    // activation logic
}
`)

	st := BuildSymbolTable(pluginAST)

	fn, ok := st.Functions["my_plugin_activate"]
	if !ok {
		t.Fatal("expected function my_plugin_activate")
	}
	if len(fn.Params) != 1 {
		t.Errorf("expected 1 param, got %d", len(fn.Params))
	} else {
		if fn.Params[0].Name != "$network_wide" && fn.Params[0].Name != "network_wide" {
			t.Errorf("expected param name $network_wide, got %q", fn.Params[0].Name)
		}
		if fn.Params[0].DefaultValue != "false" {
			t.Errorf("expected default 'false', got %q", fn.Params[0].DefaultValue)
		}
	}
}

func TestBuildSymbolTable_ClassExtends(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
class MyController extends WP_REST_Controller {
    public function register_routes() {}
}
`)

	st := BuildSymbolTable(pluginAST)

	cls, ok := st.Classes["MyController"]
	if !ok {
		t.Fatal("expected class MyController")
	}
	if cls.ParentName != "WP_REST_Controller" {
		t.Errorf("expected parent WP_REST_Controller, got %q", cls.ParentName)
	}
}

func TestBuildSymbolTable_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.php"), []byte("<?php\nclass Main {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(dir, "includes")
	os.MkdirAll(subDir, 0755)
	if err := os.WriteFile(filepath.Join(subDir, "helper.php"), []byte("<?php\nfunction helper() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	pluginAST, err := ParsePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}

	st := BuildSymbolTable(pluginAST)

	if _, ok := st.Classes["Main"]; !ok {
		t.Error("expected class Main from main.php")
	}
	if _, ok := st.Functions["helper"]; !ok {
		t.Error("expected function helper from helper.php")
	}
}

package ast

import (
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

func TestCallGraph_Build(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function foo() {
    bar();
    baz();
}

function bar() {
    baz();
}

function baz() {
    echo "leaf";
}
`)

	st := BuildSymbolTable(pluginAST)
	cg := BuildCallGraph(st, pluginAST)

	if len(cg.Edges["foo"]) < 2 {
		t.Errorf("foo should call at least bar and baz, got %v", cg.Edges["foo"])
	}

	bazNode := cg.Nodes["baz"]
	if bazNode == nil {
		t.Fatal("expected node for baz")
	}
	if len(bazNode.Callers) < 2 {
		t.Errorf("baz should have at least 2 callers (foo, bar), got %v", bazNode.Callers)
	}
}

func TestTaint_DirectSuperglobal(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function handle_request() {
    $action = $_POST['action'];
    process($action);
}

function process($data) {
    echo $data;
}

function no_input() {
    echo "hello";
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	cg := BuildCallGraph(st, pluginAST)
	ta := NewTaintAnalyzer(st, h, cg, pluginAST)

	if !ta.FunctionProcessesUserInput("handle_request") {
		t.Error("handle_request should process user input")
	}

	if ta.FunctionProcessesUserInput("no_input") {
		t.Error("no_input should NOT process user input")
	}
}

func TestTaint_NoSuperglobal(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function compute() {
    $x = 1 + 2;
    $y = "hello";
    return $x;
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	cg := BuildCallGraph(st, pluginAST)
	ta := NewTaintAnalyzer(st, h, cg, pluginAST)

	if ta.FunctionProcessesUserInput("compute") {
		t.Error("compute should NOT process user input")
	}
}

func TestTaint_TransitiveCallChain(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function handler_a() {
    handler_b();
}

function handler_b() {
    handler_c();
}

function handler_c() {
    $val = $_GET['key'];
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	cg := BuildCallGraph(st, pluginAST)
	ta := NewTaintAnalyzer(st, h, cg, pluginAST)

	if !ta.FunctionProcessesUserInput("handler_a") {
		t.Error("handler_a should transitively process user input via handler_b -> handler_c")
	}
}

func TestAuth_CurrentUserCan(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function admin_handler() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	aa := NewAuthAnalyzer(st, h, pluginAST)

	hasGuard, level := aa.HasAuthGuard("admin_handler")
	if !hasGuard {
		t.Error("admin_handler should have auth guard")
	}
	if level != models.Admin {
		t.Errorf("admin_handler: expected Admin, got %v", level)
	}
}

func TestAuth_IsUserLoggedIn(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function subscriber_handler() {
    if (!is_user_logged_in()) {
        wp_die('Please log in');
    }
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	aa := NewAuthAnalyzer(st, h, pluginAST)

	hasGuard, level := aa.HasAuthGuard("subscriber_handler")
	if !hasGuard {
		t.Error("subscriber_handler should have auth guard")
	}
	if level != models.Subscriber {
		t.Errorf("subscriber_handler: expected Subscriber, got %v", level)
	}
}

func TestAuth_NoncesNotAuthGuard(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
function nonce_only_handler() {
    wp_verify_nonce($_POST['nonce'], 'my_action');
    echo $_POST['data'];
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	aa := NewAuthAnalyzer(st, h, pluginAST)

	hasGuard, level := aa.HasAuthGuard("nonce_only_handler")
	if hasGuard {
		t.Error("nonce_only_handler should NOT have auth guard (wp_verify_nonce is CSRF only)")
	}
	if level != models.Unauthenticated {
		t.Errorf("nonce_only_handler: expected Unauthenticated, got %v", level)
	}
}

func TestAuth_PermissionCallback_ReturnsTrue(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
class My_REST extends WP_REST_Controller {
    public function check_permissions() {
        return true;
    }
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	aa := NewAuthAnalyzer(st, h, pluginAST)

	ref := CallbackRef{
		Type:       "method",
		ClassName:  "My_REST",
		MethodName: "check_permissions",
	}
	level := aa.AnalyzePermissionCallback(ref)
	if level != models.Unauthenticated {
		t.Errorf("check_permissions returns true: expected Unauthenticated, got %v", level)
	}
}

func TestAuth_PermissionCallback_CurrentUserCan(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
class My_REST extends WP_REST_Controller {
    public function check_admin() {
        return current_user_can('manage_options');
    }
}
`)

	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)
	aa := NewAuthAnalyzer(st, h, pluginAST)

	ref := CallbackRef{
		Type:       "method",
		ClassName:  "My_REST",
		MethodName: "check_admin",
	}
	level := aa.AnalyzePermissionCallback(ref)
	if level != models.Admin {
		t.Errorf("check_admin returns current_user_can('manage_options'): expected Admin, got %v", level)
	}
}

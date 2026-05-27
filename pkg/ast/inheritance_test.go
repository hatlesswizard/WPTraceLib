package ast

import (
	"testing"
)

func TestClassHierarchy_SimpleInheritance(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
class WP_REST_Controller {
    public function register_routes() {}
    public function get_items_permissions_check() { return true; }
}
class My_Controller extends WP_REST_Controller {
    public function register_routes() {}
}
class My_Sub_Controller extends My_Controller {
    public function custom_method() {}
}
`)
	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)

	// Test IsSubclassOf
	if !h.IsSubclassOf("My_Controller", "WP_REST_Controller") {
		t.Error("My_Controller should be subclass of WP_REST_Controller")
	}
	if !h.IsSubclassOf("My_Sub_Controller", "WP_REST_Controller") {
		t.Error("My_Sub_Controller should be subclass of WP_REST_Controller (transitive)")
	}
	if h.IsSubclassOf("WP_REST_Controller", "My_Controller") {
		t.Error("WP_REST_Controller should NOT be subclass of My_Controller")
	}

	// Test GetAllSubclasses
	subs := h.GetAllSubclasses("WP_REST_Controller")
	if len(subs) != 2 {
		t.Errorf("expected 2 subclasses, got %d: %v", len(subs), subs)
	}

	// Test ResolveMethod — should find overridden method in My_Controller
	m := h.ResolveMethod("My_Controller", "register_routes")
	if m == nil {
		t.Fatal("expected to resolve register_routes on My_Controller")
	}
	if m.Class != "My_Controller" {
		t.Errorf("expected resolved method on My_Controller, got %s", m.Class)
	}

	// Test ResolveMethod — should find inherited method
	m = h.ResolveMethod("My_Sub_Controller", "get_items_permissions_check")
	if m == nil {
		t.Fatal("expected to resolve get_items_permissions_check on My_Sub_Controller via inheritance")
	}
	if m.Class != "WP_REST_Controller" {
		t.Errorf("expected method from WP_REST_Controller, got %s", m.Class)
	}
}

func TestClassHierarchy_CycleDetection(t *testing.T) {
	// Can't actually create circular inheritance in valid PHP,
	// but we can test with a manually constructed symbol table
	st := &SymbolTable{
		Classes: map[string]*ClassSymbol{
			"A": {FQN: "A", ParentName: "B", Methods: map[string]*MethodSymbol{}},
			"B": {FQN: "B", ParentName: "A", Methods: map[string]*MethodSymbol{}},
		},
		Functions: make(map[string]*FunctionSymbol),
		Constants: make(map[string]*ConstantSymbol),
		Files:     make(map[string]*FileContext),
	}
	h := BuildClassHierarchy(st)

	// Should not panic or infinite loop
	if h.IsSubclassOf("A", "C") {
		t.Error("A should not be subclass of non-existent C")
	}

	mro := h.getMRO("A")
	// Should contain both A and B without infinite loop
	if len(mro) > 2 {
		t.Errorf("MRO should be at most 2 entries due to cycle, got %d: %v", len(mro), mro)
	}
}

func TestClassHierarchy_ExternalParent(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
class My_Background extends WP_Background_Process {
    protected $action = 'my_bg_process';
}
`)
	st := BuildSymbolTable(pluginAST)
	h := BuildClassHierarchy(st)

	// WP_Background_Process isn't in the plugin — parent should still be tracked
	if parent := h.Parents["My_Background"]; parent != "WP_Background_Process" {
		t.Errorf("expected parent WP_Background_Process, got %q", parent)
	}

	// IsSubclassOf should still work with external parents
	if !h.IsSubclassOf("My_Background", "WP_Background_Process") {
		t.Error("My_Background should be subclass of WP_Background_Process")
	}
}

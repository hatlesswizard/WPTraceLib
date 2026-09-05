package ast

import (
	"fmt"
	"testing"
)

// Two runs of the same binary over the same plugin tree disagreed on 21 of
// 1,885 endpoint keys, which puts the floor on any measurable improvement above
// the size of most of them. BuildClassHierarchy is one of the places that can
// do it: it fills Children by appending inside a range over st.Classes, and Go
// randomises a map range per execution of the range statement.
//
// Every case below rebuilds the hierarchy from one fixed symbol table, so each
// rebuild is an independent draw from that randomisation. A two-candidate
// ambiguity flips a coin per draw and a nine-sibling one draws from nine, so
// 200 draws means the pre-fix behaviour fails on the first `go test` rather
// than flaking into somebody's later one.
const inheritanceDeterminismRebuilds = 200

// inheritanceDeterminismSymbolTable builds a symbol table containing exactly
// the named classes, each with the given parent ("" for none). Names are FQNs
// already, so resolveClassFQN passes them through untouched.
func inheritanceDeterminismSymbolTable(parentOf map[string]string) *SymbolTable {
	st := &SymbolTable{
		Classes:   make(map[string]*ClassSymbol, len(parentOf)),
		Functions: make(map[string]*FunctionSymbol),
		Constants: make(map[string]*ConstantSymbol),
		Files:     make(map[string]*FileContext),
	}
	for fqn, parent := range parentOf {
		st.Classes[fqn] = &ClassSymbol{
			Name:       fqn,
			FQN:        fqn,
			ParentName: parent,
			Methods:    make(map[string]*MethodSymbol),
			Properties: make(map[string]*PropertySymbol),
			Constants:  make(map[string]*ConstantSymbol),
		}
	}
	return st
}

// TestInheritanceDeterminism_SubclassOrderIsFixedAcrossBuilds pins the order
// GetAllSubclasses returns, which is the order ajax.go:2900 consumes.
//
// The hierarchy is shaped so that two different mistakes are distinguishable
// from a correct answer. Aaa_Child descends from Mid_B and sorts before every
// sibling of Mid_B, so sorting the RESULT flat would hoist it to the front;
// only sorting the sibling slices inside the pre-order walk leaves it directly
// behind its parent. And Ext_A/Ext_B hang off a parent the tree never declares
// -- the usual shape, since the base a plugin subclasses is normally vendored
// or from core -- which is the case where Children has an entry whose key is
// not a key of st.Classes.
func TestInheritanceDeterminism_SubclassOrderIsFixedAcrossBuilds(t *testing.T) {
	parentOf := map[string]string{"Base": ""}
	for _, sibling := range []string{
		"Zed_Sibling", "Mid_B", "Aaa_Sibling", "Ttt_Sibling", "Nnn_Sibling",
		"Sss_Sibling", "Ppp_Sibling", "Rrr_Sibling", "Qqq_Sibling",
	} {
		parentOf[sibling] = "Base"
	}
	parentOf["Aaa_Child"] = "Mid_B"
	parentOf["Ext_B"] = "Undeclared_Vendor_Base"
	parentOf["Ext_A"] = "Undeclared_Vendor_Base"

	st := inheritanceDeterminismSymbolTable(parentOf)

	wantFromBase := []string{
		"Aaa_Sibling",
		"Mid_B",
		"Aaa_Child", // directly behind its parent, not hoisted to the front
		"Nnn_Sibling",
		"Ppp_Sibling",
		"Qqq_Sibling",
		"Rrr_Sibling",
		"Sss_Sibling",
		"Ttt_Sibling",
		"Zed_Sibling",
	}
	wantFromExternal := []string{"Ext_A", "Ext_B"}

	for i := 0; i < inheritanceDeterminismRebuilds; i++ {
		h := BuildClassHierarchy(st)

		got := h.GetAllSubclasses("Base")
		if !inheritanceDeterminismEqual(got, wantFromBase) {
			t.Fatalf("build %d: GetAllSubclasses(\"Base\") = %v\nwant %v", i, got, wantFromBase)
		}

		got = h.GetAllSubclasses("Undeclared_Vendor_Base")
		if !inheritanceDeterminismEqual(got, wantFromExternal) {
			t.Fatalf("build %d: GetAllSubclasses(\"Undeclared_Vendor_Base\") = %v\nwant %v", i, got, wantFromExternal)
		}
	}
}

func inheritanceDeterminismEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestInheritanceDeterminism_AJAXFirstWinsPicksOneWinner is the consequence the
// order actually has, rather than a statement about the order itself.
//
// DetectAJAXEndpointsWithAST walks GetSubclasses and lets the FIRST class to
// claim a route keep it, dropping the rest; the winner's own name then becomes
// the endpoint's Callback. Two subclasses reach one route with no coincidence
// required: neither has to mention $action at all, because ResolveProperty
// walks up the Parents chain (resolver.go:170-173) to the vendored base that
// declares it. Before the sibling order was defined, which of them survived was
// a coin flip per run, and mergeEndpoints keys on Callback (analyzer.go:990),
// so the two names were two different endpoint records rather than one.
func TestInheritanceDeterminism_AJAXFirstWinsPicksOneWinner(t *testing.T) {
	pluginAST := parseTestFile(t, `<?php
// Stands in for the WP_Background_Process copy plugins vendor into their own
// tree: it declares $action, and subclasses that never mention $action inherit
// its value.
class Vendor_Async_Base {
    protected $action = 'shared_queue';
    public function handle() {}
}
class Zulu_Queue extends Vendor_Async_Base {}
class Alpha_Queue extends Vendor_Async_Base {}
class Own_Action_Queue extends Vendor_Async_Base {
    protected $action = 'own_queue';
}
`)
	st := BuildSymbolTable(pluginAST)

	for i := 0; i < inheritanceDeterminismRebuilds; i++ {
		h := BuildClassHierarchy(st)
		r := NewResolver(st, h, nil, nil, nil)

		callbackByRoute := inheritanceDeterminismAJAXReplica(r, "Vendor_Async_Base")

		// Alpha_Queue and Zulu_Queue both resolve $action to 'shared_queue'.
		// The ambiguity is real -- both classes exist and both would register
		// that hook -- so the fix does not resolve it, it only makes the
		// arbitrary choice the same one every time: the lexically smaller FQN.
		if got := callbackByRoute["wp_ajax_nopriv_shared_queue"]; got != "Alpha_Queue::handle" {
			t.Fatalf("build %d: contested route kept callback %q, want %q", i, got, "Alpha_Queue::handle")
		}
		// Own_Action_Queue was never contested, so it must be unaffected: a
		// determinism fix may not change an answer that was already decided.
		if got := callbackByRoute["wp_ajax_nopriv_own_queue"]; got != "Own_Action_Queue::handle" {
			t.Fatalf("build %d: uncontested route kept callback %q, want %q", i, got, "Own_Action_Queue::handle")
		}
		if len(callbackByRoute) != 2 {
			t.Fatalf("build %d: got %d routes, want 2: %v", i, len(callbackByRoute), callbackByRoute)
		}
	}
}

// inheritanceDeterminismAJAXReplica transcribes the loop at ajax.go:2900-2927:
// resolve $action for each subclass in the order GetSubclasses hands them over,
// build the raw hook name, skip any class whose route another class already
// claimed (ajax.go:2907-2916), and record the winner as classFQN + "::handle"
// (ajax.go:2924). pkg/analyzer imports this package, so the real function
// cannot be called from here; this keeps the one property that matters, that
// the loop's state is carried across iterations and the earlier class wins.
func inheritanceDeterminismAJAXReplica(r *Resolver, baseFQN string) map[string]string {
	callbackByRoute := make(map[string]string)
	for _, classFQN := range r.GetSubclasses(baseFQN) {
		action, ok := r.ResolveProperty(classFQN, "action")
		if !ok || action == "" {
			continue
		}
		route := "wp_ajax_nopriv_" + action
		if _, claimed := callbackByRoute[route]; claimed {
			continue
		}
		callbackByRoute[route] = classFQN + "::handle"
	}
	return callbackByRoute
}

// TestInheritanceDeterminism_CaseIndexPicksSmallestSpelling covers the other
// map-order write in BuildClassHierarchy.
//
// PHP forbids two classes whose names differ only in case within one namespace,
// but that is a rule about what one process can load, not about what a static
// scan of a directory can find: a tree can hold a vendored copy and a fork
// under deprecated/ and include only one of them. A 143-plugin corpus contains
// exactly one such pair. Which one PHP would load is unknowable without running
// it, so the winner here is arbitrary by nature -- it just has to be the same
// arbitrary winner on every run.
func TestInheritanceDeterminism_CaseIndexPicksSmallestSpelling(t *testing.T) {
	st := inheritanceDeterminismSymbolTable(map[string]string{
		"Task_Runner": "",
		"Task_runner": "",
	})

	for i := 0; i < inheritanceDeterminismRebuilds; i++ {
		h := BuildClassHierarchy(st)

		// A third spelling is the only input that reaches the index at all:
		// canonical() answers from the exact-key check first (inheritance.go:150).
		if got := h.canonical("task_runner"); got != "Task_Runner" {
			t.Fatalf("build %d: canonical(%q) = %q, want %q", i, "task_runner", got, "Task_Runner")
		}
		// Both declared spellings are exact keys and must come back unchanged;
		// the tie-break must not reach past the short-circuit.
		for _, exact := range []string{"Task_Runner", "Task_runner"} {
			if got := h.canonical(exact); got != exact {
				t.Fatalf("build %d: canonical(%q) = %q, want it unchanged", i, exact, got)
			}
		}
		// A name the tree does not declare is core or external and passes
		// through, index or no index.
		if got := h.canonical("WP_REST_Controller"); got != "WP_REST_Controller" {
			t.Fatalf("build %d: canonical(%q) = %q, want it unchanged", i, "WP_REST_Controller", got)
		}
	}
}

// TestInheritanceDeterminism_CaseIndexUnambiguousUnchanged is the control for
// the case above: with one spelling declared, smallest-wins and the old
// first-writer-wins agree, and they have to keep agreeing. Only the contested
// key is allowed to move.
func TestInheritanceDeterminism_CaseIndexUnambiguousUnchanged(t *testing.T) {
	parentOf := make(map[string]string, 32)
	for i := 0; i < 32; i++ {
		parentOf[fmt.Sprintf("Mixed_Case_Class_%02d", i)] = ""
	}
	st := inheritanceDeterminismSymbolTable(parentOf)

	for i := 0; i < inheritanceDeterminismRebuilds; i++ {
		h := BuildClassHierarchy(st)
		for fqn := range parentOf {
			lowered := fmt.Sprintf("mixed_case_class_%s", fqn[len(fqn)-2:])
			if got := h.canonical(lowered); got != fqn {
				t.Fatalf("build %d: canonical(%q) = %q, want %q", i, lowered, got, fqn)
			}
		}
	}
}

package analyzer

import "testing"

// TestFindFunctionDeclarationsParenInParams covers the dominant cause of lost
// declarations: funcDefPattern matched the parameter list with [^)]*, so the
// first ")" inside the parameters ended the match and the whole declaration
// vanished from the call graph. Measured at 7,694 declarations across a
// 143-plugin corpus.
func TestFindFunctionDeclarationsParenInParams(t *testing.T) {
	src := `<?php
function with_array_default( $args = array() ) { return 1; }
function with_empty_array( $args = [] ) { return 2; }
function with_nested_call( $x = get_default( 5 ) ) { return 3; }
function with_string_paren( $s = "a)b" ) { return 4; }
function with_single_quote_paren( $s = 'c)d' ) { return 5; }
function plain( $a, $b ) { return 6; }
`
	want := []string{
		"with_array_default", "with_empty_array", "with_nested_call",
		"with_string_paren", "with_single_quote_paren", "plain",
	}
	got := map[string]bool{}
	for _, d := range FindFunctionDeclarations(src) {
		got[d.Name] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("declaration %q was not found", w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("found %d declarations, want %d: %v", len(got), len(want), got)
	}
}

// TestFindFunctionDeclarationsNotLineStart covers the second cause: the old
// pattern was anchored at (?m)^[\t ]*, so a declaration sharing its line with
// anything else was invisible. 3,950 declarations across the corpus.
func TestFindFunctionDeclarationsNotLineStart(t *testing.T) {
	src := `<?php
class OneLiner { public function inline_method() { return 1; } }
if ( ! function_exists( 'guarded' ) ) { function guarded() { return 2; } }
`
	got := map[string]bool{}
	for _, d := range FindFunctionDeclarations(src) {
		got[d.Name] = true
	}
	for _, w := range []string{"inline_method", "guarded"} {
		if !got[w] {
			t.Errorf("declaration %q was not found; got %v", w, got)
		}
	}
	// "function_exists" is a call, not a declaration, and must not be picked up.
	if got["function_exists"] {
		t.Errorf("function_exists() was treated as a declaration")
	}
}

// TestFindFunctionDeclarationsSkipsBodiless keeps abstract and interface
// signatures out of the graph. They define no calls, and admitting one would
// let it shadow the real implementation under the same bare name.
func TestFindFunctionDeclarationsSkipsBodiless(t *testing.T) {
	src := `<?php
interface Handler {
	public function handle( $req );
}
abstract class Base {
	abstract protected function run( $x = array() );
	public function real() { return 1; }
}
`
	got := map[string]bool{}
	for _, d := range FindFunctionDeclarations(src) {
		got[d.Name] = true
	}
	if got["handle"] || got["run"] {
		t.Errorf("a body-less declaration was admitted: %v", got)
	}
	if !got["real"] {
		t.Errorf("the concrete method was not found: %v", got)
	}
}

// TestFindFunctionDeclarationsReturnTypes covers PHP 7+ return types, including
// nullable and union forms, which sit between the parameter list and the body.
func TestFindFunctionDeclarationsReturnTypes(t *testing.T) {
	src := `<?php
function typed( $a = array() ) : ?string { return null; }
function unioned( $a ) : int|false { return 1; }
function namespaced( $a ) : \Foo\Bar { return null; }
function by_ref( &$a ) { return 1; }
function &returns_ref( $a = array() ) { return $a; }
`
	got := map[string]bool{}
	for _, d := range FindFunctionDeclarations(src) {
		got[d.Name] = true
	}
	for _, w := range []string{"typed", "unioned", "namespaced", "by_ref", "returns_ref"} {
		if !got[w] {
			t.Errorf("declaration %q was not found; got %v", w, got)
		}
	}
}

// TestFindFunctionDeclarationsBodySpan pins that the recorded body really is the
// function's body, since call extraction runs over exactly that span.
func TestFindFunctionDeclarationsBodySpan(t *testing.T) {
	src := `<?php
function outer( $x = array( 1, 2 ) ) {
	inner_call();
	if ( $x ) { nested_call(); }
}
`
	decls := FindFunctionDeclarations(src)
	if len(decls) != 1 {
		t.Fatalf("expected one declaration, got %d", len(decls))
	}
	body := src[decls[0].BodyOpen:decls[0].BodyClose]
	for _, want := range []string{"inner_call", "nested_call"} {
		if !contains(body, want) {
			t.Errorf("body does not contain %q; body = %q", want, body)
		}
	}
	if contains(body, "function outer") {
		t.Errorf("body wrongly includes the declaration head")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

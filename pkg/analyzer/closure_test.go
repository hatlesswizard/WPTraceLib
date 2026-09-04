package analyzer

import (
	"strings"
	"testing"
)

func bodies(content string) []ClosureBody {
	var out []ClosureBody
	for _, c := range FindClosures(content) {
		if c.Registration {
			out = append(out, c)
		}
	}
	return out
}

func hasCall(cs []ClosureBody, want string) bool {
	for _, c := range cs {
		if strings.Contains(c.Body, want) {
			return true
		}
	}
	return false
}

// TestClosureInRestRouteArrayIsFound is the commonest REST shape there is: the
// closure sits inside the array literal that register_rest_route takes as its
// third argument, so the innermost enclosing call is array( and not the
// registration. Taking only the innermost call rejected every one of these.
func TestClosureInRestRouteArrayIsFound(t *testing.T) {
	src := `<?php
register_rest_route( 'ns/v1', '/thing', array(
	'methods'             => 'POST',
	'callback'            => function ( $request ) {
		return handle_the_thing( $request );
	},
	'permission_callback' => '__return_true',
) );
`
	cs := bodies(src)
	if len(cs) != 1 {
		t.Fatalf("found %d registration closures, want 1", len(cs))
	}
	if !hasCall(cs, "handle_the_thing") {
		t.Errorf("closure body did not contain the call: %q", cs[0].Body)
	}
}

// TestClosureInShortArraySyntax: [ 'callback' => fn ] is the same shape written
// the modern way.
func TestClosureInShortArraySyntax(t *testing.T) {
	src := `<?php
register_rest_route( 'ns/v1', '/thing', [
	'callback' => function ( $r ) { return do_the_work( $r ); },
] );
`
	if !hasCall(bodies(src), "do_the_work") {
		t.Errorf("closure inside a short array was not attributed to the registration")
	}
}

// TestClosureOnAddActionIsFound covers the direct-argument case.
func TestClosureOnAddActionIsFound(t *testing.T) {
	src := `<?php
add_action( 'wp_ajax_nopriv_myaction', function () {
	process_request( $_POST );
} );
`
	if !hasCall(bodies(src), "process_request") {
		t.Errorf("closure passed directly to add_action was not found")
	}
}

// TestClosurePassedToUnrelatedCallIsIgnored is the bound. A closure given to
// usort is not an endpoint body, and treating it as one would attribute
// arbitrary code to an entry point.
func TestClosurePassedToUnrelatedCallIsIgnored(t *testing.T) {
	src := `<?php
usort( $items, function ( $a, $b ) {
	return compare_them( $a, $b );
} );
array_map( function ( $x ) { return transform( $x ); }, $list );
`
	if cs := bodies(src); len(cs) != 0 {
		t.Errorf("closures passed to usort/array_map were treated as registrations: %+v", cs)
	}
}

// TestClosureWithUseClauseAndReturnType parses the fuller syntax.
func TestClosureWithUseClauseAndReturnType(t *testing.T) {
	src := `<?php
add_filter( 'the_content', static function ( string $c ) use ( $ctx, $opts ): string {
	return render_content( $c, $ctx );
}, 10, 1 );
`
	if !hasCall(bodies(src), "render_content") {
		t.Errorf("a closure with static, a use clause and a return type was not parsed")
	}
}

// TestArrowFunctionBody: fn() => expr has no braces, and its call is still worth
// following.
func TestArrowFunctionBody(t *testing.T) {
	src := `<?php
add_filter( 'myplugin_value', fn( $v ) => sanitize_the_value( $v ) );
`
	if !hasCall(bodies(src), "sanitize_the_value") {
		t.Errorf("arrow function body was not captured")
	}
}

// TestNamedFunctionIsNotAClosure guards against double counting: named
// declarations are handled by FindFunctionDeclarations.
func TestNamedFunctionIsNotAClosure(t *testing.T) {
	src := `<?php
function my_named_handler( $r ) {
	return work( $r );
}
add_action( 'init', 'my_named_handler' );
`
	for _, c := range FindClosures(src) {
		if strings.Contains(c.Body, "work(") {
			t.Errorf("a named declaration was reported as a closure")
		}
	}
}

// TestRegistrationClosureCallsSeedsTheWalk is the point of all of it: an
// endpoint reported with the "closure" sentinel must still reach what the
// closure calls.
func TestRegistrationClosureCallsSeedsTheWalk(t *testing.T) {
	files := map[string]string{
		"api.php": `<?php
register_rest_route( 'ns/v1', '/save', array(
	'methods'             => 'POST',
	'callback'            => function ( $request ) {
		return persist_settings( $request );
	},
	'permission_callback' => '__return_true',
) );
`,
		"lib.php": `<?php
function persist_settings( $request ) {
	update_option( 'x', $request->get_param( 'v' ) );
	return audit_log( 'saved' );
}
function audit_log( $m ) {
	error_log( $m );
}
`,
	}
	cg := BuildCallGraph(files)
	calls := cg.registrationClosureCalls(files["api.php"])
	found := false
	for _, c := range calls {
		if strings.EqualFold(c, "persist_settings") {
			found = true
		}
	}
	if !found {
		t.Fatalf("registrationClosureCalls did not find persist_settings; got %v", calls)
	}
}

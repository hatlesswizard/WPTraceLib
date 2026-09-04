package analyzer

import (
	"strings"
	"testing"
)

// reaches reports whether the recursive callee walk from callback arrives at
// want, under either spelling the graph might use for it.
func reaches(cg *PluginCallGraph, callback, fileContent, want string) bool {
	bare := want
	if i := strings.LastIndex(want, "::"); i >= 0 {
		bare = want[i+2:]
	}
	for _, c := range GetRecursiveCallsForCallback(cg, callback, fileContent) {
		if strings.EqualFold(c, want) || strings.EqualFold(c, bare) {
			return true
		}
	}
	return false
}

// TestCalleeWalkResolvesBareCallToQualifiedDeclaration is the callee half of the
// resolution the file walk always had.
//
// extractCalls strips the class prefix from a call site, so `$this->svc->save()`
// is recorded as "save" while the declaration is keyed "Customer::save". The
// callee walk looked up only the name as written, found nothing, and stopped --
// while GetReachableFiles, which resolves the same name through AmbiguousFuncs,
// walked on. That asymmetry is why benchmark entries existed with forty-five
// endpoints reaching the vulnerable FILE and none reaching any function in it.
func TestCalleeWalkResolvesBareCallToQualifiedDeclaration(t *testing.T) {
	files := map[string]string{
		"entry.php": `<?php
class Controller {
	public function handle() {
		$svc = new Customer();
		$svc->save();
	}
}
`,
		"model.php": `<?php
class Customer {
	public function save() {
		$this->persist();
	}
	public function persist() {
		global $wpdb;
		$wpdb->query( "..." );
	}
}
`,
	}
	cg := BuildCallGraph(files)

	if !reaches(cg, "Controller::handle", files["entry.php"], "Customer::save") {
		t.Errorf("Customer::save not reached from Controller::handle")
	}
	// And the walk must continue THROUGH the resolved declaration, not merely
	// name it: persist is only reachable via save's own edges.
	if !reaches(cg, "Controller::handle", files["entry.php"], "Customer::persist") {
		t.Errorf("Customer::persist not reached; the walk stopped at the alias instead of following it")
	}
}

// TestCalleeWalkDoesNotInventUnrelatedCalls guards the other direction: widening
// the lookup must not connect a callback to a function nothing calls.
func TestCalleeWalkDoesNotInventUnrelatedCalls(t *testing.T) {
	files := map[string]string{
		"entry.php": `<?php
class Controller {
	public function handle() {
		$this->render();
	}
	public function render() {
		echo "hi";
	}
}
`,
		"other.php": `<?php
class Unrelated {
	public function danger() {
		eval( $_POST['x'] );
	}
}
`,
	}
	cg := BuildCallGraph(files)
	if reaches(cg, "Controller::handle", files["entry.php"], "Unrelated::danger") {
		t.Errorf("Unrelated::danger reached from a callback that cannot call it")
	}
}

// TestComposedHookNameReachesLiteralRegistrations is the missing combination in
// extractCalls' hook resolution.
//
// The shape is taken from a real REST controller:
//
//	apply_filters( 'form_wrap_process_' . $formType, $fields, $args, $request );
//
// with handlers registered under the composed literal. Call-site-literal and
// registration-dynamic were both handled; call-site-dynamic against a literal
// registration was not, which severs the graph at the hook -- and in that plugin
// the hook sits between an unauthenticated REST route and the vulnerable
// handler.
func TestComposedHookNameReachesLiteralRegistrations(t *testing.T) {
	files := map[string]string{
		"rest.php": `<?php
class RestController {
	public function submit( $request ) {
		$formType = $request->get_param( 'type' );
		$out = apply_filters( 'form_wrap_process_' . $formType, $fields, $args, $request );
		return $out;
	}
}
`,
		"handlers.php": `<?php
add_filter( 'form_wrap_process_registerForm', 'form_wrap_process_registerForm', 99, 3 );
function form_wrap_process_registerForm( $fields, $args, $request ) {
	wp_insert_user( $_POST );
}
`,
	}
	cg := BuildCallGraph(files)
	if !reaches(cg, "RestController::submit", files["rest.php"], "form_wrap_process_registerForm") {
		t.Errorf("a handler registered under the composed literal was not reached from the composed call site")
	}
}

// TestComposedHookNameInterpolatedForm covers "prefix_{$var}", the other way
// WordPress writes the same thing.
func TestComposedHookNameInterpolatedForm(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php
class Saver {
	public function run( $post ) {
		do_action( "myplugin_save_{$post->post_type}", $post );
	}
}
`,
		"b.php": `<?php
add_action( 'myplugin_save_product', 'handle_product_save' );
function handle_product_save( $post ) {
	update_post_meta( $post->ID, 'x', $_POST['v'] );
}
`,
	}
	cg := BuildCallGraph(files)
	if !reaches(cg, "Saver::run", files["a.php"], "handle_product_save") {
		t.Errorf("interpolated composed hook name did not reach its registration")
	}
}

// TestComposedHookSuffixForm covers $var . '_literal', where the selector comes
// first.
func TestComposedHookSuffixForm(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php
class Dispatcher {
	public function fire( $adapter ) {
		do_action( $adapter . '_gateway_response', $data );
	}
}
`,
		"b.php": `<?php
add_action( 'stripe_gateway_response', 'handle_gateway_response' );
function handle_gateway_response( $data ) {
	update_option( 'last', $_POST['r'] );
}
`,
	}
	cg := BuildCallGraph(files)
	if !reaches(cg, "Dispatcher::fire", files["a.php"], "handle_gateway_response") {
		t.Errorf("suffix-composed hook name did not reach its registration")
	}
}

// TestShortHookFragmentDoesNotMatchEverything is the bound.
//
// A two- or three-character literal identifies nothing. Matching on it would
// join a call site to most of the registry, which is an edge explosion rather
// than an analysis, so a fragment must be at least four characters and either
// stop on a word boundary or be long enough to stand on its own.
func TestShortHookFragmentDoesNotMatchEverything(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php
class Thing {
	public function go( $x ) {
		do_action( 'wp' . $x, $data );
	}
}
`,
		"b.php": `<?php
add_action( 'wpforms_process_complete', 'unrelated_handler' );
function unrelated_handler( $data ) {
	eval( $_POST['x'] );
}
`,
	}
	cg := BuildCallGraph(files)
	if reaches(cg, "Thing::go", files["a.php"], "unrelated_handler") {
		t.Errorf("a two-character hook fragment was allowed to match the whole registry")
	}
}

// TestFullyVariableHookNameMatchesNothing: apply_filters($name, ...) carries no
// literal at all. Linking it to every registration would be unbounded, so it is
// deliberately left unresolved.
func TestFullyVariableHookNameMatchesNothing(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php
class Thing {
	public function go( $filterName ) {
		$r = apply_filters( $filterName, $return, $request );
	}
}
`,
		"b.php": `<?php
add_action( 'myplugin_something_specific', 'some_handler' );
function some_handler( $d ) {
	eval( $_POST['x'] );
}
`,
	}
	cg := BuildCallGraph(files)
	if reaches(cg, "Thing::go", files["a.php"], "some_handler") {
		t.Errorf("a fully variable hook name was linked to a registration it cannot be shown to fire")
	}
}

// TestUsableHookFragment pins the bound directly, so a later change to the rule
// has to state its intent rather than drift.
func TestUsableHookFragment(t *testing.T) {
	for _, tc := range []struct {
		frag string
		want bool
	}{
		{"wp", false},
		{"wp_", false},
		{"save", false},    // four chars, no boundary, under eight
		{"save_", true},    // stops on a word boundary
		{"_saved", true},   // starts on one
		{"myplugin", true}, // eight characters stands alone
		{"form_wrap_process_", true},
		{"", false},
	} {
		if got := usableHookFragment(tc.frag); got != tc.want {
			t.Errorf("usableHookFragment(%q) = %v, want %v", tc.frag, got, tc.want)
		}
	}
}

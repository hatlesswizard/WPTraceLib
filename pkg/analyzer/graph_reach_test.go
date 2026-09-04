package analyzer

import (
	"sort"
	"strings"
	"testing"
)

// closureOf is the transitive callee set of one callback, as a set.
func closureOf(t *testing.T, cg *PluginCallGraph, callback, fileContent string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, c := range GetRecursiveCallsForCallback(cg, callback, fileContent) {
		out[c] = true
	}
	return out
}

func mustReach(t *testing.T, got map[string]bool, callback string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !got[w] {
			t.Errorf("closure of %q does not contain %q; got %v", callback, w, sortedKeys(got))
		}
	}
}

func mustNotReach(t *testing.T, got map[string]bool, callback string, unwanted ...string) {
	t.Helper()
	for _, u := range unwanted {
		if got[u] {
			t.Errorf("closure of %q contains %q and must not; got %v", callback, u, sortedKeys(got))
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- Type declarations the pattern used to reject -----------------------------

// A leading backslash is PHP's spelling for a global-namespace name, and it is
// how a namespaced plugin refers to a WordPress core class. Rejecting it hid
// 4,936 class declarations across 82 of 143 corpus trees and the 30,637 method
// declarations inside them.
func TestBackslashParentAndInterfaceAreStillClasses(t *testing.T) {
	files := map[string]string{
		"w.php": `<?php
namespace Plug\Admin;
class MyWidget extends \WP_Widget {
	public function widget($a, $b) { widget_sink(); }
}
class Repo implements \Countable {
	public function count(): int { return repo_sink(); }
}
final class Both extends \Base\Thing implements \ArrayAccess, \Countable {
	public function run() { both_sink(); }
}
readonly class Ro {
	public function go() { ro_sink(); }
}
`,
	}
	cg := BuildCallGraph(files)

	for _, key := range []string{"MyWidget::widget", "Repo::count", "Both::run", "Ro::go"} {
		if _, ok := cg.Functions[key]; !ok {
			t.Errorf("Functions has no %q", key)
		}
	}
	for _, cls := range []string{"MyWidget", "Repo", "Both", "Ro"} {
		if cg.ClassToFile[cls] != "w.php" {
			t.Errorf("ClassToFile[%q] = %q, want w.php", cls, cg.ClassToFile[cls])
		}
		if len(cg.ClassToFiles[cls]) != 1 {
			t.Errorf("ClassToFiles[%q] = %v, want one file", cls, cg.ClassToFiles[cls])
		}
	}
	// The parent is recorded as its last segment, which is what `parent::m()`
	// and an inherited-method lookup need.
	if got := cg.Types["MyWidget"].Parent; got != "WP_Widget" {
		t.Errorf("MyWidget parent = %q, want WP_Widget", got)
	}
	if got := cg.Types["Both"].Parent; got != "Thing" {
		t.Errorf("Both parent = %q, want Thing (last segment of \\Base\\Thing)", got)
	}
}

// The bound: an interface body holds signatures with no body, and a bodyless
// declaration is not a definition. Treating one as a definition would let it
// shadow the real implementation under the same bare name.
func TestInterfaceSignaturesAreNotDeclarations(t *testing.T) {
	files := map[string]string{
		"i.php": `<?php
interface Handler {
	public function handle($r);
}
class RealHandler implements Handler {
	public function handle($r) { real_sink(); }
}
`,
	}
	cg := BuildCallGraph(files)
	if _, ok := cg.Functions["Handler::handle"]; ok {
		t.Errorf("a bodyless interface signature was recorded as a declaration")
	}
	if _, ok := cg.Functions["RealHandler::handle"]; !ok {
		t.Errorf("the real implementation is missing")
	}
	got := closureOf(t, cg, "RealHandler::handle", "")
	mustReach(t, got, "RealHandler::handle", "real_sink")
}

// PHP 8.1 enums have a body, may declare methods and may use traits.
func TestEnumBodyIsAContainer(t *testing.T) {
	files := map[string]string{
		"e.php": `<?php
enum Status: string {
	case Draft = 'draft';
	public function handle() { enum_sink(); }
}
`,
	}
	cg := BuildCallGraph(files)
	if _, ok := cg.Functions["Status::handle"]; !ok {
		t.Errorf("Functions has no Status::handle; keys: %v", sortedKeys(callsFromKeys(cg)))
	}
}

func callsFromKeys(cg *PluginCallGraph) map[string]bool {
	out := map[string]bool{}
	for k := range cg.CallsFrom {
		out[k] = true
	}
	return out
}

// --- Traits -------------------------------------------------------------------

// `use T;` copies the trait's methods into the class at compile time, and the
// class's own declaration wins over the trait's. Trait bodies were not
// containers at all, so no Trait::method key ever existed and the pass meant to
// alias them could never fire.
func TestTraitMethodsResolveThroughTheUsingClass(t *testing.T) {
	files := map[string]string{
		"t/a_admin.php": `<?php
class Admin { use Uploads; public function handle_upload() { admin_specific_sink(); } }
`,
		"t/b_frontend.php": `<?php
class Frontend { use Uploads; public function entry() { $this->handle_upload(); } }
`,
		"t/c_trait.php": `<?php
trait Uploads { public function handle_upload() { upload_sink(); } }
`,
	}
	cg := BuildCallGraph(files)

	if _, ok := cg.CallsFrom["Uploads::handle_upload"]; !ok {
		t.Fatalf("no Uploads::handle_upload key; keys: %v", sortedKeys(callsFromKeys(cg)))
	}
	got := closureOf(t, cg, "Frontend::entry", "")
	mustReach(t, got, "Frontend::entry", "upload_sink")

	// The bound: a class that declares the method itself keeps its own body.
	// PHP gives the class's own declaration precedence over the trait's, and an
	// aliasing pass that overwrote it would report the wrong code as reachable.
	admin := closureOf(t, cg, "Admin::handle_upload", "")
	mustReach(t, admin, "Admin::handle_upload", "admin_specific_sink")
	mustNotReach(t, admin, "Admin::handle_upload", "upload_sink")
}

// A trait may use another trait, so the aliasing runs to a fixed point.
func TestTraitOfTraitIsAliasedOntoTheUsingClass(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php trait Inner { public function deep() { deep_trait_sink(); } }`,
		"b.php": `<?php trait Outer { use Inner; public function mid() { $this->deep(); } }`,
		"c.php": `<?php class User { use Outer; public function go() { $this->mid(); } }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "User::go", "")
	mustReach(t, got, "User::go", "deep_trait_sink")
}

// A trait whose name collides with a class must not evict the class from
// ClassToFile: dozens of call sites may name the class, and only the class's
// file answers them.
func TestTraitDoesNotEvictASameNamedClass(t *testing.T) {
	files := map[string]string{
		"a_class.php": `<?php class Helper { public static function fmt() { class_sink(); } }`,
		"b_trait.php": `<?php trait Helper { public function fmt() { trait_sink(); } }`,
	}
	cg := BuildCallGraph(files)
	if cg.ClassToFile["Helper"] != "a_class.php" {
		t.Errorf("ClassToFile[Helper] = %q, want a_class.php (the class, not the trait)",
			cg.ClassToFile["Helper"])
	}
	// Both files stay reachable through the many-valued index, so nothing is lost.
	if len(cg.ClassToFiles["Helper"]) != 2 {
		t.Errorf("ClassToFiles[Helper] = %v, want both declaring files", cg.ClassToFiles["Helper"])
	}
}

// --- Receiver-qualified dispatch ----------------------------------------------

// `self::m()` inside class C invokes C::m. Two classes may each declare the
// same method name with no relationship between them, and choosing by sorted
// file order walks the wrong body.
func TestSelfCallResolvesToTheEnclosingClass(t *testing.T) {
	files := map[string]string{
		"m/a.php": `<?php
class AController {
	static function boot()  { self::handleRequest(); }
	static function handleRequest() { harmlessA(); }
}`,
		"m/b.php": `<?php
class BController {
	static function boot2() { self::handleRequest(); }
	static function handleRequest() { dangerousB(); }
}`,
	}
	cg := BuildCallGraph(files)

	if !hasToken(cg.CallsFrom["BController::boot2"], "BController::handleRequest") {
		t.Errorf("CallsFrom[BController::boot2] = %v, want a BController::handleRequest token",
			cg.CallsFrom["BController::boot2"])
	}
	got := closureOf(t, cg, "BController::boot2", "")
	mustReach(t, got, "BController::boot2", "dangerousB")
}

// The bound: a token that names a receiver PHP binds is resolved against that
// receiver and is NOT merged with every same-named declaration in the tree.
// Without the gate the merge fires exactly where the language is exact -- 61.8%
// of ambiguous $this->m() sites declare m in the enclosing class.
//
// The assertion is on the token's resolution rather than on the whole closure,
// because the same call site also yields the bare spelling `act` (the direct
// call pattern matches a name after "::" too) and that spelling is deliberately
// kept: it is the only token some consumers have, and `$this->m()` is late
// bound, so a subclass override reached only through the bare name is a real
// target. Merging on the bare name over-approximates, which is the safe
// direction; merging on the qualified one would be simply wrong.
func TestQualifiedReceiverSuppressesTheSameNameMerge(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php class Helper { function act() { helper_sink(); } }`,
		"b.php": `<?php class Other  { function act() { other_sink(); } }`,
		"c.php": `<?php class Solo   { function go()  { Helper::act(); } }`,
	}
	cg := BuildCallGraph(files)

	calls, _ := cg.outgoingCalls("Helper::act")
	set := map[string]bool{}
	for _, c := range calls {
		set[c] = true
	}
	mustReach(t, set, "Helper::act", "helper_sink")
	mustNotReach(t, set, "Helper::act", "other_sink")

	got := closureOf(t, cg, "Solo::go", "")
	mustReach(t, got, "Solo::go", "helper_sink")
}

// `parent::m()` was unresolvable in principle: the extends clause had no
// capture group, so no parent name existed anywhere in the graph.
func TestParentCallResolvesThroughTheExtendsClause(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php class BaseCtl { public function setup() { base_setup_sink(); } }`,
		"b.php": `<?php class ChildCtl extends BaseCtl { public function setup() { parent::setup(); child_extra(); } }`,
		"c.php": `<?php class Decoy { public function setup() { decoy_sink(); } }`,
	}
	cg := BuildCallGraph(files)
	if !hasToken(cg.CallsFrom["ChildCtl::setup"], "BaseCtl::setup") {
		t.Errorf("CallsFrom[ChildCtl::setup] = %v, want a BaseCtl::setup token",
			cg.CallsFrom["ChildCtl::setup"])
	}
	got := closureOf(t, cg, "ChildCtl::setup", "")
	mustReach(t, got, "ChildCtl::setup", "base_setup_sink")
}

// A method a class inherits has no Class::method key of its own, so the
// resolution order has to walk to the ancestor that declares it.
func TestInheritedMethodResolvesThroughTheAncestor(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php class Base { public function shared() { base_shared_sink(); } }`,
		"b.php": `<?php class Kid extends Base { public function go() { Kid::shared(); } }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "Kid::go", "")
	mustReach(t, got, "Kid::go", "base_shared_sink")
}

// The bare spelling must survive alongside the qualified one. `$this->m()` is
// LATE bound in PHP -- the runtime object may be a subclass -- so an override
// the enclosing class's resolution order never reaches is still a real target.
func TestBareTokenSurvivesBesideTheQualifiedOne(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php abstract class Base { function run() { $this->handle(); } function handle() {} }`,
		"b.php": `<?php class Child extends Base { function handle() { evil_sink(); } }`,
	}
	cg := BuildCallGraph(files)
	if !hasToken(cg.CallsFrom["Base::run"], "handle") {
		t.Errorf("CallsFrom[Base::run] = %v, want the bare `handle` token kept", cg.CallsFrom["Base::run"])
	}
	got := closureOf(t, cg, "Base::run", "")
	mustReach(t, got, "Base::run", "evil_sink")
}

func hasToken(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// --- Constructors -------------------------------------------------------------

// `new Klass(...)` invokes Klass::__construct unconditionally. WordPress
// plugins do their whole wiring in constructors, so a missing edge terminates
// every chain that passes through an instantiation.
func TestNewCreatesAConstructorEdge(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php
function bootstrap() { $o = new Widget(); }
function bootstrap_no_parens() { $o = new Widget; }
class Widget {
	public function __construct() { register_thing(); $this->wire(); }
	public function wire() { deep_sink(); }
}`,
	}
	cg := BuildCallGraph(files)
	for _, entry := range []string{"bootstrap", "bootstrap_no_parens"} {
		got := closureOf(t, cg, entry, "")
		mustReach(t, got, entry, "Widget::__construct", "register_thing", "deep_sink")
	}
}

// A class that declares no constructor inherits its parent's.
func TestNewFindsAnInheritedConstructor(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php class Base { public function __construct() { base_ctor_sink(); } }`,
		"b.php": `<?php class Kid extends Base {}`,
		"c.php": `<?php function go() { new Kid(); }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "go", "")
	mustReach(t, got, "go", "base_ctor_sink")
}

// The bound: a constructor edge is exact or it is nothing. The bare
// `__construct` key names one arbitrary constructor, and under the same-name
// merge it names every constructor in the plugin -- 37% of one corpus tree
// reachable from a single token. An unknown class must therefore reach none.
func TestUnknownClassGetsNoConstructorEdge(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php class Alpha { public function __construct() { alpha_ctor_sink(); } }`,
		"b.php": `<?php class Beta  { public function __construct() { beta_ctor_sink(); } }`,
		"c.php": `<?php
function make_known()   { new Alpha(); }
function make_unknown() { new SomeVendorClassNotInThisTree(); }
function make_dynamic($c) { new $c(); }
function make_anon()    { $x = new class { public function __construct() { anon_sink(); } }; }`,
	}
	cg := BuildCallGraph(files)

	known := closureOf(t, cg, "make_known", "")
	mustReach(t, known, "make_known", "alpha_ctor_sink")
	mustNotReach(t, known, "make_known", "beta_ctor_sink")

	for _, entry := range []string{"make_unknown", "make_dynamic", "make_anon"} {
		got := closureOf(t, cg, entry, "")
		mustNotReach(t, got, entry, "alpha_ctor_sink", "beta_ctor_sink")
	}
	if hasToken(cg.CallsFrom["make_anon"], "class::__construct") {
		t.Errorf("an anonymous class produced a `class::__construct` token")
	}
	// An anonymous class's own body is still read, because it is written inside
	// the function that instantiates it.
	mustReach(t, closureOf(t, cg, "make_anon", ""), "make_anon", "anon_sink")
}

// --- A file's load-time code --------------------------------------------------

// PHP has no main(): code outside a function body runs when the file is
// included or requested. 618 `direct` endpoints across 77 of 143 corpus trees
// name a FILE as their callback, and every one of them resolved to nothing.
func TestFileScopeCodeIsACallGraphNode(t *testing.T) {
	files := map[string]string{
		"main.php": `<?php require_once __DIR__ . '/lib.php'; boot();`,
		"lib.php":  `<?php function boot() { sink(); }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "main.php", "")
	mustReach(t, got, "main.php", "boot", "sink")
}

// An include edge gets a function-level twin, so what the included file runs at
// its own scope is reachable from the including file.
func TestIncludeEdgeHasAFunctionLevelTwin(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php require_once 'inc/b.php';`,
		"inc/b.php": `<?php
$obj = new Runner();
class Runner { public function __construct() { run_me(); } }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "a.php", "")
	mustReach(t, got, "a.php", "run_me")
}

// The bound: blanking must start at the declaration HEAD. Blanking from the
// body brace instead leaves `function only_decl(` readable as a call and
// inflates the extracted set roughly threefold.
func TestDeclarationHeadsAreNotReadAsLoadTimeCalls(t *testing.T) {
	files := map[string]string{
		"d.php": `<?php
function only_decl($x = array()) { inner_call(); }
class Holder { public function m() { method_inner(); } }`,
	}
	cg := BuildCallGraph(files)
	for _, unwanted := range []string{"only_decl", "inner_call", "method_inner"} {
		if hasToken(cg.CallsFrom["d.php"], unwanted) {
			t.Errorf("the load-time node of d.php contains %q; CallsFrom[d.php] = %v",
				unwanted, cg.CallsFrom["d.php"])
		}
	}
}

// A callback that names a file resolves by PATH, never by a shared basename.
// 164 of the 618 direct-endpoint files share a basename with another file in
// the same tree, and a basename lookup would walk the wrong bootstrap.
func TestAmbiguousBasenameDoesNotSeedTheWrongFile(t *testing.T) {
	files := map[string]string{
		"one/handler.php": `<?php one_sink();`,
		"two/handler.php": `<?php two_sink();`,
	}
	cg := BuildCallGraph(files)

	got := closureOf(t, cg, "handler.php", "")
	mustNotReach(t, got, "handler.php", "one_sink", "two_sink")

	withFile := GetRecursiveCallsForCallbackInFile(cg, "handler.php", "two/handler.php", "")
	set := map[string]bool{}
	for _, c := range withFile {
		set[c] = true
	}
	mustReach(t, set, "two/handler.php", "two_sink")
	mustNotReach(t, set, "two/handler.php", "one_sink")
}

// A widget endpoint's callback is spelled "Class::widget()". The trailing empty
// argument list tripped the "looks like an expression" guard, so 151 widget
// endpoints across 34 corpus trees had an empty call set.
func TestCallbackWithEmptyArgumentListResolves(t *testing.T) {
	files := map[string]string{
		"w.php": `<?php class MyWidget extends \WP_Widget { public function widget($a, $b) { widget_sink(); } }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "MyWidget::widget()", "")
	mustReach(t, got, "MyWidget::widget()", "widget_sink")
}

// --- Path separators ----------------------------------------------------------

// Include paths inside PHP source are written with forward slashes while the
// files map is keyed by whatever the caller's platform produced. Comparing the
// two raw made every suffix test fail on Windows, and resolution degraded to
// "exactly one file has this basename".
func TestIncludeResolutionIgnoresPathSeparators(t *testing.T) {
	body := map[string]string{
		"root.php":                `<?php require_once 'includes/lib/helper.php';`,
		"includes/lib/helper.php": `<?php helper_sink();`,
		"other/helper.php":        `<?php other_sink();`,
	}
	slashed := map[string]string{}
	backslashed := map[string]string{}
	for k, v := range body {
		slashed[k] = v
		backslashed[strings.ReplaceAll(k, "/", "\\")] = v
	}

	for label, files := range map[string]map[string]string{"slash": slashed, "backslash": backslashed} {
		cg := BuildCallGraph(files)
		got := closureOf(t, cg, "root.php", "")
		if !got["helper_sink"] {
			t.Errorf("%s keys: root.php does not reach helper_sink; got %v", label, sortedKeys(got))
		}
		if got["other_sink"] {
			t.Errorf("%s keys: root.php reached the wrong helper.php", label)
		}
	}
}

// --- Dynamic includers --------------------------------------------------------

// A template loader is normally written with a defaulted parameter, and the
// regex parameter list this scan used stopped at the first ")" inside it.
func TestDynamicIncluderWithDefaultedParameterIsFound(t *testing.T) {
	files := map[string]string{
		"l.php": `<?php
class Loader {
	public function load_view($name, $args = array()) {
		include $this->dir . $name . '.php';
	}
}`,
	}
	cg := BuildCallGraph(files)
	if len(cg.DynIncluders["Loader::load_view"]) == 0 {
		t.Errorf("Loader::load_view was not recognised as a dynamic includer; DynIncluders = %v",
			cg.DynIncluders)
	}
}

// The bound: two includers sharing a bare name collide on this map, and
// overwriting would take away a directory that is covered today.
func TestDynamicIncluderHintsAreUnioned(t *testing.T) {
	files := map[string]string{
		"a/one.php": `<?php class A { public function render($n) { $d = 'views/'; include $d . $n . '.php'; } }`,
		"b/two.php": `<?php class B { public function render($n) { $d = 'partials/'; include $d . $n . '.php'; } }`,
	}
	cg := BuildCallGraph(files)
	hints := strings.Join(cg.DynIncluders["render"], "|")
	for _, want := range []string{"views", "partials"} {
		if !strings.Contains(hints, want) {
			t.Errorf("DynIncluders[render] = %v, want a hint containing %q", cg.DynIncluders["render"], want)
		}
	}
}

// --- Names that collide with WordPress core -----------------------------------

// A WordPress core name is skipped because there is nothing to recurse into --
// unless the plugin declares a function of that name itself, which 730
// declarations across 102 of 143 corpus trees do.
func TestPluginDeclarationShadowingCoreIsStillFollowed(t *testing.T) {
	shadow := map[string]string{
		"a.php": `<?php function get_option($k) { shadowed_sink(); }`,
		"b.php": `<?php function entry() { get_option('x'); }`,
	}
	cg := BuildCallGraph(shadow)
	got := closureOf(t, cg, "entry", "")
	mustReach(t, got, "entry", "get_option", "shadowed_sink")

	// The bound: when the tree does NOT declare it, the core name stays out.
	plain := map[string]string{
		"b.php": `<?php function entry() { get_option('x'); }`,
	}
	cg2 := BuildCallGraph(plain)
	got2 := closureOf(t, cg2, "entry", "")
	mustNotReach(t, got2, "entry", "get_option")
}

// --- Variable method names ----------------------------------------------------

// `[$this, $m]` and `$this->$m()` do not name an unknown target: $this is an
// instance of the enclosing class, so the target is one of that class's
// methods. Returning nothing throws away a bounded, enumerable set.
func TestVariableMethodOnThisExpandsToTheClassesMethods(t *testing.T) {
	files := map[string]string{
		"d.php": `<?php
class D {
	function reg() { foreach (array('a','b') as $m) { add_action('h_' . $m, array($this, $m)); } }
	function dispatch($m) { $this->$m(); }
	function a() { sink_a(); }
	function b() { sink_b(); }
}
function fire() { do_action('h_a'); }`,
	}
	cg := BuildCallGraph(files)

	var registered []string
	for _, m := range []map[string][]HookRegistration{cg.HookRegistry.Hooks, cg.HookRegistry.PrefixHooks} {
		for hook, regs := range m {
			for _, r := range regs {
				registered = append(registered, hook+" -> "+r.Callback)
				if !r.Synthesized {
					t.Errorf("registration %s -> %s should be marked synthesized", hook, r.Callback)
				}
			}
		}
	}
	sort.Strings(registered)
	joined := strings.Join(registered, "\n")
	for _, want := range []string{"D::a", "D::b"} {
		if !strings.Contains(joined, want) {
			t.Errorf("hook registry has no %s; registrations:\n%s", want, joined)
		}
	}

	got := closureOf(t, cg, "D::dispatch", "")
	mustReach(t, got, "D::dispatch", "sink_a", "sink_b")
}

// The bound: the rule is anchored on $this. A variable method on some other
// object is not bounded by the enclosing class and must expand to nothing.
func TestVariableMethodOnAnotherObjectExpandsToNothing(t *testing.T) {
	files := map[string]string{
		"d.php": `<?php
class D {
	function dispatch($obj, $m) { $obj->$m(); }
	function a() { sink_a(); }
}`,
	}
	cg := BuildCallGraph(files)
	if hasToken(cg.CallsFrom["D::dispatch"], "D::a") {
		t.Errorf("$obj->$m() expanded to the enclosing class's methods: %v", cg.CallsFrom["D::dispatch"])
	}
}

// A literal prefix bounds the set further: PHP string concatenation is
// prefix-preserving, so 'action' . $x can only name a method whose name starts
// with "action".
func TestConcatenatedMethodNameIsBoundedByItsLiteralPrefix(t *testing.T) {
	files := map[string]string{
		"c.php": `<?php
class Router {
	public function route($a, $args) {
		if (method_exists($this, 'action' . $a)) {
			call_user_func_array(array($this, 'action' . $a), $args);
		}
	}
	public function actionExportAll() { export_sink(); }
	public function unrelated() { unrelated_sink(); }
}`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "Router::route", "")
	mustReach(t, got, "Router::route", "export_sink")
	mustNotReach(t, got, "Router::route", "unrelated_sink")
}

// --- Hook registrations -------------------------------------------------------

// PHP folds adjacent string literals at compile time. Not folding them made the
// registered callback the literal text between the outer quotes, which names
// nothing.
func TestAdjacentStringLiteralsAreFolded(t *testing.T) {
	files := map[string]string{
		"h.php": `<?php
add_action('wp_ajax_nopriv_thing', 'ajax_' . 'do_thing');
function ajax_do_thing() { folded_sink(); }
function fire() { do_action('wp_ajax_nopriv_thing'); }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "fire", "")
	mustReach(t, got, "fire", "ajax_do_thing", "folded_sink")

	// The bound: an expression with a variable in it names something that
	// cannot be read, and must not be folded into a bogus name.
	if foldStringConcat("'ajax_' . $x") != "'ajax_' . $x" {
		t.Errorf("a concatenation with a variable was folded")
	}
}

// WordPress's extension model is that core, or another plugin, fires the hook.
// A callback registered for a hook nobody in this tree fires is code an
// external dispatcher runs during request handling.
func TestExternallyFiredHooksAreReportedAsRoots(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php
add_action('before_delete_post', 'cb_external');
add_action('my_own_hook', 'cb_internal');
function cb_external() { external_sink(); }
function cb_internal() { internal_sink(); }
function fire() { do_action('my_own_hook'); }`,
	}
	cg := BuildCallGraph(files)
	roots, opaque := cg.ExternalHookRoots()
	if opaque {
		t.Errorf("no firing in this fixture is opaque")
	}
	var names []string
	for _, r := range roots {
		names = append(names, r.Hook+"->"+r.Callback)
	}
	sort.Strings(names)
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "before_delete_post->cb_external") {
		t.Errorf("external root missing; roots = %v", names)
	}
	// The bound: a hook the tree fires itself already has an in-edge and is not
	// an entry point.
	if strings.Contains(joined, "my_own_hook") {
		t.Errorf("a hook the tree fires itself was reported as an external root; roots = %v", names)
	}
}

// A firing whose name cannot be read makes "this tree never fires that hook" a
// weaker statement, and the caller is told so.
func TestOpaqueFiringIsReported(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php
add_action('some_hook', 'cb');
function cb() {}
function fire($name) { do_action($name); }`,
	}
	cg := BuildCallGraph(files)
	if _, opaque := cg.ExternalHookRoots(); !opaque {
		t.Errorf("a do_action($var) firing was not reported as opaque")
	}
}

// --- File-scoped import aliases -----------------------------------------------

// PHP scopes `use X as Y` to the file it is written in. The call graph's keys
// carry no file, so the alias is ADDED rather than substituted: rewriting would
// break every other file that names the same identifier without the import.
func TestUseAliasAddsTheImportedNameWithoutRemovingTheLocalOne(t *testing.T) {
	files := map[string]string{
		"vendor_zip.php": `<?php namespace Vendor\Pack; class Zip { public static function open() { vendor_zip_sink(); } }`,
		"local_zip.php":  `<?php class Zip { public static function open() { local_zip_sink(); } }`,
		"user.php": `<?php
use Vendor\Pack\Zip as Archive;
function go() { Archive::open(); }`,
		"plain.php": `<?php function go_plain() { Zip::open(); }`,
	}
	cg := BuildCallGraph(files)

	aliased := closureOf(t, cg, "go", "")
	mustReach(t, aliased, "go", "vendor_zip_sink")

	// The bound: a file that did not import the alias keeps naming the local
	// class, and the alias must not have rewritten it away.
	plain := closureOf(t, cg, "go_plain", "")
	mustReach(t, plain, "go_plain", "local_zip_sink")
}

// --- Storage ------------------------------------------------------------------

// The alias key is "<basename>.php::<name>". A third declaration of one name in
// a single file collided on that key and its calls were dropped: 1,722
// declarations across 35 corpus trees were stored under no reachable key.
func TestThirdSameNamedDeclarationInOneFileStaysReachable(t *testing.T) {
	files := map[string]string{
		"all.php": `<?php
class One   { public function render() { one_sink(); } }
class Two   { public function render() { two_sink(); } }
class Three { public function render() { three_sink(); } }
function entry() { $a = new Three(); $a->render(); }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "entry", "")
	mustReach(t, got, "entry", "one_sink", "two_sink", "three_sink")
}

// Two files declaring the same class name must not overwrite each other's
// bodies: 487 such names across 45 of 143 corpus trees.
func TestSameClassNameInTwoFilesKeepsBothBodies(t *testing.T) {
	files := map[string]string{
		"a/dup.php": `<?php class Dup { public function m() { dup_a_sink(); } }`,
		"b/dup.php": `<?php class Dup { public function m() { dup_b_sink(); } }`,
		"c.php":     `<?php function entry() { Dup::m(); }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "entry", "")
	mustReach(t, got, "entry", "dup_a_sink", "dup_b_sink")
}

// --- Determinism --------------------------------------------------------------

// Trait aliasing writes new keys into CallsFrom. Doing that while ranging over
// the same map is unspecified in Go, so the writes are collected first.
func TestTraitAliasingIsDeterministic(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php trait T1 { public function m1() { t1_sink(); } }`,
		"b.php": `<?php trait T2 { use T1; public function m2() { t2_sink(); } }`,
		"c.php": `<?php class C1 { use T2; public function go() { $this->m1(); $this->m2(); } }`,
		"d.php": `<?php class C2 { use T1, T2; public function go2() { $this->m1(); } }`,
	}
	var first []string
	for i := 0; i < 12; i++ {
		cg := BuildCallGraph(files)
		keys := sortedKeys(callsFromKeys(cg))
		if i == 0 {
			first = keys
			continue
		}
		if strings.Join(keys, ",") != strings.Join(first, ",") {
			t.Fatalf("CallsFrom keys differ on run %d:\nfirst: %v\ngot:   %v", i+1, first, keys)
		}
	}
}

// --- A class named by a variable ----------------------------------------------

// PHP string concatenation is prefix-preserving: `"WPJP" . $x . "Controller"`
// can only ever produce a name that begins "WPJP" and ends "Controller", so the
// set of types the expression can name is bounded by the literals written at
// that very site. Framework-shaped plugins route every request through such a
// dispatch, and without the edge the whole controller layer is a dead end.
func TestConcatenatedClassNameResolvesToTheMatchingTypes(t *testing.T) {
	files := map[string]string{
		"inc.php": `<?php
function make($name) {
	$classname = "WPJP" . $name . "Controller";
	$obj = new $classname();
	return $obj;
}`,
		"cat.php": `<?php
class WPJPCategoryController {
	function __construct() { self::handleRequest(); }
	function handleRequest() { cat_sink(); }
}`,
		"job.php": `<?php
class WPJPJobController {
	function __construct() { job_setup(); }
}`,
		"other.php": `<?php
class SomethingElse {
	function __construct() { unrelated_sink(); }
}`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "make", "")
	mustReach(t, got, "make", "cat_sink", "job_setup")

	// The bound: a type that does not carry both literals is not in the set.
	mustNotReach(t, got, "make", "unrelated_sink")
}

// The bound that keeps the rule from becoming vacuous: matching is against the
// UNQUALIFIED type name, so a literal that is nothing but a namespace prefix
// constrains that name not at all. `'\Vendor\Pack\' . $x` would otherwise link
// one call site to every type in the plugin -- measured at 3,174 of 3,174 on
// one corpus tree.
func TestNamespaceOnlyLiteralIsTreatedAsUnbounded(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php
function make($x) {
	$c = '\Vendor\Pack\' . $x;
	return new $c();
}`,
		"b.php": `<?php class Alpha { function __construct() { alpha_sink(); } }`,
		"c.php": `<?php class Beta  { function __construct() { beta_sink(); } }`,
	}
	cg := BuildCallGraph(files)
	got := closureOf(t, cg, "make", "")
	mustNotReach(t, got, "make", "alpha_sink", "beta_sink")
}

// A variable holding a plain literal names exactly one class.
func TestLiteralClassNameInAVariableResolvesExactly(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php function go() { $c = 'Runner'; $c::start(); }`,
		"b.php": `<?php class Runner { public static function start() { runner_sink(); } }`,
		"c.php": `<?php class Walker { public static function start() { walker_sink(); } }`,
	}
	cg := BuildCallGraph(files)
	if !hasToken(cg.CallsFrom["go"], "Runner::start") {
		t.Errorf("CallsFrom[go] = %v, want a Runner::start token", cg.CallsFrom["go"])
	}
	// The bound: the variable holds one name, so only that class's method is
	// linked. The same site also yields the bare spelling `start`, which is
	// merged over every declaration of that name -- an over-approximation in
	// the safe direction that the exact token does not contribute to.
	if hasToken(cg.CallsFrom["go"], "Walker::start") {
		t.Errorf("CallsFrom[go] = %v, want no Walker::start token", cg.CallsFrom["go"])
	}
	mustReach(t, closureOf(t, cg, "go", ""), "go", "runner_sink")
}

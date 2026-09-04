package analyzer

import (
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

func frameworkRoutes(eps []models.Endpoint) map[string]models.Endpoint {
	out := make(map[string]models.Endpoint, len(eps))
	for _, ep := range eps {
		out[ep.Callback] = ep
	}
	return out
}

// TestFrameworkEntryPointForAnExternalBase is the shape the pass exists for: a
// class completed by code outside the tree, carrying a method the tree never
// calls.
//
// Nothing modelled that before. The widget detector keys on WP_Widget
// specifically, and no other detector treats an uncalled method as a root, so
// for a plugin whose product IS its widget classes the analyzer reported a
// couple of dozen endpoints and the code behind render() was reachable from
// nothing at all.
func TestFrameworkEntryPointForAnExternalBase(t *testing.T) {
	files := map[string]string{
		"w.php": `<?php
class My_Widget extends Some_External_Base {
	protected function render() {
		$this->render_raw();
	}
	protected function render_raw() {
		include 'styles/' . $this->style . '.php';
	}
	private function helper() {
		return acme_util();
	}
	public function used() {
		return acme_util();
	}
}

function acme_util() {
	return 1;
}

class Caller {
	function go( $w ) {
		$w->used();
	}
}
`,
	}
	eps := DetectFrameworkEntryPoints(files, "p")
	got := frameworkRoutes(eps)

	if _, ok := got["My_Widget::render"]; !ok {
		t.Errorf("render is not an entry point; got %v", entryNames(got))
	}
	if _, ok := got["My_Widget::render_raw"]; ok {
		t.Error("render_raw is called by render inside the same class, so it is not an entry point")
	}
	if _, ok := got["My_Widget::helper"]; ok {
		t.Error("helper is private: no caller outside the class can name it")
	}
	// used() IS called in the tree -- but through `$w->used()`, on a variable
	// whose class nothing establishes. That is not evidence about My_Widget,
	// and treating it as evidence is what made the bare-name reading useless:
	// override methods have generic names, so some unrelated `$x->render()`
	// always exists and every widget's render() was suppressed by it. An extra
	// endpoint for a method that happens to share a name is the safe direction.
	if _, ok := got["My_Widget::used"]; !ok {
		t.Errorf("used() is called only through an untyped variable, which says nothing about My_Widget; got %v", entryNames(got))
	}
	if _, ok := got["Caller::go"]; ok {
		t.Error("Caller extends nothing, so no code outside the tree completes it")
	}
	if ep := got["My_Widget::render"]; ep.AuthLevel != models.Unauthenticated {
		t.Errorf("AuthLevel = %s, want unauthenticated: who drives an unknown external framework is not knowable from the tree, and the bottom of the lattice is the only answer that cannot hide a bug",
			ep.AuthLevel)
	}
	if ep := got["My_Widget::render"]; ep.File != "w.php" || ep.Line != 3 {
		t.Errorf("declared at %s:%d, want w.php:3", ep.File, ep.Line)
	}
}

// TestFrameworkEntryPointIsClassScoped is the negative case that decides
// whether the pass works at all.
//
// The call graph is keyed on bare names, and framework override methods are
// exactly the ones with generic names -- render, init, run, handle. If a call
// to some OTHER class's render() counted as a call to this one, no widget's
// render would ever be an entry point, and the rule would fire only on the
// methods nobody cares about. PHP is unambiguous here: inside a class, only
// $this->m(), self::m() and static::m() denote that class's m, and
// Other::render() denotes a different method entirely.
func TestFrameworkEntryPointIsClassScoped(t *testing.T) {
	files := map[string]string{
		"w.php": `<?php
class My_Widget extends Some_External_Base {
	protected function render() {
		$this->emit();
	}
	protected function emit() {
		return acme_util();
	}
}

function acme_util() {
	return 1;
}
`,
		"other.php": `<?php
class Utils {
	public static function render( $output ) {
		return acme_util();
	}
}

class Loader {
	public function run( $transformer ) {
		Utils::render( 'x' );
		$transformer->render( 'y' );
		render( 'z' );
	}
}
`,
	}
	eps := DetectFrameworkEntryPoints(files, "p")
	got := frameworkRoutes(eps)
	if _, ok := got["My_Widget::render"]; !ok {
		t.Errorf("render was suppressed by an unrelated class's method of the same name; got %v", entryNames(got))
	}
	if _, ok := got["Utils::render"]; ok {
		t.Error("Utils::render is named explicitly at a call site, and Utils extends nothing anyway")
	}
}

// TestFrameworkEntryPointSuppressedByExplicitNaming pins the three spellings
// that can denote a method without $this: Class::m(, [ Class::class, 'm' ] and
// array( 'Class', 'm' ).
func TestFrameworkEntryPointSuppressedByExplicitNaming(t *testing.T) {
	files := map[string]string{
		"w.php": `<?php
class A extends External_Base {
	public static function boot() {
		return acme_util();
	}
	public function handle() {
		return acme_util();
	}
	public function save() {
		return acme_util();
	}
	public function keep() {
		return acme_util();
	}
}

function acme_util() {
	return 1;
}
`,
		"reg.php": `<?php
A::boot();
add_action( 'init', array( 'A', 'handle' ) );
add_action( 'init', [ A::class, 'save' ] );
`,
	}
	got := frameworkRoutes(DetectFrameworkEntryPoints(files, "p"))
	for _, gone := range []string{"A::boot", "A::handle", "A::save"} {
		if _, ok := got[gone]; ok {
			t.Errorf("%s is named at a call site and must not be an entry point", gone)
		}
	}
	if _, ok := got["A::keep"]; !ok {
		t.Errorf("A::keep is named nowhere and must be an entry point; got %v", entryNames(got))
	}
}

// TestFrameworkEntryPointClosureCoversRelatives pins the rest of the
// inheritance closure. A method of C can be denoted by $this-> in an in-tree
// ancestor (the template-method shape, where the base calls a method the
// subclass implements), by $this-> in an in-tree descendant that inherits it,
// and by parent:: in a descendant that overrides it.
func TestFrameworkEntryPointClosureCoversRelatives(t *testing.T) {
	files := map[string]string{
		"base.php": `<?php
class Mid extends External_Base {
	public function run() {
		$this->step();
	}
	public function step() {
		return acme_util();
	}
	public function draw() {
		return acme_util();
	}
	public function alone() {
		return acme_util();
	}
}

function acme_util() {
	return 1;
}
`,
		"sub.php": `<?php
class Leaf extends Mid {
	public function draw() {
		return parent::draw();
	}
}
`,
	}
	got := frameworkRoutes(DetectFrameworkEntryPoints(files, "p"))
	if _, ok := got["Mid::step"]; ok {
		t.Error("step is called by run() on the same object")
	}
	if _, ok := got["Mid::draw"]; ok {
		t.Error("draw is called by parent::draw() in a subclass")
	}
	if _, ok := got["Mid::alone"]; !ok {
		t.Errorf("alone has no call site anywhere; got %v", entryNames(got))
	}
	// Leaf's chain reaches outside the tree through Mid, so Leaf is
	// framework-managed too. Leaf::draw is NOT suppressed by its own
	// parent::draw(): that call denotes Mid::draw. It is suppressed by Mid's
	// $this->draw()... which Mid does not have -- so it stands, and must,
	// because a subclass overriding a method and calling parent:: from it is
	// the commonest override shape and the subclass's copy is the one the
	// framework invokes.
	if _, ok := got["Leaf::draw"]; !ok {
		t.Errorf("Leaf::draw was suppressed by its own parent::draw(), which denotes Mid's method, not Leaf's; got %v", entryNames(got))
	}
}

// TestFrameworkEntryPointNeedsAReachableBody is the cost bound.
//
// A method that calls nothing the tree declares and includes no file cannot
// root a walk: an endpoint for it widens the reported surface without widening
// what is examined. Widget-heavy plugins declare hundreds of one-line getters,
// and every one of them would otherwise become an endpoint.
func TestFrameworkEntryPointNeedsAReachableBody(t *testing.T) {
	files := map[string]string{
		"w.php": `<?php
class W extends External_Base {
	public function get_name() {
		return 'my-widget';
	}
	public function get_categories() {
		return array( 'general' );
	}
	public function render() {
		return acme_util();
	}
	public function load() {
		include 'partial.php';
	}
}

function acme_util() {
	return 1;
}
`,
	}
	got := frameworkRoutes(DetectFrameworkEntryPoints(files, "p"))
	for _, gone := range []string{"W::get_name", "W::get_categories"} {
		if _, ok := got[gone]; ok {
			t.Errorf("%s reaches no code in the tree and buys nothing as an endpoint", gone)
		}
	}
	for _, want := range []string{"W::render", "W::load"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s reaches in-tree code and must be an entry point; got %v", want, entryNames(got))
		}
	}
}

// TestFrameworkEntryPointIgnoresInTreeHierarchies is the other bound: a class
// whose inheritance chain ends inside the tree is completed by nothing outside
// it, so nothing licenses calling its methods entry points.
func TestFrameworkEntryPointIgnoresInTreeHierarchies(t *testing.T) {
	files := map[string]string{
		"a.php": `<?php
class Root {
	public function work() {
		return acme_util();
	}
}

class Child extends Root {
	public function other() {
		return acme_util();
	}
}

function acme_util() {
	return 1;
}
`,
	}
	if eps := DetectFrameworkEntryPoints(files, "p"); len(eps) != 0 {
		t.Fatalf("expected no entry points, got %v", entryNames(frameworkRoutes(eps)))
	}
}

func entryNames(m map[string]models.Endpoint) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

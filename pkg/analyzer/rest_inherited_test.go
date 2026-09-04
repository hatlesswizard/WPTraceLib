package analyzer

import (
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

const inheritedBasePHP = `<?php
abstract class Base {
	protected $namespace = 'ns/v1';
	protected $rest_base = '';

	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base,
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_items' ),
					'permission_callback' => array( $this, 'get_items_permissions_check' ),
				),
			)
		);
	}

	public function get_items( $request ) {
		return array();
	}

	public function get_items_permissions_check( $request ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'forbidden', 'no' );
		}
		return current_user_can( 'manage_options' );
	}
}
`

func endpointFor(eps []models.Endpoint, callback string) (models.Endpoint, bool) {
	for _, ep := range eps {
		if ep.Callback == callback {
			return ep, true
		}
	}
	return models.Endpoint{}, false
}

// TestInheritedRegisterRoutesIsOnePerSubclass pins the shape.
//
// PHP reads $this->rest_base and resolves $this->get_items() on the runtime
// object, and a class that does not redeclare register_routes() inherits its
// parent's verbatim, so WordPress registering one controller per concrete
// subclass turns one textual register_rest_route into N live routes with N
// bodies. The analyzer is a per-file text scan and reported the base's copy
// only, which left every overriding subclass reachable from nothing.
func TestInheritedRegisterRoutesIsOnePerSubclass(t *testing.T) {
	eps := analyzeFake(t, map[string]string{
		"base.php": inheritedBasePHP,
		"sub.php": `<?php
class Sub extends Base {
	protected $rest_base = 'things';

	public function get_items( $request ) {
		return array( 1 );
	}

	public function get_items_permissions_check( $request ) {
		return true;
	}
}
`,
	})

	clone, ok := endpointFor(eps, "Sub::get_items")
	if !ok {
		t.Fatalf("no endpoint for the subclass's handler; got %+v", eps)
	}
	if clone.Route != "/wp-json/ns/v1/things" {
		t.Errorf("Route = %q, want /wp-json/ns/v1/things: the route is built from $this->rest_base, which the subclass gives its own value",
			clone.Route)
	}
	if clone.File != "sub.php" {
		t.Errorf("File = %q, want sub.php: the registration core runs is the subclass's, and the walk has to start where the subclass is",
			clone.File)
	}

	// The base's own record survives. A base may itself be instantiated
	// through a concrete leaf the hierarchy did not see, and this pass adds
	// records rather than replacing them.
	if _, ok := endpointFor(eps, "this::get_items"); !ok {
		t.Errorf("the base's own endpoint was replaced rather than added to; got %+v", eps)
	}
}

// TestInheritedSubclassThatRegistersNothingNewIsNotCloned is the bound.
//
// A subclass that overrides neither the handler nor a gate the registration
// names, and gives the route no value of its own, registers a route the base's
// record already describes. Cloning it would add a record with the same route,
// the same level and literally the base's body -- and the cost is not
// theoretical: a base class in the corpus has 31 transitive descendants in a
// tree carrying 85 register_rest_route calls, so clone-per-descendant is a
// four-figure endpoint count in one plugin, each clone paying its own graph
// walks.
func TestInheritedSubclassThatRegistersNothingNewIsNotCloned(t *testing.T) {
	eps := analyzeFake(t, map[string]string{
		"base.php": inheritedBasePHP,
		"sub.php": `<?php
class Plain extends Base {
	public function unrelated() {
		return 1;
	}
}
`,
	})
	if ep, ok := endpointFor(eps, "Plain::get_items"); ok {
		t.Errorf("Plain overrides nothing the registration names and has no rest_base of its own, so it registers what the base already describes; got %+v", ep)
	}
}

// TestInheritedCloneNeverRaisesTheLevel pins the level rule.
//
// A clone is often the ONLY record reaching the subclass's method, so its level
// is the answer a consumer gets for that code. Copying the base's gate onto a
// subclass that overrides it would report a privilege this code has not been
// shown to require; re-reading the override and taking the weaker of the two
// answers means an override that cannot be read reports no gate rather than an
// inherited one.
func TestInheritedCloneNeverRaisesTheLevel(t *testing.T) {
	eps := analyzeFake(t, map[string]string{
		"base.php": `<?php
abstract class Base {
	protected $namespace = 'ns/v1';
	protected $rest_base = '';

	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base,
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_items' ),
					'permission_callback' => array( $this, 'check' ),
				),
			)
		);
	}

	public function get_items( $request ) {
		return array();
	}

	public function check( $request ) {
		return true;
	}
}
`,
		"strict.php": `<?php
class Strict extends Base {
	protected $rest_base = 'strict';

	public function check( $request ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'forbidden', 'no' );
		}
		return current_user_can( 'manage_options' );
	}
}
`,
	})

	base, ok := endpointFor(eps, "this::get_items")
	if !ok {
		t.Fatalf("the base's endpoint is missing; got %+v", eps)
	}
	clone, ok := endpointFor(eps, "Strict::get_items")
	if !ok {
		t.Fatalf("no endpoint for the subclass; got %+v", eps)
	}
	if clone.AuthLevel > base.AuthLevel {
		t.Errorf("clone level %s is above the base's %s: a clone may only ever report a weaker requirement, since it is usually the only record reaching that code",
			clone.AuthLevel, base.AuthLevel)
	}
}

// TestInheritedExpansionCrossesACaseVariantSpelling pins the hierarchy fix the
// expansion depends on.
//
// PHP compares class names case-insensitively, so `extends Rest_Controller`
// names the class declared as `REST_Controller`, and plugins really do write
// both spellings in one tree. Resolving a parent by exact string match broke
// the chain at the first such spelling: the grandchild had no ancestors, so it
// was not a subclass of anything and every route it inherited stayed invisible.
func TestInheritedExpansionCrossesACaseVariantSpelling(t *testing.T) {
	eps := analyzeFake(t, map[string]string{
		"base.php": `<?php
abstract class REST_Controller {
	protected $namespace = 'ns/v1';
	protected $rest_base = '';

	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base,
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_items' ),
					'permission_callback' => array( $this, 'get_items_permissions_check' ),
				),
			)
		);
	}

	public function get_items( $request ) {
		return array();
	}

	public function get_items_permissions_check( $request ) {
		return true;
	}
}
`,
		"mid.php": `<?php
abstract class Users_Controller extends Rest_Controller {
	public function prepare_item( $item ) {
		return $item;
	}
}
`,
		"leaf.php": `<?php
class Instructors_Controller extends Users_Controller {
	protected $rest_base = 'instructors';

	public function get_items_permissions_check( $request ) {
		return current_user_can( 'list_users' );
	}
}
`,
	})

	clone, ok := endpointFor(eps, "Instructors_Controller::get_items")
	if !ok {
		t.Fatalf("the grandchild's route is missing: its parent names the base with a different case, which is the same class in PHP; got %+v", eps)
	}
	if clone.Route != "/wp-json/ns/v1/instructors" {
		t.Errorf("Route = %q, want /wp-json/ns/v1/instructors", clone.Route)
	}
	if clone.File != "leaf.php" {
		t.Errorf("File = %q, want leaf.php", clone.File)
	}
}

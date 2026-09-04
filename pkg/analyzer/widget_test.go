package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

func epByRoute(t *testing.T, eps []models.Endpoint, route string) models.Endpoint {
	t.Helper()
	for _, ep := range eps {
		if ep.Route == route {
			return ep
		}
	}
	t.Fatalf("no endpoint with route %q; got %v", route, slashRoutes(eps))
	return models.Endpoint{}
}

// No detector may emit a callback a call graph cannot look up. A parenthesis is
// the marker of a call expression, and every graph entry point refuses a
// callback containing one; a slash fuses two method names into a string that is
// neither.
func assertUsableCallbacks(t *testing.T, eps []models.Endpoint) {
	t.Helper()
	for _, ep := range eps {
		if strings.ContainsAny(ep.Callback, "()/") {
			t.Errorf("endpoint %q has an unusable callback %q", ep.Route, ep.Callback)
		}
	}
}

// dynamic_sidebar() calls WP_Widget::widget() on a front-end page, so any
// visitor reaches it. Naming a method for an index is `Class::method`; the
// trailing "()" made it a call expression, which every call-graph entry point
// refuses, so the endpoint reached nothing in any plugin.
func TestWidgetRenderCallbackIsASymbol(t *testing.T) {
	php := `<?php
class My_W extends WP_Widget {
	public function __construct() {
		parent::__construct( 'my_w', 'My Widget' );
	}
	public function widget( $args, $instance ) {
		echo $this->sink( $instance );
	}
	public function form( $instance ) {
		echo '<input>';
	}
	public function update( $new_instance, $old_instance ) {
		return $new_instance;
	}
}
`
	eps := DetectWidgets(php, "inc/widget.php", "p")
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d: %v", len(eps), slashRoutes(eps))
	}

	render := epByRoute(t, eps, "widget:my_w:render")
	if render.Callback != "My_W::widget" {
		t.Errorf("render callback = %q, want My_W::widget", render.Callback)
	}
	if render.AuthLevel != models.Unauthenticated {
		t.Errorf("render level = %v, want unauthenticated", render.AuthLevel)
	}
	for _, ep := range eps {
		if ep.Line != 2 {
			t.Errorf("endpoint %q has line %d, want 2", ep.Route, ep.Line)
		}
	}

	// The admin side is untouched by this step, on purpose: the two methods it
	// fuses are Admin-level, and making them resolvable adds reach at a level
	// that can gate. That lands on its own.
	admin := epByRoute(t, eps, "widget:my_w:admin")
	if admin.AuthLevel != models.Admin {
		t.Errorf("admin level = %v, want admin", admin.AuthLevel)
	}
}

// A namespaced file has to write the core class fully qualified.
func TestWidgetFullyQualifiedParent(t *testing.T) {
	php := `<?php
namespace Acme\Widgets;

class Ns_W extends \WP_Widget {
	public function widget( $args, $instance ) { echo 'x'; }
}
`
	eps := DetectWidgets(php, "w.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
	if eps[0].Callback != "Ns_W::widget" {
		t.Errorf("callback = %q", eps[0].Callback)
	}
}

// The method names are what core calls; the parameter list is the plugin's
// business. Insisting on two bare `$var` parameters lost every widget whose
// override takes a default or a type.
func TestWidgetMethodSignatureVariants(t *testing.T) {
	php := `<?php
class Sig_W extends WP_Widget {
	public function widget( $args, $instance = array() ) { echo 'x'; }
	public function form( array $instance ) { echo 'y'; }
	public function update( $new, $old = null ) { return $new; }
}
`
	eps := DetectWidgets(php, "w.php", "p")
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d: %v", len(eps), slashRoutes(eps))
	}
	assertUsableCallbacks(t, []models.Endpoint{epByRoute(t, eps, "widget:sig_w:render")})
}

// register_widget() ends in WP_Widget_Factory::register(), which constructs the
// named class and calls $widget->_register(), so a class handed to it is a
// WP_Widget subclass by the API's own contract however deep its own inheritance
// goes. About 23 corpus plugins register widgets whose class extends an
// intermediate base of the plugin's own.
func TestWidgetDiscoveredThroughRegisterWidget(t *testing.T) {
	for name, php := range map[string]string{
		"string": `<?php
class Acme_Base extends WP_Widget {}
class Acme_Child extends Acme_Base {
	public function widget( $args, $instance ) { echo 'x'; }
}
register_widget( 'Acme_Child' );
`,
		"class-const": `<?php
class Acme_Base extends WP_Widget {}
class Acme_Child extends Acme_Base {
	public function widget( $args, $instance ) { echo 'x'; }
}
register_widget( Acme_Child::class );
`,
		"new": `<?php
class Acme_Base extends WP_Widget {}
class Acme_Child extends Acme_Base {
	public function widget( $args, $instance ) { echo 'x'; }
}
register_widget( new Acme_Child() );
`,
	} {
		t.Run(name, func(t *testing.T) {
			eps := DetectWidgets(php, "w.php", "p")
			if !hasCallback(eps, "Acme_Child::widget") {
				t.Fatalf("Acme_Child not discovered; got %v", callbacksOf(eps))
			}
		})
	}
}

// The bound on that widening. A registration naming a class this file does not
// declare cannot be resolved here -- the class body, and therefore which of the
// three methods exist, is not visible -- and no endpoint may be invented for it.
// Resolving those needs the AST class hierarchy, which this per-file detector is
// not given.
func TestWidgetRegistrationOfAnUnseenClassEmitsNothing(t *testing.T) {
	php := `<?php
register_widget( 'Somewhere_Else_Widget' );
register_widget( Another_Widget::class );
register_widget( new Third_Widget() );
`
	if eps := DetectWidgets(php, "w.php", "p"); len(eps) != 0 {
		t.Fatalf("want no endpoint, got %v", slashRoutes(eps))
	}
}

// The other bound: an ordinary class is not a widget just because it declares a
// method called widget().
func TestWidgetPlainClassIsNotAWidget(t *testing.T) {
	php := `<?php
class Not_A_Widget extends Some_Base {
	public function widget( $args, $instance ) { echo 'x'; }
	public function form( $instance ) { echo 'y'; }
}
`
	if eps := DetectWidgets(php, "w.php", "p"); len(eps) != 0 {
		t.Fatalf("want no endpoint, got %v", slashRoutes(eps))
	}
}

func callbacksOf(eps []models.Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, ep := range eps {
		out = append(out, ep.Callback)
	}
	return out
}

func hasCallback(eps []models.Endpoint, cb string) bool {
	for _, ep := range eps {
		if ep.Callback == cb {
			return true
		}
	}
	return false
}

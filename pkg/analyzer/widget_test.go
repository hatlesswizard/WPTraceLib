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

// WordPress core invokes exactly three methods on a registered widget, each from
// a different request: widget() from dynamic_sidebar() on a front-end page, and
// form()/update() from WP_Widget::form_callback()/update_callback() behind
// edit_theme_options. Each is its own endpoint, named as a symbol.
func TestWidgetEmitsThreeResolvableEndpoints(t *testing.T) {
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
	if len(eps) != 3 {
		t.Fatalf("want 3 endpoints, got %d: %v", len(eps), slashRoutes(eps))
	}
	assertUsableCallbacks(t, eps)

	render := epByRoute(t, eps, "widget:my_w:render")
	if render.Callback != "My_W::widget" || render.AuthLevel != models.Unauthenticated {
		t.Errorf("render = %q / %v", render.Callback, render.AuthLevel)
	}
	form := epByRoute(t, eps, "widget:my_w:form")
	if form.Callback != "My_W::form" || form.AuthLevel != models.Admin {
		t.Errorf("form = %q / %v", form.Callback, form.AuthLevel)
	}
	update := epByRoute(t, eps, "widget:my_w:update")
	if update.Callback != "My_W::update" || update.AuthLevel != models.Admin {
		t.Errorf("update = %q / %v", update.Callback, update.AuthLevel)
	}
	for _, ep := range eps {
		if ep.Line != 2 {
			t.Errorf("endpoint %q has line %d, want 2", ep.Route, ep.Line)
		}
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
	if len(eps) != 3 {
		t.Fatalf("want 3 endpoints, got %d: %v", len(eps), slashRoutes(eps))
	}
	assertUsableCallbacks(t, eps)
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

// A class that overrides only one of the three methods gets only that endpoint.
func TestWidgetPartialOverrides(t *testing.T) {
	php := `<?php
class Only_Update extends WP_Widget {
	public function update( $new, $old ) { return $new; }
}
`
	eps := DetectWidgets(php, "w.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
	if eps[0].Route != "widget:only_update:update" || eps[0].Callback != "Only_Update::update" {
		t.Errorf("endpoint = %q / %q", eps[0].Route, eps[0].Callback)
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

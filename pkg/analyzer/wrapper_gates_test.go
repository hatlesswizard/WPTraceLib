package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// findEndpointByRoute returns the first endpoint whose route ends with suffix.
// rest_lane_test.go has a findEndpoint that matches on CALLBACK and returns a
// pointer; the two grew in parallel worktrees and are different predicates.
func findEndpointByRoute(eps []models.Endpoint, routeSuffix string) (models.Endpoint, bool) {
	for _, ep := range eps {
		if strings.HasSuffix(ep.Route, routeSuffix) {
			return ep, true
		}
	}
	return models.Endpoint{}, false
}

// TestRESTWrapperClosureShapeStillResolves pins the one REST-wrapper shape the
// library already gets right, so that widening the surrounding gates cannot
// take it away.
//
// The shape -- a method taking (endpoint, methods, callback) whose body defers
// to rest_api_init through a closure that use()s all three, and hands the
// callback straight to register_rest_route -- is what mints the only endpoint
// behind one of the corpus's exact answers (kirki 6.0.5,
// ComponentLibrary/controller/CompLibFormHandler.php:27, cited as evidence).
// Two things about it are load-bearing and are asserted here rather than
// assumed: the call site is matched through $this->, and CallbackParamIndex
// stays on the parameter that really carries the callback, because the endpoint
// is tied to the vulnerable function by callback name plus file.
func TestRESTWrapperClosureShapeStillResolves(t *testing.T) {
	src := `<?php
class Form_Handler extends WP_REST_Controller {

	protected $namespace = 'acme/v1';

	public function __construct() {
		$this->init_rest_api_endpoint( 'forgot-password', WP_REST_Server::CREATABLE, array( $this, 'handle_forgot_password' ) );
	}

	public function init_rest_api_endpoint( $endpoint, $methods, $callback ) {
		add_action(
			'rest_api_init',
			function () use ( $endpoint, $methods, $callback ) {
				register_rest_route(
					$this->namespace,
					'/' . $endpoint,
					array(
						array(
							'methods'             => $methods,
							'callback'            => $callback,
							'permission_callback' => array( $this, 'get_item_permissions_check' ),
						),
					)
				);
			}
		);
	}

	public function get_item_permissions_check( $request ) {
		return true;
	}

	public function handle_forgot_password( $request ) {
		return array( 'ok' => true );
	}
}
`
	wrappers := DiscoverRESTWrappers(src, "handler.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 REST wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	w := wrappers[0]
	if w.CallbackParamIndex != 2 {
		t.Errorf("CallbackParamIndex = %d, want 2 (the parameter that carries the callback)", w.CallbackParamIndex)
	}
	if w.RouteParamIndex != 0 {
		t.Errorf("RouteParamIndex = %d, want 0", w.RouteParamIndex)
	}
	if !w.UsesThisNamespace {
		t.Error("UsesThisNamespace = false, want true")
	}

	registry := &WrapperRegistry{RESTWrappers: wrappers}
	eps := DetectRESTWrapperCalls(src, "handler.php", "acme", registry)
	ep, ok := findEndpointByRoute(eps, "/forgot-password")
	if !ok {
		t.Fatalf("no endpoint for the wrapper call site; got %+v", eps)
	}
	if ep.Callback != "handle_forgot_password" {
		t.Errorf("Callback = %q, want handle_forgot_password", ep.Callback)
	}
	if ep.Route != "/wp-json/acme/v1/forgot-password" {
		t.Errorf("Route = %q, want /wp-json/acme/v1/forgot-password", ep.Route)
	}
	if ep.File != "handler.php" {
		t.Errorf("File = %q, want the call site's file", ep.File)
	}
	if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("AuthLevel = %s, want unauthenticated (the permission callback returns true)", ep.AuthLevel)
	}
}

// TestLowercaseClassIsAClass pins (a): PHP class names have no case rule.
//
// The discovery pattern required an uppercase initial, which is a convention of
// some projects and not a rule of the language. 1,300-odd classes in a third of
// a 143-plugin corpus begin with a lowercase letter or an underscore, and every
// method of every one of them was invisible to wrapper discovery.
func TestLowercaseClassIsAClass(t *testing.T) {
	src := `<?php
class acme_registry {
	public static function hook( $tag, $cb ) {
		add_action( 'wp_ajax_' . $tag, $cb );
	}
}
`
	wrappers := DiscoverWrappers(src, "reg.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	w := wrappers[0]
	if w.ClassName != "acme_registry" || w.MethodName != "hook" {
		t.Errorf("got %s::%s, want acme_registry::hook", w.ClassName, w.MethodName)
	}
	if w.HookParamIndex != 0 || w.HookPrefix != "wp_ajax_" {
		t.Errorf("hookParamIndex=%d prefix=%q, want 0 / wp_ajax_", w.HookParamIndex, w.HookPrefix)
	}
	if !w.IsStatic {
		t.Error("IsStatic = false, want true")
	}
}

// TestFullyQualifiedParentDoesNotHideTheClass pins the other half of (a).
//
// `class Field_Base extends \Vendor\Base {` is an ordinary PHP spelling: the
// leading separator says the parent is a root-namespace name. The old pattern's
// parent clause could not start with a separator, so the whole declaration
// failed to match and every method inside was recorded as a top-level FUNCTION.
// That is not a harmless mislabel -- a wrapper believed to be a function is
// matched at call sites by its bare name, so a method named add_action was
// matched against WordPress core's own add_action() calls throughout the
// plugin, inventing an endpoint at each one.
func TestFullyQualifiedParentDoesNotHideTheClass(t *testing.T) {
	src := `<?php
class Field_Base extends \Vendor\Base {
	public function add_action( $tag, $cb ) {
		add_action( $tag, $cb );
	}
}
`
	wrappers := DiscoverWrappers(src, "base.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	if wrappers[0].ClassName != "Field_Base" {
		t.Errorf("ClassName = %q, want Field_Base -- a method recorded as a standalone function is hunted under the wrong spelling",
			wrappers[0].ClassName)
	}
}

// TestFunctionAfterAClassIsNotAMethod pins (b): a class's extent is its
// matching brace, not the start of the next declaration.
//
// Ending a class at the next class or at EOF put every top-level function
// declared after the last class in its file -- 1,270 of them across 316 files
// in the corpus -- inside that class.
func TestFunctionAfterAClassIsNotAMethod(t *testing.T) {
	src := `<?php
class Holder {
	public function unrelated() {
		return 1;
	}
}

function acme_hook( $tag, $cb ) {
	add_action( 'wp_ajax_' . $tag, $cb );
}
`
	wrappers := DiscoverWrappers(src, "mixed.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	if wrappers[0].ClassName != "" || wrappers[0].MethodName != "acme_hook" {
		t.Errorf("got %q::%q, want a standalone acme_hook", wrappers[0].ClassName, wrappers[0].MethodName)
	}
}

// TestMethodInsideAClassStaysAMethod is the negative case that pins the bound
// of the previous test: widening the class extent must not turn a method into a
// top-level function, or its bare name would be matched against every unrelated
// call to a function of the same name.
func TestMethodInsideAClassStaysAMethod(t *testing.T) {
	src := `<?php
class First {
	public function noop() {
		return 1;
	}
}

class Second {
	public function hook( $tag, $cb ) {
		add_action( 'wp_ajax_' . $tag, $cb );
	}
}
`
	wrappers := DiscoverWrappers(src, "two.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	if wrappers[0].ClassName != "Second" {
		t.Errorf("ClassName = %q, want Second", wrappers[0].ClassName)
	}
}

// TestApostropheInACommentDoesNotTruncateAClass pins the brace scanner.
//
// The scanner tracked string literals but not comments, so the apostrophe in an
// English contraction opened a string that ran to the next quote character
// anywhere in the file. Every brace in between vanished from the count, and the
// class extent ended early -- which silently moved the methods after it out of
// the class.
func TestApostropheInACommentDoesNotTruncateAClass(t *testing.T) {
	src := `<?php
class Registry {
	// We don't register anything here.
	public function noop() {
		return 1;
	}

	public function hook( $tag, $cb ) {
		add_action( 'wp_ajax_' . $tag, $cb );
	}
}
`
	wrappers := DiscoverWrappers(src, "reg.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	if wrappers[0].ClassName != "Registry" {
		t.Errorf("ClassName = %q, want Registry", wrappers[0].ClassName)
	}
}

// TestAbstractDeclarationDoesNotAdoptTheNextBody pins declBodyOpen.
//
// An abstract or interface method ends in ';'. Scanning forward for the next
// '{' handed it the body of a later declaration, so a class could be credited
// with registering hooks that a different method registers -- and, in the
// direction that matters here, an abstract stub could be recorded as a wrapper.
func TestAbstractDeclarationDoesNotAdoptTheNextBody(t *testing.T) {
	src := `<?php
abstract class Base {
	abstract public function stub( $tag, $cb );

	public function hook( $tag, $cb ) {
		add_action( 'wp_ajax_' . $tag, $cb );
	}
}
`
	wrappers := DiscoverWrappers(src, "abs.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	if wrappers[0].MethodName != "hook" {
		t.Errorf("MethodName = %q, want hook -- the abstract stub adopted a body it does not have", wrappers[0].MethodName)
	}
}

// TestRESTWrapperTakingTheDescriptor pins (d).
//
// A method that forwards a parameter of its own into register_rest_route is a
// route factory whichever argument it forwards. The old gate asked only about
// the route, so a wrapper taking the descriptor -- the array holding methods,
// callback and permission_callback -- was dropped, and with it every route
// registered through it: not mislevelled, absent.
func TestRESTWrapperTakingTheDescriptor(t *testing.T) {
	src := `<?php
class Api {
	protected $namespace = 'myplug/v1';

	public function boot() {
		$this->add_route( 'settings', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'save_settings' ),
			'permission_callback' => '__return_true',
		) );
	}

	public function add_route( $route, $args ) {
		register_rest_route( $this->namespace, '/' . $route, $args );
	}

	public function save_settings( $request ) {
		return true;
	}
}
`
	wrappers := DiscoverRESTWrappers(src, "api.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 REST wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	if wrappers[0].ArgsParamIndex != 1 {
		t.Errorf("ArgsParamIndex = %d, want 1", wrappers[0].ArgsParamIndex)
	}

	eps := DetectRESTWrapperCalls(src, "api.php", "myplug", &WrapperRegistry{RESTWrappers: wrappers})
	ep, ok := findEndpointByRoute(eps, "/settings")
	if !ok {
		t.Fatalf("no endpoint for the wrapper call site; got %+v", eps)
	}
	if ep.Route != "/wp-json/myplug/v1/settings" {
		t.Errorf("Route = %q, want /wp-json/myplug/v1/settings", ep.Route)
	}
	if ep.Callback != "save_settings" {
		t.Errorf("Callback = %q, want save_settings -- it is written at the call site, not in the wrapper", ep.Callback)
	}
	if ep.Method != "POST" {
		t.Errorf("Method = %q, want POST", ep.Method)
	}
	if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("AuthLevel = %s, want unauthenticated (__return_true)", ep.AuthLevel)
	}
}

// TestRESTWrapperArrayCallbackAtCallSite pins the balanced read of the
// descriptor. `'callback' => [ $endpoint, 'get' ]` is the ordinary spelling of
// a method callback, and a value read only as far as the first comma yields
// "[ $endpoint", from which no name can be recovered.
func TestRESTWrapperArrayCallbackAtCallSite(t *testing.T) {
	src := `<?php
function acme_register_route( $namespace, $route, $args = array() ) {
	return register_rest_route( $namespace, $route, $args );
}

function acme_boot( $endpoint ) {
	acme_register_route( 'acme/v1', '/events', array(
		'methods'  => 'GET',
		'callback' => array( $endpoint, 'get_events' ),
	) );
}
`
	wrappers := DiscoverRESTWrappers(src, "routes.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 REST wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	eps := DetectRESTWrapperCalls(src, "routes.php", "acme", &WrapperRegistry{RESTWrappers: wrappers})
	ep, ok := findEndpointByRoute(eps, "/events")
	if !ok {
		t.Fatalf("no endpoint for the wrapper call site; got %+v", eps)
	}
	if ep.Callback != "get_events" {
		t.Errorf("Callback = %q, want get_events", ep.Callback)
	}
	// No permission_callback in the descriptor: core serves such a route to
	// anyone, so the route's own gate is none.
	if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("AuthLevel = %s, want unauthenticated", ep.AuthLevel)
	}
}

// TestRESTWrapperNeedsAParameterThatReachesTheRegistration is the negative case
// that pins (d)'s bound.
//
// A method that registers a route entirely from constants is not a factory,
// however many parameters it happens to declare. Accepting it would make every
// register_rest_route in the corpus a wrapper, and then every call to a method
// of that name -- anywhere, on any object -- would mint a route.
func TestRESTWrapperNeedsAParameterThatReachesTheRegistration(t *testing.T) {
	src := `<?php
class Controller {
	public function setup( $unused ) {
		register_rest_route( 'myapi/v1', '/items', array(
			'methods'  => 'GET',
			'callback' => array( $this, 'get_items' ),
		) );
	}
}
`
	if wrappers := DiscoverRESTWrappers(src, "c.php"); len(wrappers) != 0 {
		t.Fatalf("expected 0 REST wrappers, got %d: %+v", len(wrappers), wrappers)
	}
}

// TestUnresolvablePermissionCallbackIsNotAGate pins (e).
//
// A permission callback the analyzer could not read is not evidence of a
// privilege requirement, it is an admission that the code was not read.
// Answering Subscriber invented a gate, and an invented gate is what makes a
// reachable bug look unreachable.
func TestUnresolvablePermissionCallbackIsNotAGate(t *testing.T) {
	src := `<?php
class Api {
	protected $namespace = 'myplug/v1';

	public function boot() {
		$this->add_route( 'thing', array( $this, 'handle' ) );
	}

	public function add_route( $route, $cb ) {
		register_rest_route( $this->namespace, '/' . $route, array(
			'methods'             => 'POST',
			'callback'            => $cb,
			'permission_callback' => array( $this, 'check_elsewhere' ),
		) );
	}

	public function handle( $request ) {
		return true;
	}
}
`
	wrappers := DiscoverRESTWrappers(src, "api.php")
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 REST wrapper, got %d: %+v", len(wrappers), wrappers)
	}
	eps := DetectRESTWrapperCalls(src, "api.php", "myplug", &WrapperRegistry{RESTWrappers: wrappers})
	ep, ok := findEndpointByRoute(eps, "/thing")
	if !ok {
		t.Fatalf("no endpoint; got %+v", eps)
	}
	if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("AuthLevel = %s, want unauthenticated: check_elsewhere is declared in another file and was never read", ep.AuthLevel)
	}
}

// TestResolvablePermissionCallbackStillGates is the negative case for (e):
// lowering the default must not lower a gate the analyzer CAN read.
//
// The callback deliberately does not end in `return true`. inferRESTWrapperAuthLevel
// short-circuits to Unauthenticated whenever that phrase appears anywhere in the
// body, so a gate written as `if ( ! current_user_can( ... ) ) { return false; }
// return true;` reads as public today. That is an under-restriction and so not
// this change's business, but the test would be measuring the shortcut rather
// than the default if it used that shape.
func TestResolvablePermissionCallbackStillGates(t *testing.T) {
	src := `<?php
class Api {
	protected $namespace = 'myplug/v1';

	public function boot() {
		$this->add_route( 'thing', array( $this, 'handle' ) );
	}

	public function add_route( $route, $cb ) {
		register_rest_route( $this->namespace, '/' . $route, array(
			'methods'             => 'POST',
			'callback'            => $cb,
			'permission_callback' => array( $this, 'check' ),
		) );
	}

	public function check( $request ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'rest_forbidden', 'Sorry.', array( 'status' => 401 ) );
		}
		return current_user_can( 'manage_options' );
	}

	public function handle( $request ) {
		return true;
	}
}
`
	wrappers := DiscoverRESTWrappers(src, "api.php")
	eps := DetectRESTWrapperCalls(src, "api.php", "myplug", &WrapperRegistry{RESTWrappers: wrappers})
	ep, ok := findEndpointByRoute(eps, "/thing")
	if !ok {
		t.Fatalf("no endpoint; got %+v", eps)
	}
	if ep.AuthLevel != models.Admin {
		t.Errorf("AuthLevel = %s, want admin: the permission callback is right here and requires manage_options", ep.AuthLevel)
	}
}

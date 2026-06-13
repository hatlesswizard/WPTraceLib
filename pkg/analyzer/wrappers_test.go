package analyzer

import (
	"strings"
	"testing"

	. "github.com/hatlesswizard/wptracelib/pkg/models"
)

func TestDiscoverWrappers_StaticMethod(t *testing.T) {
	content := `<?php
namespace Give\Helpers;

class Hooks {
    public static function addAction($tag, $class, $method = '__invoke', $priority = 10, $acceptedArgs = 1) {
        if (!method_exists($class, $method)) {
            throw new InvalidArgumentException("The method $method does not exist on $class");
        }

        add_action(
            $tag,
            static function () use ($tag, $class, $method) {
                $instance = give($class);
                call_user_func_array([$instance, $method], func_get_args());
            },
            $priority,
            $acceptedArgs
        );
    }
}
`
	wrappers := DiscoverWrappers(content, "test.php")

	if len(wrappers) != 1 {
		t.Fatalf("Expected 1 wrapper, got %d", len(wrappers))
	}

	w := wrappers[0]
	if w.ClassName != "Hooks" {
		t.Errorf("Expected ClassName 'Hooks', got '%s'", w.ClassName)
	}
	if w.MethodName != "addAction" {
		t.Errorf("Expected MethodName 'addAction', got '%s'", w.MethodName)
	}
	if !w.IsStatic {
		t.Error("Expected IsStatic to be true")
	}
	if w.HookParamIndex != 0 {
		t.Errorf("Expected HookParamIndex 0, got %d", w.HookParamIndex)
	}
}

func TestDiscoverWrappers_InstanceMethod(t *testing.T) {
	content := `<?php
class HooksProxy {
    public function add_action($hookName, $callback, $priority = 10) {
        add_action(
            $hookName,
            $callback,
            $priority
        );
    }
}
`
	wrappers := DiscoverWrappers(content, "test.php")

	if len(wrappers) != 1 {
		t.Fatalf("Expected 1 wrapper, got %d", len(wrappers))
	}

	w := wrappers[0]
	if w.ClassName != "HooksProxy" {
		t.Errorf("Expected ClassName 'HooksProxy', got '%s'", w.ClassName)
	}
	if w.MethodName != "add_action" {
		t.Errorf("Expected MethodName 'add_action', got '%s'", w.MethodName)
	}
	if w.IsStatic {
		t.Error("Expected IsStatic to be false")
	}
	if w.HookParamIndex != 0 {
		t.Errorf("Expected HookParamIndex 0, got %d", w.HookParamIndex)
	}
}

func TestDiscoverWrappers_StandaloneFunction(t *testing.T) {
	content := `<?php
function my_add_hook($tag, $callback) {
    add_action($tag, $callback);
}
`
	wrappers := DiscoverWrappers(content, "test.php")

	if len(wrappers) != 1 {
		t.Fatalf("Expected 1 wrapper, got %d", len(wrappers))
	}

	w := wrappers[0]
	if w.ClassName != "" {
		t.Errorf("Expected empty ClassName, got '%s'", w.ClassName)
	}
	if w.MethodName != "my_add_hook" {
		t.Errorf("Expected MethodName 'my_add_hook', got '%s'", w.MethodName)
	}
	if w.HookParamIndex != 0 {
		t.Errorf("Expected HookParamIndex 0, got %d", w.HookParamIndex)
	}
}

func TestDiscoverWrappers_SecondParamAsHook(t *testing.T) {
	content := `<?php
class Hook_Registry {
    public static function register($type, $tag, $callback) {
        if ($type === 'action') {
            add_action($tag, $callback);
        }
    }
}
`
	wrappers := DiscoverWrappers(content, "test.php")

	if len(wrappers) != 1 {
		t.Fatalf("Expected 1 wrapper, got %d", len(wrappers))
	}

	w := wrappers[0]
	if w.HookParamIndex != 1 {
		t.Errorf("Expected HookParamIndex 1 (second param), got %d", w.HookParamIndex)
	}
}

func TestDiscoverWrappers_IgnoresUnmappedParam(t *testing.T) {
	// This wrapper uses a hardcoded hook name, not a parameter
	// Should NOT be detected as a wrapper
	content := `<?php
class MyClass {
    public function init() {
        add_action('init', [$this, 'onInit']);
    }
}
`
	wrappers := DiscoverWrappers(content, "test.php")

	if len(wrappers) != 0 {
		t.Fatalf("Expected 0 wrappers (hardcoded hook), got %d", len(wrappers))
	}
}

func TestDetectWrapperCalls(t *testing.T) {
	// Setup: Create a wrapper registry
	registry := &WrapperRegistry{
		Wrappers: []WrapperDefinition{
			{
				ClassName:      "Hooks",
				MethodName:     "addAction",
				IsStatic:       true,
				HookParamIndex: 0,
			},
		},
	}

	// Content with calls to the wrapper
	content := `<?php
Hooks::addAction('wp_ajax_my_action', MyController::class, 'handleRequest');
Hooks::addAction('wp_ajax_nopriv_public_action', PublicController::class);
`

	endpoints := DetectWrapperCalls(content, "test.php", "test-plugin", registry)

	if len(endpoints) != 2 {
		t.Fatalf("Expected 2 endpoints, got %d", len(endpoints))
	}

	// Check first endpoint (authenticated)
	ep1 := endpoints[0]
	if ep1.Route != "wp-admin/admin-ajax.php?action=my_action" {
		t.Errorf("Expected route 'wp-admin/admin-ajax.php?action=my_action', got '%s'", ep1.Route)
	}
	if ep1.AuthLevel.String() != "subscriber" {
		t.Errorf("Expected auth level 'subscriber', got '%s'", ep1.AuthLevel.String())
	}

	// Check second endpoint (unauthenticated)
	ep2 := endpoints[1]
	if ep2.Route != "wp-admin/admin-ajax.php?action=public_action" {
		t.Errorf("Expected route 'wp-admin/admin-ajax.php?action=public_action', got '%s'", ep2.Route)
	}
	if ep2.AuthLevel.String() != "unauthenticated" {
		t.Errorf("Expected auth level 'unauthenticated', got '%s'", ep2.AuthLevel.String())
	}
}

func TestExtractHookName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"'wp_ajax_test'", "wp_ajax_test"},
		{`"wp_ajax_test"`, "wp_ajax_test"},
		{"'wp_ajax_' . $action", "wp_ajax_{action}"},
		{"'wp_ajax_' . self::ACTION", "wp_ajax_{ACTION}"},
		{"'wp_ajax_' . $this->action", "wp_ajax_{action}"},
		{"$hookName", "wp_ajax_{hookName}"},
	}

	for _, tt := range tests {
		result := extractHookName(tt.input)
		if result != tt.expected {
			t.Errorf("extractHookName(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestFindParameterIndex(t *testing.T) {
	tests := []struct {
		params   string
		varName  string
		expected int
	}{
		{"$tag, $class, $method", "tag", 0},
		{"$tag, $class, $method", "class", 1},
		{"$tag, $class, $method", "method", 2},
		{"$tag, $class, $method = '__invoke'", "method", 2},
		{"string $hookName, callable $callback", "hookName", 0},
		{"$type, $tag, $callback", "tag", 1},
		{"$foo", "bar", -1},
	}

	for _, tt := range tests {
		result := findParameterIndex(tt.params, tt.varName)
		if result != tt.expected {
			t.Errorf("findParameterIndex(%q, %q) = %d, expected %d", tt.params, tt.varName, result, tt.expected)
		}
	}
}

func TestSplitParameters(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"$a, $b, $c", 3},
		{"$tag, $class, $method = '__invoke'", 3},
		{"$callback = function() { return true; }, $priority = 10", 2},
		{"$arr = ['a', 'b'], $x", 2},
	}

	for _, tt := range tests {
		result := splitParameters(tt.input)
		if len(result) != tt.expected {
			t.Errorf("splitParameters(%q) returned %d params, expected %d", tt.input, len(result), tt.expected)
		}
	}
}

// --- REST Wrapper Tests ---

func TestDiscoverRESTWrappers_ClosurePattern(t *testing.T) {
	content := `<?php
namespace KirkiComponentLib\Controller;

class CompLibFormHandler extends WP_REST_Controller {

	protected $namespace = 'kirki-comp/v1';

	public function __construct() {
		$this->init_rest_api_endpoint( 'kirki-login', WP_REST_Server::CREATABLE, array( $this, 'handle_login' ) );
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
}
`
	wrappers := DiscoverRESTWrappers(content, "test.php")

	if len(wrappers) != 1 {
		t.Fatalf("Expected 1 REST wrapper, got %d", len(wrappers))
	}

	w := wrappers[0]
	if w.ClassName != "CompLibFormHandler" {
		t.Errorf("Expected ClassName 'CompLibFormHandler', got '%s'", w.ClassName)
	}
	if w.MethodName != "init_rest_api_endpoint" {
		t.Errorf("Expected MethodName 'init_rest_api_endpoint', got '%s'", w.MethodName)
	}
	if w.RouteParamIndex != 0 {
		t.Errorf("Expected RouteParamIndex 0, got %d", w.RouteParamIndex)
	}
	if w.MethodsParamIndex != 1 {
		t.Errorf("Expected MethodsParamIndex 1, got %d", w.MethodsParamIndex)
	}
	if w.CallbackParamIndex != 2 {
		t.Errorf("Expected CallbackParamIndex 2, got %d", w.CallbackParamIndex)
	}
	if !w.UsesThisNamespace {
		t.Error("Expected UsesThisNamespace to be true")
	}
}

func TestDiscoverRESTWrappers_DirectPattern(t *testing.T) {
	content := `<?php
class MyController extends WP_REST_Controller {
	protected $namespace = 'myapi/v1';

	public function add_route( $route, $callback, $methods ) {
		register_rest_route(
			$this->namespace,
			$route,
			array(
				'methods'  => $methods,
				'callback' => $callback,
				'permission_callback' => '__return_true',
			)
		);
	}
}
`
	wrappers := DiscoverRESTWrappers(content, "test.php")

	if len(wrappers) != 1 {
		t.Fatalf("Expected 1 REST wrapper, got %d", len(wrappers))
	}

	w := wrappers[0]
	if w.RouteParamIndex != 0 {
		t.Errorf("Expected RouteParamIndex 0, got %d", w.RouteParamIndex)
	}
	if w.CallbackParamIndex != 1 {
		t.Errorf("Expected CallbackParamIndex 1, got %d", w.CallbackParamIndex)
	}
	if w.MethodsParamIndex != 2 {
		t.Errorf("Expected MethodsParamIndex 2, got %d", w.MethodsParamIndex)
	}
	if !w.UsesThisNamespace {
		t.Error("Expected UsesThisNamespace to be true")
	}
}

func TestDiscoverRESTWrappers_IgnoresRegisterRoutes(t *testing.T) {
	content := `<?php
class MyController extends WP_REST_Controller {
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/items',
			array( 'methods' => 'GET', 'callback' => array( $this, 'get_items' ) )
		);
	}
}
`
	wrappers := DiscoverRESTWrappers(content, "test.php")

	if len(wrappers) != 0 {
		t.Fatalf("Expected 0 REST wrappers (register_routes should be skipped), got %d", len(wrappers))
	}
}

func TestDiscoverRESTWrappers_NoParamMapping(t *testing.T) {
	content := `<?php
class MyController {
	public function setup() {
		register_rest_route(
			'myapi/v1',
			'/items',
			array( 'methods' => 'GET', 'callback' => array( $this, 'get_items' ) )
		);
	}
}
`
	wrappers := DiscoverRESTWrappers(content, "test.php")

	if len(wrappers) != 0 {
		t.Fatalf("Expected 0 REST wrappers (no param mapping), got %d", len(wrappers))
	}
}

func TestDetectRESTWrapperCalls_BasicCallSite(t *testing.T) {
	registry := &WrapperRegistry{
		RESTWrappers: []RESTWrapperDefinition{
			{
				ClassName:          "CompLibFormHandler",
				MethodName:         "init_rest_api_endpoint",
				IsStatic:           false,
				ParamNames:         []string{"endpoint", "methods", "callback"},
				RouteParamIndex:    0,
				MethodsParamIndex:  1,
				CallbackParamIndex: 2,
				UsesThisNamespace:  true,
				PermCallbackBody:   "array( $this, 'get_item_permissions_check' )",
			},
		},
	}

	content := `<?php
class CompLibFormHandler extends WP_REST_Controller {
	protected $namespace = 'kirki-comp/v1';

	public function __construct() {
		$this->init_rest_api_endpoint( 'kirki-login', WP_REST_Server::CREATABLE, array( $this, 'handle_login' ) );
	}

	public function get_item_permissions_check( $request ) {
		return true;
	}
}
`
	endpoints := DetectRESTWrapperCalls(content, "CompLibFormHandler.php", "kirki", registry)

	if len(endpoints) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	if !strings.Contains(ep.Route, "kirki-login") {
		t.Errorf("Expected route to contain 'kirki-login', got '%s'", ep.Route)
	}
	if ep.Method != "POST" {
		t.Errorf("Expected method POST, got '%s'", ep.Method)
	}
	if ep.Callback != "handle_login" {
		t.Errorf("Expected callback 'handle_login', got '%s'", ep.Callback)
	}
	if ep.AuthLevel != Unauthenticated {
		t.Errorf("Expected auth level Unauthenticated, got %s", ep.AuthLevel)
	}
	if ep.Type != EndpointTypeREST {
		t.Errorf("Expected type REST, got %s", ep.Type)
	}
}

func TestDetectRESTWrapperCalls_MultipleCallSites(t *testing.T) {
	registry := &WrapperRegistry{
		RESTWrappers: []RESTWrapperDefinition{
			{
				ClassName:          "CompLibFormHandler",
				MethodName:         "init_rest_api_endpoint",
				IsStatic:           false,
				ParamNames:         []string{"endpoint", "methods", "callback"},
				RouteParamIndex:    0,
				MethodsParamIndex:  1,
				CallbackParamIndex: 2,
				UsesThisNamespace:  true,
				PermCallbackBody:   "array( $this, 'get_item_permissions_check' )",
			},
		},
	}

	content := `<?php
class CompLibFormHandler extends WP_REST_Controller {
	protected $namespace = 'kirki-comp/v1';

	public function __construct() {
		$this->init_rest_api_endpoint( 'kirki-login', WP_REST_Server::CREATABLE, array( $this, 'handle_login' ) );
		$this->init_rest_api_endpoint( 'kirki-register', WP_REST_Server::CREATABLE, array( $this, 'handle_register' ) );
		$this->init_rest_api_endpoint( 'kirki-forgot-password', WP_REST_Server::CREATABLE, array( $this, 'handle_forgot_password' ) );
	}

	public function get_item_permissions_check( $request ) {
		return true;
	}
}
`
	endpoints := DetectRESTWrapperCalls(content, "CompLibFormHandler.php", "kirki", registry)

	if len(endpoints) != 3 {
		t.Fatalf("Expected 3 endpoints, got %d", len(endpoints))
	}

	expectedRoutes := []string{"kirki-login", "kirki-register", "kirki-forgot-password"}
	for i, ep := range endpoints {
		if !strings.Contains(ep.Route, expectedRoutes[i]) {
			t.Errorf("Endpoint %d: expected route containing '%s', got '%s'", i, expectedRoutes[i], ep.Route)
		}
	}
}

func TestDetectRESTWrapperCalls_NamespaceResolution(t *testing.T) {
	registry := &WrapperRegistry{
		RESTWrappers: []RESTWrapperDefinition{
			{
				ClassName:         "MyAPI",
				MethodName:        "add_endpoint",
				IsStatic:          false,
				ParamNames:        []string{"route"},
				RouteParamIndex:   0,
				MethodsParamIndex: -1,
				CallbackParamIndex: -1,
				UsesThisNamespace: true,
			},
		},
	}

	content := `<?php
class MyAPI extends WP_REST_Controller {
	protected $namespace = 'custom-api/v2';

	public function __construct() {
		$this->add_endpoint( '/users' );
	}
}
`
	endpoints := DetectRESTWrapperCalls(content, "myapi.php", "myplugin", registry)

	if len(endpoints) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(endpoints))
	}

	if !strings.Contains(endpoints[0].Route, "custom-api/v2") {
		t.Errorf("Expected namespace 'custom-api/v2' in route, got '%s'", endpoints[0].Route)
	}
}

func TestDetectRESTWrapperCalls_CrossFile(t *testing.T) {
	registry := &WrapperRegistry{
		RESTWrappers: []RESTWrapperDefinition{
			{
				ClassName:          "RouteManager",
				MethodName:         "register_endpoint",
				IsStatic:           false,
				SourceFile:         "route-manager.php",
				ParamNames:         []string{"path", "method_type", "handler"},
				RouteParamIndex:    0,
				MethodsParamIndex:  1,
				CallbackParamIndex: 2,
				UsesThisNamespace:  true,
				PermCallbackBody:   "__return_true",
			},
		},
	}

	// Different file from where the wrapper is defined
	content := `<?php
class MyPlugin {
	protected $namespace = 'myplugin/v1';

	public function init() {
		$router = new RouteManager();
		$router->register_endpoint( '/settings', WP_REST_Server::READABLE, array( $this, 'get_settings' ) );
	}
}
`
	endpoints := DetectRESTWrapperCalls(content, "my-plugin.php", "myplugin", registry)

	if len(endpoints) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(endpoints))
	}

	if !strings.Contains(endpoints[0].Route, "settings") {
		t.Errorf("Expected route containing 'settings', got '%s'", endpoints[0].Route)
	}
	if endpoints[0].AuthLevel != Unauthenticated {
		t.Errorf("Expected Unauthenticated (from __return_true), got %s", endpoints[0].AuthLevel)
	}
}

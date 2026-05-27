package analyzer

import (
	"testing"
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

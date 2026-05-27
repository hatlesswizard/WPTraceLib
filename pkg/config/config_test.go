package config

import (
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

func TestNew(t *testing.T) {
	cfg := New()
	if cfg == nil {
		t.Fatal("New() returned nil")
	}
	if cfg.Capabilities == nil {
		t.Error("Capabilities is nil")
	}
	if cfg.Profiles == nil {
		t.Error("Profiles is nil")
	}
	if cfg.Framework == nil {
		t.Error("Framework is nil")
	}
	if cfg.AJAX == nil {
		t.Error("AJAX is nil")
	}
	if cfg.REST == nil {
		t.Error("REST is nil")
	}
	if cfg.AdminPatterns == nil {
		t.Error("AdminPatterns is nil")
	}
}

func TestNewMinimal(t *testing.T) {
	cfg := NewMinimal()
	if cfg == nil {
		t.Fatal("NewMinimal() returned nil")
	}
	// Minimal config should have empty profiles
	if len(cfg.Profiles) != 0 {
		t.Errorf("Expected 0 profiles in minimal config, got %d", len(cfg.Profiles))
	}
}

func TestDefaultConfigIsGeneric(t *testing.T) {
	cfg := New()

	// Default config should have no profiles
	if len(cfg.Profiles) != 0 {
		t.Errorf("Expected 0 profiles in default config, got %d", len(cfg.Profiles))
	}

	// Custom admin prefixes should be empty
	if len(cfg.AJAX.CustomAdminPrefixes) != 0 {
		t.Errorf("Expected 0 custom admin prefixes, got %d", len(cfg.AJAX.CustomAdminPrefixes))
	}

	// Admin namespaces should be empty (no hardcoded namespaces)
	if len(cfg.REST.AdminNamespaces) != 0 {
		t.Errorf("Expected 0 admin namespaces, got %d", len(cfg.REST.AdminNamespaces))
	}

	// Constant namespace mappings should be empty
	if len(cfg.REST.ConstantNamespaceMappings) != 0 {
		t.Errorf("Expected 0 constant namespace mappings, got %d", len(cfg.REST.ConstantNamespaceMappings))
	}

	// Custom admin patterns should be empty
	if len(cfg.AdminPatterns.CustomPatterns) != 0 {
		t.Errorf("Expected 0 custom admin patterns, got %d", len(cfg.AdminPatterns.CustomPatterns))
	}
}

func TestGetCapabilityLevel(t *testing.T) {
	cfg := New()

	// Test core admin capability
	level, ok := cfg.GetCapabilityLevel("manage_options")
	if !ok {
		t.Error("manage_options should be found")
	}
	if level != models.Admin {
		t.Errorf("manage_options should be Admin, got %v", level)
	}

	// Test core user capability
	level, ok = cfg.GetCapabilityLevel("read")
	if !ok {
		t.Error("read should be found")
	}
	if level != models.Subscriber {
		t.Errorf("read should be User, got %v", level)
	}

	// Test unknown capability - should not be found
	_, ok = cfg.GetCapabilityLevel("unknown_capability_xyz")
	if ok {
		t.Error("unknown_capability_xyz should not be found")
	}
}

func TestMinimalCapabilityConfig(t *testing.T) {
	cfg := NewMinimal()

	// Core capabilities should still work
	level, ok := cfg.GetCapabilityLevel("manage_options")
	if !ok {
		t.Error("manage_options should be found in minimal config")
	}
	if level != models.Admin {
		t.Errorf("manage_options should be Admin, got %v", level)
	}
}

func TestIsAdminAJAXPrefix(t *testing.T) {
	cfg := New()

	// By default, no custom prefixes are configured
	if cfg.IsAdminAJAXPrefix("custom_action") {
		t.Error("custom_action should not be admin AJAX prefix with empty config")
	}

	// Add a custom prefix and test again
	cfg.AJAX.CustomAdminPrefixes = []string{"my_admin_"}
	if !cfg.IsAdminAJAXPrefix("my_admin_action") {
		t.Error("my_admin_action should be admin AJAX prefix after adding custom prefix")
	}
}

func TestIsAdminRESTNamespace(t *testing.T) {
	cfg := New()

	// By default, no admin namespaces are configured
	if cfg.IsAdminRESTNamespace("my-api/v1") {
		t.Error("my-api/v1 should not be admin REST namespace with empty config")
	}

	// Add a custom namespace and test again
	cfg.REST.AdminNamespaces = []string{"admin-api"}
	if !cfg.IsAdminRESTNamespace("admin-api/v1") {
		t.Error("admin-api/v1 should be admin REST namespace after adding custom namespace")
	}
}

func TestMerge(t *testing.T) {
	cfg := New()
	other := &Config{
		Capabilities: &CapabilityConfig{
			Custom: map[string]string{
				"my_custom_cap": "admin",
			},
		},
	}

	cfg.Merge(other)

	// Check that custom capability was merged
	level, ok := cfg.GetCapabilityLevel("my_custom_cap")
	if !ok {
		t.Error("my_custom_cap should be found after merge")
	}
	if level != models.Admin {
		t.Errorf("my_custom_cap should be Admin, got %v", level)
	}
}

func TestAddProfile(t *testing.T) {
	cfg := New()

	// Add a custom profile
	cfg.AddProfile("my-custom-profile", &DetectionProfile{
		Enabled: true,
		Name:    "My Custom Profile",
		AJAXPrefixes: []string{
			"my_profile_",
		},
		AdminRESTNamespaces: []string{
			"my-profile/v1",
		},
	})

	// Check that profile was added
	profile, ok := cfg.Profiles["my-custom-profile"]
	if !ok {
		t.Error("my-custom-profile should exist")
	}
	if profile.Name != "My Custom Profile" {
		t.Errorf("Expected 'My Custom Profile', got '%s'", profile.Name)
	}

	// Check that AJAX prefixes were updated
	if !cfg.IsAdminAJAXPrefix("my_profile_action") {
		t.Error("my_profile_action should be admin AJAX prefix after adding profile")
	}

	// Check that REST namespaces were updated
	if !cfg.IsAdminRESTNamespace("my-profile/v1") {
		t.Error("my-profile/v1 should be admin REST namespace after adding profile")
	}
}

func TestCustomCapabilityOverride(t *testing.T) {
	cfg := New()

	// Add a custom capability mapping
	cfg.Capabilities.Custom = map[string]string{
		"my_special_cap": "admin",
	}

	// Check that custom capability is found
	level, ok := cfg.GetCapabilityLevel("my_special_cap")
	if !ok {
		t.Error("my_special_cap should be found")
	}
	if level != models.Admin {
		t.Errorf("my_special_cap should be Admin, got %v", level)
	}
}

func TestGenericFrameworkDetectionEnabled(t *testing.T) {
	cfg := New()

	// Generic framework detection should be enabled
	if !cfg.Framework.EnableGenericRouters {
		t.Error("EnableGenericRouters should be true by default")
	}
	if !cfg.Framework.EnableLaravelStyle {
		t.Error("EnableLaravelStyle should be true by default (generic Route::get() patterns)")
	}
}

func TestEnableDisableProfile(t *testing.T) {
	cfg := New()

	// Add a disabled profile
	cfg.AddProfile("test-profile", &DetectionProfile{
		Enabled: false,
		Name:    "Test Profile",
	})

	// Check it's disabled
	if cfg.Profiles["test-profile"].Enabled {
		t.Error("Profile should be disabled initially")
	}

	// Enable it
	cfg.EnableProfile("test-profile")
	if !cfg.Profiles["test-profile"].Enabled {
		t.Error("Profile should be enabled after EnableProfile()")
	}

	// Disable it
	cfg.DisableProfile("test-profile")
	if cfg.Profiles["test-profile"].Enabled {
		t.Error("Profile should be disabled after DisableProfile()")
	}
}

// Package config provides external configuration for WPTraceLib analyzer.
// This allows users to customize detection patterns without modifying core code.
package config

import (
	"encoding/json"
	"os"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Config is the main configuration structure for WPTraceLib.
// It contains all configurable aspects of the analyzer.
type Config struct {
	// Capabilities maps WordPress capabilities to authentication levels.
	// This is used to determine the auth level when current_user_can() is detected.
	Capabilities *CapabilityConfig `json:"capabilities,omitempty"`

	// Profiles contains user-defined detection profiles for custom patterns.
	// Users can add profiles for any codebase they want to analyze with custom rules.
	Profiles map[string]*DetectionProfile `json:"profiles,omitempty"`

	// Framework contains settings for framework detection.
	Framework *FrameworkConfig `json:"framework,omitempty"`

	// AJAX contains AJAX-specific detection settings.
	AJAX *AJAXConfig `json:"ajax,omitempty"`

	// REST contains REST API detection settings.
	REST *RESTConfig `json:"rest,omitempty"`

	// AdminPatterns contains custom admin detection patterns.
	AdminPatterns *AdminPatternsConfig `json:"admin_patterns,omitempty"`

	// VendorDirs contains settings for skipping vendor/third-party directories.
	VendorDirs *VendorDirConfig `json:"vendor_dirs,omitempty"`
}

// CapabilityConfig holds capability-to-auth-level mappings.
// Capabilities are mapped to the 6-level WordPress role hierarchy:
// SuperAdmin > Admin > Editor > Author > Contributor > Subscriber
type CapabilityConfig struct {
	// CoreSuperAdmin contains WordPress core super-admin-level capabilities (multisite).
	// These are always loaded and cannot be disabled.
	CoreSuperAdmin []string `json:"core_superadmin,omitempty"`

	// CoreAdmin contains WordPress core admin-level capabilities.
	// These are always loaded and cannot be disabled.
	CoreAdmin []string `json:"core_admin,omitempty"`

	// CoreEditor contains WordPress core editor-level capabilities.
	// These are always loaded and cannot be disabled.
	CoreEditor []string `json:"core_editor,omitempty"`

	// CoreAuthor contains WordPress core author-level capabilities.
	// These are always loaded and cannot be disabled.
	CoreAuthor []string `json:"core_author,omitempty"`

	// CoreContributor contains WordPress core contributor-level capabilities.
	// These are always loaded and cannot be disabled.
	CoreContributor []string `json:"core_contributor,omitempty"`

	// CoreSubscriber contains WordPress core subscriber-level capabilities.
	// These are always loaded and cannot be disabled.
	CoreSubscriber []string `json:"core_subscriber,omitempty"`

	// ExtendedCapabilities maps additional capabilities to auth levels.
	// Key is capability name, value is auth level string ("superadmin", "admin", "editor", "author", "contributor", "subscriber", "unauthenticated").
	ExtendedCapabilities map[string]string `json:"extended_capabilities,omitempty"`

	// Custom allows users to add their own capability mappings.
	// These take precedence over all other capability mappings.
	Custom map[string]string `json:"custom,omitempty"`
}

// DetectionProfile contains user-defined detection settings.
// Users can create profiles to customize endpoint detection for any codebase.
type DetectionProfile struct {
	// Enabled determines if this profile is active.
	Enabled bool `json:"enabled"`

	// Name is a human-readable name for this profile.
	Name string `json:"name,omitempty"`

	// Capabilities maps custom capability names to auth levels.
	Capabilities map[string]string `json:"capabilities,omitempty"`

	// AJAXPrefixes are action prefixes that indicate admin-level AJAX actions.
	AJAXPrefixes []string `json:"ajax_prefixes,omitempty"`

	// RESTNamespaces are REST API namespaces associated with this profile.
	RESTNamespaces []string `json:"rest_namespaces,omitempty"`

	// AdminRESTNamespaces are REST namespaces that require admin access.
	// These override the default auth detection.
	AdminRESTNamespaces []string `json:"admin_rest_namespaces,omitempty"`

	// CustomAdminPatterns are regex patterns that indicate admin-level access.
	CustomAdminPatterns []string `json:"custom_admin_patterns,omitempty"`
}

// FrameworkConfig contains settings for detecting framework-specific endpoints.
// All patterns here are generic and not tied to any specific plugin.
type FrameworkConfig struct {
	// EnableLaravelStyle enables Laravel-style Route::get() pattern detection.
	EnableLaravelStyle bool `json:"enable_laravel_style"`

	// EnableGenericRouters enables generic $router->method() pattern detection.
	EnableGenericRouters bool `json:"enable_generic_routers"`

	// EnableDataDrivenRoutes enables detection of routes defined in data arrays.
	EnableDataDrivenRoutes bool `json:"enable_data_driven_routes"`

	// CustomPatterns allows users to define their own framework detection patterns.
	CustomPatterns []CustomFramework `json:"custom_patterns,omitempty"`
}

// CustomFramework defines a custom framework detection pattern.
type CustomFramework struct {
	// Name is the identifier for this framework.
	Name string `json:"name"`

	// Pattern is the regex pattern to match framework routes.
	Pattern string `json:"pattern"`

	// RouteGroup is the capture group index for the route (1-based).
	RouteGroup int `json:"route_group"`

	// MethodGroup is the capture group index for HTTP method (1-based, 0 if not captured).
	MethodGroup int `json:"method_group,omitempty"`

	// CallbackGroup is the capture group index for callback (1-based, 0 if not captured).
	CallbackGroup int `json:"callback_group,omitempty"`

	// DefaultAuthLevel is the default auth level for this framework.
	DefaultAuthLevel string `json:"default_auth_level"`
}

// AJAXConfig contains AJAX-specific detection settings.
type AJAXConfig struct {
	// AdminIndicatorPrefixes are AJAX action prefixes that indicate admin access.
	AdminIndicatorPrefixes []string `json:"admin_indicator_prefixes,omitempty"`

	// AdminIndicatorKeywords are keywords in action names that indicate admin access.
	AdminIndicatorKeywords []string `json:"admin_indicator_keywords,omitempty"`

	// CustomAdminPrefixes are user-defined prefixes indicating admin AJAX.
	CustomAdminPrefixes []string `json:"custom_admin_prefixes,omitempty"`

	// UserFacingExceptions are patterns that override admin detection.
	UserFacingExceptions []string `json:"user_facing_exceptions,omitempty"`
}

// RESTConfig contains REST API detection settings.
type RESTConfig struct {
	// AdminNamespaces are namespace patterns that indicate admin access.
	AdminNamespaces []string `json:"admin_namespaces,omitempty"`

	// PublicIndicators are route patterns that indicate public access.
	PublicIndicators []string `json:"public_indicators,omitempty"`

	// UserRoutePatterns are patterns indicating user-level access.
	UserRoutePatterns []string `json:"user_route_patterns,omitempty"`

	// AdminRoutePatterns are patterns indicating admin-level access.
	AdminRoutePatterns []string `json:"admin_route_patterns,omitempty"`

	// ConstantNamespaceMappings maps constant names to resolved namespace values.
	// This helps resolve namespace references from constants or variables.
	ConstantNamespaceMappings map[string]string `json:"constant_namespace_mappings,omitempty"`
}

// AdminPatternsConfig contains patterns for detecting admin-level code.
// All patterns here are user-defined and not tied to any specific plugin.
type AdminPatternsConfig struct {
	// CustomPatterns are user-defined regex patterns for admin detection.
	// When matched, these patterns indicate admin-level access is required.
	CustomPatterns []string `json:"custom_patterns,omitempty"`
}

// VendorDirConfig holds settings for skipping vendor/third-party directories
// during PHP file discovery.
type VendorDirConfig struct {
	// SkipPatterns are directory names to skip (exact match).
	SkipPatterns []string `json:"skip_patterns,omitempty"`

	// SkipComposerDirs skips directories that contain their own composer.json
	// (indicating an embedded vendor package), except for the plugin root directory.
	SkipComposerDirs bool `json:"skip_composer_dirs"`
}

// DefaultVendorDirConfig returns the default vendor directory exclusion config.
func DefaultVendorDirConfig() *VendorDirConfig {
	return &VendorDirConfig{
		SkipPatterns: []string{
			"vendor", "node_modules", ".git",
			"freemius", "action-scheduler", "redux-core", "redux-framework",
			"cmb2", "starter-content", "starter-templates",
		},
		SkipComposerDirs: true,
	}
}

// New creates a new Config with default settings.
// The default configuration provides backwards-compatible behavior.
func New() *Config {
	return &Config{
		Capabilities:  DefaultCapabilityConfig(),
		Profiles:      DefaultProfiles(),
		Framework:     DefaultFrameworkConfig(),
		AJAX:          DefaultAJAXConfig(),
		REST:          DefaultRESTConfig(),
		AdminPatterns: DefaultAdminPatternsConfig(),
		VendorDirs:    DefaultVendorDirConfig(),
	}
}

// NewMinimal creates a minimal Config with only WordPress core patterns.
// This uses only generic detection without any custom profiles.
func NewMinimal() *Config {
	return &Config{
		Capabilities:  MinimalCapabilityConfig(),
		Profiles:      make(map[string]*DetectionProfile),
		Framework:     MinimalFrameworkConfig(),
		AJAX:          MinimalAJAXConfig(),
		REST:          MinimalRESTConfig(),
		AdminPatterns: MinimalAdminPatternsConfig(),
		VendorDirs:    DefaultVendorDirConfig(),
	}
}

// LoadFromFile loads configuration from a JSON file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := New() // Start with defaults
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// SaveToFile saves configuration to a JSON file.
func (c *Config) SaveToFile(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Merge merges another config into this one.
// Values from other take precedence over existing values.
func (c *Config) Merge(other *Config) {
	if other == nil {
		return
	}

	if other.Capabilities != nil {
		c.mergeCapabilities(other.Capabilities)
	}

	if other.Profiles != nil {
		if c.Profiles == nil {
			c.Profiles = make(map[string]*DetectionProfile)
		}
		for k, v := range other.Profiles {
			c.Profiles[k] = v
		}
	}

	if other.Framework != nil {
		c.Framework = other.Framework
	}

	if other.AJAX != nil {
		c.mergeAJAX(other.AJAX)
	}

	if other.REST != nil {
		c.mergeREST(other.REST)
	}

	if other.AdminPatterns != nil {
		c.AdminPatterns = other.AdminPatterns
	}

	if other.VendorDirs != nil {
		c.VendorDirs = other.VendorDirs
	}
}

// mergeCapabilities merges capability configs.
func (c *Config) mergeCapabilities(other *CapabilityConfig) {
	if c.Capabilities == nil {
		c.Capabilities = &CapabilityConfig{}
	}

	if other.ExtendedCapabilities != nil {
		if c.Capabilities.ExtendedCapabilities == nil {
			c.Capabilities.ExtendedCapabilities = make(map[string]string)
		}
		for k, v := range other.ExtendedCapabilities {
			c.Capabilities.ExtendedCapabilities[k] = v
		}
	}

	if other.Custom != nil {
		if c.Capabilities.Custom == nil {
			c.Capabilities.Custom = make(map[string]string)
		}
		for k, v := range other.Custom {
			c.Capabilities.Custom[k] = v
		}
	}
}

// mergeAJAX merges AJAX configs.
func (c *Config) mergeAJAX(other *AJAXConfig) {
	if c.AJAX == nil {
		c.AJAX = &AJAXConfig{}
	}

	if other.AdminIndicatorPrefixes != nil {
		c.AJAX.AdminIndicatorPrefixes = append(c.AJAX.AdminIndicatorPrefixes, other.AdminIndicatorPrefixes...)
	}
	if other.AdminIndicatorKeywords != nil {
		c.AJAX.AdminIndicatorKeywords = append(c.AJAX.AdminIndicatorKeywords, other.AdminIndicatorKeywords...)
	}
	if other.CustomAdminPrefixes != nil {
		c.AJAX.CustomAdminPrefixes = append(c.AJAX.CustomAdminPrefixes, other.CustomAdminPrefixes...)
	}
	if other.UserFacingExceptions != nil {
		c.AJAX.UserFacingExceptions = append(c.AJAX.UserFacingExceptions, other.UserFacingExceptions...)
	}
}

// mergeREST merges REST configs.
func (c *Config) mergeREST(other *RESTConfig) {
	if c.REST == nil {
		c.REST = &RESTConfig{}
	}

	if other.AdminNamespaces != nil {
		c.REST.AdminNamespaces = append(c.REST.AdminNamespaces, other.AdminNamespaces...)
	}
	if other.PublicIndicators != nil {
		c.REST.PublicIndicators = append(c.REST.PublicIndicators, other.PublicIndicators...)
	}
	if other.UserRoutePatterns != nil {
		c.REST.UserRoutePatterns = append(c.REST.UserRoutePatterns, other.UserRoutePatterns...)
	}
	if other.AdminRoutePatterns != nil {
		c.REST.AdminRoutePatterns = append(c.REST.AdminRoutePatterns, other.AdminRoutePatterns...)
	}
	if other.ConstantNamespaceMappings != nil {
		if c.REST.ConstantNamespaceMappings == nil {
			c.REST.ConstantNamespaceMappings = make(map[string]string)
		}
		for k, v := range other.ConstantNamespaceMappings {
			c.REST.ConstantNamespaceMappings[k] = v
		}
	}
}

// GetCapabilityLevel returns the auth level for a capability.
// Returns the level and whether the capability was found.
func (c *Config) GetCapabilityLevel(capability string) (models.AuthLevel, bool) {
	if c.Capabilities == nil {
		return models.Unauthenticated, false
	}

	// Check custom first (highest priority)
	if c.Capabilities.Custom != nil {
		if level, ok := c.Capabilities.Custom[capability]; ok {
			return parseAuthLevel(level), true
		}
	}

	// Check extended capabilities
	if c.Capabilities.ExtendedCapabilities != nil {
		if level, ok := c.Capabilities.ExtendedCapabilities[capability]; ok {
			return parseAuthLevel(level), true
		}
	}

	// Check core super admin
	for _, cap := range c.Capabilities.CoreSuperAdmin {
		if cap == capability {
			return models.SuperAdmin, true
		}
	}

	// Check core admin
	for _, cap := range c.Capabilities.CoreAdmin {
		if cap == capability {
			return models.Admin, true
		}
	}

	// Check core editor
	for _, cap := range c.Capabilities.CoreEditor {
		if cap == capability {
			return models.Editor, true
		}
	}

	// Check core author
	for _, cap := range c.Capabilities.CoreAuthor {
		if cap == capability {
			return models.Author, true
		}
	}

	// Check core contributor
	for _, cap := range c.Capabilities.CoreContributor {
		if cap == capability {
			return models.Contributor, true
		}
	}

	// Check core subscriber
	for _, cap := range c.Capabilities.CoreSubscriber {
		if cap == capability {
			return models.Subscriber, true
		}
	}

	return models.Unauthenticated, false
}

// IsAdminAJAXPrefix checks if an action prefix indicates admin AJAX.
func (c *Config) IsAdminAJAXPrefix(action string) bool {
	if c.AJAX == nil {
		return false
	}

	for _, prefix := range c.AJAX.CustomAdminPrefixes {
		if len(action) >= len(prefix) && action[:len(prefix)] == prefix {
			return true
		}
	}

	return false
}

// IsAdminRESTNamespace checks if a namespace indicates admin REST access.
func (c *Config) IsAdminRESTNamespace(namespace string) bool {
	if c.REST == nil {
		return false
	}

	for _, ns := range c.REST.AdminNamespaces {
		if contains(namespace, ns) {
			return true
		}
	}

	return false
}

// parseAuthLevel converts a string to AuthLevel.
func parseAuthLevel(s string) models.AuthLevel {
	switch s {
	case "superadmin":
		return models.SuperAdmin
	case "admin":
		return models.Admin
	case "editor":
		return models.Editor
	case "author":
		return models.Author
	case "contributor":
		return models.Contributor
	case "subscriber":
		return models.Subscriber
	// Backwards compatibility: "user" maps to Subscriber
	case "user":
		return models.Subscriber
	default:
		return models.Unauthenticated
	}
}

// contains checks if s contains substr (case-insensitive).
func contains(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	for i := 0; i <= len(sLower)-len(substrLower); i++ {
		if sLower[i:i+len(substrLower)] == substrLower {
			return true
		}
	}
	return false
}

// toLower converts a string to lowercase.
func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

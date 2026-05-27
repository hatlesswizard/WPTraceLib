package config

// DefaultProfiles returns an empty detection profiles map.
// WPTraceLib is a universal analyzer - it does not include any hardcoded profiles.
// Users can add their own profiles via AddProfile() if needed.
func DefaultProfiles() map[string]*DetectionProfile {
	return make(map[string]*DetectionProfile)
}

// DefaultFrameworkConfig returns the default framework detection configuration.
// All detection patterns are generic and not tied to any specific codebase.
func DefaultFrameworkConfig() *FrameworkConfig {
	return &FrameworkConfig{
		EnableLaravelStyle:     true,  // Generic Laravel-style Route::get() patterns
		EnableGenericRouters:   true,  // Generic $router->method() patterns
		EnableDataDrivenRoutes: false, // Data-driven route arrays (disabled by default)
		CustomPatterns:         []CustomFramework{},
	}
}

// MinimalFrameworkConfig returns a minimal framework configuration.
// This is identical to DefaultFrameworkConfig.
func MinimalFrameworkConfig() *FrameworkConfig {
	return DefaultFrameworkConfig()
}

// DefaultAJAXConfig returns the default AJAX detection configuration.
// Only generic patterns are included - no custom prefixes by default.
func DefaultAJAXConfig() *AJAXConfig {
	return &AJAXConfig{
		AdminIndicatorPrefixes: []string{
			"admin_",
			"manage_",
		},
		AdminIndicatorKeywords: []string{
			"_admin_",
			"_admin",
			"_settings_save",
			"_save_settings",
			"_update_settings",
			"_options_save",
			"_save_options",
			"_reset_settings",
			"_reset_options",
			"_import_settings",
			"_export_settings",
		},
		CustomAdminPrefixes: []string{}, // Empty - users can add custom prefixes
		UserFacingExceptions: []string{
			// Common user-facing action patterns
			"form", "submit", "entry",
			"cart", "checkout", "order", "product", "shop", "store", "payment", "shipping",
			"profile", "account", "comment", "reply", "message", "contact", "post",
			"subscribe", "newsletter",
			"register", "login", "password",
			"bookmark", "favorite", "wishlist", "follow",
			"rating", "vote", "like", "share",
			"search", "filter", "sort", "load_more", "loadmore",
			"quick_view", "quickview", "preview",
			"popup", "modal", "slider",
			"booking", "appointment", "reservation", "calendar", "event",
		},
	}
}

// MinimalAJAXConfig returns a minimal AJAX configuration.
// This is identical to DefaultAJAXConfig.
func MinimalAJAXConfig() *AJAXConfig {
	return DefaultAJAXConfig()
}

// DefaultRESTConfig returns the default REST API detection configuration.
// Only generic route patterns are included - no custom namespaces by default.
func DefaultRESTConfig() *RESTConfig {
	return &RESTConfig{
		AdminNamespaces: []string{}, // Empty - users can add custom admin namespaces
		PublicIndicators: []string{
			"/public/",
			"/embed/",
			"/widget/",
			"/oembed",
		},
		UserRoutePatterns: []string{
			"/user/",
			"/me/",
			"/me",
			"/profile/",
			"/account/",
		},
		AdminRoutePatterns: []string{
			"/admin/",
			"/admin-",
			"-admin/",
			"/settings",
			"/options",
			"/config",
			"/manage",
			"/dashboard",
		},
		ConstantNamespaceMappings: make(map[string]string), // Empty - users can add constant mappings
	}
}

// MinimalRESTConfig returns a minimal REST configuration.
// This is identical to DefaultRESTConfig.
func MinimalRESTConfig() *RESTConfig {
	return DefaultRESTConfig()
}

// DefaultAdminPatternsConfig returns the default admin patterns configuration.
// No custom patterns are included by default.
func DefaultAdminPatternsConfig() *AdminPatternsConfig {
	return &AdminPatternsConfig{
		CustomPatterns: []string{}, // Empty - users can add custom admin detection patterns
	}
}

// MinimalAdminPatternsConfig returns a minimal admin patterns configuration.
// This is identical to DefaultAdminPatternsConfig.
func MinimalAdminPatternsConfig() *AdminPatternsConfig {
	return DefaultAdminPatternsConfig()
}

// EnableProfile enables a detection profile.
func (c *Config) EnableProfile(slug string) {
	if c.Profiles == nil {
		c.Profiles = make(map[string]*DetectionProfile)
	}
	if profile, ok := c.Profiles[slug]; ok {
		profile.Enabled = true
	}
}

// DisableProfile disables a detection profile.
func (c *Config) DisableProfile(slug string) {
	if c.Profiles != nil {
		if profile, ok := c.Profiles[slug]; ok {
			profile.Enabled = false
		}
	}
}

// AddProfile adds a custom detection profile.
// This allows users to add their own detection patterns for any codebase.
func (c *Config) AddProfile(slug string, profile *DetectionProfile) {
	if c.Profiles == nil {
		c.Profiles = make(map[string]*DetectionProfile)
	}
	c.Profiles[slug] = profile

	// Update AJAX and REST configs with profile data
	if profile.Enabled {
		if c.AJAX != nil && len(profile.AJAXPrefixes) > 0 {
			c.AJAX.CustomAdminPrefixes = append(c.AJAX.CustomAdminPrefixes, profile.AJAXPrefixes...)
		}
		if c.REST != nil && len(profile.AdminRESTNamespaces) > 0 {
			c.REST.AdminNamespaces = append(c.REST.AdminNamespaces, profile.AdminRESTNamespaces...)
		}
		if c.AdminPatterns != nil && len(profile.CustomAdminPatterns) > 0 {
			c.AdminPatterns.CustomPatterns = append(c.AdminPatterns.CustomPatterns, profile.CustomAdminPatterns...)
		}
	}
}

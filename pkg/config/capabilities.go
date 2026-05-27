package config

// DefaultCapabilityConfig returns the default capability configuration.
// This includes only WordPress core capabilities mapped to the 6-level auth system:
// SuperAdmin > Admin > Editor > Author > Contributor > Subscriber
func DefaultCapabilityConfig() *CapabilityConfig {
	return &CapabilityConfig{
		CoreSuperAdmin:       wordPressCoreSuperAdminCapabilities(),
		CoreAdmin:            wordPressCoreAdminCapabilities(),
		CoreEditor:           wordPressCoreEditorCapabilities(),
		CoreAuthor:           wordPressCoreAuthorCapabilities(),
		CoreContributor:      wordPressCoreContributorCapabilities(),
		CoreSubscriber:       wordPressCoreSubscriberCapabilities(),
		ExtendedCapabilities: make(map[string]string),
		Custom:               make(map[string]string),
	}
}

// MinimalCapabilityConfig returns a minimal configuration with only WordPress core.
// This is now identical to DefaultCapabilityConfig for a universal analyzer.
func MinimalCapabilityConfig() *CapabilityConfig {
	return DefaultCapabilityConfig()
}

// wordPressCoreSuperAdminCapabilities returns WordPress core super-admin-level capabilities.
// These are capabilities ONLY available to Super Admins in multisite installations.
func wordPressCoreSuperAdminCapabilities() []string {
	return []string{
		// Multisite network administration (Super Admin exclusive)
		"manage_network",
		"manage_sites",
		"manage_network_users",
		"manage_network_plugins",
		"manage_network_themes",
		"manage_network_options",
		"setup_network",
		"upgrade_network",
		"create_sites",
		"delete_sites",
		"upload_plugins",
		"upload_themes",
	}
}

// wordPressCoreAdminCapabilities returns WordPress core admin-level capabilities.
// These are capabilities for site Administrators.
func wordPressCoreAdminCapabilities() []string {
	return []string{
		// Site administration
		"manage_options",
		"activate_plugins",
		"deactivate_plugins",
		"delete_plugins",
		"edit_plugins",
		"install_plugins",
		"update_plugins",
		"edit_themes",
		"install_themes",
		"update_themes",
		"switch_themes",
		"delete_themes",
		"edit_theme_options",
		"unfiltered_html",
		"unfiltered_upload", // Requires ALLOW_UNFILTERED_UPLOADS constant
		"import",
		"export",
		"list_users",
		"edit_users",
		"create_users",
		"delete_users",
		"promote_users",
		"remove_users",
		"update_core",
		"administrator", // Role check

		// Additional admin capabilities
		"customize",
		"edit_dashboard",
		"delete_site",
		"edit_files",
		"add_users", // Deprecated but still used
		"edit_comment",

		// Site health and maintenance
		"view_site_health_checks",
		"install_languages",
		"update_languages",
		"resume_plugins",
		"resume_themes",

		// Privacy capabilities
		"manage_privacy_options",
		"erase_others_personal_data",
		"export_others_personal_data",

		// Meta capabilities (singular forms) - user management requires Admin
		"edit_user",   // Meta cap: editing user profiles
		"delete_user", // Meta cap: deleting users
	}
}

// wordPressCoreEditorCapabilities returns WordPress core editor-level capabilities.
// Editors can manage all content, comments, and categories but NOT site settings.
func wordPressCoreEditorCapabilities() []string {
	return []string{
		// Content management (all posts/pages)
		"edit_others_posts",
		"edit_others_pages",
		"edit_published_posts",
		"edit_published_pages",
		"delete_others_posts",
		"delete_others_pages",
		"delete_published_posts",
		"delete_published_pages",
		"delete_private_posts",
		"delete_private_pages",
		"edit_private_posts",
		"edit_private_pages",
		"read_private_posts",
		"read_private_pages",
		"publish_pages",

		// Moderation and taxonomy
		"moderate_comments",
		"manage_categories",
		"manage_links",
		"edit_categories",
		"delete_categories",
		"assign_categories",

		// Meta capabilities (singular forms) - pages and terms require Editor
		"edit_page",    // Meta cap: page editing requires Editor level
		"delete_page",  // Meta cap: page deletion requires Editor level
		"publish_page", // Meta cap: page publishing requires Editor level
		"edit_term",    // Meta cap: taxonomy term editing
		"delete_term",  // Meta cap: taxonomy term deletion
		"assign_term",  // Meta cap: taxonomy term assignment
	}
}

// wordPressCoreAuthorCapabilities returns WordPress core author-level capabilities.
// Authors can publish and manage their own posts.
func wordPressCoreAuthorCapabilities() []string {
	return []string{
		// Own content publishing
		"publish_posts",
		"upload_files",
		"edit_published_posts",
		"delete_published_posts",

		// Meta capabilities (singular forms)
		"publish_post", // Meta cap: publishing requires Author level
	}
}

// wordPressCoreContributorCapabilities returns WordPress core contributor-level capabilities.
// Contributors can create posts but NOT publish them.
func wordPressCoreContributorCapabilities() []string {
	return []string{
		// Own content creation (no publish)
		"edit_posts",
		"delete_posts",

		// Meta capabilities (singular forms) - resolved to base level for static analysis
		// Without runtime context, we map to the least restrictive interpretation
		"edit_post",   // Meta cap: maps to edit_posts (own) or edit_others_posts (others)
		"delete_post", // Meta cap: maps to delete_posts (own) or delete_others_posts (others)
	}
}

// wordPressCoreSubscriberCapabilities returns WordPress core subscriber-level capabilities.
// Subscribers can only read and manage their own profile.
func wordPressCoreSubscriberCapabilities() []string {
	return []string{
		// Basic capabilities
		"read",
		"exist", // Undocumented but valid
		"level_0",

		// Meta capabilities (singular forms) - reading is subscriber level
		"read_post", // Meta cap: reading posts requires basic login
		"read_page", // Meta cap: reading pages requires basic login
	}
}

// GetAllCapabilityMappings returns all capability mappings as a single map.
// This is useful for backwards compatibility.
func (c *CapabilityConfig) GetAllCapabilityMappings() map[string]string {
	result := make(map[string]string)

	// Add core super admin capabilities
	for _, cap := range c.CoreSuperAdmin {
		result[cap] = "superadmin"
	}

	// Add core admin capabilities
	for _, cap := range c.CoreAdmin {
		result[cap] = "admin"
	}

	// Add core editor capabilities
	for _, cap := range c.CoreEditor {
		result[cap] = "editor"
	}

	// Add core author capabilities
	for _, cap := range c.CoreAuthor {
		result[cap] = "author"
	}

	// Add core contributor capabilities
	for _, cap := range c.CoreContributor {
		result[cap] = "contributor"
	}

	// Add core subscriber capabilities
	for _, cap := range c.CoreSubscriber {
		result[cap] = "subscriber"
	}

	// Add extended capabilities (if any were added)
	for cap, level := range c.ExtendedCapabilities {
		result[cap] = level
	}

	// Add custom capabilities (highest priority)
	for cap, level := range c.Custom {
		result[cap] = level
	}

	// Add __return_true as unauthenticated indicator
	result["__return_true"] = "unauthenticated"

	return result
}

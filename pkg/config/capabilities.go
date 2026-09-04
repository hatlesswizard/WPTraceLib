package config

import (
	"sync"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// The capability table below is a transcription of WordPress core's own role
// setup, populate_roles() in wp-admin/includes/schema.php, which runs on every
// install and is what wp_roles() serves afterwards. Each list names the LOWEST
// core role that holds the capability, because that is the question the analyzer
// asks: "what is the least privilege a caller needs to pass this check?".
//
// Reading a capability's level off populate_roles() is mechanical. add_cap() is
// called on named roles, so the lowest role receiving a capability across
// populate_roles_160() .. populate_roles_300() is its level. A capability granted
// to editor and to author is an AUTHOR capability here, because an author passes
// current_user_can() for it; listing it under editor as well would make the
// weakest caller who can get in look stronger than they are, which is the
// dangerous direction of error.
//
// Capabilities that populate_roles() never assigns -- the meta capabilities such
// as edit_post, and the multisite network capabilities -- sit at the level
// map_meta_cap() resolves them to, and say so individually.

// DefaultCapabilityConfig returns the default capability configuration.
// This includes only WordPress core capabilities mapped to the 7-level auth system:
// SuperAdmin > Admin > Editor > Author > Contributor > Subscriber > Unauthenticated
func DefaultCapabilityConfig() *CapabilityConfig {
	return &CapabilityConfig{
		CoreSuperAdmin:       wordPressCoreSuperAdminCapabilities(),
		CoreAdmin:            wordPressCoreAdminCapabilities(),
		CoreEditor:           wordPressCoreEditorCapabilities(),
		CoreAuthor:           wordPressCoreAuthorCapabilities(),
		CoreContributor:      wordPressCoreContributorCapabilities(),
		CoreSubscriber:       wordPressCoreSubscriberCapabilities(),
		CoreUnauthenticated:  wordPressCoreUnauthenticatedCapabilities(),
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
// populate_roles() assigns none of them; map_meta_cap() gates each behind
// is_super_admin(), which is why they sit above Admin.
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
// Everything here is granted by populate_roles() to the administrator role and to
// no other role, or is a meta capability map_meta_cap() resolves to one of those.
//
// The provenance, so the next person can check it without re-reading core:
// populate_roles_160() grants switch_themes, edit_themes, activate_plugins,
// edit_plugins, edit_users, edit_files, manage_options and import to
// administrator alone; _210 adds delete_users and create_users; _230
// unfiltered_upload; _250 edit_dashboard; _260 update_plugins and delete_plugins;
// _270 install_plugins and update_themes; _280 install_themes; _300 update_core,
// list_users, remove_users, promote_users, edit_theme_options, delete_themes and
// export.
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

		// Role slug, not a capability name in the usual sense. WP_User::add_role()
		// writes $this->caps[$role] = true and WP_User::get_role_caps() merges
		// $this->caps into $allcaps, so the slug is a live key in allcaps and
		// current_user_can('administrator') is true for exactly the administrators.
		"administrator",
	}
}

// wordPressCoreEditorCapabilities returns WordPress core editor-level capabilities.
// Editors can manage all content, comments and categories but NOT site settings.
func wordPressCoreEditorCapabilities() []string {
	return []string{
		// Content management (all posts/pages). populate_roles_160() grants
		// edit_others_posts to the editor role, and populate_roles_210() grants
		// the whole pages / private / others block to administrator and editor
		// only, so Editor is the floor for every entry below.
		"edit_others_posts",
		"edit_others_pages",
		"edit_published_pages",
		"delete_others_posts",
		"delete_others_pages",
		"delete_published_pages",
		"delete_private_posts",
		"delete_private_pages",
		"edit_private_posts",
		"edit_private_pages",
		"read_private_posts",
		"read_private_pages",
		"publish_pages",

		// delete_pages is granted to administrator and editor by
		// populate_roles_210(). It was missing from this table entirely, so it fell
		// through to the "delete_" prefix heuristic and was reported Admin -- an
		// over-restriction on a core capability, in 2 of the 143 measured trees.
		"delete_pages",

		// Moderation and taxonomy
		"moderate_comments",
		"manage_categories",
		"manage_links",
		"edit_categories",
		"delete_categories",
		"assign_categories",

		// unfiltered_html is granted to the editor role by populate_roles_160(),
		// not to administrator alone. map_meta_cap()'s `case 'unfiltered_html'`
		// maps it straight back to itself on a single site -- it only escalates to
		// super admin under is_multisite(), and DISALLOW_UNFILTERED_HTML denies it
		// to everyone -- so Editor is the floor. Reporting Admin made a check that
		// an editor passes look like an administrator gate, in 23 of the 143
		// measured plugin trees.
		"unfiltered_html",

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
		// Own content publishing. populate_roles_160() grants upload_files,
		// edit_published_posts and publish_posts to the author role;
		// populate_roles_210() grants delete_published_posts to it as well.
		//
		// The editor role receives the same four capabilities, and
		// edit_published_posts and delete_published_posts used to be listed under
		// Editor here as well. The sequential lookup scanned Editor before Author
		// and so answered Editor, one level higher than the truth, for the 7 trees
		// that check edit_published_posts. An author is the weakest caller who
		// passes those checks, so Author is where they belong.
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
		// Own content creation (no publish). populate_roles_160() grants
		// edit_posts and populate_roles_210() delete_posts to the contributor role.
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
		// Basic capabilities. populate_roles_160() grants read and level_0 to the
		// subscriber role, which is the lowest role core creates.
		"read",
		"level_0",

		// Meta capabilities (singular forms) - reading is subscriber level
		"read_post", // Meta cap: reading posts requires basic login
		"read_page", // Meta cap: reading pages requires basic login
	}
}

// wordPressCoreUnauthenticatedCapabilities returns capabilities a logged-out
// visitor passes. A check on one of these gates nothing at all.
func wordPressCoreUnauthenticatedCapabilities() []string {
	return []string{
		// WP_User::has_cap() sets `$capabilities['exist'] = true;` unconditionally,
		// under the comment "Everyone is allowed to exist.", before it tests the
		// required caps. current_user_can('exist') is therefore true for the
		// WP_User(0) that wp_get_current_user() hands an anonymous visitor, so it
		// asserts nothing about the caller.
		//
		// It appears in 0 of the 143 measured plugin trees, so this row is a
		// correctness statement rather than a measured win. It is also the only
		// row in the table that can carry a gated function BELOW the Subscriber
		// floor, so it is the one to watch on a future corpus.
		"exist",
	}
}

// capabilityIndex is the single merged capability-to-level table derived from the
// core lists.
type capabilityIndex struct {
	levels map[string]models.AuthLevel
	// shape records the lengths of the lists the index was built from, so a
	// caller that appends to one of them gets a rebuilt index rather than a
	// stale answer.
	shape [7]int
}

// capIndexMu guards CapabilityConfig.index for every CapabilityConfig. The
// critical section is a length comparison, which is cheap next to the whole
// default config pkg/analyzer already allocates on each unconfigured lookup.
var capIndexMu sync.RWMutex

func (c *CapabilityConfig) listShape() [7]int {
	return [7]int{
		len(c.CoreSuperAdmin),
		len(c.CoreAdmin),
		len(c.CoreEditor),
		len(c.CoreAuthor),
		len(c.CoreContributor),
		len(c.CoreSubscriber),
		len(c.CoreUnauthenticated),
	}
}

// coreLevels returns the merged core capability table, building it on first use.
//
// It replaces six sequential slice scans that returned whichever level came
// first in scan order. A capability listed twice therefore resolved to the
// HIGHER of its two levels, which is the dangerous direction:
// edit_published_posts was listed under both Editor and Author and answered
// Editor, while the parallel map in pkg/analyzer, built Editor-then-Author into
// one map, answered Author for the same string. One merged map removes both
// problems at once.
//
// The merge rule is MINIMUM. That is not a policy compromise but what the table
// means: a capability held by two roles is passed by the weaker of them, so the
// weaker role is the privilege a caller actually needs.
func (c *CapabilityConfig) coreLevels() map[string]models.AuthLevel {
	shape := c.listShape()

	capIndexMu.RLock()
	idx := c.index
	capIndexMu.RUnlock()
	if idx != nil && idx.shape == shape {
		return idx.levels
	}

	capIndexMu.Lock()
	defer capIndexMu.Unlock()
	if c.index != nil && c.index.shape == shape {
		return c.index.levels
	}
	c.index = buildCapabilityIndex(c)
	return c.index.levels
}

// buildCapabilityIndex merges the core lists into one map, lowest level winning.
func buildCapabilityIndex(c *CapabilityConfig) *capabilityIndex {
	levels := make(map[string]models.AuthLevel, 128)

	assign := func(caps []string, level models.AuthLevel) {
		for _, capability := range caps {
			if prev, seen := levels[capability]; seen && prev <= level {
				continue
			}
			levels[capability] = level
		}
	}

	// Order is irrelevant because assign keeps the minimum, but the lists are
	// walked low-to-high so the common case never writes an entry twice.
	assign(c.CoreUnauthenticated, models.Unauthenticated)
	assign(c.CoreSubscriber, models.Subscriber)
	assign(c.CoreContributor, models.Contributor)
	assign(c.CoreAuthor, models.Author)
	assign(c.CoreEditor, models.Editor)
	assign(c.CoreAdmin, models.Admin)
	assign(c.CoreSuperAdmin, models.SuperAdmin)

	return &capabilityIndex{levels: levels, shape: c.listShape()}
}

// ConflictingCapabilities returns every capability that appears in more than one
// core list, together with the levels it was assigned.
//
// This is hygiene for tests and tooling and is deliberately NOT enforced at
// runtime. A CapabilityConfig can come from a user's JSON file and this library
// is embedded in a long-running server, so aborting an analysis over a duplicated
// list entry would make every function in every plugin unreachable at once --
// the worst outcome available when the first objective is never to miss.
// coreLevels resolves a duplicate toward the lower level instead, which is the
// safe direction; this function is how a test notices one exists.
func (c *CapabilityConfig) ConflictingCapabilities() map[string][]models.AuthLevel {
	seen := make(map[string][]models.AuthLevel)

	record := func(caps []string, level models.AuthLevel) {
		for _, capability := range caps {
			seen[capability] = append(seen[capability], level)
		}
	}

	record(c.CoreUnauthenticated, models.Unauthenticated)
	record(c.CoreSubscriber, models.Subscriber)
	record(c.CoreContributor, models.Contributor)
	record(c.CoreAuthor, models.Author)
	record(c.CoreEditor, models.Editor)
	record(c.CoreAdmin, models.Admin)
	record(c.CoreSuperAdmin, models.SuperAdmin)

	conflicts := make(map[string][]models.AuthLevel)
	for capability, levels := range seen {
		if len(levels) > 1 {
			conflicts[capability] = levels
		}
	}
	return conflicts
}

// GetAllCapabilityMappings returns all capability mappings as a single map.
// This is useful for backwards compatibility.
func (c *CapabilityConfig) GetAllCapabilityMappings() map[string]string {
	result := make(map[string]string)

	// Core capabilities, resolved by the same lowest-level-wins rule
	// GetCapabilityLevel uses, so the two can no longer disagree.
	for capability, level := range c.coreLevels() {
		result[capability] = level.String()
	}

	// Add extended capabilities (if any were added)
	for capability, level := range c.ExtendedCapabilities {
		result[capability] = level
	}

	// Add custom capabilities (highest priority)
	for capability, level := range c.Custom {
		result[capability] = level
	}

	// Add __return_true as unauthenticated indicator
	result["__return_true"] = "unauthenticated"

	return result
}

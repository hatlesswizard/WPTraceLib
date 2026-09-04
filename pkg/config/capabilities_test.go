package config

import (
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// TestCoreCapabilityLevelsMatchPopulateRoles pins the table to WordPress core's
// own role setup. Every expectation below is the lowest role that receives the
// capability across populate_roles_160() .. populate_roles_300() in
// wp-admin/includes/schema.php, read from core rather than from a summary.
//
// The cases marked "was X" are the four capabilities the table used to report
// one or more levels too high, which is the direction that makes a reachable
// vulnerability look gated.
func TestCoreCapabilityLevelsMatchPopulateRoles(t *testing.T) {
	cfg := New()

	cases := []struct {
		capability string
		want       models.AuthLevel
		why        string
	}{
		// Subscriber: populate_roles_160() grants these to the subscriber role.
		{"read", models.Subscriber, "subscriber role, _160"},
		{"level_0", models.Subscriber, "subscriber role, _160"},

		// Contributor: _160 grants edit_posts, _210 delete_posts.
		{"edit_posts", models.Contributor, "contributor role, _160"},
		{"delete_posts", models.Contributor, "contributor role, _210"},

		// Author: _160 grants upload_files, edit_published_posts and
		// publish_posts; _210 grants delete_published_posts.
		{"publish_posts", models.Author, "author role, _160"},
		{"upload_files", models.Author, "author role, _160"},
		{"edit_published_posts", models.Author, "author role, _160 (was Editor)"},
		{"delete_published_posts", models.Author, "author role, _210 (was Editor)"},

		// Editor: _160 grants moderate_comments, manage_categories, manage_links,
		// unfiltered_html and edit_others_posts; _210 grants the pages / private /
		// others block.
		{"edit_others_posts", models.Editor, "editor role, _160"},
		{"moderate_comments", models.Editor, "editor role, _160"},
		{"manage_categories", models.Editor, "editor role, _160"},
		{"manage_links", models.Editor, "editor role, _160"},
		{"unfiltered_html", models.Editor, "editor role, _160 (was Admin)"},
		{"publish_pages", models.Editor, "editor role, _210"},
		{"delete_pages", models.Editor, "editor role, _210 (was Admin, via the delete_ prefix)"},
		{"edit_others_pages", models.Editor, "editor role, _210"},
		{"delete_others_posts", models.Editor, "editor role, _210"},
		{"read_private_posts", models.Editor, "editor role, _210"},
		{"edit_private_pages", models.Editor, "editor role, _210"},

		// Admin: granted to administrator by populate_roles and to nobody else.
		// These are the bound on the four downward moves -- an administrator-only
		// capability must not follow unfiltered_html or delete_pages down.
		{"manage_options", models.Admin, "administrator only, _160"},
		{"edit_users", models.Admin, "administrator only, _160"},
		{"edit_files", models.Admin, "administrator only, _160"},
		{"import", models.Admin, "administrator only, _160"},
		{"delete_users", models.Admin, "administrator only, _210"},
		{"create_users", models.Admin, "administrator only, _210"},
		{"unfiltered_upload", models.Admin, "administrator only, _230"},
		{"edit_dashboard", models.Admin, "administrator only, _250"},
		{"delete_plugins", models.Admin, "administrator only, _260"},
		{"install_plugins", models.Admin, "administrator only, _270"},
		{"install_themes", models.Admin, "administrator only, _280"},
		{"update_core", models.Admin, "administrator only, _300"},
		{"edit_theme_options", models.Admin, "administrator only, _300"},
		{"delete_themes", models.Admin, "administrator only, _300"},
		{"export", models.Admin, "administrator only, _300"},

		// SuperAdmin: never assigned by populate_roles; map_meta_cap gates each
		// behind is_super_admin().
		{"manage_network", models.SuperAdmin, "is_super_admin gate"},
		{"manage_sites", models.SuperAdmin, "is_super_admin gate"},
	}

	for _, tc := range cases {
		got, ok := cfg.GetCapabilityLevel(tc.capability)
		if !ok {
			t.Errorf("%s: not found in the table (%s)", tc.capability, tc.why)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %s, want %s (%s)", tc.capability, got, tc.want, tc.why)
		}
	}
}

// TestExistIsUnauthenticated pins the one capability that resolves below the
// Subscriber floor, and pins the bound alongside it.
func TestExistIsUnauthenticated(t *testing.T) {
	cfg := New()

	// WP_User::has_cap() sets $capabilities['exist'] = true unconditionally --
	// "Everyone is allowed to exist." -- before testing the required caps, so the
	// WP_User(0) handed to an anonymous visitor passes current_user_can('exist').
	level, ok := cfg.GetCapabilityLevel("exist")
	if !ok {
		t.Fatal("exist should be found in the table")
	}
	if level != models.Unauthenticated {
		t.Errorf("exist: got %s, want unauthenticated", level)
	}

	// The bound: 'read' is the capability populate_roles_160() grants to the
	// subscriber role, and it must NOT follow 'exist' below the floor.
	level, ok = cfg.GetCapabilityLevel("read")
	if !ok {
		t.Fatal("read should be found in the table")
	}
	if level != models.Subscriber {
		t.Errorf("read: got %s, want subscriber", level)
	}
}

// TestNoDuplicateCoreCapabilities is the hygiene check that replaces the runtime
// panic an earlier design proposed. A duplicate is no longer fatal -- coreLevels
// resolves it toward the lower level -- but the shipped table should not have one.
func TestNoDuplicateCoreCapabilities(t *testing.T) {
	conflicts := DefaultCapabilityConfig().ConflictingCapabilities()
	for capability, levels := range conflicts {
		t.Errorf("%q is assigned more than one core level: %v", capability, levels)
	}
}

// TestDuplicateCapabilityResolvesToLowerLevel is the negative test that pins the
// merge rule. A user-supplied config that lists one capability twice must resolve
// to the LOWER level and must not abort the analysis: this library is embedded in
// a long-running server, and aborting would make every function in every plugin
// unreachable at once.
func TestDuplicateCapabilityResolvesToLowerLevel(t *testing.T) {
	cfg := &Config{
		Capabilities: &CapabilityConfig{
			CoreAdmin:      []string{"duplicated_cap"},
			CoreSubscriber: []string{"duplicated_cap"},
		},
	}

	level, ok := cfg.GetCapabilityLevel("duplicated_cap")
	if !ok {
		t.Fatal("duplicated_cap should be found")
	}
	if level != models.Subscriber {
		t.Errorf("duplicated_cap: got %s, want subscriber (the lower of the two)", level)
	}

	conflicts := cfg.Capabilities.ConflictingCapabilities()
	if len(conflicts["duplicated_cap"]) != 2 {
		t.Errorf("ConflictingCapabilities should report the duplicate, got %v", conflicts)
	}
}

// TestCapabilityIndexRebuildsAfterListChange pins the staleness guard. The merged
// map is cached, so a caller that appends to a core list after a lookup has
// already happened must still get the new entry.
func TestCapabilityIndexRebuildsAfterListChange(t *testing.T) {
	cfg := New()

	if _, ok := cfg.GetCapabilityLevel("read"); !ok {
		t.Fatal("read should be found, priming the index")
	}

	cfg.Capabilities.CoreContributor = append(cfg.Capabilities.CoreContributor, "appended_cap")

	level, ok := cfg.GetCapabilityLevel("appended_cap")
	if !ok {
		t.Fatal("appended_cap should be found after being appended to a core list")
	}
	if level != models.Contributor {
		t.Errorf("appended_cap: got %s, want contributor", level)
	}
}

// TestGetAllCapabilityMappingsAgreesWithGetCapabilityLevel pins the two lookup
// paths together. They used to disagree by construction: GetCapabilityLevel
// scanned the lists Editor-first while GetAllCapabilityMappings wrote them
// Subscriber-last into one map, so one string had two answers.
func TestGetAllCapabilityMappingsAgreesWithGetCapabilityLevel(t *testing.T) {
	cfg := New()
	mappings := cfg.Capabilities.GetAllCapabilityMappings()

	for capability, levelName := range mappings {
		if capability == "__return_true" {
			continue // Not a capability; a permission_callback marker.
		}
		got, ok := cfg.GetCapabilityLevel(capability)
		if !ok {
			t.Errorf("%s is in GetAllCapabilityMappings but not in GetCapabilityLevel", capability)
			continue
		}
		if got.String() != levelName {
			t.Errorf("%s: GetCapabilityLevel says %s, GetAllCapabilityMappings says %s", capability, got, levelName)
		}
	}
}

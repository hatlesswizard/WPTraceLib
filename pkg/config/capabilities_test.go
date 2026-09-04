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

// TestExistStaysAtSubscriber pins a decision that measurement forced, against
// the reading of core that would otherwise apply.
//
// WP_User::has_cap() sets $capabilities['exist'] = true unconditionally, so an
// anonymous visitor passes current_user_can('exist') and the capability gates
// nothing. Moving it to CoreUnauthenticated on that reading was measured and it
// made things worse: the only occurrence of 'exist' in the 143 trees is a menu
// capability -- buddypress 14.3.3 registers an admin submenu page with it -- and
// the admin-page path in pkg/analyzer defaults a capability it cannot find to
// Admin, taking that endpoint from an exactly correct subscriber to admin.
//
// Subscriber is also the better single answer for as long as one number serves
// both uses: wp-admin/admin.php calls auth_redirect() before any page renders,
// so Subscriber is exact for a menu capability that gates nothing.
func TestExistStaysAtSubscriber(t *testing.T) {
	cfg := New()

	level, ok := cfg.GetCapabilityLevel("exist")
	if !ok {
		t.Fatal("exist should be found in the table")
	}
	if level != models.Subscriber {
		t.Errorf("exist: got %s, want subscriber; see the note in capabilities.go", level)
	}

	// The bound on the mechanism that was built for it: CoreUnauthenticated is
	// wired through the merged index, so a caller that does populate it gets
	// Unauthenticated with ok=true rather than a miss.
	custom := &Config{
		Capabilities: &CapabilityConfig{
			CoreUnauthenticated: []string{"gates_nothing"},
			CoreSubscriber:      []string{"read"},
		},
	}
	level, ok = custom.GetCapabilityLevel("gates_nothing")
	if !ok {
		t.Fatal("a CoreUnauthenticated capability should be found, not missed")
	}
	if level != models.Unauthenticated {
		t.Errorf("gates_nothing: got %s, want unauthenticated", level)
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

// TestEditPagesIsEditor pins the capability that defines the Editor level.
// populate_roles_160() grants edit_pages to administrator and editor and to no
// lower role. It was absent from the table entirely, so it missed the exact
// lookup, matched no prefix heuristic and came back at the Subscriber floor --
// which is why the analyzer could barely produce Editor at all.
func TestEditPagesIsEditor(t *testing.T) {
	cfg := New()

	level, ok := cfg.GetCapabilityLevel("edit_pages")
	if !ok {
		t.Fatal("edit_pages should be found in the table")
	}
	if level != models.Editor {
		t.Errorf("edit_pages: got %s, want editor", level)
	}

	// The bound. edit_pages raises a level, so the neighbouring names that core
	// assigns lower must not be dragged up with it: populate_roles_160() gives
	// edit_posts to the contributor role and _210 gives edit_published_posts to
	// the author role.
	for capability, want := range map[string]models.AuthLevel{
		"edit_posts":           models.Contributor,
		"edit_published_posts": models.Author,
		"edit_page":            models.Editor,
	} {
		got, ok := cfg.GetCapabilityLevel(capability)
		if !ok {
			t.Errorf("%s should be found", capability)
			continue
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", capability, got, want)
		}
	}
}

// TestNumericUserLevels pins the legacy level_N ladder to populate_roles_160(),
// which gives administrator level_10..level_0, editor level_7..level_0, author
// level_2..level_0, contributor level_1..level_0 and subscriber level_0. The
// lowest role holding level_N is what fixes its level.
func TestNumericUserLevels(t *testing.T) {
	cfg := New()

	want := map[string]models.AuthLevel{
		// The bound: level_0 is the subscriber role's own level and must not rise.
		"level_0":  models.Subscriber,
		"level_1":  models.Contributor,
		"level_2":  models.Author,
		"level_3":  models.Editor,
		"level_4":  models.Editor,
		"level_5":  models.Editor,
		"level_6":  models.Editor,
		"level_7":  models.Editor,
		"level_8":  models.Admin,
		"level_9":  models.Admin,
		"level_10": models.Admin,
	}

	for capability, expected := range want {
		got, ok := cfg.GetCapabilityLevel(capability)
		if !ok {
			t.Errorf("%s should be found in the table", capability)
			continue
		}
		if got != expected {
			t.Errorf("%s: got %s, want %s", capability, got, expected)
		}
	}

	// level_11 does not exist in core, so it must not be invented.
	if _, ok := cfg.GetCapabilityLevel("level_11"); ok {
		t.Error("level_11 is not a WordPress capability and should not be in the table")
	}
}

// TestRoleSlugsAreCapabilityKeys pins the five core role names.
//
// A role slug is a capability key, not a special case: WP_User::add_role()
// writes $this->caps[ $role ] = true, WP_User::get_role_caps() merges
// $this->caps into $allcaps wholesale, and map_meta_cap() has no case for a
// role name, so its default branch does $caps[] = $cap and has_cap() looks up
// $capabilities['editor'] directly. current_user_can('editor') is true for
// exactly the users holding that role.
//
// Only 'administrator' was recognised before, so current_user_can('editor')
// fell through to the Subscriber default -- one reason Editor, Author and
// Contributor were almost never produced. populate_roles_160() creates exactly
// these five roles, so the list is core's, not a harvest from any corpus.
func TestRoleSlugsAreCapabilityKeys(t *testing.T) {
	cfg := New()

	want := map[string]models.AuthLevel{
		"administrator": models.Admin,
		"editor":        models.Editor,
		"author":        models.Author,
		"contributor":   models.Contributor,
		"subscriber":    models.Subscriber,
	}

	for slug, expected := range want {
		got, ok := cfg.GetCapabilityLevel(slug)
		if !ok {
			t.Errorf("%s should be found in the table", slug)
			continue
		}
		if got != expected {
			t.Errorf("%s: got %s, want %s", slug, got, expected)
		}
	}

	// The bound. Only the five slugs core creates are role names; a string that
	// merely contains one is not, and must not resolve to a privilege. The
	// corpus has register_post_type( ..., 'supports' => array('editor',
	// 'author') ) and $post->post_author sitting next to real role tests, so a
	// rule that matched on containment rather than equality would read a post
	// type's editor support as an editor gate.
	for _, notARole := range []string{
		"editor_role", "post_author", "authors", "subscribers",
		"contributors", "super_admin", "shop_manager",
	} {
		if level, ok := cfg.GetCapabilityLevel(notARole); ok {
			t.Errorf("%q is not a WordPress role and should not resolve; got %s", notARole, level)
		}
	}
}

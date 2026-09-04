package ast

import (
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/config"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// TestAuthGuardTakesWeakestCheck pins the accumulation rule.
//
// walkForAuthGuards has no gating analysis: it descends the whole body and
// reports every current_user_can() it finds, whether that check stops the
// request or only decides one branch. It used to keep the STRONGEST such check
// and hand it straight to the endpoint, so a handler with an admin-only branch
// beside an unguarded vulnerable branch reported Admin -- a reachable
// vulnerability that looks gated.
func TestAuthGuardTakesWeakestCheck(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
function mixed_handler() {
    if ( isset($_POST['admin_op']) ) {
        if ( ! current_user_can('manage_options') ) { wp_die(); }
        do_admin_thing();
    }
    if ( ! current_user_can('read') ) { wp_die(); }
    save_setting( $_POST['value'] );
}
`)

	hasGuard, level := r.HasAuthGuardBeforeInput("mixed_handler")
	if !hasGuard {
		t.Fatal("mixed_handler has capability checks, so a guard should be reported")
	}
	if level != models.Subscriber {
		t.Errorf("got %s, want subscriber: the manage_options check gates one branch, "+
			"and the weakest check found is the honest floor", level)
	}
}

// TestAuthGuardIndependentGatesTakeTheWeaker is the case the brief's priority
// order decides rather than WordPress semantics, so it is worth pinning
// explicitly. Two sequential checks that each end the request are conjunctive:
// the caller really does need BOTH, and the exact answer is Admin. This walker
// cannot tell them from alternatives or from branch-local checks, so it reports
// the weaker one -- under-restriction, which is noise, rather than
// over-restriction, which hides a reachable bug.
func TestAuthGuardIndependentGatesTakeTheWeaker(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
function two_gates() {
    if ( ! current_user_can('read') ) { return; }
    if ( ! current_user_can('manage_options') ) { return; }
    $v = $_POST['value'];
}
`)

	hasGuard, level := r.HasAuthGuardBeforeInput("two_gates")
	if !hasGuard {
		t.Fatal("two_gates should report a guard")
	}
	if level != models.Subscriber {
		t.Errorf("got %s, want subscriber", level)
	}
}

// TestIdentityReadsAreNotAuthGuards is the negative test that pins the bound of
// the guard set. wp_get_current_user() and get_current_user_id() deny nothing:
// core hands a logged-out visitor a WP_User(0) and an id of 0 rather than
// refusing, so both are reads of who is calling, not assertions about it. Any
// handler that merely looked the caller up used to be promoted to Subscriber.
func TestIdentityReadsAreNotAuthGuards(t *testing.T) {
	cases := map[string]string{
		"wp_get_current_user": `<?php
function reader() {
    $u = wp_get_current_user();
    update_option( $_POST['k'], $_POST['v'] );
}
`,
		"get_current_user_id": `<?php
function reader() {
    $id = get_current_user_id();
    update_option( $_POST['k'], $_POST['v'] );
}
`,
	}

	for name, code := range cases {
		r, _ := buildTestResolver(t, code)
		hasGuard, level := r.HasAuthGuardBeforeInput("reader")
		if hasGuard {
			t.Errorf("%s: reported a guard at %s; reading the caller's identity asserts nothing", name, level)
		}
		if level != models.Unauthenticated {
			t.Errorf("%s: got %s, want unauthenticated", name, level)
		}
	}
}

// TestLoginCheckIsStillAGuard pins the other side of that bound.
// is_user_logged_in() exists only to be tested and what it tests is the
// caller's login state, so it stays in the guard set even though this walker
// cannot yet prove the body is gated on it.
func TestLoginCheckIsStillAGuard(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
function login_gated() {
    if ( ! is_user_logged_in() ) { wp_die(); }
    $v = $_POST['value'];
}
`)

	hasGuard, level := r.HasAuthGuardBeforeInput("login_gated")
	if !hasGuard {
		t.Fatal("login_gated should report a guard")
	}
	if level != models.Subscriber {
		t.Errorf("got %s, want subscriber", level)
	}
}

// TestAuthGuardUsesTheSharedCapabilityTable pins the table merge. These three
// capabilities are exactly where the deleted local copy disagreed with
// pkg/config, and the answers below are core's: populate_roles_160() grants
// edit_pages to the editor role and edit_published_posts to the author role,
// and populate_roles_210() grants delete_pages to editor.
func TestAuthGuardUsesTheSharedCapabilityTable(t *testing.T) {
	cases := map[string]models.AuthLevel{
		"edit_pages":           models.Editor,
		"edit_published_posts": models.Author,
		"delete_pages":         models.Editor,
		"unfiltered_html":      models.Editor,
		"manage_options":       models.Admin,
	}

	for capability, want := range cases {
		r, _ := buildTestResolver(t, `<?php
function capability_gated() {
    if ( ! current_user_can('`+capability+`') ) { wp_die(); }
    $v = $_POST['value'];
}
`)
		hasGuard, level := r.HasAuthGuardBeforeInput("capability_gated")
		if !hasGuard {
			t.Errorf("%s: should report a guard", capability)
			continue
		}
		if level != want {
			t.Errorf("%s: got %s, want %s", capability, level, want)
		}
	}
}

// TestSetCapabilityConfigReachesTheASTPath pins the configuration hole that the
// duplicate table created: this package held its own package-level map, so an
// embedder's capability configuration could not reach it at all.
func TestSetCapabilityConfigReachesTheASTPath(t *testing.T) {
	cfg := config.New()
	cfg.Capabilities.Custom = map[string]string{"a_plugin_defined_cap": "contributor"}

	SetCapabilityConfig(cfg)
	defer SetCapabilityConfig(nil)

	r, _ := buildTestResolver(t, `<?php
function custom_gated() {
    if ( ! current_user_can('a_plugin_defined_cap') ) { wp_die(); }
    $v = $_POST['value'];
}
`)

	hasGuard, level := r.HasAuthGuardBeforeInput("custom_gated")
	if !hasGuard {
		t.Fatal("custom_gated should report a guard")
	}
	if level != models.Contributor {
		t.Errorf("got %s, want contributor from the supplied configuration", level)
	}

	// The bound: with the configuration removed, the same capability falls back
	// to the Subscriber floor for a name the table does not carry.
	SetCapabilityConfig(nil)
	_, level = r.HasAuthGuardBeforeInput("custom_gated")
	if level != models.Subscriber {
		t.Errorf("after clearing the config: got %s, want subscriber", level)
	}
}

// TestRoleSlugAsCapability pins that a role slug passed to current_user_can()
// resolves through the shared table on this path too.
//
// Only 'administrator' is in the table. A role slug IS a capability key --
// WP_User::add_role() writes $this->caps[ $role ] = true and get_role_caps()
// merges $this->caps into $allcaps -- so 'editor', 'author', 'contributor' and
// 'subscriber' belong there on the same reasoning. They were added and then
// reverted: with them resolvable, min-over-gating-capabilities loses the
// Subscriber floor it gets from an unresolvable name, and a gate of the shape
//
//     if ( $owner_id != $user->ID && ! current_user_can('administrator')
//                                 && ! current_user_can('editor') ) { wp_die(); }
//
// reads as an editor gate although the owner -- any logged-in user -- passes it.
// The missing piece is in pkg/analyzer's guard classifier, which cannot see that
// a disjunct which is not a capability check also lets a caller in. Once it can,
// the four slugs go back.
func TestRoleSlugAsCapability(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
function role_gated() {
    if ( ! current_user_can('administrator') ) { wp_die(); }
    $v = $_POST['value'];
}
`)

	hasGuard, level := r.HasAuthGuardBeforeInput("role_gated")
	if !hasGuard {
		t.Fatal("role_gated should report a guard")
	}
	if level != models.Admin {
		t.Errorf("administrator: got %s, want admin", level)
	}
}

// TestRoleNameInDataIsNotAGuard is the negative test for the role slugs.
// register_post_type()'s 'supports' argument takes the literals 'editor' and
// 'author' -- they name the post editor UI and the author metabox, not roles --
// and both appear in the corpus. Teaching the capability table those slugs must
// not make a data array look like a privilege assertion. This walker is safe by
// construction because it only reads the first argument of current_user_can(),
// and this test is what keeps it that way.
func TestRoleNameInDataIsNotAGuard(t *testing.T) {
	r, _ := buildTestResolver(t, `<?php
function registers_a_post_type() {
    register_post_type( 'thing', array( 'supports' => array( 'editor', 'author' ) ) );
    $roles = array( 'administrator', 'editor' );
    update_option( $_POST['k'], $_POST['v'] );
}
`)

	hasGuard, level := r.HasAuthGuardBeforeInput("registers_a_post_type")
	if hasGuard {
		t.Errorf("reported a guard at %s; role names in a data array assert nothing", level)
	}
	if level != models.Unauthenticated {
		t.Errorf("got %s, want unauthenticated", level)
	}
}

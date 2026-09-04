package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// The tests in this file cover the move from "a check is present" to "a check
// gates this code". Each group names the construct it pins and carries the
// negative control -- the case the rule must NOT match -- because every rule
// here trades one error direction for the other and the bound is what makes the
// trade safe.

type levelCase struct {
	name string
	code string
	want models.AuthLevel
}

func runLevelCases(t *testing.T, cases []levelCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := InferAuthLevel(c.code); got != c.want {
				t.Errorf("InferAuthLevel = %s, want %s\ncode: %s", got, c.want, c.code)
			}
		})
	}
}

// TestNonceNeverRaisesALevel: wp_create_nonce($action) hashes the action, the
// user id and a session token, and get_current_user_id() is 0 for every
// anonymous visitor -- so the nonce minted for an action registered with
// wp_ajax_nopriv_ is identical for all of them and is printed into public page
// HTML. A nonce is CSRF provenance and establishes no privilege.
func TestNonceNeverRaisesALevel(t *testing.T) {
	content := `<?php
class A {
	public function handle() {
		$this->helper();
		update_option( 'o', $_POST['v'] );
	}
	public function helper() {
		check_ajax_referer( 'a', '_wpnonce' );
	}
	public function statically() {
		Helper::verify();
		update_option( 'o', $_POST['v'] );
	}
}
class Helper {
	public static function verify() { wp_verify_nonce( $_POST['n'], 'a' ); }
}
`
	for _, fn := range []string{"handle", "statically"} {
		if got := InferAuthLevelFromCallback(fn, content, nil); got != models.Unauthenticated {
			t.Errorf("%s: level = %s, want unauthenticated: a nonce is not a credential", fn, got)
		}
	}
}

// TestDelegateResolvingToItselfIsNotAGuard: findFunctionBody matches on the
// bare method name, so `$this->file_manager->temp_file_delete( $id )` inside
// temp_file_delete() re-finds the handler. Crediting a function with its own
// checks is never intended.
func TestDelegateResolvingToItselfIsNotAGuard(t *testing.T) {
	content := `<?php
class A {
	public function temp_file_delete() {
		check_ajax_referer( 'a', '_wpnonce' );
		if ( $this->file_manager->temp_file_delete( $_POST['id'] ) ) { wp_send_json_success(); }
	}
}
`
	if got := InferAuthLevelFromCallback("temp_file_delete", content, nil); got != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated", got)
	}
}

// TestDelegateWithARealGateIsStillFollowed is the bound on the two tests above:
// removing the nonce rule and the self-resolution must not remove delegation.
func TestDelegateWithARealGateIsStillFollowed(t *testing.T) {
	content := `<?php
class A {
	public function handle() {
		$this->guard_admin();
		update_option( 'o', $_POST['v'] );
	}
	public function guard_admin() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error(); }
	}
}
`
	if got := InferAuthLevelFromCallback("handle", content, nil); got != models.Admin {
		t.Errorf("level = %s, want admin: the delegate ends the request", got)
	}
}

// TestDelegateWhoseGuardOnlyReturnsGatesNothing. `return` transfers control to
// the caller and nothing more, so a helper's `if ( ! current_user_can(X) ) {
// return; }` protects the helper and leaves its caller open.
func TestDelegateWhoseGuardOnlyReturnsGatesNothing(t *testing.T) {
	content := `<?php
class A {
	public function handle() {
		update_option( 'o', $_POST['v'] );
		$this->render_admin_notice();
	}
	public function render_admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		echo 'hi';
	}
}
`
	if got := InferAuthLevelFromCallback("handle", content, nil); got != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: the delegate only returns", got)
	}
	// The bound: the same guard in the handler itself DOES gate, because a
	// handler's return ends the request.
	body := `{ if ( ! current_user_can( 'manage_options' ) ) { return; } update_option( 'o', $_POST['v'] ); }`
	if got := InferAuthLevel(body); got != models.Admin {
		t.Errorf("handler body level = %s, want admin", got)
	}
}

// TestNameShapedAdminPromotionIsGone. WordPress attaches no meaning to a PHP
// function's name. A method spelled isAdmin() may return
// current_user_can(<a class constant>) && is_admin(), and is_admin() is a
// location test that is true for every admin-ajax.php request.
func TestNameShapedAdminPromotionIsGone(t *testing.T) {
	runLevelCases(t, []levelCase{
		{"static isAdmin", `{ if ( Helper::isAdmin() ) { render(); } update_option('o',$_POST['v']); }`, models.Unauthenticated},
		{"check_permission", `{ $x = check_permission(); update_option('o',$_POST['v']); }`, models.Unauthenticated},
		{"can_manage", `{ if ( can_manage() ) { render(); } update_option('o',$_POST['v']); }`, models.Unauthenticated},
		{"is_admin_user", `{ if ( is_admin_user() ) { render(); } update_option('o',$_POST['v']); }`, models.Unauthenticated},
		{"verify_capability substring", `{ /* verify_capability was checked elsewhere */ update_option('o',$_POST['v']); }`, models.Unauthenticated},
		// The bound: the core vocabulary still counts when it gates.
		{"real manage_options gate", `{ if ( ! current_user_can('manage_options') ) { wp_die(); } update_option('o',$_POST['v']); }`, models.Admin},
		{"role membership gate", `{ if ( ! in_array( 'administrator', $user->roles, true ) ) { wp_die(); } update_option('o',$_POST['v']); }`, models.Admin},
	})
}

// TestPresenceOfAnIdentityPredicateIsNotAGate. is_user_logged_in() and
// is_super_admin() return booleans; PHP decides whether that boolean stops the
// request, and the same control-flow reasoning current_user_can already gets
// applies unchanged.
func TestPresenceOfAnIdentityPredicateIsNotAGate(t *testing.T) {
	runLevelCases(t, []levelCase{
		{"decorative is_super_admin", `{ if ( is_super_admin() ) { $extra = 1; } update_option('o',$_POST['v']); }`, models.Unauthenticated},
		{"decorative is_user_logged_in", `{ if ( is_user_logged_in() ) { $who = wp_get_current_user(); } update_option('o',$_POST['v']); }`, models.Unauthenticated},
		{"bare permission_callback string", `{ register_rest_route('x/v1','/y',array('permission_callback'=>array($this,'z'))); update_option('o',$_POST['v']); }`, models.Unauthenticated},
		// The bound: the same predicates gate when they gate.
		{"gating is_user_logged_in", `{ if ( ! is_user_logged_in() ) { wp_send_json_error(); } update_option('o',$_POST['v']); }`, models.Subscriber},
		{"gating auth_redirect", `{ if ( ! is_user_logged_in() ) { auth_redirect(); exit; } update_option('o',$_POST['v']); }`, models.Subscriber},
		// auth_redirect() needs no condition: core redirects and exits for a
		// caller without a valid auth cookie, so calling it forces a login on
		// everything after it.
		{"bare auth_redirect", `{ auth_redirect(); update_option('o',$_POST['v']); }`, models.Subscriber},
		// The bound: only auth_redirect does that. Every other predicate returns
		// a boolean, and a boolean nobody tests gates nothing.
		{"bare is_user_logged_in", `{ is_user_logged_in(); update_option('o',$_POST['v']); }`, models.Unauthenticated},
		{"bare is_super_admin", `{ $x = is_super_admin(); update_option('o',$_POST['v']); }`, models.Unauthenticated},
		{"auth_redirect nested in a branch", `{ if ( isset($_GET['admin']) ) { auth_redirect(); } update_option('o',$_POST['v']); }`, models.Unauthenticated},
	})
}

// TestIsSuperAdminIsAdminNotSuperAdmin. On a single-site install, which is the
// default, core defines is_super_admin() as $user->has_cap('delete_users') --
// true for every Administrator. Only under is_multisite() does it consult
// get_super_admins(), and a static analyzer cannot know which install a plugin
// will run on.
func TestIsSuperAdminIsAdminNotSuperAdmin(t *testing.T) {
	code := `{ if ( ! is_super_admin() ) { wp_die(); } update_option('o',$_POST['v']); }`
	if got := InferAuthLevel(code); got != models.Admin {
		t.Errorf("level = %s, want admin (not superadmin)", got)
	}
}

// TestLoginGateDoesNotDragACapabilityGateDown. Sequential top-level guards are
// conjunctive: the caller must pass both. Folding a login gate into the same
// minimum as a capability gate would report Subscriber for an endpoint that
// genuinely needs manage_options.
func TestLoginGateDoesNotDragACapabilityGateDown(t *testing.T) {
	code := `{
		if ( ! is_user_logged_in() ) { wp_send_json_error(); }
		if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error(); }
		update_option( 'o', $_POST['v'] );
	}`
	if got := InferAuthLevel(code); got != models.Admin {
		t.Errorf("level = %s, want admin: the login check is a floor, not an alternative", got)
	}
}

// TestUnknownCapabilityIsNotEscalatedByItsName. A capability is a string key in
// WP_User::$allcaps, populated from whatever roles the site holds;
// map_meta_cap's default branch is `$caps[] = $cap` and does no name parsing.
// events-manager grants manage_bookings and delete_events to contributors and
// read_private_events to subscribers, while the name shapes called them Admin,
// Admin and Editor.
func TestUnknownCapabilityIsNotEscalatedByItsName(t *testing.T) {
	for _, cap := range []string{
		"manage_bookings", "delete_events", "read_private_events", "read_others_locations",
		"manage_woocommerce", "duplicator_view", "backup_site", "restore_config",
		"shop_settings", "updraft_manage", "install_widgets_pro", "moderate_things",
	} {
		code := `{ if ( ! current_user_can('` + cap + `') ) { wp_die(); } sink($_POST['x']); }`
		if got := InferAuthLevel(code); got != models.Subscriber {
			t.Errorf("capability %q: level = %s, want subscriber (the floor for an unrecognised capability)", cap, got)
		}
	}
	// The bound: a real core capability still resolves to its real level.
	for cap, want := range map[string]models.AuthLevel{
		"manage_options":    models.Admin,
		"edit_others_posts": models.Editor,
		"publish_posts":     models.Author,
		"edit_posts":        models.Contributor,
		"read":              models.Subscriber,
	} {
		code := `{ if ( ! current_user_can('` + cap + `') ) { wp_die(); } sink($_POST['x']); }`
		if got := InferAuthLevel(code); got != want {
			t.Errorf("capability %q: level = %s, want %s", cap, got, want)
		}
	}
}

// TestMetaCapabilitiesResolveThroughMapMetaCap. A meta capability is not a key
// in anyone's capability map; current_user_can runs it through map_meta_cap
// first. For edit_user core contains
//
//	if ( 'edit_user' === $cap && isset( $args[0] ) && $user_id === (int) $args[0] ) { break; }
//
// which breaks with $caps empty, and WP_User::has_cap then returns true for an
// empty set -- so any logged-in user passes current_user_can('edit_user',
// $their_own_id).
func TestMetaCapabilitiesResolveThroughMapMetaCap(t *testing.T) {
	runLevelCases(t, []levelCase{
		{"edit_user with the object", `{ if ( ! current_user_can( 'edit_user', $user_id ) ) { wp_send_json_error(); } sink($_POST['x']); }`, models.Subscriber},
		{"edit_user without the object", `{ if ( ! current_user_can( 'edit_user' ) ) { wp_send_json_error(); } sink($_POST['x']); }`, models.Admin},
		{"app password with the object", `{ if ( ! current_user_can( 'create_app_password', $user_id ) ) { wp_die(); } sink($_POST['x']); }`, models.Subscriber},
		{"assign_term", `{ if ( ! current_user_can( 'assign_term', $t ) ) { wp_die(); } sink($_POST['x']); }`, models.Contributor},
		{"assign_categories", `{ if ( ! current_user_can( 'assign_categories' ) ) { wp_die(); } sink($_POST['x']); }`, models.Contributor},
		{"manage_post_tags", `{ if ( ! current_user_can( 'manage_post_tags' ) ) { wp_die(); } sink($_POST['x']); }`, models.Editor},
		{"setup_network on a single site", `{ if ( ! current_user_can( 'setup_network' ) ) { wp_die(); } sink($_POST['x']); }`, models.Admin},
		{"upload_plugins on a single site", `{ if ( ! current_user_can( 'upload_plugins' ) ) { wp_die(); } sink($_POST['x']); }`, models.Admin},
		{"edit_comment", `{ if ( ! current_user_can( 'edit_comment', $id ) ) { wp_die(); } sink($_POST['x']); }`, models.Contributor},
		// The bound: edit_post already resolved correctly and must not move.
		{"edit_post with the object", `{ if ( ! current_user_can( 'edit_post', $id ) ) { wp_die(); } sink($_POST['x']); }`, models.Contributor},
	})
}

// TestMetaCapObjectArgumentIsCountedByArity: a wrapped capability puts a comma
// after the first quoted string without there being an object argument at all,
// so the argument list has to be split rather than scanned for a comma.
func TestMetaCapObjectArgumentIsCountedByArity(t *testing.T) {
	code := `{ if ( ! current_user_can( apply_filters( 'plugin_cap', 'edit_user' ) ) ) { wp_die(); } sink($_POST['x']); }`
	if got := InferAuthLevel(code); got != models.Admin {
		t.Errorf("level = %s, want admin: apply_filters() supplies no object argument", got)
	}
}

// TestCapabilityInsideApplyFiltersIsRead. firstStringLiteral used to return the
// FILTER name for `current_user_can( apply_filters( 'plugin_role',
// 'upload_files' ) )`, which is a string that is not a capability at all.
func TestCapabilityInsideApplyFiltersIsRead(t *testing.T) {
	code := `{ if ( ! current_user_can( apply_filters( 'plugin_role', 'upload_files' ) ) ) { wp_die(); } sink($_POST['x']); }`
	if got := InferAuthLevel(code); got != models.Author {
		t.Errorf("level = %s, want author (upload_files)", got)
	}
}

// TestExplicitSubjectReadsSayNothingAboutTheCaller. user_can() and author_can()
// name the user they are asking about; when the request chooses that user, the
// answer describes the request, not the caller.
func TestExplicitSubjectReadsSayNothingAboutTheCaller(t *testing.T) {
	code := `{ $u = get_user_by( 'login', $_SERVER['PHP_AUTH_USER'] );
		if ( ! user_can( $u->ID, 'create_users' ) ) { wp_die(); }
		sink( $_POST['x'] ); }`
	if got := InferAuthLevel(code); got != models.Subscriber {
		t.Errorf("level = %s, want subscriber: the subject is request-chosen, so only the gate itself is evidence", got)
	}
	// The bound: naming the current user makes it a read about the caller.
	code = `{ if ( ! user_can( wp_get_current_user(), 'manage_options' ) ) { wp_die(); } sink($_POST['x']); }`
	if got := InferAuthLevel(code); got != models.Admin {
		t.Errorf("level = %s, want admin", got)
	}
}

// TestElseIfArmDoesNotDominate: an elseif arm runs only when the earlier
// conditions were false, so at least one arm already executed without it.
func TestElseIfArmDoesNotDominate(t *testing.T) {
	for _, body := range []string{
		`{ if ( $a ) { public_thing(); } elseif ( ! current_user_can( 'manage_options' ) ) { wp_die(); } }`,
		`{ if ( $a ) { public_thing(); } else if ( ! current_user_can( 'manage_options' ) ) { wp_die(); } }`,
	} {
		if k := kindOf(t, body); k != GuardBranch {
			t.Errorf("kind = %v, want GuardBranch for %q", k, body)
		}
		if got := InferAuthLevel(body); got != models.Unauthenticated {
			t.Errorf("level = %s, want unauthenticated for %q", got, body)
		}
	}
}

// TestTerminatingElseArmDominates: in `if (C) { A } else { B }` where B ends the
// request, every statement after the construct is reached only when C was true.
func TestTerminatingElseArmDominates(t *testing.T) {
	if got := InferAuthLevel(`{ if ( current_user_can('manage_options') ) { save($_POST['v']); } else { wp_send_json_error(); } }`); got != models.Admin {
		t.Errorf("level = %s, want admin: the else arm refuses", got)
	}
	if got := InferAuthLevel(`{ if ( current_user_can('manage_options') ) { admin_only(); } else { wp_die(); } save($_POST['v']); }`); got != models.Admin {
		t.Errorf("level = %s, want admin: the else arm refuses, so save() is reached only through the true arm", got)
	}
	// Bound 1: an else arm that does not terminate leaves the tail open.
	if got := InferAuthLevel(`{ if ( current_user_can('manage_options') ) { admin_only(); } else { $msg='nope'; } save($_POST['v']); }`); got != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: save() runs regardless", got)
	}
	// Bound 2: `return <call>` is not a refusal -- the callee runs, with
	// whatever the request supplied.
	if got := InferAuthLevel(`{ if ( current_user_can('manage_options') ) { $this->admin_view(); } else { return $this->public_view( $_POST ); } }`); got != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: public_view() runs for everyone else", got)
	}
	// Bound 3: an elseif chain with an arm that does not refuse.
	if got := InferAuthLevel(`{ if ( current_user_can('manage_options') ) { admin_only(); } elseif ( $b ) { public_thing(); } else { wp_die(); } save($_POST['v']); }`); got != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: the elseif arm reaches save()", got)
	}
}

// TestTrailingCommentDoesNotDefeatAWholeBodyGuard. A comment is not a statement
// in any PHP program, so a classifier whose answer flips because of `// done` is
// measuring lexical noise.
func TestTrailingCommentDoesNotDefeatAWholeBodyGuard(t *testing.T) {
	for _, body := range []string{
		"{ if ( current_user_can('manage_options') ) { save($_POST['v']); } // done\n}",
		"{ if ( current_user_can('manage_options') ) { save($_POST['v']); } /* done */ }",
		"{ if ( current_user_can('manage_options') ) { save($_POST['v']); } # done\n}",
	} {
		if got := InferAuthLevel(body); got != models.Admin {
			t.Errorf("level = %s, want admin for %q", got, body)
		}
	}
}

// TestCloseTagIsNotTrivia. `?>` does not end a function body; it switches the
// parser to output mode, and every byte until the next `<?php` is echoed on each
// call whether or not the check passed.
func TestCloseTagIsNotTrivia(t *testing.T) {
	body := "{ if ( current_user_can('manage_options') ) { admin_only(); } ?>\n<p>public output</p>\n<?php }"
	if got := InferAuthLevel(body); got != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: the paragraph is emitted for every caller", got)
	}
}

// TestPositiveGuardMustPrecedeTheCodeItProtects. The positive form used to get
// neither the depth demotion the negated form has nor any check that it came
// first, so a check sitting after the sink, or three blocks deep, reported the
// whole function as gated.
func TestPositiveGuardMustPrecedeTheCodeItProtects(t *testing.T) {
	runLevelCases(t, []levelCase{
		{"sink runs first", `{ update_option('o',$_POST['v']); if ( current_user_can('manage_options') ) { admin(); } }`, models.Unauthenticated},
		{"guard three blocks deep", `{ if($a){ if($b){ if(current_user_can('manage_options')){ admin(); } } } }`, models.Unauthenticated},
		{"guard after an unchecked branch", `{ if ( isset($_GET['x']) ) { $this->refresh_token(); } if ( isset($_GET['y']) && user_can( wp_get_current_user(), 'manage_options' ) ) { $this->flush(); } }`, models.Unauthenticated},
		// The bound: a positive guard that really does wrap the body still gates.
		{"positive guard wrapping the body", `{ if ( current_user_can('manage_options') ) { save($_POST['v']); } }`, models.Admin},
	})
}

// TestNegationParityIsPerOperand. `if ( ! empty($id) && current_user_can(X) ) {
// wp_die(); }` refuses callers who HAVE the capability; reading the `!` that
// belongs to empty() as if it negated the capability check reported Admin for a
// handler that gates nothing.
func TestNegationParityIsPerOperand(t *testing.T) {
	runLevelCases(t, []levelCase{
		{"negation belongs to another operand", `{ if ( ! empty($id) && current_user_can('manage_options') ) { wp_die(); } save($_POST['v']); }`, models.Unauthenticated},
		// The bound: a negation that encloses the whole condition still counts.
		{"negated disjunction", `{ if ( ! ( current_user_can('manage_options') || current_user_can('edit_posts') ) ) { wp_die(); } save($_POST['v']); }`, models.Contributor},
		{"plain negation", `{ if ( ! current_user_can('manage_options') ) { wp_die(); } save($_POST['v']); }`, models.Admin},
	})
}

// TestAssignedThenTestedIsAGuard: `$v = expr; if ( ! $v ) { terminate; }` has
// the same control flow as the inline form; only a temporary got in the way.
func TestAssignedThenTestedIsAGuard(t *testing.T) {
	runLevelCases(t, []levelCase{
		{"negated test", `{ $can = current_user_can('manage_options'); if ( ! $can ) { wp_die(); } save($_POST['v']); }`, models.Admin},
		{"empty test", `{ $can = current_user_can('manage_options'); if ( empty( $can ) ) { wp_send_json_error(); } save($_POST['v']); }`, models.Admin},
		{"negated assignment then positive test", `{ $denied = ! current_user_can('manage_options'); if ( $denied ) { wp_die(); } save($_POST['v']); }`, models.Admin},

		// Bound 1: an assignment that is never tested gates nothing.
		{"display only", `{ $can_edit = current_user_can('edit_posts'); render($can_edit); save($_POST['v']); }`, models.Unauthenticated},
		// Bound 2: reassignment before the test breaks the chain.
		{"reassigned first", `{ $can = current_user_can('manage_options'); $can = $override; if ( ! $can ) { wp_die(); } save($_POST['v']); }`, models.Unauthenticated},
		// Bound 3: the depth rule is keyed off the TEST, which is the statement
		// that dominates -- not off the assignment, which sits at the top level.
		{"tested inside a branch", `{ $can = current_user_can('manage_options');
			if ( isset($_POST['admin_op']) ) { if ( ! $can ) { wp_die(); } $this->admin_op(); }
			update_option('o',$_POST['v']); }`, models.Unauthenticated},
		// Bound 4: the variable must hold the check's result and nothing else.
		// A ternary assigns two truthy strings, so `if ( ! $x )` never fires.
		{"ternary assignment", `{ $x = current_user_can('manage_options') ? 'yes' : 'no'; if ( ! $x ) { wp_die(); } save($_POST['v']); }`, models.Unauthenticated},
		// Bound 5: a positive test protects only what follows it, so a sink
		// between the assignment and the test is still reachable by anyone.
		{"sink between the assignment and a positive test", `{ $can = current_user_can('manage_options'); update_option('o',$_POST['v']); if ( $can ) { admin(); } }`, models.Unauthenticated},
		// ... and with nothing in between, the positive test does gate.
		{"positive test wrapping the rest of the body", `{ $can = current_user_can('manage_options'); if ( $can ) { update_option('o',$_POST['v']); } }`, models.Admin},
	})
}

// TestIdentifierContainingIfIsNotACondition. The keyword search was a bare
// strings.LastIndex(prefix, "if"), so "ver-IF-ied" satisfied it: a body ending
// in `$verified = current_user_can('manage_options');` reported Admin.
func TestIdentifierContainingIfIsNotACondition(t *testing.T) {
	for _, name := range []string{"$verified", "$notify", "$modified", "$gif_url"} {
		body := `{ ` + name + ` = current_user_can('manage_options'); }`
		if k := kindOf(t, body); k != GuardNone {
			t.Errorf("%s: kind = %v, want GuardNone", name, k)
		}
		if got := InferAuthLevel(body); got != models.Unauthenticated {
			t.Errorf("%s: level = %s, want unauthenticated", name, got)
		}
	}
}

// TestGuardsInABlobBelongToItsFunctions. Brace depth is relative to the
// enclosing function declaration, not to the start of whatever substring a
// caller sliced -- and when the slice is not a body at all, its checks gate the
// functions they sit in and say nothing about the slice.
func TestGuardsInABlobBelongToItsFunctions(t *testing.T) {
	oneHandler := `<?php
class C {
	public function h() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
		update_option( 'o', $_POST['v'] );
	}
}
`
	twoHandlers := `<?php
class C {
	public function h() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
		update_option( 'o', $_POST['v'] );
	}
	public function g() { update_option( 'o', $_POST['v'] ); }
}
`
	if got := InferAuthLevel(oneHandler); got != models.Unauthenticated {
		t.Errorf("whole file = %s, want unauthenticated: the file is not a function body", got)
	}
	if got := InferAuthLevel(twoHandlers); got != models.Unauthenticated {
		t.Errorf("whole file = %s, want unauthenticated", got)
	}
	if _, gated := StrongestGuard(oneHandler); gated {
		t.Error("StrongestGuard reported a whole file gated")
	}
	// The bound: handed the method's own body, the same check gates it.
	body := findFunctionBody("h", oneHandler)
	if body == "" {
		t.Fatal("could not extract the handler body")
	}
	if got := InferAuthLevel(body); got != models.Admin {
		t.Errorf("body = %s, want admin", got)
	}
	if k := kindOf(t, body); k != GuardFunction {
		t.Errorf("kind = %v, want GuardFunction: the check is at the body's top level", k)
	}
}

// TestGuardNestedInsideTheFunctionStaysBranch is the other half of the depth
// rule: relative to the enclosing function's own opening brace, so a check
// wrapped in a try or a foreach inside that function still gates only its block.
func TestGuardNestedInsideTheFunctionStaysBranch(t *testing.T) {
	body := `{
		try {
			if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
			$this->admin_op();
		} catch ( Exception $e ) {}
		update_option( 'o', $_POST['v'] );
	}`
	if k := kindOf(t, body); k != GuardBranch {
		t.Errorf("kind = %v, want GuardBranch: the guard sits inside a try", k)
	}
}

// TestCommentsAndStringsDoNotShiftBraceDepth.
func TestCommentsAndStringsDoNotShiftBraceDepth(t *testing.T) {
	body := `{
		$tpl = '{{ handlebars }}';   // a brace in a string
		/* and a brace in a comment: { */
		if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
		update_option( 'o', $_POST['v'] );
	}`
	if k := kindOf(t, body); k != GuardFunction {
		t.Errorf("kind = %v, want GuardFunction", k)
	}
}

// TestCapabilityMentionedInACommentIsNotACheck.
func TestCapabilityMentionedInACommentIsNotACheck(t *testing.T) {
	body := `{ // requires current_user_can('manage_options') one day
		update_option( 'o', $_POST['v'] ); }`
	if gs := FindCapabilityGuards(body); len(gs) != 0 {
		t.Errorf("guards = %+v, want none: the mention is in a comment", gs)
	}
	if got := InferAuthLevel(body); got != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated", got)
	}
}

// TestReturnShapedPermissionCallback. WP_REST_Server::dispatch_request() calls
// the permission_callback and, on a falsy result or a WP_Error, answers
// rest_forbidden without invoking the route callback -- so for a permission
// callback the return value IS the gate.
func TestReturnShapedPermissionCallback(t *testing.T) {
	cases := []struct {
		name string
		body string
		want models.AuthLevel
	}{
		{"plain capability", `return current_user_can( 'edit_others_posts' );`, models.Editor},
		{"capability and a nonce", `return current_user_can( 'manage_options' ) && wp_verify_nonce( $r['n'], 'a' );`, models.Admin},
		{"identity predicate", `return is_user_logged_in();`, models.Subscriber},
		{"early accept on a capability", `if ( current_user_can( 'manage_options' ) ) { return true; } return false;`, models.Admin},
		{"early refusal then a capability", `if ( empty( $r['id'] ) ) { return false; } return current_user_can( 'manage_options' );`, models.Admin},

		// Bound 1: negation inverts the gate. `return ! current_user_can(X)`
		// admits precisely the callers who LACK X.
		{"negated capability", `return ! current_user_can( 'manage_options' );`, models.Unauthenticated},
		{"negated identity", `return ! is_user_logged_in();`, models.Unauthenticated},
		// Bound 2: an unresolvable disjunct may be satisfiable by anyone.
		{"unresolvable disjunct", `return current_user_can( 'manage_options' ) || $this->token_ok( $r );`, models.Unauthenticated},
		// Bound 3: an earlier permissive return makes the route public.
		{"earlier permissive return", `if ( 'yes' === get_option( 'public_api' ) ) { return true; } return current_user_can( 'manage_options' );`, models.Unauthenticated},
		// Bound 4: a capability that is not a literal yields no level at all.
		{"non-literal capability", `return current_user_can( get_post_type_object( 'x' )->cap->edit_posts );`, models.Unauthenticated},
		// Bound 5: an explicit subject the request chose.
		{"request-chosen subject", `$u = get_user_by( 'login', $_SERVER['PHP_AUTH_USER'] ); return user_can( $u->ID, 'create_users' );`, models.Unauthenticated},
		// Bound 6: a check inside a nested block could be skipped entirely.
		{"conditional gate two levels down", `if ( isset( $r['x'] ) ) { if ( ! current_user_can( 'manage_options' ) ) { return false; } } return true;`, models.Unauthenticated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			content := `<?php
class C {
	public function reg() {
		register_rest_route( 'ns/v1', '/x', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'run' ),
			'permission_callback' => array( $this, 'pc' ),
		) );
	}
	public function pc( $r ) { ` + c.body + ` }
}
`
			args := content[strings.Index(content, "array(") : strings.Index(content, ") );")+1]
			_, level := ParsePermissionCallbackWithContext(args, content)
			if level != c.want {
				t.Errorf("level = %s, want %s", level, c.want)
			}
		})
	}
}

// TestReturnShapeStaysOutOfHandlerAnalysis: a handler that merely computes a
// boolean gates nothing. Only a permission_callback has its return value read
// as a verdict, and that is core's doing, not a convention.
func TestReturnShapeStaysOutOfHandlerAnalysis(t *testing.T) {
	if got := InferAuthLevel(`{ return current_user_can( 'manage_options' ); }`); got != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: nothing was refused", got)
	}
}

// TestPermissionCallbackNameNeverProducesALevel. Core's own
// WP_REST_Posts_Controller::get_items_permissions_check() returns true for
// anonymous readers of a public post type, so even a name that follows core's
// convention exactly carries no privilege.
func TestPermissionCallbackNameNeverProducesALevel(t *testing.T) {
	content := `<?php
class T {
	public function reg() {
		register_rest_route( 'x/v1', '/thing', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'one' ),
			'permission_callback' => array( $this, 'check_admin_permission' ),
		) );
	}
}
`
	args := content[strings.Index(content, "array(") : strings.Index(content, ") );")+1]
	cb, level := ParsePermissionCallbackWithContext(args, content)
	if cb != "check_admin_permission" {
		t.Fatalf("callback = %q, want check_admin_permission", cb)
	}
	if level != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: the body is not in this file, and the name is not evidence", level)
	}

	// The bound: with the body in reach, the identical call site reports what
	// the body actually enforces.
	withBody := strings.Replace(content, "}\n", "}\n\tpublic function check_admin_permission( $r ) { return current_user_can( 'manage_options' ); }\n", 1)
	_, level = ParsePermissionCallbackWithContext(args, withBody)
	if level != models.Admin {
		t.Errorf("level = %s, want admin", level)
	}
}

// TestArrowFunctionPermissionCallbackIsRead: every `fn() => ...` used to report
// Subscriber regardless of what it said.
func TestArrowFunctionPermissionCallbackIsRead(t *testing.T) {
	args := `array( 'methods' => 'GET', 'permission_callback' => fn( $r ) => current_user_can( 'edit_others_posts' ) )`
	if _, level := ParsePermissionCallbackWithContext(args, args); level != models.Editor {
		t.Errorf("level = %s, want editor", level)
	}
	args = `array( 'methods' => 'GET', 'permission_callback' => fn( $r ) => $r->get_param( 'token' ) === 'x' )`
	if _, level := ParsePermissionCallbackWithContext(args, args); level != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: the expression asserts no identity", level)
	}
}

// TestSymbolicCapabilityIsResolved. PHP evaluates current_user_can()'s argument
// before the call, so a symbol that only ever holds one literal asks the same
// question as writing that literal inline.
func TestSymbolicCapabilityIsResolved(t *testing.T) {
	cases := []struct {
		name string
		php  string
		fn   string
		want models.AuthLevel
	}{
		{
			"property with a single literal",
			`<?php class M {
				private $capability = 'edit_posts';
				public function save( $id ) {
					if ( ! current_user_can( $this->capability ) ) { wp_die(); }
					update_post_meta( $id, 'x', $_POST['x'] );
				}
			}`,
			"save", models.Contributor,
		},
		{
			"class constant",
			`<?php class M {
				const CAP = 'edit_others_posts';
				public function save( $id ) {
					if ( ! current_user_can( self::CAP ) ) { wp_die(); }
					sink( $_POST['x'] );
				}
			}`,
			"save", models.Editor,
		},
		{
			"local assigned in the same body",
			`<?php function h() { $cap = 'publish_posts'; if ( ! current_user_can( $cap ) ) { wp_die(); } sink( $_POST['x'] ); }`,
			"h", models.Author,
		},
		{
			// Bound 1: a property with a setter is a default, not a value. The
			// consumer chooses, and it may choose lower.
			"property with a setter",
			`<?php class M {
				public $capability = 'manage_options';
				public function set_capability( $c ) { $this->capability = $c; return $this; }
				public function save( $id ) {
					if ( ! current_user_can( $this->capability ) ) { wp_die(); }
					sink( $_POST['x'] );
				}
			}`,
			"save", models.Subscriber,
		},
		{
			// Bound 2: PHP scopes locals to the function, so a $cap in another
			// method is a different variable and must not be read here.
			"local from another function",
			`<?php class S {
				public function render_settings() {
					$cap = 'manage_options';
					if ( ! current_user_can( $cap ) ) { wp_die(); }
				}
				public function render_row( $id ) {
					$cap = $this->row_cap_for( $id );
					if ( ! current_user_can( $cap ) ) { return; }
					echo get_post_meta( $id, 'x', true );
				}
			}`,
			"render_row", models.Subscriber,
		},
		{
			// Bound 3: several literals mean several ways in; the cheapest wins.
			"two literals",
			`<?php class M {
				private $capability = 'manage_options';
				public function reset() { $this->capability = 'edit_posts'; }
				public function save( $id ) {
					if ( ! current_user_can( $this->capability ) ) { wp_die(); }
					sink( $_POST['x'] );
				}
			}`,
			"save", models.Contributor,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := findFunctionBody(c.fn, c.php)
			if body == "" {
				t.Fatalf("could not extract %s", c.fn)
			}
			if got := InferAuthLevelInFile(body, c.php); got != c.want {
				t.Errorf("level = %s, want %s", got, c.want)
			}
		})
	}
}

// TestSymbolicCapabilityOnlyResolvesForAGatingCheck: a symbol read in a
// non-gating position must not produce a level either.
func TestSymbolicCapabilityOnlyResolvesForAGatingCheck(t *testing.T) {
	php := `<?php class M {
		private $capability = 'manage_options';
		public function render() {
			if ( current_user_can( $this->capability ) ) { $show = true; }
			update_option( 'o', $_POST['v'] );
		}
	}`
	body := findFunctionBody("render", php)
	if got := InferAuthLevelInFile(body, php); got != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: the check decorates a variable", got)
	}
}

// TestConfiguredCapabilityOutranksTheMetaTable: an operator who has configured
// a capability must still win, which is why the meta-capability table is
// consulted after the explicit configuration and before the built-in lists.
func TestConfiguredCapabilityOutranksTheMetaTable(t *testing.T) {
	original := GetAuthConfig()
	defer SetAuthConfig(original)

	cfg := *original
	caps := *original.Capabilities
	caps.ExtendedCapabilities = map[string]string{"edit_user": "admin"}
	cfg.Capabilities = &caps
	SetAuthConfig(&cfg)

	code := `{ if ( ! current_user_can( 'edit_user', $user_id ) ) { wp_die(); } sink($_POST['x']); }`
	if got := InferAuthLevel(code); got != models.Admin {
		t.Errorf("level = %s, want admin: the operator configured this capability", got)
	}
}

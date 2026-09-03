package analyzer

import "testing"

func kindOf(t *testing.T, body string) GuardKind {
	t.Helper()
	gs := FindCapabilityGuards(body)
	if len(gs) == 0 {
		t.Fatalf("no capability check found in %q", body)
	}
	return gs[0].Kind
}

// TestGuardNegatedTerminatorProtectsFunction is the idiom that really does gate
// a handler: fail the check, stop the request.
func TestGuardNegatedTerminatorProtectsFunction(t *testing.T) {
	bodies := []string{
		`{ if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'nope' ); } do_thing(); }`,
		`{ if ( ! current_user_can( 'edit_posts' ) ) { return; } do_thing(); }`,
		`{ if ( ! current_user_can( 'edit_posts' ) ) return; do_thing(); }`,
		`{ if ( ! current_user_can( 'edit_posts' ) ) { wp_send_json_error( 'no' ); } do_thing(); }`,
		`{ if ( ! current_user_can( 'edit_posts' ) ) { exit; } do_thing(); }`,
	}
	for _, b := range bodies {
		if k := kindOf(t, b); k != GuardFunction {
			t.Errorf("kind = %v, want GuardFunction for %q", k, b)
		}
	}
}

// TestGuardNegatedWithoutTerminatorProtectsNothing is the trap. The check is
// present, so the old presence-based inference reported its level, but control
// continues past it and the code below is reachable without the capability.
func TestGuardNegatedWithoutTerminatorProtectsNothing(t *testing.T) {
	body := `{ if ( ! current_user_can( 'manage_options' ) ) { $msg = 'denied'; } do_thing(); }`
	if k := kindOf(t, body); k != GuardNone {
		t.Errorf("kind = %v, want GuardNone: the branch falls through, so nothing is gated", k)
	}
}

// TestGuardPositiveBranchOnlyGatesItsBranch is the over-restriction case that
// motivated this file: an admin-only branch beside an unguarded one.
func TestGuardPositiveBranchOnlyGatesItsBranch(t *testing.T) {
	body := `{
		if ( current_user_can( 'manage_options' ) ) { admin_only(); }
		save_setting( $_POST['value'] );
	}`
	if k := kindOf(t, body); k != GuardBranch {
		t.Errorf("kind = %v, want GuardBranch: save_setting() runs regardless", k)
	}
	if _, gated := StrongestGuard(body); gated {
		t.Errorf("StrongestGuard reported the function gated; the last statement is unguarded")
	}
}

// TestGuardPositiveWrappingWholeBodyDoesGate is the counterpart: when the
// positive branch is everything, there is no unprotected tail.
func TestGuardPositiveWrappingWholeBodyDoesGate(t *testing.T) {
	body := `{
		if ( current_user_can( 'manage_options' ) ) {
			admin_only();
			save_setting( $_POST['value'] );
		}
	}`
	if k := kindOf(t, body); k != GuardFunction {
		t.Errorf("kind = %v, want GuardFunction: the branch covers the whole body", k)
	}
}

// TestGuardAssignmentIsNotAGuard covers capability checks used for display
// logic, which are common and gate nothing.
func TestGuardAssignmentIsNotAGuard(t *testing.T) {
	bodies := []string{
		`{ $can_edit = current_user_can( 'edit_posts' ); render( $can_edit ); do_thing(); }`,
		`{ $data = array( 'can' => current_user_can( 'manage_options' ) ); echo json_encode( $data ); }`,
	}
	for _, b := range bodies {
		if k := kindOf(t, b); k != GuardNone {
			t.Errorf("kind = %v, want GuardNone for %q", k, b)
		}
	}
}

// TestStrongestGuardTakesEveryGatingCapability: when several checks each gate
// the function, an attacker needs only the weakest, so all are returned for the
// caller to resolve and minimise.
func TestStrongestGuardTakesEveryGatingCapability(t *testing.T) {
	body := `{
		if ( ! current_user_can( 'edit_posts' ) ) { wp_die(); }
		if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
		do_thing();
	}`
	caps, gated := StrongestGuard(body)
	if !gated {
		t.Fatalf("expected the function to be gated")
	}
	if len(caps) != 2 {
		t.Errorf("caps = %v, want both capabilities", caps)
	}
}

// TestCapabilityFromVariableIsRecordedWithoutName: a capability held in a
// variable still gates, but its level cannot be resolved. Reporting the gate
// with an empty name lets the caller decide, rather than inventing a level.
func TestCapabilityFromVariableIsRecordedWithoutName(t *testing.T) {
	body := `{ if ( ! current_user_can( $this->cap ) ) { wp_die(); } do_thing(); }`
	gs := FindCapabilityGuards(body)
	if len(gs) != 1 {
		t.Fatalf("expected one guard, got %d", len(gs))
	}
	if gs[0].Kind != GuardFunction {
		t.Errorf("kind = %v, want GuardFunction", gs[0].Kind)
	}
	if gs[0].Capability != "" {
		t.Errorf("capability = %q, want empty for a variable", gs[0].Capability)
	}
}

// TestGuardIgnoresParensInStrings keeps a ")" inside a capability string from
// ending the argument scan early.
func TestGuardIgnoresParensInStrings(t *testing.T) {
	body := `{ if ( ! current_user_can( 'weird)cap' ) ) { wp_die(); } do_thing(); }`
	gs := FindCapabilityGuards(body)
	if len(gs) != 1 || gs[0].Capability != "weird)cap" {
		t.Errorf("guards = %+v, want one guard for 'weird)cap'", gs)
	}
}

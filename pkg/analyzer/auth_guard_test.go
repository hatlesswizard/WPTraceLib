package analyzer

import (
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// TestInferAuthLevelIgnoresNonGatingChecks is the behaviour change: a handler
// whose vulnerable statement is not protected must not inherit the level of a
// capability check that guards something else. Reporting Admin here is the
// dangerous direction of error -- it makes a reachable vulnerability look gated.
func TestInferAuthLevelIgnoresNonGatingChecks(t *testing.T) {
	cases := []struct {
		name string
		code string
		want models.AuthLevel
	}{
		{
			"admin branch beside an unguarded one",
			`{
				if ( isset( $_POST['admin_op'] ) ) {
					if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
					admin_only();
				}
				save_setting( $_POST['value'] );
			}`,
			models.Unauthenticated,
		},
		{
			"capability used for display only",
			`{ $can = current_user_can( 'manage_options' ); render( $can ); save_setting( $_POST['v'] ); }`,
			models.Unauthenticated,
		},
		{
			"negated check that falls through",
			`{ if ( ! current_user_can( 'manage_options' ) ) { $err = 1; } save_setting( $_POST['v'] ); }`,
			models.Unauthenticated,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := InferAuthLevel(c.code); got != c.want {
				t.Errorf("InferAuthLevel = %s, want %s", got, c.want)
			}
		})
	}
}

// TestInferAuthLevelHonoursRealGuards is the other half: a check that really
// does gate the body must still produce its level, or the fix would trade one
// error direction for the other.
func TestInferAuthLevelHonoursRealGuards(t *testing.T) {
	cases := []struct {
		name string
		code string
		want models.AuthLevel
	}{
		{
			"negated check that terminates",
			`{ if ( ! current_user_can( 'manage_options' ) ) { wp_die(); } save_setting( $_POST['v'] ); }`,
			models.Admin,
		},
		{
			"positive check wrapping the whole body",
			`{ if ( current_user_can( 'manage_options' ) ) { save_setting( $_POST['v'] ); } }`,
			models.Admin,
		},
		{
			"edit_posts gate",
			`{ if ( ! current_user_can( 'edit_posts' ) ) { return; } save_setting( $_POST['v'] ); }`,
			models.Contributor,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := InferAuthLevel(c.code); got != c.want {
				t.Errorf("InferAuthLevel = %s, want %s", got, c.want)
			}
		})
	}
}

// TestInferAuthLevelTakesWeakestGate: when several checks each gate the body,
// an attacker needs only the weakest of them.
func TestInferAuthLevelTakesWeakestGate(t *testing.T) {
	code := `{
		if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
		if ( ! current_user_can( 'edit_posts' ) ) { wp_die(); }
		save_setting( $_POST['v'] );
	}`
	if got := InferAuthLevel(code); got != models.Contributor {
		t.Errorf("InferAuthLevel = %s, want contributor (the weakest gate)", got)
	}
}

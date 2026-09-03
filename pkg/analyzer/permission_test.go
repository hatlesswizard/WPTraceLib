package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// TestPermissionCallbackThatChecksNothingIsUnauthenticated is D7.
//
// ParsePermissionCallbackWithContext used to find the callback body, analyse it,
// get Unauthenticated back, and then discard that result on the reasoning that
// "the presence of a named callback suggests auth is required". A
// permission_callback may check anything, and many check something that is not
// identity at all. This shape is taken from CVE-2024-11028: every value the
// callback inspects comes from the request, so it establishes no privilege, and
// reporting Subscriber overstates what an attacker needs.
func TestPermissionCallbackThatChecksNothingIsUnauthenticated(t *testing.T) {
	content := `<?php
class API {
	public function register() {
		register_rest_route( 'ns/v1', '/impersonate', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'impersonate_user' ),
			'permission_callback' => array( $this, 'impersonate_user_permissions_check' ),
		) );
	}

	public function impersonate_user_permissions_check( $request ) {
		$name  = sanitize_text_field( $request->get_param( 'username' ) );
		$token = sanitize_text_field( $request->get_param( 'login_token' ) );
		if ( empty( $name ) || empty( $token ) ) {
			return new WP_Error( 'no_auth_token', 'Authorization token not found.' );
		}
		return $this->token_check( $name, $token );
	}
}
`
	args := content[strings.Index(content, "array(") : strings.Index(content, ") );")+1]
	cb, level := ParsePermissionCallbackWithContext(args, content)
	if cb == "" {
		t.Fatalf("the permission callback was not identified at all")
	}
	if level != models.Unauthenticated {
		t.Errorf("level = %s, want unauthenticated: the callback asserts no privilege", level)
	}
}

// TestPermissionCallbackWithRealCheckStillReported guards the other direction:
// the fix must not stop a genuine capability check from being reported.
func TestPermissionCallbackWithRealCheckStillReported(t *testing.T) {
	content := `<?php
class API {
	public function register() {
		register_rest_route( 'ns/v1', '/settings', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'save_settings' ),
			'permission_callback' => array( $this, 'settings_permissions_check' ),
		) );
	}

	public function settings_permissions_check( $request ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'forbidden', 'Nope' );
		}
		return true;
	}
}
`
	args := content[strings.Index(content, "array(") : strings.Index(content, ") );")+1]
	_, level := ParsePermissionCallbackWithContext(args, content)
	if level != models.Admin {
		t.Errorf("level = %s, want admin: the callback gates on manage_options", level)
	}
}

// TestAjaxNameDoesNotPromoteToAdmin is D8.
//
// isLikelyAdminAction matched ~50 English verbs and nouns that occur in most
// action names, promoting 818 of 3478 logged-in AJAX endpoints across 143
// plugins to Admin with no gating capability check anywhere in the file.
// Dismissing a notice is something any logged-in user does.
func TestAjaxNameDoesNotPromoteToAdmin(t *testing.T) {
	for _, action := range []string{
		"analyst_notification_dismiss",
		"inisev_review",
		"myplugin_save_sort_order",
		"myplugin_add_folder",
		"myplugin_delete_folder",
		"hide_helper_notice",
	} {
		content := `<?php
add_action( 'wp_ajax_` + action + `', array( $this, 'handler' ) );
class C {
	public function handler() {
		update_option( 'x', $_POST['v'] );
	}
}
`
		eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
		for _, ep := range eps {
			if ep.AuthLevel == models.Admin {
				t.Errorf("action %q was promoted to Admin with no capability check in sight", action)
			}
			if ep.AuthLevel != models.Subscriber {
				t.Errorf("action %q level = %s, want subscriber (the wp_ajax_ floor)", action, ep.AuthLevel)
			}
		}
	}
}

// TestAjaxRealCapabilityCheckStillRaises: removing the name heuristic must not
// stop a genuine gate from being honoured.
func TestAjaxRealCapabilityCheckStillRaises(t *testing.T) {
	content := `<?php
add_action( 'wp_ajax_myplugin_save_settings', array( $this, 'handler' ) );
class C {
	public function handler() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
		update_option( 'x', $_POST['v'] );
	}
}
`
	eps := DetectAJAXEndpoints(content, "a.php", "testplugin")
	found := false
	for _, ep := range eps {
		if ep.AuthLevel == models.Admin {
			found = true
		}
	}
	if !found {
		t.Errorf("a real manage_options gate was not honoured; endpoints = %+v", eps)
	}
}

// TestShortcodeInfersFromCallbackBody is D6: shortcode.go hardcoded every
// endpoint to Unauthenticated while widget.go and block.go already inferred
// from the callback body.
func TestShortcodeInfersFromCallbackBody(t *testing.T) {
	content := `<?php
add_shortcode( 'myplugin_admin_report', 'myplugin_render_report' );
function myplugin_render_report( $atts ) {
	if ( ! current_user_can( 'manage_options' ) ) { return ''; }
	return render_report();
}
`
	eps := DetectShortcodes(content, "a.php", "testplugin")
	if len(eps) == 0 {
		t.Fatalf("no shortcode endpoint detected")
	}
	for _, ep := range eps {
		if ep.AuthLevel != models.Admin {
			t.Errorf("shortcode level = %s, want admin: its callback gates on manage_options", ep.AuthLevel)
		}
	}
}

// TestShortcodeWithoutCheckStaysUnauthenticated keeps the default: a shortcode
// renders in post content for any visitor.
func TestShortcodeWithoutCheckStaysUnauthenticated(t *testing.T) {
	content := `<?php
add_shortcode( 'myplugin_public', 'myplugin_render_public' );
function myplugin_render_public( $atts ) {
	return esc_html( get_option( 'myplugin_text' ) );
}
`
	eps := DetectShortcodes(content, "a.php", "testplugin")
	if len(eps) == 0 {
		t.Fatalf("no shortcode endpoint detected")
	}
	for _, ep := range eps {
		if ep.AuthLevel != models.Unauthenticated {
			t.Errorf("shortcode level = %s, want unauthenticated", ep.AuthLevel)
		}
	}
}

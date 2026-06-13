package analyzer

import (
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

func TestAuditRESTCoverage_AllDetected(t *testing.T) {
	endpoints := []models.Endpoint{
		{
			Type:  models.EndpointTypeREST,
			Route: "/wp-json/myapi/v1/items",
			File:  "includes/api.php",
			Line:  2,
		},
	}

	cache := map[string]string{
		"includes/api.php": "<?php\nregister_rest_route('myapi/v1', '/items', array('methods' => 'GET', 'callback' => 'get_items'));",
	}

	report := AuditRESTCoverage("", endpoints, cache)

	if report.TotalRESTRouteCalls != 1 {
		t.Errorf("Expected 1 total call, got %d", report.TotalRESTRouteCalls)
	}
	if len(report.Gaps) != 0 {
		t.Errorf("Expected 0 gaps, got %d", len(report.Gaps))
	}
}

func TestAuditRESTCoverage_GapDetected(t *testing.T) {
	endpoints := []models.Endpoint{}

	cache := map[string]string{
		"includes/wrapper.php": "<?php\nclass Handler {\n    public function init() {\n        add_action('rest_api_init', function() use ($endpoint) {\n            register_rest_route($this->namespace, '/secret', array('methods' => 'POST', 'callback' => array($this, 'handle')));\n        });\n    }\n}",
	}

	report := AuditRESTCoverage("", endpoints, cache)

	if report.TotalRESTRouteCalls != 1 {
		t.Errorf("Expected 1 total call, got %d", report.TotalRESTRouteCalls)
	}
	if len(report.Gaps) != 1 {
		t.Fatalf("Expected 1 gap, got %d", len(report.Gaps))
	}
	if report.Gaps[0].Reason != "wrapper_pattern" {
		t.Errorf("Expected reason 'wrapper_pattern', got '%s'", report.Gaps[0].Reason)
	}
}

func TestAuditRESTCoverage_LineNumberTolerance(t *testing.T) {
	// Endpoint detected at line 3, register_rest_route at line 5 (within ±3 tolerance)
	endpoints := []models.Endpoint{
		{
			Type:  models.EndpointTypeREST,
			Route: "/wp-json/ns/v1/items",
			File:  "includes/api.php",
			Line:  3,
		},
	}

	cache := map[string]string{
		"includes/api.php": "<?php\n// line 2\n// line 3\n// line 4\nregister_rest_route('ns/v1', '/items', array());",
	}

	report := AuditRESTCoverage("", endpoints, cache)

	if len(report.Gaps) != 0 {
		t.Errorf("Expected 0 gaps (line tolerance should cover ±3), got %d gaps", len(report.Gaps))
	}
}

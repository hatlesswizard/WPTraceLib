package analyzer

import (
	"regexp"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Package-level compiled regex patterns for widget detection
var (
	// Pattern 1: Class extends WP_Widget
	widgetClassPattern = regexp.MustCompile(
		`class\s+([A-Za-z_][A-Za-z0-9_]*)\s+extends\s+WP_Widget`,
	)

	// Pattern 2: parent::__construct('widget_id', ...)
	widgetConstructIdPattern = regexp.MustCompile(
		`parent\s*::\s*__construct\s*\(\s*['"]([^'"]+)['"]`,
	)

	// Pattern 3: WP_Widget::__construct('id', ...) style
	widgetDirectConstructPattern = regexp.MustCompile(
		`WP_Widget\s*::\s*__construct\s*\(\s*['"]([^'"]+)['"]`,
	)

	// Pattern 4: $this->WP_Widget('id', ...) - old PHP4 style
	widgetOldStylePattern = regexp.MustCompile(
		`\$this\s*->\s*WP_Widget\s*\(\s*['"]([^'"]+)['"]`,
	)

	// Pattern 5: register_widget('ClassName')
	registerWidgetStringPattern = regexp.MustCompile(
		`register_widget\s*\(\s*['"]([^'"]+)['"]`,
	)

	// Pattern 6: register_widget(ClassName::class)
	registerWidgetClassPattern = regexp.MustCompile(
		`register_widget\s*\(\s*([A-Za-z_][A-Za-z0-9_\\]*)::class`,
	)

	// Pattern 7: register_widget(new ClassName())
	registerWidgetNewPattern = regexp.MustCompile(
		`register_widget\s*\(\s*new\s+([A-Za-z_][A-Za-z0-9_\\]*)\s*\(`,
	)

	// Patterns to find widget methods
	// public function widget($args, $instance) { ... }
	widgetMethodPattern = regexp.MustCompile(
		`function\s+widget\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)`,
	)

	// public function form($instance) { ... }
	widgetFormMethodPattern = regexp.MustCompile(
		`function\s+form\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)`,
	)

	// public function update($new_instance, $old_instance) { ... }
	widgetUpdateMethodPattern = regexp.MustCompile(
		`function\s+update\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)`,
	)
)

// DetectWidgets finds all WP_Widget class definitions and returns them as endpoints.
// Creates two endpoints per widget:
// 1. widget:{id}:render - Frontend rendering (auth from widget() method analysis)
// 2. widget:{id}:admin - Admin form (always Admin level)
func DetectWidgets(content, filepath, pluginSlug string) []models.Endpoint {
	var endpoints []models.Endpoint

	// Find widget class definitions
	classMatches := widgetClassPattern.FindAllStringSubmatch(content, -1)
	if len(classMatches) == 0 {
		return endpoints
	}

	for _, classMatch := range classMatches {
		if len(classMatch) < 2 {
			continue
		}
		className := classMatch[1]

		// Try to find the widget ID from constructor
		widgetID := extractWidgetID(content, className)
		if widgetID == "" {
			// Use class name as fallback
			widgetID = strings.ToLower(className)
		}

		// Find the class body
		classBody := extractClassBody(content, className)
		if classBody == "" {
			continue
		}

		// Check if widget() method exists and handles input
		hasWidgetMethod := widgetMethodPattern.MatchString(classBody)
		hasFormMethod := widgetFormMethodPattern.MatchString(classBody)
		hasUpdateMethod := widgetUpdateMethodPattern.MatchString(classBody)

		// Create frontend render endpoint if widget() method exists
		if hasWidgetMethod {
			widgetMethodBody := findMethodBody("widget", classBody)
			authLevel := models.Unauthenticated // Frontend widgets are typically unauthenticated

			if widgetMethodBody != "" {
				// Check for auth patterns in widget method
				inferredAuth := InferAuthLevel(widgetMethodBody)
				if inferredAuth != models.Unauthenticated {
					authLevel = inferredAuth
				}
			}

			endpoints = append(endpoints, models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeWidget,
				Route:      "widget:" + widgetID + ":render",
				AuthLevel:  authLevel,
				Callback:   className + "::widget()",
				File:       filepath,
			})
		}

		// Create admin endpoint if form() or update() method exists
		if hasFormMethod || hasUpdateMethod {
			callback := className + "::form()"
			if hasUpdateMethod {
				callback = className + "::form()/update()"
			}

			endpoints = append(endpoints, models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeWidget,
				Route:      "widget:" + widgetID + ":admin",
				AuthLevel:  models.Admin, // Admin forms are always admin-level
				Callback:   callback,
				File:       filepath,
			})
		}
	}

	return endpoints
}

// extractWidgetID extracts the widget ID from the constructor
func extractWidgetID(content, className string) string {
	// First try to find widget ID in class body
	classBody := extractClassBody(content, className)
	if classBody == "" {
		return ""
	}

	// Try parent::__construct('widget_id', ...)
	if m := widgetConstructIdPattern.FindStringSubmatch(classBody); len(m) >= 2 {
		return m[1]
	}

	// Try WP_Widget::__construct('id', ...)
	if m := widgetDirectConstructPattern.FindStringSubmatch(classBody); len(m) >= 2 {
		return m[1]
	}

	// Try $this->WP_Widget('id', ...)
	if m := widgetOldStylePattern.FindStringSubmatch(classBody); len(m) >= 2 {
		return m[1]
	}

	return ""
}

// extractClassBody extracts the body of a class definition
func extractClassBody(content, className string) string {
	// Find: class ClassName extends ... {
	pattern := regexp.MustCompile(
		`class\s+` + regexp.QuoteMeta(className) + `\s+[^{]*\{`,
	)

	loc := pattern.FindStringIndex(content)
	if loc == nil {
		return ""
	}

	// Find the opening brace
	braceStart := strings.Index(content[loc[0]:], "{")
	if braceStart == -1 {
		return ""
	}

	startPos := loc[0] + braceStart
	return extractBracedContent(content, startPos)
}

// findMethodBody finds a method definition within a class body and extracts its body
func findMethodBody(methodName, classBody string) string {
	// Pattern: function methodName(...) { ... }
	pattern := regexp.MustCompile(
		`function\s+` + regexp.QuoteMeta(methodName) + `\s*\([^)]*\)\s*\{`,
	)

	loc := pattern.FindStringIndex(classBody)
	if loc == nil {
		return ""
	}

	// Find the opening brace
	braceStart := strings.Index(classBody[loc[0]:], "{")
	if braceStart == -1 {
		return ""
	}

	startPos := loc[0] + braceStart
	return extractBracedContent(classBody, startPos)
}

package analyzer

import (
	"regexp"
	"sort"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Package-level compiled regex patterns for widget detection
var (
	// Pattern 1: Class extends WP_Widget.
	//
	// The backslash is optional because a namespaced file must write the core
	// class fully qualified -- `class Foo extends \WP_Widget` -- and requiring
	// whitespace immediately before the name made every one of those invisible.
	// No word boundary follows the name on purpose: a class extending a core
	// subclass such as WP_Widget_Text is a widget too, and core calls the same
	// three methods on it.
	widgetClassPattern = regexp.MustCompile(
		`class\s+([A-Za-z_][A-Za-z0-9_]*)\s+extends\s+\\?WP_Widget`,
	)

	// Pattern 2: parent::__construct('widget_id', ...)
	widgetConstructIdPattern = regexp.MustCompile(
		`parent\s*::\s*__construct\s*\(\s*['"]([^'"]+)['"]`,
	)

	// Pattern 3: WP_Widget::__construct('id', ...) style
	widgetDirectConstructPattern = regexp.MustCompile(
		`\\?WP_Widget\s*::\s*__construct\s*\(\s*['"]([^'"]+)['"]`,
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

	// The three methods WordPress core invokes on a registered widget. Only the
	// name is matched, not a parameter list.
	//
	// These used to insist on exactly two (or one) plain `$var` parameters, which
	// is the signature in the core docblock and not the signature plugins write:
	// `function widget( $args, $instance = array() )` and
	// `public function form( array $instance )` both failed, and the class then
	// produced no endpoint at all. Inside a WP_Widget subclass a method named
	// widget, form or update IS the override, because those are the names
	// WP_Widget::widget_callback, ::form_callback and ::update_callback call.
	widgetMethodPattern = regexp.MustCompile(`function\s+widget\s*\(`)

	widgetFormMethodPattern = regexp.MustCompile(`function\s+form\s*\(`)

	widgetUpdateMethodPattern = regexp.MustCompile(`function\s+update\s*\(`)
)

// DetectWidgets finds WP_Widget subclasses and returns them as endpoints.
//
// WordPress core invokes exactly three methods on a registered widget, and each
// is reached at a different privilege:
//
//   - widget()  -- dynamic_sidebar() renders it on a front-end page, so any
//     visitor reaches it. Unauthenticated unless the body itself gates.
//   - form()    -- WP_Widget::form_callback(), from wp-admin/widgets.php and the
//     /wp/v2/widgets REST route, both behind edit_theme_options.
//   - update()  -- WP_Widget::update_callback(), same screen, same capability.
//
// form() and update() are separate endpoints rather than one, because they are
// separate functions reached by separate requests and a call graph can only walk
// from a name that denotes one of them.
func DetectWidgets(content, filepath, pluginSlug string) []models.Endpoint {
	var endpoints []models.Endpoint

	classes := widgetClassNames(content)
	if len(classes) == 0 {
		return endpoints
	}

	for _, className := range classes {
		declOffset := findClassDeclOffset(content, className)
		if declOffset < 0 {
			continue
		}
		// The declaration's own line. Line was left unset on every widget
		// endpoint before, which is not a position any declaration has.
		declLine := countLines(content[:declOffset]) + 1

		// Try to find the widget ID from the constructor
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
				Callback:   className + "::widget",
				File:       filepath,
				Line:       declLine,
			})
		}

		// The admin-side endpoints. Both are edit_theme_options, which is an
		// administrator capability on a stock single site.
		if hasFormMethod {
			endpoints = append(endpoints, models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeWidget,
				Route:      "widget:" + widgetID + ":form",
				AuthLevel:  models.Admin,
				Callback:   className + "::form",
				File:       filepath,
				Line:       declLine,
			})
		}
		if hasUpdateMethod {
			endpoints = append(endpoints, models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeWidget,
				Route:      "widget:" + widgetID + ":update",
				AuthLevel:  models.Admin,
				Callback:   className + "::update",
				File:       filepath,
				Line:       declLine,
			})
		}
	}

	return endpoints
}

// widgetClassNames returns the widget classes declared in this file, in a stable
// order.
//
// Two sources feed it. The first is a direct `extends WP_Widget`. The second is
// register_widget(): core's register_widget() ends in
// WP_Widget_Factory::register(), which constructs the named class and calls
// $widget->_register(), so a class name handed to it is a WP_Widget subclass by
// the API's own contract however deep its own inheritance goes. That covers the
// plugins -- 58 of the 143 corpus trees call register_widget() while only 35
// contain a literal `extends WP_Widget` -- whose widgets extend an intermediate
// base class of their own.
//
// The registration must name a class declared in this same file, because that is
// as far as a per-file detector can see. Resolving a registration whose class
// lives elsewhere needs the AST class hierarchy (Resolver.IsSubclassOf), which
// this function is not given.
func widgetClassNames(content string) []string {
	seen := map[string]bool{}
	var names []string

	add := func(n string) {
		n = strings.TrimSpace(strings.Trim(n, `\`))
		if i := strings.LastIndex(n, `\`); i >= 0 {
			n = n[i+1:]
		}
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		names = append(names, n)
	}

	for _, m := range widgetClassPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			add(m[1])
		}
	}

	for _, pat := range []*regexp.Regexp{
		registerWidgetStringPattern,
		registerWidgetClassPattern,
		registerWidgetNewPattern,
	} {
		for _, m := range pat.FindAllStringSubmatch(content, -1) {
			if len(m) < 2 {
				continue
			}
			name := m[1]
			// Only a class this file declares can have its body read here.
			if findClassDeclOffset(content, strings.TrimPrefix(name, `\`)) >= 0 {
				add(name)
			}
		}
	}

	sort.Strings(names)
	return names
}

// findClassDeclOffset returns the byte offset of the `class` keyword declaring
// className, or -1.
func findClassDeclOffset(content, className string) int {
	if className == "" {
		return -1
	}
	if i := strings.LastIndex(className, `\`); i >= 0 {
		className = className[i+1:]
	}
	pat := regexp.MustCompile(`class\s+` + regexp.QuoteMeta(className) + `\b`)
	loc := pat.FindStringIndex(content)
	if loc == nil {
		return -1
	}
	return loc[0]
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
	// Find: class ClassName [extends ...] {
	//
	// The word boundary keeps `class Foo` from matching `class FooBar`, and the
	// clause between the name and the brace is optional so that a class with no
	// parent -- `class Foo {` -- is found as well as one with an extends clause.
	pattern := regexp.MustCompile(
		`class\s+` + regexp.QuoteMeta(className) + `\b[^{]*\{`,
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

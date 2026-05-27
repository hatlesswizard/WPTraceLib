package analyzer

import (
	"regexp"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Package-level compiled regex patterns for shortcode detection.
// All patterns use (?s) to allow \s to match newlines for multi-line registrations.
var (
	// ============================================================
	// Group A: String-literal tag patterns (tag is a quoted string)
	// ============================================================

	// Pattern 1: Simple string callback
	// add_shortcode('tag', 'function_name')
	shortcodeStringCallbackPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 2: Array with $this
	// add_shortcode('tag', array($this, 'method'))
	shortcodeThisArrayPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*array\s*\(\s*\$this\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 3: Short array [$this, 'method']
	// add_shortcode('tag', [$this, 'method'])
	shortcodeThisBracketPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*\[\s*\$this\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 4: Static method string
	// add_shortcode('tag', 'ClassName::method')
	shortcodeStaticStringPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([A-Za-z_][A-Za-z0-9_\\]*::[\$a-zA-Z_][a-zA-Z0-9_]*)['"]`,
	)

	// Pattern 5: Anonymous function with string tag
	// add_shortcode('tag', function($atts) { ... })
	shortcodeAnonFuncPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*function\s*\(`,
	)

	// Pattern 6: __CLASS__ constant with array()
	// add_shortcode('tag', array(__CLASS__, 'method'))
	shortcodeClassConstArrayPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*array\s*\(\s*__CLASS__\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 7: __CLASS__ constant with []
	// add_shortcode('tag', [__CLASS__, 'method'])
	shortcodeClassConstBracketPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*\[\s*__CLASS__\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 8: ClassName::class with []
	// add_shortcode('tag', [ClassName::class, 'method'])
	shortcodeClassMethodPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*\[\s*([A-Za-z_][A-Za-z0-9_\\]*)::class\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 9: self/static with array/bracket
	// add_shortcode('tag', [self, 'method']) or array(self, 'method')
	shortcodeSelfPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*(?:array\s*\(|\[)\s*(?:self|static)\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 10: &$this reference with array()
	// add_shortcode('tag', array(&$this, 'method'))
	shortcodeRefThisArrayPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*array\s*\(\s*&\$this\s*,\s*['"]([^'"]+)['"]`,
	)

	// ============================================================
	// Group B: Variable/dynamic tag patterns
	// ============================================================

	// Pattern 11: Variable tag with $this array callback
	// add_shortcode($tag, array($this, 'method'))
	// add_shortcode($tag, [$this, 'method'])
	shortcodeVarTagThisPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*(?:array\s*\(\s*(?:&?\$this)\s*,\s*['"]([^'"]+)['"]|\[\s*(?:&?\$this)\s*,\s*['"]([^'"]+)['"])`,
	)

	// Pattern 12: Variable tag with string callback
	// add_shortcode($tag, 'function_name')
	// add_shortcode($tag, $callback)
	shortcodeVarTagStringPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 13: Variable tag with anonymous function
	// add_shortcode($tag, function($atts) { ... })
	shortcodeVarTagAnonPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*function\s*\(`,
	)

	// Pattern 14: self::CONST tag with callback
	// add_shortcode(self::SHORTCODE, array($this, 'method'))
	// add_shortcode(self::SHORTCODE, [$this, 'method'])
	// add_shortcode(self::SHORTCODE, [self, 'method'])
	shortcodeSelfConstTagPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*(?:self|static)::\$?([A-Z_][A-Z0-9_]*)\s*,\s*(?:array\s*\(\s*(?:&?\$this|self|static|__CLASS__)\s*,\s*['"]([^'"]+)['"]|\[\s*(?:&?\$this|self|static|__CLASS__)\s*,\s*['"]([^'"]+)['"])`,
	)

	// Pattern 15: self::CONST tag with string callback
	// add_shortcode(self::SHORTCODE, 'function_name')
	shortcodeSelfConstTagStringPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*(?:self|static)::\$?([A-Z_][A-Z0-9_]*)\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 16: $this->property tag
	// add_shortcode($this->tag, [$this, 'method'])
	// add_shortcode($this->shortcode, array($this, 'render'))
	shortcodeThisPropTagPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*\$this->([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*(?:array\s*\(\s*(?:&?\$this)\s*,\s*['"]([^'"]+)['"]|\[\s*(?:&?\$this)\s*,\s*['"]([^'"]+)['"])`,
	)

	// Pattern 17: $this->method() tag (method call returns tag name)
	// add_shortcode($this->tag(), [$this, 'handler'])
	shortcodeThisMethodTagPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*\$this->([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)\s*,\s*(?:array\s*\(\s*(?:&?\$this)\s*,\s*['"]([^'"]+)['"]|\[\s*(?:&?\$this)\s*,\s*['"]([^'"]+)['"])`,
	)

	// Pattern 18: Concatenated/expression tag with $this callback
	// add_shortcode($this->prefix . $this->shortcode_name, array($this, 'render'))
	shortcodeConcatTagPattern = regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*([^,]+?)\s*,\s*(?:array\s*\(\s*(?:&?\$this)\s*,\s*['"]([^'"]+)['"]|\[\s*(?:&?\$this)\s*,\s*['"]([^'"]+)['"])`,
	)

	// Patterns for detecting POST/GET/REQUEST access in callback body
	shortcodePostGetPattern = regexp.MustCompile(
		`\$_(POST|GET|REQUEST)\s*\[\s*['"]([^'"]+)['"]\s*\]`,
	)

	shortcodeFilterInputPattern = regexp.MustCompile(
		`filter_input\s*\(\s*INPUT_(POST|GET|REQUEST)\s*,\s*['"]([^'"]+)['"]`,
	)

	shortcodeIssetPattern = regexp.MustCompile(
		`(?:isset|empty)\s*\(\s*\$_(POST|GET|REQUEST)\s*\[\s*['"]([^'"]+)['"]\s*\]`,
	)

	shortcodePostDirectPattern = regexp.MustCompile(
		`\$_(POST|GET|REQUEST)\b`,
	)
)

// DetectShortcodes finds all shortcode registrations and returns them as endpoints.
// Shortcodes are always unauthenticated (they render in post content for any visitor),
// so all detected shortcodes are reported regardless of whether they process POST/GET input.
func DetectShortcodes(content, filepath, pluginSlug string) []models.Endpoint {
	var endpoints []models.Endpoint

	type shortcodeMatch struct {
		tag      string
		callback string
		isAnon   bool
	}

	var matches []shortcodeMatch

	// ============================================================
	// Group A: String-literal tag patterns
	// ============================================================

	// Pattern 1: Simple string callback
	for _, m := range shortcodeStringCallbackPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2]})
		}
	}

	// Pattern 2: Array with $this
	for _, m := range shortcodeThisArrayPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2]})
		}
	}

	// Pattern 3: Short array [$this, 'method']
	for _, m := range shortcodeThisBracketPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2]})
		}
	}

	// Pattern 4: Static method string
	for _, m := range shortcodeStaticStringPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2]})
		}
	}

	// Pattern 5: Anonymous function
	for _, m := range shortcodeAnonFuncPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: "anonymous", isAnon: true})
		}
	}

	// Pattern 6: __CLASS__ with array()
	for _, m := range shortcodeClassConstArrayPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2]})
		}
	}

	// Pattern 7: __CLASS__ with []
	for _, m := range shortcodeClassConstBracketPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2]})
		}
	}

	// Pattern 8: ClassName::class with []
	for _, m := range shortcodeClassMethodPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 4 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2] + "::" + m[3]})
		}
	}

	// Pattern 9: self/static
	for _, m := range shortcodeSelfPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2]})
		}
	}

	// Pattern 10: &$this reference
	for _, m := range shortcodeRefThisArrayPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2]})
		}
	}

	// ============================================================
	// Group B: Variable/dynamic tag patterns
	// These use the variable expression as a placeholder tag name.
	// ============================================================

	// Pattern 11: Variable tag with $this callback
	for _, m := range shortcodeVarTagThisPattern.FindAllStringSubmatch(content, -1) {
		callback := m[2]
		if callback == "" {
			callback = m[3]
		}
		if callback != "" {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: callback})
		}
	}

	// Pattern 12: Variable tag with string callback
	for _, m := range shortcodeVarTagStringPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: m[2]})
		}
	}

	// Pattern 13: Variable tag with anonymous function
	for _, m := range shortcodeVarTagAnonPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			matches = append(matches, shortcodeMatch{tag: m[1], callback: "anonymous", isAnon: true})
		}
	}

	// Pattern 14: self::CONST tag with $this/self callback
	for _, m := range shortcodeSelfConstTagPattern.FindAllStringSubmatch(content, -1) {
		callback := m[2]
		if callback == "" {
			callback = m[3]
		}
		if callback != "" {
			tag := "self::" + m[1]
			matches = append(matches, shortcodeMatch{tag: tag, callback: callback})
		}
	}

	// Pattern 15: self::CONST tag with string callback
	for _, m := range shortcodeSelfConstTagStringPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			tag := "self::" + m[1]
			matches = append(matches, shortcodeMatch{tag: tag, callback: m[2]})
		}
	}

	// Pattern 16: $this->property tag
	for _, m := range shortcodeThisPropTagPattern.FindAllStringSubmatch(content, -1) {
		callback := m[2]
		if callback == "" {
			callback = m[3]
		}
		if callback != "" {
			tag := "$this->" + m[1]
			matches = append(matches, shortcodeMatch{tag: tag, callback: callback})
		}
	}

	// Pattern 17: $this->method() tag
	for _, m := range shortcodeThisMethodTagPattern.FindAllStringSubmatch(content, -1) {
		callback := m[2]
		if callback == "" {
			callback = m[3]
		}
		if callback != "" {
			tag := "$this->" + m[1] + "()"
			matches = append(matches, shortcodeMatch{tag: tag, callback: callback})
		}
	}

	// Pattern 18: Concatenated/expression tag (catch-all for complex expressions)
	// Only use matches not already caught by earlier patterns.
	for _, m := range shortcodeConcatTagPattern.FindAllStringSubmatch(content, -1) {
		callback := m[2]
		if callback == "" {
			callback = m[3]
		}
		if callback == "" {
			continue
		}
		tag := strings.TrimSpace(m[1])
		// Skip if this is a simple string literal or variable already matched above
		if len(tag) > 0 && tag[0] == '\'' || len(tag) > 0 && tag[0] == '"' {
			continue // Already handled by Group A patterns
		}
		// Skip simple $var patterns (already handled by pattern 11-13)
		if isSimpleVar(tag) {
			continue
		}
		// Skip self::CONST (already handled by pattern 14-15)
		if strings.HasPrefix(tag, "self::") || strings.HasPrefix(tag, "static::") {
			continue
		}
		// Skip $this->prop (already handled by pattern 16-17)
		if strings.HasPrefix(tag, "$this->") && !strings.Contains(tag, ".") && !strings.Contains(tag, " ") {
			continue
		}
		matches = append(matches, shortcodeMatch{tag: tag, callback: callback})
	}

	// Deduplicate by shortcode tag
	seen := make(map[string]bool)
	for _, sm := range matches {
		if seen[sm.tag] {
			continue
		}
		seen[sm.tag] = true

		// Determine the route display name
		routeTag := sm.tag
		isDynamic := false
		if strings.HasPrefix(routeTag, "$") || strings.HasPrefix(routeTag, "self::") || strings.HasPrefix(routeTag, "static::") || strings.Contains(routeTag, "->") || strings.Contains(routeTag, ".") {
			isDynamic = true
		}

		// Try to find callback body for optional metadata extraction
		var callbackBody string
		if sm.isAnon {
			callbackBody = extractShortcodeAnonBody(content, sm.tag)
		} else {
			methodName := sm.callback
			if idx := strings.LastIndex(sm.callback, "::"); idx != -1 {
				methodName = sm.callback[idx+2:]
			}
			callbackBody = findFunctionBody(methodName, content)
		}

		// Extract optional input field metadata (informational only, not a filter)
		fieldInfo := ""
		if callbackBody != "" {
			fields := extractInputFields(callbackBody)
			if len(fields) > 0 {
				fieldInfo = "[" + strings.Join(fields, ", ") + "]"
			}
		}

		// All shortcodes are unauthenticated - they render in post content for any visitor
		authLevel := models.Unauthenticated

		// Format the route
		route := "[" + routeTag + "]"
		if isDynamic {
			route = "[dynamic:" + routeTag + "]"
		}

		endpoints = append(endpoints, models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeShortcode,
			Route:      route,
			Method:     "SHORTCODE",
			AuthLevel:  authLevel,
			Callback:   sm.callback,
			File:       filepath,
			RawCode:    fieldInfo,
		})
	}

	return endpoints
}

// isSimpleVar returns true if the string is a simple PHP variable like $tag, $name, etc.
func isSimpleVar(s string) bool {
	if len(s) < 2 || s[0] != '$' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// extractInputFields extracts all POST/GET/REQUEST field names from code
func extractInputFields(code string) []string {
	fields := make(map[string]bool)

	// $_POST['field'], $_GET['field'], $_REQUEST['field']
	for _, m := range shortcodePostGetPattern.FindAllStringSubmatch(code, -1) {
		if len(m) >= 3 {
			fields[m[1]+":"+m[2]] = true
		}
	}

	// filter_input(INPUT_POST, 'field')
	for _, m := range shortcodeFilterInputPattern.FindAllStringSubmatch(code, -1) {
		if len(m) >= 3 {
			fields[m[1]+":"+m[2]] = true
		}
	}

	// isset($_POST['field'])
	for _, m := range shortcodeIssetPattern.FindAllStringSubmatch(code, -1) {
		if len(m) >= 3 {
			fields[m[1]+":"+m[2]] = true
		}
	}

	// Convert to slice
	result := make([]string, 0, len(fields))
	for f := range fields {
		result = append(result, f)
	}
	return result
}

// extractShortcodeAnonBody extracts the body of an anonymous function registered as a shortcode callback
func extractShortcodeAnonBody(content, shortcodeTag string) string {
	// Find: add_shortcode('tag', function(...) { ... })
	// Use (?s) for multi-line matching
	pattern := regexp.MustCompile(
		`(?s)add_shortcode\s*\(\s*['"]` + regexp.QuoteMeta(shortcodeTag) + `['"]\s*,\s*function\s*\([^)]*\)\s*\{`,
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

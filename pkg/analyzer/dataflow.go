package analyzer

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Package-level compiled patterns for data flow resolution.
var (
	// Detects {placeholder} in routes produced by unresolved dynamic action names.
	routeDynamicPlaceholderRe = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

	// foreach ($src as $this->prop)
	foreachDirectPropRe = regexp.MustCompile(
		`foreach\s*\(\s*(.*?)\s+as\s+\$this\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)`,
	)

	// foreach ($src as $var) — we then scan the body for $this->prop = $var
	foreachLoopVarRe = regexp.MustCompile(
		`foreach\s*\(\s*(.*?)\s+as\s+\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\)`,
	)

	// Last method call at the end of an expression: ->methodName()
	lastMethodCallRe = regexp.MustCompile(
		`->([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)\s*$`,
	)

	// String literals that look like WordPress action/hook names
	// (alphabetic start, alphanumeric+underscore body, min 2 chars)
	actionStringLiteralRe = regexp.MustCompile(`['"]([a-zA-Z_][a-zA-Z0-9_]{1,99})['"]`)

	// return statement up to the next semicolon (handles simple returns)
	returnStmtRe = regexp.MustCompile(`return\s+([^;]{1,500});`)

	// Class constant reference: self::CONST, static::CONST, ClassName::CONST
	classConstantRefRe = regexp.MustCompile(`(?:self|static|[A-Z][a-zA-Z0-9_]*)::([A-Z_][A-Z0-9_]*)`)

	// Class property reference: $this->propertyName
	classPropertyRefRe = regexp.MustCompile(`\$this->([a-zA-Z_][a-zA-Z0-9_]*)`)

	// const CONSTNAME = 'value' or "value"
	constDeclarationRe = regexp.MustCompile(`const\s+([A-Z_][A-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]`)

	// Property declaration: public/protected/private $prop = 'value'
	propertyDeclarationRe = regexp.MustCompile(`(?:public|protected|private)\s+\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]`)

	// Constructor assignment: $this->prop = 'value'
	constructorAssignRe = regexp.MustCompile(`\$this->([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]`)

	// Class declaration: class ClassName
	classDeclarationRe = regexp.MustCompile(`class\s+([A-Z][a-zA-Z0-9_]*)\s*(?:extends|implements|\{)`)
)

// ---------------------------------------------------------------------------
// Route helpers
// ---------------------------------------------------------------------------

// isDynamicRoute reports whether a route contains an unresolved {placeholder}.
func isDynamicRoute(route string) bool {
	return routeDynamicPlaceholderRe.MatchString(route)
}

// extractPlaceholderFromRoute returns the placeholder name from a dynamic route,
// e.g. "wp-admin/admin-ajax.php?action={_action}" → "_action".
func extractPlaceholderFromRoute(route string) string {
	m := routeDynamicPlaceholderRe.FindStringSubmatch(route)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Array literal helpers
// ---------------------------------------------------------------------------

// extractArrayStringLiterals returns all string literals from a PHP array expression.
// Input can be the full array literal ("array('a','b')") or just its content ("'a','b'").
func extractArrayStringLiterals(arrayExpr string) []string {
	matches := actionStringLiteralRe.FindAllStringSubmatch(arrayExpr, -1)
	if len(matches) == 0 {
		return nil
	}
	results := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			results = append(results, m[1])
		}
	}
	return results
}

// ---------------------------------------------------------------------------
// Method body extraction
// ---------------------------------------------------------------------------

// extractBodyFromPos extracts the balanced-brace body of a function/method
// starting at startPos (the character position just after the closing ')' of
// the parameter list).  Returns an empty string if no body is found.
func extractBodyFromPos(content string, startPos int) string {
	rel := strings.Index(content[startPos:], "{")
	if rel < 0 {
		return ""
	}
	open := startPos + rel
	depth := 1
	pos := open + 1
	for pos < len(content) && depth > 0 {
		switch content[pos] {
		case '{':
			depth++
		case '}':
			depth--
		}
		pos++
	}
	if depth != 0 {
		end := open + 2000
		if end > len(content) {
			end = len(content)
		}
		return content[open:end]
	}
	return content[open:pos]
}

// ---------------------------------------------------------------------------
// Source resolution helpers
// ---------------------------------------------------------------------------

// resolveSourceToStrings resolves a foreach source expression (the part before
// "as") into concrete string values.
//
// It handles three cases:
//  1. Inline literal array: array('a', 'b') or ['a', 'b']
//  2. Variable whose assignment is visible in the same file
//  3. Method call like $obj->methodName() — triggers cross-file search
func resolveSourceToStrings(source, fileContent string, allContents map[string]string) []string {
	source = strings.TrimSpace(source)

	// Case 1: inline literal array
	lower := strings.ToLower(source)
	if strings.HasPrefix(lower, "array(") || strings.HasPrefix(lower, "array (") || strings.HasPrefix(source, "[") {
		return extractArrayStringLiterals(source)
	}

	// Case 2: plain variable — look for its assignment in the same file
	if strings.HasPrefix(source, "$") &&
		!strings.Contains(source, "->") &&
		!strings.Contains(source, "(") {
		varName := strings.TrimPrefix(source, "$")
		varAssignRe := regexp.MustCompile(
			`\$` + regexp.QuoteMeta(varName) + `\s*=\s*(?:array\s*\(|\[)([^)\]]{0,500})(?:\)|\])`,
		)
		if m := varAssignRe.FindStringSubmatch(fileContent); len(m) > 1 {
			return extractArrayStringLiterals("array(" + m[1] + ")")
		}
	}

	// Case 3: method call — extract method name and search all files
	if m := lastMethodCallRe.FindStringSubmatch(source); len(m) > 1 {
		return extractMethodReturnStrings(m[1], fileContent, allContents)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Cross-file method return extraction
// ---------------------------------------------------------------------------

// extractMethodReturnStrings finds all definitions of a method named methodName
// across the current file and allContents, returning every string literal found
// in their return statements.
func extractMethodReturnStrings(methodName, currentFileContent string, allContents map[string]string) []string {
	searchOrder := make([]string, 0, len(allContents)+1)
	searchOrder = append(searchOrder, currentFileContent)
	for _, c := range allContents {
		if c != currentFileContent {
			searchOrder = append(searchOrder, c)
		}
	}

	var results []string
	for _, content := range searchOrder {
		found := extractReturnStringsFromContent(methodName, content)
		if len(found) > 0 {
			results = append(results, found...)
			// Keep scanning — there may be multiple definitions (e.g. child classes)
		}
	}
	return deduplicateStrings(results)
}

// extractReturnStringsFromContent finds the named function/method in content and
// returns all string literals from its return statements.
func extractReturnStringsFromContent(methodName, content string) []string {
	methodRe := regexp.MustCompile(`function\s+` + regexp.QuoteMeta(methodName) + `\s*\(`)
	loc := methodRe.FindStringIndex(content)
	if loc == nil {
		return nil
	}
	body := extractBodyFromPos(content, loc[1])
	if body == "" {
		return nil
	}

	var results []string
	for _, m := range returnStmtRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		results = append(results, extractArrayStringLiterals(m[1])...)
	}
	return results
}

// ---------------------------------------------------------------------------
// Foreach-based resolution (core of data flow logic)
// ---------------------------------------------------------------------------

// resolveFromForeach attempts to resolve a dynamic property/variable by finding
// foreach loops in fileContent where propName is the loop variable or is assigned
// from the loop variable.  It then traces the loop's source to concrete string values.
//
// propName is the raw name without sigil, e.g. "_action" for both $this->_action
// and $action.
func resolveFromForeach(propName, fileContent string, allContents map[string]string) []string {
	var results []string

	// Strategy A: foreach ($src as $this->PROPNAME)
	for _, m := range foreachDirectPropRe.FindAllStringSubmatch(fileContent, -1) {
		if len(m) < 3 || m[2] != propName {
			continue
		}
		results = append(results, resolveSourceToStrings(m[1], fileContent, allContents)...)
	}

	// Strategy B: foreach ($src as $var) { ... $this->PROPNAME = $var ... }
	//             or      foreach ($src as $var) { ... $PROPNAME = $var ... }
	for _, match := range foreachLoopVarRe.FindAllStringSubmatchIndex(fileContent, -1) {
		if len(match) < 6 {
			continue
		}
		source := strings.TrimSpace(fileContent[match[2]:match[3]])
		loopVar := fileContent[match[4]:match[5]]
		foreachEnd := match[1]

		searchEnd := foreachEnd + 1500
		if searchEnd > len(fileContent) {
			searchEnd = len(fileContent)
		}
		body := fileContent[foreachEnd:searchEnd]

		thisPropAssignRe := regexp.MustCompile(
			`\$this\s*->\s*` + regexp.QuoteMeta(propName) + `\s*=\s*\$` + regexp.QuoteMeta(loopVar),
		)
		simplePropAssignRe := regexp.MustCompile(
			`\$` + regexp.QuoteMeta(propName) + `\s*=\s*\$` + regexp.QuoteMeta(loopVar),
		)

		if thisPropAssignRe.MatchString(body) || simplePropAssignRe.MatchString(body) {
			results = append(results, resolveSourceToStrings(source, fileContent, allContents)...)
		}
	}

	return deduplicateStrings(results)
}

// ---------------------------------------------------------------------------
// Class constant and property resolution
// ---------------------------------------------------------------------------

// resolveClassConstant resolves self::CONSTANT, static::CONSTANT, or ClassName::CONSTANT
// by searching for const declarations in the class body.
func resolveClassConstant(className, constName, fileContent string, allContents map[string]string) string {
	// Build search order: current file first, then all others
	searchOrder := make([]string, 0, len(allContents)+1)
	searchOrder = append(searchOrder, fileContent)
	for _, c := range allContents {
		if c != fileContent {
			searchOrder = append(searchOrder, c)
		}
	}

	for _, content := range searchOrder {
		// For self::/static::, search any class in the file.
		// For ClassName::, only search inside that specific class.
		if className != "" {
			classRe := regexp.MustCompile(`class\s+` + regexp.QuoteMeta(className) + `\s*(?:extends|implements|\{)`)
			if !classRe.MatchString(content) {
				continue
			}
		}

		for _, m := range constDeclarationRe.FindAllStringSubmatch(content, -1) {
			if len(m) >= 3 && m[1] == constName {
				return m[2]
			}
		}
	}
	return ""
}

// resolveClassProperty resolves $this->property by finding where it's assigned
// in the constructor or in a property declaration.
func resolveClassProperty(propName, fileContent string, allContents map[string]string) []string {
	var results []string

	searchOrder := make([]string, 0, len(allContents)+1)
	searchOrder = append(searchOrder, fileContent)
	for _, c := range allContents {
		if c != fileContent {
			searchOrder = append(searchOrder, c)
		}
	}

	for _, content := range searchOrder {
		// Check property declarations: protected $prop = 'value'
		for _, m := range propertyDeclarationRe.FindAllStringSubmatch(content, -1) {
			if len(m) >= 3 && m[1] == propName {
				results = append(results, m[2])
			}
		}

		// Check constructor assignments: $this->prop = 'value'
		constructorRe := regexp.MustCompile(`function\s+__construct\s*\(`)
		loc := constructorRe.FindStringIndex(content)
		if loc != nil {
			body := extractBodyFromPos(content, loc[1])
			for _, m := range constructorAssignRe.FindAllStringSubmatch(body, -1) {
				if len(m) >= 3 && m[1] == propName {
					results = append(results, m[2])
				}
			}
		}
	}

	return deduplicateStrings(results)
}

// resolveConstantInRoute checks if a route or action string contains a class constant
// reference (self::X, static::X, ClassName::X) and resolves it inline.
func resolveConstantInRoute(route, fileContent string, allContents map[string]string) (string, bool) {
	// Match patterns like: self::NAMESPACE, static::SLUG, ClassName::VERSION
	re := regexp.MustCompile(`(self|static|[A-Z][a-zA-Z0-9_]*)::([A-Z_][A-Z0-9_]*)`)
	matches := re.FindAllStringSubmatchIndex(route, -1)
	if len(matches) == 0 {
		return route, false
	}

	// Determine current class name for self::/static:: resolution
	currentClass := ""
	if m := classDeclarationRe.FindStringSubmatch(fileContent); len(m) >= 2 {
		currentClass = m[1]
	}

	resolved := false
	result := route
	// Process matches in reverse order to preserve indices
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		fullMatch := route[m[0]:m[1]]
		qualifier := route[m[2]:m[3]]
		constName := route[m[4]:m[5]]

		className := ""
		if qualifier != "self" && qualifier != "static" {
			className = qualifier
		} else {
			className = currentClass
		}

		val := resolveClassConstant(className, constName, fileContent, allContents)
		if val != "" {
			result = strings.Replace(result, fullMatch, val, 1)
			resolved = true
		}
	}

	return result, resolved
}

// resolvePropertyInRoute checks if a route or action string contains $this->property
// references and resolves them inline.
func resolvePropertyInRoute(route, fileContent string, allContents map[string]string) (string, bool) {
	matches := classPropertyRefRe.FindAllStringSubmatchIndex(route, -1)
	if len(matches) == 0 {
		return route, false
	}

	resolved := false
	result := route
	// Process matches in reverse order to preserve indices
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		fullMatch := route[m[0]:m[1]]
		propName := route[m[2]:m[3]]

		vals := resolveClassProperty(propName, fileContent, allContents)
		if len(vals) > 0 {
			// Use first resolved value for inline replacement
			result = strings.Replace(result, fullMatch, vals[0], 1)
			resolved = true
		}
	}

	return result, resolved
}

// ---------------------------------------------------------------------------
// Post-processing pass
// ---------------------------------------------------------------------------

// resolveUnresolvedEndpoints is Pass 3.5 of the analysis pipeline.
//
// It iterates over all detected endpoints and, for those whose route contains
// an unresolved {placeholder}, attempts to resolve the placeholder using
// foreach-based data flow across all plugin file contents.
//
// Outcomes per dynamic endpoint:
//   - Resolved to N values → replaced by N concrete endpoints (auth level preserved).
//   - Unresolvable           → endpoint kept as-is with [dynamic:unresolved:…] appended
//     to RawCode so the caller can see it was identified but not fully resolved.
func resolveUnresolvedEndpoints(endpoints []models.Endpoint, allContents map[string]string, pluginDir string) []models.Endpoint {
	if len(endpoints) == 0 {
		return endpoints
	}

	result := make([]models.Endpoint, 0, len(endpoints))

	for _, ep := range endpoints {
		if !isDynamicRoute(ep.Route) {
			result = append(result, ep)
			continue
		}

		placeholder := extractPlaceholderFromRoute(ep.Route)
		if placeholder == "" {
			ep.RawCode = annotateUnresolved(ep.RawCode, "no-placeholder-extracted")
			result = append(result, ep)
			continue
		}

		var fileContent string
		if pluginDir != "" {
			fullPath := filepath.Join(pluginDir, ep.File)
			fileContent = allContents[fullPath]
		}
		// Fallback: scan allContents by suffix match
		if fileContent == "" {
			for filePath, content := range allContents {
				if strings.HasSuffix(filePath, string(filepath.Separator)+ep.File) ||
					strings.HasSuffix(filePath, "/"+ep.File) {
					fileContent = content
					break
				}
			}
		}

		// Try class constant resolution on the raw route first.
		// E.g. a route containing "self::NAMESPACE" or "ClassName::SLUG".
		resolvedRoute, constResolved := resolveConstantInRoute(ep.Route, fileContent, allContents)
		if constResolved {
			ep.Route = resolvedRoute
			// If the constant resolution eliminated the placeholder, we're done.
			if !isDynamicRoute(ep.Route) {
				ep.RawCode = ep.RawCode + " [resolved-from-constant:" + placeholder + "]"
				result = append(result, ep)
				continue
			}
		}

		// Try class property resolution on the raw route.
		// E.g. a route containing "$this->slug" or "$this->opt_name".
		resolvedRoute, propResolved := resolvePropertyInRoute(ep.Route, fileContent, allContents)
		if propResolved {
			ep.Route = resolvedRoute
			if !isDynamicRoute(ep.Route) {
				ep.RawCode = ep.RawCode + " [resolved-from-property:" + placeholder + "]"
				result = append(result, ep)
				continue
			}
		}

		// Fall back to foreach-based data flow resolution.
		resolvedNames := resolveFromForeach(placeholder, fileContent, allContents)

		if len(resolvedNames) == 0 {
			// Annotate but preserve — never silently drop a detected endpoint.
			ep.RawCode = annotateUnresolved(ep.RawCode, "$this->"+placeholder+" or $"+placeholder)
			result = append(result, ep)
			continue
		}

		for _, name := range resolvedNames {
			expanded := ep
			expanded.Route = routeDynamicPlaceholderRe.ReplaceAllString(ep.Route, name)
			expanded.RawCode = ep.RawCode + " [resolved-from-dynamic:" + placeholder + "]"
			result = append(result, expanded)
		}
	}

	return result
}

// annotateUnresolved appends a [dynamic:unresolved:…] tag to rawCode unless one
// is already present (idempotent).
func annotateUnresolved(rawCode, expr string) string {
	if strings.Contains(rawCode, "[dynamic:") {
		return rawCode
	}
	return rawCode + " [dynamic:unresolved:" + expr + "]"
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// deduplicateStrings returns a slice with duplicates removed, preserving order.
func deduplicateStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// isDynamicPlaceholder reports whether an action string is an unresolved placeholder
// such as "{_action}" produced by resolveDynamicAction when it cannot find a literal.
func isDynamicPlaceholder(action string) bool {
	return len(action) > 2 && action[0] == '{' && action[len(action)-1] == '}'
}

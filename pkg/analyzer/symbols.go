package analyzer

import (
	"regexp"
	"strings"
)

// Package-level compiled regex patterns for symbol resolution
var (
	// Class constant patterns - support both uppercase and lowercase constants
	phpConstPattern = regexp.MustCompile(
		`(?m)const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]`,
	)

	// Static property patterns
	phpStaticPropertyPattern = regexp.MustCompile(
		`(?m)(?:private|protected|public)?\s*static\s+\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]`,
	)

	// Instance property patterns (with default values)
	phpPropertyPattern = regexp.MustCompile(
		`(?m)(?:private|protected|public)\s+\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]`,
	)

	// Variable assignment patterns (for local context)
	phpVariableAssignPattern = regexp.MustCompile(
		`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]`,
	)

	// Constructor assignment patterns: $this->prop = 'value'
	phpThisAssignPattern = regexp.MustCompile(
		`\$this->([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]`,
	)

	// Array key access: $array['key']
	phpArrayKeyPattern = regexp.MustCompile(
		`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*['"]([^'"]+)['"]\s*\]`,
	)

	// Pattern to extract class name from file
	phpClassNamePattern = regexp.MustCompile(
		`(?m)^\s*(?:abstract\s+|final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)\s*`,
	)

	// Function/method parameter patterns
	phpFunctionParamPattern = regexp.MustCompile(
		`function\s+\w+\s*\([^)]*\$([a-zA-Z_][a-zA-Z0-9_]*)[^)]*\)`,
	)

	// Pre-compiled patterns for ExtractInterpolatedString (memory optimization)
	extractInterpBraceVarPattern = regexp.MustCompile(`\{\$([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	extractInterpSimpleVarPattern = regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)$`)

	// Pre-compiled patterns for ResolveInterpolatedString (memory optimization)
	resolveThisMethodPattern     = regexp.MustCompile(`\{\$this->([a-zA-Z_][a-zA-Z0-9_]*)\(\)\}`)
	resolveThisPropPattern       = regexp.MustCompile(`\{\$this->([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	resolveVarPattern            = regexp.MustCompile(`\{\$([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	resolveThisMethodNoBracePattern = regexp.MustCompile(`\$this->([a-zA-Z_][a-zA-Z0-9_]*)\(\)`)
	resolveThisPropNoBracePattern   = regexp.MustCompile(`\$this->([a-zA-Z_][a-zA-Z0-9_]*)`)
	resolveVarNoBracePattern        = regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)`)
)

// SymbolTable holds resolved PHP symbols for a file
type SymbolTable struct {
	Constants        map[string]string // const NAME = 'value'
	StaticProperties map[string]string // static $prop = 'value'
	Properties       map[string]string // $this->prop = 'value' or property defaults
	Variables        map[string]string // $var = 'value'
	ClassName        string            // Class name if found
}

// NewSymbolTable creates a new symbol table from PHP content
func NewSymbolTable(content string) *SymbolTable {
	st := &SymbolTable{
		Constants:        make(map[string]string),
		StaticProperties: make(map[string]string),
		Properties:       make(map[string]string),
		Variables:        make(map[string]string),
	}

	// Extract class name
	if matches := phpClassNamePattern.FindStringSubmatch(content); len(matches) >= 2 {
		st.ClassName = matches[1]
	}

	// Extract constants
	for _, match := range phpConstPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 3 {
			st.Constants[match[1]] = match[2]
		}
	}

	// Extract static properties
	for _, match := range phpStaticPropertyPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 3 {
			st.StaticProperties[match[1]] = match[2]
		}
	}

	// Extract properties (with defaults)
	for _, match := range phpPropertyPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 3 {
			st.Properties[match[1]] = match[2]
		}
	}

	// Extract $this->prop assignments
	for _, match := range phpThisAssignPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 3 {
			st.Properties[match[1]] = match[2]
		}
	}

	// Extract variable assignments
	for _, match := range phpVariableAssignPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 3 {
			// Skip 'this' as it's handled separately
			if match[1] != "this" {
				st.Variables[match[1]] = match[2]
			}
		}
	}

	return st
}

// ResolveReference attempts to resolve a PHP reference to a string value
// Handles: self::CONST, static::CONST, $this->prop, $var, ClassName::CONST
func (st *SymbolTable) ResolveReference(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)

	// Handle self::CONSTANT (case-insensitive for constant names)
	if strings.HasPrefix(ref, "self::") {
		constName := strings.TrimPrefix(ref, "self::")
		// Direct lookup first
		if val, ok := st.Constants[constName]; ok {
			return val, true
		}
		// Case-insensitive lookup
		for k, v := range st.Constants {
			if strings.EqualFold(k, constName) {
				return v, true
			}
		}
		// Check static properties: self::$prop
		if strings.HasPrefix(constName, "$") {
			propName := strings.TrimPrefix(constName, "$")
			if val, ok := st.StaticProperties[propName]; ok {
				return val, true
			}
		}
	}

	// Handle static::CONSTANT
	if strings.HasPrefix(ref, "static::") {
		constName := strings.TrimPrefix(ref, "static::")
		if val, ok := st.Constants[constName]; ok {
			return val, true
		}
		// Case-insensitive lookup
		for k, v := range st.Constants {
			if strings.EqualFold(k, constName) {
				return v, true
			}
		}
	}

	// Handle $this->property
	if strings.HasPrefix(ref, "$this->") {
		propName := strings.TrimPrefix(ref, "$this->")
		if val, ok := st.Properties[propName]; ok {
			return val, true
		}
	}

	// Handle plain variable $var
	if strings.HasPrefix(ref, "$") && !strings.Contains(ref, "->") {
		varName := strings.TrimPrefix(ref, "$")
		if val, ok := st.Variables[varName]; ok {
			return val, true
		}
	}

	// Handle ClassName::CONSTANT (when ClassName matches current class)
	if strings.Contains(ref, "::") {
		parts := strings.SplitN(ref, "::", 2)
		if len(parts) == 2 {
			// Check if it's the current class
			if parts[0] == st.ClassName || strings.EqualFold(parts[0], st.ClassName) {
				if val, ok := st.Constants[parts[1]]; ok {
					return val, true
				}
				// Case-insensitive lookup
				for k, v := range st.Constants {
					if strings.EqualFold(k, parts[1]) {
						return v, true
					}
				}
			}
		}
	}

	return "", false
}

// ExtractLocalContext extracts variable assignments near a given position
func ExtractLocalContext(content string, position int, contextLines int) *SymbolTable {
	// Find the function/method boundary
	start := findFunctionStart(content, position)
	end := findFunctionEnd(content, position)

	// Extract the local context
	localContent := content[start:end]

	return NewSymbolTable(localContent)
}

// findFunctionStart finds the start of the function containing position
func findFunctionStart(content string, position int) int {
	// Look backwards for function keyword
	searchStart := position - 2000
	if searchStart < 0 {
		searchStart = 0
	}

	// Find the last 'function' before position
	substr := content[searchStart:position]
	lastFunc := strings.LastIndex(substr, "function ")
	if lastFunc >= 0 {
		return searchStart + lastFunc
	}

	return searchStart
}

// findFunctionEnd finds the end of the function containing position
func findFunctionEnd(content string, position int) int {
	searchEnd := position + 2000
	if searchEnd > len(content) {
		searchEnd = len(content)
	}

	return searchEnd
}

// ResolveConcatenation attempts to resolve string concatenation
// Handles: 'prefix' . $var . 'suffix', 'prefix' . self::CONST
func (st *SymbolTable) ResolveConcatenation(expr string) string {
	// Split by concatenation operator
	parts := splitConcatenation(expr)
	var result strings.Builder

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// String literal
		if (strings.HasPrefix(part, "'") && strings.HasSuffix(part, "'")) ||
			(strings.HasPrefix(part, "\"") && strings.HasSuffix(part, "\"")) {
			result.WriteString(strings.Trim(part, "'\""))
			continue
		}

		// Try to resolve reference
		if val, ok := st.ResolveReference(part); ok {
			result.WriteString(val)
		} else {
			// Cannot resolve - use clean placeholder
			result.WriteString("{" + cleanPlaceholder(part) + "}")
		}
	}

	return result.String()
}

// cleanPlaceholder converts a PHP reference to a clean placeholder name
// $this->prop -> prop, self::CONST -> CONST, $var -> var
func cleanPlaceholder(ref string) string {
	ref = strings.TrimSpace(ref)

	// Handle $this->prop or $this->method()
	if strings.HasPrefix(ref, "$this->") {
		ref = strings.TrimPrefix(ref, "$this->")
		// Remove () if it's a method call
		ref = strings.TrimSuffix(ref, "()")
		return ref
	}

	// Handle self::CONST or static::CONST
	if strings.HasPrefix(ref, "self::") {
		return strings.TrimPrefix(ref, "self::")
	}
	if strings.HasPrefix(ref, "static::") {
		return strings.TrimPrefix(ref, "static::")
	}

	// Handle ClassName::CONST
	if strings.Contains(ref, "::") {
		parts := strings.SplitN(ref, "::", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}

	// Handle $var
	if strings.HasPrefix(ref, "$") {
		return strings.TrimPrefix(ref, "$")
	}

	return ref
}

// splitConcatenation splits a PHP concatenation expression
func splitConcatenation(expr string) []string {
	var parts []string
	var current strings.Builder
	inString := false
	stringChar := byte(0)
	depth := 0

	for i := 0; i < len(expr); i++ {
		c := expr[i]

		if inString {
			current.WriteByte(c)
			if c == stringChar && (i == 0 || expr[i-1] != '\\') {
				inString = false
			}
			continue
		}

		switch c {
		case '\'', '"':
			inString = true
			stringChar = c
			current.WriteByte(c)
		case '(':
			depth++
			current.WriteByte(c)
		case ')':
			depth--
			current.WriteByte(c)
		case '.':
			if depth == 0 {
				part := strings.TrimSpace(current.String())
				if part != "" {
					parts = append(parts, part)
				}
				current.Reset()
			} else {
				current.WriteByte(c)
			}
		default:
			current.WriteByte(c)
		}
	}

	// Add last part
	part := strings.TrimSpace(current.String())
	if part != "" {
		parts = append(parts, part)
	}

	return parts
}

// ExtractInterpolatedString extracts variables from PHP interpolated strings
// e.g., "wp_ajax_{$action}" returns base="wp_ajax_", var="action"
// Memory-optimized: uses pre-compiled patterns
func ExtractInterpolatedString(s string) (base string, variable string, suffix string) {
	// Handle {$var} syntax
	matches := extractInterpBraceVarPattern.FindStringSubmatchIndex(s)
	if len(matches) >= 4 {
		base = s[:matches[0]]
		variable = s[matches[2]:matches[3]]
		suffix = s[matches[1]:]
		return
	}

	// Handle $var syntax (simple variable at end)
	matches2 := extractInterpSimpleVarPattern.FindStringSubmatchIndex(s)
	if len(matches2) >= 4 {
		base = s[:matches2[0]]
		variable = s[matches2[2]:matches2[3]]
		return
	}

	return s, "", ""
}

// ResolveInterpolatedString resolves all PHP variable interpolations in a string
// Handles patterns like "{$this->prop}", "{$var}", "$var", and method calls
// Returns the string with variables resolved or replaced with clean placeholders
// Memory-optimized: uses pre-compiled patterns
func (st *SymbolTable) ResolveInterpolatedString(s string) string {
	result := s

	// Pattern for {$this->method()} syntax - method calls
	result = resolveThisMethodPattern.ReplaceAllStringFunc(result, func(match string) string {
		methodName := resolveThisMethodPattern.FindStringSubmatch(match)[1]
		// Can't resolve method calls, use clean placeholder
		return "{" + methodName + "}"
	})

	// Pattern for {$this->property} syntax
	result = resolveThisPropPattern.ReplaceAllStringFunc(result, func(match string) string {
		propName := resolveThisPropPattern.FindStringSubmatch(match)[1]
		if val, ok := st.Properties[propName]; ok {
			return val
		}
		return "{" + propName + "}"
	})

	// Pattern for {$var} syntax
	result = resolveVarPattern.ReplaceAllStringFunc(result, func(match string) string {
		varName := resolveVarPattern.FindStringSubmatch(match)[1]
		if val, ok := st.Variables[varName]; ok {
			return val
		}
		return "{" + varName + "}"
	})

	// Pattern for $this->method() (without braces) - method calls
	result = resolveThisMethodNoBracePattern.ReplaceAllStringFunc(result, func(match string) string {
		methodName := resolveThisMethodNoBracePattern.FindStringSubmatch(match)[1]
		return "{" + methodName + "}"
	})

	// Pattern for $this->property (without braces)
	result = resolveThisPropNoBracePattern.ReplaceAllStringFunc(result, func(match string) string {
		propName := resolveThisPropNoBracePattern.FindStringSubmatch(match)[1]
		if val, ok := st.Properties[propName]; ok {
			return val
		}
		return "{" + propName + "}"
	})

	// Pattern for $var (without braces)
	result = resolveVarNoBracePattern.ReplaceAllStringFunc(result, func(match string) string {
		varName := resolveVarNoBracePattern.FindStringSubmatch(match)[1]
		if val, ok := st.Variables[varName]; ok {
			return val
		}
		return "{" + varName + "}"
	})

	return result
}

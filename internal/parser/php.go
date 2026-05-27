// Package parser provides utilities for parsing PHP code
package parser

import (
	"regexp"
	"strings"
)

// Package-level compiled regex patterns for PHP parsing
var (
	// Pattern for findMethodsInBody
	phpMethodPattern = regexp.MustCompile(
		`(?m)^[\t ]*(?:(public|private|protected)\s+)?` +
			`(?:static\s+)?` +
			`function\s+(\w+)\s*` +
			`\(([^)]*)\)`,
	)

	// Pattern for ExtractHookCallbacks
	phpHookCallbackPattern = regexp.MustCompile(
		`(add_action|add_filter)\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` +
			`([^,)]+)`,
	)

	// Pattern for ExtractShortcodes
	phpShortcodePattern = regexp.MustCompile(
		`add_shortcode\s*\(\s*` +
			`['"]([^'"]+)['"]\s*,\s*` +
			`([^,)]+)`,
	)

	// Patterns for RemoveComments
	phpMultiLineCommentPattern = regexp.MustCompile(`/\*[\s\S]*?\*/`)
	phpSingleLineCommentPattern = regexp.MustCompile(`//[^\n]*`)
	phpHashCommentPattern = regexp.MustCompile(`#[^\n]*`)

	// Patterns for ExtractStrings
	phpDoubleQuotedPattern = regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*)"`)
	phpSingleQuotedPattern = regexp.MustCompile(`'([^'\\]*(?:\\.[^'\\]*)*)'`)
)

// PHPFunction represents a parsed PHP function
type PHPFunction struct {
	Name       string
	Visibility string // public, private, protected, or empty for regular functions
	Parameters []string
	Body       string
	StartLine  int
	EndLine    int
}

// PHPClass represents a parsed PHP class
type PHPClass struct {
	Name      string
	Extends   string
	Methods   []PHPFunction
	StartLine int
	EndLine   int
}

// FindFunction finds a function definition by name
func FindFunction(content, name string) *PHPFunction {
	// Pattern for function definition
	pattern := regexp.MustCompile(
		`(?m)^[\t ]*(?:(public|private|protected)\s+)?` +
			`(?:static\s+)?` +
			`function\s+` + regexp.QuoteMeta(name) + `\s*` +
			`\(([^)]*)\)\s*` +
			`(?::\s*[?\w\\]+\s*)?` + // return type hint
			`\{`,
	)

	match := pattern.FindStringSubmatchIndex(content)
	if match == nil {
		return nil
	}

	fn := &PHPFunction{
		Name:      name,
		StartLine: countLines(content[:match[0]]) + 1,
	}

	// Extract visibility
	if match[2] >= 0 && match[3] >= 0 {
		fn.Visibility = content[match[2]:match[3]]
	}

	// Extract parameters
	if match[4] >= 0 && match[5] >= 0 {
		params := content[match[4]:match[5]]
		fn.Parameters = parseParameters(params)
	}

	// Find matching closing brace
	braceStart := match[1] - 1 // Position of opening brace
	body, endPos := findMatchingBrace(content[braceStart:])
	if body != "" {
		fn.Body = body
		fn.EndLine = fn.StartLine + countLines(content[match[0]:braceStart+endPos])
	}

	return fn
}

// FindClass finds a class definition by name
func FindClass(content, name string) *PHPClass {
	pattern := regexp.MustCompile(
		`(?m)^[\t ]*(?:abstract\s+|final\s+)?` +
			`class\s+` + regexp.QuoteMeta(name) + `\s*` +
			`(?:extends\s+(\w+)\s*)?` +
			`(?:implements\s+[^{]+)?` +
			`\{`,
	)

	match := pattern.FindStringSubmatchIndex(content)
	if match == nil {
		return nil
	}

	class := &PHPClass{
		Name:      name,
		StartLine: countLines(content[:match[0]]) + 1,
	}

	// Extract extends
	if match[2] >= 0 && match[3] >= 0 {
		class.Extends = content[match[2]:match[3]]
	}

	// Find class body
	braceStart := match[1] - 1
	body, endPos := findMatchingBrace(content[braceStart:])
	if body != "" {
		class.EndLine = class.StartLine + countLines(content[match[0]:braceStart+endPos])
		class.Methods = findMethodsInBody(body)
	}

	return class
}

// findMatchingBrace finds the matching closing brace and returns the content
func findMatchingBrace(content string) (string, int) {
	if len(content) == 0 || content[0] != '{' {
		return "", 0
	}

	depth := 0
	inString := false
	stringChar := byte(0)
	escaped := false

	for i := 0; i < len(content); i++ {
		c := content[i]

		if escaped {
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			continue
		}

		if inString {
			if c == stringChar {
				inString = false
			}
			continue
		}

		switch c {
		case '"', '\'':
			inString = true
			stringChar = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[1:i], i + 1
			}
		}
	}

	return "", 0
}

// parseParameters parses function parameters
func parseParameters(params string) []string {
	if strings.TrimSpace(params) == "" {
		return nil
	}

	result := make([]string, 0)
	parts := strings.Split(params, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}

// findMethodsInBody finds all method definitions in a class body
func findMethodsInBody(body string) []PHPFunction {
	methods := make([]PHPFunction, 0)

	// Use pre-compiled package-level pattern
	matches := phpMethodPattern.FindAllStringSubmatchIndex(body, -1)
	for _, match := range matches {
		if len(match) < 8 {
			continue
		}

		fn := PHPFunction{
			StartLine: countLines(body[:match[0]]) + 1,
		}

		// Visibility
		if match[2] >= 0 && match[3] >= 0 {
			fn.Visibility = body[match[2]:match[3]]
		}

		// Name
		if match[4] >= 0 && match[5] >= 0 {
			fn.Name = body[match[4]:match[5]]
		}

		// Parameters
		if match[6] >= 0 && match[7] >= 0 {
			params := body[match[6]:match[7]]
			fn.Parameters = parseParameters(params)
		}

		methods = append(methods, fn)
	}

	return methods
}

// ExtractHookCallbacks finds all add_action/add_filter callbacks
func ExtractHookCallbacks(content string) []HookCallback {
	callbacks := make([]HookCallback, 0)

	// Use pre-compiled package-level pattern
	matches := phpHookCallbackPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 4 {
			callbacks = append(callbacks, HookCallback{
				Type:     match[1],
				Hook:     match[2],
				Callback: strings.TrimSpace(match[3]),
			})
		}
	}

	return callbacks
}

// HookCallback represents an add_action or add_filter call
type HookCallback struct {
	Type     string // add_action or add_filter
	Hook     string // hook name
	Callback string // callback function or method
}

// ExtractShortcodes finds all add_shortcode registrations
func ExtractShortcodes(content string) []Shortcode {
	shortcodes := make([]Shortcode, 0)

	// Use pre-compiled package-level pattern
	matches := phpShortcodePattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			shortcodes = append(shortcodes, Shortcode{
				Tag:      match[1],
				Callback: strings.TrimSpace(match[2]),
			})
		}
	}

	return shortcodes
}

// Shortcode represents a WordPress shortcode registration
type Shortcode struct {
	Tag      string
	Callback string
}

// countLines counts newlines in a string
func countLines(s string) int {
	return strings.Count(s, "\n")
}

// RemoveComments removes PHP comments from content
func RemoveComments(content string) string {
	// Remove multi-line comments using pre-compiled pattern
	content = phpMultiLineCommentPattern.ReplaceAllString(content, "")

	// Remove single-line comments using pre-compiled pattern
	content = phpSingleLineCommentPattern.ReplaceAllString(content, "")

	// Remove # comments using pre-compiled pattern
	content = phpHashCommentPattern.ReplaceAllString(content, "")

	return content
}

// ExtractStrings extracts all string literals from PHP code
func ExtractStrings(content string) []string {
	result := make([]string, 0)

	// Match double-quoted strings using pre-compiled pattern
	for _, match := range phpDoubleQuotedPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			result = append(result, match[1])
		}
	}

	// Match single-quoted strings using pre-compiled pattern
	for _, match := range phpSingleQuotedPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			result = append(result, match[1])
		}
	}

	return result
}

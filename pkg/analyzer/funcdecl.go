package analyzer

import (
	"regexp"
	"strings"
)

// funcDeclHeadPattern finds the *head* of a PHP function declaration: the
// modifiers, the `function` keyword, the name, and the opening parenthesis of
// the parameter list.
//
// It deliberately stops at "(" and does not try to match the parameters. RE2
// has no counted repetition over balanced delimiters, so the previous
// `\([^)]*\)` gave up at the first ")" inside the parameter list — which any
// default value like `array()`, `[]`, a nested call, or a typed closure
// produces. Across the 143-plugin corpus that lost 11,696 of 329,198
// declarations (3.6%), concentrated badly: 26% of ultimate-member's functions,
// 15% of mw-wp-form's, 10.8% of buddypress's. A function missing from the graph
// is unreachable from everything, so the loss shows up as phantom reachability
// failures.
//
// The leading anchor is also relaxed from `(?m)^[\t ]*` to "start of line, or
// after a token that can legally precede a declaration". The old anchor made
// any declaration sharing a line with something else invisible, which
// accounted for a further 3,950 misses.
var funcDeclHeadPattern = regexp.MustCompile(
	`(?i)(?:^|[\s;{}():])((?:(?:public|private|protected|static|final|abstract)\s+)*)` +
		`function\s+(&\s*)?([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)\s*\(`)

// FuncDecl is one parsed PHP function or method declaration.
type FuncDecl struct {
	Name string
	// NameStart is the offset of the name, used to key a declaration uniquely.
	NameStart int
	// DeclStart is the offset of the first modifier or the `function` keyword.
	DeclStart int
	// BodyOpen is the offset of the body's "{".
	BodyOpen int
	// BodyClose is the offset of the matching "}".
	BodyClose int
}

// FindFunctionDeclarations returns every named function declaration with a body.
//
// Abstract and interface declarations, which end in ";" rather than a body, are
// skipped: they define no calls, and treating one as a definition would let it
// shadow the real implementation under the same bare name.
func FindFunctionDeclarations(content string) []FuncDecl {
	heads := funcDeclHeadPattern.FindAllStringSubmatchIndex(content, -1)
	out := make([]FuncDecl, 0, len(heads))
	for _, m := range heads {
		nameStart, nameEnd := m[6], m[7]
		if nameStart < 0 {
			continue
		}
		// m[1] is the end of the whole match, which is just past "(".
		parenOpen := m[1] - 1
		parenClose := matchDelimiter(content, parenOpen, '(', ')')
		if parenClose < 0 {
			continue
		}

		// Skip a return type: ": ?Foo\Bar" or ": static".
		i := skipSpace(content, parenClose+1)
		if i < len(content) && content[i] == ':' {
			i = skipSpace(content, i+1)
			for i < len(content) && (isTypeChar(content[i]) || content[i] == '|' || content[i] == '?' || content[i] == '\\') {
				i++
			}
			i = skipSpace(content, i)
		}
		if i >= len(content) || content[i] != '{' {
			// No body: an abstract method or an interface signature.
			continue
		}
		bodyClose := findMatchingBrace(content, i)
		if bodyClose < 0 {
			continue
		}

		declStart := m[2]
		if declStart < 0 || declStart > nameStart {
			declStart = nameStart
		}
		out = append(out, FuncDecl{
			Name:      content[nameStart:nameEnd],
			NameStart: nameStart,
			DeclStart: declStart,
			BodyOpen:  i,
			BodyClose: bodyClose,
		})
	}
	return out
}

// matchDelimiter finds the delimiter closing the one at open, honouring nesting
// and skipping over string literals so a ")" inside a default string value does
// not close the parameter list early.
func matchDelimiter(s string, open int, oc, cc byte) int {
	if open >= len(s) || s[open] != oc {
		return -1
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"':
			i = skipString(s, i)
			if i < 0 {
				return -1
			}
		case oc:
			depth++
		case cc:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// skipString returns the index of the closing quote of the literal starting at
// i, or -1 if it is unterminated. Backslash escapes are honoured in
// double-quoted strings and in single-quoted ones (PHP allows \' and \\).
func skipString(s string, i int) int {
	quote := s[i]
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case quote:
			return j
		}
	}
	return -1
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i
}

func isTypeChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// DeclaresFunction reports whether content declares a function of this name.
// Used where only presence matters.
func DeclaresFunction(content, name string) bool {
	for _, d := range FindFunctionDeclarations(content) {
		if strings.EqualFold(d.Name, name) {
			return true
		}
	}
	return false
}

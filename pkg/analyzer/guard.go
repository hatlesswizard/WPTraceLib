package analyzer

import (
	"regexp"
	"strings"
)

// A capability check only tells you the authorization level of an endpoint if
// it actually *gates* the code you care about. InferAuthLevel used to take the
// first current_user_can() it could find anywhere in a blob and report that
// level, which is wrong in the dangerous direction: a handler with an
// admin-only branch and an unguarded vulnerable branch reported Admin, so a
// reachable vulnerability looked gated.
//
//	public function handle() {
//	    if ( isset($_POST['admin_op']) ) {
//	        if ( ! current_user_can('manage_options') ) { wp_die(); }  // guards THIS branch
//	        ...
//	    }
//	    $this->save_setting( $_POST['value'] );                        // unguarded
//	}
//
// This file distinguishes a check that gates the whole function body from one
// that merely appears inside it. The distinction is syntactic and therefore
// universal: it is about PHP control flow, not about any plugin's conventions.

// capCheckPattern finds a capability or role assertion and captures the
// capability string when one is written literally.
var capCheckPattern = regexp.MustCompile(
	`(?i)\b(current_user_can_for_blog|current_user_can|user_can|author_can)\s*\(`)

// terminatorPattern matches the statements that end request processing. A
// negated capability check whose branch terminates is a guard; one whose branch
// merely logs or sets a flag is not.
//
// wp_die, die, exit and throw stop outright. wp_send_json_* and
// wp_redirect/wp_safe_redirect end the response in practice, and in WordPress
// handlers they are the idiomatic way to refuse. `return` ends the callback,
// which is what matters here.
var terminatorPattern = regexp.MustCompile(
	`(?i)\b(return\b|wp_die\s*\(|die\s*\(|exit\s*[\(;]|throw\b|` +
		`wp_send_json_error\s*\(|wp_send_json\s*\(|wp_send_json_success\s*\(|` +
		`wp_redirect\s*\(|wp_safe_redirect\s*\(|auth_redirect\s*\(|` +
		`wp_nonce_ays\s*\(|status_header\s*\()`)

// GuardKind says how a capability check relates to the code after it.
type GuardKind int

const (
	// GuardNone: the check's result is not used to stop anything -- assigned to
	// a variable, used to toggle UI, or tested in a branch that falls through.
	GuardNone GuardKind = iota
	// GuardBranch: the check gates one branch, but control continues past it.
	GuardBranch
	// GuardFunction: failing the check ends the function, so every statement
	// after it is reached only by a caller who passed.
	GuardFunction
)

// CapabilityGuard is one capability assertion and the strength of its gating.
type CapabilityGuard struct {
	Capability string
	Kind       GuardKind
	Offset     int
}

// FindCapabilityGuards classifies every capability check in a function body.
//
// The body should be the function's own body, so that "ends the function" is
// meaningful. Passing a whole file yields GuardBranch at best, which is the
// conservative answer.
func FindCapabilityGuards(body string) []CapabilityGuard {
	var out []CapabilityGuard
	for _, m := range capCheckPattern.FindAllStringIndex(body, -1) {
		callStart := m[0]
		parenOpen := m[1] - 1
		parenClose := matchDelimiter(body, parenOpen, '(', ')')
		if parenClose < 0 {
			continue
		}
		g := CapabilityGuard{
			Capability: firstStringLiteral(body[parenOpen+1 : parenClose]),
			Offset:     callStart,
			Kind:       classifyGuard(body, callStart, parenClose),
		}
		out = append(out, g)
	}
	return out
}

// classifyGuard decides how much of the function a check protects.
func classifyGuard(body string, callStart, parenClose int) GuardKind {
	// Walk back to the start of the enclosing statement/condition.
	stmtStart := statementStart(body, callStart)
	prefix := body[stmtStart:callStart]

	// Is this inside an `if (...)` condition at all?
	ifIdx := strings.LastIndex(strings.ToLower(prefix), "if")
	if ifIdx < 0 {
		// Not a condition: `$can = current_user_can(...)`, or an argument to
		// something else. Such a check gates nothing by itself.
		return GuardNone
	}

	negated := strings.Contains(prefix[ifIdx:], "!") || strings.Contains(prefix[ifIdx:], "empty")

	// Find the end of the whole `if (...)` condition, then the branch that follows.
	condClose := parenClose
	for {
		next := skipSpace(body, condClose+1)
		if next < len(body) && (body[next] == ')' || body[next] == '&' || body[next] == '|') {
			// Still inside a compound condition; find the real close.
			if body[next] == ')' {
				condClose = next
				continue
			}
			// A compound condition -- take the rest of the condition as opaque
			// and locate its closing paren from the `if`.
			break
		}
		break
	}

	branchStart := skipSpace(body, condClose+1)
	var branch string
	branchEnd := branchStart
	if branchStart < len(body) && body[branchStart] == '{' {
		if close := findMatchingBrace(body, branchStart); close > 0 {
			branch = body[branchStart:close]
			branchEnd = close
		}
	} else {
		// Brace-less single statement: `if ( ! current_user_can(..) ) return;`
		if semi := strings.IndexByte(body[branchStart:], ';'); semi >= 0 {
			branch = body[branchStart : branchStart+semi+1]
			branchEnd = branchStart + semi
		}
	}

	terminates := terminatorPattern.MatchString(branch)

	if negated {
		if !terminates {
			// `if ( ! can ) { $msg = 'nope'; }` -- execution continues regardless.
			return GuardNone
		}
		// `if ( ! can ) { die; }` protects the rest of the block it sits in.
		// That is the whole function only when it sits at the function's top
		// level. Nested inside another conditional --
		//
		//   if ( isset($_POST['admin_op']) ) {
		//       if ( ! current_user_can('manage_options') ) { wp_die(); }
		//       admin_only();
		//   }
		//   save_setting( $_POST['value'] );   // still unguarded
		//
		// -- it protects only that branch, which is exactly the shape that made
		// the old presence-based inference report Admin for an unguarded sink.
		if depthAt(body, callStart) > topLevelDepth(body) {
			return GuardBranch
		}
		return GuardFunction
	}

	// Positive form: `if ( can ) { ... }`. It protects only its own branch,
	// unless that branch runs to the end of the body -- in which case nothing
	// outside it exists to be unprotected.
	if branchEnd > 0 && nothingExecutesAfter(body, branchEnd) {
		return GuardFunction
	}
	return GuardBranch
}

// nothingExecutesAfter reports whether the remainder of the body is only
// closing braces and whitespace. Callers hand us a body that still carries its
// own enclosing braces, so "the branch is the last thing in the function" shows
// up as a tail of "}" rather than an empty string.
func nothingExecutesAfter(body string, pos int) bool {
	for i := pos + 1; i < len(body); i++ {
		switch body[i] {
		case ' ', '\t', '\r', '\n', '}', ';':
			continue
		default:
			return false
		}
	}
	return true
}

// statementStart walks back to the nearest statement boundary, so the text
// before a call can be inspected for `if` and negation without running into the
// previous statement.
func statementStart(body string, pos int) int {
	for i := pos - 1; i >= 0; i-- {
		switch body[i] {
		case ';', '{', '}':
			return i + 1
		}
	}
	return 0
}

// firstStringLiteral returns the first quoted string in an argument list, which
// is where a literal capability name sits. An empty result means the capability
// was a variable or a constant.
func firstStringLiteral(args string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == '\'' || args[i] == '"' {
			end := skipString(args, i)
			if end < 0 {
				return ""
			}
			return args[i+1 : end]
		}
	}
	return ""
}

// StrongestGuard returns the capability of the check that protects the whole
// function, if any, and whether one exists.
//
// When several checks gate the function, the LOWEST privilege wins: passing any
// one of them is enough to get in, so the weakest is what an attacker needs.
// Callers resolve the capability strings to levels, so this returns them all.
func StrongestGuard(body string) (caps []string, gated bool) {
	for _, g := range FindCapabilityGuards(body) {
		if g.Kind == GuardFunction {
			gated = true
			if g.Capability != "" {
				caps = append(caps, g.Capability)
			}
		}
	}
	return caps, gated
}

// depthAt returns the brace nesting depth at an offset, skipping string
// literals so a "{" inside a string cannot shift the count.
func depthAt(body string, pos int) int {
	depth := 0
	for i := 0; i < pos && i < len(body); i++ {
		switch body[i] {
		case '\'', '"':
			j := skipString(body, i)
			if j < 0 {
				return depth
			}
			i = j
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return depth
}

// topLevelDepth is the nesting depth of a function body's own statements. A
// body handed over with its enclosing braces sits at depth 1; a bare fragment
// or a whole file sits at 0.
func topLevelDepth(body string) int {
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return 1
		default:
			return 0
		}
	}
	return 0
}

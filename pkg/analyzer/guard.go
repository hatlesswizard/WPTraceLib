package analyzer

import (
	"regexp"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
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
//
// Three things follow from that, and each is a rule below rather than a special
// case:
//
//   - Whether a check gates is decided relative to the ENCLOSING FUNCTION, not
//     to the start of whatever substring a caller happened to slice. A rule
//     whose answer changes when the caller widens the slice is measuring the
//     slice. Correspondingly, when the blob handed over is not a single body --
//     a whole file, a window around a match -- the checks inside it gate the
//     functions they sit in and say nothing about the blob, so this file
//     answers "not gated" rather than guessing.
//
//   - What counts as "the request stops" depends on where the body sits. wp_die,
//     exit, throw and wp_send_json_* end the request from any depth; `return`
//     transfers control to the caller and nothing more. In an endpoint callback
//     -- or a REST permission_callback, where core turns a falsy return into
//     rest_forbidden -- returning IS refusing. In a helper it is not, so a
//     helper's `if ( ! current_user_can(X) ) { return; }` gates the helper and
//     leaves its caller wide open. BodyScope carries that distinction.
//
//   - Only a check that tests the CURRENT user says anything about the caller.
//     user_can($someone_else, X) and $user->has_cap(X) are reads about a subject
//     the request chose, which is why they are not treated as identity
//     assertions here.
//
// Nothing in this file may read a level out of an identifier's spelling. A
// method named isAdmin() may return current_user_can(<a constant>), or
// is_admin(), which is a location test that is true for every admin-ajax.php
// request including an unauthenticated one. WordPress attaches no meaning to a
// PHP function's name; it defines a finite vocabulary of privilege checks, and
// that vocabulary is the only thing matched below.

// capCheckPattern finds a capability assertion. The capability string and the
// subject are read out of the argument list afterwards, because which argument
// holds which differs between these four core functions.
var capCheckPattern = regexp.MustCompile(
	`(?i)\b(current_user_can_for_blog|current_user_can|user_can|author_can)\s*\(`)

// identityCheckPattern finds the core predicates that assert something about
// WHO is calling without naming a capability.
//
// These go through the same control-flow classifier as current_user_can for a
// PHP reason: the language does not care which function produced the boolean,
// so `if ( ! is_user_logged_in() ) { wp_die(); }` gates exactly as
// `if ( ! current_user_can('read') ) { wp_die(); }` does, and a decorative
// `if ( is_user_logged_in() ) { $who = wp_get_current_user(); }` gates exactly
// as little. Before this went through the classifier, the mere presence of the
// call anywhere in the blob produced Subscriber.
var identityCheckPattern = regexp.MustCompile(
	`(?i)\b(is_user_logged_in|is_super_admin|auth_redirect|get_current_user_id)\s*\(`)

// requestTerminatorPattern matches statements that end the REQUEST, from any
// call depth. wp_die, die, exit and throw stop outright; wp_send_json_* call
// wp_die() after printing.
//
// wp_redirect, wp_safe_redirect and status_header are listed with them although
// none of the three stops PHP -- core documents that wp_redirect() must be
// followed by exit, and status_header() only sends a header. They are kept
// because across the 143-plugin corpus there is no top-level negated capability
// guard whose branch carries one of them WITHOUT also carrying die/exit/throw or
// a return, so removing them would change no answer while losing the idiom.
var requestTerminatorPattern = regexp.MustCompile(
	`(?i)\b(wp_die\s*\(|die\s*[\(;]|exit\s*[\(;]|throw\b|` +
		`wp_send_json_error\s*\(|wp_send_json\s*\(|wp_send_json_success\s*\(|` +
		`wp_redirect\s*\(|wp_safe_redirect\s*\(|auth_redirect\s*\(|` +
		`wp_nonce_ays\s*\(|status_header\s*\()`)

// returnPattern matches any return statement. `return;`, `return false;` and
// `return $x;` all end the current function and nothing more -- the distinction
// that matters is where the function sits, not whether the return carries a
// value.
var returnPattern = regexp.MustCompile(`(?i)\breturn\b`)

// conditionKeywordPattern finds the `if` / `elseif` / `else if` that governs a
// check. It replaces a bare strings.LastIndex(prefix, "if"), which could not
// tell an elseif from an if and matched the "if" inside an identifier: a body
// ending in `$verified = current_user_can('manage_options');` classified as
// gating the whole function, because "ver-IF-ied" satisfied the substring
// search and the trailing `;` was taken for the guarded branch.
var conditionKeywordPattern = regexp.MustCompile(`(?i)\b(else\s*if|elseif|if)\b`)

// assignedCheckPattern matches a statement that is nothing but `$v = ` or
// `$v = ! ` in front of the check, which is the assign-then-test idiom.
var assignedCheckPattern = regexp.MustCompile(`^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(!\s*)?$`)

// BodyScope says what a `return` statement means in the body being classified,
// which is the difference between a check that stops the request and one that
// only ends a helper.
type BodyScope int

const (
	// ScopeRequest: the body is what WordPress dispatches. An AJAX, REST,
	// shortcode or hook callback has nothing left to run once it returns, and a
	// REST permission_callback's falsy return is turned into rest_forbidden by
	// WP_REST_Server::dispatch_request. In both cases `return` refuses.
	ScopeRequest BodyScope = iota
	// ScopeHelper: the body is a helper reached from somewhere else. `return`
	// transfers control to the caller, so a check whose only consequence is a
	// return cannot stop anything in that caller.
	ScopeHelper
)

// GuardKind says how a capability check relates to the code after it.
type GuardKind int

const (
	// GuardNone: the check's result is not used to stop anything -- assigned to
	// a variable that is never tested, used to toggle UI, or tested in a branch
	// that falls through.
	GuardNone GuardKind = iota
	// GuardBranch: the check gates one branch, but control continues past it.
	GuardBranch
	// GuardFunction: failing the check ends the function, so every statement
	// after it is reached only by a caller who passed.
	GuardFunction
)

// CapabilityGuard is one authorization assertion and the strength of its gating.
type CapabilityGuard struct {
	// Capability is the capability name, when it was written as a string
	// literal AND the check tests the current user. Empty otherwise.
	Capability string
	// CapabilityExpr is the raw argument text when the capability was not a
	// literal (`$this->capability`, `self::CAP`). A caller with the file in
	// hand can try to resolve it; on its own it means "gated by something we
	// cannot name".
	CapabilityExpr string
	// Implied is the level an identity predicate asserts by itself. Only
	// meaningful when IsIdentity is set.
	Implied models.AuthLevel
	// IsIdentity distinguishes a predicate about who is calling from a
	// capability read.
	IsIdentity bool
	// HasSubjectArg records that the check named the object it is testing
	// against, which is what map_meta_cap branches on for a meta capability:
	// current_user_can('edit_user', $id) is a different question from
	// current_user_can('edit_user').
	HasSubjectArg bool

	Kind   GuardKind
	Offset int
}

// FindCapabilityGuards classifies every authorization check in a function body.
//
// The body should be the function's own body. Handed something else -- a whole
// file, a window around a match -- the checks inside it belong to functions the
// caller has not identified, and StrongestGuard reports not-gated rather than
// attributing one function's guard to the blob.
func FindCapabilityGuards(body string) []CapabilityGuard {
	guards, _ := analyseGuards(body, ScopeRequest)
	return guards
}

// FindCapabilityGuardsInScope is FindCapabilityGuards with the caller stating
// whether a `return` in this body refuses the request.
func FindCapabilityGuardsInScope(body string, scope BodyScope) []CapabilityGuard {
	guards, _ := analyseGuards(body, scope)
	return guards
}

// analyseGuards classifies every check and also reports whether the blob is a
// single function body, which is the precondition for any of those checks to
// say something about the blob as a whole.
func analyseGuards(body string, scope BodyScope) (guards []CapabilityGuard, selfContained bool) {
	mask := maskNonCode(body)
	decls := FindFunctionDeclarations(mask)
	sites := findAuthChecks(body, mask)

	guards = make([]CapabilityGuard, 0, len(sites))
	for _, g := range sites {
		g.Kind = classifyCheck(mask, decls, g.Offset, g.parenClose, scope)
		if g.Kind == GuardNone {
			if k, ok := classifyAssignedCheck(mask, decls, g.Offset, g.parenClose, scope); ok {
				g.Kind = k
			}
		}
		guards = append(guards, g.CapabilityGuard)
	}
	return guards, blobIsSingleBody(mask, decls)
}

// blobIsSingleBody reports whether the text handed over is one function body.
//
// A complete named declaration inside the blob means the blob contains
// functions rather than being one, so a guard inside a declaration gates that
// declaration and nothing about the blob. A body handed over with its own
// braces is vouched for by its caller, and declarations inside it are nested
// functions rather than siblings.
func blobIsSingleBody(mask string, decls []FuncDecl) bool {
	if len(decls) == 0 {
		return true
	}
	return topLevelDepth(mask) == 1
}

// authCheckSite is a classified check plus the offsets classifyCheck needs.
type authCheckSite struct {
	CapabilityGuard
	parenClose int
}

// findAuthChecks locates every core authorization check in the blob, in source
// order, and reads its arguments.
func findAuthChecks(body, mask string) []authCheckSite {
	var out []authCheckSite

	add := func(site authCheckSite) {
		out = append(out, site)
	}

	for _, m := range capCheckPattern.FindAllStringSubmatchIndex(mask, -1) {
		callStart := m[0]
		fn := strings.ToLower(mask[m[2]:m[3]])
		parenOpen := m[1] - 1
		parenClose := matchDelimiter(mask, parenOpen, '(', ')')
		if parenClose < 0 {
			continue
		}
		args := splitTopLevelArgs(body[parenOpen+1:parenClose], mask[parenOpen+1:parenClose])

		g := CapabilityGuard{Offset: callStart}
		capIdx := 0
		switch fn {
		case "current_user_can":
			capIdx = 0
		case "current_user_can_for_blog":
			// current_user_can_for_blog( $blog_id, $capability, ... )
			capIdx = 1
		case "user_can", "author_can":
			// These name their subject. A check about a user the request chose
			// -- get_user_by('login', $_SERVER['PHP_AUTH_USER']), a decrypted
			// request parameter -- says nothing about the caller's privilege,
			// so the capability is only readable when the subject is provably
			// the current user.
			if len(args) == 0 || !isCurrentUserExpr(args[0]) {
				add(authCheckSite{CapabilityGuard: g, parenClose: parenClose})
				continue
			}
			capIdx = 1
		}
		if capIdx < len(args) {
			lit, expr := capabilityFromArg(args[capIdx])
			g.Capability = lit
			if lit == "" {
				g.CapabilityExpr = expr
			}
			g.HasSubjectArg = len(args) > capIdx+1
		}
		add(authCheckSite{CapabilityGuard: g, parenClose: parenClose})
	}

	for _, m := range identityCheckPattern.FindAllStringSubmatchIndex(mask, -1) {
		callStart := m[0]
		fn := strings.ToLower(mask[m[2]:m[3]])
		parenOpen := m[1] - 1
		parenClose := matchDelimiter(mask, parenOpen, '(', ')')
		if parenClose < 0 {
			continue
		}
		// With an argument these ask about someone else -- is_super_admin($id)
		// -- so only the zero-argument forms describe the caller.
		if strings.TrimSpace(mask[parenOpen+1:parenClose]) != "" {
			continue
		}
		g := CapabilityGuard{Offset: callStart, IsIdentity: true}
		switch fn {
		case "is_super_admin":
			// On a single-site install, which is the default, core defines
			// is_super_admin() as $user->has_cap('delete_users') -- true for
			// every Administrator. Only under is_multisite() does it consult
			// get_super_admins(). A static analyzer cannot know which kind of
			// install a plugin will run on, so SuperAdmin is not derivable and
			// Admin is the answer core supports.
			g.Implied = models.Admin
		default:
			// is_user_logged_in, auth_redirect and get_current_user_id all
			// separate "somebody" from "nobody" and no further.
			g.Implied = models.Subscriber
		}
		add(authCheckSite{CapabilityGuard: g, parenClose: parenClose})
	}

	// in_array( 'administrator', $user->roles ) reads WP_User::$roles, which
	// core populates from the site's role map. It is a role-membership test,
	// not a name-shaped guess, so it belongs with the core vocabulary.
	for _, m := range adminRoleInArrayPattern.FindAllStringIndex(body, -1) {
		start := m[0]
		if start >= len(mask) || mask[start] != body[start] {
			continue // inside a string literal or a comment
		}
		parenOpen := strings.IndexByte(body[start:], '(')
		if parenOpen < 0 {
			continue
		}
		parenOpen += start
		parenClose := matchDelimiter(mask, parenOpen, '(', ')')
		if parenClose < 0 {
			continue
		}
		add(authCheckSite{
			CapabilityGuard: CapabilityGuard{
				Offset:     start,
				IsIdentity: true,
				Implied:    models.Admin,
			},
			parenClose: parenClose,
		})
	}

	sortSitesByOffset(out)
	return out
}

func sortSitesByOffset(sites []authCheckSite) {
	for i := 1; i < len(sites); i++ {
		for j := i; j > 0 && sites[j].Offset < sites[j-1].Offset; j-- {
			sites[j], sites[j-1] = sites[j-1], sites[j]
		}
	}
}

// isCurrentUserExpr reports whether an argument provably names the caller.
func isCurrentUserExpr(arg string) bool {
	a := strings.ToLower(strings.TrimSpace(arg))
	a = strings.TrimSuffix(strings.ReplaceAll(a, " ", ""), ";")
	return a == "get_current_user_id()" || a == "wp_get_current_user()"
}

// capabilityFromArg reads the capability out of one argument, returning the
// literal when there is one and the raw expression otherwise.
//
// It unwraps apply_filters(), because `current_user_can( apply_filters(
// 'plugin_role', 'upload_files' ) )` puts the FILTER NAME first: taking the
// first quoted string there yields 'plugin_role', a string that is not a
// capability at all and will never resolve.
func capabilityFromArg(arg string) (literal, expr string) {
	expr = strings.TrimSpace(arg)
	inner := expr
	for {
		lower := strings.ToLower(inner)
		var prefix string
		switch {
		case strings.HasPrefix(lower, "apply_filters_deprecated"):
			prefix = "apply_filters_deprecated"
		case strings.HasPrefix(lower, "apply_filters"):
			prefix = "apply_filters"
		default:
			if lit := soleStringLiteral(inner); lit != "" {
				return lit, expr
			}
			return "", expr
		}
		rest := strings.TrimSpace(inner[len(prefix):])
		if !strings.HasPrefix(rest, "(") {
			return "", expr
		}
		close := matchDelimiter(rest, 0, '(', ')')
		if close < 0 {
			return "", expr
		}
		args := splitTopLevelArgs(rest[1:close], maskNonCode(rest[1:close]))
		if len(args) < 2 {
			return "", expr
		}
		// The default value is the second argument; a filter can still override
		// it at runtime, so this is the level the plugin ships with.
		inner = strings.TrimSpace(args[1])
	}
}

// soleStringLiteral returns the string literal an argument consists of, or ""
// when the argument is a variable, a constant or a larger expression.
func soleStringLiteral(arg string) string {
	arg = strings.TrimSpace(arg)
	if len(arg) < 2 || (arg[0] != '\'' && arg[0] != '"') {
		return ""
	}
	end := skipString(arg, 0)
	if end != len(arg)-1 {
		return ""
	}
	return arg[1:end]
}

// splitTopLevelArgs splits an argument list on commas that are not nested
// inside parentheses, brackets or braces. The mask is used for the structure so
// a comma inside a string cannot split an argument, while the slices come from
// the original text so literals survive intact.
func splitTopLevelArgs(args, mask string) []string {
	if strings.TrimSpace(args) == "" {
		return nil
	}
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(mask) && i < len(args); i++ {
		switch mask[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, args[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, args[start:])
	return out
}

// classifyCheck decides how much of the enclosing function a check protects.
func classifyCheck(mask string, decls []FuncDecl, callStart, parenClose int, scope BodyScope) GuardKind {
	stmtStart := statementStart(mask, callStart)
	prefix := mask[stmtStart:callStart]

	kwLoc := lastConditionKeyword(prefix)
	if kwLoc == nil {
		// Not a condition: an assignment, or an argument to something else.
		// Such a check gates nothing by itself; the assign-then-test idiom is
		// picked up separately.
		return GuardNone
	}
	kw := strings.ToLower(strings.Join(strings.Fields(prefix[kwLoc[0]:kwLoc[1]]), ""))
	isElseIf := kw != "if"

	condOpen := skipTrivia(mask, stmtStart+kwLoc[1])
	if condOpen >= len(mask) || mask[condOpen] != '(' {
		return GuardNone
	}
	condClose := matchDelimiter(mask, condOpen, '(', ')')
	if condClose < 0 || condClose < parenClose {
		return GuardNone
	}

	negated := negationParity(mask, condOpen, callStart)%2 == 1
	branch, branchEnd := branchAfter(mask, condClose)
	bodyDepth := enclosingBodyDepth(mask, decls, callStart)
	atTopLevel := depthAt(mask, callStart) == bodyDepth

	if negated {
		if !branchRefusesRequest(branch, scope) {
			// `if ( ! can ) { $msg = 'nope'; }` -- execution continues regardless.
			return GuardNone
		}
		if isElseIf {
			// An elseif arm is reached only when the earlier conditions were
			// false, so at least one arm already ran without this check and the
			// construct cannot dominate the statements those arms executed.
			return GuardBranch
		}
		if !atTopLevel {
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
			// -- it protects only that branch, which is exactly the shape that
			// made the old presence-based inference report Admin for an
			// unguarded sink.
			return GuardBranch
		}
		return GuardFunction
	}

	// Positive form: `if ( can ) { ... }`.
	//
	// It gets the same two tests the negated form gets, which it used to skip
	// entirely: a positive check three blocks deep, or one sitting after the
	// sink it is supposed to protect, was reported as gating the whole
	// function.
	if isElseIf || !atTopLevel || !nothingExecutesBefore(mask, decls, callStart) {
		return GuardBranch
	}
	if branchEnd > 0 && nothingExecutesAfter(mask, branchEnd) {
		// The branch is the whole body; there is no unprotected tail.
		return GuardFunction
	}
	if branchEnd > 0 && chainRefusesEveryOtherArm(mask, branchEnd, scope) {
		// `if ( can ) { work(); } else { wp_die(); }` -- the only way execution
		// reaches anything after the construct is through the true arm, so the
		// check dominates the rest of the body exactly as a negated guard does.
		return GuardFunction
	}
	return GuardBranch
}

// classifyAssignedCheck follows one hop of `$v = <check>; ... if ( ! $v ) {
// terminate; }`, which has the same control flow as the inline form: only a
// temporary got in the way.
//
// The classification is keyed off the TEST, not the assignment, because the
// test is the statement that dominates what follows. Keeping the assignment's
// depth would call this gating:
//
//	$can = current_user_can( 'manage_options' );   // depth 1
//	if ( isset( $_POST['admin_op'] ) ) {
//	    if ( ! $can ) { wp_die(); }                // depth 2, gates this branch
//	}
//	update_option( 'o', $_POST['v'] );             // reached by anyone
func classifyAssignedCheck(mask string, decls []FuncDecl, callStart, parenClose int, scope BodyScope) (GuardKind, bool) {
	stmtStart := statementStart(mask, callStart)
	m := assignedCheckPattern.FindStringSubmatch(mask[stmtStart:callStart])
	if m == nil {
		return GuardNone, false
	}
	varName := "$" + m[1]
	assignNegated := strings.TrimSpace(m[2]) == "!"

	// The variable must hold the check's result and nothing else. `$x =
	// current_user_can(X) ? 'y' : 'n';` assigns two truthy strings, so a later
	// `if ( ! $x )` never fires and reading it as a gate would invent one.
	end := skipTrivia(mask, parenClose+1)
	if end >= len(mask) || mask[end] != ';' {
		return GuardNone, false
	}
	assignEnd := end + 1
	pos := assignEnd

	for {
		idx := indexToken(mask, varName, pos)
		if idx < 0 {
			return GuardNone, false
		}
		after := skipTrivia(mask, idx+len(varName))
		if after < len(mask) && mask[after] == '=' &&
			(after+1 >= len(mask) || (mask[after+1] != '=' && mask[after+1] != '>')) {
			// Reassigned before it was tested: whatever the capability said, it
			// is not what the test sees.
			return GuardNone, false
		}

		stmt := statementStart(mask, idx)
		kwLoc := lastConditionKeyword(mask[stmt:idx])
		if kwLoc == nil {
			pos = idx + len(varName)
			continue
		}
		kw := strings.ToLower(strings.Join(strings.Fields(mask[stmt+kwLoc[0]:stmt+kwLoc[1]]), ""))
		condOpen := skipTrivia(mask, stmt+kwLoc[1])
		if condOpen >= len(mask) || mask[condOpen] != '(' {
			return GuardNone, false
		}
		condClose := matchDelimiter(mask, condOpen, '(', ')')
		if condClose < 0 {
			return GuardNone, false
		}

		testNegated := negationParity(mask, condOpen, idx)%2 == 1
		negated := testNegated != assignNegated
		branch, branchEnd := branchAfter(mask, condClose)
		bodyDepth := enclosingBodyDepth(mask, decls, idx)
		atTopLevel := depthAt(mask, idx) == bodyDepth

		if negated {
			if !branchRefusesRequest(branch, scope) {
				return GuardNone, false
			}
			if kw != "if" || !atTopLevel {
				return GuardBranch, true
			}
			return GuardFunction, true
		}
		if kw != "if" || !atTopLevel {
			return GuardBranch, true
		}
		// The positive form protects only what follows it, so nothing but the
		// assignment itself may run before the test -- otherwise
		// `$can = current_user_can(X); update_option('o',$_POST['v']); if ($can)
		// { admin(); }` would read as gated while update_option runs for anyone.
		if !nothingExecutesBefore(mask, decls, callStart) ||
			strings.TrimSpace(mask[assignEnd:stmt]) != "" {
			return GuardBranch, true
		}
		if branchEnd > 0 && (nothingExecutesAfter(mask, branchEnd) ||
			chainRefusesEveryOtherArm(mask, branchEnd, scope)) {
			return GuardFunction, true
		}
		return GuardBranch, true
	}
}

// indexToken finds the next occurrence of a whole token, so `$can` does not
// match inside `$cannot`.
func indexToken(s, token string, from int) int {
	for i := from; ; {
		idx := strings.Index(s[i:], token)
		if idx < 0 {
			return -1
		}
		idx += i
		end := idx + len(token)
		if end >= len(s) || !isTypeChar(s[end]) {
			return idx
		}
		i = end
	}
}

// lastConditionKeyword returns the offsets of the `if` / `elseif` / `else if`
// that governs the end of prefix, or nil when there is none.
func lastConditionKeyword(prefix string) []int {
	all := conditionKeywordPattern.FindAllStringIndex(prefix, -1)
	if len(all) == 0 {
		return nil
	}
	last := all[len(all)-1]
	// `else if` is matched as one keyword; an `if` immediately preceded by
	// `else` is the same construct written apart.
	if len(all) > 1 {
		prev := all[len(all)-2]
		if strings.EqualFold(strings.TrimSpace(prefix[prev[0]:prev[1]]), "else") {
			return []int{prev[0], last[1]}
		}
	}
	return last
}

// negationParity counts the negations that dominate a check inside a condition.
//
// It is a parity count rather than "does a `!` appear anywhere", because
// `if ( ! empty( $id ) && current_user_can( 'manage_options' ) ) { wp_die(); }`
// contains a `!` that belongs to a different operand entirely: the capability
// check there is positive, the branch refuses callers who HAVE the capability,
// and reading it as a negated guard reported Admin for a handler that gates
// nothing.
func negationParity(mask string, condOpen, callStart int) int {
	stack := []int{}
	pending := 0
	for i := condOpen + 1; i < callStart && i < len(mask); i++ {
		switch mask[i] {
		case '!':
			if i+1 < len(mask) && mask[i+1] == '=' {
				continue // a comparison, not a negation
			}
			pending++
		case '(':
			n := pending
			if identifierBefore(mask, i) == "empty" {
				// empty(X) is false exactly when X is truthy.
				n++
			}
			stack = append(stack, n)
			pending = 0
		case ')':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			pending = 0
		case '&', '|':
			// A new operand begins; a pending negation belonged to the last one.
			pending = 0
		}
	}
	total := pending
	for _, n := range stack {
		total += n
	}
	return total
}

// identifierBefore returns the identifier immediately preceding pos, if any.
func identifierBefore(s string, pos int) string {
	i := pos
	for i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
		i--
	}
	end := i
	for i > 0 && isTypeChar(s[i-1]) {
		i--
	}
	return strings.ToLower(s[i:end])
}

// branchAfter extracts the branch that follows a condition, braced or not, and
// returns it with the offset of its last byte.
func branchAfter(mask string, condClose int) (string, int) {
	start := skipTrivia(mask, condClose+1)
	if start >= len(mask) {
		return "", 0
	}
	if mask[start] == '{' {
		if close := findMatchingBrace(mask, start); close > 0 {
			return mask[start:close], close
		}
		return "", 0
	}
	// Brace-less single statement: `if ( ! current_user_can(..) ) return;`
	if semi := strings.IndexByte(mask[start:], ';'); semi >= 0 {
		return mask[start : start+semi+1], start + semi
	}
	return "", 0
}

// branchRefusesRequest reports whether taking this branch stops the request.
//
// wp_die and friends do so from any depth. `return` does so only when the body
// this branch sits in is what WordPress dispatched -- an endpoint callback, or
// a permission_callback whose falsy return core turns into rest_forbidden. In a
// helper, `return` hands control back to a caller that carries on, so the
// helper's guard protects the helper and nothing else.
func branchRefusesRequest(branch string, scope BodyScope) bool {
	if requestTerminatorPattern.MatchString(branch) {
		return true
	}
	return scope == ScopeRequest && returnPattern.MatchString(branch)
}

// chainRefusesEveryOtherArm reports whether every arm of the if/elseif/else
// chain OTHER than the one just examined ends the request.
//
// When they do, the only way execution reaches the code after the chain is
// through the examined arm, so its condition dominates the rest of the body.
// A chain with no final else does not qualify: falling off the end of it
// reaches the following statements with no arm having run.
func chainRefusesEveryOtherArm(mask string, branchEnd int, scope BodyScope) bool {
	pos := branchEnd
	sawElse := false
	for {
		i := skipTrivia(mask, pos+1)
		if i >= len(mask) || !hasWordAt(mask, i, "else") {
			return sawElse
		}
		j := skipTrivia(mask, i+4)
		if hasWordAt(mask, j, "if") {
			condOpen := skipTrivia(mask, j+2)
			if condOpen >= len(mask) || mask[condOpen] != '(' {
				return false
			}
			condClose := matchDelimiter(mask, condOpen, '(', ')')
			if condClose < 0 {
				return false
			}
			arm, end := branchAfter(mask, condClose)
			if !armEndsRequest(arm, scope) {
				return false
			}
			pos = end
			continue
		}
		// A plain `else`: the last arm of the chain.
		arm, _ := branchAfterElse(mask, i+4)
		if !armEndsRequest(arm, scope) {
			return false
		}
		return true
	}
}

// branchAfterElse extracts the arm of a plain `else`.
func branchAfterElse(mask string, after int) (string, int) {
	start := skipTrivia(mask, after)
	if start >= len(mask) {
		return "", 0
	}
	if mask[start] == '{' {
		if close := findMatchingBrace(mask, start); close > 0 {
			return mask[start:close], close
		}
		return "", 0
	}
	if semi := strings.IndexByte(mask[start:], ';'); semi >= 0 {
		return mask[start : start+semi+1], start + semi
	}
	return "", 0
}

// armEndsRequest is branchRefusesRequest with one extra restriction, because
// this arm is the one the caller does NOT pass through.
//
// A `return` whose expression contains a call does not refuse: the callee runs
// first, with whatever the request supplied. `else { return $this->public_view(
// $_POST ); }` hands every unprivileged caller straight to public_view(), so
// treating it as a refusal would report the whole function as gated.
func armEndsRequest(arm string, scope BodyScope) bool {
	if requestTerminatorPattern.MatchString(arm) {
		return true
	}
	if scope != ScopeRequest {
		return false
	}
	locs := returnPattern.FindAllStringIndex(arm, -1)
	if len(locs) == 0 {
		return false
	}
	for _, loc := range locs {
		expr := arm[loc[1]:]
		if semi := strings.IndexByte(expr, ';'); semi >= 0 {
			expr = expr[:semi]
		}
		if strings.ContainsRune(expr, '(') {
			return false
		}
	}
	return true
}

func hasWordAt(s string, i int, word string) bool {
	if i < 0 || i+len(word) > len(s) {
		return false
	}
	if !strings.EqualFold(s[i:i+len(word)], word) {
		return false
	}
	return i+len(word) == len(s) || !isTypeChar(s[i+len(word)])
}

// nothingExecutesBefore reports whether the guard is the first statement of the
// body it sits in. A positive guard preceded by executable code cannot protect
// that code, and reporting the function as gated hides it:
//
//	update_option( 'o', $_POST['v'] );                        // already ran
//	if ( current_user_can( 'manage_options' ) ) { admin(); }
func nothingExecutesBefore(mask string, decls []FuncDecl, callStart int) bool {
	start := enclosingBodyStart(mask, decls, callStart)
	stmt := statementStart(mask, callStart)
	if stmt <= start {
		return true
	}
	return strings.TrimSpace(mask[start:stmt]) == ""
}

// nothingExecutesAfter reports whether the remainder of the body is only
// closing braces and whitespace. Callers hand us a body that still carries its
// own enclosing braces, so "the branch is the last thing in the function" shows
// up as a tail of "}" rather than an empty string.
//
// Comments are skipped, because a comment is not a statement in any PHP program
// and a rule that changes its answer because of a trailing `// done` is
// measuring lexical noise. A `?>` is NOT skipped: it does not end the function,
// it switches the parser to output mode, and every byte until the next `<?php`
// is echoed on each call whether or not the check passed.
func nothingExecutesAfter(mask string, pos int) bool {
	for i := pos + 1; i < len(mask); i++ {
		switch mask[i] {
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
func statementStart(mask string, pos int) int {
	for i := pos - 1; i >= 0; i-- {
		switch mask[i] {
		case ';', '{', '}':
			return i + 1
		}
	}
	return 0
}

// firstStringLiteral returns the first quoted string in an argument list. It is
// kept for callers that only want the leading literal; the capability of a
// check is read with capabilityFromArg, which knows where each core function
// puts it.
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

// StrongestGuard returns the capabilities of the checks that protect the whole
// function, if any, and whether one exists.
//
// When several checks gate the function, the LOWEST privilege wins: passing any
// one of them is enough to get in, so the weakest is what an attacker needs.
// Callers resolve the capability strings to levels, so this returns them all.
//
// It reports not-gated when the text handed over is not a single function body.
// The checks in a whole file gate the functions they sit in; attributing one of
// them to the file would make the answer depend on which slice the caller took.
func StrongestGuard(body string) (caps []string, gated bool) {
	guards, selfContained := analyseGuards(body, ScopeRequest)
	if !selfContained {
		return nil, false
	}
	for _, g := range guards {
		if g.Kind != GuardFunction || g.IsIdentity {
			continue
		}
		gated = true
		if g.Capability != "" {
			caps = append(caps, g.Capability)
		}
	}
	return caps, gated
}

// depthAt returns the brace nesting depth at an offset. It runs on the masked
// text, so a "{" inside a string literal, a comment or a block of template
// output cannot shift the count.
func depthAt(mask string, pos int) int {
	depth := 0
	for i := 0; i < pos && i < len(mask); i++ {
		switch mask[i] {
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
func topLevelDepth(mask string) int {
	i := skipTrivia(mask, 0)
	if i < len(mask) && mask[i] == '{' {
		return 1
	}
	return 0
}

// enclosingBodyDepth is the depth at which the statements of the function
// containing pos sit.
//
// Brace depth is relative to the enclosing function declaration, not to the
// start of whatever substring a caller sliced. Measuring it against the blob's
// first byte made the answer depend on the slice: handed one method's body,
// `if ( ! current_user_can('manage_options') ) { die(); }` classified as gating
// the function; handed the file that method lives in, the identical check
// classified as gating only a branch, because the file starts with "<?php"
// rather than "{" and the check sits two braces deep inside a class.
//
// Only NAMED declarations count. An inline closure inside a route-definition
// array is not the enclosing function of the surrounding code, and treating it
// as one would promote a callback's internal check into the route's level.
func enclosingBodyDepth(mask string, decls []FuncDecl, pos int) int {
	if d, ok := innermostDecl(decls, pos); ok {
		return depthAt(mask, d.BodyOpen) + 1
	}
	return topLevelDepth(mask)
}

// enclosingBodyStart is the offset just inside the enclosing body's brace.
func enclosingBodyStart(mask string, decls []FuncDecl, pos int) int {
	if d, ok := innermostDecl(decls, pos); ok {
		return d.BodyOpen + 1
	}
	if topLevelDepth(mask) == 1 {
		return skipTrivia(mask, 0) + 1
	}
	return 0
}

// innermostDecl returns the tightest named declaration whose body contains pos.
func innermostDecl(decls []FuncDecl, pos int) (FuncDecl, bool) {
	var best FuncDecl
	found := false
	for _, d := range decls {
		if pos <= d.BodyOpen || pos >= d.BodyClose {
			continue
		}
		if !found || d.BodyOpen > best.BodyOpen {
			best, found = d, true
		}
	}
	return best, found
}

// skipTrivia advances over whitespace and comments, which are not statements in
// any PHP program.
func skipTrivia(mask string, i int) int {
	for i < len(mask) {
		switch mask[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

// maskNonCode returns a copy of body in which the contents of string literals,
// comments, heredocs and template-output regions are replaced by spaces.
//
// Every offset is preserved, so structural scans (brace depth, delimiter
// matching, keyword search) run on the mask while literals are read from the
// original text. Without it a "{" in a comment or a JavaScript snippet inside a
// heredoc shifts the nesting count, and a capability name mentioned in a
// comment reads as a check.
func maskNonCode(body string) string {
	out := []byte(body)
	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			if out[i] != '\n' && out[i] != '\r' {
				out[i] = ' '
			}
		}
	}
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\'', '"':
			end := skipString(body, i)
			if end < 0 {
				blank(i+1, len(body))
				return string(out)
			}
			blank(i+1, end)
			i = end
		case '/':
			if i+1 < len(body) && body[i+1] == '/' {
				j := strings.IndexByte(body[i:], '\n')
				if j < 0 {
					blank(i, len(body))
					return string(out)
				}
				blank(i, i+j)
				i += j
			} else if i+1 < len(body) && body[i+1] == '*' {
				j := strings.Index(body[i+2:], "*/")
				if j < 0 {
					blank(i, len(body))
					return string(out)
				}
				blank(i, i+2+j+2)
				i += 2 + j + 1
			}
		case '#':
			// PHP 8 attributes start "#[" and are not comments.
			if i+1 < len(body) && body[i+1] == '[' {
				continue
			}
			j := strings.IndexByte(body[i:], '\n')
			if j < 0 {
				blank(i, len(body))
				return string(out)
			}
			blank(i, i+j)
			i += j
		case '<':
			if strings.HasPrefix(body[i:], "<<<") {
				if end := heredocEnd(body, i); end > i {
					blank(i, end)
					i = end - 1
				}
			}
		case '?':
			// Everything between "?>" and the next opening tag is echoed on
			// every call. The "?>" itself is kept so callers can still see that
			// output follows.
			if i+1 < len(body) && body[i+1] == '>' {
				rest := body[i+2:]
				next := strings.Index(rest, "<?")
				if next < 0 {
					blank(i+2, len(body))
					return string(out)
				}
				blank(i+2, i+2+next)
				i = i + 2 + next
			}
		}
	}
	return string(out)
}

// heredocEnd returns the offset just past a heredoc or nowdoc starting at i.
func heredocEnd(body string, i int) int {
	j := i + 3
	for j < len(body) && (body[j] == ' ' || body[j] == '\t') {
		j++
	}
	quote := byte(0)
	if j < len(body) && (body[j] == '\'' || body[j] == '"') {
		quote = body[j]
		j++
	}
	start := j
	for j < len(body) && isTypeChar(body[j]) {
		j++
	}
	if j == start {
		return -1
	}
	label := body[start:j]
	if quote != 0 {
		if j >= len(body) || body[j] != quote {
			return -1
		}
		j++
	}
	for {
		nl := strings.IndexByte(body[j:], '\n')
		if nl < 0 {
			return len(body)
		}
		j += nl + 1
		k := j
		for k < len(body) && (body[k] == ' ' || body[k] == '\t') {
			k++
		}
		if strings.HasPrefix(body[k:], label) {
			e := k + len(label)
			if e >= len(body) || !isTypeChar(body[e]) {
				return e
			}
		}
	}
}

// symbolLiterals resolves a capability held in a symbol back to the string
// literals it can hold.
//
// PHP evaluates current_user_can()'s argument before the call, so a symbol that
// only ever holds one literal is the same question as writing that literal
// inline. What the language guarantees differs by symbol, and so does the rule:
//
//   - A class constant or a define() cannot be rebound, so its literal is the
//     value at every call site.
//   - A property or a local can be reassigned. It is resolved only when NO
//     assignment gives it a non-literal -- a constructor argument, a setter, a
//     get_option() -- because one such assignment means the initialiser is a
//     default rather than the value. A plugin whose settings screen holds
//     `public $capability = 'manage_options';` beside `set_capability($c) {
//     $this->capability = $c; }` is not an admin screen; it is a screen whose
//     capability the consumer chooses.
//   - A local is resolved only from assignments inside the body it is used in,
//     because PHP scopes locals to the function. Reading `$cap = 'manage_options'`
//     out of a different function in the same file and applying it here is not
//     the language fact this rests on, it is the opposite of it.
//
// Several candidate literals yield all of them, and the caller takes the lowest
// level: passing any one of them gets in.
func symbolLiterals(expr, body, fileContent string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}

	if rest, ok := trimPrefixFold(expr, "$this->"); ok && isPlainIdentifier(rest) {
		mask := maskNonCode(fileContent)
		lits, rebound := assignedLiterals(fileContent, mask, "$this->"+rest)
		if rebound {
			return nil
		}
		decl, declRebound := propertyDeclLiterals(fileContent, mask, rest)
		if declRebound {
			return nil
		}
		return append(lits, decl...)
	}

	if strings.HasPrefix(expr, "$") && isPlainIdentifier(expr[1:]) {
		lits, rebound := assignedLiterals(body, maskNonCode(body), expr)
		if rebound {
			return nil
		}
		return lits
	}

	if i := strings.LastIndex(expr, "::"); i > 0 {
		name := expr[i+2:]
		if isPlainIdentifier(name) {
			return constantLiterals(fileContent, maskNonCode(fileContent), name)
		}
	}
	if isPlainIdentifier(expr) {
		// A bare global constant, reached through define() or `const`.
		return constantLiterals(fileContent, maskNonCode(fileContent), expr)
	}
	return nil
}

// assignedLiterals collects the literals assigned to a symbol, and reports
// whether any assignment gave it something other than a literal.
func assignedLiterals(content, mask, symbol string) (lits []string, rebound bool) {
	for pos := 0; ; {
		idx := indexToken(mask, symbol, pos)
		if idx < 0 {
			return lits, rebound
		}
		pos = idx + len(symbol)
		eq := skipTrivia(mask, pos)
		if eq >= len(mask) || mask[eq] != '=' {
			continue
		}
		if eq+1 < len(mask) && (mask[eq+1] == '=' || mask[eq+1] == '>') {
			continue // a comparison or an array arrow
		}
		rhs := skipTrivia(mask, eq+1)
		if rhs >= len(content) || (content[rhs] != '\'' && content[rhs] != '"') {
			rebound = true
			continue
		}
		end := skipString(content, rhs)
		if end < 0 {
			rebound = true
			continue
		}
		lits = append(lits, content[rhs+1:end])
	}
}

// propertyDeclLiterals collects the literals a property declaration gives a
// name, and reports whether any declaration gives it a non-literal.
func propertyDeclLiterals(content, mask, name string) (lits []string, rebound bool) {
	symbol := "$" + name
	for pos := 0; ; {
		idx := indexToken(mask, symbol, pos)
		if idx < 0 {
			return lits, rebound
		}
		pos = idx + len(symbol)
		switch identifierBeforeSkippingTypes(mask, idx) {
		case "public", "private", "protected", "var", "static", "readonly":
		default:
			continue
		}
		eq := skipTrivia(mask, pos)
		if eq >= len(mask) || mask[eq] != '=' {
			continue
		}
		rhs := skipTrivia(mask, eq+1)
		if rhs >= len(content) || (content[rhs] != '\'' && content[rhs] != '"') {
			rebound = true
			continue
		}
		end := skipString(content, rhs)
		if end < 0 {
			rebound = true
			continue
		}
		lits = append(lits, content[rhs+1:end])
	}
}

// identifierBeforeSkippingTypes walks back over a possible type declaration to
// find the visibility modifier of a property.
func identifierBeforeSkippingTypes(mask string, pos int) string {
	id := identifierBefore(mask, pos)
	switch id {
	case "", "public", "private", "protected", "var", "static", "readonly":
		return id
	}
	// `private string $capability = ...` -- step over the type.
	i := pos
	for i > 0 && (mask[i-1] == ' ' || mask[i-1] == '\t') {
		i--
	}
	for i > 0 && (isTypeChar(mask[i-1]) || mask[i-1] == '?' || mask[i-1] == '\\' || mask[i-1] == '|') {
		i--
	}
	return identifierBefore(mask, i)
}

// constantLiterals collects the literals a class constant or a define() gives a
// name. Constants cannot be rebound, so every definition is a real candidate.
func constantLiterals(content, mask, name string) []string {
	var lits []string

	for pos := 0; ; {
		idx := indexToken(mask, name, pos)
		if idx < 0 {
			break
		}
		pos = idx + len(name)
		if identifierBefore(mask, idx) != "const" {
			continue
		}
		eq := skipTrivia(mask, pos)
		if eq >= len(mask) || mask[eq] != '=' {
			continue
		}
		rhs := skipTrivia(mask, eq+1)
		if rhs >= len(content) || (content[rhs] != '\'' && content[rhs] != '"') {
			continue
		}
		if end := skipString(content, rhs); end > 0 {
			lits = append(lits, content[rhs+1:end])
		}
	}

	for pos := 0; ; {
		idx := indexToken(mask, "define", pos)
		if idx < 0 {
			break
		}
		pos = idx + len("define")
		open := skipTrivia(mask, pos)
		if open >= len(mask) || mask[open] != '(' {
			continue
		}
		close := matchDelimiter(mask, open, '(', ')')
		if close < 0 {
			continue
		}
		args := splitTopLevelArgs(content[open+1:close], mask[open+1:close])
		if len(args) < 2 {
			continue
		}
		if soleStringLiteral(args[0]) != name {
			continue
		}
		if lit := soleStringLiteral(args[1]); lit != "" {
			lits = append(lits, lit)
		}
	}
	return lits
}

func isPlainIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTypeChar(s[i]) {
			return false
		}
	}
	return true
}

func trimPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// permissionCallbackLevel resolves the level a REST permission_callback
// enforces from the value it returns.
//
// WP_REST_Server::dispatch_request() calls the permission_callback and, when
// the result is falsy or a WP_Error, answers rest_forbidden without ever
// invoking the route's callback. So for a permission_callback the RETURN VALUE
// is the gate -- `return current_user_can('manage_options');` requires
// manage_options as surely as `if ( ! current_user_can('manage_options') ) {
// wp_die(); }` does, with core rather than the plugin doing the refusing. That
// is a fact about core, not a convention, so it holds for any plugin.
//
// This is the only rule in this file that can RAISE a level, so it answers only
// where it is certain, and every uncertainty resolves to Unauthenticated:
//
//   - The level is the MINIMUM over the paths that RETURN, because a caller
//     needs only the cheapest of them. An unconditional `return true` admits
//     everyone and settles the whole callback.
//   - A predicate reaching the return under an odd number of negations does not
//     raise anything: `return ! current_user_can('manage_options');` admits
//     precisely the callers who lack the capability.
//   - `A && B` needs both, so the level is the maximum of the operands that
//     resolve; an operand that does not resolve can only make it harder.
//     `A || B` needs either, so it is the minimum -- and one unresolvable
//     disjunct may be satisfiable by anyone, so the whole expression is unknown.
//   - A capability that is not a string literal yields no level at all -- which
//     is why this takes no file to resolve symbols from. The Subscriber floor is
//     defensible for a check that demonstrably refuses; it is not defensible for
//     a returned boolean whose capability is a property expression that a
//     post-type registration decides.
func permissionCallbackLevel(body string) (models.AuthLevel, bool) {
	mask := maskNonCode(body)
	if len(FindFunctionDeclarations(mask)) > 0 {
		return 0, false
	}
	top := topLevelDepth(mask)
	start := 0
	if top == 1 {
		start = skipTrivia(mask, 0) + 1
	}

	best := models.AuthLevel(-1)
	for _, loc := range returnPattern.FindAllStringIndex(mask, -1) {
		if loc[0] < start {
			continue
		}
		lvl, ok, decided := returnPathLevel(body, mask, loc, top)
		if !decided {
			return 0, false
		}
		if !ok {
			continue // this path refuses; it admits nobody
		}
		if best < 0 || lvl < best {
			best = lvl
		}
	}
	if best < 0 {
		return 0, false
	}
	return best, true
}

// returnPathLevel resolves one `return` statement into the level a caller needs
// to reach it and be admitted.
//
// decided is false when the path cannot be read at all, which forces the whole
// callback to Unauthenticated: a return nested in a loop, an else arm, a
// closure, or guarded by a condition that is not a privilege test could admit
// anyone, and guessing otherwise is the over-restricting direction.
func returnPathLevel(body, mask string, loc []int, top int) (lvl models.AuthLevel, admits, decided bool) {
	depth := depthAt(mask, loc[0])
	cond := ""
	switch depth {
	case top:
		// Possibly a brace-less `if ( C ) return X;`.
		stmt := statementStart(mask, loc[0])
		if kwLoc := lastConditionKeyword(mask[stmt:loc[0]]); kwLoc != nil {
			kw := strings.ToLower(strings.Join(strings.Fields(mask[stmt+kwLoc[0]:stmt+kwLoc[1]]), ""))
			if kw != "if" {
				return 0, false, false
			}
			condOpen := skipTrivia(mask, stmt+kwLoc[1])
			if condOpen >= len(mask) || mask[condOpen] != '(' {
				return 0, false, false
			}
			condClose := matchDelimiter(mask, condOpen, '(', ')')
			if condClose < 0 {
				return 0, false, false
			}
			cond = body[condOpen+1 : condClose]
		}
	case top + 1:
		open := enclosingBlockOpen(mask, loc[0], top)
		if open < 0 {
			return 0, false, false
		}
		condClose := skipTriviaBack(mask, open)
		if condClose <= 0 || mask[condClose] != ')' {
			return 0, false, false
		}
		condOpen := matchDelimiterBack(mask, condClose)
		if condOpen < 0 {
			return 0, false, false
		}
		if !hasWordAt(mask, skipTriviaBackToWord(mask, condOpen), "if") {
			return 0, false, false
		}
		// An `if` that is the tail of an `else if` chain is not the only way in.
		wordStart := skipTriviaBackToWord(mask, condOpen)
		if before := identifierBefore(mask, wordStart); before == "else" || before == "elseif" {
			return 0, false, false
		}
		cond = body[condOpen+1 : condClose]
	default:
		return 0, false, false
	}

	value := body[loc[1]:]
	if semi := strings.IndexByte(mask[loc[1]:], ';'); semi >= 0 {
		value = value[:semi]
	}

	switch classifyReturnValue(value) {
	case returnFalsy:
		// This path refuses; it constrains nobody.
		return 0, false, true
	case returnTruthy:
		if cond == "" {
			// An unconditional `return true` admits everyone.
			return 0, false, false
		}
		condLvl, ok := predicateLevel(cond)
		if !ok {
			return 0, false, false
		}
		return condLvl, true, true
	default:
		valLvl, ok := predicateLevel(value)
		if !ok {
			return 0, false, false
		}
		if cond == "" {
			return valLvl, true, true
		}
		condLvl, ok := predicateLevel(cond)
		if !ok {
			return 0, false, false
		}
		if condLvl > valLvl {
			return condLvl, true, true
		}
		return valLvl, true, true
	}
}

type returnValueKind int

const (
	returnExpr returnValueKind = iota
	returnTruthy
	returnFalsy
)

// classifyReturnValue separates the two values core reads as a verdict from an
// expression that has to be evaluated.
func classifyReturnValue(value string) returnValueKind {
	v := strings.ToLower(strings.TrimSpace(value))
	v = strings.TrimSpace(strings.Trim(v, "()"))
	switch v {
	case "true", "1":
		return returnTruthy
	case "", "false", "0", "null", "0.0", "''", `""`:
		return returnFalsy
	}
	if strings.HasPrefix(v, "new wp_error") || strings.HasPrefix(v, `new \wp_error`) {
		return returnFalsy
	}
	return returnExpr
}

// predicateLevel evaluates a boolean expression as an authorization test.
func predicateLevel(expr string) (models.AuthLevel, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return 0, false
	}
	mask := maskNonCode(expr)

	// Strip one layer of enclosing parentheses.
	if strings.HasPrefix(strings.TrimSpace(mask), "(") {
		open := skipTrivia(mask, 0)
		if close := matchDelimiter(mask, open, '(', ')'); close == len(strings.TrimRight(mask, " \t\r\n"))-1 {
			return predicateLevel(expr[open+1 : close])
		}
	}

	if parts := splitTopLevelOperator(expr, mask, "||"); len(parts) > 1 {
		best := models.AuthLevel(-1)
		for _, p := range parts {
			lvl, ok := predicateLevel(p)
			if !ok {
				// One unknown alternative may be satisfiable by anyone.
				return 0, false
			}
			if best < 0 || lvl < best {
				best = lvl
			}
		}
		return best, true
	}
	if parts := splitTopLevelOperator(expr, mask, "&&"); len(parts) > 1 {
		best := models.AuthLevel(-1)
		for _, p := range parts {
			lvl, ok := predicateLevel(p)
			if !ok {
				continue // an unknown conjunct can only make entry harder
			}
			if lvl > best {
				best = lvl
			}
		}
		if best < 0 {
			return 0, false
		}
		return best, true
	}

	if strings.HasPrefix(expr, "!") || strings.HasPrefix(strings.ToLower(expr), "empty") {
		// Negation flips the predicate, so it cannot establish a requirement.
		return 0, false
	}

	guards, _ := analyseGuards(expr, ScopeRequest)
	if len(guards) != 1 || guards[0].Offset != 0 {
		return 0, false
	}
	g := guards[0]
	if g.IsIdentity {
		return g.Implied, true
	}
	if g.Capability == "" {
		return 0, false
	}
	return resolveCapabilityForSubject(g.Capability, g.HasSubjectArg)
}

// splitTopLevelOperator splits an expression on an operator that is not nested.
func splitTopLevelOperator(expr, mask, op string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i+len(op) <= len(mask); i++ {
		switch mask[i] {
		case '(', '[', '{':
			depth++
			continue
		case ')', ']', '}':
			depth--
			continue
		}
		if depth == 0 && mask[i:i+len(op)] == op {
			out = append(out, expr[start:i])
			start = i + len(op)
			i += len(op) - 1
		}
	}
	if len(out) == 0 {
		return nil
	}
	return append(out, expr[start:])
}

// enclosingBlockOpen finds the "{" of the block containing pos, when that block
// sits at the body's top level.
func enclosingBlockOpen(mask string, pos, top int) int {
	depth := 0
	for i := pos - 1; i >= 0; i-- {
		switch mask[i] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				if depthAt(mask, i) == top {
					return i
				}
				return -1
			}
			depth--
		}
	}
	return -1
}

func skipTriviaBack(mask string, i int) int {
	j := i - 1
	for j >= 0 && (mask[j] == ' ' || mask[j] == '\t' || mask[j] == '\r' || mask[j] == '\n') {
		j--
	}
	return j
}

// matchDelimiterBack finds the "(" that the ")" at pos closes.
func matchDelimiterBack(mask string, pos int) int {
	depth := 0
	for i := pos; i >= 0; i-- {
		switch mask[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// skipTriviaBackToWord returns the offset of the identifier ending just before
// pos.
func skipTriviaBackToWord(mask string, pos int) int {
	j := skipTriviaBack(mask, pos)
	end := j + 1
	for j >= 0 && isTypeChar(mask[j]) {
		j--
	}
	if j+1 == end {
		return -1
	}
	return j + 1
}

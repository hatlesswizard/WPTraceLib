package analyzer

import (
	"regexp"
	"strings"
)

// An anonymous function passed straight to a WordPress registration call is a
// real entry point with no name:
//
//	register_rest_route( 'ns/v1', '/thing', array(
//	    'callback'            => function ( $request ) { return $this->handle( $request ); },
//	    'permission_callback' => '__return_true',
//	) );
//
// Every detector reports these with the callback "closure", and every walk in
// callgraph.go returns immediately on that sentinel. The endpoint is therefore
// reported -- correctly, and often as unauthenticated -- while everything it can
// reach is invisible. In the benchmark corpus ten entries fail exactly this way,
// and the plugins where it happens are the ones that register the most routes.
//
// The body is right there in the file the endpoint was found in, so it can be
// read. What cannot be recovered from the callback string alone is WHICH
// closure in the file this endpoint used: the sentinel carries no position. So
// the union over the file's registration closures is used instead.
//
// That is an over-approximation, and a deliberate one. It is bounded by a single
// file rather than the plugin, it includes only closures that are arguments to a
// WordPress registration function rather than every anonymous function, and it
// errs by making an endpoint look able to reach a little more than it can. That
// direction under-states the privilege an attacker needs, which costs a wasted
// look. The opposite direction -- leaving the code unreachable -- means it is
// never examined at all.

var (
	// The head of an anonymous function or arrow function. PHP spells these
	// `function (...)`, `static function (...)`, `fn (...)` and `static fn
	// (...)`; a named declaration is excluded by requiring "(" to follow.
	closureHeadPattern = regexp.MustCompile(
		`(?i)(?:^|[\s,;{}(=>:])((?:static\s+)?(?:function|fn))\s*\(`)

	// A `use (...)` clause sits between the parameter list and the body.
	closureUsePattern = regexp.MustCompile(`^\s*use\s*\(`)

	// Return types: `: string`, `: ?Foo`, `: \A\B`, `: array|null`.
	closureReturnTypePattern = regexp.MustCompile(`^\s*:\s*\??[\\\w|\s]+`)
)

// registrationFuncs is the set of WordPress calls that take a callback and turn
// it into something reachable over HTTP. A closure passed to one of these is an
// endpoint body; a closure passed to array_map is not.
//
// These are WordPress core API names, not plugin names: the rule holds for any
// plugin because it is a fact about WordPress rather than about a codebase.
var registrationFuncs = map[string]bool{
	"register_rest_route":               true,
	"register_rest_field":               true,
	"add_action":                        true,
	"add_filter":                        true,
	"add_shortcode":                     true,
	"register_block_type":               true,
	"register_block_type_from_metadata": true,
	"register_meta":                     true,
	"register_setting":                  true,
	"add_menu_page":                     true,
	"add_submenu_page":                  true,
	"add_options_page":                  true,
	"add_management_page":               true,
	"add_theme_page":                    true,
	"add_plugins_page":                  true,
	"add_users_page":                    true,
	"add_dashboard_page":                true,
	"add_posts_page":                    true,
	"add_media_page":                    true,
	"add_pages_page":                    true,
	"add_comments_page":                 true,
	"register_widget":                   true,
	"wp_ajax":                           true,
}

// ClosureBody is one anonymous function's body, with the registration call it
// was passed to when there is one.
type ClosureBody struct {
	// Body is the source between the braces, exclusive.
	Body string
	// Registration is true when the closure is an argument to a WordPress
	// registration function, looking outward through array literals.
	Registration bool
	// Line is the 1-based line the closure head sits on.
	Line int
}

// FindClosures returns every anonymous function in content that has a body.
func FindClosures(content string) []ClosureBody {
	heads := closureHeadPattern.FindAllStringSubmatchIndex(content, -1)
	out := make([]ClosureBody, 0, len(heads))
	for _, m := range heads {
		// m[1] is one past the "(" that ended the head.
		parenOpen := m[1] - 1
		parenClose := matchDelimiter(content, parenOpen, '(', ')')
		if parenClose < 0 {
			continue
		}

		rest := content[parenClose+1:]
		consumed := 0

		// An optional `use (...)` clause.
		if loc := closureUsePattern.FindStringIndex(rest); loc != nil && loc[0] == 0 {
			useOpen := parenClose + 1 + loc[1] - 1
			useClose := matchDelimiter(content, useOpen, '(', ')')
			if useClose < 0 {
				continue
			}
			consumed = useClose + 1 - (parenClose + 1)
			rest = content[useClose+1:]
		}

		// An optional return type.
		if loc := closureReturnTypePattern.FindStringIndex(rest); loc != nil && loc[0] == 0 {
			consumed += loc[1]
			rest = rest[loc[1]:]
		}

		// An arrow function has an expression body, not a braced one. Its calls
		// are worth having, so take the expression up to the end of the
		// statement.
		trimmed := strings.TrimLeft(rest, " \t\r\n")
		pad := len(rest) - len(trimmed)
		switch {
		case strings.HasPrefix(trimmed, "=>"):
			expr := trimmed[2:]
			if end := strings.IndexAny(expr, ";,\n"); end >= 0 {
				expr = expr[:end]
			}
			out = append(out, ClosureBody{
				Body:         expr,
				Registration: inRegistrationCall(content, m[0]),
				Line:         1 + strings.Count(content[:m[0]], "\n"),
			})
		case strings.HasPrefix(trimmed, "{"):
			bodyOpen := parenClose + 1 + consumed + pad
			bodyClose := matchDelimiter(content, bodyOpen, '{', '}')
			if bodyClose < 0 {
				continue
			}
			out = append(out, ClosureBody{
				Body:         content[bodyOpen+1 : bodyClose],
				Registration: inRegistrationCall(content, m[0]),
				Line:         1 + strings.Count(content[:m[0]], "\n"),
			})
		}
	}
	return out
}

// inRegistrationCall reports whether a closure at offset `from` is an argument
// to a WordPress registration function, looking outward through any containers
// in between.
//
// The commonest REST shape puts the closure inside an array literal:
//
//	register_rest_route( 'ns/v1', '/thing', array(
//	    'callback' => function ( $request ) { ... },
//	) );
//
// so the innermost enclosing call is array(, not the registration. An array
// literal, a short array and a nested argument list are all transparent: the
// question is whether ANY enclosing call is a registration function.
//
// Brackets are counted while scanning backwards. Quotes are not tracked, so a
// "(" inside a string literal can throw the count off; the failure mode is to
// give up and include nothing extra, which is the same as the old behaviour.
func inRegistrationCall(content string, from int) bool {
	pos := from
	// Six levels is past any real nesting between a registration call and its
	// callback, and stops a pathological file from being walked to its start.
	for level := 0; level < 6; level++ {
		open, name := enclosingCallName(content, pos)
		if open < 0 {
			return false
		}
		if registrationFuncs[name] {
			return true
		}
		// A container carries no name of its own ("[", or "(" used for
		// grouping) or is an array constructor. Keep going outward. Anything
		// else is a call that is not a registration, and a closure passed to
		// usort is not an endpoint body.
		if name != "" && name != "array" {
			return false
		}
		pos = open
	}
	return false
}

// enclosingCallName walks back from an offset to the bracket whose contents the
// offset sits in, and returns that bracket's position together with the
// identifier immediately before it. The name is "" for a bracket that is not a
// call: a short array, or a grouping paren.
func enclosingCallName(content string, from int) (int, string) {
	depth := 0
	i := from - 1
	for ; i >= 0; i-- {
		switch content[i] {
		case ')', ']', '}':
			depth++
		case '(', '[':
			if depth == 0 {
				goto found
			}
			depth--
		case '{':
			if depth == 0 {
				// A brace at depth zero is a block, not an argument list, so
				// the closure is not inside any call.
				return -1, ""
			}
			depth--
		case ';':
			if depth == 0 {
				return -1, ""
			}
		}
	}
	return -1, ""

found:
	open := i
	end := open
	for end > 0 && (content[end-1] == ' ' || content[end-1] == '\t' ||
		content[end-1] == '\n' || content[end-1] == '\r') {
		end--
	}
	start := end
	for start > 0 {
		c := content[start-1]
		if c == '_' || c == '\\' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			start--
			continue
		}
		break
	}
	name := content[start:end]
	if j := strings.LastIndex(name, "\\"); j >= 0 {
		name = name[j+1:]
	}
	return open, strings.ToLower(name)
}

// registrationClosureCalls returns the calls made by every closure in content
// that was passed to a WordPress registration function.
//
// This is the seed for an endpoint whose callback is the "closure" sentinel.
// cg.extractCalls is used rather than ExtractFunctionCalls so that hooks fired
// inside the closure resolve to their callbacks like anywhere else.
func (cg *PluginCallGraph) registrationClosureCalls(content string) []string {
	if content == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, c := range FindClosures(content) {
		if !c.Registration {
			continue
		}
		for _, call := range cg.extractCalls(c.Body, callSite{}) {
			if !seen[call] {
				seen[call] = true
				out = append(out, call)
			}
		}
	}
	return out
}

package analyzer

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Package-level compiled regex patterns for Gutenberg block detection
var (
	// The block registration call itself, in either spelling.
	//
	// The detector used to key on `register_block_type\s*\(\s*'literal-name'\s*,`
	// -- a literal first argument -- and since WordPress 5.8 that argument may
	// equally be a path to a block.json or to the directory holding one, which is
	// the form the tooling generates. Of the 486 registration sites in the 143
	// corpus trees only 111 spell the name as a literal, so 375 sites in 36
	// block-registering plugins produced no endpoint at all. What decides whether
	// there is an endpoint is the second argument's render_callback, not how the
	// first argument is spelled, so the call site is matched and its arguments
	// are then parsed.
	registerBlockCallPattern = regexp.MustCompile(
		`register_block_type(?:_from_metadata)?\s*\(`,
	)

	// render_callback patterns
	// Pattern 1: 'render_callback' => 'function_name'
	renderCallbackStringPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*['"]([^'"]+)['"]`,
	)

	// Pattern 2: 'render_callback' => [$this, 'method'] / array($this, 'method')
	renderCallbackThisArrayPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*(?:\[|array\s*\()\s*&?\s*\$this\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 3: 'render_callback' => [__CLASS__, 'method'] / array(__CLASS__, ...)
	renderCallbackClassConstPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*(?:\[|array\s*\()\s*__CLASS__\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 4: 'render_callback' => [ClassName::class, 'method'], which also
	// covers [self::class, ...] and [static::class, ...].
	renderCallbackClassMethodPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*(?:\[|array\s*\()\s*([A-Za-z_][A-Za-z0-9_\\]*)::class\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 5: 'render_callback' => [$obj, 'method'] for any object variable.
	// The method name alone is what the call graph resolves, exactly as
	// NormalizeCallback reduces an array callback elsewhere in the analyzer.
	renderCallbackVarArrayPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*(?:\[|array\s*\()\s*&?\s*\$[A-Za-z_][A-Za-z0-9_]*\s*(?:->[A-Za-z_][A-Za-z0-9_]*)*\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 6: 'render_callback' => function(...) or fn(...)
	renderCallbackAnonPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*(?:static\s+)?(?:function|fn)\s*\(`,
	)
)

// DetectBlocks finds Gutenberg block registrations and returns them as
// endpoints.
//
// A block with a render_callback is a dynamic block, and WordPress gives it two
// distinct request paths:
//
//   - do_blocks() runs the callback from the_content when a published post
//     containing the block is rendered, which any visitor can request.
//   - GET /wp-json/wp/v2/block-renderer/<name> runs the same callback with
//     attributes taken straight from the request.
//     WP_REST_Block_Renderer_Controller::get_item_permissions_check() requires
//     current_user_can('edit_post', $post_id) or current_user_can('edit_posts'),
//     which is Contributor, and get_item() refuses any block whose type is not
//     dynamic.
//
// Both endpoints therefore name the same callback. Because the reported level of
// a function is the minimum over the endpoints that reach it, the Contributor
// endpoint can never raise an answer above the Unauthenticated render endpoint
// beside it; what it does is bound the render endpoint from above when
// InferAuthLevel raises that one out of Unauthenticated.
//
// A block with no render_callback has no server-side PHP for the block-renderer
// route to run, so no endpoint is pointed at that route for it. It still gets
// the editor endpoint it has always had -- loading the block editor does load the
// plugin's registration file -- carrying the same Contributor level and the same
// unresolvable callback as before. That endpoint is honest file-level evidence
// and deleting it would be the one move here that can raise a reported
// privilege, so it stays exactly as it was.
//
// One shape this pass cannot decide: since WordPress 6.1 a block.json may carry
// `"render": "file:./render.php"`, and core then synthesises a render callback
// that includes that PHP file on every front-end render -- an Unauthenticated
// path. 108 of the corpus's 851 block.json files, in 7 of 143 trees, declare
// one. A registration that points at such a directory looks static here, and is
// reported only through its Contributor editor endpoint. The consequence is
// bounded rather than absent: that endpoint's reach is the REGISTRATION file and
// its include closure, and the render PHP file is included by core rather than
// by the plugin, so it is not in that closure and does not inherit the
// Contributor level. Closing the gap properly means reading block.json, which
// needs a plugin-root-aware entry point this per-file detector does not have.
func DetectBlocks(content, filepath, pluginSlug string) []models.Endpoint {
	var endpoints []models.Endpoint

	type blockInfo struct {
		name         string
		callback     string
		callbackBody string
		hasRenderCB  bool
		line         int
	}

	var blocks []blockInfo

	for _, m := range registerBlockCallPattern.FindAllStringIndex(content, -1) {
		callStart, parenPos := m[0], m[1]-1
		args := splitBlockCallArgs(content, parenPos)
		if len(args) == 0 {
			continue
		}
		line := countLines(content[:callStart]) + 1

		callback, callbackBody := "", ""
		if len(args) >= 2 {
			callback, callbackBody = extractRenderCallback(args[1], content)
		}

		name := blockNameFromArg(args[0])
		if name == "" {
			// The first argument is a path, a variable or a concatenation, so
			// the block's name lives in a block.json this pass cannot read. The
			// endpoint is still worth having -- the name is a label and the
			// callback is what carries reach -- but then the route has to stay
			// unique per registration site. A shared "{dynamic}" route would
			// collide in deduplicateEndpoints, which keys on Route|Method|Type
			// across the whole plugin, and a loop registering three blocks from
			// one call site would have two of its three render callbacks
			// discovered and then thrown away. 14 dynamic first-argument
			// expressions repeat within a single plugin, across 11 of the 143
			// corpus trees.
			//
			// When there is no callback to lose there is nothing to keep apart:
			// every such site in one file yields the identical fact, that this
			// file registers a block the editor screen loads, so they collapse
			// to one endpoint per file rather than one per line. A plugin that
			// registers its blocks in a loop over a directory listing otherwise
			// produces dozens of identical rows.
			name = "{dynamic}@" + strings.ReplaceAll(filepath, `\`, "/")
			if callback != "" {
				name += ":" + strconv.Itoa(line)
			}
		}

		blocks = append(blocks, blockInfo{
			name:         name,
			callback:     callback,
			callbackBody: callbackBody,
			hasRenderCB:  callback != "",
			line:         line,
		})
	}

	// One endpoint set per block name. When the same name is registered more
	// than once in a file, the registration that names a render callback is the
	// informative one.
	byName := map[string]int{}
	var order []string
	for i, b := range blocks {
		if idx, ok := byName[b.name]; ok {
			if b.hasRenderCB && !blocks[idx].hasRenderCB {
				byName[b.name] = i
			}
			continue
		}
		byName[b.name] = i
		order = append(order, b.name)
	}

	for _, name := range order {
		block := blocks[byName[name]]

		if block.hasRenderCB {
			authLevel := models.Unauthenticated // Default for frontend blocks

			if block.callbackBody != "" {
				inferredAuth := InferAuthLevel(block.callbackBody)
				if inferredAuth != models.Unauthenticated {
					authLevel = inferredAuth
				}
			}

			endpoints = append(endpoints, models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeBlock,
				Route:      "block:" + name + ":render",
				AuthLevel:  authLevel,
				Callback:   block.callback,
				File:       filepath,
				Line:       block.line,
			})

			endpoints = append(endpoints, models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeBlock,
				Route:      "block:" + name + ":block-renderer",
				AuthLevel:  models.Contributor, // edit_posts, per WP_REST_Block_Renderer_Controller
				Callback:   block.callback,
				File:       filepath,
				Line:       block.line,
			})
			continue
		}

		endpoints = append(endpoints, models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeBlock,
			Route:      "block:" + name + ":editor",
			AuthLevel:  models.Contributor, // edit_posts required for the block editor
			Callback:   "(Gutenberg editor)",
			File:       filepath,
			Line:       block.line,
		})
	}

	return endpoints
}

// blockNameFromArg returns the block name when the first argument to
// register_block_type is a single quoted literal, and "" otherwise. A path, a
// constant, a variable or a concatenation all yield "".
func blockNameFromArg(arg string) string {
	arg = strings.TrimSpace(arg)
	if len(arg) < 2 {
		return ""
	}
	q := arg[0]
	if q != '\'' && q != '"' {
		return ""
	}
	if arg[len(arg)-1] != q {
		return ""
	}
	inner := arg[1 : len(arg)-1]
	// A quote inside means the literal ended early and something was
	// concatenated onto it.
	if strings.IndexByte(inner, q) >= 0 {
		return ""
	}
	return inner
}

// splitBlockCallArgs returns the top-level arguments of the call whose opening
// parenthesis is at parenPos.
//
// A regex cannot do this: the second argument is an arbitrarily nested array
// whose own commas, brackets and quoted strings have to be stepped over, and the
// pattern this detector used instead took the first comma after the block name
// and then hunted forward for the next `[` or `array` -- which, for a
// registration with no second argument, found the next unrelated one further
// down the file.
//
// When the call is unbalanced -- which for comment-stripped content means the
// file is truncated -- the arguments found so far are returned rather than
// nothing, since a missing endpoint is worse than an approximate one.
func splitBlockCallArgs(content string, parenPos int) []string {
	if parenPos >= len(content) || content[parenPos] != '(' {
		return nil
	}

	var args []string
	depth := 0
	inString := false
	var stringChar byte
	start := parenPos + 1

	for i := parenPos; i < len(content); i++ {
		c := content[i]

		if inString {
			if c == '\\' {
				i++
				continue
			}
			if c == stringChar {
				inString = false
			}
			continue
		}

		switch c {
		case '\'', '"':
			inString = true
			stringChar = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return append(args, content[start:i])
			}
		case ',':
			if depth == 1 {
				args = append(args, content[start:i])
				start = i + 1
			}
		}
	}

	return append(args, content[start:])
}

// extractRenderCallback extracts the render callback and its body
func extractRenderCallback(argsContent, fullContent string) (callback string, body string) {
	// Try string callback pattern
	if m := renderCallbackStringPattern.FindStringSubmatch(argsContent); len(m) >= 2 {
		callback = m[1]
		body = findFunctionBody(callback, fullContent)
		return
	}

	// Try $this array pattern, in either array syntax
	if m := renderCallbackThisArrayPattern.FindStringSubmatch(argsContent); len(m) >= 2 {
		callback = m[1]
		body = findFunctionBody(callback, fullContent)
		return
	}

	// Try __CLASS__ pattern
	if m := renderCallbackClassConstPattern.FindStringSubmatch(argsContent); len(m) >= 2 {
		callback = m[1]
		body = findFunctionBody(callback, fullContent)
		return
	}

	// Try ClassName::class pattern
	if m := renderCallbackClassMethodPattern.FindStringSubmatch(argsContent); len(m) >= 3 {
		callback = m[1] + "::" + m[2]
		body = findFunctionBody(m[2], fullContent)
		return
	}

	// Try an array callback on any other object variable
	if m := renderCallbackVarArrayPattern.FindStringSubmatch(argsContent); len(m) >= 2 {
		callback = m[1]
		body = findFunctionBody(callback, fullContent)
		return
	}

	// Try anonymous function
	if renderCallbackAnonPattern.MatchString(argsContent) {
		callback = "anonymous"
		// Extract anonymous function body from args
		loc := renderCallbackAnonPattern.FindStringIndex(argsContent)
		if loc != nil {
			braceStart := strings.Index(argsContent[loc[0]:], "{")
			if braceStart != -1 {
				body = extractBracedContent(argsContent, loc[0]+braceStart)
			}
		}
		return
	}

	return "", ""
}

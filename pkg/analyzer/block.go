package analyzer

import (
	"regexp"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Package-level compiled regex patterns for Gutenberg block detection
var (
	// Pattern 1: register_block_type('namespace/block', [...])
	registerBlockStringPattern = regexp.MustCompile(
		`register_block_type\s*\(\s*['"]([^'"]+)['"]\s*,`,
	)

	// Pattern 2: register_block_type(__DIR__) - block.json in directory
	registerBlockDirPattern = regexp.MustCompile(
		`register_block_type\s*\(\s*__DIR__`,
	)

	// Pattern 3: register_block_type_from_metadata(...)
	registerBlockMetadataPattern = regexp.MustCompile(
		`register_block_type_from_metadata\s*\(`,
	)

	// render_callback patterns
	// Pattern 1: 'render_callback' => 'function_name'
	renderCallbackStringPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*['"]([^'"]+)['"]`,
	)

	// Pattern 2: 'render_callback' => [$this, 'method']
	renderCallbackThisBracketPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*\[\s*\$this\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 3: 'render_callback' => array($this, 'method')
	renderCallbackThisArrayPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*array\s*\(\s*\$this\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 4: 'render_callback' => [__CLASS__, 'method']
	renderCallbackClassConstPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*(?:\[|array\s*\()\s*__CLASS__\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern 5: 'render_callback' => function($attributes, $content) { ... }
	renderCallbackAnonPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*function\s*\(`,
	)

	// Pattern 6: 'render_callback' => [ClassName::class, 'method']
	renderCallbackClassMethodPattern = regexp.MustCompile(
		`['"]render_callback['"]\s*=>\s*\[\s*([A-Za-z_][A-Za-z0-9_\\]*)::class\s*,\s*['"]([^'"]+)['"]`,
	)

	// Pattern to extract block name from block.json style registration
	// Looks for 'name' => 'namespace/block-name' in the args
	blockNamePattern = regexp.MustCompile(
		`['"]name['"]\s*=>\s*['"]([^'"]+)['"]`,
	)
)

// DetectBlocks finds all Gutenberg block registrations and returns them as endpoints.
// Creates up to two endpoints per block:
// 1. block:{name}:render - Frontend render callback (auth from callback analysis)
// 2. block:{name}:editor - Block editor context (Contributor level - requires edit_posts)
func DetectBlocks(content, filepath, pluginSlug string) []models.Endpoint {
	var endpoints []models.Endpoint

	// Track unique blocks
	type blockInfo struct {
		name           string
		callback       string
		callbackBody   string
		hasRenderCB    bool
		registrationPos int
	}

	var blocks []blockInfo

	// Find register_block_type calls with string name
	for _, m := range registerBlockStringPattern.FindAllStringSubmatchIndex(content, -1) {
		if len(m) >= 4 {
			blockName := content[m[2]:m[3]]
			startPos := m[0]

			// Extract the registration args
			argsStart := strings.Index(content[startPos:], ",")
			if argsStart == -1 {
				continue
			}
			argsStart += startPos + 1

			// Find the array/bracket that starts the args
			argsBraceStart := -1
			for i := argsStart; i < len(content) && i < startPos+500; i++ {
				if content[i] == '[' || (i+4 < len(content) && content[i:i+5] == "array") {
					argsBraceStart = i
					break
				}
			}

			if argsBraceStart == -1 {
				continue
			}

			// Extract args content
			argsContent := extractBlockArgs(content, argsBraceStart)

			// Look for render_callback
			callback, callbackBody := extractRenderCallback(argsContent, content)

			blocks = append(blocks, blockInfo{
				name:            blockName,
				callback:        callback,
				callbackBody:    callbackBody,
				hasRenderCB:     callback != "",
				registrationPos: startPos,
			})
		}
	}

	// Create endpoints for each unique block
	seen := make(map[string]bool)
	for _, block := range blocks {
		if seen[block.name] {
			continue
		}
		seen[block.name] = true

		// Create render endpoint if there's a render callback
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
				Route:      "block:" + block.name + ":render",
				AuthLevel:  authLevel,
				Callback:   block.callback,
				File:       filepath,
			})
		}

		// Create editor endpoint (always Contributor level - requires edit_posts)
		endpoints = append(endpoints, models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeBlock,
			Route:      "block:" + block.name + ":editor",
			AuthLevel:  models.Contributor, // edit_posts required for block editor
			Callback:   "(Gutenberg editor)",
			File:       filepath,
		})
	}

	return endpoints
}

// extractBlockArgs extracts the block registration arguments
func extractBlockArgs(content string, startPos int) string {
	// Handle both array() and [] notation
	if startPos >= len(content) {
		return ""
	}

	if content[startPos] == '[' {
		return extractBracedContentCustom(content, startPos, '[', ']')
	}

	// array() notation
	parenStart := strings.Index(content[startPos:], "(")
	if parenStart == -1 {
		return ""
	}
	return extractBracedContentCustom(content, startPos+parenStart, '(', ')')
}

// extractBracedContentCustom extracts content between matching braces
func extractBracedContentCustom(content string, startPos int, openBrace, closeBrace byte) string {
	if startPos >= len(content) || content[startPos] != openBrace {
		return ""
	}

	depth := 0
	inString := false
	stringChar := byte(0)

	for i := startPos; i < len(content); i++ {
		c := content[i]

		if inString {
			if c == stringChar && (i == 0 || content[i-1] != '\\') {
				inString = false
			}
			continue
		}

		switch c {
		case '"', '\'':
			inString = true
			stringChar = c
		case openBrace:
			depth++
		case closeBrace:
			depth--
			if depth == 0 {
				return content[startPos : i+1]
			}
		}
	}

	// Return up to 2000 chars if no match
	maxLen := startPos + 2000
	if maxLen > len(content) {
		maxLen = len(content)
	}
	return content[startPos:maxLen]
}

// extractRenderCallback extracts the render callback and its body
func extractRenderCallback(argsContent, fullContent string) (callback string, body string) {
	// Try string callback pattern
	if m := renderCallbackStringPattern.FindStringSubmatch(argsContent); len(m) >= 2 {
		callback = m[1]
		body = findFunctionBody(callback, fullContent)
		return
	}

	// Try $this bracket pattern
	if m := renderCallbackThisBracketPattern.FindStringSubmatch(argsContent); len(m) >= 2 {
		callback = m[1]
		body = findFunctionBody(callback, fullContent)
		return
	}

	// Try $this array pattern
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

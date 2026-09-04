package analyzer

import (
	"regexp"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Package-level compiled regex patterns for admin detection (Issue 2 fix)
var (
	// Patterns for parseAdminPageMatch function type detection
	adminMenuPagePattern        = regexp.MustCompile(`add_menu_page`)
	adminSubmenuPagePattern     = regexp.MustCompile(`add_submenu_page`)
	adminOptionsThemeEtcPattern = regexp.MustCompile(`add_(options|theme|plugins|users|dashboard|management)_page`)
	adminFunctionExtractPattern = regexp.MustCompile(`add_([a-z_]+)_page`)
	adminPostsMediaEtcPattern   = regexp.MustCompile(`add_(posts|media|links|pages|comments)_page`)

	// Pattern for DetectAdminNotices
	adminNoticesPattern = regexp.MustCompile(`add_action\s*\(\s*['"]admin_notices['"]\s*,\s*([^,)]+)`)

	// Variable-based admin page patterns
	// Use a simplified pattern that just finds the function call start
	// We'll parse arguments manually to handle nested parentheses
	adminMenuPageStartPattern = regexp.MustCompile(
		`add_menu_page\s*\(`,
	)

	// add_submenu_page start pattern - arguments parsed manually
	adminSubmenuPageStartPattern = regexp.MustCompile(
		`add_submenu_page\s*\(`,
	)

	// add_*_page start patterns for options, dashboard, management, theme, plugins, users pages
	// These functions have signature: add_*_page( page_title, menu_title, capability, menu_slug, callback )
	// Callback is optional (5th arg)
	adminOtherPageStartPattern = regexp.MustCompile(
		`add_(options|dashboard|management|theme|plugins|users)_page\s*\(`,
	)

	// Legacy generic patterns (kept for fallback)
	adminMenuPageGenericPattern = regexp.MustCompile(
		`add_menu_page\s*\(\s*` +
			`([^,]+)\s*,\s*` + // page_title
			`([^,]+)\s*,\s*` + // menu_title
			`([^,]+)\s*,\s*` + // capability
			`([^,]+)\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	)

	// add_submenu_page with any arguments
	adminSubmenuPageGenericPattern = regexp.MustCompile(
		`add_submenu_page\s*\(\s*` +
			`([^,]+)\s*,\s*` + // parent_slug
			`([^,]+)\s*,\s*` + // page_title
			`([^,]+)\s*,\s*` + // menu_title
			`([^,]+)\s*,\s*` + // capability
			`([^,]+)\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	)

	// add_options_page and similar with any arguments
	adminOptionsPageGenericPattern = regexp.MustCompile(
		`add_(options|theme|plugins|users|dashboard|management)_page\s*\(\s*` +
			`([^,]+)\s*,\s*` + // page_title
			`([^,]+)\s*,\s*` + // menu_title
			`([^,]+)\s*,\s*` + // capability
			`([^,]+)\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	)

	// Spread operator pattern: add_submenu_page(...$args)
	adminSpreadPattern = regexp.MustCompile(
		`add_(menu|submenu|options|theme|plugins|users|dashboard|management)_page\s*\(\s*\.\.\.(\$[a-zA-Z_][a-zA-Z0-9_]*)`,
	)

	// Array variable pattern: add_submenu_page($args[0], $args[1], ...)
	adminArrayAccessPattern = regexp.MustCompile(
		`add_(menu|submenu)_page\s*\(\s*` +
			`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*['"0-9]+\s*\]`,
	)

	// Static patterns moved from function scope
	// For resolveMenuSlugReference
	adminVarArrayPattern  = regexp.MustCompile(`\$(?:this->)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*['"]([^'"]+)['"]\s*\]`)
	adminConstNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	adminArrayAssignPattern = regexp.MustCompile(
		`\$(?:this\s*->\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*['"]([^'"]+)['"]\s*\]\s*=\s*['"]([^'"]+)['"]`)
	// For extractCallbackName
	adminCallbackArrayPattern = regexp.MustCompile(`(?:\[|array\s*\()[^,]*,\s*['"]([^'"]+)['"]`)
	adminSimpleIdentPattern   = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// AdminPagePatterns for detecting admin page registrations
var AdminPagePatterns = []*regexp.Regexp{
	// add_menu_page(page_title, menu_title, capability, menu_slug, callback, icon, position)
	regexp.MustCompile(
		`add_menu_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // page_title
			`['"]([^'"]*)['"]\s*,\s*` + // menu_title
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback (can be various formats)
	),

	// add_submenu_page(parent_slug, page_title, menu_title, capability, menu_slug, callback)
	regexp.MustCompile(
		`add_submenu_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // parent_slug
			`['"]([^'"]*)['"]\s*,\s*` + // page_title
			`['"]([^'"]*)['"]\s*,\s*` + // menu_title
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_options_page(page_title, menu_title, capability, menu_slug, callback)
	regexp.MustCompile(
		`add_options_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // page_title
			`['"]([^'"]*)['"]\s*,\s*` + // menu_title
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_theme_page(page_title, menu_title, capability, menu_slug, callback)
	regexp.MustCompile(
		`add_theme_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // page_title
			`['"]([^'"]*)['"]\s*,\s*` + // menu_title
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_plugins_page(page_title, menu_title, capability, menu_slug, callback)
	regexp.MustCompile(
		`add_plugins_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // page_title
			`['"]([^'"]*)['"]\s*,\s*` + // menu_title
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_users_page(page_title, menu_title, capability, menu_slug, callback)
	regexp.MustCompile(
		`add_users_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // page_title
			`['"]([^'"]*)['"]\s*,\s*` + // menu_title
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_dashboard_page(page_title, menu_title, capability, menu_slug, callback)
	regexp.MustCompile(
		`add_dashboard_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // page_title
			`['"]([^'"]*)['"]\s*,\s*` + // menu_title
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_posts_page / add_media_page / add_links_page / add_pages_page / add_comments_page
	regexp.MustCompile(
		`add_(posts|media|links|pages|comments)_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // page_title
			`['"]([^'"]*)['"]\s*,\s*` + // menu_title
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_management_page (Tools menu)
	regexp.MustCompile(
		`add_management_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // page_title
			`['"]([^'"]*)['"]\s*,\s*` + // menu_title
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_management_page with translation function in page_title (first arg)
	// Uses __ or similar i18n function - REQUIRES the function to be present
	regexp.MustCompile(
		`add_management_page\s*\(\s*` +
			`(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"][^'"]*['"]\s*\)\s*,\s*` + // page_title with translation - Group 1
			`(?:(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*)?['"]([^'"]*)['"]\s*(?:,\s*['"][^'"]*['"]\s*\))?\s*,\s*` + // menu_title - Group 2
			`['"]([^'"]*)['"]\s*,\s*` + // capability - Group 3
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug - Group 4
			`([^,)]+)`, // callback - Group 5
	),

	// add_management_page with translation function in menu_title (second arg)
	// First arg is literal string, second arg is translation function
	regexp.MustCompile(
		`add_management_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // page_title (literal) - Group 1
			`(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"][^'"]*['"]\s*\)\s*,\s*` + // menu_title with translation - Group 2
			`['"]([^'"]*)['"]\s*,\s*` + // capability - Group 3
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug - Group 4
			`([^,)]+)`, // callback - Group 5
	),

	// add_options_page with translation function in first arg
	regexp.MustCompile(
		`add_options_page\s*\(\s*` +
			`(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"][^'"]*['"]\s*\)\s*,\s*` +
			`(?:(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*)?['"]([^'"]*)['"]\s*(?:,\s*['"][^'"]*['"]\s*\))?\s*,\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_theme_page with translation function in first arg
	regexp.MustCompile(
		`add_theme_page\s*\(\s*` +
			`(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"][^'"]*['"]\s*\)\s*,\s*` +
			`(?:(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*)?['"]([^'"]*)['"]\s*(?:,\s*['"][^'"]*['"]\s*\))?\s*,\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_plugins_page with translation function in first arg
	regexp.MustCompile(
		`add_plugins_page\s*\(\s*` +
			`(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"][^'"]*['"]\s*\)\s*,\s*` +
			`(?:(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*)?['"]([^'"]*)['"]\s*(?:,\s*['"][^'"]*['"]\s*\))?\s*,\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_users_page with translation function in first arg
	regexp.MustCompile(
		`add_users_page\s*\(\s*` +
			`(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"][^'"]*['"]\s*\)\s*,\s*` +
			`(?:(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*)?['"]([^'"]*)['"]\s*(?:,\s*['"][^'"]*['"]\s*\))?\s*,\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_dashboard_page with translation function in first arg
	regexp.MustCompile(
		`add_dashboard_page\s*\(\s*` +
			`(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"][^'"]*['"]\s*\)\s*,\s*` +
			`(?:(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*)?['"]([^'"]*)['"]\s*(?:,\s*['"][^'"]*['"]\s*\))?\s*,\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_menu_page with translation function in first arg
	regexp.MustCompile(
		`add_menu_page\s*\(\s*` +
			`(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"][^'"]*['"]\s*\)\s*,\s*` +
			`(?:(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*)?['"]([^'"]*)['"]\s*(?:,\s*['"][^'"]*['"]\s*\))?\s*,\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // capability
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug
			`([^,)]+)`, // callback
	),

	// add_submenu_page with translation function in page_title (second arg after parent_slug)
	regexp.MustCompile(
		`add_submenu_page\s*\(\s*` +
			`['"]([^'"]*)['"]\s*,\s*` + // parent_slug - Group 1
			`(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"][^'"]*['"]\s*\)\s*,\s*` + // page_title with translation - Group 2
			`(?:(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*)?['"]([^'"]*)['"]\s*(?:,\s*['"][^'"]*['"]\s*\))?\s*,\s*` + // menu_title - Group 3
			`['"]([^'"]*)['"]\s*,\s*` + // capability - Group 4
			`['"]([^'"]*)['"]\s*,\s*` + // menu_slug - Group 5
			`([^,)]+)`, // callback - Group 6
	),
}

// AdminPageInfo holds parsed admin page information
type AdminPageInfo struct {
	FunctionType string
	PageTitle    string
	MenuTitle    string
	Capability   string
	MenuSlug     string
	Callback     string
	ParentSlug   string // Only for submenu
}

// Patterns for cleaning PHP interpolation from ADMIN page slugs
var (
	adminSlugThisBracePattern     = regexp.MustCompile(`\{\$this->([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	adminSlugVarBracePattern      = regexp.MustCompile(`\{\$([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	adminSlugThisNoBracePattern   = regexp.MustCompile(`\$this->([a-zA-Z_][a-zA-Z0-9_]*)`)
	adminSlugVarNoBracePattern    = regexp.MustCompile(`\$([a-z][a-zA-Z0-9_]*)`)
	adminSlugMethodCallPattern    = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\(\)\}`)
	adminSlugDynamicPattern       = regexp.MustCompile(`\{dynamic:([a-zA-Z_][a-zA-Z0-9_()]*)\}`)
	adminSlugClassConstPattern    = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*_[A-Z_]+)\}`)
)

// contextPrefixes are common PHP context prefixes to strip from identifiers
var contextPrefixes = []string{"this_", "self_", "static_"}

// stripContextPrefixes removes common PHP context prefixes from identifiers
func stripContextPrefixes(name string) string {
	for _, prefix := range contextPrefixes {
		if strings.HasPrefix(name, prefix) {
			return name[len(prefix):]
		}
	}
	return name
}

// findClosingParenPos finds the position after the matching closing parenthesis
// starting from argsStartPos (which should be right after an opening paren).
// Returns the position of the content up to and including the closing paren.
// If not found within maxLen characters, returns argsStartPos + maxLen.
func findClosingParenPos(content string, argsStartPos, maxLen int) int {
	depth := 1
	for i, c := range content[argsStartPos:] {
		if i > maxLen {
			return argsStartPos + i
		}
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return argsStartPos + i + 1
			}
		}
	}
	return argsStartPos + maxLen
}

// cleanAdminSlug cleans PHP interpolation syntax from ADMIN page slugs
func cleanAdminSlug(slug string) string {
	// Replace {$this->method()} or {method()} with {method}
	slug = adminSlugMethodCallPattern.ReplaceAllString(slug, "{$1}")

	// Replace {$this->prop} with {prop}
	slug = adminSlugThisBracePattern.ReplaceAllString(slug, "{$1}")

	// Replace {$var} with {var}
	slug = adminSlugVarBracePattern.ReplaceAllString(slug, "{$1}")

	// Replace $this->prop with {prop}
	slug = adminSlugThisNoBracePattern.ReplaceAllString(slug, "{$1}")

	// Replace $var with {var} (only lowercase-starting vars to avoid superglobals)
	slug = adminSlugVarNoBracePattern.ReplaceAllString(slug, "{$1}")

	// Clean up {dynamic:...} placeholders
	slug = adminSlugDynamicPattern.ReplaceAllStringFunc(slug, func(match string) string {
		submatches := adminSlugDynamicPattern.FindStringSubmatch(match)
		if len(submatches) > 1 {
			name := stripContextPrefixes(submatches[1])
			name = strings.TrimSuffix(name, "()")
			return "{" + name + "}"
		}
		return match
	})

	// Clean prefixes from simple placeholder names like {this_slug} -> {slug}
	if strings.HasPrefix(slug, "{") && strings.HasSuffix(slug, "}") {
		inner := slug[1 : len(slug)-1]
		if cleaned := stripContextPrefixes(inner); cleaned != inner {
			slug = "{" + cleaned + "}"
		}
	}

	// Clean up class constant patterns like {Menu_Config_EDITOR_MENU_SLUG} -> {EDITOR_MENU_SLUG}
	slug = adminSlugClassConstPattern.ReplaceAllStringFunc(slug, func(match string) string {
		submatches := adminSlugClassConstPattern.FindStringSubmatch(match)
		if len(submatches) > 1 {
			name := submatches[1]
			// Find where the all-caps part starts (e.g., Menu_Config_EDITOR_MENU_SLUG -> EDITOR_MENU_SLUG)
			parts := strings.Split(name, "_")
			for i, part := range parts {
				if part != "" && strings.ToUpper(part) == part {
					// Found the start of all-caps section
					name = strings.Join(parts[i:], "_")
					break
				}
			}
			return "{" + name + "}"
		}
		return match
	})

	return slug
}

// formatAdminRoute formats a menu slug as a full admin URL path
func formatAdminRoute(menuSlug string) string {
	if menuSlug == "" {
		return ""
	}

	// Clean PHP interpolation syntax first
	menuSlug = cleanAdminSlug(menuSlug)

	// If it already has the prefix or is a dynamic placeholder, return as-is
	if strings.HasPrefix(menuSlug, "wp-admin/") || strings.HasPrefix(menuSlug, "{") {
		return menuSlug
	}
	return "wp-admin/admin.php?page=" + menuSlug
}

// DetectAdminPages finds all admin page registrations in PHP code
func DetectAdminPages(content, filepath string, pluginSlug string) []models.Endpoint {
	// Pre-allocate with estimated capacity to reduce slice growth allocations
	endpoints := make([]models.Endpoint, 0, 8)
	processedPositions := make(map[int]bool)

	// Build symbol table for the file
	symbolTable := NewSymbolTable(content)

	// 1. First, handle each standard pattern type (literal strings)
	for _, pattern := range AdminPagePatterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			info := parseAdminPageMatch(content, match, pattern.String())
			if info == nil {
				continue
			}

			// Skip entries with empty menu slug (empty route)
			if info.MenuSlug == "" || info.MenuSlug == "''" || info.MenuSlug == "\"\"" {
				continue
			}

			processedPositions[match[0]] = true
			lineNum := countLines(content[:match[0]]) + 1
			fullMatch := content[match[0]:match[1]]

			// The literal-string patterns capture the callback as ([^,)]+), which
			// stops at the first comma -- so every PHP array callable arrives here
			// truncated to "array( $this" or "[ $this". NormalizeCallback then has
			// no method name to extract and answers the placeholder
			// "this::callback", which is unusable as a call-graph key: the page is
			// discovered and then leads nowhere. Re-read the argument with the same
			// balanced scanner the variable-argument paths below already use.
			if rescued := rescueTruncatedArrayCallback(content, match[0], info.Callback); rescued != "" {
				info.Callback = rescued
			}

			// Determine auth level from capability (primary)
			authLevel := determineAuthLevelFromCapability(info.Capability)

			// Analyze callback function for additional auth checks
			// The callback might have stricter auth requirements than the menu capability
			authLevel = analyzeAdminCallbackAuth(info.Callback, content, authLevel)

			ep := models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeAdmin,
				Route:      formatAdminRoute(info.MenuSlug),
				Method:     "GET", // Admin pages are typically GET
				AuthLevel:  authLevel,
				Callback:   NormalizeCallback(info.Callback),
				File:       filepath,
				Line:       lineNum,
				RawCode:    truncateCode(fullMatch, 500),
				Namespace:  info.FunctionType,
			}
			endpoints = append(endpoints, ep)
		}
	}

	// 2. Handle add_menu_page with variable arguments using balanced parsing
	menuStartMatches := adminMenuPageStartPattern.FindAllStringIndex(content, -1)
	for _, match := range menuStartMatches {
		startPos := match[0]
		if processedPositions[startPos] {
			continue
		}

		// Parse arguments with proper parenthesis balancing
		argsStartPos := match[1] // Position right after the opening (
		args := parseBalancedArgs(content, argsStartPos)

		// add_menu_page needs at least 5 args: page_title, menu_title, capability, menu_slug, callback
		if len(args) < 5 {
			continue
		}

		processedPositions[startPos] = true

		endPos := findClosingParenPos(content, argsStartPos, 2000)
		fullMatch := content[startPos:endPos]

		pageTitle := resolveAdminArg(args[0], symbolTable, content, startPos)
		capability := resolveAdminArg(args[2], symbolTable, content, startPos)
		menuSlug := resolveAdminArg(args[3], symbolTable, content, startPos)
		callback := args[4]

		// Skip if we couldn't resolve a meaningful slug
		if menuSlug == "" {
			menuSlug = "{dynamic:menu_page}"
		}

		lineNum := countLines(content[:startPos]) + 1
		authLevel := determineAuthLevelFromCapability(capability)

		// Analyze callback function for additional auth checks
		authLevel = analyzeAdminCallbackAuth(callback, content, authLevel)

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAdmin,
			Route:      formatAdminRoute(menuSlug),
			Method:     "GET",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
			Namespace:  "add_menu_page",
		}
		_ = pageTitle // Used for potential future enhancement
		endpoints = append(endpoints, ep)
	}

	// 3. Handle add_submenu_page with variable arguments using balanced parsing
	submenuStartMatches := adminSubmenuPageStartPattern.FindAllStringIndex(content, -1)
	for _, match := range submenuStartMatches {
		startPos := match[0]
		if processedPositions[startPos] {
			continue
		}

		// Parse arguments with proper parenthesis balancing
		argsStartPos := match[1] // Position right after the opening (
		args := parseBalancedArgs(content, argsStartPos)

		// add_submenu_page needs at least 5 args: parent_slug, page_title, menu_title, capability, menu_slug
		// The 6th arg (callback) is optional - when omitted, WordPress creates a direct link menu item
		// This is common for linking to taxonomy pages, external URLs, etc.
		if len(args) < 5 {
			continue
		}

		processedPositions[startPos] = true

		endPos := findClosingParenPos(content, argsStartPos, 2000)
		fullMatch := content[startPos:endPos]

		parentSlug := resolveAdminArg(args[0], symbolTable, content, startPos)
		capability := resolveAdminArg(args[3], symbolTable, content, startPos)
		menuSlug := resolveAdminArg(args[4], symbolTable, content, startPos)
		// Callback is optional (6th arg) - default to empty if not provided
		callback := ""
		if len(args) >= 6 {
			callback = args[5]
		}

		// Skip if we couldn't resolve a meaningful slug
		if menuSlug == "" {
			menuSlug = "{dynamic:submenu_page}"
		}

		lineNum := countLines(content[:startPos]) + 1
		authLevel := determineAuthLevelFromCapability(capability)

		// Analyze callback function for additional auth checks
		authLevel = analyzeAdminCallbackAuth(callback, content, authLevel)

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAdmin,
			Route:      formatAdminRoute(menuSlug),
			Method:     "GET",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
			Namespace:  "add_submenu_page:" + parentSlug,
		}
		endpoints = append(endpoints, ep)
	}

	// 4. Handle add_options_page, add_dashboard_page, add_management_page, etc. with balanced parsing
	// These functions have signature: add_*_page(page_title, menu_title, capability, menu_slug, callback)
	// The 5th arg (callback) is optional
	// NOTE: This MUST run before the generic pattern which doesn't handle nested parentheses
	otherPageMatches := adminOtherPageStartPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range otherPageMatches {
		startPos := match[0]
		if processedPositions[startPos] {
			continue
		}

		// Extract the function type from the capture group
		funcType := "add_" + content[match[2]:match[3]] + "_page"

		// Parse arguments with proper parenthesis balancing
		argsStartPos := match[1] // Position right after the opening (
		args := parseBalancedArgs(content, argsStartPos)

		// These pages need at least 4 args: page_title, menu_title, capability, menu_slug
		// The 5th arg (callback) is optional
		if len(args) < 4 {
			continue
		}

		processedPositions[startPos] = true

		endPos := findClosingParenPos(content, argsStartPos, 2000)
		fullMatch := content[startPos:endPos]

		capability := resolveAdminArg(args[2], symbolTable, content, startPos)
		menuSlug := resolveAdminArg(args[3], symbolTable, content, startPos)
		// Callback is optional (5th arg) - default to empty if not provided
		callback := ""
		if len(args) >= 5 {
			callback = args[4]
		}

		// Skip if we couldn't resolve a meaningful slug
		if menuSlug == "" {
			menuSlug = "{dynamic:" + funcType + "}"
		}

		lineNum := countLines(content[:startPos]) + 1
		authLevel := determineAuthLevelFromCapability(capability)

		// Analyze callback function for additional auth checks
		if callback != "" {
			authLevel = analyzeAdminCallbackAuth(callback, content, authLevel)
		}

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAdmin,
			Route:      formatAdminRoute(menuSlug),
			Method:     "GET",
			AuthLevel:  authLevel,
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
			Namespace:  funcType,
		}
		endpoints = append(endpoints, ep)
	}

	// 5. Handle spread operator: add_submenu_page(...$args)
	spreadMatches := adminSpreadPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range spreadMatches {
		if len(match) < 6 || processedPositions[match[0]] {
			continue
		}

		processedPositions[match[0]] = true
		fullMatch := content[match[0]:match[1]]
		funcType := "add_" + content[match[2]:match[3]] + "_page"
		argsVar := content[match[4]:match[5]]

		// Try to find the $args array definition
		menuSlug := tryResolveSpreadArgs(argsVar, symbolTable, content, match[0])
		if menuSlug == "" {
			menuSlug = "{spread:" + argsVar + "}"
		}

		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAdmin,
			Route:      formatAdminRoute(menuSlug),
			Method:     "GET",
			AuthLevel:  models.Admin, // Assume admin for spread args
			Callback:   "spread:" + argsVar,
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 500),
			Namespace:  funcType,
		}
		endpoints = append(endpoints, ep)
	}

	return endpoints
}

// rescueTruncatedArrayCallback re-reads the callback argument of an add_*_page
// call with balanced-delimiter parsing, for the case where the caller's regex
// capture was cut short.
//
// It returns "" when there is nothing to rescue, so the caller keeps whatever the
// regex found. Only an array-form callback can be truncated this way: a PHP array
// callable always contains a comma and the capture class ([^,)]+) ends there.
//
// callPos is the offset of the add_*_page identifier. Every one of these core
// functions takes the callback as its fifth argument except add_submenu_page,
// whose leading parent_slug pushes it to the sixth (wp-admin/includes/plugin.php).
func rescueTruncatedArrayCallback(content string, callPos int, captured string) string {
	captured = strings.TrimSpace(captured)
	if !strings.HasPrefix(captured, "[") && !strings.HasPrefix(captured, "array(") &&
		!strings.HasPrefix(captured, "array (") {
		return ""
	}
	open := strings.IndexByte(content[callPos:], '(')
	if open < 0 {
		return ""
	}
	idx := 4
	if strings.HasPrefix(content[callPos:], "add_submenu_page") {
		idx = 5
	}
	args := parseBalancedArgs(content, callPos+open+1)
	if idx >= len(args) {
		return ""
	}
	return args[idx]
}

// resolveAdminArg resolves a single admin page argument
func resolveAdminArg(arg string, st *SymbolTable, content string, position int) string {
	arg = strings.TrimSpace(arg)

	// String literal
	if (strings.HasPrefix(arg, "'") && strings.HasSuffix(arg, "'")) ||
		(strings.HasPrefix(arg, "\"") && strings.HasSuffix(arg, "\"")) {
		return strings.Trim(arg, "'\"")
	}

	// Try to resolve reference
	if val, ok := st.ResolveReference(arg); ok {
		return val
	}

	// Try local context
	localST := ExtractLocalContext(content, position, 50)
	if val, ok := localST.ResolveReference(arg); ok {
		return val
	}

	// Handle array access: $this->args['key'] or $args['key'] using pre-compiled pattern
	if matches := adminVarArrayPattern.FindStringSubmatch(arg); len(matches) >= 3 {
		// We found array access but can't resolve the array
		return "{" + matches[1] + ":" + matches[2] + "}"
	}

	// Handle variables and class constants
	if strings.HasPrefix(arg, "$") || strings.Contains(arg, "::") {
		return "{" + sanitizeForRoute(arg) + "}"
	}

	// Handle standalone constants (all caps, underscores) using pre-compiled pattern
	if adminConstNamePattern.MatchString(arg) {
		return "{" + sanitizeForRoute(arg) + "}"
	}

	return ""
}

// tryResolveSpreadArgs attempts to resolve spread operator arguments
func tryResolveSpreadArgs(argsVar string, st *SymbolTable, content string, position int) string {
	// Look for array definition: $args = ['slug', ...] or $args = array('slug', ...)
	varName := strings.TrimPrefix(argsVar, "$")

	// Pattern to find array assignment
	arrayAssignPattern := regexp.MustCompile(
		`\$` + regexp.QuoteMeta(varName) + `\s*=\s*(?:\[|array\s*\()\s*` +
			`(?:[^,]+,\s*){3,4}` + // Skip first 3-4 elements (parent_slug/page_title/menu_title/capability)
			`['"]([^'"]+)['"]`, // menu_slug
	)

	// Search backwards from position
	searchStart := position - 2000
	if searchStart < 0 {
		searchStart = 0
	}
	searchContent := content[searchStart:position]

	if matches := arrayAssignPattern.FindStringSubmatch(searchContent); len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

// parseBalancedArgs parses function arguments while respecting nested parentheses and brackets
// Returns a slice of trimmed argument strings
func parseBalancedArgs(content string, startPos int) []string {
	args := make([]string, 0, 8)
	if startPos >= len(content) {
		return args
	}

	// Track nesting levels
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	inSingleQuote := false
	inDoubleQuote := false
	currentArg := strings.Builder{}

	for i := startPos; i < len(content); i++ {
		char := content[i]

		// Handle string literals.
		//
		// The escape test is "the character before this quote is not a
		// backslash", and a quote at offset 0 has no character before it, so it
		// cannot be escaped. Written as i > 0 the test silently declined to OPEN
		// a literal that began the parsed region: every comma after it then
		// looked like it was inside a string, and the whole argument list came
		// back as one element. Callers that pass startPos just after a "(" never
		// see it, because offset 0 is then never reached; a caller parsing a bare
		// argument list does.
		if char == '\'' && !inDoubleQuote {
			// Check for escaped quote
			if i == 0 || content[i-1] != '\\' {
				inSingleQuote = !inSingleQuote
			}
			currentArg.WriteByte(char)
			continue
		}
		if char == '"' && !inSingleQuote {
			if i == 0 || content[i-1] != '\\' {
				inDoubleQuote = !inDoubleQuote
			}
			currentArg.WriteByte(char)
			continue
		}

		// Skip processing of characters inside strings
		if inSingleQuote || inDoubleQuote {
			currentArg.WriteByte(char)
			continue
		}

		// Track nesting
		switch char {
		case '(':
			parenDepth++
			currentArg.WriteByte(char)
		case ')':
			if parenDepth == 0 {
				// End of function arguments
				arg := strings.TrimSpace(currentArg.String())
				if arg != "" {
					args = append(args, arg)
				}
				return args
			}
			parenDepth--
			currentArg.WriteByte(char)
		case '[':
			bracketDepth++
			currentArg.WriteByte(char)
		case ']':
			bracketDepth--
			currentArg.WriteByte(char)
		case '{':
			braceDepth++
			currentArg.WriteByte(char)
		case '}':
			braceDepth--
			currentArg.WriteByte(char)
		case ',':
			// Only split at top level
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				arg := strings.TrimSpace(currentArg.String())
				if arg != "" {
					args = append(args, arg)
				}
				currentArg.Reset()
			} else {
				currentArg.WriteByte(char)
			}
		default:
			currentArg.WriteByte(char)
		}

		// Safety limit - don't parse more than 2000 chars
		if i-startPos > 2000 {
			break
		}
	}

	// If we reached here, add remaining content as last arg
	arg := strings.TrimSpace(currentArg.String())
	if arg != "" {
		args = append(args, arg)
	}

	return args
}

// parseAdminPageMatch extracts admin page info from a regex match
func parseAdminPageMatch(content string, match []int, patternStr string) *AdminPageInfo {
	if len(match) < 2 {
		return nil
	}

	info := &AdminPageInfo{}

	// Determine function type using pre-compiled package-level patterns
	if adminMenuPagePattern.MatchString(patternStr) {
		info.FunctionType = "add_menu_page"
		if len(match) >= 12 {
			info.PageTitle = safeExtract(content, match, 2)
			info.MenuTitle = safeExtract(content, match, 4)
			info.Capability = safeExtract(content, match, 6)
			info.MenuSlug = safeExtract(content, match, 8)
			info.Callback = safeExtract(content, match, 10)
		}
	} else if adminSubmenuPagePattern.MatchString(patternStr) {
		info.FunctionType = "add_submenu_page"
		if len(match) >= 14 {
			info.ParentSlug = safeExtract(content, match, 2)
			info.PageTitle = safeExtract(content, match, 4)
			info.MenuTitle = safeExtract(content, match, 6)
			info.Capability = safeExtract(content, match, 8)
			info.MenuSlug = safeExtract(content, match, 10)
			info.Callback = safeExtract(content, match, 12)
		}
	} else if adminOptionsThemeEtcPattern.MatchString(patternStr) {
		// These all have the same signature
		funcMatch := adminFunctionExtractPattern.FindStringSubmatch(patternStr)
		if len(funcMatch) >= 2 {
			info.FunctionType = "add_" + funcMatch[1] + "_page"
		}
		if len(match) >= 12 {
			info.PageTitle = safeExtract(content, match, 2)
			info.MenuTitle = safeExtract(content, match, 4)
			info.Capability = safeExtract(content, match, 6)
			info.MenuSlug = safeExtract(content, match, 8)
			info.Callback = safeExtract(content, match, 10)
		}
	} else if adminPostsMediaEtcPattern.MatchString(patternStr) {
		if len(match) >= 14 {
			info.FunctionType = "add_" + safeExtract(content, match, 2) + "_page"
			info.PageTitle = safeExtract(content, match, 4)
			info.MenuTitle = safeExtract(content, match, 6)
			info.Capability = safeExtract(content, match, 8)
			info.MenuSlug = safeExtract(content, match, 10)
			info.Callback = safeExtract(content, match, 12)
		}
	}

	return info
}

// safeExtract safely extracts a capture group from content
func safeExtract(content string, match []int, index int) string {
	if index >= len(match) || index+1 >= len(match) {
		return ""
	}
	start, end := match[index], match[index+1]
	if start < 0 || end < 0 || start > len(content) || end > len(content) {
		return ""
	}
	return content[start:end]
}

// determineAuthLevelFromCapability maps the capability declared on an admin page
// onto the ladder.
//
// The exact table answers every capability WordPress core defines. Past that, the
// pattern heuristics recognise the conventional plugin spellings (manage_*,
// *_users, install_*, and so on) that core itself established.
//
// What is left is a capability nobody can name: a string the tables do not know,
// or the "{...}" placeholder resolveAdminArg emits when the argument is a
// variable, a constant or an array lookup it could not follow -- 704 such sites
// in 81 of the 143 corpus plugins. The answer used to be Admin, which is a
// privilege claim invented from no evidence, and inventing privilege is the
// dangerous direction: a vulnerability behind an endpoint the tool calls Admin
// looks gated and gets dismissed. What the evidence does support is that this is
// a wp-admin screen at all, and wp-admin/admin.php calls auth_redirect() before
// any screen renders, so every admin page needs a logged-in user. Subscriber is
// that floor and it is the whole of what is known.
func determineAuthLevelFromCapability(capability string) models.AuthLevel {
	initCapabilityLevels()
	if level, ok := capabilityLevels[capability]; ok {
		return level
	}
	if level := inferCapabilityAuthLevel(capability); level != models.Unauthenticated {
		return level
	}
	return models.Subscriber
}

// analyzeAdminCallbackAuth combines the capability WordPress enforces on an admin
// page with whatever the page's own callback enforces on top of it.
//
// The declared capability is a floor, not a hint. add_submenu_page() returns
// false without registering anything when ! current_user_can( $capability );
// add_menu_page() attaches the callback only inside a condition that includes
// current_user_can( $capability ); and wp-admin/admin.php refuses a hook suffix
// missing from $_registered_pages (wp-admin/includes/plugin.php,
// user_can_access_admin_page()). Core refuses the page before the callback runs,
// so the callback can only add requirements to it.
//
// models.AuthLevel is an ascending iota enum (Unauthenticated < Subscriber <
// Contributor < Author < Editor < Admin < SuperAdmin), so "the more restrictive
// of the two" is an ordinal maximum. The if-chain this replaces enumerated three
// of those seven values, so a page declaring edit_posts, publish_posts or
// edit_others_posts matched neither test and fell through to Unauthenticated --
// and it fell through only when the callback WAS found, which made resolving the
// callback strictly worse than failing to. Measured over the 143-plugin corpus:
// 78 admin pages in 17 plugins declare a contributor/author/editor capability and
// not one of them kept its level.
//
// Two guards keep the max from inventing privilege of its own:
//
//   - The callback contributes only through StrongestGuard, not through all of
//     InferAuthLevel. InferAuthLevel's later steps raise on an admin-shaped
//     assertion -- is_super_admin(), is_network_admin() -- that capCheckPattern
//     does not cover, so FindCapabilityGuards cannot classify it as gating and
//     cannot veto it. A body whose only such call decides whether to draw a
//     network-tools link would otherwise report Admin for a page core gates at
//     edit_posts. is_super_admin appears in 50 of the 143 corpus plugins.
//
//   - The raise happens only when the callback body is unambiguously resolved.
//     findFunctionBody takes the first "function <name>(" in the file and 174
//     files in 57 corpus plugins declare the same name twice, so on an ambiguous
//     name the raise could come from a guard belonging to a different class.
//
// SuperAdmin is deliberately held out of the combination. A declared
// manage_network_options is one site in the whole corpus and it does not reach
// this path today, so promoting a page six levels on the strength of one string
// would be the largest single over-restriction available here for no measured
// benefit. Admin is the ceiling this combination can produce; a page whose
// capability alone says SuperAdmin still reports SuperAdmin through the early
// returns above, which never enter the combination.
func analyzeAdminCallbackAuth(callback string, content string, capabilityLevel models.AuthLevel) models.AuthLevel {
	funcName := extractFunctionNameFromCallback(callback)
	if funcName == "" {
		return capabilityLevel
	}

	funcBody := findFunctionBody(funcName, content)
	if funcBody == "" {
		return capabilityLevel
	}
	if !uniquelyDeclaredInFile(funcName, content) {
		return capabilityLevel
	}

	level := capabilityLevel
	if level > models.Admin {
		level = models.Admin
	}
	if callbackLevel := gatingGuardLevel(funcBody); callbackLevel > level {
		return callbackLevel
	}
	return level
}

// gatingGuardLevel is the privilege a function body demands of its own caller,
// counting only checks that gate the whole body.
//
// This is InferAuthLevel's capability step and nothing else. The steps after that
// one exist to salvage an answer from weaker evidence -- a capability string that
// merely appears, an admin-shaped predicate, a login test -- and each is a channel
// by which a decorative check inside a page callback could raise the page above
// what WordPress enforces at the menu. When the question is "does the callback
// demand MORE than the menu capability", only a check that stops the request can
// answer yes.
//
// Among several gating checks the lowest wins, for the same reason it does in
// InferAuthLevel: passing any one of the alternatives is enough to get in, so the
// weakest is what an attacker needs.
func gatingGuardLevel(body string) models.AuthLevel {
	gatingCaps, gated := StrongestGuard(body)
	if !gated {
		return models.Unauthenticated
	}
	best := models.AuthLevel(-1)
	for _, c := range gatingCaps {
		lvl, ok := resolveCapabilityLevel(c)
		if !ok {
			continue
		}
		if best < 0 || lvl < best {
			best = lvl
		}
	}
	if best < 0 {
		// Gated, but by a capability held in a variable or constant that cannot
		// be resolved statically. Something is required; Subscriber is the floor.
		return models.Subscriber
	}
	return best
}

// uniquelyDeclaredInFile reports whether exactly one function or method in this
// file is called funcName, which is the condition under which findFunctionBody's
// answer is certainly the right body.
//
// FindFunctionDeclarations is the balanced-paren scan the call graph uses, so it
// sees declarations that findFunctionBody's plain "function <name>" search would
// spell differently. Counting with the more generous scanner makes the "ambiguous"
// verdict more likely, which is the safe direction here: ambiguity only suppresses
// a raise.
func uniquelyDeclaredInFile(funcName, content string) bool {
	seen := 0
	for _, d := range FindFunctionDeclarations(content) {
		if d.Name == funcName {
			seen++
			if seen > 1 {
				return false
			}
		}
	}
	return seen == 1
}

// extractFunctionNameFromCallback extracts the function name from various callback formats
// Handles: 'function_name', [$this, 'method'], array($this, 'method'), Class::method
func extractFunctionNameFromCallback(callback string) string {
	callback = strings.TrimSpace(callback)

	// String function name: 'function_name' or "function_name"
	if (strings.HasPrefix(callback, "'") && strings.HasSuffix(callback, "'")) ||
		(strings.HasPrefix(callback, "\"") && strings.HasSuffix(callback, "\"")) {
		return strings.Trim(callback, "'\"")
	}

	// Array callback: [$this, 'method'] or array($this, 'method') using pre-compiled pattern
	if matches := adminCallbackArrayPattern.FindStringSubmatch(callback); len(matches) >= 2 {
		return matches[1]
	}

	// Static method: Class::method
	if strings.Contains(callback, "::") {
		parts := strings.Split(callback, "::")
		if len(parts) >= 2 {
			return strings.TrimSpace(parts[1])
		}
	}

	// Plain function name (no quotes) using pre-compiled pattern
	if adminSimpleIdentPattern.MatchString(callback) {
		return callback
	}

	return ""
}

// DetectAdminNotices finds admin notice hooks that might indicate admin functionality
func DetectAdminNotices(content, filepath string, pluginSlug string) []models.Endpoint {
	endpoints := make([]models.Endpoint, 0)

	// Use pre-compiled package-level pattern
	matches := adminNoticesPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		fullMatch := content[match[0]:match[1]]
		callback := content[match[2]:match[3]]
		lineNum := countLines(content[:match[0]]) + 1

		ep := models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeAdmin,
			Route:      "admin_notices",
			Method:     "GET",
			AuthLevel:  models.Admin, // Admin notices require admin access
			Callback:   NormalizeCallback(callback),
			File:       filepath,
			Line:       lineNum,
			RawCode:    truncateCode(fullMatch, 300),
			Namespace:  "admin_notices",
		}
		endpoints = append(endpoints, ep)
	}

	return endpoints
}

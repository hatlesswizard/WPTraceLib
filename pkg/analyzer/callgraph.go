package analyzer

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// CallGraph represents the call relationships for a callback function
type CallGraph struct {
	// Callees are functions called BY this callback (forward direction)
	Callees []string `json:"callees,omitempty"`
	// Callers are functions that CALL this callback (backward direction)
	Callers []string `json:"callers,omitempty"`
}

// FunctionDef represents a PHP function or method definition
type FunctionDef struct {
	Name       string // Function or method name
	ClassName  string // Empty for standalone functions
	FilePath   string // Relative path within plugin where this function is defined
	StartLine  int    // Line where function starts
	EndLine    int    // Line where function ends
	IsMethod   bool   // True if it's a class method
	Visibility string // public, private, protected (for methods)
	// Note: Body field removed for memory optimization.
	// Use CallsFrom map instead of storing/re-extracting function bodies.
}

// HookRegistration records a callback registered for a WordPress hook
type HookRegistration struct {
	Callback string // Resolved callback name
	File     string // File where add_action/add_filter was called
	// Hook is the hook name the callback was registered under. For a
	// registration whose name was composed at the call site this is the literal
	// prefix, which is what PrefixHooks is keyed by.
	Hook string
	// Synthesized marks a registration that was not written literally in the
	// source. `add_action( 'h_' . $a, array( $this, $m ) )` names a method the
	// language bounds to the enclosing class but does not spell out, so one
	// registration is recorded per method of that class. Those are sound as
	// call-graph edges and must not be mistaken for evidence that a particular
	// callback was registered.
	Synthesized bool
}

// HookRegistry maps hook names to their registered callbacks.
// Built during call graph construction to link do_action/apply_filters to add_action/add_filter.
type HookRegistry struct {
	Hooks       map[string][]HookRegistration
	PrefixHooks map[string][]HookRegistration
	// Fired holds every hook name this tree fires with a string literal.
	Fired map[string]bool
	// FiredPrefixes holds the literal head of every firing whose name was
	// composed at the call site: do_action( 'save_post_' . $type ).
	FiredPrefixes map[string]bool
	// FiredOpaque records that the tree fires at least one hook whose name is
	// a bare variable or a constant, so it cannot be read. A consumer deciding
	// that a registration is fired only from outside the plugin should know
	// that some in-tree firings could not be attributed.
	FiredOpaque bool
	mu          sync.RWMutex
}

// NewHookRegistry creates a new empty hook registry
func NewHookRegistry() *HookRegistry {
	return &HookRegistry{
		Hooks:         make(map[string][]HookRegistration),
		PrefixHooks:   make(map[string][]HookRegistration),
		Fired:         make(map[string]bool),
		FiredPrefixes: make(map[string]bool),
	}
}

// PluginCallGraph holds call graph data for an entire plugin
type PluginCallGraph struct {
	// Functions maps function/method names to their definitions
	Functions map[string]*FunctionDef
	// CallsFrom maps a function name to functions it calls
	CallsFrom map[string][]string
	// CallsTo maps a function name to functions that call it
	CallsTo map[string][]string
	// AmbiguousFuncs maps a bare function name to all file-qualified keys
	// e.g. "display" -> ["admin/controllers/Submissions_fm.php::display", "frontend/controllers/FMControllerForm_maker_preview.php::display"]
	// This tracks standalone functions that share the same name across different files.
	AmbiguousFuncs map[string][]string
	// IncludesFrom maps source file path to files it includes/requires
	IncludesFrom map[string][]string
	// ClassToFile maps class name (and FQN with namespace) to file path
	ClassToFile map[string]string
	// ClassToFiles maps a type name to EVERY file declaring it.
	//
	// ClassToFile is single-valued and last-writer-wins, so recognising more
	// type declarations would let a newly visible one displace an existing
	// mapping and REMOVE the file reach it carried -- measured at 163 names in
	// 36 of 143 corpus trees when the backslash-parent and trait shapes became
	// visible. Every reachability consumer reads this many-valued map instead,
	// so widening what the analyzer can see can only add file reach.
	ClassToFiles map[string][]string
	// Types records what is known about each declared type: its kind, its
	// parent, the traits it uses and the methods it declares. PHP resolves a
	// method against the class, then its traits in declaration order, then its
	// parent, and that walk needs all four.
	Types map[string]*TypeDef
	// typeFold maps a lower-cased type name to its canonical spelling. PHP type
	// names are case-insensitive while the graph preserves the source's case,
	// so `extends WPForms_Field` must find a declaration of `WPForms_field`.
	typeFold map[string]string
	// FilesByBasename maps file basename to full relative paths for include resolution
	FilesByBasename map[string][]string
	// normFiles maps a separator-normalised file path to the key AllFiles
	// actually holds.
	//
	// Callers key the files map by whatever their platform produced:
	// production passes absolute OS paths, the benchmark passes filepath.Rel
	// output, and both carry backslashes on Windows. Include paths inside PHP
	// source are written with forward slashes, so every suffix comparison
	// against a raw key failed on Windows and include resolution silently
	// degraded to unique-basename matching. Comparisons are made against this
	// index and the ORIGINAL key is returned, so no downstream consumer ever
	// sees a path spelled differently from the one it passed in.
	normFiles map[string]string
	// DeclaredNames holds every bare function and method name this tree
	// declares. extractCalls drops a call whose name is a WordPress core
	// function, which is wrong when the plugin declares a function of that name
	// itself -- 730 such declarations across 102 of 143 corpus trees, and 2,943
	// `$this-><coreName>(` call sites in 74 of them.
	DeclaredNames map[string]bool
	// AllFiles tracks every PHP file path passed to BuildCallGraph
	AllFiles map[string]bool
	// DynIncluders maps function names that contain variable includes to directory hints
	DynIncluders map[string][]string
	// AutoloadBaseDirs holds PSR-4 base directories from spl_autoload_register / composer
	AutoloadBaseDirs []string
	// HookRegistry links WordPress hook names to registered callbacks
	HookRegistry *HookRegistry
	mu           sync.RWMutex
}

// NewPluginCallGraph creates a new empty call graph
func NewPluginCallGraph() *PluginCallGraph {
	return &PluginCallGraph{
		Functions:        make(map[string]*FunctionDef),
		CallsFrom:        make(map[string][]string),
		CallsTo:          make(map[string][]string),
		AmbiguousFuncs:   make(map[string][]string),
		IncludesFrom:     make(map[string][]string),
		ClassToFile:      make(map[string]string),
		ClassToFiles:     make(map[string][]string),
		Types:            make(map[string]*TypeDef),
		typeFold:         make(map[string]string),
		FilesByBasename:  make(map[string][]string),
		normFiles:        make(map[string]string),
		DeclaredNames:    make(map[string]bool),
		AllFiles:         make(map[string]bool),
		DynIncluders:     make(map[string][]string),
		AutoloadBaseDirs: make([]string, 0),
		HookRegistry:     NewHookRegistry(),
	}
}

// Package-level compiled regex patterns for call graph analysis
var (
	// Function declarations are found by FindFunctionDeclarations (funcdecl.go),
	// which walks the parameter list's delimiters. The regex that preceded it
	// is deliberately gone rather than left unused: `\([^)]*\)` cannot match a
	// balanced parameter list, and RE2 offers no way to make it.

	// Class, trait, interface and enum declarations are recognised by
	// classDeclPattern in classinfo.go, which classDefPattern aliases.

	// Pattern for direct function calls: function_name(...)
	directCallPattern = regexp.MustCompile(
		`\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern for method calls: $this->method(...), $var->method(...)
	methodCallPattern = regexp.MustCompile(
		`\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern for $this->method calls specifically
	thisMethodCallPattern = regexp.MustCompile(
		`\$this\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern for static method calls: ClassName::method(...), self::method(...), static::method(...)
	staticCallPattern = regexp.MustCompile(
		`([a-zA-Z_][a-zA-Z0-9_]*|self|static|parent)\s*::\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`,
	)

	// Pattern for call_user_func variants
	callUserFuncPattern = regexp.MustCompile(
		`call_user_func(?:_array)?\s*\(\s*` +
			`(?:` +
			`['"]([^'"]+)['"]` + // Simple string callback
			`|` +
			`\[\s*[^,]+,\s*['"]([^'"]+)['"]` + // Array callback [obj, 'method']
			`|` +
			`array\s*\(\s*[^,]+,\s*['"]([^'"]+)['"]` + // array(obj, 'method')
			`)`,
	)

	// Pattern for do_action and apply_filters (WordPress hooks that trigger callbacks)
	//
	// do_action_ref_array and apply_filters_ref_array fire a hook exactly as
	// their plain counterparts do -- the only difference is how arguments are
	// passed -- so a pattern that omits them severs 268 firings across 49 trees.
	wpHookCallPattern = regexp.MustCompile(
		`(?:do_action|apply_filters)(?:_ref_array)?\s*\(\s*['"]([^'"]+)['"]`,
	)

	// Hook names composed at the call site. WordPress plugins routinely write
	//     apply_filters( 'form_wrap_process_' . $formType, ... )
	//     do_action( "save_post_{$post->post_type}", ... )
	// while the handlers register under the composed literal name. Without
	// these the call site resolves to nothing and the graph is severed at the
	// hook, which is where a great deal of WordPress control flow lives.
	//
	// Only the literal fragment is captured. A name with no literal part at all
	// is not matched: it identifies nothing, and joining it to every
	// registration would replace analysis with an edge explosion.
	wpHookCallConcatPrefixPattern = regexp.MustCompile(
		`(?:do_action|apply_filters)(?:_ref_array)?\s*\(\s*['"]([A-Za-z0-9_/-]{4,})['"]\s*\.`,
	)
	wpHookCallConcatSuffixPattern = regexp.MustCompile(
		`(?:do_action|apply_filters)(?:_ref_array)?\s*\(\s*[^,'"()]+\.\s*['"]([A-Za-z0-9_/-]{4,})['"]\s*[,)]`,
	)
	wpHookCallInterpPrefixPattern = regexp.MustCompile(
		`(?:do_action|apply_filters)(?:_ref_array)?\s*\(\s*"([A-Za-z0-9_/-]{4,})\{?\$`,
	)
	wpHookCallInterpSuffixPattern = regexp.MustCompile(
		`(?:do_action|apply_filters)(?:_ref_array)?\s*\(\s*"\{?\$[^"]*\}?([A-Za-z0-9_/-]{4,})"`,
	)

	// A firing whose name is a bare variable, a constant or a call: the name
	// cannot be read, so "this tree never fires that hook" cannot be concluded
	// from its absence.
	wpHookCallOpaquePattern = regexp.MustCompile(
		`(?:do_action|apply_filters)(?:_ref_array)?\s*\(\s*(?:\$|[A-Z][A-Z0-9_]{2,}\s*[,)])`,
	)

	// Pre-compiled patterns for ResolveCallback (memory optimization)
	cleanFunctionNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	arrayMethodNamePattern   = regexp.MustCompile(`['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)

	// Pattern for include/require file path extraction
	// Group 1: simple string literal
	// Group 2: __DIR__/dirname relative path
	// Group 3: any expression (constant, variable, property) + literal .php path
	includePattern = regexp.MustCompile(
		`(?:include|include_once|require|require_once)\s*` +
			`(?:\(\s*)?` +
			`(?:` +
			`['"]([^'"]+\.php)['"]` +
			`|(?:__DIR__|dirname\s*\(\s*__FILE__\s*\))\s*\.\s*['"]([^'"]+)['"]` +
			`|[a-zA-Z_$][a-zA-Z0-9_:>$\-]*[^'"]*['"]([^'"]*\.php)['"]` +
			`)`,
	)

	// Pattern for multi-segment concatenated includes with DIRECTORY_SEPARATOR
	// Extracts all string fragments that look like path segments from include statements
	includeFragmentPattern = regexp.MustCompile(
		`(?:include|include_once|require|require_once)\s*(?:\(\s*)?([^;]+)`,
	)

	// Pattern for namespace declaration
	namespacePattern = regexp.MustCompile(`(?m)^namespace\s+([a-zA-Z_][a-zA-Z0-9_\\]*)\s*;`)

	// Pattern for add_action/add_filter with static hook name
	// Callback group captures array syntax [...], array(...), or simple expression
	hookRegistrationPattern = regexp.MustCompile(
		`\b(?:add_action|add_filter)\s*\(\s*['"]([^'"]+)['"]\s*,\s*` +
			`(\[[^\]]*\]|array\s*\([^)]*\)|[^,)]+)`,
	)

	// Pattern for add_action/add_filter with concatenated hook: 'prefix_' . $var
	hookRegistrationDynamicPattern = regexp.MustCompile(
		`\b(?:add_action|add_filter)\s*\(\s*['"]([^'"]+)['"]\s*\.\s*[^,]+,\s*` +
			`(\[[^\]]*\]|array\s*\([^)]*\)|[^,)]+)`,
	)

	// Pattern for add_shortcode('tag', callback)
	shortcodeRegistrationPattern = regexp.MustCompile(
		`\badd_shortcode\s*\(\s*['"]([^'"]+)['"]\s*,\s*` +
			`(\[[^\]]*\]|array\s*\([^)]*\)|[^,)]+)`,
	)

	// PHP trait usage inside a type body is matched by traitUsePattern in
	// classinfo.go.

	// Instantiation. `new` is a PHP keyword, so the class name survives only as
	// a bare token from directCallPattern -- and then only when the call is
	// written with parentheses. `new Klass;`, `return new Klass,` and
	// `new Klass)` are all legal and emit nothing at all today: 2,409 such
	// sites across 81 of 143 corpus trees, 916 of them naming a class that
	// declares __construct.
	//
	// `new self`, `new static` and `new parent` are matched here too and are
	// mapped to the enclosing class by the caller. `new class` (an anonymous
	// class) and `new $var` are excluded: the first names no type, and the
	// second names one this pattern cannot read.
	newInstancePattern = regexp.MustCompile(
		`\bnew\s+\\?([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\\]*)`,
	)

	// A class named by a variable: `new $classname()` and `$classname::method()`.
	// Framework-shaped plugins route every request through one of these, so the
	// dispatch layer is a cut edge without them: 1,373 `new $var` sites in 107
	// of 143 corpus trees and 1,137 `$var::method()` sites in 60.
	newVarPattern        = regexp.MustCompile(`\bnew\s+\$([a-zA-Z_][a-zA-Z0-9_]*)`)
	varStaticCallPattern = regexp.MustCompile(
		`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*::\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)

	// An assignment whose right-hand side may be a string built from literals.
	// The value is bounded to a few hundred characters because a class name is
	// short and the scan is per function body.
	varAssignPattern = regexp.MustCompile(
		`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;{}]{1,300});`)

	// A method call whose NAME is held in a variable: $this->$m(), $this->{$m}().
	// The receiver is not unknown -- $this is an instance of the lexically
	// enclosing class -- so the target is one of that class's methods.
	thisVarMethodPattern = regexp.MustCompile(
		`\$this\s*->\s*\{?\s*\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\}?\s*\(`,
	)

	// call_user_func(array($this, $m)) and its variants, where the method slot
	// is a variable rather than a literal, optionally with a literal prefix:
	// array($this, 'action' . $name). PHP string concatenation is
	// prefix-preserving, so "action" . $x can only ever name a method whose
	// name starts with "action".
	callUserFuncThisVarPattern = regexp.MustCompile(
		`(?:call_user_func(?:_array)?|method_exists|is_callable)\s*\(\s*` +
			`(?:\[|array\s*\()\s*\$this\s*,\s*(?:['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\s*\.\s*)?\$`,
	)

	// Pattern to extract class name from callback expressions like ClassName::class
	hookCallbackClassPattern = regexp.MustCompile(`([A-Z][a-zA-Z0-9_]*)::class|['"]([A-Z][a-zA-Z0-9_]*)['"]`)

	// Detects include/require with a variable path (not a string literal)
	dynamicIncludeVarPattern = regexp.MustCompile(
		`(?:include|include_once|require|require_once)\s*(?:\(\s*)?\$[a-zA-Z_]`,
	)

	// Captures function calls with string literal first argument
	funcWithStringArgPattern = regexp.MustCompile(
		`(?:` +
			`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*['"]([^'"]+)['"]` + // Groups 1,2: func('arg')
			`|` +
			`\$(?:this|self)\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*['"]([^'"]+)['"]` + // Groups 3,4: $this->func('arg')
			`|` +
			`([A-Z][a-zA-Z0-9_]*)\s*::\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*['"]([^'"]+)['"]` + // Groups 5,6,7: Class::func('arg')
			`)`,
	)

	// Extracts string literals containing directory separators (for directory hints)
	dirHintPattern = regexp.MustCompile(`['"]([^'"]*[/\\][^'"]*)['"]`)

	// PHP keywords that look like function calls but aren't
	phpKeywords = map[string]bool{
		"if": true, "else": true, "elseif": true, "while": true, "for": true,
		"foreach": true, "switch": true, "case": true, "return": true,
		"echo": true, "print": true, "die": true, "exit": true,
		"include": true, "include_once": true, "require": true, "require_once": true,
		"new": true, "clone": true, "throw": true, "catch": true, "try": true,
		"finally": true, "use": true, "namespace": true, "class": true,
		"interface": true, "trait": true, "extends": true, "implements": true,
		"public": true, "private": true, "protected": true, "static": true,
		"final": true, "abstract": true, "const": true, "function": true,
		"array": true, "list": true, "isset": true, "unset": true, "empty": true,
		"eval": true, "global": true, "var": true, "declare": true,
		"enddeclare": true, "endfor": true, "endforeach": true, "endif": true,
		"endswitch": true, "endwhile": true, "as": true, "default": true,
		"break": true, "continue": true, "goto": true, "match": true,
		"fn": true, "yield": true, "from": true, "insteadof": true,
	}

	// Common WordPress core functions (we don't need to recurse into these)
	wpCoreFunctions = map[string]bool{
		// Database
		"wpdb": true, "$wpdb": true,
		// Options
		"get_option": true, "update_option": true, "delete_option": true, "add_option": true,
		"get_site_option": true, "update_site_option": true, "delete_site_option": true,
		"get_transient": true, "set_transient": true, "delete_transient": true,
		// Posts
		"get_post": true, "get_posts": true, "wp_insert_post": true, "wp_update_post": true,
		"wp_delete_post": true, "get_post_meta": true, "update_post_meta": true,
		"delete_post_meta": true, "add_post_meta": true,
		// Users
		"get_user_by": true, "get_userdata": true, "get_current_user_id": true,
		"wp_get_current_user": true, "get_user_meta": true, "update_user_meta": true,
		"wp_create_user": true, "wp_insert_user": true, "wp_update_user": true,
		// Security/Auth
		"current_user_can": true, "is_user_logged_in": true, "wp_verify_nonce": true,
		"check_ajax_referer": true, "wp_create_nonce": true, "is_admin": true,
		"is_super_admin": true, "user_can": true,
		// AJAX/JSON responses
		"wp_send_json": true, "wp_send_json_success": true, "wp_send_json_error": true,
		"wp_die": true,
		// Sanitization
		"sanitize_text_field": true, "sanitize_email": true, "sanitize_title": true,
		"sanitize_file_name": true, "sanitize_key": true, "sanitize_user": true,
		"sanitize_html_class": true, "sanitize_option": true,
		"wp_kses": true, "wp_kses_post": true, "esc_html": true, "esc_attr": true,
		"esc_url": true, "esc_sql": true, "absint": true, "intval": true,
		// Validation
		"is_email": true, "wp_validate_boolean": true,
		// Hooks
		"add_action": true, "add_filter": true, "remove_action": true, "remove_filter": true,
		"do_action": true, "apply_filters": true, "has_action": true, "has_filter": true,
		// Queries
		"WP_Query": true, "WP_User_Query": true, "get_terms": true, "get_term": true,
		// REST
		"register_rest_route": true, "rest_ensure_response": true,
		// Admin
		"add_menu_page": true, "add_submenu_page": true, "add_options_page": true,
		// Capabilities
		"map_meta_cap": true, "add_cap": true, "remove_cap": true,
		// Misc
		"__": true, "_e": true, "esc_html__": true, "esc_attr__": true,
		"wp_enqueue_script": true, "wp_enqueue_style": true,
		"wp_localize_script": true, "wp_register_script": true,
		"admin_url": true, "home_url": true, "site_url": true, "plugins_url": true,
		"plugin_dir_path": true, "plugin_dir_url": true,
		"wp_redirect": true, "wp_safe_redirect": true,
		"wp_remote_get": true, "wp_remote_post": true, "wp_remote_request": true,
		"wp_upload_dir": true, "wp_handle_upload": true,
	}
)

// fileParse is one file's structure, parsed once and shared by every sub-pass.
//
// Five sub-passes used to rebuild the class ranges independently, which is five
// brace-matching scans of every file in the plugin, and two of them parsed the
// function declarations a second time as well. Under this project's memory
// ceiling that is worth doing once.
type fileParse struct {
	decls   []FuncDecl
	types   map[string]classInfo
	aliases map[string]string
}

// BuildCallGraph builds a call graph for all PHP files in a plugin
// Memory-optimized: extracts calls inline during discovery, avoiding body storage
// DETERMINISM: Files are processed in sorted order to ensure consistent results
//
// Sub-passes:
//
//	0: Parse declarations and type bodies once per file; register types,
//	   declared names and per-type method lists so later passes can resolve a
//	   call against the whole tree rather than against one file
//	A: Build hook registry + extract file includes + register class-to-file mappings
//	B: Discover functions and extract calls (with hook resolution via registry)
//	C: Link each file's load-time code to the load-time code of what it includes
//	D: Resolve trait usage — alias trait methods to using classes
func BuildCallGraph(files map[string]string) *PluginCallGraph {
	cg := NewPluginCallGraph()

	// Sort file paths for deterministic processing order
	sortedPaths := make([]string, 0, len(files))
	for fp := range files {
		sortedPaths = append(sortedPaths, fp)
	}
	sort.Strings(sortedPaths)

	// Register all files and build basename index early (needed for resolution in Sub-pass B)
	for _, fp := range sortedPaths {
		cg.AllFiles[fp] = true
	}
	cg.buildFileIndex()

	// Sub-pass 0: parse each file once and register what the whole tree
	// declares. Sub-pass B needs the finished picture -- which names the plugin
	// declares, which methods each type has -- so it cannot be folded in.
	parsed := make(map[string]*fileParse, len(files))
	for _, fp := range sortedPaths {
		content := files[fp]
		p := &fileParse{
			decls:   FindFunctionDeclarations(content),
			types:   findClassInfos(content),
			aliases: fileUseAliases(content),
		}
		parsed[fp] = p
		cg.registerTypes(content, fp, p)
	}

	// Sub-pass A: Build hook registry, extract includes, register classes, detect dynamic includers
	for _, fp := range sortedPaths {
		cg.extractHookRegistrations(files[fp], fp, parsed[fp])
		cg.extractFileIncludes(files[fp], fp)
		cg.extractDynIncluders(files[fp], fp, parsed[fp])
		cg.extractAutoloadHints(files[fp], fp)
	}

	// Sub-pass B: Discover functions, extract calls (with hook resolution), resolve dynamic include edges
	for _, fp := range sortedPaths {
		cg.discoverFunctionsAndCalls(files[fp], fp, parsed[fp])
		cg.extractDynIncludeEdges(files[fp], fp)
	}

	// Sub-pass C: give the include graph a function-level twin.
	cg.linkTopLevelIncludes(sortedPaths)

	// Sub-pass D: Resolve trait usage
	cg.discoverTraitUsage()

	return cg
}

// registerTypes records every type this file declares, the names it declares,
// and the methods of each type.
//
// ClassToFile keeps its existing single-valued shape and its existing
// last-writer rule for classes, so no consumer outside this package sees a
// different answer than before. A trait, interface or enum is written only when
// the name is free: a trait named like a class must not displace the class,
// because dozens of call sites may name that class and only the class's file
// answers them. ClassToFiles records all of them, which is what reachability
// reads.
func (cg *PluginCallGraph) registerTypes(content, filePath string, p *fileParse) {
	namespace := ""
	if m := namespacePattern.FindStringSubmatch(content); len(m) > 1 {
		namespace = m[1]
	}

	cg.mu.Lock()
	defer cg.mu.Unlock()

	for _, d := range p.decls {
		cg.DeclaredNames[d.Name] = true
	}

	for name := range p.types {
		ci := p.types[name]

		if ci.Kind == "class" {
			cg.ClassToFile[name] = filePath
		} else if _, taken := cg.ClassToFile[name]; !taken {
			cg.ClassToFile[name] = filePath
		}
		if namespace != "" {
			fqn := namespace + "\\" + name
			if ci.Kind == "class" {
				cg.ClassToFile[fqn] = filePath
			} else if _, taken := cg.ClassToFile[fqn]; !taken {
				cg.ClassToFile[fqn] = filePath
			}
			cg.addClassFile(fqn, filePath)
		}
		cg.addClassFile(name, filePath)

		td := cg.Types[name]
		if td == nil {
			td = &TypeDef{Name: name, Kind: ci.Kind, Parent: ci.Parent}
			cg.Types[name] = td
			if lower := strings.ToLower(name); cg.typeFold[lower] == "" {
				cg.typeFold[lower] = name
			}
		} else if td.Parent == "" {
			td.Parent = ci.Parent
		}
		for _, t := range ci.Traits {
			if !containsName(td.Traits, t) {
				td.Traits = append(td.Traits, t)
			}
		}
		td.Files = append(td.Files, filePath)

		methods := make([]string, 0, 8)
		for _, d := range p.decls {
			if d.DeclStart > ci.Open && d.DeclStart < ci.Close {
				methods = append(methods, d.Name)
			}
		}
		td.addMethods(methods)
	}
}

func (cg *PluginCallGraph) addClassFile(name, filePath string) {
	if !containsName(cg.ClassToFiles[name], filePath) {
		cg.ClassToFiles[name] = append(cg.ClassToFiles[name], filePath)
	}
}

func containsName(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// discoverFunctionsAndCalls finds all function definitions and extracts their calls in one pass
// Memory-optimized: extracts calls immediately without storing function bodies
func (cg *PluginCallGraph) discoverFunctionsAndCalls(content, filePath string, p *fileParse) {
	// FindFunctionDeclarations scans the parameter list with a
	// balanced-delimiter walk instead of a regex. funcDefPattern's `\([^)]*\)`
	// stopped at the first ")" inside the parameters, so every declaration with
	// a default value like array() or a nested call was invisible -- 11,696 of
	// 329,198 declarations across a 143-plugin corpus, and 26% of the functions
	// in some plugins.
	decls := p.decls

	for _, decl := range decls {
		funcName := decl.Name
		startPos := decl.DeclStart
		startLine := countNewlines(content[:startPos])

		bodyStart := decl.BodyOpen
		endPos := decl.BodyClose
		endLine := countNewlines(content[:endPos])

		// Extract function body temporarily for call extraction
		body := content[bodyStart:endPos]

		// Determine which type declaration lexically encloses this function.
		encl := enclosingType(startPos, p.types)
		className := ""
		isMethod := false
		if encl != nil {
			className = encl.Name
			isMethod = true
		}

		// Create a unique key for the function
		key := funcName
		if className != "" {
			key = className + "::" + funcName
		}

		// Extract calls from the body immediately (memory-optimized: don't store body)
		calls := cg.extractCalls(body, callSite{class: encl, aliases: p.aliases})

		funcDef := &FunctionDef{
			Name:      funcName,
			ClassName: className,
			FilePath:  filePath,
			StartLine: startLine,
			EndLine:   endLine,
			IsMethod:  isMethod,
		}

		cg.mu.Lock()
		// A qualified key is written once. Two files may declare the same class
		// name -- 487 such names across 45 of 143 corpus trees -- and an
		// unconditional write let the second silently replace the first's body.
		// The loser is recorded as an ambiguous implementation instead, so both
		// bodies stay reachable from the same key.
		if prev, taken := cg.Functions[key]; !taken || prev == nil {
			cg.Functions[key] = funcDef
		}
		if className != "" {
			if _, taken := cg.CallsFrom[key]; !taken {
				cg.CallsFrom[key] = calls
			} else {
				cg.addQualifiedAlias(key, funcName, filePath, calls, funcDef)
			}
		}

		// Also store without class prefix for lookups.
		//
		// A method declared in a trait, interface or enum keeps the
		// unconditional (last-writer) binding it had when those bodies were
		// invisible and className was therefore empty. Moving it to the
		// first-writer branch would change 860 bare-name bindings corpus-wide
		// and, with them, which file a consumer reports as the declaration
		// site: an answer that is exact today would become ambiguous. Nothing
		// is gained by the move, so it is not made.
		if className != "" && (encl.Kind != "class" || cg.Functions[funcName] == nil) {
			cg.Functions[funcName] = funcDef
		}

		// DETERMINISM: track ambiguity when several definitions share a bare
		// name, and keep every function reachable under that bare name.
		//
		// This block runs for METHODS as well as standalone functions, and must.
		// Every lookup in this package falls back from "Class::method" to the
		// bare method name, and none goes the other way (see
		// GetRecursiveCallsForCallback and recurseCalls). extractCalls also
		// strips class prefixes from most call sites. So a method stored only
		// under its qualified key would vanish from every call chain -- which is
		// how it behaved before findClassRanges was fixed, when className was
		// always empty and this branch happened to run for everything.
		if _, alreadyExists := cg.CallsFrom[funcName]; alreadyExists {
			cg.addQualifiedAlias(funcName, funcName, filePath, calls, funcDef)
		} else {
			// First time seeing this bare name — store normally.
			// Functions[funcName] is first-writer above, so both maps now
			// agree on which definition the bare name denotes; they used to
			// disagree, Functions being last-writer and CallsFrom first.
			cg.CallsFrom[funcName] = calls
		}

		for _, callee := range calls {
			cg.CallsTo[callee] = append(cg.CallsTo[callee], key)
		}
		cg.mu.Unlock()
	}

	cg.addTopLevelNode(content, filePath, decls, p)
}

// addQualifiedAlias files one implementation under a key that already has an
// owner, so the loser of the collision stays reachable.
//
// The alias is "<basename>.php::<name>", the shape consumers already expect.
// When that shape is taken too -- a third declaration of the same name in one
// file, 1,722 declarations across 35 corpus trees -- the full path is used
// instead, so no implementation is dropped. Caller must hold cg.mu.
func (cg *PluginCallGraph) addQualifiedAlias(underKey, funcName, filePath string, calls []string, funcDef *FunctionDef) {
	aliasKey := filepath.Base(filePath) + "::" + funcName
	if _, taken := cg.CallsFrom[aliasKey]; taken {
		base := filepath.ToSlash(filePath) + "::" + funcName
		aliasKey = ""
		for n := 2; n < 64; n++ {
			cand := base + "#" + strconv.Itoa(n)
			if _, taken := cg.CallsFrom[cand]; !taken {
				aliasKey = cand
				break
			}
		}
		if aliasKey == "" {
			return
		}
	}
	cg.CallsFrom[aliasKey] = calls
	if _, taken := cg.Functions[aliasKey]; !taken {
		cg.Functions[aliasKey] = funcDef
	}
	cg.AmbiguousFuncs[underKey] = append(cg.AmbiguousFuncs[underKey], aliasKey)
}

// addTopLevelNode gives the file's load-time code a node in the call graph.
//
// PHP has no main(): every statement outside a function body runs when the file
// is included or requested directly. That is where WordPress plugins bootstrap
// -- instantiate the plugin object, call its init, register everything -- and
// the graph had no node for it at all. So an include edge could only ever
// produce file-level evidence, and a `direct` endpoint, whose callback IS a
// file, resolved to nothing: 618 such endpoints across 77 of 143 corpus trees,
// every one of them at level unauthenticated, contributing nothing to the
// minimum privilege a function requires. Measured on three trees, 6 of 6, 2 of
// 2 and 14 of 14 direct endpoints had a provably empty transitive call set.
//
// The body is the file with every declaration blanked out. Blanking must start
// at the DECLARATION HEAD and not at the body brace: leaving `function foo(` in
// place makes the declaration head itself read as a call, which inflates the
// extracted set roughly threefold.
//
// The node is keyed by file path only. A basename key would be wrong: 164 of
// the 618 direct-endpoint files, in 43 of 143 trees, share a basename with
// another file in the same tree, and a first-writer map would then hand the
// walk a different file's bootstrap.
func (cg *PluginCallGraph) addTopLevelNode(content, filePath string, decls []FuncDecl, p *fileParse) {
	loadTime := topLevelSource(content, decls)
	if strings.TrimSpace(loadTime) == "" {
		return
	}
	calls := cg.extractCalls(loadTime, callSite{aliases: p.aliases})
	if len(calls) == 0 {
		return
	}

	def := &FunctionDef{
		Name:      topLevelName,
		FilePath:  filePath,
		StartLine: 1,
		EndLine:   countNewlines(content),
	}

	cg.mu.Lock()
	defer cg.mu.Unlock()
	for _, key := range topLevelKeys(filePath) {
		if _, taken := cg.CallsFrom[key]; taken {
			continue
		}
		cg.CallsFrom[key] = calls
		cg.Functions[key] = def
	}
	for _, callee := range calls {
		cg.CallsTo[callee] = append(cg.CallsTo[callee], filePath)
	}
}

// topLevelName is the synthetic name a file's load-time code is given.
const topLevelName = "__toplevel"

// topLevelKeys are the call-graph keys a file's load-time node answers to. The
// slash-normalised spelling is included because callers key their file maps by
// whatever their platform produced.
func topLevelKeys(filePath string) []string {
	slashed := filepath.ToSlash(filePath)
	if slashed == filePath {
		return []string{filePath}
	}
	return []string{filePath, slashed}
}

// topLevelSource returns the file with every function declaration removed, head
// included, leaving only the code that runs when the file is loaded.
//
// Removing must start at the DECLARATION HEAD and not at the body brace:
// leaving `function foo(` behind makes the declaration head itself read as a
// call, which inflates the extracted set roughly threefold.
//
// The remaining fragments are joined rather than blanked in place. Blanking
// keeps the file's original length, so every pattern then scans megabytes of
// spaces; joining scans only the load-time text, which is a small fraction of a
// typical plugin file. A newline between fragments keeps two of them from
// running together into a token that appears in neither.
func topLevelSource(content string, decls []FuncDecl) string {
	if len(decls) == 0 {
		return content
	}
	var b strings.Builder
	prev := 0
	for _, d := range decls {
		start, end := d.DeclStart, d.BodyClose
		if start < prev || end > len(content) || start >= end {
			continue
		}
		b.WriteString(content[prev:start])
		b.WriteByte('\n')
		prev = end
	}
	if prev < len(content) {
		b.WriteString(content[prev:])
	}
	return b.String()
}

// linkTopLevelIncludes joins each file's load-time node to the load-time node
// of every file it includes.
//
// followIncludes already propagates FILES along these edges. This gives the
// same edges a function-level twin, so a chain that runs through a bootstrap
// file -- `require_once __DIR__.'/lib.php'; boot();` -- is a chain the callee
// walk can follow rather than a fact only the file walk knows.
func (cg *PluginCallGraph) linkTopLevelIncludes(sortedPaths []string) {
	cg.mu.Lock()
	defer cg.mu.Unlock()

	for _, fp := range sortedPaths {
		includes := cg.IncludesFrom[fp]
		if len(includes) == 0 {
			continue
		}
		key := fp
		existing, ok := cg.CallsFrom[key]
		if !ok {
			// A file whose load-time code calls nothing still includes other
			// files, and what those files load at their own scope runs.
			cg.Functions[key] = &FunctionDef{Name: topLevelName, FilePath: fp, StartLine: 1}
		}
		seen := make(map[string]bool, len(existing))
		for _, c := range existing {
			seen[c] = true
		}
		added := existing
		for _, inc := range includes {
			target := cg.resolveIncludePathLocked(inc)
			if target == "" || target == fp || seen[target] {
				continue
			}
			seen[target] = true
			added = append(added, target)
			cg.CallsTo[target] = append(cg.CallsTo[target], key)
		}
		if len(added) == len(existing) {
			continue
		}
		sort.Strings(added)
		for _, k := range topLevelKeys(fp) {
			cg.CallsFrom[k] = added
		}
	}
}

// findClassRanges finds the start and end positions of all types in content.
func findClassRanges(content string) map[string][2]int {
	infos := findClassInfos(content)
	ranges := make(map[string][2]int, len(infos))
	for name := range infos {
		ci := infos[name]
		ranges[name] = [2]int{ci.Open, ci.Close}
	}
	return ranges
}

// findMatchingBrace finds the position of the closing brace matching the one at pos
func findMatchingBrace(content string, pos int) int {
	if pos >= len(content) || content[pos] != '{' {
		return -1
	}

	depth := 1
	inString := false
	stringChar := byte(0)
	inComment := false
	inLineComment := false

	for i := pos + 1; i < len(content); i++ {
		c := content[i]

		// Handle line comments
		if inLineComment {
			if c == '\n' {
				inLineComment = false
			}
			continue
		}

		// Handle multi-line comments
		if inComment {
			if c == '*' && i+1 < len(content) && content[i+1] == '/' {
				inComment = false
				i++
			}
			continue
		}

		// Check for comment start
		if !inString && c == '/' && i+1 < len(content) {
			if content[i+1] == '/' {
				inLineComment = true
				continue
			}
			if content[i+1] == '*' {
				inComment = true
				continue
			}
		}

		// Handle strings
		if !inString {
			if c == '"' || c == '\'' {
				inString = true
				stringChar = c
				continue
			}
		} else {
			if c == '\\' && i+1 < len(content) {
				i++ // Skip escaped character
				continue
			}
			if c == stringChar {
				inString = false
			}
			continue
		}

		// Count braces
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}

	return -1
}

// countNewlines counts the number of newlines in a string
func countNewlines(s string) int {
	return strings.Count(s, "\n") + 1
}

// callSite is what the language knows about the place a body was written: the
// type that lexically encloses it, and the file-scoped `use ... as ...` renames
// in effect there.
//
// PHP resolves a method call against the receiver, not against a global name
// table. `$this->m()` inside class C calls the m that C resolves through its
// own declaration, then its traits, then its parent; `self::m()` calls C's m;
// `parent::m()` calls the m of C's declared parent. extractCalls had this
// information available at the moment it ran -- discoverFunctionsAndCalls
// computes the enclosing class before calling it -- and simply did not receive
// it, so 214,687 intra-class dispatch sites across 140 of 143 corpus trees
// emitted a bare name and resolved to whichever declaration sorted first.
type callSite struct {
	class   *classInfo
	aliases map[string]string
}

// extractCalls extracts all function/method calls from a code block.
//
// A receiver-qualified token is emitted IN ADDITION to the bare one, never
// instead of it. Two reasons, both measured. A bare name is the only spelling
// some consumers have -- 18 of 43 exactly-correct benchmark answers rest on
// evidence that is entirely unqualified tokens -- and `$this->m()` is LATE
// bound in PHP: the runtime object may be a subclass whose override the
// enclosing class's resolution order never reaches, so dropping the bare token
// would make a genuinely reachable override unreachable.
func (cg *PluginCallGraph) extractCalls(code string, site callSite) []string {
	calls := make(map[string]bool)
	enclosing := ""
	if site.class != nil {
		enclosing = site.class.Name
	}

	// alias records the token and, when its leading name was renamed by a
	// file-scoped `use X as Y`, the same token under the imported name. Both
	// are emitted: PHP scopes the alias to this file, and the call graph's keys
	// carry no file, so rewriting instead of adding would break every OTHER
	// file that names the same identifier without the import.
	add := func(token string) {
		calls[token] = true
		if len(site.aliases) == 0 {
			return
		}
		head, rest := token, ""
		if i := strings.Index(token, "::"); i > 0 {
			head, rest = token[:i], token[i:]
		}
		if target, ok := site.aliases[head]; ok {
			calls[target+rest] = true
		}
	}

	// Extract direct function calls
	matches := directCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			name := match[1]
			// A PHP magic method is never a free function: the language invokes
			// it through an object or through `parent::`. The bare token this
			// pattern produces for `parent::__construct(` therefore names no
			// one function, and following it reaches an arbitrary unrelated
			// constructor. The receiver-qualified token carries the real edge.
			if phpMagicMethods[name] {
				continue
			}
			// A WordPress core name is skipped because there is nothing to
			// recurse into -- unless the plugin declares a function of that
			// name itself, in which case the call site is the only edge to it.
			if !phpKeywords[name] && (!wpCoreFunctions[name] || cg.DeclaredNames[name]) {
				add(name)
			}
		}
	}

	// Extract $this->method() calls
	matches = thisMethodCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			calls["$this->"+match[1]] = true
			if enclosing != "" {
				calls[enclosing+"::"+match[1]] = true
			}
		}
	}

	// Extract other method calls $var->method()
	matches = methodCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			calls["->"+match[1]] = true
		}
	}

	// Extract static calls Class::method()
	matches = staticCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 2 {
			recv, method := match[1], match[2]
			add(recv + "::" + method)
			switch recv {
			case "self", "static":
				// self:: is the enclosing class; static:: is that class or a
				// subclass of it, so the enclosing class's resolution is a
				// sound starting point and the bare token covers the rest.
				if enclosing != "" {
					calls[enclosing+"::"+method] = true
				}
			case "parent":
				// parent:: was unresolvable in principle: the extends clause
				// had no capture group, so no parent name existed anywhere in
				// the graph. 8,330 parent:: call sites across 120 of 143 trees.
				if site.class != nil && site.class.Parent != "" {
					calls[site.class.Parent+"::"+method] = true
				}
			}
		}
	}

	// Instantiation calls the constructor. `new Klass(...)` invokes
	// Klass::__construct unconditionally -- that is the language, not a
	// heuristic -- and WordPress plugins do their entire wiring in
	// constructors. 29,955 `new` sites across 141 of 143 trees name a class
	// that declares __construct in the same tree, and every one of those edges
	// was missing.
	for _, match := range findAllIfPresent(newInstancePattern, code, "new") {
		name := lastNameSegment(match[1])
		switch strings.ToLower(name) {
		case "class":
			// `new class { ... }` is an anonymous class: it names no type.
			continue
		case "self", "static":
			name = enclosing
		case "parent":
			if site.class != nil {
				name = site.class.Parent
			} else {
				name = ""
			}
		}
		if name == "" {
			continue
		}
		// The bare class token is what collectReachableFiles maps through
		// ClassToFile, and the paren-less spelling never produced one.
		add(name)
		add(name + "::__construct")
	}

	// A method named by a variable: $this->$m(), $this->{$m}(), and
	// call_user_func(array($this, $m)). The receiver is not unknown -- $this is
	// an instance of the enclosing class -- so the target is one of that
	// class's methods. Enumerating them is an exact over-approximation of an
	// enumerable set, bounded by one class, rather than a guess about what the
	// variable holds.
	if enclosing != "" && strings.Contains(code, "$this") {
		if thisVarMethodPattern.MatchString(code) {
			cg.addClassMethodTokens(enclosing, "", calls)
		}
		for _, match := range callUserFuncThisVarPattern.FindAllStringSubmatch(code, -1) {
			// A literal prefix bounds the set further: PHP string
			// concatenation is prefix-preserving, so 'action' . $x can only
			// name a method whose name starts with "action".
			cg.addClassMethodTokens(enclosing, match[1], calls)
		}
	}

	// A class named by a variable. PHP string concatenation is
	// prefix-preserving: `"WPJP" . $x . "Controller"` can only ever produce a
	// name beginning "WPJP" and ending "Controller", so the set of types it can
	// name is bounded by the literal parts written at that very site.
	cg.addVariableClassTokens(code, calls)

	// Extract call_user_func callbacks
	matches = findAllIfPresent(callUserFuncPattern, code, "call_user_func")
	for _, match := range matches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				add(match[i])
				break
			}
		}
	}

	// Resolve do_action/apply_filters through hook registry
	if cg.HookRegistry != nil && firesAHook(code) {
		hookMatches := wpHookCallPattern.FindAllStringSubmatch(code, -1)
		for _, match := range hookMatches {
			if len(match) > 1 {
				hookName := match[1]

				cg.HookRegistry.mu.RLock()
				if regs, ok := cg.HookRegistry.Hooks[hookName]; ok {
					for _, reg := range regs {
						calls[reg.Callback] = true
					}
				}
				for prefix, regs := range cg.HookRegistry.PrefixHooks {
					if strings.HasPrefix(hookName, prefix) {
						for _, reg := range regs {
							calls[reg.Callback] = true
						}
					}
				}
				cg.HookRegistry.mu.RUnlock()
			}
		}

		// A hook name composed at the call site names a family of hooks rather
		// than one. Link it to every registration in that family.
		for _, pat := range [2]*regexp.Regexp{wpHookCallConcatPrefixPattern, wpHookCallInterpPrefixPattern} {
			for _, match := range pat.FindAllStringSubmatch(code, -1) {
				if len(match) > 1 {
					cg.addHookFamilyCalls(match[1], true, calls)
				}
			}
		}
		for _, pat := range [2]*regexp.Regexp{wpHookCallConcatSuffixPattern, wpHookCallInterpSuffixPattern} {
			for _, match := range pat.FindAllStringSubmatch(code, -1) {
				if len(match) > 1 {
					cg.addHookFamilyCalls(match[1], false, calls)
				}
			}
		}
	}

	// Convert to sorted slice for deterministic order
	result := make([]string, 0, len(calls))
	for call := range calls {
		result = append(result, call)
	}
	sort.Strings(result)

	return result
}

// nameShape is what a call site tells us about a class name it does not spell
// out: either the exact name, or the literal prefix and suffix that every value
// the expression can produce must carry.
type nameShape struct {
	Exact, Prefix, Suffix string
}

// addVariableClassTokens links `new $v(...)` and `$v::m(...)` to the types the
// variable can name, when the variable was assigned a string with literal parts
// in the same body.
//
// The bound is the literal, and the literal is read out of the call site's own
// source -- never from a table of known prefixes, which would stop the rule
// being universal.
//
// Matching is against the UNQUALIFIED type name, and a literal whose final
// segment is a namespace separator constrains that name not at all: for
// `'\Vendor\Pack\' . $x` the prefix contributes nothing, and matching it
// against every type in the plugin would connect one call site to all of them.
// Such a site is treated as unbounded and contributes nothing.
func (cg *PluginCallGraph) addVariableClassTokens(code string, calls map[string]bool) {
	newSites := findAllIfPresent(newVarPattern, code, "new $")
	varStatic := findAllIfPresent(varStaticCallPattern, code, "::")
	if len(newSites) == 0 && len(varStatic) == 0 {
		return
	}

	shapes := map[string]nameShape{}
	for _, m := range varAssignPattern.FindAllStringSubmatch(code, -1) {
		if s, ok := shapeOfExpression(m[2]); ok {
			// A variable reassigned in the same body could hold either value,
			// so the widest shape is kept: an exact name loses to a pattern.
			if prev, seen := shapes[m[1]]; seen && prev.Exact != "" && s.Exact == "" {
				shapes[m[1]] = s
			} else if !seen {
				shapes[m[1]] = s
			}
		}
	}
	if len(shapes) == 0 {
		return
	}

	emit := func(varName, method string) {
		s, ok := shapes[varName]
		if !ok {
			return
		}
		for _, cls := range cg.typesMatching(s) {
			calls[cls] = true
			calls[cls+"::"+method] = true
		}
	}
	for _, m := range newSites {
		emit(m[1], "__construct")
	}
	for _, m := range varStatic {
		emit(m[1], m[2])
	}
}

// shapeOfExpression reads what a right-hand side guarantees about the string it
// produces. It reports false when the expression guarantees nothing.
func shapeOfExpression(expr string) (nameShape, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || strings.ContainsAny(expr, "()[]") {
		// A call or a subscript can return anything.
		return nameShape{}, false
	}
	folded := foldStringConcat(expr)
	if isQuotedLiteral(folded) {
		name := lastNameSegment(strings.Trim(folded, "'\""))
		if name == "" {
			return nameShape{}, false
		}
		return nameShape{Exact: name}, true
	}
	if !strings.Contains(expr, "$") || !strings.Contains(expr, ".") {
		return nameShape{}, false
	}

	var s nameShape
	if lit, ok := leadingLiteral(expr); ok {
		// Only what follows the last namespace separator constrains the
		// unqualified name.
		s.Prefix = lastNameSegment(lit)
	}
	if lit, ok := trailingLiteral(expr); ok && !strings.Contains(lit, "\\") {
		s.Suffix = lit
	}
	if len(s.Prefix) < 3 && len(s.Suffix) < 3 {
		// One or two characters identify nothing; a site bounded only that
		// loosely would match most of a plugin.
		return nameShape{}, false
	}
	return s, true
}

func isQuotedLiteral(s string) bool {
	if len(s) < 2 {
		return false
	}
	q := s[0]
	return (q == '\'' || q == '"') && s[len(s)-1] == q &&
		strings.IndexByte(s[1:len(s)-1], q) < 0
}

// leadingLiteral returns the literal a concatenation starts with.
func leadingLiteral(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if len(expr) == 0 || (expr[0] != '\'' && expr[0] != '"') {
		return "", false
	}
	end := skipString(expr, 0)
	if end <= 0 {
		return "", false
	}
	return expr[1:end], true
}

// trailingLiteral returns the literal a concatenation ends with.
func trailingLiteral(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if len(expr) == 0 {
		return "", false
	}
	q := expr[len(expr)-1]
	if q != '\'' && q != '"' {
		return "", false
	}
	for i := len(expr) - 2; i >= 0; i-- {
		if expr[i] == q && (i == 0 || expr[i-1] != '\\') {
			return expr[i+1 : len(expr)-1], true
		}
	}
	return "", false
}

// typesMatching returns the declared types a name shape can denote. PHP type
// names are case-insensitive, so the comparison folds case.
func (cg *PluginCallGraph) typesMatching(s nameShape) []string {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	if s.Exact != "" {
		if name := cg.foldTypeLocked(s.Exact); name != "" {
			return []string{name}
		}
		return nil
	}
	prefix, suffix := strings.ToLower(s.Prefix), strings.ToLower(s.Suffix)
	var out []string
	for name := range cg.Types {
		l := strings.ToLower(name)
		if len(l) < len(prefix)+len(suffix) {
			continue
		}
		if strings.HasPrefix(l, prefix) && strings.HasSuffix(l, suffix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// findAllIfPresent runs a pattern only when a literal substring the pattern
// requires is present.
//
// A regexp engine with no literal prefix has to walk every byte; a substring
// scan does not. The call graph runs a dozen patterns over every function body
// in a plugin, and most bodies contain none of the constructs most of them look
// for.
func findAllIfPresent(pat *regexp.Regexp, code, must string) [][]string {
	if !strings.Contains(code, must) {
		return nil
	}
	return pat.FindAllStringSubmatch(code, -1)
}

// firesAHook reports whether code contains any hook firing at all.
func firesAHook(code string) bool {
	return strings.Contains(code, "do_action") || strings.Contains(code, "apply_filters")
}

// addClassMethodTokens emits one Class::method token for each method the class
// declares -- through its traits and ancestors as well, which is the set PHP
// itself would dispatch over -- optionally restricted to a literal prefix.
//
// The bound is one class's method list, so this cannot become the "matches
// everything" rule: it links a call site to the methods of the receiver, which
// is exactly what the language says the target must be.
func (cg *PluginCallGraph) addClassMethodTokens(class, prefix string, calls map[string]bool) {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	seen := make(map[string]bool, 4)
	for name := cg.foldTypeLocked(class); name != "" && !seen[name]; {
		seen[name] = true
		td := cg.Types[name]
		if td == nil {
			return
		}
		for _, m := range td.Methods {
			if prefix == "" || strings.HasPrefix(m, prefix) {
				calls[name+"::"+m] = true
			}
		}
		for _, t := range td.Traits {
			tn := cg.foldTypeLocked(t)
			if tn == "" || seen[tn] {
				continue
			}
			seen[tn] = true
			if tt := cg.Types[tn]; tt != nil {
				for _, m := range tt.Methods {
					if prefix == "" || strings.HasPrefix(m, prefix) {
						calls[tn+"::"+m] = true
					}
				}
			}
		}
		name = cg.foldTypeLocked(td.Parent)
	}
}

// foldTypeLocked maps a type name to the spelling the graph indexed it under.
// PHP type names are case-insensitive while the graph preserves the source's
// case, so `extends WPForms_Field` must find a declaration of `WPForms_field`.
// Caller must hold cg.mu.
func (cg *PluginCallGraph) foldTypeLocked(name string) string {
	if name == "" {
		return ""
	}
	if _, ok := cg.Types[name]; ok {
		return name
	}
	return cg.typeFold[strings.ToLower(name)]
}

// usableHookFragment decides whether a literal fragment of a composed hook name
// is specific enough to match on.
//
// WordPress composes dynamic hook names as a subsystem name plus a selector:
// "save_post_{$post_type}", "form_wrap_process_" . $formType,
// "{$adapter}_response". The literal half is what identifies the family. A
// fragment of one or two characters identifies nothing and would join a call
// site to most of the registry, so the fragment must be at least four
// characters and must either stop on a word boundary -- which is where a
// composed name joins -- or be long enough that a coincidental match is
// unlikely on its own.
func usableHookFragment(frag string) bool {
	if len(frag) < 4 {
		return false
	}
	switch frag[len(frag)-1] {
	case '_', '-', '/':
		return true
	}
	switch frag[0] {
	case '_', '-', '/':
		return true
	}
	return len(frag) >= 8
}

// addHookFamilyCalls links a composed hook name to every callback registered
// under a name in the same family. atStart selects prefix composition
// ("family_" . $x) from suffix composition ($x . "_family").
func (cg *PluginCallGraph) addHookFamilyCalls(frag string, atStart bool, calls map[string]bool) {
	if !usableHookFragment(frag) {
		return
	}
	match := func(hook string) bool {
		if atStart {
			return len(hook) > len(frag) && strings.HasPrefix(hook, frag)
		}
		return len(hook) > len(frag) && strings.HasSuffix(hook, frag)
	}

	cg.HookRegistry.mu.RLock()
	defer cg.HookRegistry.mu.RUnlock()

	for hook, regs := range cg.HookRegistry.Hooks {
		if match(hook) {
			for _, reg := range regs {
				calls[reg.Callback] = true
			}
		}
	}
	// A registration whose own name was composed is stored by its literal
	// prefix. Two composed names belong to the same family when either literal
	// extends the other: "wpforms_process_" . $x registers under the prefix
	// "wpforms_process_", and a call site saying "wpforms_" . $y reaches it.
	if atStart {
		for prefix, regs := range cg.HookRegistry.PrefixHooks {
			if strings.HasPrefix(prefix, frag) || strings.HasPrefix(frag, prefix) {
				for _, reg := range regs {
					calls[reg.Callback] = true
				}
			}
		}
	}
}

// GetCallees returns all functions called by the given callback, recursively
func (cg *PluginCallGraph) GetCallees(callback string) []string {
	visited := make(map[string]bool)
	result := make([]string, 0)

	cg.getCalleesRecursive(callback, visited, &result)

	return result
}

// getCalleesRecursive is the recursive helper for GetCallees
func (cg *PluginCallGraph) getCalleesRecursive(funcName string, visited map[string]bool, result *[]string) {
	if visited[funcName] {
		return
	}
	visited[funcName] = true

	cg.mu.RLock()
	calls, ok := cg.CallsFrom[funcName]
	cg.mu.RUnlock()

	if !ok {
		return
	}

	for _, callee := range calls {
		*result = append(*result, callee)
		cg.getCalleesRecursive(callee, visited, result)
	}
}

// outgoingCalls resolves one call-graph name to the edges leaving it.
//
// A call site and a declaration rarely agree on spelling. extractCalls strips
// the class prefix from most call sites, so a call to $this->save() is recorded
// as "save" while the declaration is keyed "Customer::save"; namespaced code
// adds a third spelling. Looking up only the name as written finds nothing and
// ends the walk.
//
// This is the same resolution collectReachableFiles has always performed for
// the FILE walk (see the AmbiguousFuncs handling there). Having it in one place
// keeps the two walks from disagreeing about what is reachable, which they did:
// entries existed where forty-five endpoints reached a file and none reached
// any function in it.
//
// aliases are the qualified keys a bare name may denote. They are returned
// separately because they are reachable functions in their own right and belong
// in the callee set, not merely as a route to further edges.
// phpMagicMethods are names the language itself defines. They carry no identity:
// every class may declare __construct, and a plugin has hundreds. Merging every
// same-named body for one of these turns a single token into a broadcast --
// measured at 496 distinct names, 37% of the plugin, reached from the bare
// `__construct` key of one 1,323-function tree.
var phpMagicMethods = map[string]bool{
	"__construct": true, "__destruct": true, "__call": true, "__callStatic": true,
	"__get": true, "__set": true, "__isset": true, "__unset": true,
	"__sleep": true, "__wakeup": true, "__serialize": true, "__unserialize": true,
	"__toString": true, "__invoke": true, "__set_state": true, "__clone": true,
	"__debugInfo": true,
}

func (cg *PluginCallGraph) outgoingCalls(name string) (calls []string, aliases []string) {
	if name == "" {
		return nil, nil
	}

	cg.mu.RLock()
	defer cg.mu.RUnlock()

	seenCall := make(map[string]bool)
	addCalls := func(cs []string) {
		for _, c := range cs {
			if !seenCall[c] {
				seenCall[c] = true
				calls = append(calls, c)
			}
		}
	}
	seenAlias := make(map[string]bool)
	addAliases := func(key string) {
		for _, qual := range cg.AmbiguousFuncs[key] {
			if seenAlias[qual] {
				continue
			}
			seenAlias[qual] = true
			aliases = append(aliases, qual)
			if cs, ok := cg.CallsFrom[qual]; ok {
				addCalls(cs)
			}
		}
	}

	// A file's load-time node is keyed by path. Paths carry both separators and
	// must not be split on "\" as a namespace would be.
	if isFileKey(name) {
		if cs, ok := cg.CallsFrom[name]; ok {
			addCalls(cs)
		} else if cs, ok := cg.CallsFrom[filepath.ToSlash(name)]; ok {
			addCalls(cs)
		}
		return calls, aliases
	}

	bare := name
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		bare = name[i+1:]
	}
	method := bare
	receiver := ""
	if i := strings.LastIndex(bare, "::"); i >= 0 {
		receiver, method = bare[:i], bare[i+2:]
	} else {
		// A "$this->m" or "->m" token names a method with the receiver spelled
		// out. Stripping the receiver is the same normalisation "::" already
		// gets, and without it the token resolves to nothing at all -- which is
		// the only edge a method whose name collides with a WordPress core
		// function has, at 2,943 call sites across 74 of 143 corpus trees.
		method = strings.TrimPrefix(strings.TrimPrefix(method, "$this"), "->")
	}

	// A token that names a receiver PHP binds is resolved against that
	// receiver, and the same-name merge below is NOT applied to it. Without
	// this gate the merge fires precisely where the language is exact: 30.1% of
	// $this->m() sites name a method two or more classes declare, and 61.8% of
	// those declare it in the enclosing class, so unioning would enter every
	// other class's body for a call PHP resolves in one step.
	if receiver != "" && receiver != "self" && receiver != "static" && receiver != "parent" {
		if key := cg.resolveMethodKeyLocked(receiver, method); key != "" {
			if cs, ok := cg.CallsFrom[key]; ok {
				addCalls(cs)
			}
			addAliases(key)
			return calls, aliases
		}
		// A constructor edge is exact or it is nothing. Falling back to the
		// bare `__construct` key would hand every `new` in the plugin one
		// arbitrary constructor, and under the same-name merge, all of them.
		if phpMagicMethods[method] {
			return calls, aliases
		}
	}

	for _, key := range [3]string{name, bare, method} {
		if key == "" {
			continue
		}
		if cs, ok := cg.CallsFrom[key]; ok {
			addCalls(cs)
		}
		if key == method && phpMagicMethods[method] {
			// The bare magic name is a valid key but names no one function.
			continue
		}
		addAliases(key)
	}
	return calls, aliases
}

// isFileKey reports whether a call-graph name is a file path rather than a
// function name. PHP identifiers contain neither "/" nor ".".
func isFileKey(name string) bool {
	// A file-qualified alias such as "src/Repo.php::save" carries both a path
	// and a function, and it is the function that must be resolved.
	if strings.Contains(name, "::") {
		return false
	}
	if strings.IndexByte(name, '/') >= 0 {
		return true
	}
	if len(name) < 4 {
		return false
	}
	tail := name[len(name)-4:]
	return tail[0] == '.' &&
		(tail[1] == 'p' || tail[1] == 'P') &&
		(tail[2] == 'h' || tail[2] == 'H') &&
		(tail[3] == 'p' || tail[3] == 'P')
}

// resolveMethodKeyLocked returns the CallsFrom key that Class::method denotes,
// following PHP's method resolution order: the class's own declaration, then
// each trait it uses in declaration order, then its parent, recursively.
//
// This is the ordering pkg/ast/inheritance.go already implements for the
// tree-sitter path; it is copied rather than re-derived. The walk folds case
// because PHP type names are case-insensitive, and it carries a visited set
// because `class A extends B` / `class B extends A` occurs in broken vendor
// trees. Caller must hold cg.mu.
func (cg *PluginCallGraph) resolveMethodKeyLocked(class, method string) string {
	// The overwhelmingly common case is a class that declares the method
	// itself, so that lookup is tried before anything is allocated.
	if _, ok := cg.CallsFrom[class+"::"+method]; ok {
		return class + "::" + method
	}
	name := cg.foldTypeLocked(class)
	if name == "" {
		return ""
	}
	var seen []string
	visited := func(n string) bool {
		for _, s := range seen {
			if s == n {
				return true
			}
		}
		// A cycle guard is needed because `class A extends B` /
		// `class B extends A` occurs in broken vendor trees.
		seen = append(seen, n)
		return false
	}
	for name != "" && !visited(name) {
		if _, ok := cg.CallsFrom[name+"::"+method]; ok {
			return name + "::" + method
		}
		td := cg.Types[name]
		if td == nil {
			return ""
		}
		for _, t := range td.Traits {
			tn := cg.foldTypeLocked(t)
			if tn == "" || visited(tn) {
				continue
			}
			if _, ok := cg.CallsFrom[tn+"::"+method]; ok {
				return tn + "::" + method
			}
		}
		name = cg.foldTypeLocked(td.Parent)
	}
	return ""
}

// GetCallers returns all functions that call the given callback
func (cg *PluginCallGraph) GetCallers(callback string) []string {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	callers, ok := cg.CallsTo[callback]
	if !ok {
		return nil
	}

	// Return a copy
	result := make([]string, len(callers))
	copy(result, callers)
	return result
}

// AnalyzeCallback analyzes a callback function and returns its call graph
func (cg *PluginCallGraph) AnalyzeCallback(callback string) *CallGraph {
	callees := cg.GetCallees(callback)
	callers := cg.GetCallers(callback)

	return &CallGraph{
		Callees: callees,
		Callers: callers,
	}
}

// ExtractFunctionCalls extracts function calls from a single code snippet
// This is a simpler version for quick analysis without building a full call graph
func ExtractFunctionCalls(code string) []string {
	calls := make(map[string]bool)

	// Remove comments first
	code = StripPHPComments(code)

	// Extract direct function calls
	matches := directCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			name := match[1]
			if !phpKeywords[name] {
				calls[name] = true
			}
		}
	}

	// Extract $this->method() calls
	matches = thisMethodCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 1 {
			calls[match[1]] = true
		}
	}

	// Extract static calls
	matches = staticCallPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) > 2 {
			calls[match[2]] = true
		}
	}

	// Convert to sorted slice for deterministic order
	result := make([]string, 0, len(calls))
	for call := range calls {
		result = append(result, call)
	}
	sort.Strings(result)

	return result
}

// ResolveCallback attempts to resolve a callback string to its actual function
// Handles cases like:
// - "function_name" -> function_name
// - "ClassName::method" -> ClassName::method
// - "$this->method" -> looks up in current class context
// - "array($this, 'method')" -> extracts method name
// Memory-optimized: uses pre-compiled patterns
func ResolveCallback(callback, currentClass string) string {
	callback = strings.TrimSpace(callback)

	// Already a clean function name
	if cleanFunctionNamePattern.MatchString(callback) {
		return callback
	}

	// Static method call ClassName::method
	if strings.Contains(callback, "::") {
		return callback
	}

	// $this->method
	if strings.HasPrefix(callback, "$this->") {
		method := strings.TrimPrefix(callback, "$this->")
		if currentClass != "" {
			return currentClass + "::" + method
		}
		return method
	}

	// Array callback extraction
	if strings.Contains(callback, "[") || strings.Contains(callback, "array(") {
		// Extract method name from array callback
		methodMatch := arrayMethodNamePattern.FindStringSubmatch(callback)
		if len(methodMatch) > 1 {
			return methodMatch[1]
		}
	}

	return callback
}

// AnalyzeCallbackInFile analyzes a callback function within a single file
// This is a lightweight analysis that finds the callback's function body and extracts its calls
// Returns the list of functions called by the callback (first level only for performance)
func AnalyzeCallbackInFile(fileContent, callback string) []string {
	if callback == "" || callback == "unknown" || callback == "inline" || callback == "closure" {
		return nil
	}

	// Clean up the callback name
	callback = ResolveCallback(callback, "")

	// Skip if callback looks like a variable or expression
	if strings.HasPrefix(callback, "$") || strings.Contains(callback, "(") {
		return nil
	}

	// Find the function body in the file
	body := lookupFunctionBody(fileContent, callback)
	if body == "" {
		return nil
	}

	// Extract function calls from the body
	return ExtractFunctionCalls(body)
}

// lookupFunctionBody locates a function/method by name and returns its body.
//
// The search used to be a literal scan for "function "+name, which missed
// `function &name(` -- 50 sites across 19 of 143 corpus trees -- and
// `function  name(` with more than one space, 68 sites across 28 trees, and
// took the first textual hit even when the file declares two classes with a
// same-named method. FindFunctionDeclarations answers all three, and it is the
// same parse the graph itself is built from, so the two cannot disagree.
//
// When the name is qualified, a declaration inside the named class is preferred
// over one merely sharing the method name.
func lookupFunctionBody(content, funcName string) string {
	methodOnly := funcName
	className := ""
	if idx := strings.LastIndex(funcName, "::"); idx >= 0 {
		className, methodOnly = funcName[:idx], funcName[idx+2:]
	}

	decls := declarationsNamed(content, methodOnly)
	if len(decls) == 0 {
		return ""
	}
	if len(decls) > 1 && className != "" {
		// Only when the file declares the name more than once does it matter
		// which class the declaration belongs to, and only then is the cost of
		// finding the class ranges worth paying.
		if ci, ok := findClassInfos(content)[className]; ok {
			for i := range decls {
				if decls[i].DeclStart > ci.Open && decls[i].DeclStart < ci.Close {
					return content[decls[i].BodyOpen:decls[i].BodyClose]
				}
			}
		}
	}
	return content[decls[0].BodyOpen:decls[0].BodyClose]
}

// declarationsNamed finds every declaration of one function name in content.
//
// Scanning for the name and verifying backwards is what keeps this cheap: a
// full FindFunctionDeclarations parse of the endpoint's file, run once per
// endpoint, dominated the whole analysis on a plugin with many endpoints in one
// file. Verifying backwards still accepts the spellings a literal
// "function "+name search rejects -- `function &name(` and `function  name(`.
func declarationsNamed(content, name string) []FuncDecl {
	if name == "" {
		return nil
	}
	var out []FuncDecl
	for from := 0; ; {
		idx := strings.Index(content[from:], name)
		if idx < 0 {
			return out
		}
		pos := from + idx
		from = pos + len(name)

		// The match must be a whole identifier.
		if pos > 0 && isTypeChar(content[pos-1]) {
			continue
		}
		after := skipSpace(content, pos+len(name))
		if after >= len(content) || content[after] != '(' {
			continue
		}

		// Walk back over optional whitespace and a by-reference "&" to the
		// `function` keyword.
		i := pos
		for i > 0 && (content[i-1] == ' ' || content[i-1] == '\t' || content[i-1] == '\n' || content[i-1] == '\r') {
			i--
		}
		if i > 0 && content[i-1] == '&' {
			i--
			for i > 0 && (content[i-1] == ' ' || content[i-1] == '\t') {
				i--
			}
		}
		const kw = "function"
		if i < len(kw) || !strings.EqualFold(content[i-len(kw):i], kw) {
			continue
		}
		if i-len(kw) > 0 && isTypeChar(content[i-len(kw)-1]) {
			continue
		}

		parenClose := matchDelimiter(content, after, '(', ')')
		if parenClose < 0 {
			continue
		}
		j := skipSpace(content, parenClose+1)
		if j < len(content) && content[j] == ':' {
			j = skipSpace(content, j+1)
			for j < len(content) && (isTypeChar(content[j]) || content[j] == '|' || content[j] == '?' || content[j] == '\\') {
				j++
			}
			j = skipSpace(content, j)
		}
		if j >= len(content) || content[j] != '{' {
			// No body: an abstract method or an interface signature.
			continue
		}
		bodyClose := findMatchingBrace(content, j)
		if bodyClose < 0 {
			continue
		}
		out = append(out, FuncDecl{
			Name:      content[pos : pos+len(name)],
			NameStart: pos,
			DeclStart: i - len(kw),
			BodyOpen:  j,
			BodyClose: bodyClose,
		})
		from = bodyClose
	}
}

// EnrichEndpointsWithCallGraph adds function call information to endpoints
// This analyzes each endpoint's callback within the given file content (single-file, non-recursive)
func EnrichEndpointsWithCallGraph(endpoints []models.Endpoint, fileContent string) {
	for i := range endpoints {
		if endpoints[i].Callback == "" {
			continue
		}

		calls := AnalyzeCallbackInFile(fileContent, endpoints[i].Callback)
		if len(calls) > 0 {
			endpoints[i].FunctionCalls = calls
		}
	}
}

// EnrichEndpointsWithPluginCallGraph adds RECURSIVE function call information to endpoints
// This analyzes each endpoint's callback using the plugin-wide function index,
// following calls across ALL files in the plugin.
func EnrichEndpointsWithPluginCallGraph(endpoints []models.Endpoint, callGraph *PluginCallGraph, fileContent string) {
	if callGraph == nil {
		// Fall back to single-file analysis
		EnrichEndpointsWithCallGraph(endpoints, fileContent)
		return
	}

	for i := range endpoints {
		if endpoints[i].Callback == "" {
			continue
		}

		// Get recursive calls using the plugin-wide call graph. The endpoint's
		// own file is passed, because a callback that names a FILE rather than
		// a function can only be resolved with it.
		calls := GetRecursiveCallsForCallbackInFile(callGraph, endpoints[i].Callback, endpoints[i].File, fileContent)
		if len(calls) > 0 {
			endpoints[i].FunctionCalls = calls
		}
	}
}

// closureSeededCalls is the callee walk for an endpoint whose callback is
// anonymous.
//
// The seed is every call made by a closure in this file that was passed to a
// WordPress registration function; from there the walk proceeds through the
// graph exactly as it does for a named callback.
func (cg *PluginCallGraph) closureSeededCalls(fileContent string) []string {
	seeds := cg.registrationClosureCalls(fileContent)
	if len(seeds) == 0 {
		return nil
	}
	visited := make(map[string]bool)
	allCalls := make([]string, 0, len(seeds))
	for _, call := range seeds {
		if visited[call] {
			continue
		}
		visited[call] = true
		allCalls = append(allCalls, call)
		recurseCalls(cg, call, visited, &allCalls)
	}
	return allCalls
}

// GetRecursiveCallsForCallback gets all functions called by a callback recursively
// across the entire plugin codebase
// Memory-optimized: uses pre-computed CallsFrom map instead of re-parsing bodies
func GetRecursiveCallsForCallback(cg *PluginCallGraph, callback, fileContent string) []string {
	return GetRecursiveCallsForCallbackInFile(cg, callback, "", fileContent)
}

// GetRecursiveCallsForCallbackInFile is GetRecursiveCallsForCallback told which
// file the endpoint was found in.
//
// Some endpoints have no function for a callback at all. A `direct` endpoint is
// a .php file an unauthenticated caller can request, and its callback is the
// file's own name; a widget's is "Class::widget()", with the parentheses that
// the "looks like an expression" guard rejects. Both resolved to an empty call
// set for every plugin. The file path disambiguates the first, because 164 of
// the 618 direct-endpoint files in the corpus share a basename with another
// file in the same tree and a basename lookup would walk the wrong bootstrap.
func GetRecursiveCallsForCallbackInFile(cg *PluginCallGraph, callback, endpointFile, fileContent string) []string {
	if callback == "" || callback == "unknown" || callback == "inline" || callback == "closure" {
		// An anonymous callback has no name to look up, but it does have a
		// body, and that body is in the file this endpoint was found in.
		// Returning nil here meant that every route registered with an inline
		// function reached nothing at all -- the endpoint was reported and
		// everything behind it was invisible.
		return cg.closureSeededCalls(fileContent)
	}

	// Clean up the callback name
	callback = ResolveCallback(callback, "")

	// A callback written "Class::widget()" names a method, not an expression.
	// Trimming the empty argument list before the guard below is what lets a
	// widget endpoint resolve at all: 151 of them across 34 corpus trees, every
	// one with an empty call set.
	callback = strings.TrimSuffix(strings.TrimSpace(callback), "()")

	// A callback that names a FILE is the file's load-time code.
	if key := cg.topLevelKeyFor(callback, endpointFile); key != "" {
		return cg.walkFrom(key)
	}

	// Skip if callback looks like a variable or expression
	if strings.HasPrefix(callback, "$") || strings.Contains(callback, "(") {
		return nil
	}

	// Track visited functions to prevent infinite recursion
	visited := make(map[string]bool)
	allCalls := make([]string, 0)

	// First, try to find the callback body in the current file (for local methods like $this->method)
	body := lookupFunctionBody(fileContent, callback)

	// If we found the body in the current file, extract its immediate calls.
	//
	// The body alone is not enough. ExtractFunctionCalls is a package-level
	// function with no call graph, so it cannot resolve do_action('x') to the
	// callbacks registered for x -- cg.extractCalls does that, and its result
	// lives in CallsFrom. Taking only the body meant that for every endpoint
	// whose callback is declared in the file that registered it, which is the
	// ordinary case, every hook edge was discarded. WordPress control flow runs
	// through hooks, so that disconnected a large part of each plugin from its
	// own entry points.
	//
	// The two sources are complementary rather than alternative, so both are
	// used: the body is precise about this declaration, and the graph knows
	// about hooks and about names spelled differently at the call site.
	if body != "" {
		immediateCalls := ExtractFunctionCalls(body)
		graphCalls, graphAliases := cg.outgoingCalls(callback)
		immediateCalls = append(immediateCalls, graphAliases...)
		immediateCalls = append(immediateCalls, graphCalls...)
		for _, call := range immediateCalls {
			if !visited[call] {
				visited[call] = true
				allCalls = append(allCalls, call)
				// Recursively follow this call using the pre-computed call graph
				recurseCalls(cg, call, visited, &allCalls)
			}
		}
	} else {
		// Try to find in the plugin-wide index using pre-computed calls.
		calls, aliases := cg.outgoingCalls(callback)
		for _, alias := range aliases {
			if !visited[alias] {
				visited[alias] = true
				allCalls = append(allCalls, alias)
			}
		}
		for _, call := range calls {
			if !visited[call] {
				visited[call] = true
				allCalls = append(allCalls, call)
				// Recursively follow this call
				recurseCalls(cg, call, visited, &allCalls)
			}
		}
	}

	return allCalls
}

// topLevelKeyFor resolves a callback that names a file to that file's
// load-time call-graph key, or "" when the callback does not name a file.
//
// The endpoint's own file is preferred, because it is unambiguous. A bare
// basename is accepted only when exactly one file in the tree carries it --
// the same rule resolveIncludePath already applies -- so an ambiguous name
// resolves to nothing rather than to an arbitrary other file's bootstrap.
func (cg *PluginCallGraph) topLevelKeyFor(callback, endpointFile string) string {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	for _, cand := range [2]string{endpointFile, callback} {
		if cand == "" || !strings.HasSuffix(strings.ToLower(cand), ".php") {
			continue
		}
		if _, ok := cg.CallsFrom[cand]; ok {
			return cand
		}
		norm := filepath.ToSlash(cand)
		if _, ok := cg.CallsFrom[norm]; ok {
			return norm
		}
		if real, ok := cg.normFiles[norm]; ok {
			if _, ok := cg.CallsFrom[real]; ok {
				return real
			}
		}
		if paths := cg.FilesByBasename[filepath.Base(cand)]; len(paths) == 1 {
			if _, ok := cg.CallsFrom[paths[0]]; ok {
				return paths[0]
			}
		}
	}
	return ""
}

// walkFrom expands one call-graph key into its transitive callee set.
func (cg *PluginCallGraph) walkFrom(key string) []string {
	visited := map[string]bool{key: true}
	allCalls := make([]string, 0, 16)
	recurseCalls(cg, key, visited, &allCalls)
	return allCalls
}

// recurseCalls recursively follows function calls through the plugin-wide index
// Memory-optimized: uses pre-computed CallsFrom map instead of re-parsing bodies
func recurseCalls(cg *PluginCallGraph, funcName string, visited map[string]bool, allCalls *[]string) {
	// Don't recurse into PHP built-ins, or into WordPress core unless the
	// plugin declares a function of that name itself -- 730 such declarations
	// across 102 of 143 corpus trees, whose bodies are otherwise unreachable.
	if phpKeywords[funcName] || (wpCoreFunctions[funcName] && !cg.DeclaredNames[funcName]) {
		return
	}

	// Look up the pre-computed calls for this function. outgoingCalls also
	// maps a bare call name back to the qualified declarations that hold the
	// edges, which is what the file walk does and what this walk used to omit.
	calls, aliases := cg.outgoingCalls(funcName)

	// An alias is a real function that this name may denote, so it is part of
	// the callee set and not merely a route to further edges. Recording it is
	// what lets a caller ask "does this endpoint reach Customer::save" and get
	// an answer when the call site only ever said "save".
	for _, alias := range aliases {
		if !visited[alias] {
			visited[alias] = true
			*allCalls = append(*allCalls, alias)
		}
	}

	if len(calls) == 0 {
		// External function (WordPress core, PHP built-in, or not found in plugin)
		return
	}

	for _, call := range calls {
		if !visited[call] {
			visited[call] = true
			*allCalls = append(*allCalls, call)
			// Continue recursion
			recurseCalls(cg, call, visited, allCalls)
		}
	}
}

// BuildPluginCallGraphFromFiles builds a plugin-wide call graph from all PHP file contents
// This is used to enable cross-file recursive call analysis
func BuildPluginCallGraphFromFiles(files map[string]string) *PluginCallGraph {
	return BuildCallGraph(files)
}

// GetHierarchicalCallsForCallback returns a hierarchical tree of function calls
// instead of the flat list returned by GetRecursiveCallsForCallback.
// This is used when -chain-human or -chain-json flags are specified.
func GetHierarchicalCallsForCallback(cg *PluginCallGraph, callback, fileContent string) []*models.CallChainNode {
	if callback == "" || callback == "unknown" || callback == "inline" || callback == "closure" {
		return nil
	}

	// Clean up the callback name
	callback = ResolveCallback(callback, "")

	// Skip if callback looks like a variable or expression
	if strings.HasPrefix(callback, "$") || strings.Contains(callback, "(") {
		return nil
	}

	// Track visited functions to prevent infinite recursion
	// Using a map per recursive path to allow same function in different branches
	visited := make(map[string]bool)

	// First, try to find the callback body in the current file
	body := lookupFunctionBody(fileContent, callback)

	var immediateCalls []string
	if body != "" {
		// Extract calls from the function body
		immediateCalls = ExtractFunctionCalls(body)
	} else {
		// Try to find in the plugin-wide index
		cg.mu.RLock()
		calls, found := cg.CallsFrom[callback]
		ambiguousKeys := cg.AmbiguousFuncs[callback]
		if !found {
			// Try without class prefix
			methodOnly := callback
			if idx := strings.LastIndex(callback, "::"); idx >= 0 {
				methodOnly = callback[idx+2:]
			}
			calls, found = cg.CallsFrom[methodOnly]
			if found {
				ambiguousKeys = cg.AmbiguousFuncs[methodOnly]
			}
		}
		cg.mu.RUnlock()

		if found {
			immediateCalls = calls
			// DETERMINISM: If the root callback is ambiguous, merge all implementations
			if len(ambiguousKeys) > 0 {
				allCalls := make(map[string]bool, len(calls))
				for _, c := range calls {
					allCalls[c] = true
				}
				cg.mu.RLock()
				for _, qualifiedKey := range ambiguousKeys {
					if extraCalls, ok := cg.CallsFrom[qualifiedKey]; ok {
						for _, c := range extraCalls {
							allCalls[c] = true
						}
					}
				}
				cg.mu.RUnlock()
				immediateCalls = make([]string, 0, len(allCalls))
				for c := range allCalls {
					immediateCalls = append(immediateCalls, c)
				}
				sort.Strings(immediateCalls)
			}
		}
	}

	if len(immediateCalls) == 0 {
		return nil
	}

	// Build hierarchical tree from immediate calls
	visited[callback] = true
	result := make([]*models.CallChainNode, 0, len(immediateCalls))
	nodeCount := 0
	const maxNodes = 10000 // Safety limit to prevent unbounded tree growth

	for _, call := range immediateCalls {
		if visited[call] {
			continue
		}
		if nodeCount >= maxNodes {
			break
		}
		node := buildCallTree(cg, call, visited, &nodeCount, maxNodes)
		if node != nil {
			result = append(result, node)
		}
	}

	return result
}

// buildCallTree recursively builds the call tree for a function
func buildCallTree(cg *PluginCallGraph, funcName string, visited map[string]bool, nodeCount *int, maxNodes int) *models.CallChainNode {
	*nodeCount++

	// Circuit breaker: stop expanding if node limit reached
	if *nodeCount >= maxNodes {
		return &models.CallChainNode{
			Function: funcName,
			Calls:    nil,
		}
	}

	// Don't recurse into PHP built-ins or WordPress core
	if phpKeywords[funcName] || wpCoreFunctions[funcName] {
		// Still include the node, just don't recurse
		return &models.CallChainNode{
			Function: funcName,
			Calls:    nil,
		}
	}

	// Create the node
	node := &models.CallChainNode{
		Function: funcName,
		Calls:    nil,
	}

	// Mark as visited on THIS PATH only (ancestor tracking for cycle detection).
	// After processing all children, we remove it so sibling branches can
	// independently expand this function. The maxNodes cap bounds total growth.
	visited[funcName] = true
	defer delete(visited, funcName)

	// Look up the pre-computed calls for this function
	cg.mu.RLock()
	calls, found := cg.CallsFrom[funcName]
	ambiguousKeys := cg.AmbiguousFuncs[funcName]
	if !found {
		// Try without class prefix
		methodOnly := funcName
		if idx := strings.LastIndex(funcName, "::"); idx >= 0 {
			methodOnly = funcName[idx+2:]
		}
		calls, found = cg.CallsFrom[methodOnly]
		if found {
			ambiguousKeys = cg.AmbiguousFuncs[methodOnly]
		}
	}
	cg.mu.RUnlock()

	if !found || len(calls) == 0 {
		return node
	}

	// DETERMINISM: If this function name is ambiguous (multiple standalone
	// implementations across different files), include calls from ALL
	// implementations to ensure complete coverage. This way the output
	// always includes all reachable code paths regardless of file ordering.
	if len(ambiguousKeys) > 0 {
		allCalls := make(map[string]bool, len(calls))
		for _, c := range calls {
			allCalls[c] = true
		}
		cg.mu.RLock()
		for _, qualifiedKey := range ambiguousKeys {
			if extraCalls, ok := cg.CallsFrom[qualifiedKey]; ok {
				for _, c := range extraCalls {
					allCalls[c] = true
				}
			}
		}
		cg.mu.RUnlock()
		// Rebuild calls as a sorted slice for deterministic order
		calls = make([]string, 0, len(allCalls))
		for c := range allCalls {
			calls = append(calls, c)
		}
		sort.Strings(calls)
	}

	// Build child nodes
	node.Calls = make([]*models.CallChainNode, 0, len(calls))
	for _, call := range calls {
		if visited[call] {
			continue // Skip cycles
		}
		if *nodeCount >= maxNodes {
			break
		}
		childNode := buildCallTree(cg, call, visited, nodeCount, maxNodes)
		if childNode != nil {
			node.Calls = append(node.Calls, childNode)
		}
	}

	return node
}

// --- Reachability analysis: include tracking, class mapping, hook registry, traits ---

// extractFileIncludes scans a PHP file for include/require statements and records file-level edges.
func (cg *PluginCallGraph) extractFileIncludes(content, filePath string) {
	sourceDir := filepath.Dir(filePath)
	includes := make([]string, 0, 4)

	// Standard include pattern matching
	for _, match := range includePattern.FindAllStringSubmatch(content, -1) {
		var includedPath string
		switch {
		case match[1] != "":
			includedPath = match[1]
		case match[2] != "":
			includedPath = filepath.Join(sourceDir, match[2])
		case match[3] != "":
			includedPath = match[3]
		}
		if includedPath != "" {
			includedPath = filepath.ToSlash(filepath.Clean(includedPath))
			includes = append(includes, includedPath)
		}
	}

	// Also extract .php path fragments from complex include expressions
	// (e.g., CONSTANT . DIRECTORY_SEPARATOR . 'database' . DIRECTORY_SEPARATOR . 'search-replace.php')
	for _, match := range includeFragmentPattern.FindAllStringSubmatch(content, -1) {
		expr := match[1]
		// Extract all string literals from the include expression
		for _, strMatch := range regexp.MustCompile(`['"]([^'"]+)['"]`).FindAllStringSubmatch(expr, -1) {
			frag := strMatch[1]
			if strings.HasSuffix(frag, ".php") {
				includes = append(includes, filepath.ToSlash(filepath.Clean(frag)))
			}
		}
	}

	if len(includes) > 0 {
		cg.mu.Lock()
		cg.IncludesFrom[filePath] = append(cg.IncludesFrom[filePath], includes...)
		cg.mu.Unlock()
	}

	// Detect Composer autoload inclusion
	if strings.Contains(content, "vendor/autoload.php") {
		cg.mu.Lock()
		cg.AutoloadBaseDirs = append(cg.AutoloadBaseDirs, "vendor")
		cg.mu.Unlock()
	}

	// Parse Composer autoload_psr4.php for namespace→directory mappings
	if strings.HasSuffix(filePath, "vendor/composer/autoload_psr4.php") {
		cg.parseComposerPSR4(content)
	}
}

// parseComposerPSR4 extracts namespace→directory mappings from Composer's autoload_psr4.php
func (cg *PluginCallGraph) parseComposerPSR4(content string) {
	psr4Pat := regexp.MustCompile(`'([^']+\\\\)'\s*=>\s*array\s*\(\s*\$[a-zA-Z]+ \. '([^']+)'`)
	for _, m := range psr4Pat.FindAllStringSubmatch(content, -1) {
		namespace := strings.ReplaceAll(m[1], "\\\\", "\\")
		dir := strings.Trim(m[2], "/")
		cg.mu.Lock()
		cg.AutoloadBaseDirs = append(cg.AutoloadBaseDirs, dir)
		_ = namespace // namespace prefix stored implicitly via directory
		cg.mu.Unlock()
	}
}

// buildFileIndex builds a basename-to-paths index from ALL known PHP files,
// plus the separator-normalised index every path comparison uses.
//
// DETERMINISM: cg.AllFiles is a map, so the basename lists are sorted. Without
// that, resolveIncludePath's single-candidate rule and resolveArgToFile's
// suffix scan return whichever path the map iteration produced first.
func (cg *PluginCallGraph) buildFileIndex() {
	paths := make([]string, 0, len(cg.AllFiles))
	for fp := range cg.AllFiles {
		paths = append(paths, fp)
	}
	sort.Strings(paths)
	for _, fp := range paths {
		base := filepath.Base(fp)
		cg.FilesByBasename[base] = append(cg.FilesByBasename[base], fp)
		norm := filepath.ToSlash(fp)
		if _, taken := cg.normFiles[norm]; !taken {
			cg.normFiles[norm] = fp
		}
	}
}

// extractHookRegistrations scans a PHP file for add_action, add_filter, add_shortcode calls.
func (cg *PluginCallGraph) extractHookRegistrations(content, filePath string, p *fileParse) {
	// Which hooks does this tree fire itself? A registration for a hook the
	// tree never fires is not dead code: WordPress core, or another plugin,
	// fires it during request handling. Recording the firings is what lets a
	// consumer tell the two apart.
	cg.recordFirings(content)

	record := func(name string, reg HookRegistration, prefix bool) {
		cg.HookRegistry.mu.Lock()
		if prefix {
			cg.HookRegistry.PrefixHooks[name] = append(cg.HookRegistry.PrefixHooks[name], reg)
		} else {
			cg.HookRegistry.Hooks[name] = append(cg.HookRegistry.Hooks[name], reg)
		}
		cg.HookRegistry.mu.Unlock()
	}

	register := func(hookName, callbackExpr string, at int, prefix bool) {
		encl := enclosingType(at, p.types)
		className := ""
		if encl != nil {
			className = encl.Name
		}
		if resolved := resolveHookCallback(callbackExpr, className); resolved != "" {
			record(hookName, HookRegistration{
				Callback: resolved, File: filePath, Hook: hookName,
			}, prefix)
			return
		}
		// `add_action( 'h', array( $this, $method ) )` names a method the
		// language bounds to the enclosing class but does not spell out. The
		// receiver is not unknown, so the enumerable set of possibilities is
		// recorded rather than nothing at all -- 180 such sites across 63 of
		// 143 corpus trees, and it is the only in-edge some AJAX handlers have.
		if className == "" || !isVariableThisCallback(callbackExpr) {
			return
		}
		for _, m := range cg.methodsOf(className) {
			record(hookName, HookRegistration{
				Callback: className + "::" + m, File: filePath, Hook: hookName,
				Synthesized: true,
			}, prefix)
		}
	}

	// Static hook registrations: add_action('hook', callback)
	for _, match := range hookRegistrationPattern.FindAllStringSubmatchIndex(content, -1) {
		register(content[match[2]:match[3]], strings.TrimSpace(content[match[4]:match[5]]), match[0], false)
	}

	// Dynamic/concatenated hook registrations: add_action('prefix_' . $var, callback)
	for _, match := range hookRegistrationDynamicPattern.FindAllStringSubmatchIndex(content, -1) {
		register(content[match[2]:match[3]], strings.TrimSpace(content[match[4]:match[5]]), match[0], true)
	}

	// Shortcode registrations: add_shortcode('tag', callback)
	for _, match := range shortcodeRegistrationPattern.FindAllStringSubmatchIndex(content, -1) {
		register("shortcode::"+content[match[2]:match[3]], strings.TrimSpace(content[match[4]:match[5]]), match[0], false)
	}
}

// methodsOf returns the method names a type declares, through its traits and
// ancestors.
func (cg *PluginCallGraph) methodsOf(class string) []string {
	calls := make(map[string]bool)
	cg.addClassMethodTokens(class, "", calls)
	out := make([]string, 0, len(calls))
	for k := range calls {
		if i := strings.LastIndex(k, "::"); i >= 0 {
			out = append(out, k[i+2:])
		}
	}
	sort.Strings(out)
	return out
}

// isVariableThisCallback reports whether a callback expression is the
// `[$this, $method]` shape: an array whose object slot is $this and whose
// method slot is not a literal.
func isVariableThisCallback(expr string) bool {
	if !strings.Contains(expr, "$this") {
		return false
	}
	if !strings.Contains(expr, "[") && !strings.Contains(expr, "array") {
		return false
	}
	rest := expr[strings.Index(expr, "$this")+len("$this"):]
	comma := strings.IndexByte(rest, ',')
	if comma < 0 {
		return false
	}
	return strings.Contains(rest[comma:], "$")
}

// recordFirings notes every hook this file fires, so a consumer can tell a
// registration the plugin dispatches itself from one only an outside
// dispatcher can reach.
func (cg *PluginCallGraph) recordFirings(content string) {
	if !firesAHook(content) {
		return
	}
	reg := cg.HookRegistry
	reg.mu.Lock()
	defer reg.mu.Unlock()

	for _, m := range wpHookCallPattern.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			reg.Fired[m[1]] = true
		}
	}
	for _, pat := range [2]*regexp.Regexp{wpHookCallConcatPrefixPattern, wpHookCallInterpPrefixPattern} {
		for _, m := range pat.FindAllStringSubmatch(content, -1) {
			if len(m) > 1 {
				reg.FiredPrefixes[m[1]] = true
			}
		}
	}
	// A firing whose name is a bare variable or a constant cannot be read at
	// all. It is recorded as a caveat rather than ignored, because "the tree
	// never fires this hook" is only sound if every firing was legible.
	if wpHookCallOpaquePattern.MatchString(content) {
		reg.FiredOpaque = true
	}
}

// ExternalHookRoots returns the registrations whose hook name nothing in this
// tree fires with a string literal.
//
// WordPress's whole extension model is that core, or another plugin, fires the
// hook: 65% of the literal add_action/add_filter registrations in a 143-plugin
// corpus name a hook the registering tree never fires. Such a callback is not
// dead code, it is code an external dispatcher runs during request handling, so
// it is an entry point. Root status is decided by exact literal firings alone:
// a prefix inferred from `do_action( 'wp_' . $x )` would otherwise deny root
// status to every wp_ajax_nopriv_ registration in the tree.
//
// The second return value reports that some firing in this tree could not be
// read, so "never fired here" is a weaker statement than it looks.
func (cg *PluginCallGraph) ExternalHookRoots() ([]HookRegistration, bool) {
	cg.HookRegistry.mu.RLock()
	defer cg.HookRegistry.mu.RUnlock()

	var out []HookRegistration
	names := make([]string, 0, len(cg.HookRegistry.Hooks))
	for name := range cg.HookRegistry.Hooks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if cg.HookRegistry.Fired[name] || strings.HasPrefix(name, "shortcode::") {
			continue
		}
		out = append(out, cg.HookRegistry.Hooks[name]...)
	}
	return out, cg.HookRegistry.FiredOpaque
}

// resolveHookCallback resolves a callback expression to a function/method name.
func resolveHookCallback(expr, currentClass string) string {
	expr = foldStringConcat(strings.TrimSpace(expr))

	// String callback: 'function_name'
	if (strings.HasPrefix(expr, "'") || strings.HasPrefix(expr, "\"")) &&
		(strings.HasSuffix(expr, "'") || strings.HasSuffix(expr, "\"")) {
		return strings.Trim(expr, "'\"")
	}

	// Array callback with $this: [$this, 'method'] or array($this, 'method')
	if strings.Contains(expr, "$this") {
		methodMatch := arrayMethodNamePattern.FindStringSubmatch(expr)
		if len(methodMatch) > 1 && currentClass != "" {
			return currentClass + "::" + methodMatch[1]
		}
		if len(methodMatch) > 1 {
			return methodMatch[1]
		}
	}

	// self/static: [self::class, 'method']
	if strings.Contains(expr, "self") || strings.Contains(expr, "static::") {
		methodMatch := arrayMethodNamePattern.FindStringSubmatch(expr)
		if len(methodMatch) > 1 && currentClass != "" {
			return currentClass + "::" + methodMatch[1]
		}
	}

	// Array/static callback: [ClassName::class, 'method'] or ['ClassName', 'method']
	if strings.Contains(expr, "::class") || strings.Contains(expr, "[") || strings.Contains(expr, "array(") {
		parts := arrayMethodNamePattern.FindAllStringSubmatch(expr, -1)
		if len(parts) >= 1 {
			method := parts[len(parts)-1][1]
			classMatch := hookCallbackClassPattern.FindStringSubmatch(expr)
			if len(classMatch) > 1 {
				cls := classMatch[1]
				if cls == "" {
					cls = classMatch[2]
				}
				if cls != "" {
					return cls + "::" + method
				}
			}
			return method
		}
	}

	// Variable callback — skip
	if strings.HasPrefix(expr, "$") {
		return ""
	}

	// Bare function name
	if cleanFunctionNamePattern.MatchString(expr) {
		return expr
	}

	return ""
}

// foldStringConcat joins adjacent string literals the way PHP does at compile
// time, so `'ajax_' . 'WPBC_CREATE'` is the callback name ajax_WPBC_CREATE
// rather than the literal text between the outer quotes.
//
// Only literal-to-literal joins are folded. An expression with a variable in it
// names something this function cannot know, and is left alone for the caller
// to reject.
func foldStringConcat(expr string) string {
	if !strings.Contains(expr, ".") {
		return expr
	}
	var out strings.Builder
	quote := byte(0)
	i := 0
	for i < len(expr) {
		c := expr[i]
		if quote == 0 && (c == '\'' || c == '"') {
			if out.Len() == 0 {
				out.WriteByte(c)
				quote = c
				i++
				continue
			}
			// A second literal begins: drop the closing quote already written
			// and this opening one, splicing the two literals together.
			s := out.String()
			if len(s) > 0 && s[len(s)-1] == c {
				out.Reset()
				out.WriteString(s[:len(s)-1])
				quote = c
				i++
				continue
			}
			return expr
		}
		if quote != 0 {
			if c == '\\' && i+1 < len(expr) {
				out.WriteByte(c)
				out.WriteByte(expr[i+1])
				i += 2
				continue
			}
			out.WriteByte(c)
			if c == quote {
				quote = 0
			}
			i++
			continue
		}
		// Between literals only "." and whitespace may appear; anything else
		// means the expression is not a pure literal join.
		if c != '.' && c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return expr
		}
		i++
	}
	if quote != 0 {
		return expr
	}
	if out.Len() == 0 {
		return expr
	}
	return out.String()
}

// findEnclosingClass determines which class (if any) contains a given byte position.
func findEnclosingClass(pos int, classRanges map[string][2]int) string {
	className := ""
	smallestRange := int(^uint(0) >> 1)
	for cn, bounds := range classRanges {
		if pos > bounds[0] && pos < bounds[1] {
			rangeSize := bounds[1] - bounds[0]
			if rangeSize < smallestRange {
				smallestRange = rangeSize
				className = cn
			}
		}
	}
	return className
}

// discoverTraitUsage aliases the methods a type gets from its traits onto that
// type, so `Bootstrap::send_password_reset` exists when Bootstrap uses the
// trait that declares it.
//
// `use T;` inside a class body copies T's methods into the class at compile
// time, and a method the class declares itself takes precedence over the
// trait's. The own-declaration guard below is that precedence rule and must be
// kept.
//
// The previous implementation could never fire, because a trait body was not a
// class range and no `Trait::method` key was ever created. It also scanned the
// whole of CallsFrom for every `use` statement in every file -- 739 trait uses
// against 8,959 keys in one corpus tree -- and INSERTED into the map it was
// ranging over, which Go leaves unspecified. It is driven off the per-type
// method index instead, and the writes are collected before any is applied.
func (cg *PluginCallGraph) discoverTraitUsage() {
	cg.mu.Lock()
	defer cg.mu.Unlock()

	type alias struct {
		classKey string
		traitKey string
	}
	var pending []alias

	names := make([]string, 0, len(cg.Types))
	for name := range cg.Types {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		td := cg.Types[name]
		// A trait may itself use a trait, so the walk runs to a fixed point.
		// Four rounds is past any real depth and stops a cycle from spinning.
		seen := map[string]bool{name: true}
		frontier := append([]string(nil), td.Traits...)
		for round := 0; round < 4 && len(frontier) > 0; round++ {
			var next []string
			for _, t := range frontier {
				tn := cg.foldTypeLocked(t)
				if tn == "" || seen[tn] {
					continue
				}
				seen[tn] = true
				tt := cg.Types[tn]
				if tt == nil {
					continue
				}
				for _, m := range tt.Methods {
					pending = append(pending, alias{classKey: name + "::" + m, traitKey: tn + "::" + m})
				}
				next = append(next, tt.Traits...)
			}
			frontier = next
		}
	}

	for _, a := range pending {
		if _, hasOwn := cg.CallsFrom[a.classKey]; hasOwn {
			continue
		}
		calls, ok := cg.CallsFrom[a.traitKey]
		if !ok {
			continue
		}
		cg.CallsFrom[a.classKey] = calls
		if funcDef, ok := cg.Functions[a.traitKey]; ok {
			if _, taken := cg.Functions[a.classKey]; !taken {
				cg.Functions[a.classKey] = funcDef
			}
		}
		for _, callee := range calls {
			cg.CallsTo[callee] = append(cg.CallsTo[callee], a.classKey)
		}
	}
}

// GetReachableFiles returns the set of file paths reachable from an endpoint callback.
// It follows function calls, class references, and include/require edges transitively.
func (cg *PluginCallGraph) GetReachableFiles(callback, callbackFile string) map[string]bool {
	reachable := make(map[string]bool)
	reachable[callbackFile] = true

	callback = ResolveCallback(callback, "")
	if callback == "" || callback == "unknown" || callback == "inline" || callback == "closure" {
		// The caller has no file content to offer here, so an anonymous
		// callback still contributes only its own file. followIncludes below
		// then does what it can with that. The callee walk is where a closure's
		// body is actually read; see closureSeededCalls.
		cg.followIncludes(reachable)
		return reachable
	}

	visited := make(map[string]bool)
	cg.collectReachableFiles(callback, visited, reachable)

	// Also collect files from hook registry callbacks reachable via the call chain
	cg.HookRegistry.mu.RLock()
	for _, reg := range cg.HookRegistry.allHookCallbackFiles() {
		if visited[reg.Callback] {
			reachable[reg.File] = true
		}
	}
	cg.HookRegistry.mu.RUnlock()

	cg.followIncludes(reachable)

	return reachable
}

// collectReachableFiles recursively follows the call graph adding files of reached functions.
func (cg *PluginCallGraph) collectReachableFiles(funcName string, visited map[string]bool, reachable map[string]bool) {
	if visited[funcName] || phpKeywords[funcName] {
		return
	}
	visited[funcName] = true

	// Strip PHP namespace prefix for call graph lookup (e.g., "YayExtra\\plugins_loaded" -> "plugins_loaded")
	bareName := funcName
	if idx := strings.LastIndex(funcName, "\\"); idx >= 0 {
		bareName = funcName[idx+1:]
	}

	cg.mu.RLock()

	// Add file where this function is defined (try FQN first, then bare name)
	if def, ok := cg.Functions[funcName]; ok && def.FilePath != "" {
		reachable[def.FilePath] = true
	} else if bareName != funcName {
		if def, ok := cg.Functions[bareName]; ok && def.FilePath != "" {
			reachable[def.FilePath] = true
		}
	}

	// Resolve type-to-file for Class::method patterns.
	//
	// ClassToFiles rather than ClassToFile: a name may be declared in several
	// files, and the single-valued map keeps only one of them. Reading the
	// many-valued index means recognising more type declarations can only add
	// file reach.
	markFiles := func(name string) {
		for _, f := range cg.ClassToFiles[name] {
			reachable[f] = true
		}
	}
	if idx := strings.Index(bareName, "::"); idx > 0 {
		markFiles(bareName[:idx])
	}
	// Also check bare name as a class (from `new ClassName()` calls)
	markFiles(bareName)
	if bareName != funcName {
		markFiles(funcName)
	}
	// PSR-4 autoload resolution for namespaced references (uses locked state)
	if strings.Contains(funcName, "\\") {
		resolved := cg.resolvePSR4Locked(funcName)
		if resolved != "" {
			reachable[resolved] = true
		}
	}

	// Get calls from this function (try FQN, then bare name, then method-only)
	calls, found := cg.CallsFrom[funcName]
	if !found && bareName != funcName {
		calls, found = cg.CallsFrom[bareName]
	}
	if !found {
		methodOnly := bareName
		if idx := strings.LastIndex(bareName, "::"); idx >= 0 {
			methodOnly = bareName[idx+2:]
		}
		if methodOnly != bareName {
			calls, found = cg.CallsFrom[methodOnly]
		}
	}

	// Also check ambiguous implementations
	ambiguousKeys := cg.AmbiguousFuncs[funcName]
	if len(ambiguousKeys) == 0 && bareName != funcName {
		ambiguousKeys = cg.AmbiguousFuncs[bareName]
	}

	cg.mu.RUnlock()

	if found {
		for _, call := range calls {
			cg.collectReachableFiles(call, visited, reachable)
		}
	}

	// Follow ambiguous implementations too
	for _, qualKey := range ambiguousKeys {
		cg.mu.RLock()
		if def, ok := cg.Functions[qualKey]; ok && def.FilePath != "" {
			reachable[def.FilePath] = true
		}
		extraCalls := cg.CallsFrom[qualKey]
		cg.mu.RUnlock()

		for _, call := range extraCalls {
			cg.collectReachableFiles(call, visited, reachable)
		}
	}
}

// followIncludes performs BFS through include edges from all reachable files.
func (cg *PluginCallGraph) followIncludes(reachable map[string]bool) {
	queue := make([]string, 0, len(reachable))
	for f := range reachable {
		queue = append(queue, f)
	}

	cg.mu.RLock()
	defer cg.mu.RUnlock()

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, inc := range cg.IncludesFrom[current] {
			// Always try to resolve to an actual file in the plugin
			resolved := cg.resolveIncludePathLocked(inc)
			if resolved != "" {
				if !reachable[resolved] {
					reachable[resolved] = true
					queue = append(queue, resolved)
				}
			} else if !reachable[inc] {
				// Store raw path for downstream matching
				reachable[inc] = true
				queue = append(queue, inc)
			}
		}
	}
}

// resolveIncludePath tries to match an include path to a known file via basename + suffix matching.
func (cg *PluginCallGraph) resolveIncludePath(path string) string {
	cg.mu.RLock()
	defer cg.mu.RUnlock()
	return cg.resolveIncludePathLocked(path)
}

// resolveIncludePathLocked is resolveIncludePath with cg.mu already held.
//
// Both sides of the comparison are separator-normalised and the ORIGINAL key is
// returned. Include paths inside PHP source are written with forward slashes
// while the files map is keyed by whatever the caller's platform produced --
// absolute OS paths in production, filepath.Rel output in the benchmark, both
// with backslashes on Windows. So the suffix test could never fire there and
// resolution silently degraded to "exactly one file has this basename":
// measured on one tree, 315 resolved include edges instead of 349, and 89
// endpoint-reachable files instead of 98.
func (cg *PluginCallGraph) resolveIncludePathLocked(path string) string {
	path = filepath.ToSlash(path)
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimPrefix(path, "./")
	base := filepath.Base(path)
	candidates := cg.FilesByBasename[base]

	// Try exact suffix match first
	for _, candidate := range candidates {
		norm := filepath.ToSlash(candidate)
		if strings.HasSuffix(norm, "/"+path) || norm == path {
			return candidate
		}
	}
	// Fall back to basename-only match if there's exactly one candidate
	if len(candidates) == 1 {
		return candidates[0]
	}
	return ""
}

// allHookCallbackFiles returns all hook registrations from both exact and prefix maps.
func (cg *HookRegistry) allHookCallbackFiles() []HookRegistration {
	var all []HookRegistration
	for _, regs := range cg.Hooks {
		all = append(all, regs...)
	}
	for _, regs := range cg.PrefixHooks {
		all = append(all, regs...)
	}
	return all
}

// wpCoreHTTPHooks are WordPress CORE hooks that fire on every HTTP request.
// Callbacks registered for these are implicitly reachable.
//
// The list used to name hooks belonging to three specific third-party plugins.
// Those are not WordPress semantics, and they are no longer needed: a
// registration for a hook this tree never fires is now recognised as externally
// dispatched by set difference, which covers any plugin's hooks without naming
// one. What remains is core's own request lifecycle, kept because a tree that
// DOES fire one of these itself would otherwise drop out of the derived set.
var wpCoreHTTPHooks = map[string]bool{
	"plugins_loaded": true, "muplugins_loaded": true,
	"init": true, "wp_loaded": true, "wp": true,
	"admin_init": true, "admin_menu": true, "admin_bar_menu": true,
	"rest_api_init": true, "parse_request": true,
	"template_redirect": true, "template_include": true,
	"wp_head": true, "wp_footer": true, "admin_head": true, "admin_footer": true,
	"wp_enqueue_scripts": true, "admin_enqueue_scripts": true,
	"widgets_init": true, "after_setup_theme": true,
	"shutdown": true, "wp_ajax_": true,
}

// GetAllHTTPReachableFiles returns files reachable from detected endpoints AND
// WordPress core hooks that fire on every HTTP request.
func (cg *PluginCallGraph) GetAllHTTPReachableFiles(endpoints []models.Endpoint) map[string]bool {
	reachable := make(map[string]bool)

	// Start from all endpoint callbacks
	for _, ep := range endpoints {
		epReachable := cg.GetReachableFiles(ep.Callback, ep.File)
		for f := range epReachable {
			reachable[f] = true
		}
	}

	// Start from hooks nothing in this tree fires, and from core's request
	// lifecycle.
	//
	// WordPress's extension model is that core, or another plugin, fires the
	// hook: 65% of the literal registrations in a 143-plugin corpus name a hook
	// the registering tree never fires. Such a callback is run by an external
	// dispatcher during request handling, so its code is reachable, and the set
	// is computed from the tree itself rather than from a list of hook names.
	cg.HookRegistry.mu.RLock()
	for hookName, regs := range cg.HookRegistry.Hooks {
		if wpCoreHTTPHooks[hookName] || (!cg.HookRegistry.Fired[hookName] && !strings.HasPrefix(hookName, "shortcode::")) {
			for _, reg := range regs {
				hookReachable := cg.GetReachableFiles(reg.Callback, reg.File)
				for f := range hookReachable {
					reachable[f] = true
				}
			}
		}
	}
	// Also check prefix hooks (e.g., add_action('wp_ajax_' . $action, ...))
	for prefix, regs := range cg.HookRegistry.PrefixHooks {
		for coreHook := range wpCoreHTTPHooks {
			if strings.HasPrefix(prefix, coreHook) || strings.HasPrefix(coreHook, prefix) {
				for _, reg := range regs {
					hookReachable := cg.GetReachableFiles(reg.Callback, reg.File)
					for f := range hookReachable {
						reachable[f] = true
					}
				}
				break
			}
		}
	}
	cg.HookRegistry.mu.RUnlock()

	// Mark all files included from the plugin root file(s) as reachable
	for fp := range cg.AllFiles {
		if !strings.Contains(fp, "/") {
			reachable[fp] = true
		}
	}
	cg.followIncludes(reachable)

	// Strategy: Autoload base directory coverage
	// If autoloading is detected, all files under autoload dirs are potentially loadable
	if len(cg.AutoloadBaseDirs) > 0 {
		for f := range cg.AllFiles {
			for _, baseDir := range cg.AutoloadBaseDirs {
				if baseDir != "" && (strings.HasPrefix(f, baseDir+"/") || f == baseDir) {
					reachable[f] = true
					break
				}
			}
		}
	}

	// Strategy: Dynamic includer directory coverage
	// If a reachable dynamic includer's hints point to directories, mark all files there
	cg.mu.RLock()
	for funcName, hints := range cg.DynIncluders {
		isReachable := false
		if def, ok := cg.Functions[funcName]; ok && def.FilePath != "" {
			isReachable = reachable[def.FilePath]
		}
		if !isReachable {
			bareName := funcName
			if idx := strings.LastIndex(funcName, "::"); idx >= 0 {
				bareName = funcName[idx+2:]
			}
			if def, ok := cg.Functions[bareName]; ok && def.FilePath != "" {
				isReachable = reachable[def.FilePath]
			}
		}
		if isReachable {
			for _, hint := range hints {
				hint = strings.TrimSuffix(hint, "/")
				if hint == "" || hint == "." {
					continue
				}
				for f := range cg.AllFiles {
					if strings.HasPrefix(f, hint+"/") {
						reachable[f] = true
					}
				}
			}
		}
	}
	cg.mu.RUnlock()

	// Strategy: Class reference coverage
	// Any class referenced in the call graph that maps to a file is reachable
	cg.mu.RLock()
	// ClassToFiles rather than ClassToFile, so a name declared in several files
	// pulls in all of them instead of whichever one the single-valued map kept.
	for className, classFiles := range cg.ClassToFiles {
		allReachable := true
		for _, f := range classFiles {
			if !reachable[f] {
				allReachable = false
				break
			}
		}
		if allReachable {
			continue
		}
		// Check if any reachable function references this class
		for funcName := range cg.Functions {
			if strings.HasPrefix(funcName, className+"::") {
				if def := cg.Functions[funcName]; def != nil && reachable[def.FilePath] {
					for _, f := range classFiles {
						reachable[f] = true
					}
					break
				}
			}
		}
	}
	cg.mu.RUnlock()

	// Strategy: Template/module directory coverage
	// If any file from a conventional WordPress directory is already reachable,
	// mark all files in that directory as reachable
	templateDirNames := map[string]bool{
		"templates": true, "views": true, "partials": true, "tpl": true,
		"modules": true, "widgets": true, "blocks": true, "extensions": true,
	}
	// Find template/module directory ROOTS from reachable files AND all known files
	// If the plugin has endpoints (which it does if we're here), template/module dirs are loadable
	reachableTemplateRoots := make(map[string]bool)
	// From reachable files
	for f := range reachable {
		parts := strings.Split(f, "/")
		for i, part := range parts {
			if templateDirNames[strings.ToLower(part)] {
				root := strings.Join(parts[:i+1], "/")
				reachableTemplateRoots[root] = true
				break
			}
		}
	}
	// Also check if any include edge targets a template dir
	for _, includes := range cg.IncludesFrom {
		for _, inc := range includes {
			parts := strings.Split(inc, "/")
			for i, part := range parts {
				if templateDirNames[strings.ToLower(part)] {
					root := strings.Join(parts[:i+1], "/")
					reachableTemplateRoots[root] = true
					break
				}
			}
		}
	}
	// Also check dynamic includer hints
	for _, hints := range cg.DynIncluders {
		for _, hint := range hints {
			parts := strings.Split(hint, "/")
			for i, part := range parts {
				if templateDirNames[strings.ToLower(part)] {
					root := strings.Join(parts[:i+1], "/")
					reachableTemplateRoots[root] = true
					break
				}
			}
		}
	}
	// For plugins with endpoints, also scan all files — if a template dir exists,
	// its contents are loadable by the plugin's template loading infrastructure
	if len(endpoints) > 0 {
		for f := range cg.AllFiles {
			parts := strings.Split(f, "/")
			for i, part := range parts {
				if templateDirNames[strings.ToLower(part)] {
					root := strings.Join(parts[:i+1], "/")
					reachableTemplateRoots[root] = true
					break
				}
			}
		}
	}
	// Mark ALL files under any reachable template root
	for f := range cg.AllFiles {
		for root := range reachableTemplateRoots {
			if strings.HasPrefix(f, root+"/") {
				reachable[f] = true
				break
			}
		}
	}

	// Strategy: Vendor directory unity
	// If any vendor file is reachable, the whole vendor library is loadable
	vendorReachable := false
	for f := range reachable {
		if strings.HasPrefix(f, "vendor/") {
			vendorReachable = true
			break
		}
	}
	if vendorReachable {
		for f := range cg.AllFiles {
			if strings.HasPrefix(f, "vendor/") {
				reachable[f] = true
			}
		}
	}

	// Final: follow includes from newly reachable files
	cg.followIncludes(reachable)

	return reachable
}

// --- Dynamic includer detection and function-arg-to-file resolution ---

// extractDynIncluders scans for functions whose body contains variable includes.
//
// The declaration scan used to be funcDefPattern, whose regex parameter list
// `\([^)]*\)` stops at the first ")" inside the parameters. A template loader
// is normally written `function load_view( $name, $args = array() )`, so the
// commonest shape of the very construct this function looks for was invisible:
// 11,696 of 329,198 declarations across the corpus, 26% of one plugin's.
// FindFunctionDeclarations walks the delimiters instead, which is why every
// other consumer already moved to it.
func (cg *PluginCallGraph) extractDynIncluders(content, filePath string, p *fileParse) {
	for _, decl := range p.decls {
		body := content[decl.BodyOpen:decl.BodyClose]
		if !dynamicIncludeVarPattern.MatchString(body) {
			continue
		}

		key := decl.Name
		if encl := enclosingType(decl.DeclStart, p.types); encl != nil {
			key = encl.Name + "::" + decl.Name
		}

		hints := extractDirHints(body, filePath)

		// Hints are UNIONED, not replaced. Two includers sharing a bare name
		// collide on this map, and recognising more of them makes that more
		// likely; overwriting would take away a directory that is covered
		// today, which is the one way this change could remove reachability.
		cg.mu.Lock()
		cg.DynIncluders[key] = unionHints(cg.DynIncluders[key], hints)
		if key != decl.Name {
			cg.DynIncluders[decl.Name] = unionHints(cg.DynIncluders[decl.Name], hints)
		}
		cg.mu.Unlock()
	}
}

func unionHints(existing, add []string) []string {
	if len(existing) == 0 {
		return add
	}
	for _, h := range add {
		if !containsName(existing, h) {
			existing = append(existing, h)
		}
	}
	return existing
}

func extractDirHints(body, filePath string) []string {
	hints := make([]string, 0, 4)
	matches := dirHintPattern.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		hint := filepath.ToSlash(m[1])
		hint = strings.Trim(hint, "/")
		if hint != "" && !strings.HasPrefix(hint, "http") && !strings.HasPrefix(hint, "//") {
			hints = append(hints, hint)
		}
	}
	hints = append(hints, filepath.ToSlash(filepath.Dir(filePath)))
	return hints
}

// extractDynIncludeEdges scans file content for calls to dynamic includers with string args.
func (cg *PluginCallGraph) extractDynIncludeEdges(content, filePath string) {
	matches := funcWithStringArgPattern.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		var funcName, arg string
		switch {
		case m[1] != "" && m[2] != "":
			funcName, arg = m[1], m[2]
		case m[3] != "" && m[4] != "":
			funcName, arg = m[3], m[4]
		case m[5] != "" && m[6] != "" && m[7] != "":
			funcName = m[5] + "::" + m[6]
			arg = m[7]
		default:
			continue
		}

		cg.mu.RLock()
		hints, isIncluder := cg.DynIncluders[funcName]
		cg.mu.RUnlock()
		if !isIncluder {
			continue
		}

		resolved := cg.resolveArgToFile(arg, hints)
		if resolved != "" {
			cg.mu.Lock()
			cg.IncludesFrom[filePath] = append(cg.IncludesFrom[filePath], resolved)
			cg.mu.Unlock()
		}
	}
}

func (cg *PluginCallGraph) resolveArgToFile(arg string, dirHints []string) string {
	arg = strings.TrimSpace(arg)

	candidates := []string{arg}
	if !strings.HasSuffix(arg, ".php") {
		candidates = append(candidates, arg+".php")
		candidates = append(candidates, arg+".html.php")
	}

	cg.mu.RLock()
	defer cg.mu.RUnlock()

	for _, candidate := range candidates {
		base := filepath.Base(candidate)
		paths := cg.FilesByBasename[base]

		if len(paths) == 1 {
			return paths[0]
		}

		// Every comparison normalises the stored key, because the caller's keys
		// carry OS separators while the candidate is built from PHP source.
		normalizedCandidate := filepath.ToSlash(candidate)
		for _, hint := range dirHints {
			suffixPath := filepath.ToSlash(filepath.Join(hint, normalizedCandidate))
			for _, p := range paths {
				if n := filepath.ToSlash(p); strings.HasSuffix(n, "/"+suffixPath) || n == suffixPath {
					return p
				}
			}
			for _, p := range paths {
				if strings.HasSuffix(filepath.ToSlash(p), "/"+normalizedCandidate) {
					return p
				}
			}
		}

		// DETERMINISM: normFiles is built from a sorted path list, so the first
		// suffix match is the same on every run. Ranging over the AllFiles map
		// returned whichever key the hash order produced.
		if real, ok := cg.normFiles[normalizedCandidate]; ok {
			return real
		}
		for _, norm := range cg.sortedNormPaths() {
			if strings.HasSuffix(norm, "/"+normalizedCandidate) {
				return cg.normFiles[norm]
			}
		}
	}
	return ""
}

// fileByNormPath looks a candidate path up in the separator-normalised index
// and returns the key AllFiles actually holds. Caller must hold cg.mu.
func (cg *PluginCallGraph) fileByNormPath(path string) string {
	return cg.normFiles[filepath.ToSlash(path)]
}

// sortedNormPaths returns every known file's normalised path in sorted order.
// Caller must hold cg.mu.
func (cg *PluginCallGraph) sortedNormPaths() []string {
	out := make([]string, 0, len(cg.normFiles))
	for n := range cg.normFiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (cg *PluginCallGraph) extractAutoloadHints(content, filePath string) {
	if !strings.Contains(content, "spl_autoload_register") {
		return
	}

	baseDirPat := regexp.MustCompile(
		`\$[a-zA-Z_]+\s*=\s*(?:__DIR__|dirname\s*\([^)]+\))\s*\.\s*['"]([^'"]+)['"]`,
	)
	for _, m := range baseDirPat.FindAllStringSubmatch(content, -1) {
		if m[1] != "" {
			dir := filepath.ToSlash(strings.Trim(m[1], "/"))
			baseDir := filepath.ToSlash(filepath.Join(filepath.Dir(filePath), dir))
			cg.mu.Lock()
			cg.AutoloadBaseDirs = append(cg.AutoloadBaseDirs, baseDir)
			cg.mu.Unlock()
		}
	}

	cg.mu.Lock()
	cg.AutoloadBaseDirs = append(cg.AutoloadBaseDirs, filepath.ToSlash(filepath.Dir(filePath)))
	cg.mu.Unlock()
}

func (cg *PluginCallGraph) resolvePSR4(fqn string) string {
	cg.mu.RLock()
	defer cg.mu.RUnlock()
	return cg.resolvePSR4Locked(fqn)
}

// resolvePSR4Locked converts a FQN to a file path. Caller must hold cg.mu.RLock.
// Handles both namespace\Class and Prefix_Underscore_Class conventions.
func (cg *PluginCallGraph) resolvePSR4Locked(fqn string) string {
	// Try namespace-to-directory (PSR-4): Vendor\Package\Class -> Vendor/Package/Class.php
	relPath := strings.ReplaceAll(fqn, "\\", "/") + ".php"

	// The candidate is built with forward slashes while AllFiles is keyed by
	// whatever the caller's platform produced, so the lookup goes through the
	// normalised index and returns the key the caller would recognise.
	for _, baseDir := range cg.AutoloadBaseDirs {
		if hit := cg.fileByNormPath(filepath.Join(baseDir, relPath)); hit != "" {
			return hit
		}
		if idx := strings.Index(relPath, "/"); idx > 0 {
			stripped := relPath[idx+1:]
			if hit := cg.fileByNormPath(filepath.Join(baseDir, stripped)); hit != "" {
				return hit
			}
			if idx2 := strings.Index(stripped, "/"); idx2 > 0 {
				if hit := cg.fileByNormPath(filepath.Join(baseDir, stripped[idx2+1:])); hit != "" {
					return hit
				}
			}
		}
	}

	// Namespace-to-directory basename match
	parts := strings.Split(relPath, "/")
	className := parts[len(parts)-1]
	if paths, ok := cg.FilesByBasename[className]; ok {
		if len(paths) == 1 {
			return paths[0]
		}
		for segs := len(parts); segs >= 2; segs-- {
			suffix := strings.Join(parts[len(parts)-segs:], "/")
			for _, p := range paths {
				if n := filepath.ToSlash(p); strings.HasSuffix(n, "/"+suffix) || n == suffix {
					return p
				}
			}
		}
	}

	// WordPress convention: underscore-to-directory (Prefix_Module_Class -> Prefix/Module/Class.php)
	if strings.Contains(fqn, "_") && !strings.Contains(fqn, "\\") {
		underscorePath := strings.ReplaceAll(fqn, "_", "/") + ".php"
		for _, baseDir := range cg.AutoloadBaseDirs {
			if hit := cg.fileByNormPath(filepath.Join(baseDir, underscorePath)); hit != "" {
				return hit
			}
		}
		// Also try with "classes/" prefix (common Visualizer pattern)
		uParts := strings.Split(underscorePath, "/")
		uClassName := uParts[len(uParts)-1]
		if paths, ok := cg.FilesByBasename[uClassName]; ok {
			if len(paths) == 1 {
				return paths[0]
			}
			for segs := len(uParts); segs >= 2; segs-- {
				suffix := strings.Join(uParts[len(uParts)-segs:], "/")
				for _, p := range paths {
					if n := filepath.ToSlash(p); strings.HasSuffix(n, "/"+suffix) || n == suffix {
						return p
					}
				}
			}
		}
	}

	// Kebab-case convention: Underscore_Name -> underscore-name.php
	if strings.Contains(fqn, "_") {
		lastPart := fqn
		if idx := strings.LastIndex(fqn, "\\"); idx >= 0 {
			lastPart = fqn[idx+1:]
		}
		kebab := strings.ToLower(strings.ReplaceAll(lastPart, "_", "-")) + ".php"
		if paths, ok := cg.FilesByBasename[kebab]; ok {
			if len(paths) == 1 {
				return paths[0]
			}
		}
	}

	return ""
}

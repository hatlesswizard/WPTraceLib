package analyzer

import (
	"regexp"
	"strconv"
	"strings"

	wpast "github.com/hatlesswizard/wptracelib/pkg/ast"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// This file turns `add_action` / `add_filter` registrations on WordPress core
// hooks into endpoints.
//
// MEMBERSHIP RULE for the tables below, and the only argument that may be used
// to add a hook to them:
//
//	A hook belongs here iff WordPress CORE fires it, and the level recorded
//	beside it is the privilege of the CHEAPEST core path that fires it. Name the
//	core file that does the firing in the comment, so the claim is checkable by
//	someone who has never seen this codebase.
//
// That rule is what keeps admin_enqueue_scripts and admin_notices OUT (both fire
// after wp-admin/admin.php has called auth_redirect() and the screen's own
// capability test, so their cheapest path is not public and their true level
// depends on which screen is being drawn), and what keeps admin_init IN
// (wp-admin/admin-ajax.php and admin-post.php include wp-load.php directly and
// fire admin_init before the wp_ajax / wp_ajax_nopriv split, so an anonymous
// request reaches it). It also excludes muplugins_loaded, which wp-settings.php
// fires after the mu-plugins include loop and BEFORE the loop that includes
// regularly activated plugins: a plugin in wp-content/plugins cannot have a
// callback attached when it fires, so a registration on it seeds nothing.
//
// add_action() is literally `return add_filter( $hook_name, $callback, $priority,
// $accepted_args );` in wp-includes/plugin.php, so both spellings register the
// same callback on the same hook and which one a plugin writes is style. Matching
// only add_action, as this file used to, was matching text rather than semantics
// and lost 21 registrations in 17 of the 143 corpus plugins on the covered hooks
// alone.

// hookSpec is one modelled core hook: the privilege its cheapest core firing path
// requires, and a label for which family of core code fires it.
type hookSpec struct {
	Level   models.AuthLevel
	Context string
}

// legacyLifecycleHooks are the hooks this detector covered before the widening.
// They are named separately because the endpoints they already produced keep
// their inferred level; see hookEndpointLevel.
var legacyLifecycleHooks = map[string]bool{
	"init": true, "admin_init": true, "wp": true, "wp_loaded": true,
	"template_redirect": true, "send_headers": true, "parse_request": true,
	"plugins_loaded": true, "setup_theme": true, "after_setup_theme": true,
}

// coreHookSpecs maps a fixed core hook name onto the privilege its cheapest core
// firing path requires. Every entry cites the core file that fires it.
var coreHookSpecs = map[string]hookSpec{
	// -- request lifecycle: wp-settings.php runs these on every request, before
	// any credential is examined, and wp-includes/class-wp.php and
	// wp-includes/template-loader.php run the rest while serving a front-end
	// page to an anonymous visitor.
	"plugins_loaded":    {models.Unauthenticated, "lifecycle"},
	"setup_theme":       {models.Unauthenticated, "lifecycle"},
	"after_setup_theme": {models.Unauthenticated, "lifecycle"},
	"init":              {models.Unauthenticated, "lifecycle"},
	"wp_loaded":         {models.Unauthenticated, "lifecycle"},
	"parse_request":     {models.Unauthenticated, "lifecycle"},
	"send_headers":      {models.Unauthenticated, "lifecycle"},
	"wp":                {models.Unauthenticated, "lifecycle"},
	"template_redirect": {models.Unauthenticated, "lifecycle"},
	// admin_init is reached by an anonymous request: wp-admin/admin-ajax.php and
	// wp-admin/admin-post.php include wp-load.php themselves and fire admin_init
	// before the wp_ajax / wp_ajax_nopriv split decides anything.
	"admin_init": {models.Unauthenticated, "lifecycle"},

	// -- front-end render: wp-includes/general-template.php, template-loader.php
	// and post-template.php fire these while building a page for whoever asked
	// for it. The state they carry -- the requested post, the query vars, the
	// request URI -- is attacker-influenced exactly as init's is.
	"wp_head":          {models.Unauthenticated, "frontend"},
	"wp_body_open":     {models.Unauthenticated, "frontend"},
	"wp_footer":        {models.Unauthenticated, "frontend"},
	"get_header":       {models.Unauthenticated, "frontend"},
	"get_footer":       {models.Unauthenticated, "frontend"},
	"get_sidebar":      {models.Unauthenticated, "frontend"},
	"loop_start":       {models.Unauthenticated, "frontend"},
	"loop_end":         {models.Unauthenticated, "frontend"},
	"the_content":      {models.Unauthenticated, "frontend"},
	"the_excerpt":      {models.Unauthenticated, "frontend"},
	"the_title":        {models.Unauthenticated, "frontend"},
	"template_include": {models.Unauthenticated, "frontend"},
	"body_class":       {models.Unauthenticated, "frontend"},

	// -- main query: wp-includes/class-wp-query.php and class-wp.php run these
	// against the query vars parsed straight out of the request URI.
	"pre_get_posts":   {models.Unauthenticated, "query"},
	"parse_query":     {models.Unauthenticated, "query"},
	"posts_selection": {models.Unauthenticated, "query"},
	"query_vars":      {models.Unauthenticated, "query"},

	// -- widgets: wp-includes/widgets.php fires widgets_init from init and
	// dynamic_sidebar while rendering a sidebar on a front-end page.
	"widgets_init":    {models.Unauthenticated, "widgets"},
	"dynamic_sidebar": {models.Unauthenticated, "widgets"},

	// -- wp-login.php, which by construction runs before anyone is logged in.
	"login_init":        {models.Unauthenticated, "login"},
	"login_head":        {models.Unauthenticated, "login"},
	"login_form":        {models.Unauthenticated, "login"},
	"login_errors":      {models.Unauthenticated, "login"},
	"authenticate":      {models.Unauthenticated, "login"},
	"wp_authenticate":   {models.Unauthenticated, "login"},
	"register_form":     {models.Unauthenticated, "login"},
	"register_post":     {models.Unauthenticated, "login"},
	"lostpassword_post": {models.Unauthenticated, "login"},
	"password_reset":    {models.Unauthenticated, "login"},

	// -- wp-comments-post.php, which accepts a comment from an anonymous visitor
	// whenever the site allows unregistered commenting.
	"pre_comment_on_post": {models.Unauthenticated, "comments"},
	"comment_post":        {models.Unauthenticated, "comments"},

	// -- media pipeline. These fire from INSIDE core functions that are ordinary
	// public API -- wp_delete_attachment(), _wp_handle_upload(),
	// media_handle_upload(), wp_generate_attachment_metadata() -- so the hook
	// fires wherever those are called, including from a front-end submission
	// handler in this plugin, in another plugin, or in the theme. "Core only
	// fires it behind capability C" is therefore FALSE for this family, and the
	// honest floor is Unauthenticated. Reporting the wp-admin caller's capability
	// here would be a privilege claim about code an anonymous upload path can
	// reach.
	"wp_handle_upload":                {models.Unauthenticated, "media"},
	"wp_handle_upload_prefilter":      {models.Unauthenticated, "media"},
	"wp_check_filetype_and_ext":       {models.Unauthenticated, "media"},
	"upload_mimes":                    {models.Unauthenticated, "media"},
	"wp_generate_attachment_metadata": {models.Unauthenticated, "media"},
	"add_attachment":                  {models.Unauthenticated, "media"},
	"attachment_updated":              {models.Unauthenticated, "media"},
	"delete_attachment":               {models.Unauthenticated, "media"},
	"attachment_fields_to_edit":       {models.Unauthenticated, "media"},
	"attachment_fields_to_save":       {models.Unauthenticated, "media"},

	// -- wp-admin screen render. Core fires these only while drawing a wp-admin
	// screen, behind that screen's own gate: wp-admin/edit.php wp_die()s unless
	// current_user_can( $post_type_object->cap->edit_posts ), and wp-admin/post.php
	// wp_die()s unless current_user_can( 'edit_post', $post_id ) before
	// edit-form-advanced.php fires the editor hooks. For the core post types both
	// resolve to edit_posts, which is Contributor.
	//
	// A plugin CAN fire one of these itself from a public page; 7 of the 143
	// corpus plugins do. That case is handled by the self-fire companion endpoint
	// below rather than by lowering the whole family.
	"manage_posts_columns":        {models.Contributor, "admin_screen"},
	"manage_pages_columns":        {models.Contributor, "admin_screen"},
	"manage_posts_custom_column":  {models.Contributor, "admin_screen"},
	"manage_pages_custom_column":  {models.Contributor, "admin_screen"},
	"post_row_actions":            {models.Contributor, "admin_screen"},
	"page_row_actions":            {models.Contributor, "admin_screen"},
	"restrict_manage_posts":       {models.Contributor, "admin_screen"},
	"quick_edit_custom_box":       {models.Contributor, "admin_screen"},
	"bulk_edit_custom_box":        {models.Contributor, "admin_screen"},
	"add_meta_boxes":              {models.Contributor, "admin_screen"},
	"dbx_post_advanced":           {models.Contributor, "admin_screen"},
	"post_submitbox_misc_actions": {models.Contributor, "admin_screen"},
	"edit_form_top":               {models.Contributor, "admin_screen"},
	"edit_form_after_title":       {models.Contributor, "admin_screen"},
	"edit_form_advanced":          {models.Contributor, "admin_screen"},
	"edit_form_after_editor":      {models.Contributor, "admin_screen"},
	"edit_form_before_permalink":  {models.Contributor, "admin_screen"},
	// The comment list table is drawn by wp-admin/edit-comments.php. Its gate is
	// not one this file can assert from core semantics alone, so the level here is
	// only the floor every wp-admin screen shares: wp-admin/admin.php calls
	// auth_redirect() before any screen renders.
	"comment_row_actions": {models.Subscriber, "admin_screen"},
}

// adminScreenHookTemplates are the core screen hooks whose name embeds a post
// type or screen id, written with "*" for the interpolated segment. Order is
// most specific first, because "manage_*_columns" would otherwise swallow
// "manage_*_posts_columns".
//
// A registration on one of these is Contributor only when the interpolated
// segment is literally a core post type, because for a custom post type
// wp-admin/edit.php gates on that type's own mapped capability, which the site
// may have granted to any role. Otherwise the level is the wp-admin floor,
// Subscriber. Guessing Contributor for a CPT screen would be over-restriction
// derived from a capability name this file cannot see; 69 of the 143 corpus
// plugins register a post type with a custom capability_type.
var adminScreenHookTemplates = []string{
	"manage_*_posts_custom_column",
	"manage_*_posts_columns",
	"manage_*_sortable_columns",
	"manage_edit-*_columns",
	"manage_*_custom_column",
	"manage_*_columns",
	"add_meta_boxes_*",
}

// coreScreenHookInstances are the fully literal spellings of the templates above
// that name a core post type, and therefore carry core's own edit_posts gate.
var coreScreenHookInstances = map[string]bool{
	"manage_post_posts_custom_column":   true,
	"manage_page_posts_custom_column":   true,
	"manage_post_posts_columns":         true,
	"manage_page_posts_columns":         true,
	"manage_edit-post_columns":          true,
	"manage_edit-page_columns":          true,
	"manage_edit-post_sortable_columns": true,
	"manage_edit-page_sortable_columns": true,
	"add_meta_boxes_post":               true,
	"add_meta_boxes_page":               true,
}

// Package-level compiled regex patterns for hook input detection
var (
	// Patterns to detect direct superglobal access in callbacks
	// $_POST['field'], $_GET['field'], $_REQUEST['field'], $_SERVER['REQUEST_URI'], etc.
	hookSuperglobalAccessPattern = regexp.MustCompile(
		`\$_(POST|GET|REQUEST|SERVER)\s*\[\s*['"]([^'"]+)['"]\s*\]`,
	)

	// get_query_var('var') - WordPress function for accessing query variables
	hookGetQueryVarPattern = regexp.MustCompile(
		`get_query_var\s*\(`,
	)

	// filter_input(INPUT_POST, 'field'), filter_input(INPUT_GET, 'field')
	hookFilterInputAccessPattern = regexp.MustCompile(
		`filter_input\s*\(\s*INPUT_(POST|GET|REQUEST)\s*,\s*['"]([^'"]+)['"]`,
	)

	// $_SERVER['REQUEST_METHOD'] === 'POST' check
	hookRequestMethodPattern = regexp.MustCompile(
		`\$_SERVER\s*\[\s*['"]REQUEST_METHOD['"]\s*\]\s*===?\s*['"](POST|GET)['"]`,
	)

	// Direct $_POST or $_GET variable check (without field)
	hookDirectSuperglobalPattern = regexp.MustCompile(
		`(?:isset|empty|!empty)\s*\(\s*\$_(POST|GET|REQUEST)\s*\)`,
	)

	// The registration call itself. One scan over the file finds every
	// registration on every hook; the arguments are then read with the same
	// balanced-delimiter parser the admin-page detector uses, which is what makes
	// the callback shapes and the sprintf/interpolated hook names tractable at
	// all. Building one regex per (hook, shape) pair, as this file used to, could
	// never match a hook name that is not a literal.
	hookCallSitePattern = regexp.MustCompile(`\badd_(?:action|filter)\s*\(`)

	// do_action / apply_filters, so a plugin that fires a core screen hook itself
	// can be told from one that only listens for core to fire it.
	hookFiringPattern = regexp.MustCompile(`\b(?:do_action|do_action_ref_array|apply_filters|apply_filters_ref_array)\s*\(`)

	// A bare PHP identifier, used to accept a method name out of a callable.
	hookIdentPattern = regexp.MustCompile(`^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$`)

	// A class name, optionally namespace-qualified.
	hookClassNamePattern = regexp.MustCompile(`^\\?[A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*$`)

	// 'Class::method' written as one string.
	hookStaticStringPattern = regexp.MustCompile(`^\\?([A-Za-z_][A-Za-z0-9_\\]*)::([A-Za-z_][A-Za-z0-9_]*)$`)

	// A closure or arrow function passed inline.
	hookClosureArgPattern = regexp.MustCompile(`^(?:static\s+)?(?:function\s*(?:&\s*)?\(|fn\s*(?:&\s*)?\()`)

	// printf-style placeholders inside an interpolated hook name: %s, %d, %1$s.
	hookPrintfSpecPattern = regexp.MustCompile(`%[0-9]*\$?[a-zA-Z]`)

	// "{$this->post_type}" and "$post_type" inside a double-quoted hook name.
	hookInterpolationPattern = regexp.MustCompile(`\{\$[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)*`)

	// The shape a normalised hook name must have to be looked up at all.
	hookNameShapePattern = regexp.MustCompile(`^[A-Za-z0-9_*/-]+$`)

	// A hook argument that is nothing but a local variable, whose value has to be
	// looked for in the assignment that precedes the registration.
	hookLocalVarPattern = regexp.MustCompile(`^\$([a-zA-Z_][a-zA-Z0-9_]*)$`)
)

// callbackShape records how the callback was spelled, which is what decides
// whether the receiving class is knowable and whether this registration is one
// the detector already covered.
type callbackShape int

const (
	shapeNone callbackShape = iota
	// shapeFunctionName: add_action( 'h', 'my_function' )
	shapeFunctionName
	// shapeStaticString: add_action( 'h', 'Cls::method' )
	shapeStaticString
	// shapeThis: add_action( 'h', [ $this, 'm' ] ) and array( &$this, 'm' )
	shapeThis
	// shapeSelfStatic: [ __CLASS__, 'm' ], [ self::class, 'm' ], [ static, 'm' ]
	shapeSelfStatic
	// shapeNamedClass: [ 'Cls', 'm' ], [ Cls::class, 'm' ]
	shapeNamedClass
	// shapeObjectExpr: [ $var, 'm' ], [ $this->loader, 'm' ], [ Foo::instance(), 'm' ]
	shapeObjectExpr
	// shapeClosure: an inline function or arrow function
	shapeClosure
)

// hookCallback is one parsed registration argument.
type hookCallback struct {
	Shape  callbackShape
	Method string // bare method or function name; "" for a closure
	Class  string // the class named by the spelling, when it names one
	Raw    string // the object expression, kept so legacy spellings can be told apart
}

// DetectHookInputEndpoints finds callbacks registered on WordPress core hooks and
// reports each as an endpoint.
//
// Reachability is objective one. A callback on a core hook is code that runs when
// that hook fires, and whether the callback's own body happens to mention $_POST
// says nothing about whether it runs -- the data may arrive as a hook argument,
// through a query var, or one call deeper in another file. This detector used to
// require a superglobal in the callback body IN THE SAME FILE before it would
// emit anything, which turned a triage heuristic into a reachability criterion
// and reduced 4,168 registrations across the corpus to 575 endpoints. The input
// test survives, but only to decide the LEVEL (see hookEndpointLevel) and as
// metadata in RawCode.
func DetectHookInputEndpoints(content, filepath, pluginSlug string) []models.Endpoint {
	var endpoints []models.Endpoint

	classRanges := findClassRanges(content)
	selfFired := hooksFiredInFile(content)

	// Deduplicate within the file. Across files the route carries the file name,
	// so two classes that both register `init` no longer collapse onto one
	// endpoint in deduplicateEndpoints.
	seen := make(map[string]bool)

	// Line numbers are counted incrementally. FindAllStringIndex yields matches in
	// increasing order, so counting newlines from the previous match keeps the
	// whole loop linear in the file; counting from the start each time would be
	// quadratic, and the largest corpus plugins have hundreds of registrations in
	// one file.
	lineNum, scanned := 1, 0

	for _, loc := range hookCallSitePattern.FindAllStringIndex(content, -1) {
		lineNum += countLines(content[scanned:loc[0]])
		scanned = loc[0]

		args := parseBalancedArgs(content, loc[1])
		if len(args) < 2 {
			continue
		}
		hookName := resolveHookName(args[0], content, loc[0])
		if hookName == "" {
			continue
		}
		spec, ok := lookupHookSpec(hookName)
		if !ok {
			continue
		}

		cb := parseHookCallback(args[1])
		if cb.Shape == shapeNone {
			continue
		}

		callback := hookCallbackName(cb, loc[0], classRanges)
		if callback == "" {
			continue
		}

		// Closures all share one callback sentinel, so they are keyed on where
		// they were registered instead. Keying them on the name collapsed every
		// inline registration on one hook in one file into a single endpoint
		// carrying a single body.
		key := hookName + ":" + callback
		if cb.Shape == shapeClosure {
			key += "@" + strconv.Itoa(loc[0])
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		body := hookCallbackBody(cb, content, loc[0])
		fields, handlesInput := hookInputEvidence(body)

		fieldInfo := ""
		if len(fields) > 0 {
			fieldInfo = "[" + strings.Join(fields, ", ") + "]"
		}

		route := hookName + ":" + callback + "@" + filepath
		if cb.Shape == shapeClosure {
			route = hookName + ":closure@" + filepath + ":" + strconv.Itoa(lineNum)
		}

		endpoints = append(endpoints, models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeHookInput,
			Route:      route,
			Method:     "POST/GET",
			AuthLevel:  hookEndpointLevel(hookName, spec, cb, body, handlesInput),
			Callback:   callback,
			File:       filepath,
			Line:       lineNum,
			RawCode:    fieldInfo,
			Namespace:  spec.Context,
		})

		// A screen hook that this plugin fires itself is no longer gated by the
		// wp-admin screen that normally fires it: do_action() runs the callback
		// wherever the call sits, which may be a public page. Core is the only
		// other firer, so "core's gate, unless this plugin fires it too" is
		// exhaustive -- and the cheaper of the two endpoints is what
		// min-over-endpoints will use.
		if spec.Level > models.Unauthenticated && selfFired[hookName] {
			endpoints = append(endpoints, models.Endpoint{
				PluginSlug: pluginSlug,
				Type:       models.EndpointTypeHookInput,
				Route:      route + ":selffired",
				Method:     "POST/GET",
				AuthLevel:  models.Unauthenticated,
				Callback:   callback,
				File:       filepath,
				Line:       lineNum,
				RawCode:    fieldInfo,
				Namespace:  spec.Context + ":selffired",
			})
		}
	}

	return endpoints
}

// hookEndpointLevel decides what privilege to report for one hook callback.
//
// The default is the level of the hook's cheapest core firing path, which for
// almost every hook here is Unauthenticated: the hook fires for anyone, and a
// capability check inside the callback body restricts what runs NEXT rather than
// who may call it. Reading the body's own guard as the endpoint's level is how a
// lifecycle-hook callback carrying a current_user_can() came to be the sole
// evidence for a vulnerability whose truth is unauthenticated.
//
// The single exception preserves the answers this detector already gave: a
// registration that the old five patterns matched, on one of the ten hooks the old
// list contained, spelled with add_action, whose body does read request input,
// keeps its inferred level. That is the whole of the endpoint set that existed
// before this file was widened, so no hook_input answer already in the benchmark
// moves, and every endpoint the widening adds is a seed at Unauthenticated that
// cannot manufacture an over-restriction.
func hookEndpointLevel(hookName string, spec hookSpec, cb hookCallback, body string, handlesInput bool) models.AuthLevel {
	if handlesInput && body != "" && legacyLifecycleHooks[hookName] && isLegacyCallbackShape(cb) {
		return InferAuthLevel(body)
	}
	return spec.Level
}

// isLegacyCallbackShape reports whether this spelling is one of the five the
// detector matched before the widening: a quoted function name, a quoted
// Class::method, [ $this, 'm' ] without a reference sigil, [ __CLASS__, 'm' ],
// or an inline closure.
func isLegacyCallbackShape(cb hookCallback) bool {
	switch cb.Shape {
	case shapeFunctionName, shapeStaticString, shapeClosure:
		return true
	case shapeThis:
		return !strings.Contains(cb.Raw, "&")
	case shapeSelfStatic:
		return strings.Contains(cb.Raw, "__CLASS__")
	}
	return false
}

// hookCallbackName is the string the endpoint carries as its callback, and the
// key every downstream walk uses.
//
// Where the spelling names a class, the class is used. Both the call graph
// (lookupFunctionBody) and the benchmark harness (CleanCallback) reduce a
// qualified name to its bare tail before matching, so qualifying costs nothing
// and stops a bare `init` or `render` from being satisfied by a same-named method
// of an unrelated class: 2,123 of the registrations these shapes match carry a
// method name declared in more than one file of the same plugin.
func hookCallbackName(cb hookCallback, offset int, classRanges map[string][2]int) string {
	switch cb.Shape {
	case shapeClosure:
		// "closure" is the sentinel GetRecursiveCallsForCallback recognises, and
		// recognising it is what lets the walk fall back to the closures
		// registered in this file. "anonymous", which this detector used to emit,
		// is a sentinel to the harness but not to the walk, so it reached nothing.
		return "closure"
	case shapeFunctionName, shapeObjectExpr:
		return cb.Method
	case shapeStaticString, shapeNamedClass:
		return cb.Class + "::" + cb.Method
	case shapeThis, shapeSelfStatic:
		if class := findEnclosingClass(offset, classRanges); class != "" {
			return class + "::" + cb.Method
		}
		return cb.Method
	}
	return ""
}

// hookCallbackBody finds the callback's body in this file, or "" when the body is
// somewhere else. An empty body no longer suppresses the endpoint -- that is
// exactly the cross-file case reachability needs most -- it only means the level
// falls back to the hook's own.
func hookCallbackBody(cb hookCallback, content string, offset int) string {
	if cb.Shape == shapeClosure {
		return extractAnonHookBodyAt(content, offset)
	}
	if cb.Method == "" {
		return ""
	}
	return findFunctionBody(cb.Method, content)
}

// hookInputEvidence reports the request fields a body reads, and whether it shows
// any sign of handling request input at all.
func hookInputEvidence(body string) ([]string, bool) {
	if body == "" {
		return nil, false
	}
	fields := extractHookInputFields(body)
	handles := len(fields) > 0 ||
		hookRequestMethodPattern.MatchString(body) ||
		hookDirectSuperglobalPattern.MatchString(body) ||
		hookGetQueryVarPattern.MatchString(body)
	return fields, handles
}

// lookupHookSpec resolves a normalised hook name to the privilege of its cheapest
// core firing path.
func lookupHookSpec(hookName string) (hookSpec, bool) {
	if spec, ok := coreHookSpecs[hookName]; ok {
		return spec, true
	}
	for _, tpl := range adminScreenHookTemplates {
		if !globMatchHookName(tpl, hookName) {
			continue
		}
		if coreScreenHookInstances[hookName] {
			return hookSpec{models.Contributor, "admin_screen"}, true
		}
		return hookSpec{models.Subscriber, "admin_screen"}, true
	}
	return hookSpec{}, false
}

// globMatchHookName matches a hook name against a template containing exactly one
// "*", which stands for the interpolated post type or screen id. The wildcard
// must match at least one character, so "manage_*_columns" does not match the
// literal "manage__columns".
func globMatchHookName(template, name string) bool {
	star := strings.IndexByte(template, '*')
	if star < 0 {
		return template == name
	}
	prefix, suffix := template[:star], template[star+1:]
	if len(name) <= len(prefix)+len(suffix) {
		return false
	}
	return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
}

// resolveHookName is normalizeHookName plus one hop through a local variable.
//
// PHP evaluates the argument, so
//
//	$action = sprintf( "manage_%s_posts_custom_column", $type );
//	add_action( $action, [ $this, 'render_value' ], 10, 2 );
//
// registers on exactly the hook the inline spelling would. Building the name into
// a variable first is the idiomatic way to write a screen-hook registration,
// because the same string is usually wanted again for did_action() or
// remove_action(), and refusing to follow it lost the whole construct.
//
// The search is bounded and takes the NEAREST preceding assignment, which is the
// one in scope at a call site below it. A resolution that lands on the wrong
// assignment yields a name that either fails to classify -- in which case nothing
// is emitted, exactly as before -- or classifies as some other core hook, in which
// case the endpoint is a seed at that hook's level. Only the wp-admin screen family
// carries a level above Unauthenticated, so the worst this can do is report one or
// two levels for an endpoint that would otherwise not exist at all.
func resolveHookName(raw, content string, callPos int) string {
	if name := normalizeHookName(raw); name != "" {
		return name
	}
	m := hookLocalVarPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if m == nil {
		return ""
	}
	rhs := lastLocalAssignment(m[1], content, callPos)
	if rhs == "" {
		return ""
	}
	return normalizeHookName(rhs)
}

// lastLocalAssignment returns the right-hand side of the nearest `$name = ...;`
// that precedes callPos, searching a bounded window backwards.
func lastLocalAssignment(name, content string, callPos int) string {
	const window = 2000
	start := callPos - window
	if start < 0 {
		start = 0
	}
	needle := "$" + name
	best := -1
	for i := start; i < callPos; {
		j := strings.Index(content[i:callPos], needle)
		if j < 0 {
			break
		}
		at := i + j
		i = at + len(needle)
		// Reject a longer identifier that merely begins with this name.
		if at+len(needle) < len(content) && isIdentByte(content[at+len(needle)]) {
			continue
		}
		k := skipSpace(content, at+len(needle))
		// A single "=", not "==", "===", "=>" or a comparison ending in "=".
		if k >= len(content) || content[k] != '=' {
			continue
		}
		if k+1 < len(content) && (content[k+1] == '=' || content[k+1] == '>') {
			continue
		}
		if at > 0 && (content[at-1] == '=' || content[at-1] == '!' || content[at-1] == '<' || content[at-1] == '>') {
			continue
		}
		best = k + 1
	}
	if best < 0 {
		return ""
	}
	end := statementEnd(content, best)
	if end <= best {
		return ""
	}
	return strings.TrimSpace(content[best:end])
}

// statementEnd finds the ";" that ends the expression starting at pos, ignoring
// semicolons inside string literals or nested delimiters.
func statementEnd(content string, pos int) int {
	depth := 0
	for i := pos; i < len(content) && i-pos < 2000; i++ {
		switch c := content[i]; c {
		case '\'', '"':
			j := skipString(content, i)
			if j < 0 {
				return -1
			}
			i = j
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth < 0 {
				return i
			}
		case ';':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// normalizeHookName reduces the first argument of a registration to a comparable
// hook name, collapsing everything the plugin computes at runtime to "*".
//
// It handles the four spellings plugins use for a hook name whose screen or post
// type varies: a plain literal, a double-quoted string with "{$var}" in it,
// sprintf() with a %s, and string concatenation. All four denote the same family
// of core hook, so all four must normalise to the same template.
func normalizeHookName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// sprintf( 'manage_%s_posts_custom_column', $type ) -> its format string.
	if lower := strings.ToLower(raw); strings.HasPrefix(lower, "sprintf") {
		if inner := splitCallableArgs("array" + strings.TrimSpace(raw)[len("sprintf"):]); len(inner) > 0 {
			raw = inner[0]
		}
	}

	var b strings.Builder
	pendingWildcard := false
	for i := 0; i < len(raw); {
		c := raw[i]
		switch {
		case c == '\'' || c == '"':
			end := skipString(raw, i)
			if end < 0 || end >= len(raw) {
				return ""
			}
			if pendingWildcard {
				b.WriteByte('*')
				pendingWildcard = false
			}
			b.WriteString(interpolationToWildcard(raw[i+1 : end]))
			i = end + 1
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '.':
			i++
		default:
			pendingWildcard = true
			i++
		}
	}
	if pendingWildcard {
		b.WriteByte('*')
	}

	name := collapseWildcards(b.String())
	if name == "" || name == "*" || !hookNameShapePattern.MatchString(name) {
		return ""
	}
	return name
}

// interpolationToWildcard replaces the parts of a string literal that PHP or
// sprintf would substitute at runtime with a single wildcard token.
//
// The printf specifiers go first: "%1$s" is a positional specifier, and letting
// the PHP-interpolation pattern see it first would consume the "$s" and leave a
// stray "%1" behind, which no hook name can contain.
func interpolationToWildcard(lit string) string {
	lit = hookPrintfSpecPattern.ReplaceAllString(lit, "*")
	return hookInterpolationPattern.ReplaceAllString(lit, "*")
}

// collapseWildcards folds runs of wildcards, and the separators between them, into
// one, so `'manage_' . $a . '_' . $b . '_columns'` and "manage_{$x}_columns" agree.
func collapseWildcards(s string) string {
	var b strings.Builder
	lastStar := false
	for i := 0; i < len(s); i++ {
		if s[i] == '*' {
			if !lastStar {
				b.WriteByte('*')
			}
			lastStar = true
			continue
		}
		if lastStar && s[i] == '_' {
			// "*_*" collapses to "*": the separator belongs to the runtime part.
			if j := i + 1; j < len(s) && s[j] == '*' {
				continue
			}
		}
		b.WriteByte(s[i])
		lastStar = false
	}
	return b.String()
}

// parseHookCallback classifies the second argument of a registration.
func parseHookCallback(raw string) hookCallback {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return hookCallback{}
	}

	if hookClosureArgPattern.MatchString(raw) {
		return hookCallback{Shape: shapeClosure, Raw: raw}
	}

	if unquoted, ok := unquotePHPString(raw); ok {
		if m := hookStaticStringPattern.FindStringSubmatch(unquoted); m != nil {
			return hookCallback{Shape: shapeStaticString, Class: strings.TrimPrefix(m[1], "\\"), Method: m[2], Raw: raw}
		}
		if hookIdentPattern.MatchString(unquoted) {
			return hookCallback{Shape: shapeFunctionName, Method: unquoted, Raw: raw}
		}
		return hookCallback{}
	}

	// PHP's array callable, in either spelling. [$obj,'m'], [&$obj,'m'],
	// ['Cls','m'] and [Cls::class,'m'] are the same callable type and PHP invokes
	// them identically, so a detector that recognises one and not the others is
	// matching text rather than semantics.
	parts := splitCallableArgs(raw)
	if len(parts) < 2 {
		return hookCallback{}
	}
	method, ok := unquotePHPString(parts[1])
	if !ok || !hookIdentPattern.MatchString(method) {
		return hookCallback{}
	}
	obj := strings.TrimSpace(parts[0])
	bare := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(obj), "&"))

	switch {
	case bare == "$this":
		return hookCallback{Shape: shapeThis, Method: method, Raw: obj}
	case bare == "__CLASS__" || bare == "self" || bare == "static" ||
		bare == "self::class" || bare == "static::class":
		return hookCallback{Shape: shapeSelfStatic, Method: method, Raw: obj}
	}
	if lit, ok := unquotePHPString(bare); ok {
		if lit == "self" || lit == "static" {
			return hookCallback{Shape: shapeSelfStatic, Method: method, Raw: obj}
		}
		if hookClassNamePattern.MatchString(lit) {
			return hookCallback{Shape: shapeNamedClass, Class: strings.TrimPrefix(lit, "\\"), Method: method, Raw: obj}
		}
		return hookCallback{}
	}
	if strings.HasSuffix(bare, "::class") {
		class := strings.TrimSuffix(bare, "::class")
		if hookClassNamePattern.MatchString(class) {
			return hookCallback{Shape: shapeNamedClass, Class: strings.TrimPrefix(class, "\\"), Method: method, Raw: obj}
		}
	}

	// A receiving object this file cannot name: $loader, $this->handler,
	// Foo::instance(). The bare method name is still the call graph's key, so the
	// registration is worth reporting -- but only as an Unauthenticated seed,
	// which is what hookEndpointLevel gives every non-legacy shape.
	return hookCallback{Shape: shapeObjectExpr, Method: method, Raw: obj}
}

// splitCallableArgs splits the contents of an array literal, in either PHP
// spelling, into its top-level elements.
func splitCallableArgs(raw string) []string {
	raw = strings.TrimSpace(raw)
	var inner string
	switch {
	case strings.HasPrefix(raw, "["):
		end := matchDelimiter(raw, 0, '[', ']')
		if end < 0 {
			return nil
		}
		inner = raw[1:end]
	default:
		open := strings.IndexByte(raw, '(')
		if open < 0 || !strings.EqualFold(strings.TrimSpace(raw[:open]), "array") {
			return nil
		}
		end := matchDelimiter(raw, open, '(', ')')
		if end < 0 {
			return nil
		}
		inner = raw[open+1 : end]
	}
	return parseBalancedArgs(inner+")", 0)
}

// unquotePHPString returns the contents of a single-quoted or double-quoted PHP
// string literal, and false when the text is not one literal.
func unquotePHPString(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 {
		return "", false
	}
	q := raw[0]
	if q != '\'' && q != '"' {
		return "", false
	}
	end := skipString(raw, 0)
	if end != len(raw)-1 {
		return "", false
	}
	return raw[1:end], true
}

// hooksFiredInFile is the set of normalised hook names this file fires itself with
// do_action or apply_filters.
func hooksFiredInFile(content string) map[string]bool {
	fired := make(map[string]bool)
	for _, loc := range hookFiringPattern.FindAllStringIndex(content, -1) {
		args := parseBalancedArgs(content, loc[1])
		if len(args) == 0 {
			continue
		}
		if name := normalizeHookName(args[0]); name != "" {
			fired[name] = true
		}
	}
	return fired
}

// extractHookInputFields extracts all POST/GET/REQUEST field names from hook callback code
func extractHookInputFields(code string) []string {
	fields := make(map[string]bool)

	// $_POST['field'], $_GET['field'], $_REQUEST['field']
	for _, m := range hookSuperglobalAccessPattern.FindAllStringSubmatch(code, -1) {
		if len(m) >= 3 {
			fields[m[1]+":"+m[2]] = true
		}
	}

	// filter_input(INPUT_POST, 'field')
	for _, m := range hookFilterInputAccessPattern.FindAllStringSubmatch(code, -1) {
		if len(m) >= 3 {
			fields[m[1]+":"+m[2]] = true
		}
	}

	// Convert to slice
	result := make([]string, 0, len(fields))
	for f := range fields {
		result = append(result, f)
	}
	return result
}

// extractAnonHookBodyAt extracts the body of the closure registered at a specific
// call site.
//
// Taking the first closure in the file for every anonymous registration, as this
// used to, meant that a file registering several closures on the same hook
// reported one endpoint carrying one body; 147 registrations in 50 corpus plugins
// are inline closures.
func extractAnonHookBodyAt(content string, callPos int) string {
	if callPos < 0 || callPos >= len(content) {
		return ""
	}
	limit := callPos + 2000
	if limit > len(content) {
		limit = len(content)
	}
	// String literals are skipped, because a hook name written with PHP
	// interpolation -- "manage_{$type}_columns" -- puts a brace in the argument
	// list ahead of the closure's own.
	for i := callPos; i < limit; i++ {
		switch content[i] {
		case '\'', '"':
			j := skipString(content, i)
			if j < 0 {
				return ""
			}
			i = j
		case '{':
			return extractBracedContent(content, i)
		}
	}
	return ""
}

// DetectHookInputEndpointsWithAST wraps DetectHookInputEndpoints with AST-backed
// cross-file callback resolution.
//
// The textual pass now emits an endpoint for every registration it can name,
// including the ones whose body lives in another file, so this pass has little
// left to add. What it still fixes is the callback reference it builds: a method
// name was sent to the resolver as Type "function", and the resolver's "function"
// branch searches only SymTable.Functions while methods are filed under
// Classes[..].Methods -- so the single most common registration shape in
// WordPress could never be resolved here. Endpoints it adds are seeds at
// Unauthenticated, for the same reason the textual pass's are: the hook fires for
// whoever core fires it for, not for whoever the body would admit.
func DetectHookInputEndpointsWithAST(content, filepath, pluginSlug string, astCtx *wpast.ASTContext) []models.Endpoint {
	endpoints := DetectHookInputEndpoints(content, filepath, pluginSlug)

	if astCtx == nil || !astCtx.Available {
		return endpoints
	}

	classRanges := findClassRanges(content)
	for _, loc := range hookCallSitePattern.FindAllStringIndex(content, -1) {
		args := parseBalancedArgs(content, loc[1])
		if len(args) < 2 {
			continue
		}
		hookName := resolveHookName(args[0], content, loc[0])
		if hookName == "" {
			continue
		}
		spec, ok := lookupHookSpec(hookName)
		if !ok {
			continue
		}
		cb := parseHookCallback(args[1])
		if cb.Shape == shapeNone || cb.Shape == shapeClosure {
			continue
		}
		callback := hookCallbackName(cb, loc[0], classRanges)
		if callback == "" {
			continue
		}

		alreadyDetected := false
		for _, ep := range endpoints {
			if ep.Callback == callback && strings.HasPrefix(ep.Route, hookName+":") {
				alreadyDetected = true
				break
			}
		}
		if alreadyDetected {
			continue
		}

		ref := wpast.CallbackRef{Type: "function", FuncName: cb.Method, File: filepath}
		switch cb.Shape {
		case shapeStaticString, shapeNamedClass:
			ref = wpast.CallbackRef{Type: "static_method", ClassName: cb.Class, MethodName: cb.Method, File: filepath}
		case shapeThis, shapeSelfStatic:
			if class := findEnclosingClass(loc[0], classRanges); class != "" {
				ref = wpast.CallbackRef{Type: "method", ClassName: class, MethodName: cb.Method, File: filepath}
			}
		}

		if _, _, err := astCtx.Resolver.ResolveCallback(ref); err != nil {
			continue
		}

		endpoints = append(endpoints, models.Endpoint{
			PluginSlug: pluginSlug,
			Type:       models.EndpointTypeHookInput,
			Route:      hookName + ":" + callback + "@" + filepath,
			Method:     "POST/GET",
			AuthLevel:  spec.Level,
			Callback:   callback,
			File:       filepath,
			Line:       countLines(content[:loc[0]]) + 1,
			RawCode:    "[AST:cross-file resolution]",
			Namespace:  spec.Context,
		})
	}

	return endpoints
}

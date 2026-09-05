package ast

import (
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/hatlesswizard/wptracelib/pkg/config"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

type CallGraph struct {
	Nodes map[string]*CallGraphNode
	Edges map[string][]string
}

type CallGraphNode struct {
	FQN       string
	File      string
	Line      int
	Callees   []string
	Callers   []string
	Tainted   bool
	AuthGuard *AuthGuardInfo
}

type AuthGuardInfo struct {
	HasGuard  bool
	Level     models.AuthLevel
	GuardFunc string
	Line      int
}

type TaintSource struct {
	Variable string
	Type     string
	File     string
	Line     int
}

// TaintAnalyzer traces user input (superglobals) through call chains.
type TaintAnalyzer struct {
	SymTable  *SymbolTable
	Hierarchy *ClassHierarchy
	Graph     *CallGraph
	AST       *PluginAST
	MaxDepth  int
}

// AuthAnalyzer detects auth guards (current_user_can, is_user_logged_in)
// and analyzes REST permission_callback return values.
type AuthAnalyzer struct {
	SymTable  *SymbolTable
	Hierarchy *ClassHierarchy
	AST       *PluginAST
	MaxDepth  int
}

var superglobals = map[string]string{
	"$_GET":     "GET",
	"$_POST":    "POST",
	"$_REQUEST": "REQUEST",
	"$_COOKIE":  "COOKIE",
	"$_SERVER":  "SERVER",
	"$_FILES":   "FILES",
}

// capabilityConfig is the capability table this package resolves a
// current_user_can() argument against.
//
// It used to be a second copy of the table in pkg/config, declared here as a
// package-level map. The two disagreed -- edit_pages was Editor here and absent
// there, edit_published_posts and delete_published_posts were Author here and
// Editor there -- so a capability correction in pkg/config silently did not
// apply on this path, and an embedder's SetAuthConfig could not reach it at all.
// pkg/config imports nothing from this package, so reading the one table
// directly is both possible and the smallest fix.
var (
	capabilityConfigMu sync.RWMutex
	capabilityConfig   *config.Config
)

// defaultCapabilityConfig builds the stock WordPress table once. config.New()
// allocates the whole configuration, so it is not something to call per lookup.
var defaultCapabilityConfig = sync.OnceValue(config.New)

// SetCapabilityConfig points this package at a caller-supplied capability
// table. Passing nil restores the WordPress core defaults.
func SetCapabilityConfig(cfg *config.Config) {
	capabilityConfigMu.Lock()
	capabilityConfig = cfg
	capabilityConfigMu.Unlock()
}

// capabilityLevel resolves a capability name to the lowest core role that holds
// it, exactly as pkg/config does for every other code path.
func capabilityLevel(capability string) (models.AuthLevel, bool) {
	capabilityConfigMu.RLock()
	cfg := capabilityConfig
	capabilityConfigMu.RUnlock()

	if cfg == nil {
		cfg = defaultCapabilityConfig()
	}
	return cfg.GetCapabilityLevel(capability)
}

// BuildCallGraph walks every function/method body in the symbol table, finds
// function_call_expression and member_call_expression nodes, resolves callee
// FQN, and populates edges.
func BuildCallGraph(st *SymbolTable, pluginAST *PluginAST) *CallGraph {
	cg := &CallGraph{
		Nodes: make(map[string]*CallGraphNode),
		Edges: make(map[string][]string),
	}

	for fqn, fn := range st.Functions {
		cg.Nodes[fqn] = &CallGraphNode{FQN: fqn, File: fn.File, Line: fn.Line}
	}
	for _, cls := range st.Classes {
		for _, method := range cls.Methods {
			fqn := cls.FQN + "::" + method.Name
			cg.Nodes[fqn] = &CallGraphNode{FQN: fqn, File: method.File, Line: method.Line}
		}
	}

	for fqn, fn := range st.Functions {
		if fn.BodyNode == nil {
			continue
		}
		pf := pluginAST.Files[fn.File]
		if pf == nil {
			continue
		}
		callees := extractCallees(fn.BodyNode, pf.Source, st, "")
		cg.Edges[fqn] = callees
		if node := cg.Nodes[fqn]; node != nil {
			node.Callees = callees
		}
		for _, callee := range callees {
			if node := cg.Nodes[callee]; node != nil {
				node.Callers = append(node.Callers, fqn)
			}
		}
	}

	for _, cls := range st.Classes {
		for _, method := range cls.Methods {
			if method.BodyNode == nil {
				continue
			}
			fqn := cls.FQN + "::" + method.Name
			pf := pluginAST.Files[method.File]
			if pf == nil {
				continue
			}
			callees := extractCallees(method.BodyNode, pf.Source, st, cls.FQN)
			cg.Edges[fqn] = callees
			if node := cg.Nodes[fqn]; node != nil {
				node.Callees = callees
			}
			for _, callee := range callees {
				if node := cg.Nodes[callee]; node != nil {
					node.Callers = append(node.Callers, fqn)
				}
			}
		}
	}

	return cg
}

func extractCallees(node *sitter.Node, source []byte, st *SymbolTable, classFQN string) []string {
	var callees []string
	seen := make(map[string]bool)
	walkForCalls(node, source, st, classFQN, &callees, seen)
	return callees
}

func walkForCalls(node *sitter.Node, source []byte, st *SymbolTable, classFQN string, callees *[]string, seen map[string]bool) {
	if node == nil {
		return
	}

	switch node.Type() {
	case "function_call_expression":
		fqn := resolveFunctionCallFQN(node, source, st)
		if fqn != "" && !seen[fqn] {
			seen[fqn] = true
			*callees = append(*callees, fqn)
		}

	case "member_call_expression":
		fqn := resolveMemberCallFQN(node, source, st, classFQN)
		if fqn != "" && !seen[fqn] {
			seen[fqn] = true
			*callees = append(*callees, fqn)
		}

	case "scoped_call_expression":
		fqn := resolveScopedCallFQN(node, source, st, classFQN)
		if fqn != "" && !seen[fqn] {
			seen[fqn] = true
			*callees = append(*callees, fqn)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		walkForCalls(node.Child(i), source, st, classFQN, callees, seen)
	}
}

func resolveFunctionCallFQN(node *sitter.Node, source []byte, st *SymbolTable) string {
	funcNode := node.ChildByFieldName("function")
	if funcNode == nil {
		return ""
	}
	name := nodeText(funcNode, source)
	if name == "" {
		return ""
	}

	if _, ok := st.Functions[name]; ok {
		return name
	}

	for fqn := range st.Functions {
		parts := strings.Split(fqn, `\`)
		if parts[len(parts)-1] == name {
			return fqn
		}
	}
	return ""
}

func resolveMemberCallFQN(node *sitter.Node, source []byte, st *SymbolTable, classFQN string) string {
	obj := node.ChildByFieldName("object")
	nameNode := node.ChildByFieldName("name")
	if obj == nil || nameNode == nil {
		return ""
	}

	objText := nodeText(obj, source)
	methodName := nodeText(nameNode, source)

	if objText == "$this" && classFQN != "" {
		return classFQN + "::" + methodName
	}

	for _, cls := range st.Classes {
		if _, ok := cls.Methods[methodName]; ok {
			return cls.FQN + "::" + methodName
		}
	}
	return ""
}

func resolveScopedCallFQN(node *sitter.Node, source []byte, st *SymbolTable, classFQN string) string {
	scope := node.ChildByFieldName("scope")
	nameNode := node.ChildByFieldName("name")
	if scope == nil || nameNode == nil {
		return ""
	}

	scopeText := nodeText(scope, source)
	methodName := nodeText(nameNode, source)

	if scopeText == "self" || scopeText == "static" {
		if classFQN != "" {
			return classFQN + "::" + methodName
		}
		return ""
	}

	if scopeText == "parent" && classFQN != "" {
		return ""
	}

	if _, ok := st.Classes[scopeText]; ok {
		return scopeText + "::" + methodName
	}

	for fqn := range st.Classes {
		parts := strings.Split(fqn, `\`)
		if parts[len(parts)-1] == scopeText {
			return fqn + "::" + methodName
		}
	}
	return ""
}

// --- TaintAnalyzer ---

func NewTaintAnalyzer(st *SymbolTable, h *ClassHierarchy, cg *CallGraph, pluginAST *PluginAST) *TaintAnalyzer {
	return &TaintAnalyzer{
		SymTable:  st,
		Hierarchy: h,
		Graph:     cg,
		AST:       pluginAST,
		MaxDepth:  10,
	}
}

func (t *TaintAnalyzer) FunctionProcessesUserInput(funcFQN string) bool {
	return t.functionProcessesUserInputRecursive(funcFQN, 0, make(map[string]bool))
}

func (t *TaintAnalyzer) functionProcessesUserInputRecursive(funcFQN string, depth int, visited map[string]bool) bool {
	if depth > t.MaxDepth || visited[funcFQN] {
		return false
	}
	visited[funcFQN] = true

	bodyNode, source := t.getFunctionBody(funcFQN)
	if bodyNode == nil {
		return false
	}

	if containsSuperglobalAccess(bodyNode, source) {
		return true
	}

	for _, callee := range t.Graph.Edges[funcFQN] {
		if t.functionProcessesUserInputRecursive(callee, depth+1, visited) {
			return true
		}
	}

	return false
}

func (t *TaintAnalyzer) getFunctionBody(funcFQN string) (*sitter.Node, []byte) {
	if fn, ok := t.SymTable.Functions[funcFQN]; ok && fn.BodyNode != nil {
		return fn.BodyNode, t.sourceForFile(fn.File)
	}

	parts := strings.SplitN(funcFQN, "::", 2)
	if len(parts) == 2 {
		if cls, ok := t.SymTable.Classes[parts[0]]; ok {
			if m, ok := cls.Methods[parts[1]]; ok && m.BodyNode != nil {
				return m.BodyNode, t.sourceForFile(m.File)
			}
		}
	}

	return nil, nil
}

func (t *TaintAnalyzer) sourceForFile(filePath string) []byte {
	if t.AST == nil {
		return nil
	}
	if pf, ok := t.AST.Files[filePath]; ok {
		return pf.Source
	}
	return nil
}

func (t *TaintAnalyzer) GetTaintSources(funcFQN string) []TaintSource {
	bodyNode, source := t.getFunctionBodyWithSource(funcFQN)
	if bodyNode == nil {
		return nil
	}

	var sources []TaintSource
	collectTaintSources(bodyNode, source, funcFQN, &sources)
	return sources
}

func (t *TaintAnalyzer) getFunctionBodyWithSource(funcFQN string) (*sitter.Node, []byte) {
	return t.getFunctionBody(funcFQN)
}

func containsSuperglobalAccess(node *sitter.Node, source []byte) bool {
	if node == nil {
		return false
	}
	return walkForSuperglobals(node, source)
}

func walkForSuperglobals(node *sitter.Node, source []byte) bool {
	if node == nil {
		return false
	}

	switch node.Type() {
	case "subscript_expression":
		obj := node.ChildByFieldName("object")
		if obj != nil {
			objText := nodeTextFromNode(obj, source)
			if _, ok := superglobals[objText]; ok {
				return true
			}
		}

	case "variable_name":
		varText := nodeTextFromNode(node, source)
		if _, ok := superglobals[varText]; ok {
			return true
		}

	case "function_call_expression":
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			funcName := nodeTextFromNode(funcNode, source)
			if funcName == "file_get_contents" {
				args := node.ChildByFieldName("arguments")
				if args != nil {
					for i := 0; i < int(args.NamedChildCount()); i++ {
						arg := args.NamedChild(i)
						argText := nodeTextFromNode(arg, source)
						if strings.Contains(argText, "php://input") {
							return true
						}
					}
				}
			}
			if funcName == "filter_input" {
				return true
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		if walkForSuperglobals(node.Child(i), source) {
			return true
		}
	}
	return false
}

func nodeTextFromNode(node *sitter.Node, source []byte) string {
	if source == nil {
		return ""
	}
	return string(source[node.StartByte():node.EndByte()])
}

func collectTaintSources(node *sitter.Node, source []byte, file string, sources *[]TaintSource) {
	if node == nil {
		return
	}

	if node.Type() == "subscript_expression" {
		obj := node.ChildByFieldName("object")
		if obj != nil && source != nil {
			objText := nodeTextFromNode(obj, source)
			if taintType, ok := superglobals[objText]; ok {
				*sources = append(*sources, TaintSource{
					Variable: nodeTextFromNode(node, source),
					Type:     taintType,
					File:     file,
					Line:     int(node.StartPoint().Row) + 1,
				})
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		collectTaintSources(node.Child(i), source, file, sources)
	}
}

// --- AuthAnalyzer ---

func NewAuthAnalyzer(st *SymbolTable, h *ClassHierarchy, pluginAST *PluginAST) *AuthAnalyzer {
	return &AuthAnalyzer{
		SymTable:  st,
		Hierarchy: h,
		AST:       pluginAST,
		MaxDepth:  10,
	}
}

func (a *AuthAnalyzer) HasAuthGuard(funcFQN string) (bool, models.AuthLevel) {
	bodyNode, source := a.getFunctionBody(funcFQN)
	if bodyNode == nil {
		return false, models.Unauthenticated
	}

	return a.findAuthGuard(bodyNode, source)
}

func (a *AuthAnalyzer) getFunctionBody(funcFQN string) (*sitter.Node, []byte) {
	if fn, ok := a.SymTable.Functions[funcFQN]; ok && fn.BodyNode != nil {
		return fn.BodyNode, a.sourceForFile(fn.File)
	}

	parts := strings.SplitN(funcFQN, "::", 2)
	if len(parts) == 2 {
		if cls, ok := a.SymTable.Classes[parts[0]]; ok {
			if m, ok := cls.Methods[parts[1]]; ok && m.BodyNode != nil {
				return m.BodyNode, a.sourceForFile(m.File)
			}
		}
	}

	return nil, nil
}

func (a *AuthAnalyzer) sourceForFile(filePath string) []byte {
	if a.AST == nil {
		return nil
	}
	if pf, ok := a.AST.Files[filePath]; ok {
		return pf.Source
	}
	return nil
}

func (a *AuthAnalyzer) findAuthGuard(node *sitter.Node, source []byte) (bool, models.AuthLevel) {
	if node == nil {
		return false, models.Unauthenticated
	}

	var found bool
	var weakestLevel models.AuthLevel

	walkForAuthGuards(node, source, &found, &weakestLevel)
	return found, weakestLevel
}

// walkForAuthGuards records the WEAKEST authorization check anywhere in a body.
//
// It used to record the strongest, and that is unsound here, because this walker
// has no gating analysis at all: it descends the whole body and reports every
// current_user_can() it finds, whether failing that check stops the request,
// decides one branch of an if, or merely lands in a variable. A handler with an
// admin-only branch beside an unguarded vulnerable branch therefore reported
// Admin -- a reachable vulnerability that looks gated, which is exactly the
// defect the guard classifier in pkg/analyzer was written to remove.
//
// The minimum is not the semantic requirement in every case, and it is worth
// being honest about that: two checks in sequence that each end the request on
// failure are conjunctive, and there the caller genuinely needs the stronger of
// the two. What the minimum buys is the direction of the error. Reporting too
// little privilege is noise; reporting too much hides a real bug. Until this
// walker can tell a check that gates the function from a check that gates a
// branch, the weakest check found is the honest floor -- the same reasoning
// StrongestGuard applies in pkg/analyzer to checks that gate a whole function.
func walkForAuthGuards(node *sitter.Node, source []byte, found *bool, level *models.AuthLevel) {
	if node == nil {
		return
	}

	// record keeps the minimum, treating the first check found as the seed so
	// that the zero value of *level (Unauthenticated) is never mistaken for one.
	record := func(authLevel models.AuthLevel) {
		if !*found || authLevel < *level {
			*level = authLevel
		}
		*found = true
	}

	if node.Type() == "function_call_expression" {
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			funcName := nodeTextFromNode(funcNode, source)

			switch funcName {
			case "current_user_can":
				args := node.ChildByFieldName("arguments")
				if args != nil && args.NamedChildCount() > 0 {
					capArg := args.NamedChild(0)
					capStr := extractCapabilityString(capArg, source)
					if capStr != "" {
						authLevel, ok := capabilityLevel(capStr)
						if !ok {
							// A capability this table does not know is still a
							// capability, and WordPress grants no capability at
							// all to a logged-out visitor, so Subscriber is the
							// floor for one it cannot name.
							authLevel = models.Subscriber
						}
						record(authLevel)
						return
					}
				}
				record(models.Subscriber)
				return

			case "is_user_logged_in":
				// A predicate that exists only to be tested, and what it tests
				// is the caller's login state. Its presence is still not proof
				// that the body is gated on it -- that needs the control-flow
				// analysis this walker does not have -- so a body that merely
				// branches on login state can still read Subscriber. Under the
				// minimum rule it can at least no longer raise a body above a
				// capability check sitting beside it.
				record(models.Subscriber)
				return
			}

			// get_current_user_id() and wp_get_current_user() used to be counted
			// here as guards worth Subscriber. They are not guards: both return a
			// value and neither denies anything. wp_get_current_user() is how
			// every plugin READS the caller -- it hands a logged-out visitor a
			// WP_User(0) rather than refusing -- and get_current_user_id()
			// returns 0 for that same visitor. Counting them promoted any handler
			// that merely looked up who was calling:
			//
			//     function h() { $u = wp_get_current_user(); update_option( $_POST['k'], $_POST['v'] ); }
			//
			// Truth: unauthenticated. Reported before this change: subscriber.
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		walkForAuthGuards(node.Child(i), source, found, level)
	}
}

func extractCapabilityString(node *sitter.Node, source []byte) string {
	if node == nil || source == nil {
		return ""
	}

	var target *sitter.Node
	if node.Type() == "argument" && node.NamedChildCount() > 0 {
		target = node.NamedChild(0)
	} else {
		target = node
	}

	if target.Type() == "string" {
		if content := findNamedChild(target, "string_content"); content != nil {
			return nodeTextFromNode(content, source)
		}
		text := nodeTextFromNode(target, source)
		if len(text) >= 2 {
			return text[1 : len(text)-1]
		}
	}

	if target.Type() == "encapsed_string" {
		text := nodeTextFromNode(target, source)
		if len(text) >= 2 {
			return text[1 : len(text)-1]
		}
	}

	return ""
}

func (a *AuthAnalyzer) AnalyzePermissionCallback(ref CallbackRef) models.AuthLevel {
	bodyNode, source, enclosingFQN := a.resolveCallbackBody(ref)
	if bodyNode == nil {
		return models.Subscriber
	}

	return a.analyzeReturnStatements(bodyNode, source, 0, enclosingFQN)
}

// resolveCallbackBody returns the body a callback reference names, the source it
// was parsed from, and the FQN of the class that body belongs to -- "" when the
// body is not a method, or when the reference does not say which class it came
// from. That third value is what lets analyzeReturnExpression resolve a
// `return $this->m();` against the enclosing class instead of against every
// class in the plugin; see the comment at the member_call_expression case there.
func (a *AuthAnalyzer) resolveCallbackBody(ref CallbackRef) (*sitter.Node, []byte, string) {
	switch ref.Type {
	case "function":
		if fn, ok := a.SymTable.Functions[ref.FuncName]; ok && fn.BodyNode != nil {
			return fn.BodyNode, a.sourceForFile(fn.File), ""
		}

		// A callback string carries no namespace, so once the exact key misses
		// the only thing left to match on is the last segment of the FQN -- and
		// a plugin that declares the same function name under two namespaces
		// then offers two bodies with nothing in the callback to choose between
		// them. This loop used to take whichever the map handed over first. Go
		// randomises map iteration, which turned that into a coin flip per call:
		// one run reads a `return true;` body, the next reads
		// `return current_user_can('manage_options');`, and the endpoint moves
		// between unauthenticated and admin with no change to the tree or to the
		// binary. That is exactly the kind of flip that makes a benchmark
		// unreadable, because it moves keys without any edit to blame.
		//
		// Smallest FQN does not resolve the ambiguity: which body PHP would have
		// loaded depends on include order at run time and is not decidable from
		// a callback string. It makes the choice DEFINED -- a total order over
		// the plugin's own symbols that cannot move with file-walk order, map
		// seed or goroutine scheduling. Scanning for the minimum lands on the
		// same symbol a sorted key list would, for one pass and no allocation.
		//
		// Across the benchmark corpus this loop resolves nothing at all: of the
		// 1,204 function callbacks it is asked about, 31 hit the exact key above
		// and the other 1,173 name a function the tree does not declare. So no
		// answer the corpus produces changes here. It is a guard for the tree
		// that does collide two names, where today the flip is silent.
		var bestFn *FunctionSymbol
		for _, fn := range a.SymTable.Functions {
			if fn.BodyNode == nil {
				continue
			}
			parts := strings.Split(fn.FQN, `\`)
			if parts[len(parts)-1] != ref.FuncName {
				continue
			}
			if bestFn == nil || fn.FQN < bestFn.FQN {
				bestFn = fn
			}
		}
		if bestFn != nil {
			return bestFn.BodyNode, a.sourceForFile(bestFn.File), ""
		}

	case "method", "static_method":
		className := ref.ClassName
		if cls, ok := a.SymTable.Classes[className]; ok {
			if m, ok := cls.Methods[ref.MethodName]; ok && m.BodyNode != nil {
				return m.BodyNode, a.sourceForFile(m.File), cls.FQN
			}
		}

		// The same ambiguity as the function case above, one level down: a
		// callback like 'Ctl::handle' names the class by its short name, and two
		// namespaces -- or a bundled second copy of a library -- can each
		// declare a Ctl that declares handle(). First-in-map-order picked one of
		// the two bodies per run; smallest FQN picks the same one on every run.
		// The ambiguity is real and stays real; this only stops it moving. Of
		// the corpus's 4,312 method callbacks, 14 reach this loop and every one
		// of them has a single candidate, so again nothing measured changes.
		var bestCls *ClassSymbol
		var bestMethod *MethodSymbol
		for _, cls := range a.SymTable.Classes {
			parts := strings.Split(cls.FQN, `\`)
			if parts[len(parts)-1] != className {
				continue
			}
			m, ok := cls.Methods[ref.MethodName]
			if !ok || m.BodyNode == nil {
				continue
			}
			if bestCls == nil || cls.FQN < bestCls.FQN {
				bestCls, bestMethod = cls, m
			}
		}
		if bestMethod != nil {
			return bestMethod.BodyNode, a.sourceForFile(bestMethod.File), bestCls.FQN
		}

		if a.Hierarchy != nil {
			m := a.Hierarchy.ResolveMethod(className, ref.MethodName)
			if m != nil && m.BodyNode != nil {
				// The receiver is the class the callback named, not the ancestor
				// the body was declared in: `$this` inside an inherited body
				// still means the subclass, and a nested $this->n() has to
				// resolve from there.
				return m.BodyNode, a.sourceForFile(m.File), className
			}
		}

	case "closure":
		if ref.ClosureNode != nil {
			body := ref.ClosureNode.ChildByFieldName("body")
			if body != nil {
				// A closure reference carries a node and a file but no class, so
				// there is no receiver to hand down. A `$this->m()` inside one
				// falls back to the whole-plugin scan in
				// analyzeReturnExpression.
				return body, a.sourceForFile(ref.File), ""
			}
		}
	}

	return nil, nil, ""
}

// analyzeReturnStatements scores the return values of one body. enclosingFQN is
// the class that body belongs to ("" if it is not a method or the class is not
// known); it is what `$this` means inside this body.
func (a *AuthAnalyzer) analyzeReturnStatements(node *sitter.Node, source []byte, depth int, enclosingFQN string) models.AuthLevel {
	if depth > 5 {
		return models.Subscriber
	}

	var returns []models.AuthLevel
	collectReturnLevels(node, source, a, depth, enclosingFQN, &returns)

	if len(returns) == 0 {
		return models.Subscriber
	}

	leastRestrictive := returns[0]
	for _, lvl := range returns[1:] {
		if lvl < leastRestrictive {
			leastRestrictive = lvl
		}
	}
	return leastRestrictive
}

func collectReturnLevels(node *sitter.Node, source []byte, aa *AuthAnalyzer, depth int, enclosingFQN string, levels *[]models.AuthLevel) {
	if node == nil {
		return
	}

	if node.Type() == "return_statement" {
		level := analyzeReturnValue(node, source, aa, depth, enclosingFQN)
		*levels = append(*levels, level)
		return
	}

	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == "function_definition" || child.Type() == "anonymous_function_creation_expression" {
			continue
		}
		collectReturnLevels(child, source, aa, depth, enclosingFQN, levels)
	}
}

func analyzeReturnValue(retNode *sitter.Node, source []byte, aa *AuthAnalyzer, depth int, enclosingFQN string) models.AuthLevel {
	if retNode.NamedChildCount() == 0 {
		return models.Subscriber
	}

	expr := retNode.NamedChild(0)
	return analyzeReturnExpression(expr, source, aa, depth, enclosingFQN)
}

func analyzeReturnExpression(expr *sitter.Node, source []byte, aa *AuthAnalyzer, depth int, enclosingFQN string) models.AuthLevel {
	if expr == nil {
		return models.Subscriber
	}

	switch expr.Type() {
	case "boolean":
		text := nodeTextFromNode(expr, source)
		if strings.EqualFold(text, "true") {
			return models.Unauthenticated
		}
		return models.Admin

	case "function_call_expression":
		funcNode := expr.ChildByFieldName("function")
		if funcNode == nil {
			return models.Subscriber
		}
		funcName := nodeTextFromNode(funcNode, source)

		switch funcName {
		case "current_user_can":
			args := expr.ChildByFieldName("arguments")
			if args != nil && args.NamedChildCount() > 0 {
				capStr := extractCapabilityString(args.NamedChild(0), source)
				if capStr != "" {
					if level, ok := capabilityLevel(capStr); ok {
						return level
					}
					return models.Subscriber
				}
			}
			return models.Subscriber

		case "is_user_logged_in":
			return models.Subscriber
		}
		return models.Subscriber

	case "member_call_expression":
		if depth >= 5 {
			return models.Subscriber
		}
		nameNode := expr.ChildByFieldName("name")
		objNode := expr.ChildByFieldName("object")
		if nameNode == nil {
			return models.Subscriber
		}
		methodName := nodeTextFromNode(nameNode, source)
		if objNode != nil && nodeTextFromNode(objNode, source) == "$this" {
			// `$this->m()` calls m on the object this body belongs to: the
			// enclosing class, then its traits, then its ancestors. Nothing else
			// is a candidate, in any PHP.
			//
			// This used to scan every class in the plugin and keep whichever
			// declared an m first in map order, which is wrong twice over. It is
			// nondeterministic -- two runs of one binary over one tree pick
			// different bodies and report different levels for the same endpoint
			// -- and even where it settles it answers with a method from a class
			// that has no relationship to the one under analysis. That is not
			// hypothetical: 38 of the corpus's 72 `$this->m()` resolutions had
			// more than one candidate -- two REST controllers and an
			// authentication class in one tree each declare a
			// check_permissions() -- and in 19 of them the class the scan
			// reached was not the class the body belongs to. Those three bodies
			// happen to score the same level, so no endpoint level moved on this
			// corpus: 28,881 endpoint keys, identical either way. What moved is
			// which method the answer came from, and the receiver's own is the
			// only one that can be right the moment the capabilities differ.
			//
			// resolveCallbackBody knows which class it took the body from, so
			// the receiver is threaded down here and resolved through the MRO
			// (class -> traits -> parent -> ...), which is where PHP looks and is
			// already deterministic. Resolving this way removes the ambiguity
			// rather than defining it: one receiver, one answer. The receiver is
			// passed on unchanged rather than replaced by the declaring class,
			// because `$this` inside an inherited body still means the subclass.
			if enclosingFQN != "" && aa.Hierarchy != nil {
				if m := aa.Hierarchy.ResolveMethod(enclosingFQN, methodName); m != nil && m.BodyNode != nil {
					return aa.analyzeReturnStatements(m.BodyNode, aa.sourceForFile(m.File), depth+1, enclosingFQN)
				}
			}

			// Fallback, for the two shapes the MRO cannot answer: no receiver at
			// all (a closure reference carries a node and a file but no class),
			// or a receiver whose ancestry is not wholly inside the tree -- a
			// parent that lives in WordPress core, an alias this resolver could
			// not follow. The whole-plugin scan is then the only candidate set
			// there is, and dropping to Subscriber instead would throw away the
			// one candidate that might be right, so it stays -- but it takes the
			// smallest FQN, for the reason spelled out at resolveCallbackBody's
			// function case: an arbitrary choice that is at least the same
			// arbitrary choice on every run. It fires 0 times on the corpus,
			// where all 72 resolutions had a receiver and the MRO answered every
			// one of them.
			var bestCls *ClassSymbol
			var bestMethod *MethodSymbol
			for _, cls := range aa.SymTable.Classes {
				m, ok := cls.Methods[methodName]
				if !ok || m.BodyNode == nil {
					continue
				}
				if bestCls == nil || cls.FQN < bestCls.FQN {
					bestCls, bestMethod = cls, m
				}
			}
			if bestMethod != nil {
				return aa.analyzeReturnStatements(bestMethod.BodyNode, aa.sourceForFile(bestMethod.File), depth+1, bestCls.FQN)
			}
		}
		return models.Subscriber

	case "parenthesized_expression":
		if expr.NamedChildCount() > 0 {
			return analyzeReturnExpression(expr.NamedChild(0), source, aa, depth, enclosingFQN)
		}
	}

	return models.Subscriber
}

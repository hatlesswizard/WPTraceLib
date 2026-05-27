package ast

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
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

var capabilityMap = map[string]models.AuthLevel{
	"read":                  models.Subscriber,
	"exist":                 models.Subscriber,
	"level_0":               models.Subscriber,
	"read_post":             models.Subscriber,
	"read_page":             models.Subscriber,
	"edit_posts":            models.Contributor,
	"delete_posts":          models.Contributor,
	"edit_post":             models.Contributor,
	"delete_post":           models.Contributor,
	"publish_posts":         models.Author,
	"upload_files":          models.Author,
	"publish_post":          models.Author,
	"edit_published_posts":  models.Author,
	"delete_published_posts": models.Author,
	"edit_others_posts":     models.Editor,
	"moderate_comments":     models.Editor,
	"manage_categories":     models.Editor,
	"edit_pages":            models.Editor,
	"edit_page":             models.Editor,
	"delete_page":           models.Editor,
	"publish_page":          models.Editor,
	"edit_others_pages":     models.Editor,
	"delete_others_posts":   models.Editor,
	"delete_others_pages":   models.Editor,
	"edit_published_pages":  models.Editor,
	"delete_published_pages": models.Editor,
	"publish_pages":         models.Editor,
	"manage_links":          models.Editor,
	"edit_term":             models.Editor,
	"delete_term":           models.Editor,
	"assign_term":           models.Editor,
	"manage_options":        models.Admin,
	"activate_plugins":      models.Admin,
	"install_plugins":       models.Admin,
	"delete_plugins":        models.Admin,
	"update_plugins":        models.Admin,
	"edit_plugins":          models.Admin,
	"edit_theme_options":    models.Admin,
	"install_themes":        models.Admin,
	"update_themes":         models.Admin,
	"switch_themes":         models.Admin,
	"delete_themes":         models.Admin,
	"edit_themes":           models.Admin,
	"update_core":           models.Admin,
	"edit_users":            models.Admin,
	"delete_users":          models.Admin,
	"create_users":          models.Admin,
	"list_users":            models.Admin,
	"promote_users":         models.Admin,
	"remove_users":          models.Admin,
	"unfiltered_html":       models.Admin,
	"import":                models.Admin,
	"export":                models.Admin,
	"administrator":         models.Admin,
	"customize":             models.Admin,
	"edit_dashboard":        models.Admin,
	"edit_files":            models.Admin,
	"edit_user":             models.Admin,
	"delete_user":           models.Admin,
	"manage_privacy_options": models.Admin,
	"manage_network":        models.SuperAdmin,
	"manage_sites":          models.SuperAdmin,
	"manage_network_users":  models.SuperAdmin,
	"manage_network_plugins": models.SuperAdmin,
	"manage_network_themes": models.SuperAdmin,
	"manage_network_options": models.SuperAdmin,
	"setup_network":         models.SuperAdmin,
	"upgrade_network":       models.SuperAdmin,
	"upload_plugins":        models.SuperAdmin,
	"upload_themes":         models.SuperAdmin,
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
	var highestLevel models.AuthLevel

	walkForAuthGuards(node, source, &found, &highestLevel)
	return found, highestLevel
}

func walkForAuthGuards(node *sitter.Node, source []byte, found *bool, level *models.AuthLevel) {
	if node == nil {
		return
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
						authLevel, ok := capabilityMap[capStr]
						if !ok {
							authLevel = models.Subscriber
						}
						*found = true
						if authLevel > *level {
							*level = authLevel
						}
						return
					}
				}
				*found = true
				if models.Subscriber > *level {
					*level = models.Subscriber
				}
				return

			case "is_user_logged_in":
				*found = true
				if models.Subscriber > *level {
					*level = models.Subscriber
				}
				return

			case "get_current_user_id":
				*found = true
				if models.Subscriber > *level {
					*level = models.Subscriber
				}
				return

			case "wp_get_current_user":
				*found = true
				if models.Subscriber > *level {
					*level = models.Subscriber
				}
				return
			}
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
	bodyNode, source := a.resolveCallbackBody(ref)
	if bodyNode == nil {
		return models.Subscriber
	}

	return a.analyzeReturnStatements(bodyNode, source, 0)
}

func (a *AuthAnalyzer) resolveCallbackBody(ref CallbackRef) (*sitter.Node, []byte) {
	switch ref.Type {
	case "function":
		if fn, ok := a.SymTable.Functions[ref.FuncName]; ok && fn.BodyNode != nil {
			return fn.BodyNode, a.sourceForFile(fn.File)
		}
		for _, fn := range a.SymTable.Functions {
			parts := strings.Split(fn.FQN, `\`)
			if parts[len(parts)-1] == ref.FuncName && fn.BodyNode != nil {
				return fn.BodyNode, a.sourceForFile(fn.File)
			}
		}

	case "method", "static_method":
		className := ref.ClassName
		if cls, ok := a.SymTable.Classes[className]; ok {
			if m, ok := cls.Methods[ref.MethodName]; ok && m.BodyNode != nil {
				return m.BodyNode, a.sourceForFile(m.File)
			}
		}
		for _, cls := range a.SymTable.Classes {
			parts := strings.Split(cls.FQN, `\`)
			if parts[len(parts)-1] == className {
				if m, ok := cls.Methods[ref.MethodName]; ok && m.BodyNode != nil {
					return m.BodyNode, a.sourceForFile(m.File)
				}
			}
		}
		if a.Hierarchy != nil {
			m := a.Hierarchy.ResolveMethod(className, ref.MethodName)
			if m != nil && m.BodyNode != nil {
				return m.BodyNode, a.sourceForFile(m.File)
			}
		}

	case "closure":
		if ref.ClosureNode != nil {
			body := ref.ClosureNode.ChildByFieldName("body")
			if body != nil {
				return body, a.sourceForFile(ref.File)
			}
		}
	}

	return nil, nil
}

func (a *AuthAnalyzer) analyzeReturnStatements(node *sitter.Node, source []byte, depth int) models.AuthLevel {
	if depth > 5 {
		return models.Subscriber
	}

	var returns []models.AuthLevel
	collectReturnLevels(node, source, a, depth, &returns)

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

func collectReturnLevels(node *sitter.Node, source []byte, aa *AuthAnalyzer, depth int, levels *[]models.AuthLevel) {
	if node == nil {
		return
	}

	if node.Type() == "return_statement" {
		level := analyzeReturnValue(node, source, aa, depth)
		*levels = append(*levels, level)
		return
	}

	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == "function_definition" || child.Type() == "anonymous_function_creation_expression" {
			continue
		}
		collectReturnLevels(child, source, aa, depth, levels)
	}
}

func analyzeReturnValue(retNode *sitter.Node, source []byte, aa *AuthAnalyzer, depth int) models.AuthLevel {
	if retNode.NamedChildCount() == 0 {
		return models.Subscriber
	}

	expr := retNode.NamedChild(0)
	return analyzeReturnExpression(expr, source, aa, depth)
}

func analyzeReturnExpression(expr *sitter.Node, source []byte, aa *AuthAnalyzer, depth int) models.AuthLevel {
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
					if level, ok := capabilityMap[capStr]; ok {
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
			for _, cls := range aa.SymTable.Classes {
				if m, ok := cls.Methods[methodName]; ok && m.BodyNode != nil {
					methodSource := aa.sourceForFile(m.File)
					return aa.analyzeReturnStatements(m.BodyNode, methodSource, depth+1)
				}
			}
		}
		return models.Subscriber

	case "parenthesized_expression":
		if expr.NamedChildCount() > 0 {
			return analyzeReturnExpression(expr.NamedChild(0), source, aa, depth)
		}
	}

	return models.Subscriber
}

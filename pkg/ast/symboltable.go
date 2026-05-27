package ast

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

type SymbolTable struct {
	Classes   map[string]*ClassSymbol
	Functions map[string]*FunctionSymbol
	Constants map[string]*ConstantSymbol
	Files     map[string]*FileContext
}

type ClassSymbol struct {
	Name       string
	Namespace  string
	FQN        string
	File       string
	Line       int
	ParentName string
	Interfaces []string
	Traits     []string
	Methods    map[string]*MethodSymbol
	Properties map[string]*PropertySymbol
	Constants  map[string]*ConstantSymbol
	Node       *sitter.Node
}

type MethodSymbol struct {
	Name       string
	Class      string
	Visibility string
	Static     bool
	Params     []ParameterInfo
	BodyNode   *sitter.Node
	File       string
	Line       int
}

type FunctionSymbol struct {
	Name      string
	Namespace string
	FQN       string
	File      string
	Line      int
	Params    []ParameterInfo
	BodyNode  *sitter.Node
}

type PropertySymbol struct {
	Name         string
	DefaultValue string
	IsResolved   bool
	Visibility   string
	Static       bool
}

type ConstantSymbol struct {
	Name          string
	ResolvedValue string
	IsResolved    bool
}

type FileContext struct {
	Namespace string
	UseMap    map[string]string
	Path      string
}

type ParameterInfo struct {
	Name         string
	TypeHint     string
	DefaultValue string
	IsVariadic   bool
}

type CallbackRef struct {
	Type        string // "function", "method", "static_method", "closure"
	FuncName    string
	ClassName   string
	MethodName  string
	ClosureNode *sitter.Node
	File        string
	Line        int
}

type FunctionScope struct {
	FuncFQN    string
	Variables  map[string]string
	Parameters map[string]string
	ClassFQN   string
}

func BuildSymbolTable(pluginAST *PluginAST) *SymbolTable {
	st := &SymbolTable{
		Classes:   make(map[string]*ClassSymbol),
		Functions: make(map[string]*FunctionSymbol),
		Constants: make(map[string]*ConstantSymbol),
		Files:     make(map[string]*FileContext),
	}

	for path, pf := range pluginAST.Files {
		fc := &FileContext{
			UseMap: make(map[string]string),
			Path:   path,
		}
		st.Files[path] = fc

		root := pf.Tree.RootNode()
		extractSymbols(root, pf.Source, path, fc, st)
	}

	return st
}

func extractSymbols(node *sitter.Node, source []byte, filePath string, fc *FileContext, st *SymbolTable) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		switch child.Type() {
		case "namespace_definition":
			nsName := extractNamespaceName(child, source)
			fc.Namespace = nsName
			if body := child.ChildByFieldName("body"); body != nil {
				extractSymbols(body, source, filePath, fc, st)
			}

		case "namespace_use_declaration":
			extractUseDeclarations(child, source, fc)

		case "class_declaration", "interface_declaration", "trait_declaration":
			cls := extractClassSymbol(child, source, filePath, fc)
			if cls != nil {
				st.Classes[cls.FQN] = cls
			}

		case "function_definition":
			fn := extractFunctionSymbol(child, source, filePath, fc)
			if fn != nil {
				st.Functions[fn.FQN] = fn
			}

		case "const_declaration":
			consts := extractConstDeclaration(child, source, fc)
			for _, c := range consts {
				st.Constants[c.Name] = c
			}

		case "expression_statement":
			c := extractDefineConstant(child, source)
			if c != nil {
				st.Constants[c.Name] = c
			}
		}
	}
}

func extractNamespaceName(node *sitter.Node, source []byte) string {
	nameNode := node.ChildByFieldName("name")
	if nameNode != nil {
		return nodeText(nameNode, source)
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == "namespace_name" {
			return nodeText(child, source)
		}
	}
	return ""
}

func extractUseDeclarations(node *sitter.Node, source []byte, fc *FileContext) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() != "namespace_use_clause" {
			continue
		}
		fqn := nodeText(child, source)
		// Check for alias: `use Foo\Bar as Baz`
		alias := ""
		for j := 0; j < int(child.NamedChildCount()); j++ {
			gc := child.NamedChild(j)
			if gc.Type() == "namespace_aliasing_clause" {
				alias = nodeText(gc.NamedChild(0), source)
			}
		}
		if alias == "" {
			parts := strings.Split(fqn, `\`)
			alias = parts[len(parts)-1]
		}
		fc.UseMap[alias] = fqn
	}
}

func extractClassSymbol(node *sitter.Node, source []byte, filePath string, fc *FileContext) *ClassSymbol {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return nil
	}
	name := nodeText(nameNode, source)
	fqn := resolveFQN(name, fc)

	cls := &ClassSymbol{
		Name:       name,
		Namespace:  fc.Namespace,
		FQN:        fqn,
		File:       filePath,
		Line:       int(node.StartPoint().Row) + 1,
		Methods:    make(map[string]*MethodSymbol),
		Properties: make(map[string]*PropertySymbol),
		Constants:  make(map[string]*ConstantSymbol),
		Node:       node,
	}

	if baseClause := findNamedChild(node, "base_clause"); baseClause != nil {
		for i := 0; i < int(baseClause.NamedChildCount()); i++ {
			child := baseClause.NamedChild(i)
			if child.Type() == "name" || child.Type() == "qualified_name" {
				cls.ParentName = nodeText(child, source)
			}
		}
	}

	if ifaceClause := findNamedChild(node, "class_interface_clause"); ifaceClause != nil {
		for i := 0; i < int(ifaceClause.NamedChildCount()); i++ {
			child := ifaceClause.NamedChild(i)
			if child.Type() == "name" || child.Type() == "qualified_name" {
				cls.Interfaces = append(cls.Interfaces, nodeText(child, source))
			}
		}
	}

	body := node.ChildByFieldName("body")
	if body == nil {
		body = findNamedChild(node, "declaration_list")
	}
	if body != nil {
		extractClassBody(body, source, filePath, fqn, cls)
	}

	return cls
}

func extractClassBody(body *sitter.Node, source []byte, filePath string, classFQN string, cls *ClassSymbol) {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		child := body.NamedChild(i)
		switch child.Type() {
		case "method_declaration":
			m := extractMethodSymbol(child, source, filePath, classFQN)
			if m != nil {
				cls.Methods[m.Name] = m
			}

		case "property_declaration":
			props := extractPropertyDeclaration(child, source)
			for _, p := range props {
				cls.Properties[p.Name] = p
			}

		case "const_declaration":
			consts := extractClassConstDeclaration(child, source)
			for _, c := range consts {
				cls.Constants[c.Name] = c
			}

		case "use_declaration":
			for j := 0; j < int(child.NamedChildCount()); j++ {
				gc := child.NamedChild(j)
				if gc.Type() == "name" || gc.Type() == "qualified_name" {
					cls.Traits = append(cls.Traits, nodeText(gc, source))
				}
			}
		}
	}
}

func extractMethodSymbol(node *sitter.Node, source []byte, filePath string, classFQN string) *MethodSymbol {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return nil
	}

	m := &MethodSymbol{
		Name:       nodeText(nameNode, source),
		Class:      classFQN,
		Visibility: "public",
		File:       filePath,
		Line:       int(node.StartPoint().Row) + 1,
	}

	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		switch child.Type() {
		case "visibility_modifier":
			m.Visibility = nodeText(child, source)
		case "static_modifier":
			m.Static = true
		case "formal_parameters":
			m.Params = extractParameters(child, source)
		case "compound_statement":
			m.BodyNode = child
		}
	}

	return m
}

func extractPropertyDeclaration(node *sitter.Node, source []byte) []*PropertySymbol {
	var props []*PropertySymbol
	visibility := "public"
	static := false

	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		switch child.Type() {
		case "visibility_modifier":
			visibility = nodeText(child, source)
		case "static_modifier":
			static = true
		case "property_element":
			p := &PropertySymbol{
				Visibility: visibility,
				Static:     static,
			}
			varName := findNamedChild(child, "variable_name")
			if varName != nil {
				raw := nodeText(varName, source)
				p.Name = strings.TrimPrefix(raw, "$")
			}
			if init := findNamedChild(child, "property_initializer"); init != nil {
				val, resolved := extractLiteralValue(init, source)
				p.DefaultValue = val
				p.IsResolved = resolved
			}
			if p.Name != "" {
				props = append(props, p)
			}
		}
	}
	return props
}

func extractClassConstDeclaration(node *sitter.Node, source []byte) []*ConstantSymbol {
	var consts []*ConstantSymbol
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() != "const_element" {
			continue
		}
		if child.NamedChildCount() < 1 {
			continue
		}
		nameNode := child.NamedChild(0)
		if nameNode.Type() != "name" {
			continue
		}
		c := &ConstantSymbol{
			Name: nodeText(nameNode, source),
		}
		if child.NamedChildCount() >= 2 {
			valNode := child.NamedChild(int(child.NamedChildCount()) - 1)
			val, resolved := extractNodeLiteral(valNode, source)
			c.ResolvedValue = val
			c.IsResolved = resolved
		}
		consts = append(consts, c)
	}
	return consts
}

func extractFunctionSymbol(node *sitter.Node, source []byte, filePath string, fc *FileContext) *FunctionSymbol {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return nil
	}
	name := nodeText(nameNode, source)

	fn := &FunctionSymbol{
		Name:      name,
		Namespace: fc.Namespace,
		FQN:       resolveFQN(name, fc),
		File:      filePath,
		Line:      int(node.StartPoint().Row) + 1,
	}

	if params := node.ChildByFieldName("parameters"); params != nil {
		fn.Params = extractParameters(params, source)
	}
	if bodyNode := node.ChildByFieldName("body"); bodyNode != nil {
		fn.BodyNode = bodyNode
	}

	return fn
}

func extractParameters(node *sitter.Node, source []byte) []ParameterInfo {
	var params []ParameterInfo
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		switch child.Type() {
		case "simple_parameter":
			p := ParameterInfo{}
			if nameField := child.ChildByFieldName("name"); nameField != nil {
				p.Name = nodeText(nameField, source)
			}
			if typeField := child.ChildByFieldName("type"); typeField != nil {
				p.TypeHint = nodeText(typeField, source)
			}
			if defField := child.ChildByFieldName("default_value"); defField != nil {
				p.DefaultValue = nodeText(defField, source)
			}
			params = append(params, p)

		case "variadic_parameter":
			p := ParameterInfo{IsVariadic: true}
			if nameField := child.ChildByFieldName("name"); nameField != nil {
				p.Name = nodeText(nameField, source)
			}
			if typeField := child.ChildByFieldName("type"); typeField != nil {
				p.TypeHint = nodeText(typeField, source)
			}
			params = append(params, p)
		}
	}
	return params
}

func extractConstDeclaration(node *sitter.Node, source []byte, fc *FileContext) []*ConstantSymbol {
	var consts []*ConstantSymbol
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() != "const_element" {
			continue
		}
		if child.NamedChildCount() < 1 {
			continue
		}
		nameNode := child.NamedChild(0)
		if nameNode.Type() != "name" {
			continue
		}
		name := nodeText(nameNode, source)
		fqn := resolveFQN(name, fc)

		c := &ConstantSymbol{Name: fqn}
		if child.NamedChildCount() >= 2 {
			valNode := child.NamedChild(int(child.NamedChildCount()) - 1)
			val, resolved := extractNodeLiteral(valNode, source)
			c.ResolvedValue = val
			c.IsResolved = resolved
		}
		consts = append(consts, c)
	}
	return consts
}

func extractDefineConstant(exprStmt *sitter.Node, source []byte) *ConstantSymbol {
	if exprStmt.NamedChildCount() == 0 {
		return nil
	}
	call := exprStmt.NamedChild(0)
	if call.Type() != "function_call_expression" {
		return nil
	}

	funcNode := call.ChildByFieldName("function")
	if funcNode == nil || nodeText(funcNode, source) != "define" {
		return nil
	}

	argsNode := call.ChildByFieldName("arguments")
	if argsNode == nil || argsNode.NamedChildCount() < 2 {
		return nil
	}

	nameArg := argsNode.NamedChild(0)
	valArg := argsNode.NamedChild(1)

	constName := extractStringLiteral(nameArg, source)
	if constName == "" {
		return nil
	}

	c := &ConstantSymbol{Name: constName}

	val, resolved := extractArgumentLiteral(valArg, source)
	c.ResolvedValue = val
	c.IsResolved = resolved

	return c
}

func resolveFQN(name string, fc *FileContext) string {
	if strings.HasPrefix(name, `\`) {
		return strings.TrimPrefix(name, `\`)
	}
	if fqn, ok := fc.UseMap[name]; ok {
		return fqn
	}
	if idx := strings.Index(name, `\`); idx > 0 {
		prefix := name[:idx]
		if mapped, ok := fc.UseMap[prefix]; ok {
			return mapped + name[idx:]
		}
	}
	if fc.Namespace != "" {
		return fc.Namespace + `\` + name
	}
	return name
}

func nodeText(node *sitter.Node, source []byte) string {
	return string(source[node.StartByte():node.EndByte()])
}

func findNamedChild(node *sitter.Node, typeName string) *sitter.Node {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == typeName {
			return child
		}
	}
	return nil
}

func extractStringLiteral(node *sitter.Node, source []byte) string {
	// The argument node wraps the actual value
	var strNode *sitter.Node
	if node.Type() == "argument" && node.NamedChildCount() > 0 {
		strNode = node.NamedChild(0)
	} else {
		strNode = node
	}
	if strNode.Type() == "string" {
		if content := findNamedChild(strNode, "string_content"); content != nil {
			return nodeText(content, source)
		}
		// Empty string
		text := nodeText(strNode, source)
		if text == `""` || text == `''` {
			return ""
		}
	}
	return ""
}

func extractArgumentLiteral(node *sitter.Node, source []byte) (string, bool) {
	var valNode *sitter.Node
	if node.Type() == "argument" && node.NamedChildCount() > 0 {
		valNode = node.NamedChild(0)
	} else {
		valNode = node
	}
	return extractNodeLiteral(valNode, source)
}

func extractNodeLiteral(node *sitter.Node, source []byte) (string, bool) {
	switch node.Type() {
	case "string":
		if content := findNamedChild(node, "string_content"); content != nil {
			return nodeText(content, source), true
		}
		text := nodeText(node, source)
		if text == `""` || text == `''` {
			return "", true
		}
		return text, false
	case "integer", "float":
		return nodeText(node, source), true
	case "boolean":
		return nodeText(node, source), true
	case "null":
		return "null", true
	default:
		return nodeText(node, source), false
	}
}

func extractLiteralValue(initNode *sitter.Node, source []byte) (string, bool) {
	// property_initializer has `=` then the value
	for i := 0; i < int(initNode.NamedChildCount()); i++ {
		child := initNode.NamedChild(i)
		return extractNodeLiteral(child, source)
	}
	return "", false
}

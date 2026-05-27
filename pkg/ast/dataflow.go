package ast

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

type DataFlowAnalyzer struct {
	SymTable  *SymbolTable
	Hierarchy *ClassHierarchy
}

func NewDataFlowAnalyzer(st *SymbolTable, h *ClassHierarchy) *DataFlowAnalyzer {
	return &DataFlowAnalyzer{SymTable: st, Hierarchy: h}
}

func (d *DataFlowAnalyzer) ResolveExpression(node *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	if node == nil {
		return "", false
	}

	switch node.Type() {
	case "string":
		return d.resolveStringLiteral(node, source, scope)

	case "encapsed_string":
		return d.resolveInterpolatedString(node, source, scope)

	case "binary_expression":
		return d.resolveBinaryExpression(node, source, scope)

	case "variable_name", "simple_variable":
		varName := nodeText(node, source)
		return d.resolveVariable(varName, scope)

	case "member_access_expression":
		return d.resolveMemberAccess(node, source, scope)

	case "scoped_property_access_expression", "class_constant_access_expression":
		return d.resolveClassConstantAccess(node, source, scope)

	case "function_call_expression":
		return d.resolveFunctionCall(node, source, scope)

	case "parenthesized_expression":
		if node.NamedChildCount() > 0 {
			return d.ResolveExpression(node.NamedChild(0), source, scope)
		}

	case "concatenated_string":
		return d.resolveConcatenation(node, source, scope)

	case "argument":
		if node.NamedChildCount() > 0 {
			return d.ResolveExpression(node.NamedChild(0), source, scope)
		}
	}

	text := nodeText(node, source)
	if text != "" {
		return "{dynamic:" + text + "}", false
	}
	return "", false
}

func (d *DataFlowAnalyzer) ResolveHookName(callNode *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	args := callNode.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return "", false
	}
	firstArg := args.NamedChild(0)
	return d.ResolveExpression(firstArg, source, scope)
}

func (d *DataFlowAnalyzer) resolveStringLiteral(node *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	if content := findNamedChild(node, "string_content"); content != nil {
		return nodeText(content, source), true
	}
	text := nodeText(node, source)
	if len(text) >= 2 && (text[0] == '\'' || text[0] == '"') {
		return text[1 : len(text)-1], true
	}
	return text, true
}

func (d *DataFlowAnalyzer) resolveInterpolatedString(node *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	var parts []string
	allResolved := true
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "string_value", "string_content":
			parts = append(parts, nodeText(child, source))
		case "simple_variable", "variable_name":
			val, ok := d.resolveVariable(nodeText(child, source), scope)
			if !ok {
				allResolved = false
			}
			parts = append(parts, val)
		case "\"":
			// skip quote delimiters
		default:
			val, ok := d.ResolveExpression(child, source, scope)
			if !ok {
				allResolved = false
			}
			parts = append(parts, val)
		}
	}
	return strings.Join(parts, ""), allResolved
}

func (d *DataFlowAnalyzer) resolveBinaryExpression(node *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	op := ""
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "." {
			op = "."
			break
		}
		text := nodeText(child, source)
		if text == "." {
			op = "."
			break
		}
	}

	if op != "." {
		return "{dynamic:binary_op}", false
	}

	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")

	leftVal, leftOk := d.ResolveExpression(left, source, scope)
	rightVal, rightOk := d.ResolveExpression(right, source, scope)

	return leftVal + rightVal, leftOk && rightOk
}

func (d *DataFlowAnalyzer) resolveConcatenation(node *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	var parts []string
	allResolved := true
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		val, ok := d.ResolveExpression(child, source, scope)
		if !ok {
			allResolved = false
		}
		parts = append(parts, val)
	}
	return strings.Join(parts, ""), allResolved
}

func (d *DataFlowAnalyzer) resolveVariable(varName string, scope *FunctionScope) (string, bool) {
	if scope == nil {
		return fmt.Sprintf("{param:%s}", varName), false
	}
	if val, ok := scope.Variables[varName]; ok {
		return val, true
	}
	if val, ok := scope.Parameters[varName]; ok {
		return val, true
	}
	return fmt.Sprintf("{param:%s}", varName), false
}

func (d *DataFlowAnalyzer) resolveMemberAccess(node *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	obj := node.ChildByFieldName("object")
	name := node.ChildByFieldName("name")
	if obj == nil || name == nil {
		return "{dynamic:member}", false
	}

	objText := nodeText(obj, source)
	propName := nodeText(name, source)

	if objText == "$this" && scope != nil && scope.ClassFQN != "" {
		cls := d.SymTable.Classes[scope.ClassFQN]
		if cls != nil {
			if prop, ok := cls.Properties[propName]; ok && prop.IsResolved {
				return prop.DefaultValue, true
			}
		}
	}

	return fmt.Sprintf("{dynamic:%s->%s}", objText, propName), false
}

func (d *DataFlowAnalyzer) resolveClassConstantAccess(node *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	text := nodeText(node, source)
	parts := strings.SplitN(text, "::", 2)
	if len(parts) != 2 {
		return "{dynamic:const}", false
	}

	className := parts[0]
	constName := parts[1]

	if (className == "self" || className == "static") && scope != nil {
		className = scope.ClassFQN
	}

	cls := d.SymTable.Classes[className]
	if cls != nil {
		if c, ok := cls.Constants[constName]; ok && c.IsResolved {
			return c.ResolvedValue, true
		}
	}

	if c, ok := d.SymTable.Constants[constName]; ok && c.IsResolved {
		return c.ResolvedValue, true
	}

	return fmt.Sprintf("{dynamic:%s::%s}", className, constName), false
}

func (d *DataFlowAnalyzer) resolveFunctionCall(node *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	funcName := ""
	nameNode := node.ChildByFieldName("function")
	if nameNode != nil {
		funcName = nodeText(nameNode, source)
	}

	if funcName == "sprintf" {
		return d.resolveSprintf(node, source, scope)
	}

	return fmt.Sprintf("{dynamic:%s()}", funcName), false
}

func (d *DataFlowAnalyzer) resolveSprintf(node *sitter.Node, source []byte, scope *FunctionScope) (string, bool) {
	args := node.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return "{dynamic:sprintf()}", false
	}

	formatNode := args.NamedChild(0)
	format, ok := d.ResolveExpression(formatNode, source, scope)
	if !ok {
		return "{dynamic:sprintf()}", false
	}

	argIdx := 1
	result := strings.Builder{}
	for i := 0; i < len(format); i++ {
		if i+1 < len(format) && format[i] == '%' {
			spec := format[i+1]
			if spec == 's' || spec == 'd' {
				if argIdx < int(args.NamedChildCount()) {
					val, _ := d.ResolveExpression(args.NamedChild(argIdx), source, scope)
					result.WriteString(val)
				} else {
					result.WriteString(fmt.Sprintf("{arg%d}", argIdx))
				}
				argIdx++
				i++
				continue
			}
			if spec == '%' {
				result.WriteByte('%')
				i++
				continue
			}
		}
		result.WriteByte(format[i])
	}

	return result.String(), argIdx > 1
}

func (d *DataFlowAnalyzer) BuildFunctionScope(funcFQN string, bodyNode *sitter.Node, source []byte, classFQN string) *FunctionScope {
	scope := &FunctionScope{
		FuncFQN:    funcFQN,
		Variables:  make(map[string]string),
		Parameters: make(map[string]string),
		ClassFQN:   classFQN,
	}

	if bodyNode == nil {
		return scope
	}

	d.scanAssignments(bodyNode, source, scope, 0)
	return scope
}

func (d *DataFlowAnalyzer) scanAssignments(node *sitter.Node, source []byte, scope *FunctionScope, depth int) {
	if depth > 5 {
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == "expression_statement" {
			expr := child.NamedChild(0)
			if expr != nil && expr.Type() == "assignment_expression" {
				left := expr.ChildByFieldName("left")
				right := expr.ChildByFieldName("right")
				if left != nil && right != nil {
					varName := nodeText(left, source)
					val, _ := d.ResolveExpression(right, source, scope)
					if val != "" {
						scope.Variables[varName] = val
					}
				}
			}
		}
		if child.Type() != "function_definition" && child.Type() != "anonymous_function_creation_expression" {
			d.scanAssignments(child, source, scope, depth+1)
		}
	}
}

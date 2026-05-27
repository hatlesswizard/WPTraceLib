package ast

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Resolver is the high-level query API used by existing detectors.
// It composes all lower analysis layers.
type Resolver struct {
	SymTable  *SymbolTable
	Hierarchy *ClassHierarchy
	DataFlow  *DataFlowAnalyzer
	Taint     *TaintAnalyzer
	Auth      *AuthAnalyzer
}

func NewResolver(st *SymbolTable, h *ClassHierarchy, df *DataFlowAnalyzer, ta *TaintAnalyzer, aa *AuthAnalyzer) *Resolver {
	return &Resolver{
		SymTable:  st,
		Hierarchy: h,
		DataFlow:  df,
		Taint:     ta,
		Auth:      aa,
	}
}

// ResolveCallback resolves a CallbackRef to its MethodSymbol or FunctionSymbol.
// For closures, returns (nil, nil, nil) and the caller should use ref.ClosureNode.
func (r *Resolver) ResolveCallback(ref CallbackRef) (*MethodSymbol, *FunctionSymbol, error) {
	switch ref.Type {
	case "function":
		if fn, ok := r.SymTable.Functions[ref.FuncName]; ok {
			return nil, fn, nil
		}
		if ref.File != "" {
			if fc, ok := r.SymTable.Files[ref.File]; ok {
				fqn := resolveFQN(ref.FuncName, fc)
				if fn, ok := r.SymTable.Functions[fqn]; ok {
					return nil, fn, nil
				}
			}
		}
		// Try suffix match across all namespaces
		for fqn, fn := range r.SymTable.Functions {
			parts := strings.Split(fqn, `\`)
			if parts[len(parts)-1] == ref.FuncName {
				return nil, fn, nil
			}
		}
		return nil, nil, fmt.Errorf("function not found: %s", ref.FuncName)

	case "method", "static_method":
		classFQN := r.resolveClassName(ref.ClassName, ref.File)
		m := r.Hierarchy.ResolveMethod(classFQN, ref.MethodName)
		if m != nil {
			return m, nil, nil
		}
		return nil, nil, fmt.Errorf("method not found: %s::%s", classFQN, ref.MethodName)

	case "closure":
		return nil, nil, nil
	}

	return nil, nil, fmt.Errorf("unknown callback type: %s", ref.Type)
}

// ResolveAuthLevel determines the effective auth level for a callback.
func (r *Resolver) ResolveAuthLevel(ref CallbackRef) models.AuthLevel {
	funcFQN := r.callbackToFQN(ref)
	if funcFQN == "" {
		return models.Unauthenticated
	}

	hasGuard, level := r.Auth.HasAuthGuard(funcFQN)
	if hasGuard {
		return level
	}
	return models.Unauthenticated
}

// ResolvePermissionCallback analyzes a REST permission_callback.
func (r *Resolver) ResolvePermissionCallback(ref CallbackRef) models.AuthLevel {
	return r.Auth.AnalyzePermissionCallback(ref)
}

// ResolveHookActionName resolves a dynamically-constructed hook name.
func (r *Resolver) ResolveHookActionName(addActionNode *sitter.Node, source []byte) (string, bool) {
	scope := &FunctionScope{
		Variables:  make(map[string]string),
		Parameters: make(map[string]string),
	}
	return r.DataFlow.ResolveHookName(addActionNode, source, scope)
}

// FunctionAccessesUserInput checks if a function processes user input (taint analysis).
func (r *Resolver) FunctionAccessesUserInput(funcFQN string) bool {
	return r.Taint.FunctionProcessesUserInput(funcFQN)
}

// HasAuthGuardBeforeInput checks if auth is verified before input processing.
// Returns (false, Unauthenticated) when the function doesn't process user input at all.
func (r *Resolver) HasAuthGuardBeforeInput(funcFQN string) (bool, models.AuthLevel) {
	if !r.Taint.FunctionProcessesUserInput(funcFQN) {
		return false, models.Unauthenticated
	}
	return r.Auth.HasAuthGuard(funcFQN)
}

// IsSubclassOf checks class hierarchy.
func (r *Resolver) IsSubclassOf(classFQN, parentFQN string) bool {
	return r.Hierarchy.IsSubclassOf(classFQN, parentFQN)
}

// GetSubclasses returns all subclasses of a given class.
func (r *Resolver) GetSubclasses(parentFQN string) []string {
	return r.Hierarchy.GetAllSubclasses(parentFQN)
}

// ResolveConstant resolves a class or global constant to its string value.
func (r *Resolver) ResolveConstant(name string, fileContext *FileContext) (string, bool) {
	// Direct global lookup
	if c, ok := r.SymTable.Constants[name]; ok && c.IsResolved {
		return c.ResolvedValue, true
	}

	// Class constant via "::" syntax
	if parts := strings.SplitN(name, "::", 2); len(parts) == 2 {
		classFQN := r.resolveClassName(parts[0], "")
		if cls, ok := r.SymTable.Classes[classFQN]; ok {
			if c, ok := cls.Constants[parts[1]]; ok && c.IsResolved {
				return c.ResolvedValue, true
			}
		}
	}

	// Try with file namespace prefix
	if fileContext != nil && fileContext.Namespace != "" {
		fqn := fileContext.Namespace + `\` + name
		if c, ok := r.SymTable.Constants[fqn]; ok && c.IsResolved {
			return c.ResolvedValue, true
		}
	}

	// Try UseMap resolution
	if fileContext != nil {
		if fqn, ok := fileContext.UseMap[name]; ok {
			if c, ok := r.SymTable.Constants[fqn]; ok && c.IsResolved {
				return c.ResolvedValue, true
			}
		}
	}

	return "", false
}

// ResolveProperty resolves a class property to its default value.
// Falls back to parent class if property not found directly.
func (r *Resolver) ResolveProperty(classFQN, propName string) (string, bool) {
	cls, ok := r.SymTable.Classes[classFQN]
	if !ok {
		return "", false
	}
	if prop, ok := cls.Properties[propName]; ok && prop.IsResolved {
		return prop.DefaultValue, true
	}
	// Try parent class
	if parent, ok := r.Hierarchy.Parents[classFQN]; ok {
		return r.ResolveProperty(parent, propName)
	}
	return "", false
}

func (r *Resolver) resolveClassName(name, filePath string) string {
	if _, ok := r.SymTable.Classes[name]; ok {
		return name
	}
	if filePath != "" {
		return resolveClassFQN(name, r.SymTable, filePath)
	}
	// Try suffix match
	for fqn := range r.SymTable.Classes {
		parts := strings.Split(fqn, `\`)
		if parts[len(parts)-1] == name {
			return fqn
		}
	}
	return name
}

func (r *Resolver) callbackToFQN(ref CallbackRef) string {
	switch ref.Type {
	case "function":
		return ref.FuncName
	case "method", "static_method":
		classFQN := r.resolveClassName(ref.ClassName, ref.File)
		return classFQN + "::" + ref.MethodName
	}
	return ""
}

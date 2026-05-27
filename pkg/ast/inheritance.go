package ast

type ClassHierarchy struct {
	Parents    map[string]string
	Children   map[string][]string
	Interfaces map[string][]string
	Traits     map[string][]string
	MROCache   map[string][]string
	symTable   *SymbolTable
}

func BuildClassHierarchy(st *SymbolTable) *ClassHierarchy {
	h := &ClassHierarchy{
		Parents:    make(map[string]string),
		Children:   make(map[string][]string),
		Interfaces: make(map[string][]string),
		Traits:     make(map[string][]string),
		MROCache:   make(map[string][]string),
		symTable:   st,
	}

	for fqn, cls := range st.Classes {
		if cls.ParentName != "" {
			parentFQN := resolveClassFQN(cls.ParentName, st, cls.File)
			h.Parents[fqn] = parentFQN
			h.Children[parentFQN] = append(h.Children[parentFQN], fqn)
		}
		if len(cls.Interfaces) > 0 {
			resolved := make([]string, len(cls.Interfaces))
			for i, iface := range cls.Interfaces {
				resolved[i] = resolveClassFQN(iface, st, cls.File)
			}
			h.Interfaces[fqn] = resolved
		}
		if len(cls.Traits) > 0 {
			resolved := make([]string, len(cls.Traits))
			for i, trait := range cls.Traits {
				resolved[i] = resolveClassFQN(trait, st, cls.File)
			}
			h.Traits[fqn] = resolved
		}
	}

	return h
}

// resolveClassFQN resolves a short class name to FQN using the file's context.
// If the class is found in the symbol table under the file's namespace or UseMap, use that.
// Otherwise, check global scope. If still not found, return the name as-is
// (it may be a WordPress core class or external dependency).
func resolveClassFQN(name string, st *SymbolTable, filePath string) string {
	// Already FQN
	if _, ok := st.Classes[name]; ok {
		return name
	}

	fc := st.Files[filePath]
	if fc == nil {
		return name
	}

	// Check UseMap
	if fqn, ok := fc.UseMap[name]; ok {
		return fqn
	}

	// Check namespaced
	if fc.Namespace != "" {
		fqn := fc.Namespace + `\` + name
		if _, ok := st.Classes[fqn]; ok {
			return fqn
		}
	}

	return name
}

// ResolveMethod follows MRO: class → traits → parent → recurse
func (h *ClassHierarchy) ResolveMethod(classFQN, methodName string) *MethodSymbol {
	mro := h.getMRO(classFQN)
	for _, fqn := range mro {
		cls := h.symTable.Classes[fqn]
		if cls == nil {
			continue
		}
		if m, ok := cls.Methods[methodName]; ok {
			return m
		}
	}
	return nil
}

func (h *ClassHierarchy) IsSubclassOf(classFQN, parentFQN string) bool {
	visited := make(map[string]bool)
	return h.isSubclassOfRecursive(classFQN, parentFQN, visited)
}

func (h *ClassHierarchy) isSubclassOfRecursive(classFQN, parentFQN string, visited map[string]bool) bool {
	if classFQN == parentFQN {
		return true
	}
	if visited[classFQN] {
		return false // cycle detection
	}
	visited[classFQN] = true

	parent, ok := h.Parents[classFQN]
	if !ok {
		return false
	}
	return h.isSubclassOfRecursive(parent, parentFQN, visited)
}

func (h *ClassHierarchy) GetAllSubclasses(parentFQN string) []string {
	var result []string
	h.collectSubclasses(parentFQN, &result, make(map[string]bool))
	return result
}

func (h *ClassHierarchy) collectSubclasses(fqn string, result *[]string, visited map[string]bool) {
	for _, child := range h.Children[fqn] {
		if visited[child] {
			continue
		}
		visited[child] = true
		*result = append(*result, child)
		h.collectSubclasses(child, result, visited)
	}
}

// getMRO computes method resolution order: class → traits (decl order) → parent → recurse
func (h *ClassHierarchy) getMRO(classFQN string) []string {
	if cached, ok := h.MROCache[classFQN]; ok {
		return cached
	}

	visited := make(map[string]bool)
	var mro []string
	h.buildMRO(classFQN, &mro, visited)

	h.MROCache[classFQN] = mro
	return mro
}

func (h *ClassHierarchy) buildMRO(classFQN string, mro *[]string, visited map[string]bool) {
	if visited[classFQN] {
		return // cycle detection
	}
	visited[classFQN] = true
	*mro = append(*mro, classFQN)

	// Traits next
	for _, traitFQN := range h.Traits[classFQN] {
		h.buildMRO(traitFQN, mro, visited)
	}

	// Parent
	if parent, ok := h.Parents[classFQN]; ok {
		h.buildMRO(parent, mro, visited)
	}
}

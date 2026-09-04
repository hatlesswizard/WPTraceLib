package ast

import (
	"strings"
	"sync"
)

type ClassHierarchy struct {
	Parents    map[string]string
	Children   map[string][]string
	Interfaces map[string][]string
	Traits     map[string][]string
	MROCache   map[string][]string
	symTable   *SymbolTable

	// caseIndex maps a lowercased FQN to the spelling the symbol table stores.
	//
	// PHP class names are case-insensitive: `class LLMS_REST_Controller` and
	// `extends LLMS_Rest_Controller` are the same class, and plugins really do
	// write both. Resolving a parent by exact string match broke the chain at
	// the first such spelling, which silently truncated the inheritance graph:
	// a controller whose grandparent was spelled differently in its own
	// declaration had no ancestors, so no subclass of that grandparent could be
	// found and every method it inherited was invisible.
	//
	// The index is safe against collisions because it is keyed on the whole
	// FQN: two classes may differ only in case across namespaces (A\Foo and
	// B\foo), but not within one, which is what PHP forbids.
	caseIndex map[string]string

	// mroMu guards MROCache. One ClassHierarchy is built per plugin
	// (analyzer.go:300) and shared by every per-file goroutine that
	// AnalyzePlugin runs through its errgroup (analyzer.go:189-191), so the
	// lazy write in getMRO races. Unsynchronised concurrent writes to a Go map
	// are not merely lossy: the runtime detects them and kills the process with
	// "fatal error: concurrent map writes", taking the host application down
	// with it. Observed while analysing a corpus of 143 plugins.
	//
	// The other maps here are filled once in BuildClassHierarchy before the
	// hierarchy is published to any goroutine and are read-only afterwards, so
	// only MROCache needs guarding.
	mroMu sync.RWMutex
}

func BuildClassHierarchy(st *SymbolTable) *ClassHierarchy {
	h := &ClassHierarchy{
		Parents:    make(map[string]string),
		Children:   make(map[string][]string),
		Interfaces: make(map[string][]string),
		Traits:     make(map[string][]string),
		MROCache:   make(map[string][]string),
		symTable:   st,
		caseIndex:  make(map[string]string, len(st.Classes)),
	}
	for fqn := range st.Classes {
		lower := strings.ToLower(fqn)
		// First writer wins, so the result does not depend on map order.
		if _, exists := h.caseIndex[lower]; !exists {
			h.caseIndex[lower] = fqn
		}
	}

	for fqn, cls := range st.Classes {
		if cls.ParentName != "" {
			parentFQN := h.canonical(resolveClassFQN(cls.ParentName, st, cls.File))
			h.Parents[fqn] = parentFQN
			h.Children[parentFQN] = append(h.Children[parentFQN], fqn)
		}
		if len(cls.Interfaces) > 0 {
			resolved := make([]string, len(cls.Interfaces))
			for i, iface := range cls.Interfaces {
				resolved[i] = h.canonical(resolveClassFQN(iface, st, cls.File))
			}
			h.Interfaces[fqn] = resolved
		}
		if len(cls.Traits) > 0 {
			resolved := make([]string, len(cls.Traits))
			for i, trait := range cls.Traits {
				resolved[i] = h.canonical(resolveClassFQN(trait, st, cls.File))
			}
			h.Traits[fqn] = resolved
		}
	}

	return h
}

// canonical returns the spelling the symbol table stores for a class name,
// which may differ from the one written at the reference site: PHP compares
// class names case-insensitively, so `extends LLMS_Rest_Controller` names the
// class declared as `LLMS_REST_Controller`. A name the tree does not declare at
// all is returned unchanged, since it is a core or external class.
func (h *ClassHierarchy) canonical(fqn string) string {
	if _, ok := h.symTable.Classes[fqn]; ok {
		return fqn
	}
	if canonical, ok := h.caseIndex[strings.ToLower(fqn)]; ok {
		return canonical
	}
	return fqn
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
	h.mroMu.RLock()
	cached, ok := h.MROCache[classFQN]
	h.mroMu.RUnlock()
	if ok {
		return cached
	}

	// buildMRO reads only the immutable maps, so it runs outside the lock;
	// holding the write lock across it would serialise every goroutine on the
	// first cache miss for no benefit. Two goroutines racing to compute the
	// same MRO produce equal results, so the loser's value is simply discarded.
	visited := make(map[string]bool)
	var mro []string
	h.buildMRO(classFQN, &mro, visited)

	h.mroMu.Lock()
	if existing, ok := h.MROCache[classFQN]; ok {
		mro = existing
	} else {
		h.MROCache[classFQN] = mro
	}
	h.mroMu.Unlock()
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

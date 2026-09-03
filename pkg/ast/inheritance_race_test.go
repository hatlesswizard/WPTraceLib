package ast

import (
	"fmt"
	"sync"
	"testing"
)

// TestGetMROConcurrent reproduces the crash that killed a 143-plugin corpus run.
//
// One ClassHierarchy is built per plugin (analyzer.go:300) and shared by every
// per-file goroutine AnalyzePlugin starts (analyzer.go:189-191). getMRO fills
// MROCache lazily, so those goroutines wrote the same map at once. That is not
// a benign race: the Go runtime aborts the process with
// "fatal error: concurrent map writes", which no caller can recover from.
//
// Run with -race to catch the unsynchronised access even when the runtime's own
// detector does not fire.
func TestGetMROConcurrent(t *testing.T) {
	st := &SymbolTable{
		Classes: map[string]*ClassSymbol{},
		Files:   map[string]*FileContext{},
	}
	// A deep-ish hierarchy so getMRO does real work and the window stays open.
	const depth = 40
	for i := 0; i < depth; i++ {
		fqn := fmt.Sprintf("Class%d", i)
		cls := &ClassSymbol{Name: fqn, Methods: map[string]*MethodSymbol{}}
		if i > 0 {
			cls.ParentName = fmt.Sprintf("Class%d", i-1)
		}
		st.Classes[fqn] = cls
	}
	h := BuildClassHierarchy(st)

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < depth; i++ {
				// Every goroutine walks every class, so they collide on both
				// the read and the fill.
				_ = h.getMRO(fmt.Sprintf("Class%d", (i+g)%depth))
			}
		}(g)
	}
	wg.Wait()

	// The cache must still be coherent afterwards: one entry per class, each
	// starting at that class.
	for i := 0; i < depth; i++ {
		fqn := fmt.Sprintf("Class%d", i)
		mro := h.getMRO(fqn)
		if len(mro) == 0 || mro[0] != fqn {
			t.Fatalf("MRO for %s is %v; want it to start at %s", fqn, mro, fqn)
		}
	}
}

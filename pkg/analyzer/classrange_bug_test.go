package analyzer

import "testing"

// TestFindClassRangesCoversWholeClass pins the contract findClassRanges is
// supposed to satisfy: the range recorded for a class must span that class's
// own body, so every method declared inside it is contained by the range.
//
// classDefPattern ends with `\s*\{`, so the regexp match already consumes the
// class's opening brace. Searching for the next `{` after the match therefore
// finds the first *method's* brace, and the recorded range is that method's
// body rather than the class. Nothing declared in the class then falls inside
// the range, so every method is attributed to no class at all.
func TestFindClassRangesCoversWholeClass(t *testing.T) {
	src := `<?php
class Alpha {
	public function first() {
		return 1;
	}
	public function second() {
		return 2;
	}
}
`
	ranges := findClassRanges(src)
	bounds, ok := ranges["Alpha"]
	if !ok {
		t.Fatalf("findClassRanges did not record class Alpha; got %v", ranges)
	}

	// The class body runs from the brace after "class Alpha" to the final
	// brace, so it must contain both method declarations.
	for _, method := range []string{"public function first", "public function second"} {
		idx := indexOf(src, method)
		if idx < 0 {
			t.Fatalf("test source lost %q", method)
		}
		if idx <= bounds[0] || idx >= bounds[1] {
			t.Errorf("method %q at offset %d is outside recorded class range [%d,%d); "+
				"the range spans %q",
				method, idx, bounds[0], bounds[1], truncate(src[bounds[0]:minInt(bounds[1], len(src))], 60))
		}
	}
}

// TestDiscoverFunctionsAttributesMethodsToClass is the observable consequence:
// a method must be keyed as Class::method in the call graph, not under its bare
// name. Without this, two classes with a same-named method collapse into one
// node and every call chain through them is wrong.
func TestDiscoverFunctionsAttributesMethodsToClass(t *testing.T) {
	files := map[string]string{
		"alpha.php": `<?php
class Alpha {
	public function handle() {
		return 1;
	}
}
`,
		"beta.php": `<?php
class Beta {
	public function handle() {
		return 2;
	}
}
`,
	}
	cg := BuildCallGraph(files)

	for _, want := range []string{"Alpha::handle", "Beta::handle"} {
		if _, ok := cg.Functions[want]; !ok {
			t.Errorf("call graph has no %q key", want)
		}
	}
	withClass := 0
	for _, d := range cg.Functions {
		if d.ClassName != "" {
			withClass++
		}
	}
	if withClass == 0 {
		t.Errorf("no function in the graph carries a ClassName; keys present: %v", keysOf(cg))
	}
}

func keysOf(cg *PluginCallGraph) []string {
	out := make([]string, 0, len(cg.Functions))
	for k, d := range cg.Functions {
		out = append(out, k+"(class="+d.ClassName+")")
	}
	return out
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

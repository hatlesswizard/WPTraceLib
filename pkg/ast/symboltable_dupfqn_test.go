package ast

import (
	"os"
	"path/filepath"
	"testing"
)

// dupFQNFixture writes a tree in which one class, one function and one constant
// are each declared twice, in two files whose sort order is plain from their
// names. The second copy is padded so that every declaration in it sits on a
// different line from its twin, and declares one fewer method: that way an
// assertion says not just that a symbol survived but which file it came from.
func dupFQNFixture(t *testing.T) (dir, firstFile, secondFile string) {
	t.Helper()
	dir = t.TempDir()

	const first = `<?php
// The copy in the file that sorts first.
class Duplicated_Controller {
    public function get_items() {}
    public function permission_check() { return true; }
}

function duplicated_helper() { return 1; }

define( 'DUPLICATED_CONST', 'first' );
`

	const second = `<?php
// The copy in the file that sorts last. A plugin ships two of these when a
// library is vendored twice, when an includes/ copy is left beside a src/ one,
// or when a "- Copy" file makes it into the shipped zip.
//
class Duplicated_Controller {
    public function get_items() {}
}

function duplicated_helper() { return 2; }

define( 'DUPLICATED_CONST', 'second' );

class Only_In_Second {}
`

	firstFile = filepath.Join(dir, "aaa-first.php")
	secondFile = filepath.Join(dir, "zzz-second.php")
	if err := os.WriteFile(firstFile, []byte(first), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondFile, []byte(second), 0644); err != nil {
		t.Fatal(err)
	}
	return dir, firstFile, secondFile
}

// TestBuildSymbolTable_DuplicateFQNKeepsSortedFirstFile pins the rule
// BuildSymbolTable applies when a tree declares one name in two files: the
// declaration in the first file by sorted path wins, whole.
//
// It builds the same parsed tree many times on purpose. Before the rule, the
// surviving symbol was whichever copy Go's randomised map iteration reached
// last, so a single build proves nothing: measured on this fixture against the
// old code, the sorted-first copy survived 1,285 of 10,000 builds and the
// sorted-last copy the other 8,715. One build agreed with this test's
// expectation about one time in eight; 300 do so with probability near zero.
func TestBuildSymbolTable_DuplicateFQNKeepsSortedFirstFile(t *testing.T) {
	dir, firstFile, secondFile := dupFQNFixture(t)

	pluginAST, err := ParsePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pluginAST.Files) != 2 {
		t.Fatalf("fixture parsed %d files, want 2", len(pluginAST.Files))
	}

	const builds = 300
	for i := 0; i < builds; i++ {
		st := BuildSymbolTable(pluginAST)

		cls, ok := st.Classes["Duplicated_Controller"]
		if !ok {
			t.Fatalf("build %d: class Duplicated_Controller missing", i)
		}
		if cls.File != firstFile || cls.Line != 3 {
			t.Fatalf("build %d: class kept from %s:%d, want %s:3", i, cls.File, cls.Line, firstFile)
		}
		// The whole symbol has to come from the winning file, not just its File
		// and Line: expandInheritedRESTEndpoints decides whether to emit a clone
		// at all by looking up a method name in Methods, so a mixed symbol would
		// still move endpoints between runs.
		if len(cls.Methods) != 2 {
			t.Fatalf("build %d: class kept %d methods, want the first copy's 2", i, len(cls.Methods))
		}

		fn, ok := st.Functions["duplicated_helper"]
		if !ok {
			t.Fatalf("build %d: function duplicated_helper missing", i)
		}
		if fn.File != firstFile || fn.Line != 8 {
			t.Fatalf("build %d: function kept from %s:%d, want %s:8", i, fn.File, fn.Line, firstFile)
		}

		c, ok := st.Constants["DUPLICATED_CONST"]
		if !ok {
			t.Fatalf("build %d: constant DUPLICATED_CONST missing", i)
		}
		if c.ResolvedValue != "first" {
			t.Fatalf("build %d: constant resolved to %q, want %q", i, c.ResolvedValue, "first")
		}

		// A file that loses one name still contributes the rest of its own.
		only, ok := st.Classes["Only_In_Second"]
		if !ok {
			t.Fatalf("build %d: class Only_In_Second missing", i)
		}
		if only.File != secondFile {
			t.Fatalf("build %d: Only_In_Second came from %s, want %s", i, only.File, secondFile)
		}
	}
}

// TestBuildSymbolTable_DuplicateFQNRecorded checks that the copies the rule
// discards are still reported. Choosing a winner is unavoidable, but doing it
// silently would leave a tree that really does ship two copies of a class
// indistinguishable from one that ships a single unambiguous copy.
func TestBuildSymbolTable_DuplicateFQNRecorded(t *testing.T) {
	dir, firstFile, secondFile := dupFQNFixture(t)

	pluginAST, err := ParsePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := BuildSymbolTable(pluginAST)

	want := map[string][]string{
		"class Duplicated_Controller": {firstFile, secondFile},
		"function duplicated_helper":  {firstFile, secondFile},
		"const DUPLICATED_CONST":      {firstFile, secondFile},
	}
	if len(st.Duplicates) != len(want) {
		t.Fatalf("Duplicates has %d entries (%v), want %d", len(st.Duplicates), st.Duplicates, len(want))
	}
	for key, wantFiles := range want {
		got, ok := st.Duplicates[key]
		if !ok {
			t.Errorf("Duplicates missing %q", key)
			continue
		}
		if len(got) != len(wantFiles) {
			t.Errorf("Duplicates[%q] = %v, want %v", key, got, wantFiles)
			continue
		}
		for i := range wantFiles {
			if got[i] != wantFiles[i] {
				// Element 0 is the copy that was kept, so order is part of the
				// contract, not an artefact.
				t.Errorf("Duplicates[%q][%d] = %s, want %s", key, i, got[i], wantFiles[i])
			}
		}
	}

	// A tree with nothing declared twice must not report duplicates at all.
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "only.php"), []byte("<?php\nclass Sole {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cleanAST, err := ParsePlugin(clean)
	if err != nil {
		t.Fatal(err)
	}
	if dup := BuildSymbolTable(cleanAST).Duplicates; len(dup) != 0 {
		t.Errorf("clean tree reported duplicates: %v", dup)
	}
}

// TestBuildSymbolTable_RepeatedDeclarationInOneFileUnchanged marks the edge of
// the determinism fix. Two declarations of one name inside a single file are
// still resolved the way they always were, last one wins, because that walk is
// an index loop over source order with no map in it: nothing about it varied
// between runs, so changing it would be a behaviour change hiding inside a
// determinism fix.
//
// This pins the behaviour, it does not endorse it. PHP keeps the first define()
// and warns on the second, so 'first' is the answer a running site would give.
// Two of the 154 trees in the benchmark corpus contain this shape (a sample
// config file defining one constant twice, for two alternative backends), and
// correcting it is a change that should be measured on its own.
func TestBuildSymbolTable_RepeatedDeclarationInOneFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	const src = `<?php
define( 'REPEATED_CONST', 'first' );
define( 'REPEATED_CONST', 'second' );
`
	if err := os.WriteFile(filepath.Join(dir, "sample-config.php"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	pluginAST, err := ParsePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}

	st := BuildSymbolTable(pluginAST)
	c, ok := st.Constants["REPEATED_CONST"]
	if !ok {
		t.Fatal("constant REPEATED_CONST missing")
	}
	if c.ResolvedValue != "second" {
		t.Errorf("REPEATED_CONST = %q, want %q (the pre-existing last-wins answer within one file)", c.ResolvedValue, "second")
	}
	if len(st.Duplicates) != 0 {
		t.Errorf("Duplicates = %v, want none: a repeat inside one file is not a cross-file ambiguity", st.Duplicates)
	}
}

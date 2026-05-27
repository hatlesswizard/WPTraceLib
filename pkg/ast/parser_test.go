package ast

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFile_ValidPHP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.php")
	content := `<?php
function hello() {
    echo "Hello, World!";
}
class MyPlugin {
    public function init() {
        add_action('wp_ajax_nopriv_test', [$this, 'handle']);
    }
}
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	pf, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if pf.Tree == nil {
		t.Fatal("parsed tree is nil")
	}
	root := pf.Tree.RootNode()
	if root == nil {
		t.Fatal("root node is nil")
	}
	if root.Type() != "program" {
		t.Errorf("expected root type 'program', got %q", root.Type())
	}
	if root.NamedChildCount() < 2 {
		t.Errorf("expected at least 2 named children, got %d", root.NamedChildCount())
	}
}

func TestParseFile_BOMStripping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.php")
	bom := []byte{0xEF, 0xBB, 0xBF}
	content := append(bom, []byte("<?php\necho 'test';\n")...)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	pf, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile with BOM failed: %v", err)
	}
	if pf.Tree == nil {
		t.Fatal("parsed tree is nil for BOM file")
	}
}

func TestParseFile_BinarySkip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.php")
	content := []byte("<?php\x00binary content")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ParseFile(path)
	if err == nil {
		t.Fatal("expected error for binary file")
	}
}

func TestParseFile_MalformedPHP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.php")
	content := `<?php
function broken( {
    echo 'test';
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	pf, err := ParseFile(path)
	if err != nil {
		t.Fatalf("expected error recovery, got error: %v", err)
	}
	if pf.Tree == nil {
		t.Fatal("expected partial AST from malformed PHP")
	}
}

func TestParsePlugin(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "main.php"), []byte("<?php\necho 'main';\n"), 0644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(dir, "includes")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "helper.php"), []byte("<?php\nfunction helper() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	vendorDir := filepath.Join(dir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "dep.php"), []byte("<?php\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("readme"), 0644); err != nil {
		t.Fatal(err)
	}

	pluginAST, err := ParsePlugin(dir)
	if err != nil {
		t.Fatalf("ParsePlugin failed: %v", err)
	}

	if len(pluginAST.Files) != 2 {
		t.Errorf("expected 2 parsed files, got %d", len(pluginAST.Files))
		for path := range pluginAST.Files {
			t.Logf("  parsed: %s", path)
		}
	}

	for path := range pluginAST.Files {
		if filepath.Base(filepath.Dir(path)) == "vendor" {
			t.Errorf("vendor file should have been skipped: %s", path)
		}
	}
}

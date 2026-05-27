package ast

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/php"
)

type ParsedFile struct {
	Path     string
	Tree     *sitter.Tree
	Source   []byte
	Language *sitter.Language
}

type PluginAST struct {
	Files map[string]*ParsedFile
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func ParseFile(path string) (*ParsedFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Skip binary files: null byte in first 512 bytes
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}
	if bytes.ContainsRune(data[:checkLen], 0) {
		return nil, fmt.Errorf("skip binary file: %s", path)
	}

	// Strip UTF-8 BOM
	data = bytes.TrimPrefix(data, utf8BOM)

	lang := php.GetLanguage()
	parser := sitter.NewParser()
	parser.SetLanguage(lang)

	tree, err := parser.ParseCtx(context.Background(), nil, data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return &ParsedFile{
		Path:     path,
		Tree:     tree,
		Source:   data,
		Language: lang,
	}, nil
}

func ParsePlugin(pluginDir string) (*PluginAST, error) {
	ast := &PluginAST{
		Files: make(map[string]*ParsedFile),
	}

	err := filepath.Walk(pluginDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := strings.ToLower(filepath.Base(path))
			if base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".php") {
			return nil
		}

		parsed, parseErr := ParseFile(path)
		if parseErr != nil {
			// Log warning but continue — regex fallback will handle this file
			fmt.Fprintf(os.Stderr, "ast: warning: %v\n", parseErr)
			return nil
		}

		ast.Files[path] = parsed
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", pluginDir, err)
	}

	return ast, nil
}

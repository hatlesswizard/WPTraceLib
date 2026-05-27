package analyzer

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	wpast "github.com/hatlesswizard/wptracelib/pkg/ast"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

var (
	directSuperglobalPattern = regexp.MustCompile(
		`\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[`)

	directPhpInputPattern = regexp.MustCompile(
		`php://input`)

	directBootstrapGuardPattern = regexp.MustCompile(
		`(?:defined\s*\(\s*['"](ABSPATH|WPINC)['"]\s*\)|` +
			`require(?:_once)?\s*\(?[^)]*(?:wp-load\.php|wp-blog-header\.php|wp-config\.php)|` +
			`(?:require|include)(?:_once)?\s*\(?[^)]*ABSPATH)`)

	directNamespacePattern = regexp.MustCompile(
		`^\s*namespace\s+[A-Za-z_\\]`)

	directClassOrFunctionOnlyPattern = regexp.MustCompile(
		`^\s*(?:abstract\s+|final\s+)?class\s+|^\s*(?:function\s+)`)
)

var skipDirs = map[string]bool{
	"templates": true,
	"views":     true,
	"partials":  true,
	"vendor":    true,
	"node_modules": true,
}

func DetectDirectPHPEndpoints(pluginDir, pluginSlug string) []models.Endpoint {
	var endpoints []models.Endpoint

	filepath.Walk(pluginDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			base := strings.ToLower(filepath.Base(path))
			if skipDirs[base] {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(path), ".php") {
			return nil
		}

		ep := analyzeDirectPHPFile(path, pluginDir, pluginSlug)
		if ep != nil {
			endpoints = append(endpoints, *ep)
		}
		return nil
	})

	return endpoints
}

func analyzeDirectPHPFile(path, pluginDir, pluginSlug string) *models.Endpoint {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	for i := 0; i < 100 && scanner.Scan(); i++ {
		lines = append(lines, scanner.Text())
	}

	if len(lines) == 0 {
		return nil
	}

	content := strings.Join(lines, "\n")

	hasSuperglobal := directSuperglobalPattern.MatchString(content)
	hasPhpInput := directPhpInputPattern.MatchString(content)

	if !hasSuperglobal && !hasPhpInput {
		return nil
	}

	if directBootstrapGuardPattern.MatchString(content) {
		return nil
	}

	firstCodeLine := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "<?php") ||
			strings.HasPrefix(trimmed, "<?") || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "#") {
			continue
		}
		firstCodeLine = trimmed
		break
	}

	if directNamespacePattern.MatchString(firstCodeLine) {
		return nil
	}

	if directClassOrFunctionOnlyPattern.MatchString(firstCodeLine) {
		hasProceduralCode := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if directSuperglobalPattern.MatchString(trimmed) || directPhpInputPattern.MatchString(trimmed) {
				hasProceduralCode = true
				break
			}
		}
		if !hasProceduralCode {
			return nil
		}
	}

	relPath, err := filepath.Rel(pluginDir, path)
	if err != nil {
		relPath = path
	}

	return &models.Endpoint{
		PluginSlug: pluginSlug,
		Type:       models.EndpointTypeDirect,
		Route:      relPath,
		Method:     "GET/POST",
		AuthLevel:  models.Unauthenticated,
		Callback:   filepath.Base(path),
		File:       relPath,
	}
}

// DetectDirectPHPEndpointsWithAST wraps DetectDirectPHPEndpoints with AST-backed
// auth dominator analysis to reclassify endpoints that have auth guards after bootstrap.
func DetectDirectPHPEndpointsWithAST(pluginDir, pluginSlug string, astCtx *wpast.ASTContext) []models.Endpoint {
	endpoints := DetectDirectPHPEndpoints(pluginDir, pluginSlug)

	if astCtx == nil || !astCtx.Available {
		return endpoints
	}

	for i := range endpoints {
		ep := &endpoints[i]
		funcFQN := "file:" + ep.File
		hasGuard, level := astCtx.Resolver.HasAuthGuardBeforeInput(funcFQN)
		if hasGuard {
			ep.AuthLevel = level
		}
	}

	return endpoints
}

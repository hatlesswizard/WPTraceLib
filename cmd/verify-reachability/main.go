package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/analyzer"
	"github.com/hatlesswizard/wptracelib/pkg/config"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

type CSVEntry struct {
	Status       string
	FullPath     string
	Plugin       string
	Version      string
	RelativePath string
	CVE          string
	Col5         string
	Col6         string
	Col7         string
	PluginDir    string
}

type FileResult struct {
	File              string   `json:"file"`
	PluginDir         string   `json:"plugin_dir"`
	CVE               string   `json:"cve"`
	Col6Prior         string   `json:"col6_prior"`
	Reachable         bool     `json:"reachable"`
	DirectEndpoint    bool     `json:"direct_endpoint"`
	InCallGraph       bool     `json:"in_call_graph"`
	EndpointsInPlugin int      `json:"endpoints_in_plugin"`
	MatchedEndpoints  []string `json:"matched_endpoints,omitempty"`
}

type Summary struct {
	Total          int `json:"total"`
	Reachable      int `json:"reachable"`
	NotReachable   int `json:"not_reachable"`
	EndpointsFound int `json:"endpoints_found"`
}

type Report struct {
	Summary Summary      `json:"summary"`
	Results []FileResult `json:"results"`
}

func main() {
	inputPath := flag.String("input", "", "Path to file-check-results.csv")
	pluginsDir := flag.String("plugins", "", "Base directory containing plugin directories")
	outputPath := flag.String("output", "results-wptracelib.json", "Output JSON path")
	flag.Parse()

	if *inputPath == "" || *pluginsDir == "" {
		fmt.Println("Usage: verify-reachability -input <csv> -plugins <dir> [-output <json>]")
		os.Exit(1)
	}

	fmt.Println("=== Step 1: Parsing CSV ===")
	entries := parseCSV(*inputPath)
	fmt.Printf("Parsed %d FOUND entries\n", len(entries))

	grouped := groupByPluginDir(entries)
	fmt.Printf("Unique plugin directories: %d\n", len(grouped))

	fmt.Println("\n=== Step 2: Analyzing plugins ===")
	report := analyzeAndVerify(grouped, *pluginsDir)

	fmt.Println("\n=== Step 3: Writing report ===")
	writeReport(report, *outputPath)
	fmt.Printf("Report saved to: %s\n", *outputPath)

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total files: %d\n", report.Summary.Total)
	fmt.Printf("Reachable: %d\n", report.Summary.Reachable)
	fmt.Printf("Not reachable: %d\n", report.Summary.NotReachable)
	fmt.Printf("Endpoints found across all plugins: %d\n", report.Summary.EndpointsFound)
}

func parseCSV(path string) []CSVEntry {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening CSV: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var entries []CSVEntry
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue
		}
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) < 9 {
			continue
		}
		if parts[0] != "FOUND" {
			continue
		}

		entry := CSVEntry{
			Status:       parts[0],
			FullPath:     parts[1],
			Plugin:       parts[2],
			Version:      parts[3],
			RelativePath: parts[4],
			CVE:          parts[5],
			Col5:         parts[6],
			Col6:         parts[7],
			Col7:         parts[8],
		}

		entry.PluginDir = extractPluginDir(entry.FullPath)
		if entry.PluginDir == "" {
			fmt.Printf("  Warning: could not extract plugin dir from %s\n", entry.FullPath)
			continue
		}

		entries = append(entries, entry)
	}
	return entries
}

func extractPluginDir(fullPath string) string {
	normalized := filepath.ToSlash(fullPath)
	parts := strings.Split(normalized, "/")
	for i, part := range parts {
		if part == "patchleaks-verify-test" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func groupByPluginDir(entries []CSVEntry) map[string][]CSVEntry {
	grouped := make(map[string][]CSVEntry)
	for _, e := range entries {
		grouped[e.PluginDir] = append(grouped[e.PluginDir], e)
	}
	return grouped
}

func analyzeAndVerify(grouped map[string][]CSVEntry, pluginsBase string) Report {
	cfg := config.New()
	cfg.VendorDirs = &config.VendorDirConfig{
		SkipPatterns:     []string{".git", "node_modules"},
		SkipComposerDirs: false,
	}

	a := analyzer.New(
		analyzer.WithChainMode(analyzer.ChainModeFlat),
		analyzer.WithConfig(cfg),
		analyzer.WithWorkers(10),
	)

	var report Report
	totalEndpoints := 0

	for pluginDir, entries := range grouped {
		dir := filepath.Join(pluginsBase, pluginDir)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			fmt.Printf("  [SKIP] %s: directory not found\n", pluginDir)
			for _, e := range entries {
				report.Results = append(report.Results, FileResult{
					File:      e.RelativePath,
					PluginDir: pluginDir,
					CVE:       e.CVE,
					Col6Prior: e.Col6,
				})
			}
			continue
		}

		fmt.Printf("  Analyzing %s...", pluginDir)
		analysis, err := a.AnalyzePlugin(context.Background(), dir)
		if err != nil {
			fmt.Printf(" ERROR: %v\n", err)
			for _, e := range entries {
				report.Results = append(report.Results, FileResult{
					File:      e.RelativePath,
					PluginDir: pluginDir,
					CVE:       e.CVE,
					Col6Prior: e.Col6,
				})
			}
			continue
		}
		epCount := len(analysis.Endpoints)
		totalEndpoints += epCount
		fmt.Printf(" %d endpoints", epCount)

		// Build the full call graph with all reachability features
		phpFiles := readAllPHPFiles(dir)
		cg := analyzer.BuildCallGraph(phpFiles)
		fmt.Printf(", %d funcs\n", len(cg.Functions))

		// Convert to models.Endpoint slice for the API
		modelEndpoints := make([]models.Endpoint, len(analysis.Endpoints))
		copy(modelEndpoints, analysis.Endpoints)

		// Build unified reachability: endpoints + WP core hooks + root file includes
		allReachableRaw := cg.GetAllHTTPReachableFiles(modelEndpoints)
		allReachable := make(map[string]bool, len(allReachableRaw))
		for f := range allReachableRaw {
			allReachable[normalizePath(f)] = true
		}

		// Debug: print stats for plugins with target files
		if len(entries) > 0 {
			rootFiles := 0
			for fp := range cg.AllFiles {
				if !strings.Contains(fp, "/") {
					rootFiles++
				}
			}
			fmt.Printf("    [debug] reachable=%d/%d, rootFiles=%d, hooks=%d, includes=%d, classes=%d\n",
				len(allReachable), len(cg.AllFiles), rootFiles,
				len(cg.HookRegistry.Hooks), len(cg.IncludesFrom), len(cg.ClassToFile))
		}

		type epInfo struct {
			epType   string
			route    string
			callback string
		}
		endpointsByFile := make(map[string][]epInfo)
		for _, ep := range analysis.Endpoints {
			norm := normalizePath(ep.File)
			endpointsByFile[norm] = append(endpointsByFile[norm], epInfo{
				epType:   string(ep.Type),
				route:    ep.Route,
				callback: ep.Callback,
			})
		}

		for _, entry := range entries {
			result := FileResult{
				File:              entry.RelativePath,
				PluginDir:         pluginDir,
				CVE:               entry.CVE,
				Col6Prior:         entry.Col6,
				EndpointsInPlugin: epCount,
			}

			targetNorm := normalizePath(entry.RelativePath)

			// Check 1: Direct endpoint in this file
			for fileKey, eps := range endpointsByFile {
				if pathMatch(fileKey, targetNorm) {
					result.DirectEndpoint = true
					for _, ep := range eps {
						detail := fmt.Sprintf("%s: %s (%s)", ep.epType, ep.route, ep.callback)
						result.MatchedEndpoints = append(result.MatchedEndpoints, detail)
					}
					break
				}
			}

			// Check 2: File is in the reachability set of any endpoint
			if !result.DirectEndpoint {
				for reachFile := range allReachable {
					if pathMatch(reachFile, targetNorm) {
						result.InCallGraph = true
						break
					}
				}
			}

			result.Reachable = result.DirectEndpoint || result.InCallGraph
			report.Results = append(report.Results, result)
		}
	}

	report.Summary.EndpointsFound = totalEndpoints
	for _, r := range report.Results {
		report.Summary.Total++
		if r.Reachable {
			report.Summary.Reachable++
		} else {
			report.Summary.NotReachable++
		}
	}

	return report
}

// readAllPHPFiles walks a directory and returns a map of relative path -> stripped PHP content.
// Does NOT skip vendor directories — we need full coverage for reachability analysis.
func readAllPHPFiles(dir string) map[string]string {
	files := make(map[string]string)

	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".php") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(dir, path)
		relPath = filepath.ToSlash(relPath)
		files[relPath] = analyzer.StripPHPComments(string(content))
		return nil
	})

	return files
}

func normalizePath(p string) string {
	return strings.ToLower(filepath.ToSlash(filepath.Clean(p)))
}

func pathMatch(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	if strings.HasSuffix(strings.ToLower(a), "/"+strings.ToLower(b)) {
		return true
	}
	if strings.HasSuffix(strings.ToLower(b), "/"+strings.ToLower(a)) {
		return true
	}
	return false
}

func writeReport(report Report, path string) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling report: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Printf("Error writing report: %v\n", err)
		os.Exit(1)
	}
}

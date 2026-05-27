// +build ignore

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ManualEndpoint represents an endpoint from manual analysis
type ManualEndpoint struct {
	Route     string
	Type      string // rest, ajax, admin
	AuthLevel string // unauth, user, admin
}

// DetectedEndpoint represents an endpoint from WPTraceLib
type DetectedEndpoint struct {
	Route     string
	Type      string
	AuthLevel string
	Method    string
}

// PluginValidation holds validation results for a plugin
type PluginValidation struct {
	Name              string
	ManualTotal       int
	ManualREST        int
	ManualAJAX        int
	ManualAdmin       int
	DetectedTotal     int
	DetectedREST      int
	DetectedAJAX      int
	DetectedAdmin     int
	RESTMatched       int
	AJAXMatched       int
	AdminMatched      int
	RESTMissed        []string
	AJAXMissed        []string
	AdminMissed       []string
	RESTExtra         []string
	AJAXExtra         []string
	AdminExtra        []string
	AuthCorrect       int
	AuthWrong         int
	AuthMismatches    []string
}

// ValidationReport holds the full validation report
type ValidationReport struct {
	TotalPlugins        int
	PluginsAnalyzed     int
	ManualTotal         int
	ManualREST          int
	ManualAJAX          int
	ManualAdmin         int
	DetectedTotal       int
	DetectedREST        int
	DetectedAJAX        int
	DetectedAdmin       int
	MatchedREST         int
	MatchedAJAX         int
	MatchedAdmin        int
	RESTCoverage        float64
	AJAXCoverage        float64
	AdminCoverage       float64
	OverallCoverage     float64
	AuthAccuracy        float64
	AuthCorrect         int
	AuthWrong           int
	PluginDetails       []PluginValidation
	MissedPatterns      map[string]int
}

func main() {
	analysisDir := "./analysis-results"
	pluginsDir := "./plugins"

	// Get list of manual analysis files
	files, err := filepath.Glob(filepath.Join(analysisDir, "*.txt"))
	if err != nil {
		fmt.Println("Error reading analysis files:", err)
		os.Exit(1)
	}

	report := ValidationReport{
		TotalPlugins:   len(files),
		MissedPatterns: make(map[string]int),
	}

	for _, file := range files {
		pluginName := strings.TrimSuffix(filepath.Base(file), ".txt")
		pluginPath := filepath.Join(pluginsDir, pluginName)

		// Check if plugin directory exists
		if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
			continue
		}

		// Parse manual analysis
		manualEndpoints := parseManualAnalysis(file)
		if len(manualEndpoints) == 0 {
			continue
		}

		// Run WPTraceLib
		detectedEndpoints := runWPTraceLib(pluginPath)

		// Compare
		validation := compareEndpoints(pluginName, manualEndpoints, detectedEndpoints)

		// Aggregate results
		report.PluginsAnalyzed++
		report.ManualTotal += validation.ManualTotal
		report.ManualREST += validation.ManualREST
		report.ManualAJAX += validation.ManualAJAX
		report.ManualAdmin += validation.ManualAdmin
		report.DetectedTotal += validation.DetectedTotal
		report.DetectedREST += validation.DetectedREST
		report.DetectedAJAX += validation.DetectedAJAX
		report.DetectedAdmin += validation.DetectedAdmin
		report.MatchedREST += validation.RESTMatched
		report.MatchedAJAX += validation.AJAXMatched
		report.MatchedAdmin += validation.AdminMatched
		report.AuthCorrect += validation.AuthCorrect
		report.AuthWrong += validation.AuthWrong

		// Track missed patterns
		for _, missed := range validation.RESTMissed {
			report.MissedPatterns["REST:"+missed]++
		}
		for _, missed := range validation.AJAXMissed {
			report.MissedPatterns["AJAX:"+missed]++
		}
		for _, missed := range validation.AdminMissed {
			report.MissedPatterns["Admin:"+missed]++
		}

		report.PluginDetails = append(report.PluginDetails, validation)

		// Progress output
		if report.PluginsAnalyzed%50 == 0 {
			fmt.Printf("Processed %d plugins...\n", report.PluginsAnalyzed)
		}
	}

	// Calculate coverage percentages
	if report.ManualREST > 0 {
		report.RESTCoverage = float64(report.MatchedREST) / float64(report.ManualREST) * 100
	}
	if report.ManualAJAX > 0 {
		report.AJAXCoverage = float64(report.MatchedAJAX) / float64(report.ManualAJAX) * 100
	}
	if report.ManualAdmin > 0 {
		report.AdminCoverage = float64(report.MatchedAdmin) / float64(report.ManualAdmin) * 100
	}
	if report.ManualTotal > 0 {
		report.OverallCoverage = float64(report.MatchedREST+report.MatchedAJAX+report.MatchedAdmin) / float64(report.ManualTotal) * 100
	}
	if report.AuthCorrect+report.AuthWrong > 0 {
		report.AuthAccuracy = float64(report.AuthCorrect) / float64(report.AuthCorrect+report.AuthWrong) * 100
	}

	// Output report
	printReport(report)

	// Save JSON report
	jsonData, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile("validation-report.json", jsonData, 0644)
}

func parseManualAnalysis(filepath string) []ManualEndpoint {
	file, err := os.Open(filepath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var endpoints []ManualEndpoint
	scanner := bufio.NewScanner(file)
	currentAuthLevel := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Detect auth level headers
		if strings.HasPrefix(line, "Unauthenticated Endpoint List:") {
			currentAuthLevel = "unauth"
			continue
		}
		if strings.HasPrefix(line, "Authenticated Endpoint List (User):") {
			currentAuthLevel = "user"
			continue
		}
		if strings.HasPrefix(line, "Authenticated Endpoint List (Admin):") {
			currentAuthLevel = "admin"
			continue
		}

		// Skip headers and empty lines
		if currentAuthLevel == "" {
			continue
		}

		// Parse endpoint
		ep := ManualEndpoint{
			Route:     line,
			AuthLevel: currentAuthLevel,
		}

		// Determine type
		if strings.HasPrefix(line, "/wp-json/") || strings.HasPrefix(line, "/wp-json") {
			ep.Type = "rest"
			ep.Route = strings.TrimPrefix(line, "/wp-json")
		} else if strings.Contains(line, "admin-ajax.php?action=") {
			ep.Type = "ajax"
			// Extract action name
			parts := strings.Split(line, "action=")
			if len(parts) > 1 {
				ep.Route = "wp_ajax_" + parts[1]
			}
		} else if strings.HasPrefix(line, "wp-ajax-") || strings.HasPrefix(line, "wp_ajax_") {
			ep.Type = "ajax"
			ep.Route = strings.Replace(line, "wp-ajax-", "wp_ajax_", 1)
		} else if strings.Contains(line, "admin.php?page=") {
			ep.Type = "admin"
			// Extract page slug
			parts := strings.Split(line, "page=")
			if len(parts) > 1 {
				ep.Route = parts[1]
			}
		} else if strings.Contains(line, "admin-post.php") {
			ep.Type = "admin"
			ep.Route = line
		} else if strings.Contains(line, "edit-tags.php") || strings.Contains(line, "edit.php") || strings.Contains(line, "tools.php") {
			ep.Type = "admin"
			ep.Route = line
		} else if strings.HasPrefix(line, "/") {
			// REST endpoint without /wp-json prefix
			ep.Type = "rest"
		} else {
			// Assume admin page slug
			ep.Type = "admin"
		}

		endpoints = append(endpoints, ep)
	}

	return endpoints
}

func runWPTraceLib(pluginPath string) []DetectedEndpoint {
	cmd := exec.Command("./wptracelib", "-analyze", pluginPath, "-json", "-json-file", "/tmp/wptracelib-output.json")
	cmd.Run()

	// Read JSON output
	data, err := os.ReadFile("/tmp/wptracelib-output.json")
	if err != nil {
		return nil
	}

	// Correct JSON structure
	type EndpointData struct {
		Type      string `json:"type"`
		Route     string `json:"route"`
		Method    string `json:"method"`
		AuthLevel string `json:"auth_level"`
	}

	var result struct {
		Endpoints struct {
			Unauthenticated []EndpointData `json:"unauthenticated"`
			Subscriber      []EndpointData `json:"subscriber"`
			Contributor     []EndpointData `json:"contributor"`
			Author          []EndpointData `json:"author"`
			Editor          []EndpointData `json:"editor"`
			Admin           []EndpointData `json:"admin"`
			SuperAdmin      []EndpointData `json:"superadmin"`
		} `json:"endpoints"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	var endpoints []DetectedEndpoint

	// Process unauthenticated endpoints
	for _, ep := range result.Endpoints.Unauthenticated {
		endpoints = append(endpoints, DetectedEndpoint{
			Route:     ep.Route,
			Type:      strings.ToLower(ep.Type),
			AuthLevel: "unauth",
			Method:    ep.Method,
		})
	}

	// Process subscriber endpoints (was "user")
	for _, ep := range result.Endpoints.Subscriber {
		endpoints = append(endpoints, DetectedEndpoint{
			Route:     ep.Route,
			Type:      strings.ToLower(ep.Type),
			AuthLevel: "user", // Keep "user" for validation compatibility
			Method:    ep.Method,
		})
	}

	// Process contributor endpoints
	for _, ep := range result.Endpoints.Contributor {
		endpoints = append(endpoints, DetectedEndpoint{
			Route:     ep.Route,
			Type:      strings.ToLower(ep.Type),
			AuthLevel: "user", // For validation, contributor is treated as "user" level
			Method:    ep.Method,
		})
	}

	// Process author endpoints
	for _, ep := range result.Endpoints.Author {
		endpoints = append(endpoints, DetectedEndpoint{
			Route:     ep.Route,
			Type:      strings.ToLower(ep.Type),
			AuthLevel: "user", // For validation, author is treated as "user" level
			Method:    ep.Method,
		})
	}

	// Process editor endpoints
	for _, ep := range result.Endpoints.Editor {
		endpoints = append(endpoints, DetectedEndpoint{
			Route:     ep.Route,
			Type:      strings.ToLower(ep.Type),
			AuthLevel: "user", // For validation, editor is treated as "user" level
			Method:    ep.Method,
		})
	}

	// Process admin endpoints
	for _, ep := range result.Endpoints.Admin {
		endpoints = append(endpoints, DetectedEndpoint{
			Route:     ep.Route,
			Type:      strings.ToLower(ep.Type),
			AuthLevel: "admin",
			Method:    ep.Method,
		})
	}

	// Process superadmin endpoints
	for _, ep := range result.Endpoints.SuperAdmin {
		endpoints = append(endpoints, DetectedEndpoint{
			Route:     ep.Route,
			Type:      strings.ToLower(ep.Type),
			AuthLevel: "admin", // For validation, superadmin is treated as "admin" level
			Method:    ep.Method,
		})
	}

	return endpoints
}

func normalizeAuthLevel(level string) string {
	level = strings.ToLower(level)
	if strings.Contains(level, "unauth") {
		return "unauth"
	}
	if strings.Contains(level, "admin") {
		return "admin"
	}
	return "user"
}

func compareEndpoints(pluginName string, manual []ManualEndpoint, detected []DetectedEndpoint) PluginValidation {
	v := PluginValidation{Name: pluginName}

	// Count by type
	for _, ep := range manual {
		v.ManualTotal++
		switch ep.Type {
		case "rest":
			v.ManualREST++
		case "ajax":
			v.ManualAJAX++
		case "admin":
			v.ManualAdmin++
		}
	}

	for _, ep := range detected {
		v.DetectedTotal++
		switch ep.Type {
		case "rest":
			v.DetectedREST++
		case "ajax":
			v.DetectedAJAX++
		case "admin":
			v.DetectedAdmin++
		}
	}

	// Build detected sets for matching
	detectedREST := make(map[string]DetectedEndpoint)
	detectedAJAX := make(map[string]DetectedEndpoint)
	detectedAdmin := make(map[string]DetectedEndpoint)

	for _, ep := range detected {
		switch ep.Type {
		case "rest":
			detectedREST[normalizeRoute(ep.Route)] = ep
		case "ajax":
			detectedAJAX[normalizeRoute(ep.Route)] = ep
		case "admin":
			detectedAdmin[normalizeRoute(ep.Route)] = ep
		}
	}

	// Match manual against detected
	usedREST := make(map[string]bool)
	usedAJAX := make(map[string]bool)
	usedAdmin := make(map[string]bool)

	for _, mep := range manual {
		normalizedRoute := normalizeRoute(mep.Route)

		switch mep.Type {
		case "rest":
			if dep, found := findMatchingEndpoint(normalizedRoute, detectedREST); found {
				v.RESTMatched++
				usedREST[normalizeRoute(dep.Route)] = true
				// Check auth level
				if dep.AuthLevel == mep.AuthLevel {
					v.AuthCorrect++
				} else {
					v.AuthWrong++
					v.AuthMismatches = append(v.AuthMismatches,
						fmt.Sprintf("[%s] %s: expected %s, got %s", mep.Type, mep.Route, mep.AuthLevel, dep.AuthLevel))
				}
			} else {
				v.RESTMissed = append(v.RESTMissed, mep.Route)
			}
		case "ajax":
			if dep, found := findMatchingEndpoint(normalizedRoute, detectedAJAX); found {
				v.AJAXMatched++
				usedAJAX[normalizeRoute(dep.Route)] = true
				if dep.AuthLevel == mep.AuthLevel {
					v.AuthCorrect++
				} else {
					v.AuthWrong++
					v.AuthMismatches = append(v.AuthMismatches,
						fmt.Sprintf("[%s] %s: expected %s, got %s", mep.Type, mep.Route, mep.AuthLevel, dep.AuthLevel))
				}
			} else {
				v.AJAXMissed = append(v.AJAXMissed, mep.Route)
			}
		case "admin":
			if dep, found := findMatchingEndpoint(normalizedRoute, detectedAdmin); found {
				v.AdminMatched++
				usedAdmin[normalizeRoute(dep.Route)] = true
				if dep.AuthLevel == mep.AuthLevel {
					v.AuthCorrect++
				} else {
					v.AuthWrong++
					v.AuthMismatches = append(v.AuthMismatches,
						fmt.Sprintf("[%s] %s: expected %s, got %s", mep.Type, mep.Route, mep.AuthLevel, dep.AuthLevel))
				}
			} else {
				v.AdminMissed = append(v.AdminMissed, mep.Route)
			}
		}
	}

	// Find extra detections (potential false positives)
	for route := range detectedREST {
		if !usedREST[route] {
			v.RESTExtra = append(v.RESTExtra, route)
		}
	}
	for route := range detectedAJAX {
		if !usedAJAX[route] {
			v.AJAXExtra = append(v.AJAXExtra, route)
		}
	}
	for route := range detectedAdmin {
		if !usedAdmin[route] {
			v.AdminExtra = append(v.AdminExtra, route)
		}
	}

	return v
}

func normalizeRoute(route string) string {
	route = strings.ToLower(route)
	route = strings.TrimPrefix(route, "/")
	route = strings.TrimPrefix(route, "wp-json/")
	route = strings.TrimPrefix(route, "wp-admin/")
	route = strings.ReplaceAll(route, "wp_ajax_", "")
	route = strings.ReplaceAll(route, "admin-ajax.php?action=", "")
	route = strings.ReplaceAll(route, "admin.php?page=", "")

	// Normalize regex patterns for route params
	route = regexp.MustCompile(`\(\?[pP]<[^>]+>`).ReplaceAllString(route, "(")
	route = regexp.MustCompile(`\(\?P<[^>]+>[^)]+\)`).ReplaceAllString(route, "*")
	route = regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(route, "*")
	route = regexp.MustCompile(`\\d\+`).ReplaceAllString(route, "*")
	route = regexp.MustCompile(`\[[^\]]+\]\+?`).ReplaceAllString(route, "*")
	route = regexp.MustCompile(`\(\*\)`).ReplaceAllString(route, "*")
	route = regexp.MustCompile(`\*+`).ReplaceAllString(route, "*")

	// Remove trailing slashes
	route = strings.TrimSuffix(route, "/")

	return route
}

// extractRouteKey extracts the key parts of a route for matching
func extractRouteKey(route string) string {
	normalized := normalizeRoute(route)

	// Split by / and keep significant parts
	parts := strings.Split(normalized, "/")
	var significant []string
	for _, p := range parts {
		if p != "" && p != "*" && len(p) > 1 {
			significant = append(significant, p)
		}
	}

	return strings.Join(significant, "/")
}

func findMatchingEndpoint(normalizedRoute string, endpoints map[string]DetectedEndpoint) (DetectedEndpoint, bool) {
	// Exact match
	if ep, found := endpoints[normalizedRoute]; found {
		return ep, true
	}

	// Extract key for fuzzy matching
	manualKey := extractRouteKey(normalizedRoute)

	// Try to find matching endpoint
	bestScore := 0.0
	var bestMatch DetectedEndpoint
	found := false

	for route, ep := range endpoints {
		detectedKey := extractRouteKey(route)

		score := fuzzyMatchScore(manualKey, detectedKey, normalizedRoute, route)
		if score > bestScore && score >= 0.5 {
			bestScore = score
			bestMatch = ep
			found = true
		}
	}

	return bestMatch, found
}

func fuzzyMatchScore(keyA, keyB, fullA, fullB string) float64 {
	// Check for exact key match
	if keyA == keyB && keyA != "" {
		return 1.0
	}

	// Check if one contains the other
	if strings.Contains(keyA, keyB) || strings.Contains(keyB, keyA) {
		if len(keyA) > 3 && len(keyB) > 3 {
			return 0.8
		}
	}

	// Check for suffix match (common for action names)
	partsA := strings.Split(keyA, "/")
	partsB := strings.Split(keyB, "/")

	// Get last significant part
	var lastA, lastB string
	if len(partsA) > 0 {
		lastA = partsA[len(partsA)-1]
	}
	if len(partsB) > 0 {
		lastB = partsB[len(partsB)-1]
	}

	// Last part exact match is a good indicator
	if lastA == lastB && len(lastA) > 3 {
		return 0.7
	}

	// Check if last parts are similar
	if strings.Contains(lastA, lastB) || strings.Contains(lastB, lastA) {
		if len(lastA) > 5 || len(lastB) > 5 {
			return 0.6
		}
	}

	// Count matching parts
	matchCount := 0
	for _, pa := range partsA {
		for _, pb := range partsB {
			if pa == pb && pa != "" && pa != "*" && len(pa) > 2 {
				matchCount++
			}
		}
	}

	if matchCount >= 2 {
		return 0.6
	}
	if matchCount >= 1 && (len(partsA) <= 2 || len(partsB) <= 2) {
		return 0.5
	}

	return 0.0
}

func printReport(r ValidationReport) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("WPTRACELIB VALIDATION REPORT")
	fmt.Println(strings.Repeat("=", 80))

	fmt.Printf("\nPlugins with Manual Analysis: %d\n", r.TotalPlugins)
	fmt.Printf("Plugins Successfully Analyzed: %d\n", r.PluginsAnalyzed)

	fmt.Println("\n" + strings.Repeat("-", 40))
	fmt.Println("ENDPOINT COUNTS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("%-20s %10s %10s %10s\n", "Type", "Manual", "Detected", "Matched")
	fmt.Printf("%-20s %10d %10d %10d\n", "REST", r.ManualREST, r.DetectedREST, r.MatchedREST)
	fmt.Printf("%-20s %10d %10d %10d\n", "AJAX", r.ManualAJAX, r.DetectedAJAX, r.MatchedAJAX)
	fmt.Printf("%-20s %10d %10d %10d\n", "Admin", r.ManualAdmin, r.DetectedAdmin, r.MatchedAdmin)
	fmt.Printf("%-20s %10d %10d %10d\n", "TOTAL", r.ManualTotal, r.DetectedTotal, r.MatchedREST+r.MatchedAJAX+r.MatchedAdmin)

	fmt.Println("\n" + strings.Repeat("-", 40))
	fmt.Println("COVERAGE METRICS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("REST Coverage:    %.1f%%\n", r.RESTCoverage)
	fmt.Printf("AJAX Coverage:    %.1f%%\n", r.AJAXCoverage)
	fmt.Printf("Admin Coverage:   %.1f%%\n", r.AdminCoverage)
	fmt.Printf("Overall Coverage: %.1f%%\n", r.OverallCoverage)
	fmt.Printf("Auth Accuracy:    %.1f%% (%d correct, %d wrong)\n", r.AuthAccuracy, r.AuthCorrect, r.AuthWrong)

	fmt.Println("\n" + strings.Repeat("-", 40))
	fmt.Println("TOP MISSED PATTERNS")
	fmt.Println(strings.Repeat("-", 40))

	// Sort missed patterns by count
	type patternCount struct {
		pattern string
		count   int
	}
	var patterns []patternCount
	for p, c := range r.MissedPatterns {
		patterns = append(patterns, patternCount{p, c})
	}
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].count > patterns[j].count
	})

	count := 0
	for _, p := range patterns {
		if count >= 20 {
			break
		}
		fmt.Printf("%3d x %s\n", p.count, p.pattern)
		count++
	}

	fmt.Println("\n" + strings.Repeat("-", 40))
	fmt.Println("WORST PERFORMING PLUGINS")
	fmt.Println(strings.Repeat("-", 40))

	// Sort plugins by missed count
	sort.Slice(r.PluginDetails, func(i, j int) bool {
		missedI := len(r.PluginDetails[i].RESTMissed) + len(r.PluginDetails[i].AJAXMissed) + len(r.PluginDetails[i].AdminMissed)
		missedJ := len(r.PluginDetails[j].RESTMissed) + len(r.PluginDetails[j].AJAXMissed) + len(r.PluginDetails[j].AdminMissed)
		return missedI > missedJ
	})

	for i := 0; i < 10 && i < len(r.PluginDetails); i++ {
		p := r.PluginDetails[i]
		missed := len(p.RESTMissed) + len(p.AJAXMissed) + len(p.AdminMissed)
		matched := p.RESTMatched + p.AJAXMatched + p.AdminMatched
		if missed == 0 {
			break
		}
		fmt.Printf("%s: %d missed, %d matched (Manual: %d, Detected: %d)\n",
			p.Name, missed, matched, p.ManualTotal, p.DetectedTotal)
		if len(p.RESTMissed) > 0 && len(p.RESTMissed) <= 3 {
			for _, m := range p.RESTMissed {
				fmt.Printf("  - REST: %s\n", m)
			}
		}
		if len(p.AJAXMissed) > 0 && len(p.AJAXMissed) <= 3 {
			for _, m := range p.AJAXMissed {
				fmt.Printf("  - AJAX: %s\n", m)
			}
		}
		if len(p.AdminMissed) > 0 && len(p.AdminMissed) <= 3 {
			for _, m := range p.AdminMissed {
				fmt.Printf("  - Admin: %s\n", m)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("VALIDATION COMPLETE")
	fmt.Println(strings.Repeat("=", 80))
}

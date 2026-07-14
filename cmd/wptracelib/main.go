package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hatlesswizard/wptracelib"
	"github.com/hatlesswizard/wptracelib/pkg/analyzer"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

const separator60 = "============================================================"

func main() {
	// Parse command line flags
	outputDir := flag.String("output", "./plugins", "Directory to download plugins to")
	workers := flag.Int("workers", 10, "Number of concurrent workers")
	maxPages := flag.Int("pages", 0, "Maximum number of pages to scrape (0 = all)")
	maxPlugins := flag.Int("plugins", 0, "Maximum successful plugins to fetch (0 = all)")
	analyzeOnly := flag.String("analyze", "", "Analyze existing plugins in directory")
	listOnly := flag.Bool("list-only", false, "Only list plugins without downloading")

	// Output control flags
	statsOnly := flag.Bool("stats", false, "Show only statistics without endpoint list")
	showUnauth := flag.Bool("unauth", false, "Show only unauthenticated endpoints")
	showSubscriber := flag.Bool("subscriber", false, "Show only subscriber-level endpoints")
	showContributor := flag.Bool("contributor", false, "Show only contributor-level endpoints")
	showAuthor := flag.Bool("author", false, "Show only author-level endpoints")
	showEditor := flag.Bool("editor", false, "Show only editor-level endpoints")
	showAdmin := flag.Bool("admin", false, "Show only admin-level endpoints")
	showSuperAdmin := flag.Bool("superadmin", false, "Show only super-admin-level endpoints")
	// Convenience aliases
	showUser := flag.Bool("user", false, "Alias for -subscriber (backwards compatibility)")
	showAuthenticated := flag.Bool("auth", false, "Show all authenticated endpoints (subscriber+)")
	saveFile := flag.String("save", "", "Save output to file")

	// Call chain output flags
	chainHuman := flag.Bool("chain-human", false, "Show hierarchical call chains in tree format")
	chainJson := flag.Bool("chain-json", false, "Output as JSON with nested call chains")

	flag.Parse()

	// Determine chain mode from flags
	var chainMode analyzer.ChainMode
	if *chainJson || *chainHuman {
		chainMode = analyzer.ChainModeHierarchical
	} else {
		chainMode = analyzer.ChainModeNone
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupted, cleaning up...")
		cancel()
	}()

	// Create config
	cfg := wptracelib.Config{
		OutputDir:      *outputDir,
		Workers:        *workers,
		ExtractPlugins: true,
		MaxPages:       *maxPages,
		MaxPlugins:     *maxPlugins,
		ChainMode:      chainMode,
	}

	// Create library instance
	lib := wptracelib.New(cfg)

	var report *models.FullReport
	var err error

	if *analyzeOnly != "" {
		// Only analyze existing plugins
		report, err = analyzeExisting(ctx, lib, *analyzeOnly)
	} else if *listOnly {
		// Only list plugins
		err = listPlugins(ctx, lib)
		return
	} else {
		// Full run: fetch, download, analyze
		report, err = lib.Run(ctx)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if report == nil {
		return
	}

	// Build output
	var output bytes.Buffer
	filters := AuthFilters{
		Unauth:        *showUnauth,
		Subscriber:    *showSubscriber || *showUser, // -user is alias for -subscriber
		Contributor:   *showContributor,
		Author:        *showAuthor,
		Editor:        *showEditor,
		Admin:         *showAdmin,
		SuperAdmin:    *showSuperAdmin,
		Authenticated: *showAuthenticated,
	}

	if *chainJson {
		// Output as JSON with nested call chains
		writeChainJSON(&output, report, filters)
	} else if *chainHuman {
		// Show hierarchical call chains in tree format
		writeChainHuman(&output, report, filters)
		writeSummary(&output, report)
	} else if *statsOnly {
		// Only show summary
		writeSummary(&output, report)
	} else {
		// Show endpoints (filtered if flags provided)
		writeEndpoints(&output, report, filters)
		writeSummary(&output, report)
	}

	// Get bytes once to avoid multiple copies
	outputBytes := output.Bytes()

	// Print to stdout (write directly from bytes to avoid extra copy)
	os.Stdout.Write(outputBytes)

	// Save to file if requested
	if *saveFile != "" {
		if err := os.WriteFile(*saveFile, outputBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save to file: %v\n", err)
		} else {
			fmt.Printf("\nOutput saved to: %s\n", *saveFile)
		}
	}
}

type AuthFilters struct {
	Unauth        bool
	Subscriber    bool
	Contributor   bool
	Author        bool
	Editor        bool
	Admin         bool
	SuperAdmin    bool
	Authenticated bool // Show all authenticated (subscriber+)
}

func (f AuthFilters) ShowAll() bool {
	return !f.Unauth && !f.Subscriber && !f.Contributor && !f.Author &&
		!f.Editor && !f.Admin && !f.SuperAdmin && !f.Authenticated
}

func (f AuthFilters) ShowAuthenticated() bool {
	return f.Authenticated
}

func analyzeExisting(ctx context.Context, lib *wptracelib.WPTraceLib, dir string) (*models.FullReport, error) {
	fmt.Printf("Analyzing plugins in: %s\n", dir)

	analyses, err := lib.AnalyzeDirectory(ctx, dir)
	if err != nil {
		return nil, err
	}

	// Pre-calculate total endpoint count for allocation
	totalEndpoints := 0
	for _, a := range analyses {
		totalEndpoints += len(a.Endpoints)
	}

	// Create a minimal report with pre-allocated capacity
	allEndpoints := make([]models.Endpoint, 0, totalEndpoints)
	for _, a := range analyses {
		allEndpoints = append(allEndpoints, a.Endpoints...)
	}

	// Create plugin info from analyses
	pluginInfos := make([]models.PluginInfo, len(analyses))
	for i, a := range analyses {
		pluginInfos[i] = models.PluginInfo{
			Slug:    a.PluginSlug,
			Name:    a.PluginName,
			Version: a.Version,
		}
	}

	report := &models.FullReport{
		Plugins:   pluginInfos,
		Endpoints: models.SortEndpointsByAuth(allEndpoints),
		Summary:   models.CalculateSummary(pluginInfos, analyses),
	}

	return report, nil
}

func listPlugins(ctx context.Context, lib *wptracelib.WPTraceLib) error {
	fmt.Println("Fetching popular plugins list...")

	plugins, err := lib.FetchPluginList(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("\nFound %d plugins:\n\n", len(plugins))
	fmt.Printf("%-40s %-20s %-15s\n", "NAME", "INSTALLS", "VERSION")
	fmt.Println(separator60)

	for _, p := range plugins {
		name := p.Name
		if len(name) > 38 {
			name = name[:35] + "..."
		}
		fmt.Printf("%-40s %-20s %-15s\n", name, p.ActiveInstallations, p.Version)
	}

	return nil
}

func writeEndpoints(buf *bytes.Buffer, report *models.FullReport, filters AuthFilters) {
	showAll := filters.ShowAll()
	showAuth := filters.ShowAuthenticated()

	if showAll || filters.Unauth {
		writeEndpointSection(buf, "UNAUTHENTICATED", report.Endpoints.Unauthenticated)
	}

	if showAll || showAuth || filters.Subscriber {
		writeEndpointSection(buf, "SUBSCRIBER", report.Endpoints.Subscriber)
	}

	if showAll || showAuth || filters.Contributor {
		writeEndpointSection(buf, "CONTRIBUTOR", report.Endpoints.Contributor)
	}

	if showAll || showAuth || filters.Author {
		writeEndpointSection(buf, "AUTHOR", report.Endpoints.Author)
	}

	if showAll || showAuth || filters.Editor {
		writeEndpointSection(buf, "EDITOR", report.Endpoints.Editor)
	}

	if showAll || showAuth || filters.Admin {
		writeEndpointSection(buf, "ADMIN", report.Endpoints.Admin)
	}

	if showAll || showAuth || filters.SuperAdmin {
		writeEndpointSection(buf, "SUPER ADMIN", report.Endpoints.SuperAdmin)
	}
}

func writeEndpointSection(buf *bytes.Buffer, title string, endpoints []models.Endpoint) {
	if len(endpoints) == 0 {
		return
	}

	buf.WriteString("\n")
	buf.WriteString(separator60)
	buf.WriteString("\n")
	fmt.Fprintf(buf, "%s ENDPOINTS (%d)\n", title, len(endpoints))
	buf.WriteString(separator60)
	buf.WriteString("\n")

	for _, ep := range endpoints {
		// Format: METHOD /route -> callback [func1, func2, ...]
		// For REST endpoints, show HTTP method
		// For AJAX/Admin, show endpoint type indicator
		switch ep.Type {
		case models.EndpointTypeREST:
			method := ep.Method
			if method == "" {
				method = "GET"
			}
			buf.WriteString(method)
			buf.WriteString(" ")
			buf.WriteString(ep.Route)
		case models.EndpointTypeAJAX:
			buf.WriteString("AJAX ")
			buf.WriteString(ep.Route)
		case models.EndpointTypeAdmin:
			buf.WriteString("ADMIN ")
			buf.WriteString(ep.Route)
		case models.EndpointTypeShortcode:
			buf.WriteString("SHORTCODE ")
			buf.WriteString(ep.Route)
		case models.EndpointTypeWidget:
			buf.WriteString("WIDGET ")
			buf.WriteString(ep.Route)
		case models.EndpointTypeBlock:
			buf.WriteString("BLOCK ")
			buf.WriteString(ep.Route)
		case models.EndpointTypeHookInput:
			buf.WriteString("HOOK ")
			buf.WriteString(ep.Route)
		default:
			buf.WriteString(ep.Route)
		}

		// Show callback if available and meaningful
		if ep.Callback != "" && ep.Callback != "unknown" && ep.Callback != "array_defined" {
			buf.WriteString(" -> ")
			buf.WriteString(ep.Callback)
		}

		// Show extracted input fields for shortcode/hook endpoints
		if ep.RawCode != "" && (ep.Type == models.EndpointTypeShortcode || ep.Type == models.EndpointTypeHookInput) {
			buf.WriteString(" ")
			buf.WriteString(ep.RawCode)
		}

		// Show function calls if available
		if len(ep.FunctionCalls) > 0 {
			buf.WriteString(" [")
			buf.WriteString(strings.Join(ep.FunctionCalls, ", "))
			buf.WriteString("]")
		}
		buf.WriteString("\n")
	}
}

func writeSummary(buf *bytes.Buffer, report *models.FullReport) {
	buf.WriteString("\n")
	buf.WriteString(separator60)
	buf.WriteString("\n")
	buf.WriteString("SUMMARY\n")
	buf.WriteString(separator60)
	buf.WriteString("\n")

	s := report.Summary
	authenticatedCount := s.AuthenticatedCount()

	fmt.Fprintf(buf, "Total: %d endpoints\n", s.TotalEndpoints)
	fmt.Fprintf(buf, "  Unauthenticated: %d\n", s.UnauthenticatedCount)
	fmt.Fprintf(buf, "  Authenticated:   %d (subscriber: %d, contributor: %d, author: %d, editor: %d, admin: %d, superadmin: %d)\n",
		authenticatedCount,
		s.SubscriberCount,
		s.ContributorCount,
		s.AuthorCount,
		s.EditorCount,
		s.AdminCount,
		s.SuperAdminCount)

	fmt.Fprintf(buf, "Types: %d REST | %d AJAX | %d Admin | %d Shortcode | %d Widget | %d Block | %d Hook\n",
		s.RESTCount,
		s.AJAXCount,
		s.AdminPagesCount,
		s.ShortcodeCount,
		s.WidgetCount,
		s.BlockCount,
		s.HookInputCount)

	if s.TotalPlugins > 1 {
		fmt.Fprintf(buf, "Plugins: %d\n", s.TotalPlugins)
	}
}

// JSONEndpoint is the structure for JSON output with call chains
type JSONEndpoint struct {
	PluginSlug string                  `json:"plugin_slug"`
	Method     string                  `json:"method,omitempty"`
	Route      string                  `json:"route"`
	Type       string                  `json:"type"`
	AuthLevel  string                  `json:"auth_level"`
	Callback   string                  `json:"callback"`
	File       string                  `json:"file"`
	Line       int                     `json:"line"`
	CallChain  []*models.CallChainNode `json:"call_chain,omitempty"`
}

func writeChainJSON(buf *bytes.Buffer, report *models.FullReport, filters AuthFilters) {
	// Build filtered endpoint list
	var endpoints []models.Endpoint

	showAll := filters.ShowAll()
	showAuth := filters.ShowAuthenticated()

	if showAll || filters.Unauth {
		endpoints = append(endpoints, report.Endpoints.Unauthenticated...)
	}
	if showAll || showAuth || filters.Subscriber {
		endpoints = append(endpoints, report.Endpoints.Subscriber...)
	}
	if showAll || showAuth || filters.Contributor {
		endpoints = append(endpoints, report.Endpoints.Contributor...)
	}
	if showAll || showAuth || filters.Author {
		endpoints = append(endpoints, report.Endpoints.Author...)
	}
	if showAll || showAuth || filters.Editor {
		endpoints = append(endpoints, report.Endpoints.Editor...)
	}
	if showAll || showAuth || filters.Admin {
		endpoints = append(endpoints, report.Endpoints.Admin...)
	}
	if showAll || showAuth || filters.SuperAdmin {
		endpoints = append(endpoints, report.Endpoints.SuperAdmin...)
	}

	// Convert to JSON output format
	output := make([]JSONEndpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		output = append(output, JSONEndpoint{
			PluginSlug: ep.PluginSlug,
			Method:     ep.Method,
			Route:      ep.Route,
			Type:       string(ep.Type),
			AuthLevel:  ep.AuthLevel.String(),
			Callback:   ep.Callback,
			File:       ep.File,
			Line:       ep.Line,
			CallChain:  ep.CallChain,
		})
	}

	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}

func writeChainHuman(buf *bytes.Buffer, report *models.FullReport, filters AuthFilters) {
	showAll := filters.ShowAll()
	showAuth := filters.ShowAuthenticated()

	if showAll || filters.Unauth {
		writeChainSection(buf, "UNAUTHENTICATED", report.Endpoints.Unauthenticated)
	}
	if showAll || showAuth || filters.Subscriber {
		writeChainSection(buf, "SUBSCRIBER", report.Endpoints.Subscriber)
	}
	if showAll || showAuth || filters.Contributor {
		writeChainSection(buf, "CONTRIBUTOR", report.Endpoints.Contributor)
	}
	if showAll || showAuth || filters.Author {
		writeChainSection(buf, "AUTHOR", report.Endpoints.Author)
	}
	if showAll || showAuth || filters.Editor {
		writeChainSection(buf, "EDITOR", report.Endpoints.Editor)
	}
	if showAll || showAuth || filters.Admin {
		writeChainSection(buf, "ADMIN", report.Endpoints.Admin)
	}
	if showAll || showAuth || filters.SuperAdmin {
		writeChainSection(buf, "SUPER ADMIN", report.Endpoints.SuperAdmin)
	}
}

func writeChainSection(buf *bytes.Buffer, title string, endpoints []models.Endpoint) {
	if len(endpoints) == 0 {
		return
	}

	buf.WriteString("\n")
	buf.WriteString(separator60)
	buf.WriteString("\n")
	fmt.Fprintf(buf, "%s ENDPOINTS (%d)\n", title, len(endpoints))
	buf.WriteString(separator60)
	buf.WriteString("\n")

	for _, ep := range endpoints {
		buf.WriteString("\n")

		// Write endpoint header
		switch ep.Type {
		case models.EndpointTypeREST:
			method := ep.Method
			if method == "" {
				method = "GET"
			}
			fmt.Fprintf(buf, "%s %s\n", method, ep.Route)
		case models.EndpointTypeAJAX:
			fmt.Fprintf(buf, "AJAX %s\n", ep.Route)
		case models.EndpointTypeAdmin:
			fmt.Fprintf(buf, "ADMIN %s\n", ep.Route)
		case models.EndpointTypeShortcode:
			fmt.Fprintf(buf, "SHORTCODE %s\n", ep.Route)
		case models.EndpointTypeWidget:
			fmt.Fprintf(buf, "WIDGET %s\n", ep.Route)
		case models.EndpointTypeBlock:
			fmt.Fprintf(buf, "BLOCK %s\n", ep.Route)
		case models.EndpointTypeHookInput:
			fmt.Fprintf(buf, "HOOK %s\n", ep.Route)
		default:
			buf.WriteString(ep.Route)
			buf.WriteString("\n")
		}

		// Write callback
		if ep.Callback != "" && ep.Callback != "unknown" && ep.Callback != "array_defined" {
			fmt.Fprintf(buf, "  Callback: %s\n", ep.Callback)
		}

		// Write extracted input fields for shortcode/hook endpoints
		if ep.RawCode != "" && (ep.Type == models.EndpointTypeShortcode || ep.Type == models.EndpointTypeHookInput) {
			fmt.Fprintf(buf, "  Input Fields: %s\n", ep.RawCode)
		}

		// Write call chain tree
		if len(ep.CallChain) > 0 {
			buf.WriteString("  Call Chain:\n")
			for i, node := range ep.CallChain {
				isLast := i == len(ep.CallChain)-1
				writeCallNode(buf, node, "    ", isLast)
			}
		}
	}
}

func writeCallNode(buf *bytes.Buffer, node *models.CallChainNode, prefix string, isLast bool) {
	// Tree drawing characters
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	buf.WriteString(prefix)
	buf.WriteString(connector)
	buf.WriteString(node.Function)
	buf.WriteString("\n")

	// Prepare prefix for children
	childPrefix := prefix
	if isLast {
		childPrefix += "    "
	} else {
		childPrefix += "│   "
	}

	// Write children
	for i, child := range node.Calls {
		writeCallNode(buf, child, childPrefix, i == len(node.Calls)-1)
	}
}

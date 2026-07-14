// Package wptracelib provides functionality to download WordPress plugins
// and analyze their endpoints for authentication requirements.
package wptracelib

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/analyzer"
	"github.com/hatlesswizard/wptracelib/pkg/downloader"
	"github.com/hatlesswizard/wptracelib/pkg/models"
	"github.com/hatlesswizard/wptracelib/pkg/scraper"
)

// Config holds configuration for WPTraceLib
type Config struct {
	// OutputDir is the directory where plugins will be downloaded
	OutputDir string

	// Workers is the number of concurrent workers for downloading and analysis
	Workers int

	// SaveMetadata determines whether to save plugin metadata to JSON
	SaveMetadata bool

	// MetadataFile is the path for the metadata JSON file
	MetadataFile string

	// ExtractPlugins determines whether to extract downloaded ZIP files
	ExtractPlugins bool

	// MaxPages limits the number of popular plugin pages to scrape (0 = all)
	MaxPages int

	// MaxPlugins limits successfully resolved plugins in popularity order (0 = all)
	MaxPlugins int

	// HTTPClientFactory is called once per HTTP attempt, including retries.
	// Nil uses WPTraceLib's default direct clients.
	HTTPClientFactory func() *http.Client

	// ChainMode specifies the call chain analysis mode
	// 0 (ChainModeNone): Skip call chain analysis (default, fastest)
	// 1 (ChainModeFlat): Build flat call lists
	// 2 (ChainModeHierarchical): Build hierarchical call trees for -chain-human or -chain-json
	ChainMode analyzer.ChainMode
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		OutputDir:      "./plugins",
		Workers:        10,
		SaveMetadata:   false,
		MetadataFile:   "plugins.json",
		ExtractPlugins: true,
		MaxPages:       0,
		MaxPlugins:     0,
	}
}

// WPTraceLib is the main library interface
type WPTraceLib struct {
	config     Config
	scraper    *scraper.Scraper
	downloader *downloader.Downloader
	analyzer   *analyzer.Analyzer
}

// New creates a new WPTraceLib instance
func New(cfg Config) *WPTraceLib {
	if cfg.Workers <= 0 {
		cfg.Workers = 10
	}

	scraperOptions := []scraper.Option{scraper.WithWorkers(cfg.Workers)}
	downloaderOptions := []downloader.Option{downloader.WithWorkers(cfg.Workers), downloader.WithOutputDir(cfg.OutputDir), downloader.WithExtract(cfg.ExtractPlugins)}
	if cfg.HTTPClientFactory != nil {
		scraperOptions = append(scraperOptions, scraper.WithHTTPClientProvider(cfg.HTTPClientFactory))
		downloaderOptions = append(downloaderOptions, downloader.WithHTTPClientProvider(cfg.HTTPClientFactory))
	}
	return &WPTraceLib{
		config:     cfg,
		scraper:    scraper.New(scraperOptions...),
		downloader: downloader.New(downloaderOptions...),
		analyzer:   analyzer.New(analyzer.WithWorkers(cfg.Workers), analyzer.WithChainMode(cfg.ChainMode)),
	}
}

// FetchPluginList fetches the list of popular WordPress plugins
func (w *WPTraceLib) FetchPluginList(ctx context.Context) ([]models.PluginInfo, error) {
	if w.config.MaxPlugins < 0 {
		return nil, fmt.Errorf("MaxPlugins cannot be negative: %d", w.config.MaxPlugins)
	}
	return w.scraper.FetchPopularPluginsBounded(ctx, w.config.MaxPages, w.config.MaxPlugins)
}

// DownloadPlugins downloads all specified plugins
func (w *WPTraceLib) DownloadPlugins(ctx context.Context, plugins []models.PluginInfo) ([]downloader.DownloadResult, error) {
	results := w.downloader.DownloadAll(ctx, plugins)

	// Count failures
	failures := 0
	for _, r := range results {
		if !r.Success {
			failures++
		}
	}

	if failures > 0 {
		fmt.Printf("Warning: %d/%d plugins failed to download\n", failures, len(plugins))
	}

	return results, nil
}

// AnalyzePlugin analyzes a single plugin directory
func (w *WPTraceLib) AnalyzePlugin(ctx context.Context, pluginDir string) (*models.PluginAnalysis, error) {
	return w.analyzer.AnalyzePlugin(ctx, pluginDir)
}

// AnalyzeAllPlugins analyzes all plugins in the output directory
func (w *WPTraceLib) AnalyzeAllPlugins(ctx context.Context) ([]models.PluginAnalysis, error) {
	return w.analyzer.AnalyzeAll(ctx, w.config.OutputDir)
}

// AnalyzeDirectory analyzes plugins in the specified directory.
// It auto-detects whether dir is a single plugin directory or a parent
// directory containing multiple plugins.
func (w *WPTraceLib) AnalyzeDirectory(ctx context.Context, dir string) ([]models.PluginAnalysis, error) {
	// Check if dir is a single plugin directory
	if isSinglePluginDirectory(dir) {
		analysis, err := w.analyzer.AnalyzePlugin(ctx, dir)
		if err != nil {
			return nil, err
		}
		return []models.PluginAnalysis{*analysis}, nil
	}
	// Otherwise treat as plugins parent directory
	return w.analyzer.AnalyzeAll(ctx, dir)
}

// isSinglePluginDirectory checks if dir is a WordPress plugin directory
// by looking for PHP files at root level with plugin headers.
func isSinglePluginDirectory(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	// Check for PHP files at root with plugin headers
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".php") {
			continue
		}

		// Read file and check for WordPress plugin header
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}

		// WordPress plugin header marker
		if strings.Contains(string(content), "Plugin Name:") {
			return true
		}
	}
	return false
}

// Run executes the full workflow: fetch, download, analyze
func (w *WPTraceLib) Run(ctx context.Context) (*models.FullReport, error) {
	// Step 1: Fetch plugin list
	fmt.Println("Fetching popular plugins list...")
	plugins, err := w.FetchPluginList(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch plugin list: %w", err)
	}
	fmt.Printf("Found %d plugins\n", len(plugins))

	// Step 2: Download plugins
	fmt.Println("Downloading plugins...")
	results, err := w.DownloadPlugins(ctx, plugins)
	if err != nil {
		return nil, fmt.Errorf("failed to download plugins: %w", err)
	}

	// Filter to successfully downloaded plugins
	successfulPlugins := make([]models.PluginInfo, 0)
	for _, r := range results {
		if r.Success {
			successfulPlugins = append(successfulPlugins, r.Plugin)
		}
	}
	fmt.Printf("Successfully downloaded %d plugins\n", len(successfulPlugins))

	// Step 3: Analyze plugins
	fmt.Println("Analyzing plugin endpoints...")
	analyses, err := w.AnalyzeAllPlugins(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze plugins: %w", err)
	}

	// Step 4: Generate report
	report := w.generateReport(successfulPlugins, analyses)

	// Step 5: Save metadata if requested
	if w.config.SaveMetadata {
		if err := w.saveMetadata(report); err != nil {
			fmt.Printf("Warning: failed to save metadata: %v\n", err)
		}
	}

	return report, nil
}

// generateReport creates a full report from plugins and analyses
func (w *WPTraceLib) generateReport(plugins []models.PluginInfo, analyses []models.PluginAnalysis) *models.FullReport {
	// Collect all endpoints
	allEndpoints := analyzer.CollectAllEndpoints(analyses)

	// Sort by auth level
	endpointsByAuth := models.SortEndpointsByAuth(allEndpoints)

	// Calculate summary
	summary := models.CalculateSummary(plugins, analyses)

	return &models.FullReport{
		Plugins:   plugins,
		Endpoints: endpointsByAuth,
		Summary:   summary,
	}
}

// saveMetadata saves the report to a JSON file
func (w *WPTraceLib) saveMetadata(report *models.FullReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(w.config.MetadataFile, data, 0644)
}

// SaveReport saves the report to a JSON file
func (w *WPTraceLib) SaveReport(report *models.FullReport, filepath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0644)
}

// GetEndpointsByAuthLevel returns endpoints filtered by authentication level
func GetEndpointsByAuthLevel(report *models.FullReport, level models.AuthLevel) []models.Endpoint {
	switch level {
	case models.Unauthenticated:
		return report.Endpoints.Unauthenticated
	case models.Subscriber:
		return report.Endpoints.Subscriber
	case models.Contributor:
		return report.Endpoints.Contributor
	case models.Author:
		return report.Endpoints.Author
	case models.Editor:
		return report.Endpoints.Editor
	case models.Admin:
		return report.Endpoints.Admin
	case models.SuperAdmin:
		return report.Endpoints.SuperAdmin
	default:
		return nil
	}
}

// GetUnauthenticatedEndpoints returns all unauthenticated endpoints
func GetUnauthenticatedEndpoints(report *models.FullReport) []models.Endpoint {
	return report.Endpoints.Unauthenticated
}

// GetSubscriberEndpoints returns all subscriber-level endpoints
func GetSubscriberEndpoints(report *models.FullReport) []models.Endpoint {
	return report.Endpoints.Subscriber
}

// GetContributorEndpoints returns all contributor-level endpoints
func GetContributorEndpoints(report *models.FullReport) []models.Endpoint {
	return report.Endpoints.Contributor
}

// GetAuthorEndpoints returns all author-level endpoints
func GetAuthorEndpoints(report *models.FullReport) []models.Endpoint {
	return report.Endpoints.Author
}

// GetEditorEndpoints returns all editor-level endpoints
func GetEditorEndpoints(report *models.FullReport) []models.Endpoint {
	return report.Endpoints.Editor
}

// GetAdminEndpoints returns all admin-level endpoints
func GetAdminEndpoints(report *models.FullReport) []models.Endpoint {
	return report.Endpoints.Admin
}

// GetSuperAdminEndpoints returns all super-admin-level endpoints
func GetSuperAdminEndpoints(report *models.FullReport) []models.Endpoint {
	return report.Endpoints.SuperAdmin
}

// GetAllAuthenticatedEndpoints returns all endpoints requiring authentication (subscriber+)
func GetAllAuthenticatedEndpoints(report *models.FullReport) []models.Endpoint {
	count := len(report.Endpoints.Subscriber) + len(report.Endpoints.Contributor) +
		len(report.Endpoints.Author) + len(report.Endpoints.Editor) +
		len(report.Endpoints.Admin) + len(report.Endpoints.SuperAdmin)
	endpoints := make([]models.Endpoint, 0, count)
	endpoints = append(endpoints, report.Endpoints.Subscriber...)
	endpoints = append(endpoints, report.Endpoints.Contributor...)
	endpoints = append(endpoints, report.Endpoints.Author...)
	endpoints = append(endpoints, report.Endpoints.Editor...)
	endpoints = append(endpoints, report.Endpoints.Admin...)
	endpoints = append(endpoints, report.Endpoints.SuperAdmin...)
	return endpoints
}

// GetEndpointsByPlugin returns all endpoints for a specific plugin
func GetEndpointsByPlugin(report *models.FullReport, pluginSlug string) []models.Endpoint {
	// Collect all endpoint slices for iteration
	allSlices := [][]models.Endpoint{
		report.Endpoints.Unauthenticated,
		report.Endpoints.Subscriber,
		report.Endpoints.Contributor,
		report.Endpoints.Author,
		report.Endpoints.Editor,
		report.Endpoints.Admin,
		report.Endpoints.SuperAdmin,
	}

	// Pre-count matching endpoints to avoid reallocations
	count := 0
	for _, slice := range allSlices {
		for _, ep := range slice {
			if ep.PluginSlug == pluginSlug {
				count++
			}
		}
	}

	endpoints := make([]models.Endpoint, 0, count)
	for _, slice := range allSlices {
		for _, ep := range slice {
			if ep.PluginSlug == pluginSlug {
				endpoints = append(endpoints, ep)
			}
		}
	}

	return endpoints
}

// GetEndpointsByType returns endpoints filtered by type (rest, ajax, admin)
// Iterates through slices directly to avoid creating intermediate slice (Issue 8 fix)
func GetEndpointsByType(report *models.FullReport, endpointType models.EndpointType) []models.Endpoint {
	// Collect all endpoint slices for iteration
	allSlices := [][]models.Endpoint{
		report.Endpoints.Unauthenticated,
		report.Endpoints.Subscriber,
		report.Endpoints.Contributor,
		report.Endpoints.Author,
		report.Endpoints.Editor,
		report.Endpoints.Admin,
		report.Endpoints.SuperAdmin,
	}

	// Pre-count matching endpoints to avoid reallocations
	count := 0
	for _, slice := range allSlices {
		for _, ep := range slice {
			if ep.Type == endpointType {
				count++
			}
		}
	}

	endpoints := make([]models.Endpoint, 0, count)
	for _, slice := range allSlices {
		for _, ep := range slice {
			if ep.Type == endpointType {
				endpoints = append(endpoints, ep)
			}
		}
	}

	return endpoints
}

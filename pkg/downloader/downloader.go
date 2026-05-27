package downloader

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hatlesswizard/wptracelib/pkg/httputil"
	"github.com/hatlesswizard/wptracelib/pkg/models"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout   = 5 * time.Minute
	defaultUserAgent = "WPTraceLib/1.0"
	defaultWorkers   = 10
)

// DownloadResult contains the result of a download operation
type DownloadResult struct {
	Plugin    models.PluginInfo
	Success   bool
	Error     error
	LocalPath string
}

// ProgressCallback is called to report download progress
type ProgressCallback func(completed, total int, current models.PluginInfo)

// Downloader handles concurrent plugin downloads
type Downloader struct {
	client    *http.Client
	outputDir string
	workers   int
	userAgent string
	extract   bool
	progress  ProgressCallback
}

// Option is a functional option for configuring the Downloader
type Option func(*Downloader)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) Option {
	return func(d *Downloader) {
		d.client = client
	}
}

// WithWorkers sets the number of concurrent workers
func WithWorkers(n int) Option {
	return func(d *Downloader) {
		if n > 0 {
			d.workers = n
		}
	}
}

// WithOutputDir sets the output directory
func WithOutputDir(dir string) Option {
	return func(d *Downloader) {
		d.outputDir = dir
	}
}

// WithExtract sets whether to auto-extract ZIP files
func WithExtract(extract bool) Option {
	return func(d *Downloader) {
		d.extract = extract
	}
}

// WithProgress sets a progress callback
func WithProgress(cb ProgressCallback) Option {
	return func(d *Downloader) {
		d.progress = cb
	}
}

// New creates a new Downloader instance
func New(opts ...Option) *Downloader {
	d := &Downloader{
		client: &http.Client{
			Timeout: defaultTimeout,
		},
		outputDir: "./plugins",
		workers:   defaultWorkers,
		userAgent: defaultUserAgent,
		extract:   true,
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// DownloadAll downloads all plugins concurrently
func (d *Downloader) DownloadAll(ctx context.Context, plugins []models.PluginInfo) []DownloadResult {
	// Ensure output directory exists
	if err := os.MkdirAll(d.outputDir, 0755); err != nil {
		results := make([]DownloadResult, len(plugins))
		for i, p := range plugins {
			results[i] = DownloadResult{
				Plugin:  p,
				Success: false,
				Error:   fmt.Errorf("failed to create output directory: %w", err),
			}
		}
		return results
	}

	var mu sync.Mutex
	results := make([]DownloadResult, 0, len(plugins))
	completed := 0
	total := len(plugins)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(d.workers)

	for _, plugin := range plugins {
		plugin := plugin // capture for goroutine
		g.Go(func() error {
			result := d.Download(ctx, plugin)

			mu.Lock()
			results = append(results, result)
			completed++
			if d.progress != nil {
				d.progress(completed, total, plugin)
			}
			mu.Unlock()

			return nil // Don't fail the group on individual download failures
		})
	}

	g.Wait()
	return results
}

// Download downloads a single plugin
func (d *Downloader) Download(ctx context.Context, plugin models.PluginInfo) DownloadResult {
	result := DownloadResult{Plugin: plugin}

	if plugin.DownloadURL == "" {
		result.Error = fmt.Errorf("no download URL available")
		return result
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, plugin.DownloadURL, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to create request: %w", err)
		return result
	}
	req.Header.Set("User-Agent", d.userAgent)

	// Execute request with retry logic
	resp, err := httputil.DoWithRetry(ctx, d.client, req, httputil.DefaultRetryConfig())
	if err != nil {
		result.Error = fmt.Errorf("failed to download after retries: %w", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		return result
	}

	// Determine file path
	zipPath := filepath.Join(d.outputDir, fmt.Sprintf("%s.zip", plugin.Slug))

	// Create file
	file, err := os.Create(zipPath)
	if err != nil {
		result.Error = fmt.Errorf("failed to create file: %w", err)
		return result
	}

	// Copy response body to file
	_, err = io.Copy(file, resp.Body)
	file.Close()

	if err != nil {
		os.Remove(zipPath)
		result.Error = fmt.Errorf("failed to write file: %w", err)
		return result
	}

	result.LocalPath = zipPath

	// Extract if requested
	if d.extract {
		extractPath := filepath.Join(d.outputDir, plugin.Slug)
		if err := d.extractZip(zipPath, extractPath); err != nil {
			result.Error = fmt.Errorf("failed to extract: %w", err)
			return result
		}
		// Remove the ZIP file after extraction
		os.Remove(zipPath)
		result.LocalPath = extractPath
	}

	result.Success = true
	return result
}

// extractZip extracts a ZIP file to the destination directory
func (d *Downloader) extractZip(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer reader.Close()

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}

	for _, file := range reader.File {
		err := d.extractFile(file, destDir)
		if err != nil {
			return err
		}
	}

	return nil
}

// extractFile extracts a single file from the ZIP archive
func (d *Downloader) extractFile(file *zip.File, destDir string) error {
	// Construct the full path
	path := filepath.Join(destDir, file.Name)

	// Check for ZipSlip vulnerability
	if !isInsidePath(destDir, path) {
		return fmt.Errorf("invalid file path: %s", file.Name)
	}

	if file.FileInfo().IsDir() {
		return os.MkdirAll(path, file.Mode())
	}

	// Create parent directories
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	// Create file
	destFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Open file in archive
	srcFile, err := file.Open()
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Copy contents
	_, err = io.Copy(destFile, srcFile)
	return err
}

// isInsidePath checks if target is inside base (prevents ZipSlip)
func isInsidePath(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(rel) && !strings.HasPrefix(rel, "..")
}

// GetOutputDir returns the output directory
func (d *Downloader) GetOutputDir() string {
	return d.outputDir
}

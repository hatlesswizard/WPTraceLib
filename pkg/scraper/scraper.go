package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hatlesswizard/wptracelib/pkg/httputil"
	"github.com/hatlesswizard/wptracelib/pkg/models"
	"golang.org/x/sync/errgroup"
)

const (
	defaultBaseURL   = "https://wordpress.org"
	defaultAPIURL    = "https://api.wordpress.org/plugins/info/1.2/"
	defaultUserAgent = "WPTraceLib/1.0"
	defaultTimeout   = 30 * time.Second
	defaultWorkers   = 10
	pluginsPerPage   = 20
)

// Package-level compiled regex patterns for scraper (Issue 12 fix)
var (
	// Pattern for extracting page number from pagination links
	scraperPageNumPattern = regexp.MustCompile(`/page/(\d+)/?`)

	// Pattern for extracting plugin slugs from URLs
	scraperPluginSlugPattern = regexp.MustCompile(`/plugins/([a-z0-9\-]+)/?$`)
)

// Scraper fetches plugin information from WordPress.org
type Scraper struct {
	client         *http.Client
	clientProvider httputil.ClientProvider
	baseURL        string
	apiURL         string
	userAgent      string
	workers        int
}

// Option is a functional option for configuring the Scraper
type Option func(*Scraper)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) Option {
	return func(s *Scraper) {
		s.client = client
	}
}

// WithHTTPClientProvider sets a provider that is called once per HTTP attempt.
func WithHTTPClientProvider(provider httputil.ClientProvider) Option {
	return func(s *Scraper) {
		s.clientProvider = provider
	}
}

// WithWorkers sets the number of concurrent workers
func WithWorkers(n int) Option {
	return func(s *Scraper) {
		if n > 0 {
			s.workers = n
		}
	}
}

// WithUserAgent sets a custom user agent
func WithUserAgent(ua string) Option {
	return func(s *Scraper) {
		s.userAgent = ua
	}
}

// New creates a new Scraper instance
func New(opts ...Option) *Scraper {
	s := &Scraper{
		client: &http.Client{
			Timeout: defaultTimeout,
		},
		baseURL:   defaultBaseURL,
		apiURL:    defaultAPIURL,
		userAgent: defaultUserAgent,
		workers:   defaultWorkers,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// FetchPopularPlugins fetches all plugins from the popular plugins pages
func (s *Scraper) FetchPopularPlugins(ctx context.Context) ([]models.PluginInfo, error) {
	return s.FetchPopularPluginsWithPages(ctx, 0) // 0 means all pages
}

// FetchPopularPluginsWithPages fetches plugins from the specified number of pages.
// If maxPages is 0, all available pages are considered.
func (s *Scraper) FetchPopularPluginsWithPages(ctx context.Context, maxPages int) ([]models.PluginInfo, error) {
	return s.FetchPopularPluginsBounded(ctx, maxPages, 0)
}

// FetchPopularPluginsBounded returns at most maxPlugins successfully resolved
// plugins in WordPress popularity order. Zero limits mean unlimited.
func (s *Scraper) FetchPopularPluginsBounded(ctx context.Context, maxPages, maxPlugins int) ([]models.PluginInfo, error) {
	if maxPlugins < 0 {
		return nil, fmt.Errorf("max plugins cannot be negative: %d", maxPlugins)
	}

	totalPages, slugs, err := s.fetchFirstPage(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch first page: %w", err)
	}
	if maxPages > 0 && totalPages > maxPages {
		totalPages = maxPages
	}

	plugins := make([]models.PluginInfo, 0)
	seen := make(map[string]bool)
	for page := 1; page <= totalPages; page++ {
		if page > 1 {
			slugs, err = s.fetchPage(ctx, page)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch page %d: %w", page, err)
			}
		}
		pageSlugs := make([]string, 0, len(slugs))
		for _, slug := range slugs {
			if !seen[slug] {
				seen[slug] = true
				pageSlugs = append(pageSlugs, slug)
			}
		}
		remaining := 0
		if maxPlugins > 0 {
			remaining = maxPlugins - len(plugins)
			if remaining == 0 {
				break
			}
		}
		resolved, err := s.fetchPluginDetailsBounded(ctx, pageSlugs, remaining)
		if err != nil {
			return nil, err
		}
		plugins = append(plugins, resolved...)
		if maxPlugins > 0 && len(plugins) >= maxPlugins {
			break
		}
	}
	return plugins, nil
}

// fetchFirstPage fetches the first page and returns total pages and slugs
func (s *Scraper) fetchFirstPage(ctx context.Context) (int, []string, error) {
	url := fmt.Sprintf("%s/plugins/browse/popular/", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := httputil.DoWithRetryProvider(ctx, s.httpClientProvider(), req, httputil.DefaultRetryConfig())
	if err != nil {
		return 0, nil, fmt.Errorf("failed to fetch first page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	// Extract total pages from pagination
	totalPages := s.extractTotalPages(doc)

	// Extract plugin slugs
	slugs := s.extractPluginSlugs(doc)

	return totalPages, slugs, nil
}

// extractTotalPages parses pagination to find total page count
func (s *Scraper) extractTotalPages(doc *goquery.Document) int {
	maxPage := 1

	// Look for pagination links
	doc.Find(".pagination a, .nav-links a, .posts-pagination a").Each(func(_ int, sel *goquery.Selection) {
		href, exists := sel.Attr("href")
		if !exists {
			return
		}

		// Extract page number from URL using pre-compiled pattern (Issue 12 fix)
		matches := scraperPageNumPattern.FindStringSubmatch(href)
		if len(matches) >= 2 {
			var pageNum int
			fmt.Sscanf(matches[1], "%d", &pageNum)
			if pageNum > maxPage {
				maxPage = pageNum
			}
		}
	})

	return maxPage
}

// extractPluginSlugs extracts plugin slugs from the page
func (s *Scraper) extractPluginSlugs(doc *goquery.Document) []string {
	slugs := make([]string, 0)
	seen := make(map[string]bool)

	// Find all plugin links
	doc.Find("a[href*='/plugins/']").Each(func(_ int, sel *goquery.Selection) {
		href, exists := sel.Attr("href")
		if !exists {
			return
		}

		// Extract slug from URL using pre-compiled pattern (Issue 12 fix)
		matches := scraperPluginSlugPattern.FindStringSubmatch(href)
		if len(matches) >= 2 {
			slug := matches[1]
			// Skip browse pages and other non-plugin paths
			if slug == "browse" || slug == "developers" || slug == "featured" || slug == "popular" || slug == "beta" {
				return
			}
			if !seen[slug] {
				seen[slug] = true
				slugs = append(slugs, slug)
			}
		}
	})

	return slugs
}

// fetchRemainingPages fetches pages from start to end concurrently
func (s *Scraper) fetchRemainingPages(ctx context.Context, start, end int) ([]string, error) {
	var mu sync.Mutex
	// Pre-allocate with estimated capacity based on pages and pluginsPerPage (Issue 5 fix)
	numPages := end - start + 1
	allSlugs := make([]string, 0, numPages*pluginsPerPage)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(s.workers)

	for page := start; page <= end; page++ {
		page := page // capture for goroutine
		g.Go(func() error {
			slugs, err := s.fetchPage(ctx, page)
			if err != nil {
				return fmt.Errorf("failed to fetch page %d: %w", page, err)
			}

			mu.Lock()
			allSlugs = append(allSlugs, slugs...)
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return allSlugs, nil
}

// fetchPage fetches a single page and returns plugin slugs
func (s *Scraper) fetchPage(ctx context.Context, page int) ([]string, error) {
	url := fmt.Sprintf("%s/plugins/browse/popular/page/%d/", s.baseURL, page)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := httputil.DoWithRetryProvider(ctx, s.httpClientProvider(), req, httputil.DefaultRetryConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch page %d: %w", page, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	return s.extractPluginSlugs(doc), nil
}

// fetchPluginDetailsBounded fetches details concurrently while preserving input
// order. For a positive limit, it requests only enough additional records to
// replace failures and reach that many successes.
func (s *Scraper) fetchPluginDetailsBounded(ctx context.Context, slugs []string, limit int) ([]models.PluginInfo, error) {
	plugins := make([]models.PluginInfo, 0, len(slugs))
	for next := 0; next < len(slugs) && (limit == 0 || len(plugins) < limit); {
		batchSize := s.workers
		if limit > 0 && batchSize > limit-len(plugins) {
			batchSize = limit - len(plugins)
		}
		if batchSize > len(slugs)-next {
			batchSize = len(slugs) - next
		}
		type result struct {
			info *models.PluginInfo
			err  error
		}
		results := make([]result, batchSize)
		g, groupCtx := errgroup.WithContext(ctx)
		for i := 0; i < batchSize; i++ {
			i, slug := i, slugs[next+i]
			g.Go(func() error {
				results[i].info, results[i].err = s.FetchPluginInfo(groupCtx, slug)
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return nil, err
		}
		for i, result := range results {
			if result.err != nil {
				fmt.Printf("Warning: failed to fetch plugin %s: %v\n", slugs[next+i], result.err)
				continue
			}
			plugins = append(plugins, *result.info)
			if limit > 0 && len(plugins) == limit {
				break
			}
		}
		next += batchSize
	}
	return plugins, nil
}

// fetchPluginDetails fetches all details and is retained for package callers.
func (s *Scraper) fetchPluginDetails(ctx context.Context, slugs []string) ([]models.PluginInfo, error) {
	return s.fetchPluginDetailsBounded(ctx, slugs, 0)
}

// FetchPluginInfo fetches detailed information for a single plugin
func (s *Scraper) FetchPluginInfo(ctx context.Context, slug string) (*models.PluginInfo, error) {
	url := fmt.Sprintf("%s?action=plugin_information&slug=%s", s.apiURL, slug)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := httputil.DoWithRetryProvider(ctx, s.httpClientProvider(), req, httputil.DefaultRetryConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch plugin info for %s: %w", slug, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp models.PluginAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	info := apiResp.ToPluginInfo()
	return &info, nil
}

// deduplicate removes duplicate strings from a slice
func deduplicate(items []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(items))

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func (s *Scraper) httpClientProvider() httputil.ClientProvider {
	if s.clientProvider != nil {
		return s.clientProvider
	}
	return httputil.StaticClientProvider(s.client)
}

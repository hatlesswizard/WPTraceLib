package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

type scrapeFixture struct {
	t             *testing.T
	pages         map[int][]string
	fail          map[string]bool
	delay         map[string]time.Duration
	mu            sync.Mutex
	pageRequests  []int
	detailRequest []string
	server        *httptest.Server
}

func newScrapeFixture(t *testing.T, pages map[int][]string) *scrapeFixture {
	f := &scrapeFixture{t: t, pages: pages, fail: map[string]bool{}, delay: map[string]time.Duration{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}

func (f *scrapeFixture) scraper(workers int) *Scraper {
	s := New(WithWorkers(workers))
	s.baseURL = f.server.URL
	s.apiURL = f.server.URL + "/api"
	return s
}

func (f *scrapeFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api" {
		slug := r.URL.Query().Get("slug")
		f.mu.Lock()
		f.detailRequest = append(f.detailRequest, slug)
		f.mu.Unlock()
		time.Sleep(f.delay[slug])
		if f.fail[slug] {
			http.Error(w, "missing", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"slug": slug, "name": slug, "download_link": f.server.URL + "/" + slug + ".zip"})
		return
	}
	page := 1
	if _, err := fmt.Sscanf(r.URL.Path, "/plugins/browse/popular/page/%d/", &page); err != nil && r.URL.Path != "/plugins/browse/popular/" {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	f.pageRequests = append(f.pageRequests, page)
	f.mu.Unlock()
	for _, slug := range f.pages[page] {
		fmt.Fprintf(w, `<a href="%s/plugins/%s/">%s</a>`, f.server.URL, slug, slug)
	}
	for n := 2; n <= len(f.pages); n++ {
		fmt.Fprintf(w, `<div class="pagination"><a href="%s/plugins/browse/popular/page/%d/">%d</a></div>`, f.server.URL, n, n)
	}
}

func TestFetchPopularPluginsBoundedLimits(t *testing.T) {
	tests := []struct {
		name       string
		maxPages   int
		maxPlugins int
		want       []string
		wantPages  []int
	}{
		{"unlimited", 0, 0, []string{"a", "b", "c", "d"}, []int{1, 2}},
		{"one", 0, 1, []string{"a"}, []int{1}},
		{"crosses pages", 0, 3, []string{"a", "b", "c"}, []int{1, 2}},
		{"max pages wins", 1, 3, []string{"a", "b"}, []int{1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newScrapeFixture(t, map[int][]string{1: {"a", "b"}, 2: {"c", "d"}})
			got, err := f.scraper(4).FetchPopularPluginsBounded(context.Background(), tc.maxPages, tc.maxPlugins)
			if err != nil {
				t.Fatal(err)
			}
			gotSlugs := make([]string, len(got))
			for i := range got {
				gotSlugs[i] = got[i].Slug
			}
			if !reflect.DeepEqual(gotSlugs, tc.want) {
				t.Fatalf("slugs = %v, want %v", gotSlugs, tc.want)
			}
			if !reflect.DeepEqual(f.pageRequests, tc.wantPages) {
				t.Fatalf("page requests = %v, want %v", f.pageRequests, tc.wantPages)
			}
			if tc.maxPlugins == 1 && !reflect.DeepEqual(f.detailRequest, []string{"a"}) {
				t.Fatalf("detail requests = %v; MaxPlugins=1 must request only one detail", f.detailRequest)
			}
		})
	}
}

func TestFetchPopularPluginsBoundedFailureReplacement(t *testing.T) {
	f := newScrapeFixture(t, map[int][]string{1: {"a", "b", "c"}})
	f.fail["a"] = true
	got, err := f.scraper(3).FetchPopularPluginsBounded(context.Background(), 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if gotSlugs := []string{got[0].Slug, got[1].Slug}; !reflect.DeepEqual(gotSlugs, []string{"b", "c"}) {
		t.Fatalf("slugs = %v", gotSlugs)
	}
	if len(f.detailRequest) != 3 {
		t.Fatalf("detail requests = %v, want all three candidates", f.detailRequest)
	}
	requested := map[string]bool{}
	for _, slug := range f.detailRequest {
		requested[slug] = true
	}
	if !requested["a"] || !requested["b"] || !requested["c"] {
		t.Fatalf("detail requests = %v", f.detailRequest)
	}
}

func TestFetchPopularPluginsBoundedPreservesOrderUnderConcurrency(t *testing.T) {
	f := newScrapeFixture(t, map[int][]string{1: {"a", "b", "c"}})
	f.delay["a"] = 30 * time.Millisecond
	f.delay["b"] = 10 * time.Millisecond
	got, err := f.scraper(3).FetchPopularPluginsBounded(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	gotSlugs := []string{got[0].Slug, got[1].Slug, got[2].Slug}
	if !reflect.DeepEqual(gotSlugs, []string{"a", "b", "c"}) {
		t.Fatalf("slugs = %v", gotSlugs)
	}
}

func TestHTTPClientProviderUsedForPageAndDetail(t *testing.T) {
	f := newScrapeFixture(t, map[int][]string{1: {"a"}})
	s := f.scraper(1)
	calls := 0
	s.clientProvider = func() *http.Client {
		calls++
		return f.server.Client()
	}
	got, err := s.FetchPopularPluginsBounded(context.Background(), 0, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %d plugins, err %v", len(got), err)
	}
	if calls != 2 {
		t.Fatalf("factory calls = %d, want page + detail attempts", calls)
	}
}

func TestFetchPopularPluginsBoundedNegative(t *testing.T) {
	f := newScrapeFixture(t, map[int][]string{1: {"a"}})
	if _, err := f.scraper(1).FetchPopularPluginsBounded(context.Background(), 0, -1); err == nil {
		t.Fatal("expected negative MaxPlugins error")
	}
}

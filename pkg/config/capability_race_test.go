package config

import (
	"sync"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// TestCapabilityIndexIsSafeUnderConcurrentLookup pins the lazily-built index
// against the concurrency this library actually runs under: the analyzer resolves
// capabilities from a worker pool, and the index is shared package state guarded
// by one lock. Run with -race, this fails if the build ever escapes the lock or
// if the returned map is mutated after publication.
func TestCapabilityIndexIsSafeUnderConcurrentLookup(t *testing.T) {
	cfg := New()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, capability := range []string{
				"manage_options", "edit_pages", "read", "edit_published_posts",
				"unfiltered_html", "not_a_capability_at_all",
			} {
				level, ok := cfg.GetCapabilityLevel(capability)
				if capability == "manage_options" && (!ok || level != models.Admin) {
					t.Errorf("manage_options: got %s ok=%v", level, ok)
				}
			}
		}()
	}
	wg.Wait()
}

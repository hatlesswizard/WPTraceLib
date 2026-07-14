package downloader

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

func TestDownloadUsesHTTPClientProvider(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	file, _ := zw.Create("plugin/plugin.php")
	_, _ = file.Write([]byte("<?php"))
	_ = zw.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive.Bytes())
	}))
	defer server.Close()

	var calls int32
	d := New(
		WithOutputDir(t.TempDir()),
		WithExtract(false),
		WithHTTPClientProvider(func() *http.Client {
			atomic.AddInt32(&calls, 1)
			return server.Client()
		}),
	)
	result := d.Download(context.Background(), models.PluginInfo{Slug: "plugin", DownloadURL: server.URL})
	if !result.Success {
		t.Fatalf("download failed: %v", result.Error)
	}
	if calls != 1 {
		t.Fatalf("factory calls = %d, want 1", calls)
	}
}

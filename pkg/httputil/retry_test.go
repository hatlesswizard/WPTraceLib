package httputil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoWithRetry_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := DoWithRetry(context.Background(), client, req, DefaultRetryConfig())
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestDoWithRetry_RetryOn503(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	cfg := RetryConfig{
		MaxRetries: 15,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}

	resp, err := DoWithRetry(context.Background(), client, req, cfg)
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}
	defer resp.Body.Close()

	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestDoWithRetry_ExhaustedRetries(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	cfg := RetryConfig{
		MaxRetries: 15,
		BaseDelay:  1 * time.Millisecond,
		MaxDelay:   10 * time.Millisecond,
	}

	_, err := DoWithRetry(context.Background(), client, req, cfg)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}

	if attempts != 15 {
		t.Errorf("expected exactly 15 attempts, got %d", attempts)
	}

	retryErr, ok := err.(*RetryError)
	if !ok {
		t.Fatalf("expected RetryError, got %T", err)
	}
	if retryErr.Attempts != 15 {
		t.Errorf("expected 15 attempts in error, got %d", retryErr.Attempts)
	}
}

func TestDoWithRetry_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	cfg := RetryConfig{
		MaxRetries: 15,
		BaseDelay:  100 * time.Millisecond,
		MaxDelay:   1 * time.Second,
	}

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := DoWithRetry(ctx, client, req, cfg)
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
}

func TestDoWithRetry_NonRetryableStatus(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusNotFound) // 404 is not retryable
	}))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := DoWithRetry(context.Background(), client, req, DefaultRetryConfig())
	if err != nil {
		t.Fatalf("expected response (not error) for non-retryable status: %v", err)
	}
	defer resp.Body.Close()

	if attempts != 1 {
		t.Errorf("expected 1 attempt for non-retryable status, got %d", attempts)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDoWithRetry_RetryAfterHeader(t *testing.T) {
	var attempts int32
	start := time.Now()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 2 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	cfg := RetryConfig{
		MaxRetries: 15,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   5 * time.Second,
	}

	resp, err := DoWithRetry(context.Background(), client, req, cfg)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	defer resp.Body.Close()

	// Should have waited at least 1 second due to Retry-After header
	if elapsed < 900*time.Millisecond {
		t.Errorf("expected at least 1s delay from Retry-After, got %v", elapsed)
	}
}

func TestDoWithRetry_OnRetryCallback(t *testing.T) {
	var attempts int32
	var callbackCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	cfg := RetryConfig{
		MaxRetries: 15,
		BaseDelay:  1 * time.Millisecond,
		MaxDelay:   10 * time.Millisecond,
		OnRetry: func(attempt int, err error, statusCode int) {
			atomic.AddInt32(&callbackCalls, 1)
		},
	}

	resp, err := DoWithRetry(context.Background(), client, req, cfg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	defer resp.Body.Close()

	// Should have called OnRetry twice (for attempts 1 and 2)
	if callbackCalls != 2 {
		t.Errorf("expected 2 OnRetry calls, got %d", callbackCalls)
	}
}

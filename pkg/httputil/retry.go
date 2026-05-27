// Package httputil provides HTTP utilities including retry logic.
package httputil

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

const (
	// MaxRetries is the fixed number of retry attempts.
	MaxRetries = 15

	// BaseDelay is the initial delay between retries.
	BaseDelay = 500 * time.Millisecond

	// MaxDelay caps the exponential backoff.
	MaxDelay = 30 * time.Second
)

// RetryableStatusCodes defines HTTP status codes that warrant a retry.
var RetryableStatusCodes = map[int]bool{
	429: true, // Too Many Requests
	500: true, // Internal Server Error
	502: true, // Bad Gateway
	503: true, // Service Unavailable
	504: true, // Gateway Timeout
}

// RetryConfig holds configuration for retry behavior.
type RetryConfig struct {
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
	// OnRetry is called before each retry attempt (optional, for logging).
	OnRetry func(attempt int, err error, statusCode int)
}

// DefaultRetryConfig returns a configuration with 15 retries.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: MaxRetries,
		BaseDelay:  BaseDelay,
		MaxDelay:   MaxDelay,
	}
}

// RetryError represents a failed request after all retries exhausted.
type RetryError struct {
	Attempts   int
	LastError  error
	StatusCode int
}

func (e *RetryError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("request failed after %d attempts: status %d", e.Attempts, e.StatusCode)
	}
	return fmt.Sprintf("request failed after %d attempts: %v", e.Attempts, e.LastError)
}

func (e *RetryError) Unwrap() error {
	return e.LastError
}

// DoWithRetry executes an HTTP request with retry logic.
// It returns the response (caller must close body) or an error after exhausting retries.
func DoWithRetry(ctx context.Context, client *http.Client, req *http.Request, cfg RetryConfig) (*http.Response, error) {
	var lastErr error
	var lastStatusCode int

	for attempt := 1; attempt <= cfg.MaxRetries; attempt++ {
		// Check context before each attempt
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context cancelled: %w", err)
		}

		// Clone request for retry (body must be re-readable or nil for GET)
		reqCopy := req.Clone(ctx)

		resp, err := client.Do(reqCopy)

		// Success case
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		// Handle network errors
		if err != nil {
			lastErr = err
			lastStatusCode = 0

			if cfg.OnRetry != nil {
				cfg.OnRetry(attempt, err, 0)
			}

			if attempt < cfg.MaxRetries {
				sleepWithJitter(ctx, cfg, attempt)
			}
			continue
		}

		// Handle retryable HTTP status codes
		if RetryableStatusCodes[resp.StatusCode] {
			lastStatusCode = resp.StatusCode
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)

			// Drain and close body to allow connection reuse
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if cfg.OnRetry != nil {
				cfg.OnRetry(attempt, lastErr, resp.StatusCode)
			}

			if attempt < cfg.MaxRetries {
				// For 429, check Retry-After header
				delay := calculateDelay(cfg, attempt, resp)
				sleepWithContext(ctx, delay)
			}
			continue
		}

		// Non-retryable status code (4xx except 429)
		return resp, nil
	}

	return nil, &RetryError{
		Attempts:   cfg.MaxRetries,
		LastError:  lastErr,
		StatusCode: lastStatusCode,
	}
}

// sleepWithJitter applies exponential backoff with jitter.
func sleepWithJitter(ctx context.Context, cfg RetryConfig, attempt int) {
	delay := calculateDelay(cfg, attempt, nil)
	sleepWithContext(ctx, delay)
}

// calculateDelay computes the delay for a given attempt.
func calculateDelay(cfg RetryConfig, attempt int, resp *http.Response) time.Duration {
	// Check for Retry-After header (for 429 responses)
	if resp != nil {
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if seconds, err := strconv.Atoi(retryAfter); err == nil {
				duration := time.Duration(seconds) * time.Second
				if duration <= cfg.MaxDelay {
					return duration
				}
			}
		}
	}

	// Exponential backoff: baseDelay * 2^(attempt-1)
	delay := cfg.BaseDelay * (1 << (attempt - 1))
	if delay > cfg.MaxDelay {
		delay = cfg.MaxDelay
	}

	// Add jitter: +/- 25%
	jitter := time.Duration(rand.Int63n(int64(delay / 2)))
	delay = delay - (delay / 4) + jitter

	return delay
}

// sleepWithContext sleeps for duration but respects context cancellation.
func sleepWithContext(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(d):
		return
	}
}

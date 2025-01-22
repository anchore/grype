package java

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestNewMavenSearchRateLimiter(t *testing.T) {
	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// We don't need to respond with anything for this test
	}))
	defer ts.Close()

	t.Run("default initialization", func(t *testing.T) {
		ms := newMavenSearch(http.DefaultClient, ts.URL)

		if ms.client == nil {
			t.Error("HTTP client was not initialized")
		}

		if ms.baseURL != ts.URL {
			t.Errorf("unexpected base URL: got %q, want %q", ms.baseURL, ts.URL)
		}

		if ms.rateLimiter == nil {
			t.Error("rate limiter was not initialized")
		}
	})

	t.Run("rate limiter configuration", func(t *testing.T) {
		ms := newMavenSearch(http.DefaultClient, ts.URL)

		expectedRate := rate.Every(300 * time.Millisecond)
		if ms.rateLimiter.Limit() != expectedRate {
			t.Errorf("unexpected rate limit: got %v, want %v", ms.rateLimiter.Limit(), rate.Limit(expectedRate))
		}

		if ms.rateLimiter.Burst() != 1 {
			t.Errorf("unexpected burst limit: got %d, want 1", ms.rateLimiter.Burst())
		}
	})

	t.Run("rate limiter behavior", func(t *testing.T) {
		ms := newMavenSearch(http.DefaultClient, ts.URL)
		ctx := context.Background()

		// First request should proceed immediately
		start := time.Now()
		err := ms.rateLimiter.Wait(ctx)
		if err != nil {
			t.Errorf("unexpected error on first wait: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
			t.Errorf("first request took too long: %v", elapsed)
		}

		// Second request should be delayed by ~300ms
		start = time.Now()
		err = ms.rateLimiter.Wait(ctx)
		if err != nil {
			t.Errorf("unexpected error on second wait: %v", err)
		}
		if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
			t.Errorf("rate limiting not enforced, second request took: %v", elapsed)
		}
	})

	t.Run("nil client", func(t *testing.T) {
		ms := newMavenSearch(nil, ts.URL)
		if ms.rateLimiter == nil {
			t.Error("rate limiter was not initialized with nil client")
		}
	})
}

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

	t.Run("custom rate limit initialization", func(t *testing.T) {
		customDuration := 500 * time.Millisecond
		ms := newMavenSearch(http.DefaultClient, ts.URL, customDuration)

		expectedRate := rate.Every(customDuration)
		if ms.rateLimiter.Limit() != expectedRate {
			t.Errorf("unexpected rate limit: got %v, want %v", ms.rateLimiter.Limit(), rate.Limit(expectedRate))
		}
	})

	t.Run("default rate limit initialization", func(t *testing.T) {
		defaultDuration := 300 * time.Millisecond
		ms := newMavenSearch(http.DefaultClient, ts.URL, defaultDuration)

		expectedRate := rate.Every(defaultDuration)
		if ms.rateLimiter.Limit() != expectedRate {
			t.Errorf("unexpected rate limit: got %v, want %v", ms.rateLimiter.Limit(), rate.Limit(expectedRate))
		}
	})

	t.Run("rate limiter behavior", func(t *testing.T) {
		ms := newMavenSearch(http.DefaultClient, ts.URL, 200*time.Millisecond)
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

		// Second request should be delayed
		start = time.Now()
		err = ms.rateLimiter.Wait(ctx)
		if err != nil {
			t.Errorf("unexpected error on second wait: %v", err)
		}
		if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
			t.Errorf("rate limiting not enforced, second request took: %v", elapsed)
		}
	})

	t.Run("config integration", func(t *testing.T) {
		testCases := []struct {
			name      string
			rateLimit time.Duration
			want      rate.Limit
		}{
			{
				name:      "with default rate limit",
				rateLimit: 300 * time.Millisecond,
				want:      rate.Every(300 * time.Millisecond),
			},
			{
				name:      "with custom rate limit",
				rateLimit: 500 * time.Millisecond,
				want:      rate.Every(500 * time.Millisecond),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ms := newMavenSearch(http.DefaultClient, ts.URL, tc.rateLimit)
				if ms.rateLimiter.Limit() != tc.want {
					t.Errorf("rate limit = %v, want %v", ms.rateLimiter.Limit(), tc.want)
				}
			})
		}
	})
}

func withinDelta(got, want, delta time.Duration) bool {
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	return diff <= delta
}

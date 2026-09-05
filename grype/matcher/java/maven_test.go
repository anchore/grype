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

func TestNewJavaMatcherTimeout(t *testing.T) {
	// stand up a server that hangs forever so any successful response would only happen
	// because the configured timeout failed to abort the request. The hang channel must be
	// closed before ts.Close() so any in-flight handlers unblock cleanly during shutdown.
	hang := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hang
	}))
	t.Cleanup(func() {
		close(hang)
		ts.Close()
	})

	t.Run("timeout aborts hanging upstream", func(t *testing.T) {
		m := NewJavaMatcher(MatcherConfig{
			ExternalSearchConfig: ExternalSearchConfig{
				MavenBaseURL:   ts.URL,
				MavenRateLimit: time.Nanosecond,
				MavenTimeout:   100 * time.Millisecond,
			},
		})

		start := time.Now()
		_, err := m.GetMavenPackageBySha(context.Background(), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		// give the runtime a generous ceiling so this test stays stable on slow CI
		if elapsed > 2*time.Second {
			t.Errorf("timeout did not fire promptly: elapsed = %v", elapsed)
		}
	})

	t.Run("zero timeout disables the per-request limit", func(t *testing.T) {
		m := NewJavaMatcher(MatcherConfig{
			ExternalSearchConfig: ExternalSearchConfig{
				MavenBaseURL: ts.URL,
				// MavenTimeout intentionally unset (zero value)
			},
		})

		// the underlying Matcher's MavenSearcher should be using http.DefaultClient,
		// which has no Timeout set
		ms, ok := m.MavenSearcher.(*mavenSearch)
		if !ok {
			t.Fatalf("MavenSearcher is not *mavenSearch, got %T", m.MavenSearcher)
		}
		if ms.client.Timeout != 0 {
			t.Errorf("expected zero timeout on default client, got %v", ms.client.Timeout)
		}
	})
}

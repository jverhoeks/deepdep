package resolve_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/resolve"
)

// crates.io rate-limits aggressively and asks crawlers for roughly one request
// a second. Without backoff a fleet scan turns every 429 into
// "error:ratelimit" on the node — a whole Rust repository silently degrades to
// Declared with no failure line anywhere, so the numbers look real and are not.
//
// A full org scan produced 352 of those across three repositories.
func TestCratesRetriesAfterRateLimit(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"versions":[{"num":"1.0.0","yanked":false}]}`))
	}))
	defer srv.Close()

	r := resolve.NewCratesResolver(srv.URL, nil, srv.Client(), 0, nil)
	got, err := r.Versions(context.Background(), "serde", false)
	if err != nil {
		t.Fatalf("a 429 must be retried, not surfaced as a resolution failure: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d versions after retry, want 1", len(got))
	}
	if atomic.LoadInt32(&hits) < 2 {
		t.Error("the request was never retried")
	}
}

// A limit that never gives up would hang a scan against a server that is down.
func TestCratesGivesUpAfterRepeatedRateLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	r := resolve.NewCratesResolver(srv.URL, nil, srv.Client(), 0, nil)
	done := make(chan error, 1)
	go func() {
		_, err := r.Versions(context.Background(), "serde", false)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a persistently rate-limited request must eventually fail")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("retries never gave up")
	}
}

// Requests are paced so a scan does not earn the 429 in the first place.
func TestCratesPacesItsRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"versions":[]}`))
	}))
	defer srv.Close()

	r := resolve.NewCratesResolver(srv.URL, nil, srv.Client(), 0, nil)
	start := time.Now()
	for _, name := range []string{"a", "b", "c"} {
		if _, err := r.Versions(context.Background(), name, false); err != nil {
			t.Fatal(err)
		}
	}
	// Three distinct crates cannot all go out in the same instant.
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("three requests took %v; they are not being paced at all", elapsed)
	}
}

package supply_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jverhoeks/deepdep/internal/supply"
)

// deps.dev rate-limits, and a widened closure asks it about far more projects
// far faster. Without backoff a 429 became a hard error, and because Projects
// returned the first error it saw, ONE throttled lookup failed the entire
// repository: a fleet run lost 8 of its first 46 repositories that way.
func TestProjectsRetriesRateLimits(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"starsCount": 7}`))
	}))
	defer srv.Close()

	c := supply.New(srv.URL, srv.Client())
	got, failed, err := c.Projects(context.Background(), []string{"github.com/a/b"})
	if err != nil {
		t.Fatalf("a 429 must be retried, not fail the repository: %v", err)
	}
	if failed != 0 {
		t.Errorf("failed = %d, want 0 after a successful retry", failed)
	}
	if got["github.com/a/b"].Stars != 7 {
		t.Errorf("got %+v, want the project after retry", got["github.com/a/b"])
	}
}

// Posture is one of four scoring terms and an ENRICHMENT. One project that
// stays unreachable must degrade that project to unknown, not lose the whole
// report — but the count must be returned so it can be said out loud rather
// than silently dropped.
func TestOneUnreachableProjectDoesNotFailTheRest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("") == "" && contains(r.URL.String(), "bad") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"starsCount": 3}`))
	}))
	defer srv.Close()

	c := supply.New(srv.URL, srv.Client())
	got, failed, err := c.Projects(context.Background(),
		[]string{"github.com/ok/one", "github.com/bad/two", "github.com/ok/three"})
	if err != nil {
		t.Fatalf("a partial result must not be an error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d projects, want the 2 that resolved: %v", len(got), got)
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1 — the loss must be counted, not dropped", failed)
	}
}

// A total outage IS an error: reporting every project as unknown would read as
// "nothing upstream is unmaintained", which is a wrong answer rather than a
// partial one.
func TestTotalOutageIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := supply.New(srv.URL, srv.Client())
	if _, failed, err := c.Projects(context.Background(),
		[]string{"github.com/a/b", "github.com/c/d"}); err == nil {
		t.Errorf("every lookup failed (%d) but no error was returned", failed)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && fmt.Sprintf("%s", s) != "" && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

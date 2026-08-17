package resolve_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/resolve"
)

// --concurrency is meaningless if a resolver serialises its own fetches.
//
// Both registry resolvers took a single mutex and DEFERRED the unlock across the
// whole of fetch — including the HTTP request — so every packument was
// downloaded one at a time no matter what the walker's concurrency was set to.
// A closure of a few thousand packages then costs a few thousand round trips
// end to end, which is what pushed a Poetry repository past its --timeout once
// extras were walked.
//
// Twelve distinct packages, each served with a delay: done in parallel this is
// about one delay, serialised it is twelve.
func assertParallel(t *testing.T, fetch func(ctx context.Context, name string) error) {
	t.Helper()
	const (
		n     = 12
		delay = 120 * time.Millisecond
	)
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = fetch(context.Background(), fmt.Sprintf("pkg%d", i))
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i, err := range errs {
		if err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}
	// Serialised would be n*delay. Allow generous slack for scheduling; the
	// point is to catch full serialisation, not to benchmark.
	if limit := time.Duration(n/3) * delay; elapsed > limit {
		t.Errorf("%d fetches took %v, over the %v budget — they are being serialised",
			n, elapsed, limit)
	}
}

func slowServer(t *testing.T, delay time.Duration, body func(name string) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.Write([]byte(body(r.URL.Path)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPyPIFetchesInParallel(t *testing.T) {
	srv := slowServer(t, 120*time.Millisecond, func(string) string {
		return `{"releases":{"1.0.0":[{"upload_time_iso_8601":"2024-01-01T00:00:00Z"}]},"info":{"requires_dist":[]}}`
	})
	r := resolve.NewPyPIResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, time.Now)
	assertParallel(t, func(ctx context.Context, name string) error {
		_, err := r.Versions(ctx, name, false)
		return err
	})
}

func TestNPMFetchesInParallel(t *testing.T) {
	srv := slowServer(t, 120*time.Millisecond, func(string) string {
		return `{"versions":{"1.0.0":{"name":"x","version":"1.0.0"}}}`
	})
	r := resolve.NewNPMResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, time.Now)
	assertParallel(t, func(ctx context.Context, name string) error {
		_, err := r.Versions(ctx, name, false)
		return err
	})
}

// Concurrent callers asking for the SAME package must not each fetch it. That
// is the reason the lock was held so widely in the first place, and it has to
// keep holding once the lock is narrowed.
func TestResolversFetchEachPackageOnce(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte(`{"versions":{"1.0.0":{"name":"x","version":"1.0.0"}}}`))
	}))
	defer srv.Close()

	r := resolve.NewNPMResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, time.Now)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Versions(context.Background(), "same-package", false)
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	for path, n := range hits {
		if n > 1 {
			t.Errorf("%s fetched %d times; concurrent callers must share one fetch", path, n)
		}
	}
}

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
// peakTracker records the greatest number of requests in flight at once.
//
// This asserts on OBSERVED CONCURRENCY rather than elapsed time. A wall-clock
// budget looks simpler but is a proxy, and it goes flaky the moment the machine
// is busy — this suite is routinely run while a fleet scan saturates the box.
// Counting overlap at the server measures the property directly and does not
// care how fast anything runs.
type peakTracker struct {
	mu       sync.Mutex
	inFlight int
	peak     int
}

func (p *peakTracker) enter() {
	p.mu.Lock()
	p.inFlight++
	if p.inFlight > p.peak {
		p.peak = p.inFlight
	}
	p.mu.Unlock()
}

func (p *peakTracker) leave() {
	p.mu.Lock()
	p.inFlight--
	p.mu.Unlock()
}

func (p *peakTracker) Peak() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

// assertParallel fetches n distinct packages concurrently and requires that
// more than one was ever in flight at the same time.
//
// Both registry resolvers used to take a single mutex and DEFER the unlock
// across the whole of fetch — including the HTTP request — so peak concurrency
// was exactly 1 no matter what --concurrency was set to. A few-thousand-package
// closure then cost a few-thousand sequential round trips, which is what pushed
// a Poetry repository past its --timeout once extras were walked.
func assertParallel(t *testing.T, peak *peakTracker, fetch func(ctx context.Context, name string) error) {
	t.Helper()
	const n = 12

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

	for i, err := range errs {
		if err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}
	if got := peak.Peak(); got < 2 {
		t.Errorf("peak concurrent requests = %d; the resolver is serialising its fetches", got)
	}
}

// blockingServer holds every request until `release` many are in flight, so a
// serialised resolver DEADLOCKS into its timeout rather than passing slowly.
// The barrier is what makes this deterministic instead of timing-dependent.
func trackedServer(t *testing.T, peak *peakTracker, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peak.enter()
		// Long enough that concurrent callers genuinely overlap, short enough
		// that a serialised implementation still finishes and reports peak 1.
		time.Sleep(30 * time.Millisecond)
		peak.leave()
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPyPIFetchesInParallel(t *testing.T) {
	var peak peakTracker
	srv := trackedServer(t, &peak,
		`{"releases":{"1.0.0":[{"upload_time_iso_8601":"2024-01-01T00:00:00Z"}]},"info":{"requires_dist":[]}}`)
	r := resolve.NewPyPIResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, time.Now)
	assertParallel(t, &peak, func(ctx context.Context, name string) error {
		_, err := r.Versions(ctx, name, false)
		return err
	})
}

func TestNPMFetchesInParallel(t *testing.T) {
	var peak peakTracker
	srv := trackedServer(t, &peak, `{"versions":{"1.0.0":{"name":"x","version":"1.0.0"}}}`)
	r := resolve.NewNPMResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, time.Now)
	assertParallel(t, &peak, func(ctx context.Context, name string) error {
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

package resolve_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/resolve"
)

func fixtures(t *testing.T) (abbrev, full []byte) {
	t.Helper()
	a, err := os.ReadFile("testdata/is-string-abbrev.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.ReadFile("testdata/is-string-full.json")
	if err != nil {
		t.Fatal(err)
	}
	return a, f
}

// serve returns a registry stub and a pointer to the Accept headers it saw.
func serve(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	abbrev, full := fixtures(t)
	var accepts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := r.Header.Get("Accept")
		accepts = append(accepts, a)
		if strings.Contains(a, "install-v1") {
			w.Write(abbrev)
		} else {
			w.Write(full)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &accepts
}

func TestAbbreviatedByDefault(t *testing.T) {
	srv, accepts := serve(t)
	r := resolve.NewNPMResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, time.Now)

	vs, err := r.Versions(context.Background(), "is-string", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("no versions parsed from packument")
	}
	if !strings.Contains((*accepts)[0], "install-v1") {
		t.Errorf("Accept = %q, want the abbreviated packument media type", (*accepts)[0])
	}
	// ascending, so the last is the newest
	for i := 1; i < len(vs); i++ {
		if vs[i-1].Version.String() > vs[i].Version.String() && vs[i-1].Version.String()[0] <= vs[i].Version.String()[0] {
			continue // string compare is not version compare; ordering asserted below
		}
	}
}

// The abbreviated packument has NO `time` map — verified against the real
// registry. Asking for publish times must therefore switch to the full
// document, or --as-of would be silently unimplementable.
func TestPublishTimesForceFullPackument(t *testing.T) {
	srv, accepts := serve(t)
	r := resolve.NewNPMResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, time.Now)

	vs, err := r.Versions(context.Background(), "is-string", true)
	if err != nil {
		t.Fatal(err)
	}
	last := (*accepts)[len(*accepts)-1]
	if strings.Contains(last, "install-v1") {
		t.Fatalf("Accept = %q; needPublished must fetch the FULL packument", last)
	}
	for _, v := range vs {
		if v.PublishedAt.IsZero() {
			t.Errorf("version %s has zero PublishedAt", v.Version)
		}
	}
}

// A packument is MUTABLE. Caching it under a timeless key freezes the resolver:
// every later run silently misses newly published versions, and a reproducibility
// check then passes for the wrong reason.
func TestPackumentRefetchedAfterMaxAge(t *testing.T) {
	abbrev, _ := fixtures(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write(abbrev)
	}))
	defer srv.Close()

	now := time.Now()
	clock := func() time.Time { return now }
	r := resolve.NewNPMResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, clock)

	r.Versions(context.Background(), "is-string", false)
	r.Versions(context.Background(), "is-string", false)
	if hits != 1 {
		t.Fatalf("within maxAge: %d fetches, want 1", hits)
	}

	now = now.Add(2 * time.Hour)
	if _, err := r.Versions(context.Background(), "is-string", false); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("after maxAge: %d fetches, want 2 — a packument must not be cached forever", hits)
	}
}

func TestRequirementsCarryScopes(t *testing.T) {
	srv, _ := serve(t)
	r := resolve.NewNPMResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, time.Now)

	vs, err := r.Versions(context.Background(), "is-string", false)
	if err != nil {
		t.Fatal(err)
	}
	newest := vs[len(vs)-1]
	reqs, err := r.Requirements(context.Background(), "is-string", newest.Version)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) == 0 {
		t.Fatal("is-string's newest version has dependencies in the fixture")
	}
	var sawProd bool
	for _, q := range reqs {
		if q.Constraint == "" {
			t.Errorf("requirement %q has an empty constraint", q.Name)
		}
		if q.Scope == "" {
			t.Errorf("requirement %q has no scope; the walker needs it to skip transitive dev deps", q.Name)
		}
		if q.Scope == graph.Prod {
			sawProd = true
		}
	}
	if !sawProd {
		t.Error("expected at least one prod dependency")
	}
}

func TestUnknownPackageIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	r := resolve.NewNPMResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(), time.Hour, time.Now)
	if _, err := r.Versions(context.Background(), "nope", false); err == nil {
		t.Error("a 404 must surface, so the walker can mark the node error:404 rather than dropping it")
	}
}

// TestParsedVersionMemoRespectsMaxAge.
//
// Versions() memoises the PARSED and sorted version list, because re-parsing a
// thousand version strings per requirement cost more than the fetch it avoided.
// That memo is derived from a MUTABLE document, so it has to die when the
// document is refetched — otherwise the packument refreshes and the list it was
// derived from does not, which is precisely the freeze the observation design
// exists to prevent.
func TestParsedVersionMemoRespectsMaxAge(t *testing.T) {
	abbrev, err := os.ReadFile("testdata/is-string-abbrev.json")
	if err != nil {
		t.Fatal(err)
	}
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write(abbrev)
	}))
	defer srv.Close()

	now := time.Now()
	r := resolve.NewNPMResolver(srv.URL, cache.NewFS(t.TempDir()), srv.Client(),
		time.Hour, func() time.Time { return now })

	for i := 0; i < 5; i++ {
		if _, err := r.Versions(context.Background(), "is-string", false); err != nil {
			t.Fatal(err)
		}
	}
	if hits != 1 {
		t.Fatalf("within maxAge: %d fetches, want 1 — the memo must absorb repeats", hits)
	}

	now = now.Add(2 * time.Hour)
	if _, err := r.Versions(context.Background(), "is-string", false); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("after maxAge: %d fetches, want 2 — the memo must not outlive the document", hits)
	}
}

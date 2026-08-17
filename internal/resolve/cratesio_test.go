package resolve_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jverhoeks/deepdep/internal/resolve"
	"github.com/jverhoeks/deepdep/internal/version"
)

func cratesStub(t *testing.T, docs map[string]string) (*resolve.CratesResolver, *[]string) {
	t.Helper()
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		body, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return resolve.NewCratesResolver(srv.URL, nil, srv.Client(), 0, nil), &asked
}

// The index's directory layout is keyed by NAME LENGTH. Getting it wrong 404s
// every crate shorter than four characters — cc, log, rand — which are among
// the most depended-upon crates there are.
func TestCratesIndexPathsByNameLength(t *testing.T) {
	line := `{"name":"x","vers":"1.0.0","yanked":false,"deps":[]}`
	r, asked := cratesStub(t, map[string]string{
		"/1/a":         line,
		"/2/cc":        line,
		"/3/l/log":     line,
		"/se/rd/serde": line,
	})
	for _, name := range []string{"a", "cc", "log", "serde"} {
		if _, err := r.Versions(context.Background(), name, false); err != nil {
			t.Errorf("Versions(%q): %v — wrong index path", name, err)
		}
	}
	if len(*asked) != 4 {
		t.Errorf("asked %v, want one request per crate", *asked)
	}
}

// A crate name is case-insensitive in the index and always lowercased there.
func TestCratesIndexLowercasesNames(t *testing.T) {
	r, asked := cratesStub(t, map[string]string{
		"/se/rd/serde_json": `{"name":"serde_json","vers":"1.0.0","yanked":false,"deps":[]}`,
	})
	if _, err := r.Versions(context.Background(), "Serde_JSON", false); err != nil {
		t.Fatalf("a capitalised crate name 404'd: %v", err)
	}
	if (*asked)[0] != "/se/rd/serde_json" {
		t.Errorf("requested %q, want the lowercased path", (*asked)[0])
	}
}

// One index request must serve BOTH versions and dependencies — that is the
// whole reason for using the index over the rate-limited API.
func TestCratesRequirementsCostNoExtraRequest(t *testing.T) {
	r, asked := cratesStub(t, map[string]string{
		"/se/rd/serde": `{"name":"serde","vers":"1.0.0","yanked":false,"deps":[{"name":"serde_derive","req":"^1","kind":"normal","optional":true},{"name":"criterion","req":"^0.5","kind":"dev","optional":false}]}`,
	})
	v, err := version.Cargo.Parse("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Versions(context.Background(), "serde", false); err != nil {
		t.Fatal(err)
	}
	reqs, err := r.Requirements(context.Background(), "serde", v)
	if err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 1 {
		t.Errorf("made %d requests, want 1 — the index line carries the deps", len(*asked))
	}
	if len(reqs) != 1 || reqs[0].Name != "serde_derive" {
		t.Fatalf("got %+v, want the normal dependency only (dev excluded)", reqs)
	}
}

// `package` names the real crate behind a rename; that is what is fetched and
// what advisories attach to.
func TestCratesRequirementsFollowRenames(t *testing.T) {
	r, _ := cratesStub(t, map[string]string{
		"/se/rd/serde": `{"name":"serde","vers":"1.0.0","yanked":false,"deps":[{"name":"alias","package":"real-crate","req":"^1","kind":"normal"}]}`,
	})
	v, _ := version.Cargo.Parse("1.0.0")
	reqs, err := r.Requirements(context.Background(), "serde", v)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Name != "real-crate" {
		t.Fatalf("got %+v, want the renamed-to crate", reqs)
	}
}

// A yank means no new resolution can select the version, so can-mode must not
// offer it as reachable.
func TestCratesExcludesYankedVersions(t *testing.T) {
	r, _ := cratesStub(t, map[string]string{
		"/se/rd/serde": "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"yanked\":false,\"deps\":[]}\n" +
			"{\"name\":\"serde\",\"vers\":\"1.0.1\",\"yanked\":true,\"deps\":[]}\n",
	})
	got, err := r.Versions(context.Background(), "serde", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Version.String() != "1.0.0" {
		t.Fatalf("got %v, want the unyanked version only", got)
	}
}

// A transient 429 or 503 must be retried rather than surfaced as a resolution
// failure: an error marks the node error:ratelimit and a whole Rust repository
// silently degrades to Declared with no failure line anywhere.
func TestCratesRetriesTransientFailures(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"name":"serde","vers":"1.0.0","yanked":false,"deps":[]}`))
	}))
	defer srv.Close()

	r := resolve.NewCratesResolver(srv.URL, nil, srv.Client(), 0, nil)
	got, err := r.Versions(context.Background(), "serde", false)
	if err != nil {
		t.Fatalf("a 429 must be retried: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d versions after retry, want 1", len(got))
	}
}

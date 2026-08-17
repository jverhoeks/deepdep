package forge_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/forge"
)

// repoPage renders n repositories as GitHub would.
func repoPage(prefix string, n int) string {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"full_name":"%s/r%d","clone_url":"https://x/%s/r%d.git"}`,
			prefix, i, prefix, i)
	}
	b.WriteString("]")
	return b.String()
}

// The bug this exists for. A rate limit part-way through the organisation
// listing used to fall through to the USER endpoint, whose smaller result was
// then reported as the organisation's size — one scan saying 186 repositories
// and the next 144, with nothing said about the 42 that vanished.
//
// Every fleet number is a sum over this list. A partial one is worse than none.
func TestRateLimitDoesNotSilentlyFallBackToASmallerList(t *testing.T) {
	var orgPages, userCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/orgs/"):
			orgPages++
			if orgPages == 1 {
				fmt.Fprint(w, repoPage("org", 100)) // full page: more to come
				return
			}
			w.Header().Set("X-RateLimit-Reset", "1893456000")
			w.WriteHeader(http.StatusForbidden)
		case strings.HasPrefix(r.URL.Path, "/users/"):
			userCalls++
			fmt.Fprint(w, repoPage("user", 3))
		}
	}))
	defer srv.Close()

	got, err := forge.New(srv.URL, "", srv.Client()).
		Org(context.Background(), "acme", forge.Options{})
	if err == nil {
		t.Fatalf("got %d repositories and no error; a truncated listing must fail loudly", len(got))
	}
	if got != nil {
		t.Errorf("got %d repositories alongside the error; callers sum these", len(got))
	}
	if userCalls != 0 {
		t.Error("fell back to the user endpoint after a rate limit; that substitutes " +
			"a different, smaller fleet for the one asked about")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("error = %q, want it to name the rate limit and the fix", err)
	}
}

// The fallback still has to work: people type `deepdep org torvalds`, and being
// told "not an organisation" helps nobody. 404 is the one condition that means
// "try the other endpoint".
func TestUserFallbackStillWorksOnNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/orgs/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, repoPage("torvalds", 2))
	}))
	defer srv.Close()

	got, err := forge.New(srv.URL, "", srv.Client()).
		Org(context.Background(), "torvalds", forge.Options{})
	if err != nil {
		t.Fatalf("a user account must still resolve: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d repositories, want 2", len(got))
	}
}

// A full page means another page follows; a short one is the end. Stopping early
// loses repositories just as quietly as the fallback did.
func TestPaginationCollectsEveryPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			fmt.Fprint(w, repoPage("a", 100))
		case "2":
			fmt.Fprint(w, repoPage("b", 7))
		default:
			fmt.Fprint(w, "[]")
		}
	}))
	defer srv.Close()

	got, err := forge.New(srv.URL, "", srv.Client()).
		Org(context.Background(), "acme", forge.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 107 {
		t.Errorf("got %d repositories, want 107 across two pages", len(got))
	}
}

// A genuinely absent owner is an error naming the name, not an empty success
// that reads as "this organisation has nothing in it".
func TestUnknownOwnerIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := forge.New(srv.URL, "", srv.Client()).
		Org(context.Background(), "nope", forge.Options{}); err == nil {
		t.Error("an owner that does not exist must not look like an empty one")
	}
}

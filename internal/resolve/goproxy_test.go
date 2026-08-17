package resolve_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/resolve"
	"github.com/jverhoeks/deepdep/internal/version"
)

// goProxyStub serves the three proxy endpoints and records what was asked for,
// so a test can assert on the URL as well as the answer.
func goProxyStub(t *testing.T, docs map[string]string) (*resolve.GoProxyResolver, *[]string) {
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
	return resolve.NewGoProxyResolver(srv.URL, nil, srv.Client(), 0, nil), &asked
}

// Module paths are case-sensitive but many filesystems are not, so the proxy
// protocol encodes every capital as "!" plus its lowercase. Getting this wrong
// 404s every module with a capital — Masterminds, Azure, BurntSushi — and the
// failure reads as "no such module" rather than as a client bug.
func TestGoProxyEscapesCapitalsInModulePaths(t *testing.T) {
	r, asked := goProxyStub(t, map[string]string{
		"/github.com/!masterminds/semver/@v/list": "v1.5.0\nv3.2.1\n",
	})

	got, err := r.Versions(context.Background(), "github.com/Masterminds/semver", false)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d versions, want 2", len(got))
	}
	if len(*asked) == 0 || !strings.Contains((*asked)[0], "!masterminds") {
		t.Errorf("requested %v, want the capital encoded as !masterminds", *asked)
	}
}

// A version can carry a capital too, and the separators between module and
// version must stay literal — escaping the whole path at once mangles them.
func TestGoProxyEscapesTheVersionSeparately(t *testing.T) {
	r, asked := goProxyStub(t, map[string]string{
		// Registered under the ESCAPED path: this is what a real proxy serves.
		"/example.com/m/@v/v1.0.0-!r!c1.mod": "module example.com/m\n\nrequire example.com/dep v1.2.3\n",
	})
	v, err := version.Go.Parse("v1.0.0-RC1")
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := r.Requirements(context.Background(), "example.com/m", v)
	if err != nil {
		t.Fatalf("Requirements: %v", err)
	}
	if len(reqs) != 1 || reqs[0].Name != "example.com/dep" {
		t.Fatalf("got %+v, want the one direct requirement", reqs)
	}
	if !strings.Contains((*asked)[0], "/@v/v1.0.0-!r!c1.mod") {
		t.Errorf("requested %q, want the version's capitals encoded and the /@v/ separator literal", (*asked)[0])
	}
}

// A dependency's go.mod lists ITS indirect requirements too. Returning them
// would re-add the same modules at every level of the walk and count one
// package many times; the walker reaches them through their own module instead.
func TestGoProxyReturnsOnlyDirectRequirements(t *testing.T) {
	r, _ := goProxyStub(t, map[string]string{
		"/example.com/m/@v/v1.0.0.mod": `
module example.com/m

require (
	example.com/direct v1.0.0
	example.com/indirect v2.0.0 // indirect
)
`,
	})
	v, _ := version.Go.Parse("v1.0.0")
	reqs, err := r.Requirements(context.Background(), "example.com/m", v)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Name != "example.com/direct" {
		t.Fatalf("got %+v, want only the direct requirement", reqs)
	}
}

// A module with no tagged releases is served an empty list. That is a real
// answer — "nothing published under a tag" — and must not read as an error, or
// one such dependency fails the whole scan.
func TestGoProxyEmptyVersionListIsNotAnError(t *testing.T) {
	r, _ := goProxyStub(t, map[string]string{"/example.com/m/@v/list": "\n"})
	got, err := r.Versions(context.Background(), "example.com/m", false)
	if err != nil {
		t.Fatalf("an empty list must not be an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d versions, want 0", len(got))
	}
}

func TestGoProxyEcosystem(t *testing.T) {
	r, _ := goProxyStub(t, nil)
	if r.Ecosystem() != "golang" {
		t.Errorf("Ecosystem() = %q, want golang to match the PURL type", r.Ecosystem())
	}
}

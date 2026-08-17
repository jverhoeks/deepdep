package effective_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/source"
)

func goResolve(t *testing.T, files ...source.File) []effective.Instance {
	t.Helper()
	inst, err := effective.GoMod{}.Resolve(context.Background(), source.Static(files))
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

// The build list is the WHOLE require set. Indirect entries are what MVS
// actually selected and installed; the extractor deliberately leaves them out of
// the declarations, so if they are missing here they are missing everywhere and
// a Go repository's real closure goes unaudited.
func TestGoBuildListIncludesIndirectRequirements(t *testing.T) {
	inst := goResolve(t, source.File{Path: "go.mod", Data: []byte(`
module example.com/app

go 1.24

require (
	github.com/gorilla/mux v1.8.1
	golang.org/x/net v0.17.0 // indirect
)
`)})
	if len(inst) != 2 {
		t.Fatalf("got %d instances, want 2 — the indirect requirement is part of the build", len(inst))
	}
	for _, want := range []string{
		"pkg:golang/github.com/gorilla/mux@v1.8.1",
		"pkg:golang/golang.org/x/net@v0.17.0",
	} {
		found := false
		for _, i := range inst {
			if string(i.NodeID) == want {
				found = true
				if i.DerivedFrom != "lockfile" {
					t.Errorf("%s DerivedFrom = %q, want lockfile — go.mod IS the lockfile", want, i.DerivedFrom)
				}
			}
		}
		if !found {
			t.Errorf("missing %s from the build list", want)
		}
	}
}

// go.sum lists every version ever CONSIDERED, including ones MVS rejected.
// Reading it as the install set inflates the closure with versions that are not
// there, so it must be ignored entirely.
func TestGoSumIsNotTheBuildList(t *testing.T) {
	inst := goResolve(t,
		source.File{Path: "go.mod", Data: []byte("module m\n\nrequire example.com/a v1.2.0\n")},
		source.File{Path: "go.sum", Data: []byte(
			"example.com/a v1.0.0 h1:aaa=\nexample.com/a v1.1.0 h1:bbb=\nexample.com/a v1.2.0 h1:ccc=\n")},
	)
	if len(inst) != 1 {
		t.Fatalf("got %d instances, want 1; go.sum's rejected versions leaked into the build list", len(inst))
	}
	if got := string(inst[0].NodeID); got != "pkg:golang/example.com/a@v1.2.0" {
		t.Errorf("selected %s, want the version go.mod requires", got)
	}
}

// A repository can hold several modules, each with its own selected versions.
// Reading only the root reports an empty build for all the others, and
// collapsing them would hide one of two legitimately different selections.
func TestGoEveryModuleInTheRepositoryIsRead(t *testing.T) {
	inst := goResolve(t,
		source.File{Path: "go.mod", Data: []byte("module m\n\nrequire example.com/a v1.0.0\n")},
		source.File{Path: "svc/go.mod", Data: []byte("module m/svc\n\nrequire example.com/a v2.0.0\n")},
	)
	if len(inst) != 2 {
		t.Fatalf("got %d instances, want 2 — one per module", len(inst))
	}
	if inst[0].Locator == inst[1].Locator {
		t.Error("both modules share a locator; one selection is hiding the other")
	}
}

// vendor/ holds OTHER modules' manifests. Their requirements are not this
// build's selected versions, and reading them reports another project's
// dependencies as this repository's.
func TestGoVendoredManifestsAreIgnored(t *testing.T) {
	inst := goResolve(t,
		source.File{Path: "go.mod", Data: []byte("module m\n\nrequire example.com/a v1.0.0\n")},
		source.File{Path: "vendor/example.com/b/go.mod", Data: []byte("module example.com/b\n\nrequire example.com/c v9.9.9\n")},
	)
	for _, i := range inst {
		if strings.Contains(string(i.NodeID), "example.com/c") {
			t.Error("a vendored module's own requirements were read as this build's")
		}
	}
	if len(inst) != 1 {
		t.Fatalf("got %d instances, want 1", len(inst))
	}
}

// A module replaced by a local directory is never fetched, so claiming an
// installed version for it would be inventing a fact.
func TestGoLocallyReplacedModuleIsNotAnInstance(t *testing.T) {
	inst := goResolve(t, source.File{Path: "go.mod", Data: []byte(`
module m

require example.com/lib v1.0.0

replace example.com/lib => ../lib
`)})
	if len(inst) != 0 {
		t.Errorf("got %d instances, want 0; a local replace resolves to no published package", len(inst))
	}
}

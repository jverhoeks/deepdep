package extract_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func goExtract(t *testing.T, body string) ([]graph.Edge, map[graph.NodeID]graph.Node) {
	t.Helper()
	f := source.File{Path: "go.mod", Data: []byte(body)}
	edges, nodes, err := extract.GoMod{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	by := map[graph.NodeID]graph.Node{}
	for _, n := range nodes {
		by[n.ID] = n
	}
	return edges, by
}

func hasEdgeTo(edges []graph.Edge, want string) *graph.Edge {
	for i := range edges {
		if string(edges[i].To) == want {
			return &edges[i]
		}
	}
	return nil
}

// go.mod writes requirements two ways — a parenthesised block and a single
// line — and a parser that handles only the block silently reports a module
// with no dependencies at all.
func TestGoModReadsBlockAndSingleLineRequires(t *testing.T) {
	edges, _ := goExtract(t, `
module example.com/app

go 1.24

require github.com/single/line v1.0.0

require (
	github.com/gorilla/mux v1.8.1
	golang.org/x/net v0.17.0
)
`)
	for _, want := range []string{
		"pkg:golang/github.com/single/line@v1.0.0",
		"pkg:golang/github.com/gorilla/mux@v1.8.1",
		"pkg:golang/golang.org/x/net@v0.17.0",
	} {
		if hasEdgeTo(edges, want) == nil {
			t.Errorf("missing requirement %s", want)
		}
	}
	if len(edges) != 3 {
		t.Errorf("got %d edges, want 3 — the module itself must not become its own dependency", len(edges))
	}
}

// A version in go.mod is exact and already selected, so the node is Resolved.
// That is what makes a Go repository auditable: advisories need a version.
func TestGoModRequirementsAreResolved(t *testing.T) {
	_, nodes := goExtract(t, "module m\n\nrequire github.com/gorilla/mux v1.8.1\n")
	n, ok := nodes["pkg:golang/github.com/gorilla/mux@v1.8.1"]
	if !ok {
		t.Fatal("no node for the requirement")
	}
	if n.Completeness != graph.Resolved {
		t.Errorf("completeness = %q, want Resolved — go.mod names an exact version", n.Completeness)
	}
	if n.Ecosystem != "golang" {
		t.Errorf("ecosystem = %q, want golang", n.Ecosystem)
	}
}

// `// indirect` requirements must NOT come out of the extractor.
//
// store.Surfaces calls a node first-party when a non-package node points at it,
// and every extracted edge hangs off the go.mod FILE node. So an indirect edge
// here would report a module nobody named as a dependency the maintainer can fix
// by editing one line — backwards, and at Go's scale it is hundreds of them.
//
// They are still counted: effective.GoMod reads the whole build list as
// placement, with no Spec, which is the same shape npm's lockfile uses.
func TestGoModExcludesIndirectRequirementsFromDeclarations(t *testing.T) {
	edges, _ := goExtract(t, `
module m

require (
	github.com/direct/dep v1.0.0
	github.com/indirect/dep v2.0.0 // indirect
)
`)
	if hasEdgeTo(edges, "pkg:golang/github.com/direct/dep@v1.0.0") == nil {
		t.Error("the direct requirement is missing")
	}
	if hasEdgeTo(edges, "pkg:golang/github.com/indirect/dep@v2.0.0") != nil {
		t.Error("an indirect requirement was reported as declared by this repository")
	}
	if len(edges) != 1 {
		t.Errorf("got %d edges, want 1 (the direct requirement only)", len(edges))
	}
}

// A replace to a LOCAL path is not a registry package. Resolving it would query
// proxy.golang.org for a module that was never published; dropping it would hide
// a real edge. It becomes a frontier node saying exactly what it is.
func TestGoModLocalReplaceIsAFrontierNotAPackage(t *testing.T) {
	edges, nodes := goExtract(t, `
module m

require example.com/lib v1.0.0

replace example.com/lib => ../lib
`)
	if hasEdgeTo(edges, "pkg:golang/example.com/lib@v1.0.0") != nil {
		t.Error("a locally replaced module must not be reported as the published package")
	}
	found := false
	for _, n := range nodes {
		if strings.Contains(string(n.ID), "lib") && n.Completeness != graph.Resolved {
			found = true
			if n.Reason == "" {
				t.Error("the replacement node carries no reason")
			}
		}
	}
	if !found {
		t.Error("a local replace produced no frontier node at all — the edge was silently dropped")
	}
}

// A replace to another MODULE is a real registry package, just a different one
// than was required. The version that ends up in the build is the target's.
func TestGoModModuleReplaceRetargets(t *testing.T) {
	edges, _ := goExtract(t, `
module m

require example.com/lib v1.0.0

replace example.com/lib => example.com/fork v1.5.0
`)
	if hasEdgeTo(edges, "pkg:golang/example.com/fork@v1.5.0") == nil {
		t.Error("replace to another module must resolve to the replacement")
	}
	if hasEdgeTo(edges, "pkg:golang/example.com/lib@v1.0.0") != nil {
		t.Error("the replaced module must not also be reported; the build never uses it")
	}
}

// exclude removes a version from consideration. It is not a dependency and must
// not become a node of its own.
func TestGoModExcludeIsNotADependency(t *testing.T) {
	edges, _ := goExtract(t, `
module m

require example.com/lib v1.2.0

exclude example.com/lib v1.1.0
`)
	if hasEdgeTo(edges, "pkg:golang/example.com/lib@v1.1.0") != nil {
		t.Error("an excluded version became a dependency")
	}
	if len(edges) != 1 {
		t.Errorf("got %d edges, want only the require", len(edges))
	}
}

func TestGoModMatch(t *testing.T) {
	m := extract.GoMod{}
	for _, p := range []string{"go.mod", "sub/go.mod"} {
		if !m.Match(p) {
			t.Errorf("Match(%q) = false", p)
		}
	}
	for _, p := range []string{"go.sum", "gomod", "vendor/example.com/x/go.mod"} {
		if m.Match(p) {
			t.Errorf("Match(%q) = true; vendored and non-manifest paths are not declarations", p)
		}
	}
}

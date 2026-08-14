package graph_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/graph"
)

func TestGraphDedupesNodesAndIdenticalEdges(t *testing.T) {
	g := graph.New()
	n := graph.Node{ID: "pkg:npm/lodash@4.17.21", Completeness: graph.Resolved}
	g.Add(n)
	g.Add(n)
	if len(g.Nodes()) != 1 {
		t.Fatalf("nodes = %d, want 1", len(g.Nodes()))
	}

	e := graph.Edge{From: "root", To: "pkg:npm/lodash@4.17.21", Kind: graph.DependsOn, Spec: "^4.0.0", Scope: graph.Prod}
	g.Link(e)
	g.Link(e)
	if len(g.Edges()) != 1 {
		t.Fatalf("identical edges = %d, want 1 (re-extraction must not inflate)", len(g.Edges()))
	}

	g.Link(graph.Edge{From: "root", To: "pkg:npm/lodash@4.17.21", Kind: graph.DependsOn, Spec: "^3.0.0", Scope: graph.Prod})
	if len(g.Edges()) != 2 {
		t.Fatalf("distinct specs must be distinct edges, got %d", len(g.Edges()))
	}
}

func TestCompletenessUpgradesMonotonically(t *testing.T) {
	g := graph.New()
	id := graph.NodeID("pkg:npm/a@1.0.0")

	g.Add(graph.Node{ID: id, Completeness: graph.Declared, Reason: "bound:depth"})
	g.Add(graph.Node{ID: id, Completeness: graph.Resolved})
	if got := g.Node(id).Completeness; got != graph.Resolved {
		t.Errorf("completeness = %q, want resolved (must upgrade)", got)
	}
	if got := g.Node(id).Reason; got != "" {
		t.Errorf("reason = %q, want empty — a stale bound reason must not survive an upgrade", got)
	}

	g.Add(graph.Node{ID: id, Completeness: graph.Declared, Reason: "bound:nodes"})
	if got := g.Node(id).Completeness; got != graph.Resolved {
		t.Errorf("completeness = %q, want resolved (must never downgrade)", got)
	}
}

func TestSamePackageInMultipleThreadsKeepsEveryPath(t *testing.T) {
	g := graph.New()
	for _, id := range []graph.NodeID{"root", "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/lodash@4.17.21"} {
		g.Add(graph.Node{ID: id})
	}
	g.Link(graph.Edge{From: "root", To: "pkg:npm/a@1.0.0", Kind: graph.DependsOn})
	g.Link(graph.Edge{From: "root", To: "pkg:npm/b@1.0.0", Kind: graph.DependsOn})
	g.Link(graph.Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/lodash@4.17.21", Kind: graph.DependsOn})
	g.Link(graph.Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/lodash@4.17.21", Kind: graph.DependsOn})

	if got := len(g.InboundTo("pkg:npm/lodash@4.17.21")); got != 2 {
		t.Fatalf("inbound edges = %d, want 2 (one per thread)", got)
	}
	if got := len(g.PathsTo("pkg:npm/lodash@4.17.21", 10)); got != 2 {
		t.Fatalf("PathsTo returned %d chains, want 2 — provenance lost", got)
	}
}

func TestPathsToRespectsBoundAndCycles(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: "root"})
	g.Add(graph.Node{ID: "pkg:npm/x@1.0.0"})
	for i := 0; i < 50; i++ {
		mid := graph.NodeID(fmt.Sprintf("pkg:npm/m%d@1.0.0", i))
		g.Add(graph.Node{ID: mid})
		g.Link(graph.Edge{From: "root", To: mid, Kind: graph.DependsOn})
		g.Link(graph.Edge{From: mid, To: "pkg:npm/x@1.0.0", Kind: graph.DependsOn})
	}
	if got := len(g.PathsTo("pkg:npm/x@1.0.0", 5)); got != 5 {
		t.Errorf("PathsTo(maxPaths=5) = %d, want 5", got)
	}

	g.Link(graph.Edge{From: "pkg:npm/x@1.0.0", To: "pkg:npm/m0@1.0.0", Kind: graph.DependsOn})
	done := make(chan struct{})
	go func() { g.PathsTo("pkg:npm/x@1.0.0", 5); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("PathsTo hung on a cycle")
	}
}

func TestNodesAreSortedForDeterministicEmission(t *testing.T) {
	g := graph.New()
	for _, id := range []graph.NodeID{"pkg:npm/z@1.0.0", "pkg:npm/a@1.0.0", "pkg:npm/m@1.0.0"} {
		g.Add(graph.Node{ID: id})
	}
	got := g.Nodes()
	for i := 1; i < len(got); i++ {
		if string(got[i-1].ID) > string(got[i].ID) {
			t.Fatalf("Nodes() not sorted: %v", got)
		}
	}
}

func TestScopedNPMIdentityIsCanonicalPURL(t *testing.T) {
	id, err := graph.NPMNodeID("@types/node", "20.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(id), "%40types") {
		t.Errorf("scoped id = %q, want percent-encoded scope — string concat corrupts joins", id)
	}
}

func TestVersionlessNPMIdentityHasNoAtSign(t *testing.T) {
	id, err := graph.NPMNodeID("lodash", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(id) != "pkg:npm/lodash" {
		t.Errorf("version-less id = %q, want pkg:npm/lodash", id)
	}
}

func TestHeterogeneousIdentities(t *testing.T) {
	for _, s := range []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:github/actions/checkout@v4",
		"pkg:oci/alpine@3.19",
		"pkg:golang/github.com/go-git/go-git/v6@6.0.0",
	} {
		if _, err := graph.NewNodeID(s); err != nil {
			t.Errorf("NewNodeID(%q): %v", s, err)
		}
	}
}

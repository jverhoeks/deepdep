package store_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
)

// A base image and a CI action are the most direct dependencies a repository
// has — one line each, nobody upstream to wait for — and both hang off a build
// FILE node rather than off the root. A root-only notion of "direct" therefore
// files them under "inherited", which is the opposite of the truth and would
// tell a maintainer the fix is not theirs.
func TestSurfacesReachThroughBuildFiles(t *testing.T) {
	dockerfile := extract.BuildFileNode("dockerfile", "Dockerfile")
	workflow := extract.BuildFileNode("workflow", ".github/workflows/ci.yml")

	g := graph.New()
	g.Add(graph.Node{ID: "root", Completeness: graph.Resolved})
	g.Add(dockerfile)
	g.Add(workflow)
	for _, n := range []graph.Node{
		{ID: "pkg:npm/direct-dep@1.0.0", Ecosystem: "npm", Name: "direct-dep", Version: "1.0.0"},
		{ID: "pkg:npm/transitive@1.0.0", Ecosystem: "npm", Name: "transitive", Version: "1.0.0"},
		{ID: "pkg:deb/debian/curl@7.88.1", Ecosystem: "deb", Name: "debian/curl", Version: "7.88.1"},
		{ID: "pkg:github/actions/checkout@v4", Ecosystem: "github", Name: "actions/checkout", Version: "v4"},
	} {
		n.Completeness = graph.Resolved
		g.Add(n)
	}

	g.Link(graph.Edge{From: "root", To: dockerfile.ID, Kind: graph.Invokes})
	g.Link(graph.Edge{From: "root", To: workflow.ID, Kind: graph.Invokes})
	g.Link(graph.Edge{From: "root", To: "pkg:npm/direct-dep@1.0.0", Kind: graph.DependsOn, Spec: "^1.0.0"})
	g.Link(graph.Edge{From: "pkg:npm/direct-dep@1.0.0", To: "pkg:npm/transitive@1.0.0", Kind: graph.DependsOn})
	g.Link(graph.Edge{From: dockerfile.ID, To: "pkg:deb/debian/curl@7.88.1", Kind: graph.Installs})
	g.Link(graph.Edge{From: workflow.ID, To: "pkg:github/actions/checkout@v4", Kind: graph.Invokes})

	s := open(t)
	runID, err := s.WriteRun(context.Background(), sampleMeta(), g, nil, rollup.Compute(g, nil, "root"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Surfaces(context.Background(), runID)
	if err != nil {
		t.Fatal(err)
	}

	for id, want := range map[graph.NodeID][]string{
		"pkg:npm/direct-dep@1.0.0":       {store.SurfaceManifest},
		"pkg:deb/debian/curl@7.88.1":     {store.SurfaceDockerfile},
		"pkg:github/actions/checkout@v4": {store.SurfaceCI},
	} {
		if !reflect.DeepEqual(got[id], want) {
			t.Errorf("surfaces of %s = %v, want %v", id, got[id], want)
		}
	}
	if s, ok := got["pkg:npm/transitive@1.0.0"]; ok {
		t.Errorf("a package only an upstream package asked for is inherited, got surfaces %v", s)
	}
}

// One package, two lines to edit. Collapsing it to a single surface hides the
// drift between a pin in a manifest and an install in a Dockerfile.
func TestSurfacesRecordsEveryFileThatNamesAPackage(t *testing.T) {
	dockerfile := extract.BuildFileNode("dockerfile", "Dockerfile")

	g := graph.New()
	g.Add(graph.Node{ID: "root", Completeness: graph.Resolved})
	g.Add(dockerfile)
	g.Add(graph.Node{ID: "pkg:pypi/requests@2.31.0", Ecosystem: "pypi", Name: "requests",
		Version: "2.31.0", Completeness: graph.Resolved})
	g.Link(graph.Edge{From: "root", To: dockerfile.ID, Kind: graph.Invokes})
	g.Link(graph.Edge{From: "root", To: "pkg:pypi/requests@2.31.0", Kind: graph.DependsOn, Spec: "==2.31.0"})
	g.Link(graph.Edge{From: dockerfile.ID, To: "pkg:pypi/requests@2.31.0", Kind: graph.Installs})

	s := open(t)
	runID, err := s.WriteRun(context.Background(), sampleMeta(), g, nil, rollup.Compute(g, nil, "root"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Surfaces(context.Background(), runID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{store.SurfaceDockerfile, store.SurfaceManifest}
	if !reflect.DeepEqual(got["pkg:pypi/requests@2.31.0"], want) {
		t.Errorf("surfaces = %v, want %v", got["pkg:pypi/requests@2.31.0"], want)
	}
}

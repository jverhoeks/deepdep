package emit_test

import (
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
)

// splitFixture is a two-app monorepo with one Dockerfile and a shared pipeline.
func splitFixture() (*graph.Graph, []effective.Instance, graph.NodeID) {
	g := graph.New()
	root := graph.NodeID("pkg:generic/repo@deadbeef")
	dockerfile := graph.NodeID("pkg:generic/buildfile/dockerfile@aaa111#backend/Dockerfile")

	for _, n := range []graph.Node{
		{ID: root, Name: "repo", Completeness: graph.Resolved},
		{ID: "pkg:pypi/flask@3.0.0", Name: "flask", Version: "3.0.0", Completeness: graph.Resolved},
		{ID: "pkg:npm/react@19.0.0", Name: "react", Version: "19.0.0", Completeness: graph.Resolved},
		{ID: dockerfile, Name: "Dockerfile", Note: "backend/Dockerfile", Completeness: graph.Resolved},
		{ID: "pkg:oci/python@3.12-slim", Name: "python", Version: "3.12-slim", Completeness: graph.Declared},
		{ID: "pkg:generic/opaque@bbb222", Completeness: graph.Opaque, Note: "pip install ."},
		// pipeline-level: no instance, no Dockerfile
		{ID: "pkg:gitlab/org/tmpl@v1", Name: "tmpl", Version: "v1", Completeness: graph.Resolved},
	} {
		g.Add(n)
	}
	g.Link(graph.Edge{From: root, To: "pkg:pypi/flask@3.0.0", Kind: graph.DependsOn})
	g.Link(graph.Edge{From: root, To: "pkg:npm/react@19.0.0", Kind: graph.DependsOn})
	g.Link(graph.Edge{From: root, To: dockerfile, Kind: graph.Invokes})
	g.Link(graph.Edge{From: dockerfile, To: "pkg:oci/python@3.12-slim", Kind: graph.BuildsOn})
	g.Link(graph.Edge{From: dockerfile, To: "pkg:generic/opaque@bbb222", Kind: graph.Installs})
	g.Link(graph.Edge{From: root, To: "pkg:gitlab/org/tmpl@v1", Kind: graph.Invokes})

	inst := []effective.Instance{
		{Locator: "backend#flask", NodeID: "pkg:pypi/flask@3.0.0", DerivedFrom: "lockfile"},
		{Locator: "frontend#react", NodeID: "pkg:npm/react@19.0.0", DerivedFrom: "lockfile"},
	}
	return g, inst, root
}

func unitsByName(us []emit.Unit) map[string]emit.Unit {
	m := map[string]emit.Unit{}
	for _, u := range us {
		m[u.Name] = u
	}
	return m
}

// TestSplitAssignsByLockfileThenDockerfileThenRepo pins the three rules.
func TestSplitAssignsByLockfileThenDockerfileThenRepo(t *testing.T) {
	by := unitsByName(emit.Split(splitFixture()))

	for name, kind := range map[string]string{
		"backend": "application", "frontend": "application",
		"backend/Dockerfile": "image", "_repo": "repository",
	} {
		u, ok := by[name]
		if !ok {
			t.Fatalf("missing unit %q; got %v", name, keysOf(by))
		}
		if u.Kind != kind {
			t.Errorf("%s kind = %q, want %q", name, u.Kind, kind)
		}
	}
	if !by["backend"].Graph.Has("pkg:pypi/flask@3.0.0") {
		t.Error("backend must contain its own lockfile package")
	}
	if by["backend"].Graph.Has("pkg:npm/react@19.0.0") {
		t.Error("backend must NOT contain the frontend's package")
	}
	if !by["backend/Dockerfile"].Graph.Has("pkg:oci/python@3.12-slim") {
		t.Error("the image unit must contain its base image")
	}
}

// TestRepoLevelNodesGetTheirOwnDocument. A pipeline template has no instance
// locator and belongs to no application. Copying it into every per-app document
// inflates each one and double-counts the union; dropping it makes every
// document look cleaner than the repository is.
func TestRepoLevelNodesGetTheirOwnDocument(t *testing.T) {
	by := unitsByName(emit.Split(splitFixture()))
	const tmpl = graph.NodeID("pkg:gitlab/org/tmpl@v1")

	if !by["_repo"].Graph.Has(tmpl) {
		t.Error("the pipeline template is missing from the repository unit")
	}
	for name, u := range by {
		if name == "_repo" {
			continue
		}
		if u.Graph.Has(tmpl) {
			t.Errorf("%s duplicates a repo-level node", name)
		}
	}
}

// TestImageUnitCarriesItsBuildSteps: the per-image document must contain the
// build requirements, which is the whole point of splitting per Dockerfile.
//
// The unit's GRAPH deliberately holds the build steps — formulation walks the
// file -> step edges — while the emitted components[] must not, because a shell
// command is not a library. Asserting only the graph, as an earlier version of
// this test did, passed while every per-image document shipped with zero steps.
func TestImageUnitCarriesItsBuildSteps(t *testing.T) {
	var img emit.Unit
	for _, u := range emit.Split(splitFixture()) {
		if u.Name == "backend/Dockerfile" {
			img = u
		}
	}
	if img.Graph == nil {
		t.Fatal("no image unit")
	}

	m := emit.Meta{Ref: unitRefOf(img.Root), Repo: img.Name, ToolVersion: "test"}
	b := encode(t, img.Graph, m, emit.CycloneDXOptions{Formulation: true})

	for _, c := range b.Components {
		if c.BOMRef == "pkg:generic/opaque@bbb222" {
			t.Error("a build step must not appear in components[]")
		}
	}
	var steps int
	for _, f := range b.Formulation {
		for _, w := range f.Workflows {
			steps += len(w.Steps)
		}
	}
	if steps == 0 {
		t.Error("the per-image document has no build steps — the build requirements are missing")
	}
}

// TestEachUnitHasItsOwnSubject: a per-app document that names the whole
// repository as its metadata.component defeats the point of splitting.
func TestEachUnitHasItsOwnSubject(t *testing.T) {
	for _, u := range emit.Split(splitFixture()) {
		if !u.Graph.Has(u.Root) {
			t.Errorf("%s: synthetic root %q missing from its own graph", u.Name, u.Root)
		}
		if _, err := graph.NewNodeID(string(u.Root)); err != nil {
			t.Errorf("%s: root %q is not a valid PURL: %v", u.Name, u.Root, err)
		}
	}
}

func keysOf(m map[string]emit.Unit) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// unitRefOf mirrors what the CLI does: the emitter picks metadata.component by
// matching Meta.Ref against a node id's version half.
func unitRefOf(id graph.NodeID) string {
	s := string(id)
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return s[i+1:]
	}
	return ""
}

// TestNoStepIsLostBySplitting: every build step in the closure must land in
// exactly one document. Excluding steps from the repository unit dropped all 26
// pipeline commands while the per-image ones survived — a partition that loses
// a third of the build evidence and reports nothing.
func TestNoStepIsLostBySplitting(t *testing.T) {
	g, inst, root := splitFixture()

	var want int
	for _, n := range g.Nodes() {
		if n.Completeness == graph.Opaque {
			want++
		}
	}
	got := map[graph.NodeID]bool{}
	for _, u := range emit.Split(g, inst, root) {
		for _, n := range u.Graph.Nodes() {
			if n.Completeness == graph.Opaque {
				got[n.ID] = true
			}
		}
	}
	if len(got) != want {
		t.Errorf("build steps after splitting = %d, want %d — the partition lost some", len(got), want)
	}
}

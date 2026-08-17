package extract_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func ghExtract(t *testing.T, body string) ([]graph.Edge, map[graph.NodeID]graph.Node) {
	t.Helper()
	f := source.File{Path: ".github/workflows/ci.yml", Data: []byte(body)}
	edges, nodes, err := extract.GHActions{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	by := map[graph.NodeID]graph.Node{}
	for _, n := range nodes {
		by[n.ID] = n
	}
	return edges, by
}

func TestGHActionsExtractsActionsImagesAndWorkflows(t *testing.T) {
	edges, _ := ghExtract(t, `
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:20-alpine
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:3.19
      - run: make install
  call:
    uses: myorg/shared/.github/workflows/release.yml@v1
`)
	// One root edge, to the workflow file; everything the workflow pulls in
	// hangs off that node so several workflows cannot steal each other's
	// findings through a shared, deduplicated action or image.
	kind := map[graph.NodeID]graph.EdgeKind{}
	var file graph.NodeID
	for _, e := range edges {
		if e.From == "" {
			file = e.To
			continue
		}
		if e.From != file {
			t.Errorf("edge From = %q, want the workflow file node %q", e.From, file)
		}
		kind[e.To] = e.Kind
	}
	if file == "" {
		t.Fatal("no root edge to the workflow file node")
	}

	for id, want := range map[graph.NodeID]graph.EdgeKind{
		"pkg:github/actions/checkout@v4": graph.Invokes,
		"pkg:oci/node@20-alpine":         graph.BuildsOn,
		"pkg:oci/alpine@3.19":            graph.BuildsOn,
	} {
		if kind[id] != want {
			t.Errorf("edge to %s = %q, want %q (have %v)", id, kind[id], want, keys(kind))
		}
	}

	// A reusable workflow keeps its path as a PURL subpath: two workflows in the
	// same repo must not collapse into one node.
	var sawWorkflow bool
	for id := range kind {
		if strings.HasPrefix(string(id), "pkg:github/myorg/shared@v1#") {
			sawWorkflow = true
		}
	}
	if !sawWorkflow {
		t.Errorf("reusable workflow lost its subpath; got %v", keys(kind))
	}
}

// A moving tag is the tj-actions attack surface and the headline risk this tool
// exists to surface. Calling it "resolved" would both misclassify the risk and
// poison the time-travel archive, since tag->SHA history cannot be recovered later.
func TestMutableRefsDeclaredAndShaRefsResolved(t *testing.T) {
	_, nodes := ghExtract(t, `
jobs:
  b:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@8c91899e586c5b171469028077307d293428b516
      - uses: actions/cache@main
`)
	for _, c := range []struct {
		id     graph.NodeID
		comp   graph.Completeness
		reason string
	}{
		{"pkg:github/actions/checkout@v4", graph.Declared, graph.ReasonUnpinnedRef},
		{"pkg:github/actions/cache@main", graph.Declared, graph.ReasonUnpinnedRef},
		{"pkg:github/actions/setup-node@8c91899e586c5b171469028077307d293428b516", graph.Resolved, ""},
	} {
		n, ok := nodes[c.id]
		if !ok {
			t.Errorf("missing node %s (have %v)", c.id, keysN(nodes))
			continue
		}
		if n.Completeness != c.comp {
			t.Errorf("%s completeness = %q, want %q", c.id, n.Completeness, c.comp)
		}
		if n.Reason != c.reason {
			t.Errorf("%s reason = %q, want %q", c.id, n.Reason, c.reason)
		}
	}
}

func TestRunStepsBecomeOpaqueFrontier(t *testing.T) {
	edges, nodes := ghExtract(t, `
jobs:
  b:
    steps:
      - run: curl -sSf https://example.com/install.sh | sh
`)
	var opaque int
	for _, n := range nodes {
		if n.Completeness == graph.Opaque {
			opaque++
			if !strings.Contains(n.Note, "curl") {
				t.Errorf("opaque node must record the command it could not analyse, got %q", n.Note)
			}
		}
	}
	if opaque != 1 {
		t.Fatalf("opaque nodes = %d, want 1 — an undecidable step must be reported, not dropped", opaque)
	}
	var installs int
	for _, e := range edges {
		if e.Kind == graph.Installs {
			installs++
		}
	}
	if installs != 1 {
		t.Errorf("installs edges = %d, want 1", installs)
	}
}

func TestIdenticalRunStepsShareOneNode(t *testing.T) {
	_, nodes := ghExtract(t, `
jobs:
  a:
    steps:
      - run: make all
  b:
    steps:
      - run: make all
`)
	var opaque int
	for _, n := range nodes {
		if n.Completeness == graph.Opaque {
			opaque++
		}
	}
	if opaque != 1 {
		t.Errorf("opaque nodes = %d, want 1 — the same command is the same frontier", opaque)
	}
}

func TestGHActionsMatch(t *testing.T) {
	e := extract.GHActions{}
	for _, p := range []string{".github/workflows/ci.yml", ".github/workflows/release.yaml"} {
		if !e.Match(p) {
			t.Errorf("should match %q", p)
		}
	}
	for _, p := range []string{"package.json", "docs/ci.yml", ".github/dependabot.yml"} {
		if e.Match(p) {
			t.Errorf("must not match %q", p)
		}
	}
}

func TestMalformedWorkflowSurfacesError(t *testing.T) {
	f := source.File{Path: ".github/workflows/ci.yml", Data: []byte("jobs:\n  - [unbalanced")}
	if _, _, err := (extract.GHActions{}).Extract(context.Background(), f); err == nil {
		t.Error("malformed YAML must surface an error rather than silently yielding nothing")
	}
}

func keys(m map[graph.NodeID]graph.EdgeKind) []graph.NodeID {
	var out []graph.NodeID
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysN(m map[graph.NodeID]graph.Node) []graph.NodeID {
	var out []graph.NodeID
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSharedActionIsAttributedToEveryWorkflow is the attribution bug, in the
// place it is most likely to matter: nearly every workflow in a repo uses
// actions/checkout, and a deduplicated node's Source names only the first file
// that reached it. Anchoring findings to the repository root made every
// workflow after the first report having pulled in nothing.
func TestSharedActionIsAttributedToEveryWorkflow(t *testing.T) {
	const body = `
jobs:
  b:
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:3.19
`
	files := map[graph.NodeID][]graph.NodeID{}
	for _, p := range []string{".github/workflows/ci.yml", ".github/workflows/release.yml"} {
		edges, _, err := extract.GHActions{}.Extract(context.Background(),
			source.File{Path: p, Data: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		var self graph.NodeID
		for _, e := range edges {
			if e.From == "" {
				self = e.To
			}
		}
		for _, e := range edges {
			if e.From == self {
				files[self] = append(files[self], e.To)
			}
		}
	}
	if len(files) != 2 {
		t.Fatalf("workflow file nodes = %d, want 2 distinct", len(files))
	}
	for f, targets := range files {
		want := map[graph.NodeID]bool{
			"pkg:github/actions/checkout@v4": false,
			"pkg:oci/alpine@3.19":            false,
		}
		for _, to := range targets {
			if _, ok := want[to]; ok {
				want[to] = true
			}
		}
		for id, seen := range want {
			if !seen {
				t.Errorf("%s has no edge to %s — attribution lost to deduplication", f, id)
			}
		}
	}
}

// `uses: ./` is a LOCAL action — the repository's own action.yml, not a
// dependency on anyone. It was being split as org/repo, which yields org "."
// and an empty repo, and the resulting nameless purl failed to parse and took
// the whole repository's scan down with it ("purl is missing name").
//
// Whatever the local action itself depends on is extracted from action.yml
// directly, so skipping the reference loses nothing.
func TestLocalActionReferencesAreSkipped(t *testing.T) {
	for _, uses := range []string{"./", "./.github/actions/setup", "../sibling"} {
		edges, nodes := ghExtract(t, `
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: `+uses+`
`)
		for id := range nodes {
			if strings.Contains(string(id), "pkg:github/.") || strings.Contains(string(id), "pkg:github/..") {
				t.Errorf("uses: %q produced a node for a local path: %s", uses, id)
			}
		}
		// The real action alongside it must still come through: skipping the
		// local reference must not skip the step list.
		found := false
		for _, e := range edges {
			if strings.Contains(string(e.To), "actions/checkout") {
				found = true
			}
		}
		if !found {
			t.Errorf("uses: %q — the neighbouring actions/checkout was lost", uses)
		}
	}
}

// A local reference in a job-level `uses:` is the same mistake in the other
// position, and reusable-workflow calls are where `uses:` sits at job level.
func TestLocalReusableWorkflowReferenceIsSkipped(t *testing.T) {
	_, nodes, err := (extract.GHActions{}).Extract(context.Background(), source.File{
		Path: ".github/workflows/ci.yml",
		Data: []byte("jobs:\n  call:\n    uses: ./.github/workflows/build.yml\n"),
	})
	if err != nil {
		t.Fatalf("a local reusable-workflow call must not fail the scan: %v", err)
	}
	for _, n := range nodes {
		if n.Ecosystem == "github" {
			t.Errorf("local reusable workflow became a dependency node: %s", n.ID)
		}
	}
}

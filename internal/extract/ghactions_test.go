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
	kind := map[graph.NodeID]graph.EdgeKind{}
	for _, e := range edges {
		if e.From != "" {
			t.Errorf("edge From = %q, want empty — a workflow file has no self-identity", e.From)
		}
		kind[e.To] = e.Kind
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

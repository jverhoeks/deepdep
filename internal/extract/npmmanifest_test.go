package extract_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func TestNPMManifestEmitsRangesWithScopes(t *testing.T) {
	f := source.File{Path: "package.json", Data: []byte(`{
      "name":"app","version":"1.0.0",
      "dependencies":{"lodash":"^4.17.0"},
      "devDependencies":{"jest":"~29.5.0"},
      "peerDependencies":{"react":">=18"},
      "optionalDependencies":{"fsevents":"^2.3.0"}
    }`)}

	edges, _, err := extract.NPMManifest{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 4 {
		t.Fatalf("edges = %d, want 4", len(edges))
	}

	got := map[graph.NodeID]graph.Edge{}
	for _, e := range edges {
		if e.From != "" {
			t.Errorf("root edge From = %q, want empty — only the walker knows the root's identity", e.From)
		}
		if e.Kind != graph.DependsOn {
			t.Errorf("edge to %s kind = %q, want depends_on", e.To, e.Kind)
		}
		got[e.To] = e
	}

	for _, c := range []struct {
		id    graph.NodeID
		spec  string
		scope graph.Scope
	}{
		{"pkg:npm/lodash", "^4.17.0", graph.Prod},
		{"pkg:npm/jest", "~29.5.0", graph.Dev},
		{"pkg:npm/react", ">=18", graph.Peer},
		{"pkg:npm/fsevents", "^2.3.0", graph.Optional},
	} {
		e, ok := got[c.id]
		if !ok {
			t.Errorf("missing edge to %s", c.id)
			continue
		}
		if e.Spec != c.spec {
			t.Errorf("%s spec = %q, want %q — the RANGE must survive, not a resolved pin", c.id, e.Spec, c.spec)
		}
		if e.Scope != c.scope {
			t.Errorf("%s scope = %q, want %q", c.id, e.Scope, c.scope)
		}
	}
}

func TestNPMManifestScopedPackageIsCanonical(t *testing.T) {
	f := source.File{Path: "package.json", Data: []byte(`{"dependencies":{"@types/node":"^20.0.0"}}`)}
	edges, _, err := extract.NPMManifest{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].To != "pkg:npm/%40types/node" {
		t.Errorf("got %+v, want a percent-encoded scoped PURL", edges)
	}
}

func TestNPMManifestMatch(t *testing.T) {
	e := extract.NPMManifest{}
	for _, p := range []string{"package.json", "web/package.json"} {
		if !e.Match(p) {
			t.Errorf("should match %q", p)
		}
	}
	for _, p := range []string{"node_modules/x/package.json", "package-lock.json", "readme.md"} {
		if e.Match(p) {
			t.Errorf("must not match %q", p)
		}
	}
}

func TestNPMManifestIgnoresMalformedJSON(t *testing.T) {
	f := source.File{Path: "package.json", Data: []byte(`{not json`)}
	if _, _, err := (extract.NPMManifest{}).Extract(context.Background(), f); err == nil {
		t.Error("a malformed manifest must surface an error, not be silently skipped")
	}
}

func TestRegistryDispatchesByPath(t *testing.T) {
	r := extract.NewRegistry()
	r.Register(extract.NPMManifest{})

	if got := r.For("package.json"); len(got) != 1 {
		t.Errorf("For(package.json) = %d extractors, want 1", len(got))
	}
	if got := r.For("some/other.txt"); len(got) != 0 {
		t.Errorf("For(other.txt) = %d extractors, want 0", len(got))
	}
}

// TestProtocolSpecsAreNotVersionRanges.
//
// pnpm's workspace:, catalog:, link: and file: protocols name a resolution
// MECHANISM, not a version range. n8n declares 396 of them, and recording those
// strings in a spec field made a sibling package in the same repo look like an
// unbounded dependency on a public one — wrong in the more alarming direction,
// and unparseable by any semver scheme.
func TestProtocolSpecsAreNotVersionRanges(t *testing.T) {
	f := source.File{Path: "package.json", Data: []byte(`{
      "name":"app",
      "dependencies":{
        "@n8n/config":"workspace:*",
        "vue":"catalog:frontend",
        "local-rules":"link:./scripts/eslint-rules",
        "lodash":"^4.17.0"
      }}`)}
	edges, _, err := extract.NPMManifest{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	got := map[graph.NodeID]string{}
	for _, e := range edges {
		got[e.To] = e.Spec
	}
	for _, id := range []graph.NodeID{"pkg:npm/%40n8n/config", "pkg:npm/vue", "pkg:npm/local-rules"} {
		spec, ok := got[id]
		if !ok {
			t.Errorf("%s missing entirely; the dependency is still real", id)
			continue
		}
		if spec != "" {
			t.Errorf("%s spec = %q, want empty — a protocol is not a range", id, spec)
		}
	}
	if got["pkg:npm/lodash"] != "^4.17.0" {
		t.Errorf("a real range was lost: %q", got["pkg:npm/lodash"])
	}
}

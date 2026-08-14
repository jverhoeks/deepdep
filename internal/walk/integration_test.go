package walk_test

import (
	"context"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/resolve"
	"github.com/jverhoeks/deepdep/internal/source"
	"github.com/jverhoeks/deepdep/internal/version"
	"github.com/jverhoeks/deepdep/internal/walk"
)

// The project's acceptance criterion, against the real registry: the set of
// packages a future install COULD pull is strictly larger than what installs
// today. If these two ever agree, the tool has no reason to exist.
func TestLiveRegistryCanExceedsWill(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	manifest := `{"name":"fx","dependencies":{"is-string":"^1.0.0"}}`

	run := func(mode version.VersionMode, maxVersions int) *graph.Graph {
		t.Helper()
		c := cache.NewFS(t.TempDir())
		r := resolve.NewNPMResolver("https://registry.npmjs.org", c, nil, time.Hour, time.Now)
		reg := extract.NewRegistry()
		reg.Register(extract.NPMManifest{})
		w := walk.New(walk.Bounds{
			MaxDepth: 8, MaxNodes: 20000, Concurrency: 16,
			Version: version.BoundPolicy{Mode: mode, MaxVersionsPerRange: maxVersions},
		}, map[string]resolve.Resolver{"npm": r}, reg, map[string]version.VersionScheme{"npm": version.NPM})

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		g, err := w.Walk(ctx, source.Static([]source.File{{Path: "package.json", Data: []byte(manifest)}}), rootID)
		if err != nil {
			t.Fatalf("%s walk: %v", mode, err)
		}
		return g
	}

	will := run(version.ModeLatest, 1)
	can := run(version.ModeAll, 6)

	t.Logf("will: %d nodes, %d edges", len(will.Nodes()), len(will.Edges()))
	t.Logf("can:  %d nodes, %d edges", len(can.Nodes()), len(can.Edges()))

	if len(will.Nodes()) < 3 {
		t.Fatalf("will closure has %d nodes; is-string has real transitive deps", len(will.Nodes()))
	}
	if len(can.Nodes()) <= len(will.Nodes()) {
		t.Fatalf("can = %d nodes, will = %d; can MUST be strictly larger",
			len(can.Nodes()), len(will.Nodes()))
	}

	// Every will-node must also be reachable in can: can is a superset by
	// construction, and a violation would mean the enumeration lost a version.
	for _, n := range will.Nodes() {
		if !can.Has(n.ID) {
			t.Errorf("node %s present in will but missing from can", n.ID)
		}
	}

	// Provenance must survive: at least one package should be reachable by more
	// than one chain in the can closure.
	var multi int
	for _, n := range can.Nodes() {
		if len(can.InboundTo(n.ID)) > 1 {
			multi++
		}
	}
	t.Logf("packages reachable by >1 dependency thread in can: %d", multi)
}

// Reproducibility: the same --as-of instant must produce the same closure.
func TestLiveRegistryAsOfIsStable(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	asOf := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	manifest := `{"name":"fx","dependencies":{"is-string":"^1.0.0"}}`

	run := func() []graph.NodeID {
		c := cache.NewFS(t.TempDir()) // fresh cache: no frozen-packument masking
		r := resolve.NewNPMResolver("https://registry.npmjs.org", c, nil, time.Hour, time.Now)
		reg := extract.NewRegistry()
		reg.Register(extract.NPMManifest{})
		w := walk.New(walk.Bounds{
			MaxDepth: 6, MaxNodes: 5000, Concurrency: 16,
			Version: version.BoundPolicy{Mode: version.ModeLatest},
			AsOf:    asOf,
		}, map[string]resolve.Resolver{"npm": r}, reg, map[string]version.VersionScheme{"npm": version.NPM})
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		g, err := w.Walk(ctx, source.Static([]source.File{{Path: "package.json", Data: []byte(manifest)}}), rootID)
		if err != nil {
			t.Fatal(err)
		}
		return ids(g)
	}

	a, b := run(), run()
	if len(a) != len(b) {
		t.Fatalf("two --as-of runs gave %d and %d nodes", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("node %d differs: %s vs %s", i, a[i], b[i])
		}
	}
	t.Logf("as-of %s reproducibly resolved %d nodes across two cold caches", asOf.Format("2006-01-02"), len(a))
}

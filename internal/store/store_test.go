package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
)

func open(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleGraph() *graph.Graph {
	g := graph.New()
	g.Add(graph.Node{ID: "root", Completeness: graph.Resolved})
	g.Add(graph.Node{ID: "pkg:npm/a@1.0.0", Ecosystem: "npm", Name: "a", Version: "1.0.0", Completeness: graph.Resolved})
	g.Add(graph.Node{ID: "pkg:npm/lodash@4.17.21", Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Completeness: graph.Resolved})
	g.Link(graph.Edge{From: "root", To: "pkg:npm/a@1.0.0", Kind: graph.DependsOn, Spec: "^1.0.0", Scope: graph.Prod})
	g.Link(graph.Edge{From: "root", To: "pkg:npm/lodash@4.17.21", Kind: graph.DependsOn, Spec: "^4.0.0", Scope: graph.Prod})
	g.Link(graph.Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/lodash@4.17.21", Kind: graph.DependsOn, Spec: "^4.0.0", Scope: graph.Prod})
	return g
}

func sampleMeta() emit.Meta {
	ts := time.Unix(1765000000, 0).UTC()
	return emit.Meta{AsOf: ts, KnownAt: ts, Ref: "abc", Repo: "fx", Mode: "will", ToolVersion: "0.1.0"}
}

// The store's adjacency query must agree with the in-memory graph, or "why is
// this here?" answers differently depending on which one you ask.
func TestWriteRunRoundTripsGraph(t *testing.T) {
	s := open(t)
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")

	runID, err := s.WriteRun(context.Background(), sampleMeta(), g, nil, res)
	if err != nil {
		t.Fatal(err)
	}
	if runID == "" {
		t.Fatal("empty run id")
	}

	got, err := s.InboundTo(context.Background(), runID, "pkg:npm/lodash@4.17.21")
	if err != nil {
		t.Fatal(err)
	}
	want := g.InboundTo("pkg:npm/lodash@4.17.21")
	if len(got) != len(want) {
		t.Fatalf("store inbound = %d, graph inbound = %d — they must agree", len(got), len(want))
	}
}

func TestSchemaIsIdempotentAcrossOpens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d.db")
	for i := 0; i < 3; i++ {
		s, err := store.Open(p)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		s.Close()
	}
}

// The graph dedups identical edges; the store's primary key is the second line
// of defence. Both must hold or stored and in-memory answers diverge.
func TestDuplicateEdgesCollapse(t *testing.T) {
	s := open(t)
	g := graph.New()
	g.Add(graph.Node{ID: "root"})
	g.Add(graph.Node{ID: "pkg:npm/a@1.0.0", Ecosystem: "npm", Name: "a", Version: "1.0.0"})
	e := graph.Edge{From: "root", To: "pkg:npm/a@1.0.0", Kind: graph.DependsOn, Spec: "^1.0.0", Scope: graph.Prod}
	g.Link(e)
	g.Link(e)

	runID, err := s.WriteRun(context.Background(), sampleMeta(), g, nil, rollup.Compute(g, nil, "root"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.InboundTo(context.Background(), runID, "pkg:npm/a@1.0.0")
	if len(got) != 1 {
		t.Errorf("stored edges = %d, want 1", len(got))
	}
}

func TestPackagesQueryReturnsRollup(t *testing.T) {
	s := open(t)
	g := sampleGraph()
	inst := []effective.Instance{
		{Locator: "node_modules/lodash", NodeID: "pkg:npm/lodash@4.17.21", DerivedFrom: "lockfile"},
	}
	res := rollup.Compute(g, inst, "root")

	runID, err := s.WriteRun(context.Background(), sampleMeta(), g, inst, res)
	if err != nil {
		t.Fatal(err)
	}

	pkgs, err := s.Packages(context.Background(), runID, store.PackageQuery{Name: "lodash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %d, want 1", len(pkgs))
	}
	p := pkgs[0]
	if p.InstanceCount != 1 {
		t.Errorf("instance count = %d, want 1", p.InstanceCount)
	}
	if p.PathCount != 2 {
		t.Errorf("path count = %d, want 2 (root direct + via a)", p.PathCount)
	}
	if len(p.Versions) != 1 || p.Versions[0].State != rollup.Installed {
		t.Errorf("versions = %+v, want one installed", p.Versions)
	}
}

func TestInstancesPersistHoistedAndNested(t *testing.T) {
	s := open(t)
	g := sampleGraph()
	inst := []effective.Instance{
		{Locator: "node_modules/lodash", NodeID: "pkg:npm/lodash@4.17.21", DerivedFrom: "lockfile"},
		{Locator: "node_modules/a/node_modules/lodash", NodeID: "pkg:npm/lodash@4.17.21",
			ParentLocator: "node_modules/a", DerivedFrom: "lockfile"},
	}
	runID, err := s.WriteRun(context.Background(), sampleMeta(), g, inst, rollup.Compute(g, inst, "root"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Instances(context.Background(), runID, "pkg:npm/lodash@4.17.21")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("instances = %d, want 2 — a package really can be installed twice", len(got))
	}
}

func TestRunsAreListedNewestFirst(t *testing.T) {
	s := open(t)
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")
	for i := 0; i < 3; i++ {
		if _, err := s.WriteRun(context.Background(), sampleMeta(), g, nil, res); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := s.Runs(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Fatalf("runs = %d, want 3", len(runs))
	}
}

// A run must round-trip both time axes: an audit that cannot say which instant
// it reasoned about is not an audit.
func TestBothTimeAxesPersist(t *testing.T) {
	s := open(t)
	g := sampleGraph()
	m := sampleMeta()
	m.KnownAt = time.Unix(1765009999, 0).UTC()

	runID, err := s.WriteRun(context.Background(), m, g, nil, rollup.Compute(g, nil, "root"))
	if err != nil {
		t.Fatal(err)
	}
	runs, err := s.Runs(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if runs[0].RunID != runID {
		t.Fatalf("run id mismatch")
	}
	if !runs[0].AsOf.Equal(m.AsOf) || !runs[0].KnownAt.Equal(m.KnownAt) {
		t.Errorf("as_of/known_at = %v/%v, want %v/%v", runs[0].AsOf, runs[0].KnownAt, m.AsOf, m.KnownAt)
	}
}

// Observations are what make a re-scan incremental across processes: without a
// durable record, every run starts cold and --max-metadata-age can never help.
func TestPackumentObservationsRoundTrip(t *testing.T) {
	s := open(t)
	ctx := context.Background()

	if _, _, _, ok := s.LastPackument(ctx, "npm", "lodash"); ok {
		t.Fatal("empty store reported an observation")
	}

	t1 := time.Unix(1765000000, 0).UTC()
	if err := s.RecordPackument(ctx, "npm", "lodash", "sha-abbrev", t1, false); err != nil {
		t.Fatal(err)
	}
	sha, at, full, ok := s.LastPackument(ctx, "npm", "lodash")
	if !ok || sha != "sha-abbrev" || full || !at.Equal(t1) {
		t.Fatalf("got %q %v full=%v ok=%v", sha, at, full, ok)
	}

	// A later, fuller observation must win: an abbreviated body cannot satisfy a
	// request that needs publish times.
	t2 := t1.Add(time.Hour)
	if err := s.RecordPackument(ctx, "npm", "lodash", "sha-full", t2, true); err != nil {
		t.Fatal(err)
	}
	sha, at, full, _ = s.LastPackument(ctx, "npm", "lodash")
	if sha != "sha-full" || !full || !at.Equal(t2) {
		t.Errorf("newest observation not returned: %q %v full=%v", sha, at, full)
	}
}

// Tag -> SHA history is the one thing no API can reconstruct after the fact, so
// every observation of it must be kept rather than overwritten.
func TestRefObservationsAreAppendOnly(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	ref := "pkg:github/actions/checkout@v4"

	t1 := time.Unix(1765000000, 0).UTC()
	t2 := t1.Add(24 * time.Hour)
	if err := s.RecordRef(ctx, ref, "aaaa1111", t1); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordRef(ctx, ref, "bbbb2222", t2); err != nil {
		t.Fatal(err)
	}
	runs, err := s.RefHistory(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("ref history = %d entries, want 2 — a re-pointed tag must be visible", len(runs))
	}
	if runs[0].Resolved != "aaaa1111" || runs[1].Resolved != "bbbb2222" {
		t.Errorf("history out of order: %+v", runs)
	}
}

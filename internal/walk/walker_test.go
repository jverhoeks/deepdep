package walk_test

import (
	"context"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/resolve"
	"github.com/jverhoeks/deepdep/internal/source"
	"github.com/jverhoeks/deepdep/internal/version"
	"github.com/jverhoeks/deepdep/internal/walk"
)

const rootID = graph.NodeID("pkg:generic/root@test")

// fakeResolver serves a fixed universe so the walker's own logic is what is
// under test, not the registry client.
type fakeResolver struct {
	vers map[string][]string
	deps map[string][]resolve.Requirement
	pub  map[string]time.Time
}

func (f fakeResolver) Ecosystem() string { return "npm" }

func (f fakeResolver) Versions(_ context.Context, n string, _ bool) ([]resolve.VersionInfo, error) {
	var out []resolve.VersionInfo
	for _, s := range f.vers[n] {
		v, err := version.NPM.Parse(s)
		if err != nil {
			return nil, err
		}
		out = append(out, resolve.VersionInfo{Version: v, PublishedAt: f.pub[n+"@"+s]})
	}
	return out, nil
}

func (f fakeResolver) Requirements(_ context.Context, n string, v version.Version) ([]resolve.Requirement, error) {
	return f.deps[n+"@"+v.String()], nil
}

func walkManifest(t *testing.T, fr fakeResolver, p version.BoundPolicy, depth int, manifest string) *graph.Graph {
	t.Helper()
	return walkOpts(t, fr, walk.Bounds{
		MaxDepth: depth, MaxNodes: 10000, Concurrency: 4, Version: p,
	}, manifest)
}

func walkOpts(t *testing.T, fr fakeResolver, b walk.Bounds, manifest string) *graph.Graph {
	t.Helper()
	g, err := tryWalk(fr, b, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func tryWalk(fr fakeResolver, b walk.Bounds, manifest string) (*graph.Graph, error) {
	reg := extract.NewRegistry()
	reg.Register(extract.NPMManifest{})
	src := source.Static([]source.File{{Path: "package.json", Data: []byte(manifest)}})
	w := walk.New(b, map[string]resolve.Resolver{"npm": fr}, reg, map[string]version.VersionScheme{"npm": version.NPM})
	return w.Walk(context.Background(), src, rootID)
}

func mustWalk(t *testing.T, fr fakeResolver, p version.BoundPolicy, depth int) *graph.Graph {
	t.Helper()
	return walkManifest(t, fr, p, depth, `{"name":"root","dependencies":{"a":"^1.0.0"}}`)
}

func mustWalkWithDeps(t *testing.T, fr fakeResolver, manifest string) *graph.Graph {
	t.Helper()
	return walkManifest(t, fr, version.BoundPolicy{Mode: version.ModeLatest}, 32, manifest)
}

// The product thesis, in one test. Different satisfying versions of `a` have
// DIFFERENT dependency sets, so the union over the range is strictly larger than
// what installs today. Every existing SBOM tool reports only the `will` answer.
func TestWalkerWillVsCan(t *testing.T) {
	fr := fakeResolver{
		vers: map[string][]string{"a": {"1.0.0", "1.1.0"}, "b": {"2.0.0"}, "c": {"3.0.0"}},
		deps: map[string][]resolve.Requirement{
			"a@1.0.0": {{Name: "b", Constraint: "^2.0.0", Scope: graph.Prod}},
			"a@1.1.0": {{Name: "c", Constraint: "^3.0.0", Scope: graph.Prod}},
		},
	}

	will := mustWalk(t, fr, version.BoundPolicy{Mode: version.ModeLatest}, 32)
	if will.Has("pkg:npm/b@2.0.0") {
		t.Error("will-closure must not contain b: only a@1.1.0 installs today")
	}
	if !will.Has("pkg:npm/c@3.0.0") {
		t.Error("will-closure must contain c")
	}

	can := mustWalk(t, fr, version.BoundPolicy{Mode: version.ModeAll, MaxVersionsPerRange: 10}, 32)
	if !can.Has("pkg:npm/b@2.0.0") || !can.Has("pkg:npm/c@3.0.0") {
		t.Error("can-closure must contain BOTH b and c")
	}
	if len(can.Nodes()) <= len(will.Nodes()) {
		t.Errorf("can has %d nodes, will has %d; can must be strictly larger",
			len(can.Nodes()), len(will.Nodes()))
	}
}

// npm installs devDependencies of the ROOT manifest only. Walking them
// transitively inflates the closure with the jest-subtrees of your dependencies.
func TestWalkerSkipsTransitiveDevDeps(t *testing.T) {
	fr := fakeResolver{
		vers: map[string][]string{"a": {"1.0.0"}, "jest": {"29.0.0"}},
		deps: map[string][]resolve.Requirement{
			"a@1.0.0": {{Name: "jest", Constraint: "^29.0.0", Scope: graph.Dev}},
		},
	}
	g := mustWalk(t, fr, version.BoundPolicy{Mode: version.ModeLatest}, 32)
	if g.Has("pkg:npm/jest@29.0.0") {
		t.Error("transitive devDependencies must NOT be walked")
	}
}

func TestWalkerIncludesRootDevDeps(t *testing.T) {
	fr := fakeResolver{vers: map[string][]string{"jest": {"29.0.0"}}}
	g := mustWalkWithDeps(t, fr, `{"name":"root","devDependencies":{"jest":"^29.0.0"}}`)
	if !g.Has("pkg:npm/jest@29.0.0") {
		t.Error("root devDependencies MUST be walked — npm installs them")
	}
}

func TestWalkerTerminatesOnCycle(t *testing.T) {
	fr := fakeResolver{
		vers: map[string][]string{"a": {"1.0.0"}, "b": {"1.0.0"}},
		deps: map[string][]resolve.Requirement{
			"a@1.0.0": {{Name: "b", Constraint: "^1.0.0", Scope: graph.Prod}},
			"b@1.0.0": {{Name: "a", Constraint: "^1.0.0", Scope: graph.Prod}},
		},
	}
	done := make(chan struct{})
	go func() {
		tryWalk(fr, walk.Bounds{MaxDepth: 32, MaxNodes: 1000, Concurrency: 4,
			Version: version.BoundPolicy{Mode: version.ModeAll, MaxVersionsPerRange: 10}},
			`{"name":"root","dependencies":{"a":"^1.0.0"}}`)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("walker did not terminate on a dependency cycle")
	}
}

// A bound must never silently drop a node. "Here are the places the closure is
// incomplete" is the product; a quietly shorter list is a wrong answer.
func TestDepthBoundMarksDeclaredWithReason(t *testing.T) {
	fr := fakeResolver{
		vers: map[string][]string{"a": {"1.0.0"}, "b": {"1.0.0"}},
		deps: map[string][]resolve.Requirement{
			"a@1.0.0": {{Name: "b", Constraint: "^1.0.0", Scope: graph.Prod}},
		},
	}
	g := mustWalk(t, fr, version.BoundPolicy{Mode: version.ModeLatest}, 1)

	var found bool
	for _, n := range g.Nodes() {
		if n.Completeness == graph.Declared && n.Reason == graph.ReasonBoundDepth {
			found = true
		}
	}
	if !found {
		t.Error("depth-bounded frontier must be Declared with reason bound:depth, never dropped")
	}
	if !g.Has("pkg:npm/a@1.0.0") {
		t.Error("nodes within the bound must still resolve")
	}
}

func TestScopedPackageIdentitySurvivesWalk(t *testing.T) {
	fr := fakeResolver{vers: map[string][]string{"@types/node": {"20.1.0"}}}
	g := mustWalkWithDeps(t, fr, `{"name":"r","dependencies":{"@types/node":"^20.0.0"}}`)
	if !g.Has("pkg:npm/%40types/node@20.1.0") {
		t.Errorf("scoped node missing; got %v", ids(g))
	}
}

func TestRootEdgesAreRewrittenToRootNode(t *testing.T) {
	fr := fakeResolver{vers: map[string][]string{"a": {"1.0.0"}}}
	g := mustWalk(t, fr, version.BoundPolicy{Mode: version.ModeLatest}, 32)
	if !g.Has(rootID) {
		t.Fatal("root node missing from graph")
	}
	in := g.InboundTo("pkg:npm/a@1.0.0")
	if len(in) != 1 || in[0].From != rootID {
		t.Errorf("inbound = %+v, want a single edge from %s", in, rootID)
	}
}

// --as-of is an audit flag. If publish times are unavailable we must fail loudly
// rather than record the flag and quietly ignore it.
func TestAsOfWithoutPublishTimesErrors(t *testing.T) {
	fr := fakeResolver{vers: map[string][]string{"a": {"1.0.0", "1.1.0"}}} // no pub times
	_, err := tryWalk(fr, walk.Bounds{
		MaxDepth: 32, MaxNodes: 1000, Concurrency: 2,
		Version: version.BoundPolicy{Mode: version.ModeLatest},
		AsOf:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}, `{"name":"root","dependencies":{"a":"^1.0.0"}}`)
	if err == nil {
		t.Error("--as-of must error when publish times are unavailable")
	}
}

func TestAsOfExcludesVersionsPublishedLater(t *testing.T) {
	old := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fr := fakeResolver{
		vers: map[string][]string{"a": {"1.0.0", "1.1.0"}},
		pub:  map[string]time.Time{"a@1.0.0": old, "a@1.1.0": recent},
	}
	g := walkOpts(t, fr, walk.Bounds{
		MaxDepth: 32, MaxNodes: 1000, Concurrency: 2,
		Version: version.BoundPolicy{Mode: version.ModeLatest},
		AsOf:    time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC),
	}, `{"name":"root","dependencies":{"a":"^1.0.0"}}`)

	if !g.Has("pkg:npm/a@1.0.0") {
		t.Error("version published before --as-of must be present")
	}
	if g.Has("pkg:npm/a@1.1.0") {
		t.Error("version published AFTER --as-of must not exist yet")
	}
}

func ids(g *graph.Graph) []graph.NodeID {
	var out []graph.NodeID
	for _, n := range g.Nodes() {
		out = append(out, n.ID)
	}
	return out
}

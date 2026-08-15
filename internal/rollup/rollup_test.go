package rollup_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/version"
)

const root = graph.NodeID("root")

// link adds a node the way the walker does — with a concrete version — and an
// edge to it. Version matters: a version-less node is an unresolved requirement,
// not a version, and the rollup treats the two differently.
func link(g *graph.Graph, from, to graph.NodeID) {
	name, ver := "n", "1.0.0"
	if i := strings.LastIndex(string(to), "@"); i > 0 {
		name, ver = string(to)[:i], string(to)[i+1:]
	} else {
		name = string(to)
	}
	g.Add(graph.Node{ID: to, Ecosystem: "npm", Name: name, Version: ver})
	g.Link(graph.Edge{From: from, To: to, Kind: graph.DependsOn})
}

func versions(res rollup.Result) map[graph.NodeID]rollup.VersionStatus {
	out := map[graph.NodeID]rollup.VersionStatus{}
	for _, v := range res.Versions {
		out[v.NodeID] = v
	}
	return out
}

// A diamond: two parents both reach d. That is TWO ways d gets pulled in, and
// the count must reflect it — this is the "why is this here?" statistic.
func TestPathCountOnDiamond(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: root})
	link(g, root, "pkg:npm/a@1.0.0")
	link(g, root, "pkg:npm/b@1.0.0")
	link(g, "pkg:npm/a@1.0.0", "pkg:npm/d@1.0.0")
	link(g, "pkg:npm/b@1.0.0", "pkg:npm/d@1.0.0")

	got := versions(rollup.Compute(g, nil, root))
	if got["pkg:npm/d@1.0.0"].Paths != 2 {
		t.Errorf("diamond path count = %d, want 2", got["pkg:npm/d@1.0.0"].Paths)
	}
	if got["pkg:npm/a@1.0.0"].Paths != 1 {
		t.Errorf("direct dep path count = %d, want 1", got["pkg:npm/a@1.0.0"].Paths)
	}
}

// Counting simple paths in a cyclic graph is #P-complete, so the count is taken
// over the SCC condensation. Without that this hangs or explodes.
func TestTerminatesOnCycleViaSCC(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: root})
	link(g, root, "pkg:npm/a@1.0.0")
	link(g, "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0")
	link(g, "pkg:npm/b@1.0.0", "pkg:npm/a@1.0.0") // cycle

	done := make(chan rollup.Result, 1)
	go func() { done <- rollup.Compute(g, nil, root) }()
	select {
	case res := <-done:
		if len(res.Versions) == 0 {
			t.Error("cyclic graph produced no rollup rows")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rollup hung on a cycle — SCC condensation missing")
	}
}

// 20 chained diamonds is 2^20 paths. The count must saturate rather than
// overflow, and the report must say "10000+" rather than a wrong number.
func TestPathCountSaturates(t *testing.T) {
	// Real package PURLs: only package nodes reach the version rollup, because a
	// build file and a shell step carry a version field and are not packages.
	id := func(pfx string, i int) graph.NodeID {
		return graph.NodeID(fmt.Sprintf("pkg:npm/%s%d@1.0.0", pfx, i))
	}
	g := graph.New()
	g.Add(graph.Node{ID: id("n", 0), Ecosystem: "npm", Name: "n0", Version: "1.0.0"})
	for i := 0; i < 20; i++ {
		for _, n := range []graph.NodeID{id("l", i), id("r", i), id("n", i+1)} {
			g.Add(graph.Node{ID: n, Ecosystem: "npm", Name: string(n), Version: "1.0.0"})
		}
		link(g, id("n", i), id("l", i))
		link(g, id("n", i), id("r", i))
		link(g, id("l", i), id("n", i+1))
		link(g, id("r", i), id("n", i+1))
	}
	got := versions(rollup.Compute(g, nil, id("n", 0)))
	if got[id("n", 20)].Paths != rollup.PathCap {
		t.Errorf("paths = %d, want saturation at %d", got[id("n", 20)].Paths, rollup.PathCap)
	}
}

// State (will it land on disk?) is orthogonal to Completeness (how well do we
// know it?). This is the can/will distinction surfaced per package.
func TestInstalledVsPossibleVsUnknown(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: root})
	g.Add(graph.Node{ID: "pkg:npm/a@1.0.0", Ecosystem: "npm", Name: "a", Version: "1.0.0"})
	g.Add(graph.Node{ID: "pkg:npm/a@1.1.0", Ecosystem: "npm", Name: "a", Version: "1.1.0"})
	g.Link(graph.Edge{From: root, To: "pkg:npm/a@1.0.0", Kind: graph.DependsOn})
	g.Link(graph.Edge{From: root, To: "pkg:npm/a@1.1.0", Kind: graph.DependsOn})

	inst := []effective.Instance{{Locator: "node_modules/a", NodeID: "pkg:npm/a@1.1.0", DerivedFrom: "lockfile"}}
	got := versions(rollup.Compute(g, inst, root))
	if got["pkg:npm/a@1.1.0"].State != rollup.Installed {
		t.Errorf("1.1.0 = %q, want installed", got["pkg:npm/a@1.1.0"].State)
	}
	if got["pkg:npm/a@1.0.0"].State != rollup.Possible {
		t.Errorf("1.0.0 = %q, want possible", got["pkg:npm/a@1.0.0"].State)
	}

	// With NO instances at all we cannot know. Saying "possible" would lie in the
	// other direction.
	for _, v := range versions(rollup.Compute(g, nil, root)) {
		if v.NodeID == root {
			continue
		}
		if v.State != rollup.Unknown {
			t.Errorf("no lockfile: %s = %q, want unknown", v.NodeID, v.State)
		}
	}
}

// Hoisted means one copy serving many dependents; nested means genuinely
// several copies. Instances and Paths measure different things.
func TestInstanceCountDistinguishesHoistedFromNested(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: root})
	g.Add(graph.Node{ID: "pkg:npm/lodash@4.17.21", Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	g.Add(graph.Node{ID: "pkg:npm/lodash@3.10.1", Ecosystem: "npm", Name: "lodash", Version: "3.10.1"})
	g.Link(graph.Edge{From: root, To: "pkg:npm/lodash@4.17.21", Kind: graph.DependsOn})
	g.Link(graph.Edge{From: root, To: "pkg:npm/lodash@3.10.1", Kind: graph.DependsOn})

	inst := []effective.Instance{
		{Locator: "node_modules/lodash", NodeID: "pkg:npm/lodash@4.17.21", DerivedFrom: "lockfile"},
		{Locator: "node_modules/b/node_modules/lodash", NodeID: "pkg:npm/lodash@3.10.1", DerivedFrom: "lockfile"},
		{Locator: "node_modules/c/node_modules/lodash", NodeID: "pkg:npm/lodash@3.10.1", DerivedFrom: "lockfile"},
	}
	res := rollup.Compute(g, inst, root)

	var pkg rollup.PackageEntry
	for _, p := range res.Packages {
		if p.Name == "lodash" {
			pkg = p
		}
	}
	if pkg.Name == "" {
		t.Fatal("lodash missing from package rollup")
	}
	if pkg.InstanceCount != 3 {
		t.Errorf("lodash instance count = %d, want 3", pkg.InstanceCount)
	}
	if len(pkg.Versions) != 2 {
		t.Errorf("lodash versions = %d, want 2", len(pkg.Versions))
	}
	got := versions(res)
	if got["pkg:npm/lodash@3.10.1"].Instances != 2 {
		t.Errorf("3.10.1 instances = %d, want 2 (nested twice)", got["pkg:npm/lodash@3.10.1"].Instances)
	}
	if got["pkg:npm/lodash@4.17.21"].Instances != 1 {
		t.Errorf("4.17.21 instances = %d, want 1 (hoisted)", got["pkg:npm/lodash@4.17.21"].Instances)
	}
}

func TestDirectFlagAndWorstCompleteness(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: root})
	g.Add(graph.Node{ID: "pkg:npm/a@1.0.0", Ecosystem: "npm", Name: "a", Version: "1.0.0", Completeness: graph.Resolved})
	g.Add(graph.Node{ID: "pkg:npm/deep@1.0.0", Ecosystem: "npm", Name: "deep", Version: "1.0.0", Completeness: graph.Declared})
	g.Link(graph.Edge{From: root, To: "pkg:npm/a@1.0.0", Kind: graph.DependsOn})
	g.Link(graph.Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/deep@1.0.0", Kind: graph.DependsOn})

	by := map[string]rollup.PackageEntry{}
	for _, p := range rollup.Compute(g, nil, root).Packages {
		by[p.Name] = p
	}
	if !by["a"].Direct {
		t.Error("a is named by the root manifest and must be Direct")
	}
	if by["deep"].Direct {
		t.Error("deep is transitive and must not be Direct")
	}
	if by["deep"].WorstCompleteness != graph.Declared {
		t.Errorf("deep worst completeness = %q, want declared", by["deep"].WorstCompleteness)
	}
}

// The distinction the pinning axis exists for: same installed version, very
// different exposure. A wide range held by a lockfile moves the moment someone
// regenerates the lock; an exact manifest constraint does not.
func TestLockedVersusPinnedVersusFloating(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: root})
	add := func(id graph.NodeID, name, ver, spec string) {
		g.Add(graph.Node{ID: id, Ecosystem: "npm", Name: name, Version: ver})
		g.Link(graph.Edge{From: root, To: id, Kind: graph.DependsOn, Spec: spec, Scope: graph.Prod})
	}
	add("pkg:npm/wide@4.6.1", "wide", "4.6.1", "^4.5.0")  // lockfile holds it
	add("pkg:npm/exact@4.6.1", "exact", "4.6.1", "4.6.1") // manifest holds it
	add("pkg:npm/loose@1.0.0", "loose", "1.0.0", "^1.0.0")

	inst := []effective.Instance{
		{Locator: "node_modules/wide", NodeID: "pkg:npm/wide@4.6.1", DerivedFrom: "lockfile"},
		{Locator: "node_modules/exact", NodeID: "pkg:npm/exact@4.6.1", DerivedFrom: "lockfile"},
	}
	got := versions(rollup.ComputeWith(g, inst, root, map[string]version.VersionScheme{"npm": version.NPM}))

	if p := got["pkg:npm/wide@4.6.1"]; p.Pinning != rollup.Locked {
		t.Errorf("wide range + lockfile = %q, want locked", p.Pinning)
	} else if p.DeclaredSpec != "^4.5.0" {
		t.Errorf("locked row must carry the range it can move within, got %q", p.DeclaredSpec)
	}
	if p := got["pkg:npm/exact@4.6.1"]; p.Pinning != rollup.Pinned {
		t.Errorf("exact manifest constraint = %q, want pinned", p.Pinning)
	}
	if p := got["pkg:npm/loose@1.0.0"]; p.Pinning != rollup.Floating {
		t.Errorf("range with no lockfile entry = %q, want floating", p.Pinning)
	}

	// Both installed at the same version — the pinning axis is the only thing
	// that separates them.
	if got["pkg:npm/wide@4.6.1"].State != got["pkg:npm/exact@4.6.1"].State {
		t.Fatal("both should be installed; the axes must differ only in pinning")
	}
}

// Resolution intersects every constraint reaching a copy, so ONE exact
// constraint binds it however wide the others are. Requiring all of them to be
// exact reported a genuinely immovable package as movable.
func TestOneExactConstraintIsEnoughToPin(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: root})
	g.Add(graph.Node{ID: "pkg:npm/a@1.0.0", Ecosystem: "npm", Name: "a", Version: "1.0.0"})
	g.Add(graph.Node{ID: "pkg:npm/d@2.0.0", Ecosystem: "npm", Name: "d", Version: "2.0.0"})
	g.Link(graph.Edge{From: root, To: "pkg:npm/a@1.0.0", Kind: graph.DependsOn, Spec: "1.0.0"})
	g.Link(graph.Edge{From: root, To: "pkg:npm/d@2.0.0", Kind: graph.DependsOn, Spec: "2.0.0"})
	g.Link(graph.Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/d@2.0.0", Kind: graph.DependsOn, Spec: "^2.0.0"})

	inst := []effective.Instance{{Locator: "node_modules/d", NodeID: "pkg:npm/d@2.0.0", DerivedFrom: "lockfile"}}
	got := versions(rollup.ComputeWith(g, inst, root, map[string]version.VersionScheme{"npm": version.NPM}))
	if p := got["pkg:npm/d@2.0.0"]; p.Pinning != rollup.Pinned {
		t.Errorf("exact root constraint + wider transitive = %q, want pinned: "+
			"the intersection cannot move", p.Pinning)
	}
}

// Without a scheme we cannot judge exactness, and guessing with the wrong syntax
// would be worse than declining.
func TestNoSchemeDoesNotGuessPinning(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: root})
	g.Add(graph.Node{ID: "pkg:npm/a@1.0.0", Ecosystem: "npm", Name: "a", Version: "1.0.0"})
	g.Link(graph.Edge{From: root, To: "pkg:npm/a@1.0.0", Kind: graph.DependsOn, Spec: "1.0.0"})
	got := versions(rollup.Compute(g, nil, root))
	if p := got["pkg:npm/a@1.0.0"]; p.Pinning == rollup.Pinned {
		t.Error("must not claim pinned without an ecosystem to judge exactness")
	}
}

// TestOfflineLockedVersionKeepsItsDeclaredRange.
//
// The distinction the user asked for: `>4.5.0` in a manifest plus `4.6.1` in a
// lockfile installs the same version as `==4.6.1` and carries entirely
// different exposure — regenerate the lock and the first moves, the second does
// not. Recording "locked" without recording what it is locked away FROM throws
// the distinction away.
//
// Offline this needs a join. With no registry the walker never resolves the
// range, so the range sits on an edge to the VERSION-LESS node while the
// installed version arrives separately from the lockfile as a different node.
// Every offline run reported locked with an empty declared_spec — 0 of 1302
// rows on a real repo — until the two were joined by (ecosystem, name).
func TestOfflineLockedVersionKeepsItsDeclaredRange(t *testing.T) {
	g := graph.New()
	root := graph.NodeID("pkg:generic/app@sha")
	g.Add(graph.Node{ID: root, Completeness: graph.Resolved})

	// What the manifest declared: a RANGE, unresolved because we are offline.
	g.Add(graph.Node{ID: "pkg:pypi/requests", Ecosystem: "pypi", Name: "requests",
		Completeness: graph.Declared, Reason: graph.ReasonOffline})
	g.Link(graph.Edge{From: root, To: "pkg:pypi/requests", Kind: graph.DependsOn,
		Spec: ">4.5.0", Scope: graph.Prod})

	// What the lockfile pinned: a different node id entirely.
	g.Add(graph.Node{ID: "pkg:pypi/requests@4.6.1", Ecosystem: "pypi", Name: "requests",
		Version: "4.6.1", Completeness: graph.Resolved})

	inst := []effective.Instance{{Locator: "#requests",
		NodeID: "pkg:pypi/requests@4.6.1", DerivedFrom: "lockfile"}}

	res := rollup.ComputeWith(g, inst, root,
		map[string]version.VersionScheme{"pypi": version.PEP440})

	var got rollup.VersionStatus
	for _, v := range res.Versions {
		if v.NodeID == "pkg:pypi/requests@4.6.1" {
			got = v
		}
	}
	if got.Pinning != rollup.Locked {
		t.Errorf("pinning = %q, want locked", got.Pinning)
	}
	if got.DeclaredSpec != ">4.5.0" {
		t.Errorf("declared_spec = %q, want %q — locked without the range it is "+
			"locked away from is not an answer", got.DeclaredSpec, ">4.5.0")
	}
}

// TestExactManifestConstraintIsPinnedNotLocked is the other half: `==4.6.1`
// needs no lockfile to hold it, so regenerating one changes nothing.
func TestExactManifestConstraintIsPinnedNotLocked(t *testing.T) {
	g := graph.New()
	root := graph.NodeID("pkg:generic/app@sha")
	g.Add(graph.Node{ID: root, Completeness: graph.Resolved})
	g.Add(graph.Node{ID: "pkg:pypi/requests", Ecosystem: "pypi", Name: "requests",
		Completeness: graph.Declared})
	g.Link(graph.Edge{From: root, To: "pkg:pypi/requests", Kind: graph.DependsOn,
		Spec: "==4.6.1", Scope: graph.Prod})
	g.Add(graph.Node{ID: "pkg:pypi/requests@4.6.1", Ecosystem: "pypi", Name: "requests",
		Version: "4.6.1", Completeness: graph.Resolved})

	inst := []effective.Instance{{Locator: "#requests",
		NodeID: "pkg:pypi/requests@4.6.1", DerivedFrom: "lockfile"}}
	res := rollup.ComputeWith(g, inst, root,
		map[string]version.VersionScheme{"pypi": version.PEP440})

	for _, v := range res.Versions {
		if v.NodeID != "pkg:pypi/requests@4.6.1" {
			continue
		}
		if v.Pinning != rollup.Pinned {
			t.Errorf("pinning = %q, want pinned — an exact constraint needs no lockfile", v.Pinning)
		}
		return
	}
	t.Fatal("the locked version is missing from the rollup")
}

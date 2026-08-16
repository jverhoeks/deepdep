package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/store"
	"github.com/jverhoeks/deepdep/internal/walk"
)

// Coverage is a confidence qualifier: it must measure what we could not READ,
// never what we correctly decided not to install.
//
// A dependency's own devDependencies and an unrequested Python extra are
// frontiers because the walk stopped on purpose. Counting them as unread
// packages put axios at 44% auditable — below MinCoverage — when its closure is
// in fact complete for everything that installs. Across a 131-repository fleet
// that suppressed every grade, so the tool reported no verdict anywhere while
// having every fact it needed.
func TestCoverageIgnoresDeliberatelyUninstalledFrontiers(t *testing.T) {
	nodes := []graph.Node{
		{ID: "pkg:npm/installed@1.0.0", Completeness: graph.Resolved},
		{ID: "pkg:npm/also-installed@1.0.0", Completeness: graph.Resolved},
		{ID: "pkg:npm/jest-of-a-dependency@29.0.0", Completeness: graph.Declared,
			Reason: walk.ReasonDevNotInstalled},
		{ID: "pkg:pypi/some-extra@1.0.0", Completeness: graph.Declared,
			Reason: walk.ReasonExtraNotRequested},
		{ID: "pkg:npm/really-unread@1.0.0", Completeness: graph.Declared,
			Reason: graph.ReasonBoundDepth},
	}
	targets := []graph.NodeID{"pkg:npm/installed@1.0.0", "pkg:npm/also-installed@1.0.0"}

	r := buildReport(store.Run{}, "all", time.Now(), targets, nil, nil,
		map[graph.NodeID][]string{}, nodes, map[graph.NodeID][]string{})

	// Denominator is the three in-scope packages, not all five.
	if r.PackageNodes != 3 {
		t.Errorf("package nodes = %d, want 3 — a frontier we chose not to cross is not an unread package", r.PackageNodes)
	}
	if got := r.Auditable; got < 0.66 || got > 0.67 {
		t.Errorf("auditable = %.2f, want 2/3", got)
	}
	// Still listed: they explain the will/can gap and must not vanish.
	if r.Coverage[walk.ReasonDevNotInstalled] != 1 || r.Coverage[graph.ReasonBoundDepth] != 1 {
		t.Errorf("coverage frontier lost a reason: %v", r.Coverage)
	}
}

// The usage text promises that when --timeout fires "the partial closure is
// still emitted, with the frontier marked bound:timeout". One context for the
// whole run broke that in the worst place: the walker stopped correctly and
// marked its frontier, then the store write inherited the expired deadline and
// discarded everything. The largest repositories — precisely the ones where the
// bound fires — reported as total failures while holding a good partial answer.
func TestTimedOutScanStillPersistsItsPartialClosure(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"fx","dependencies":{"is-string":"^1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "d.db")

	// A deadline so short that expansion cannot finish. Offline so the test
	// makes no network call; the point is that the run still lands.
	out, err := run([]string{"scan", "--offline", "--timeout", "1ns",
		"--db", db, "--format", "json", dir})
	if err != nil {
		t.Fatalf("a fired bound must not be an error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no document emitted")
	}
	s, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	runs, err := s.Runs(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatal("the partial closure was not persisted")
	}
}

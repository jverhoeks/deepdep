package store_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/project"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
)

// Scanning the same repository twice is two runs and ONE project. If it were two
// projects the registry would be no more useful than the run list it replaces.
func TestSecondScanOfARepoIsTheSameProject(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")
	o := project.Origin{Kind: project.KindLocal, Remote: "git@github.com:o/r.git", Path: "/src/r"}

	for i := 0; i < 2; i++ {
		if _, err := s.WriteRun(ctx, sampleMeta(), g, nil, res, store.WithOrigin(o)); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("got %d projects, want 1", len(ps))
	}
	if ps[0].Key != "github.com/o/r" {
		t.Errorf("Key = %q, want github.com/o/r", ps[0].Key)
	}
	if ps[0].Runs != 2 {
		t.Errorf("Runs = %d, want 2", ps[0].Runs)
	}
	if len(ps[0].Paths) != 1 || ps[0].Paths[0] != "/src/r" {
		t.Errorf("Paths = %v, want [/src/r] — recorded once, not once per run", ps[0].Paths)
	}
}

// "Paths are locations": one repository checked out twice is one project that
// knows about both directories.
func TestTwoCheckoutsOfOneRepoAreTwoLocations(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")

	for _, p := range []string{"/src/r", "/work/r"} {
		o := project.Origin{Kind: project.KindLocal, Remote: "https://github.com/o/r.git", Path: p}
		if _, err := s.WriteRun(ctx, sampleMeta(), g, nil, res, store.WithOrigin(o)); err != nil {
			t.Fatal(err)
		}
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("got %d projects, want 1", len(ps))
	}
	if len(ps[0].Paths) != 2 {
		t.Fatalf("Paths = %v, want both checkouts", ps[0].Paths)
	}
}

// A run written without an origin — the static source, or --no-db's absence of
// one — must not invent a project, and must stay reportable by run id.
func TestARunWithoutAnOriginIsUnclaimed(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	g := sampleGraph()

	runID, err := s.WriteRun(ctx, sampleMeta(), g, nil, rollup.Compute(g, nil, "root"))
	if err != nil {
		t.Fatal(err)
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 {
		t.Fatalf("got %d projects, want 0", len(ps))
	}
	un, err := s.UnclaimedRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(un) != 1 || un[0].RunID != runID {
		t.Fatalf("UnclaimedRuns = %+v, want the one run %s", un, runID)
	}
}

// Deleting a project takes its runs and their derived rows with it. This is the
// ON DELETE CASCADE chain the schema header promises; it works only because
// foreign_keys(1) rides in the DSN, applying to every pooled connection.
func TestDeletingAProjectCascadesToItsDerivedRows(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")
	o := project.Origin{Kind: project.KindRemote, Remote: "https://github.com/o/r.git"}

	if _, err := s.WriteRun(ctx, sampleMeta(), g, nil, res, store.WithOrigin(o)); err != nil {
		t.Fatal(err)
	}
	// A second, unclaimed run that must SURVIVE the delete.
	keep, err := s.WriteRun(ctx, sampleMeta(), g, nil, res)
	if err != nil {
		t.Fatal(err)
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProjects(ctx, []int64{ps[0].Num}); err != nil {
		t.Fatal(err)
	}

	runs, err := s.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].RunID != keep {
		t.Fatalf("runs = %+v, want only the unclaimed %s", runs, keep)
	}
	for _, table := range []string{"nodes", "edges", "version_rollup", "package_rollup"} {
		n, err := s.CountRowsForTest(ctx, table)
		if err != nil {
			t.Fatal(err)
		}
		want, err := s.CountRowsForRunForTest(ctx, table, keep)
		if err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("%s: %d rows total but %d for the surviving run — the cascade left orphans", table, n, want)
		}
	}
}

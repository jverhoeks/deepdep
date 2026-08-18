package store_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/project"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
)

func seedRuns(t *testing.T, s *store.Store, remote string, n int) []string {
	t.Helper()
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")
	var ids []string
	for i := 0; i < n; i++ {
		id, err := s.WriteRun(context.Background(), sampleMeta(), g, nil, res,
			store.WithOrigin(project.Origin{Kind: project.KindRemote, Remote: remote}))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

// newRunID mixes in UnixNano, so every re-scan appends a run row forever. "Keep
// the newest N per project" is therefore the form of cleanup that matters.
func TestKeepNRetainsTheNewestPerProject(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seedRuns(t, s, "https://github.com/o/one.git", 4)
	seedRuns(t, s, "https://github.com/o/two.git", 3)

	plan, err := s.PlanPrune(ctx, store.PruneQuery{Keep: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Runs) != 3 {
		t.Fatalf("plan deletes %d runs, want 3 (4-2 plus 3-2)", len(plan.Runs))
	}
	if err := s.ApplyPrune(ctx, plan); err != nil {
		t.Fatal(err)
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if p.Runs != 2 {
			t.Errorf("%s has %d runs after --keep 2", p.Key, p.Runs)
		}
	}
}

// The plan and the apply must describe the same deletion, or --dry-run is a
// different code path from the real thing and stops being a preview.
func TestPlanAndApplyAgree(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seedRuns(t, s, "https://github.com/o/one.git", 3)

	plan, err := s.PlanPrune(ctx, store.PruneQuery{Keep: 1})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPrune(ctx, plan); err != nil {
		t.Fatal(err)
	}
	after, err := s.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(before)-len(after) != len(plan.Runs) {
		t.Fatalf("plan said %d runs, apply removed %d", len(plan.Runs), len(before)-len(after))
	}
}

// THE test. scorecard_obs holds 47,557 rows deps.dev will not serve again — it
// serves only the current scorecard, so a deleted one is gone for good. Nothing
// in clean may touch these tables, and the only way to see a regression is to
// count before and after.
func TestPruneNeverTouchesTheObservationTables(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seedRuns(t, s, "https://github.com/o/one.git", 2)
	if err := s.PutScorecardForTest(ctx, "github.com/o/one", 7.5); err != nil {
		t.Fatal(err)
	}

	before, err := s.ObservationCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before["scorecard_obs"] == 0 {
		t.Fatal("fixture wrote no observation, so the test would pass vacuously")
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.PlanPrune(ctx, store.PruneQuery{Num: ps[0].Num, Keep: -1, Purge: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPrune(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := s.Vacuum(ctx); err != nil {
		t.Fatal(err)
	}

	after, err := s.ObservationCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for table, n := range before {
		if after[table] != n {
			t.Errorf("%s: %d rows before, %d after — clean destroyed observations it cannot recreate",
				table, n, after[table])
		}
	}
	runs, err := s.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Errorf("purge left %d runs", len(runs))
	}
}

// An empty selection deletes nothing rather than everything. A cleanup command
// whose bare form wipes the store is a footgun with a countdown.
func TestPlanPruneWithNoSelectionSelectsNothing(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seedRuns(t, s, "https://github.com/o/one.git", 3)

	plan, err := s.PlanPrune(ctx, store.PruneQuery{Keep: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Runs) != 0 || len(plan.Projects) != 0 {
		t.Fatalf("plan = %+v, want empty", plan)
	}
}

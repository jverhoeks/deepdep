package store

import (
	"context"
	"fmt"
	"time"
)

// PruneQuery selects what to delete. The zero value selects NOTHING.
//
// That is the important property. A cleanup command whose empty form means
// "everything" is a footgun, so emptiness has to be the safe answer here rather
// than being caught by a flag check in the CLI that a future caller might skip.
type PruneQuery struct {
	Num       int64     // 0 = every project
	Keep      int       // keep the newest N runs per project; <0 = keep all
	OlderThan time.Time // zero = no age filter
	Unclaimed bool      // also delete runs belonging to no project
	Purge     bool      // delete the project rows too, not just their runs
}

// PrunePlan is exactly what will be deleted. Producing it is separate from
// applying it so --dry-run previews the real thing rather than an approximation
// of it.
type PrunePlan struct {
	Runs     []string
	Projects []int64
	KeptRuns int
}

// PlanPrune works out what a query selects, touching nothing.
func (s *Store) PlanPrune(ctx context.Context, q PruneQuery) (PrunePlan, error) {
	var plan PrunePlan

	ps, err := s.Projects(ctx, ProjectQuery{Num: q.Num})
	if err != nil {
		return plan, err
	}

	for _, p := range ps {
		runs, err := s.RunsForProject(ctx, p.Num) // newest first
		if err != nil {
			return plan, err
		}
		if q.Purge {
			plan.Projects = append(plan.Projects, p.Num)
			for _, r := range runs {
				plan.Runs = append(plan.Runs, r.RunID)
			}
			continue
		}
		for i, r := range runs {
			switch {
			case q.Keep >= 0 && i >= q.Keep:
			case !q.OlderThan.IsZero() && r.CreatedAt.Before(q.OlderThan):
			default:
				plan.KeptRuns++
				continue
			}
			plan.Runs = append(plan.Runs, r.RunID)
		}
	}

	if q.Unclaimed {
		un, err := s.UnclaimedRuns(ctx)
		if err != nil {
			return plan, err
		}
		for _, r := range un {
			if !q.OlderThan.IsZero() && !r.CreatedAt.Before(q.OlderThan) {
				plan.KeptRuns++
				continue
			}
			plan.Runs = append(plan.Runs, r.RunID)
		}
	}
	return plan, nil
}

// ApplyPrune executes a plan in one transaction.
//
// Deleting a run is one DELETE: nodes, edges, instances and both rollups hang
// off it with ON DELETE CASCADE, and foreign_keys(1) is in the DSN so the
// cascade applies on every pooled connection. It deletes from no other table —
// see ObservationCounts for what must survive and why.
func (s *Store) ApplyPrune(ctx context.Context, plan PrunePlan) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range plan.Runs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM runs WHERE run_id = ?`, id); err != nil {
			return err
		}
	}
	for _, num := range plan.Projects {
		if _, err := tx.ExecContext(ctx, `DELETE FROM projects WHERE num = ?`, num); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteRuns removes runs by id and nothing else.
func (s *Store) DeleteRuns(ctx context.Context, ids []string) error {
	return s.ApplyPrune(ctx, PrunePlan{Runs: ids})
}

// observationTables are append-only records of mutable things, and none of them
// is run-scoped.
//
// scorecard_obs is the reason this list is enforced rather than merely
// documented: deps.dev serves only the CURRENT scorecard, with no history
// endpoint and no as-of parameter, so recording one on every run is the only
// thing that makes "what was this project's Code-Review score six months ago"
// answerable. Deleting a row is destroying the only copy.
var observationTables = []string{
	"advisories", "advisory_affects", "packument_obs", "depsdev_obs",
	"scorecard_obs", "ref_obs", "version_facts",
}

// ObservationCounts reports what cleanup preserved, so the guarantee is visible
// in the command's output and assertable in a test.
func (s *Store) ObservationCounts(ctx context.Context) (map[string]int, error) {
	out := make(map[string]int, len(observationTables))
	for _, t := range observationTables {
		n, err := s.count(ctx, `SELECT count(*) FROM `+safeTable(t))
		if err != nil {
			return nil, fmt.Errorf("count %s: %w", t, err)
		}
		out[t] = n
	}
	return out, nil
}

// Vacuum reclaims file space.
//
// The checkpoint comes first because VACUUM rewrites the whole file and cannot
// run with outstanding WAL frames on a pooled connection. Slow — 849MB for the
// store this was written for — so it is opt-in at the CLI.
func (s *Store) Vacuum(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `VACUUM`)
	return err
}

// PutScorecardForTest writes one scorecard observation.
//
// Test-only: it exists so the preservation test cannot pass vacuously against an
// empty table, which it otherwise would, since nothing in this package writes
// scorecard_obs yet.
func (s *Store) PutScorecardForTest(ctx context.Context, projectID string, score float64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scorecard_obs (project_id,observed_at,scorecard_date,overall_score,stars,checks_json)
		 VALUES (?,?,?,?,?,?)`,
		projectID, time.Now().UTC().Format(time.RFC3339Nano), "", score, 0, "{}")
	return err
}

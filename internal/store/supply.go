package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/supply"
)

// RecordSupply appends deps.dev version facts and project scorecards as
// observations.
//
// This is prospective recording, not caching. deps.dev serves only the CURRENT
// scorecard for a project — there is no history endpoint and no `as-of`
// parameter — so a scorecard that was 3/10 when you shipped is unrecoverable
// once the project fixes its CI. `deepdep risk` therefore cannot answer
// "what was this project's posture at release T?" from the API, only from rows
// written at T. Same argument as ref_obs, and the reason both write from the
// first run rather than waiting for a feature that needs them.
//
// Recording is best-effort by design: a failure here must not fail the report
// the user asked for. The caller logs and continues.
func (s *Store) RecordSupply(ctx context.Context, facts []supply.Fact,
	projects map[string]supply.Project, observedAt time.Time) error {

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	at := observedAt.UTC().Format(time.RFC3339)

	fs, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO depsdev_obs
	  (purl, observed_at, known, deprecated, deprecated_why, licenses,
	   advisory_ids, attested, source_repo, repo_provenance)
	  VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer fs.Close()
	for _, f := range facts {
		if _, err := fs.ExecContext(ctx, string(f.NodeID), at,
			boolInt(f.Known), boolInt(f.Deprecated), f.DeprecatedReason,
			strings.Join(f.Licenses, ","), strings.Join(f.AdvisoryIDs, ","),
			boolInt(f.Attested), f.SourceRepo, f.RepoProvenance); err != nil {
			return err
		}
	}

	ps, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO scorecard_obs
	  (project_id, observed_at, scorecard_date, overall_score, stars, checks_json)
	  VALUES (?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer ps.Close()
	for id, p := range projects {
		if !p.HasScorecard {
			continue
		}
		checks, err := json.Marshal(p.Checks)
		if err != nil {
			return err
		}
		date := ""
		if !p.ScorecardDate.IsZero() {
			date = p.ScorecardDate.UTC().Format(time.RFC3339)
		}
		if _, err := ps.ExecContext(ctx, id, at, date, p.OverallScore,
			p.Stars, string(checks)); err != nil {
			return err
		}
	}

	return tx.Commit()
}

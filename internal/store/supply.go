package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
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

// SupplyFacts returns the NEWEST deps.dev observation for each node.
//
// Newest, not "the one from this run": these are observations of a mutable
// upstream, and an SBOM should carry the best information available at emission
// time. The observed_at that produced each row stays in the table, so a later
// question about what we knew when is still answerable.
//
// An empty result is legitimate and load-bearing — it means `deepdep risk` has
// never run — and the emitter turns it into a named gap rather than letting the
// document read as "these components genuinely have no licence".
func (s *Store) SupplyFacts(ctx context.Context, nodes []graph.Node) (map[graph.NodeID]emit.Facts, error) {
	rows, err := s.db.QueryContext(ctx, `
	  SELECT d.purl, d.licenses, d.source_repo, d.repo_provenance
	    FROM depsdev_obs d
	    JOIN (SELECT purl, MAX(observed_at) AS newest FROM depsdev_obs GROUP BY purl) m
	      ON m.purl = d.purl AND m.newest = d.observed_at
	   WHERE d.known = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	all := map[graph.NodeID]emit.Facts{}
	for rows.Next() {
		var purl, licenses, repo, prov string
		if err := rows.Scan(&purl, &licenses, &repo, &prov); err != nil {
			return nil, err
		}
		f := emit.Facts{SourceRepo: repo, RepoProvenance: prov}
		if licenses != "" {
			f.Licenses = strings.Split(licenses, ",")
		}
		all[graph.NodeID(purl)] = f
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Return only what this graph asked about, so a caller cannot accidentally
	// emit a licence for a package that is not in the document.
	out := make(map[graph.NodeID]emit.Facts, len(nodes))
	for _, n := range nodes {
		if f, ok := all[n.ID]; ok {
			out[n.ID] = f
		}
	}
	return out, nil
}

// NodeOwners maps each node to the applications and build files that pull it in.
//
// Two sources, because a package can arrive either way: an instance's locator
// directory names the application whose lockfile installed it, and an edge from
// a build-file node names the Dockerfile or workflow that runs it. A node with
// neither is repository-level.
//
// Read from the store rather than recomputed, so a report can attribute a
// finding without re-scanning the tree.
func (s *Store) NodeOwners(ctx context.Context, runID string) (map[graph.NodeID][]string, error) {
	out := map[graph.NodeID]map[string]bool{}
	add := func(id graph.NodeID, owner string) {
		if owner == "" {
			return
		}
		if out[id] == nil {
			out[id] = map[string]bool{}
		}
		out[id][owner] = true
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, locator FROM instances WHERE run_id=?`, runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, locator string
		if err := rows.Scan(&id, &locator); err != nil {
			rows.Close()
			return nil, err
		}
		dir, _, ok := strings.Cut(locator, "#")
		if !ok || dir == "" {
			dir = "."
		}
		add(graph.NodeID(id), dir)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// A build file's node id carries its path as the PURL subpath, so the owner
	// name comes straight out of the join with no second lookup.
	rows, err = s.db.QueryContext(ctx, `
	  SELECT e.to_id, e.from_id FROM edges e
	   WHERE e.run_id=? AND e.from_id LIKE 'pkg:generic/buildfile/%'`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var to, from string
		if err := rows.Scan(&to, &from); err != nil {
			return nil, err
		}
		if _, p, ok := strings.Cut(from, "#"); ok {
			add(graph.NodeID(to), p)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	final := make(map[graph.NodeID][]string, len(out))
	for id, set := range out {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		final[id] = names
	}
	return final, nil
}

// Nodes returns a run's full node list.
//
// The rollup views cover package VERSIONS; control detection needs the rest of
// the graph — CI actions, shell steps, recognised-but-unexpanded config files —
// because that is where the evidence of a security control lives.
func (s *Store) Nodes(ctx context.Context, runID string) ([]graph.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
	  SELECT id, ecosystem, name, version, completeness, reason, source_file, note
	    FROM nodes WHERE run_id=? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []graph.Node
	for rows.Next() {
		var n graph.Node
		var reason, source, note *string
		if err := rows.Scan(&n.ID, &n.Ecosystem, &n.Name, &n.Version,
			&n.Completeness, &reason, &source, &note); err != nil {
			return nil, err
		}
		n.Reason, n.Source, n.Note = deref(reason), deref(source), deref(note)
		out = append(out, n)
	}
	return out, rows.Err()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// PinningCounts returns how many package versions are pinned, locked or
// floating — the hygiene input to the score.
func (s *Store) PinningCounts(ctx context.Context, runID string) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT pinning, COUNT(*) FROM version_rollup WHERE run_id=? GROUP BY pinning`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// Package store persists runs in SQLite.
//
// SQLite via modernc.org/sqlite (pure Go, no cgo) keeps deepdep a single
// statically-linked, cross-compilable binary. The engine choice is driven by the
// queries rather than the writes: bitemporal audits are timestamp-filtered
// joins, the UI needs indexed adjacency for expand-on-click and ORDER BY/LIMIT
// for a paginated package list. A key-value store would mean hand-rolling all of
// that; the ~2x insert cost against the cgo driver is irrelevant for one bulk
// transaction per run.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/rollup"
)

//go:embed schema.sql
var schemaSQL string

// schemaVersion drives migrations through PRAGMA user_version.
const schemaVersion = 3

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// WAL lets a future `deepdep serve` read while a scan writes.
	for _, p := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, err
		}
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v >= schemaVersion {
		return nil
	}
	if v == 0 {
		if _, err := s.db.Exec(schemaSQL); err != nil {
			return err
		}
	}
	if v == 1 {
		// v1 stored packument observations without recording which form of the
		// document it was; an abbreviated body cannot satisfy an --as-of run.
		if _, err := s.db.Exec(`ALTER TABLE packument_obs ADD COLUMN full INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if v > 0 && v < 3 {
		for _, stmt := range []string{
			`ALTER TABLE version_rollup ADD COLUMN pinning TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE version_rollup ADD COLUMN declared_spec TEXT NOT NULL DEFAULT ''`,
		} {
			if _, err := s.db.Exec(stmt); err != nil {
				return err
			}
		}
	}
	_, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))
	return err
}

// Run is a stored scan's provenance.
type Run struct {
	RunID       string
	Target      string
	Ref         string
	Mode        string
	AsOf        time.Time
	KnownAt     time.Time
	ToolVersion string
	CreatedAt   time.Time
}

// PackageQuery filters the flat package list.
type PackageQuery struct {
	Name      string
	Ecosystem string
	State     rollup.State
	Limit     int
	Offset    int
}

// WriteRun persists a whole scan in one transaction.
func (s *Store) WriteRun(ctx context.Context, m emit.Meta, g *graph.Graph,
	inst []effective.Instance, res rollup.Result) (string, error) {

	runID := newRunID(m, g)
	bounds, _ := json.Marshal(m.Bounds)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO runs (run_id,target,ref,mode,as_of,known_at,tool_version,bounds_json,created_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		runID, m.Repo, m.Ref, defaultMode(m.Mode), rfc(m.AsOf), rfc(m.KnownAt), m.ToolVersion, string(bounds), now,
	); err != nil {
		return "", err
	}

	nodeStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO nodes (run_id,id,ecosystem,name,version,completeness,reason,resolved_ref,published_at,source_file,note)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return "", err
	}
	for _, n := range g.Nodes() {
		var pub any
		if !n.PublishedAt.IsZero() {
			pub = rfc(n.PublishedAt)
		}
		if _, err := nodeStmt.ExecContext(ctx, runID, string(n.ID), n.Ecosystem, n.Name, n.Version,
			string(n.Completeness), n.Reason, n.ResolvedRef, pub, n.Source, n.Note); err != nil {
			return "", err
		}
	}

	// INSERT OR IGNORE: the graph already deduplicates, and the primary key is
	// the second line of defence. They must not disagree.
	edgeStmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO edges (run_id,from_id,to_id,kind,spec,scope) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		return "", err
	}
	for _, e := range g.Edges() {
		scope := e.Scope
		if scope == "" {
			scope = graph.Prod
		}
		if _, err := edgeStmt.ExecContext(ctx, runID, string(e.From), string(e.To),
			string(e.Kind), e.Spec, string(scope)); err != nil {
			return "", err
		}
	}

	instStmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO instances (run_id,locator,node_id,parent_locator,derived_from) VALUES (?,?,?,?,?)`)
	if err != nil {
		return "", err
	}
	for _, i := range inst {
		if _, err := instStmt.ExecContext(ctx, runID, i.Locator, string(i.NodeID),
			i.ParentLocator, i.DerivedFrom); err != nil {
			return "", err
		}
	}

	pkgStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO package_rollup (run_id,ecosystem,name,direct,instance_count,path_count,worst_completeness)
		 VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		return "", err
	}
	for _, p := range res.Packages {
		if _, err := pkgStmt.ExecContext(ctx, runID, p.Ecosystem, p.Name, boolInt(p.Direct),
			p.InstanceCount, p.PathCount, string(p.WorstCompleteness)); err != nil {
			return "", err
		}
	}

	verStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO version_rollup (run_id,node_id,ecosystem,name,version,installedness,pinning,declared_spec,instance_count,path_count)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return "", err
	}
	for _, p := range res.Packages {
		for _, v := range p.Versions {
			if _, err := verStmt.ExecContext(ctx, runID, string(v.NodeID), p.Ecosystem, p.Name,
				v.Version, string(v.State), string(v.Pinning), v.DeclaredSpec, v.Instances, v.Paths); err != nil {
				return "", err
			}
		}
	}

	return runID, tx.Commit()
}

// newRunID derives a stable id from the run's inputs, so re-running the same
// scan twice is visible as two rows rather than colliding.
func newRunID(m emit.Meta, g *graph.Graph) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%d|%d",
		m.Repo, m.Ref, m.Mode, rfc(m.AsOf), len(g.Nodes()), time.Now().UnixNano())
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (s *Store) InboundTo(ctx context.Context, runID string, id graph.NodeID) ([]graph.Edge, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT from_id,to_id,kind,spec,scope FROM edges WHERE run_id=? AND to_id=? ORDER BY from_id,spec`,
		runID, string(id))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []graph.Edge
	for rows.Next() {
		var e graph.Edge
		var from, to, kind, scope string
		if err := rows.Scan(&from, &to, &kind, &e.Spec, &scope); err != nil {
			return nil, err
		}
		e.From, e.To = graph.NodeID(from), graph.NodeID(to)
		e.Kind, e.Scope = graph.EdgeKind(kind), graph.Scope(scope)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Instances(ctx context.Context, runID string, id graph.NodeID) ([]effective.Instance, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT locator,node_id,COALESCE(parent_locator,''),derived_from
		   FROM instances WHERE run_id=? AND node_id=? ORDER BY locator`,
		runID, string(id))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []effective.Instance
	for rows.Next() {
		var i effective.Instance
		var node string
		if err := rows.Scan(&i.Locator, &node, &i.ParentLocator, &i.DerivedFrom); err != nil {
			return nil, err
		}
		i.NodeID = graph.NodeID(node)
		out = append(out, i)
	}
	return out, rows.Err()
}

// Packages returns the flat, sortable package list — the view an engineer reads.
func (s *Store) Packages(ctx context.Context, runID string, q PackageQuery) ([]rollup.PackageEntry, error) {
	if runID == "" {
		runs, err := s.Runs(ctx, 1)
		if err != nil {
			return nil, err
		}
		if len(runs) == 0 {
			return nil, nil
		}
		runID = runs[0].RunID
	}

	sqlStr := `SELECT ecosystem,name,direct,instance_count,path_count,worst_completeness
	             FROM package_rollup WHERE run_id=?`
	args := []any{runID}
	if q.Name != "" {
		sqlStr += " AND name=?"
		args = append(args, q.Name)
	}
	if q.Ecosystem != "" {
		sqlStr += " AND ecosystem=?"
		args = append(args, q.Ecosystem)
	}
	sqlStr += " ORDER BY path_count DESC, name"
	if q.Limit > 0 {
		sqlStr += fmt.Sprintf(" LIMIT %d OFFSET %d", q.Limit, q.Offset)
	}

	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []rollup.PackageEntry
	for rows.Next() {
		var p rollup.PackageEntry
		var direct int
		var worst string
		if err := rows.Scan(&p.Ecosystem, &p.Name, &direct, &p.InstanceCount, &p.PathCount, &worst); err != nil {
			return nil, err
		}
		p.Direct = direct == 1
		p.WorstCompleteness = graph.Completeness(worst)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range out {
		vs, err := s.versionsFor(ctx, runID, out[i].Ecosystem, out[i].Name, q.State)
		if err != nil {
			return nil, err
		}
		out[i].Versions = vs
	}
	return out, nil
}

func (s *Store) versionsFor(ctx context.Context, runID, eco, name string, state rollup.State) ([]rollup.VersionStatus, error) {
	sqlStr := `SELECT node_id,version,installedness,pinning,declared_spec,instance_count,path_count
	             FROM version_rollup WHERE run_id=? AND ecosystem=? AND name=?`
	args := []any{runID, eco, name}
	if state != "" {
		sqlStr += " AND installedness=?"
		args = append(args, string(state))
	}
	sqlStr += " ORDER BY version"

	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []rollup.VersionStatus
	for rows.Next() {
		var v rollup.VersionStatus
		var node, st, pin string
		if err := rows.Scan(&node, &v.Version, &st, &pin, &v.DeclaredSpec, &v.Instances, &v.Paths); err != nil {
			return nil, err
		}
		v.NodeID = graph.NodeID(node)
		v.State = rollup.State(st)
		v.Pinning = rollup.Pinning(pin)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) Runs(ctx context.Context, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT run_id,target,ref,mode,as_of,known_at,tool_version,created_at
		   FROM runs ORDER BY created_at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Run
	for rows.Next() {
		var r Run
		var asOf, knownAt, created string
		if err := rows.Scan(&r.RunID, &r.Target, &r.Ref, &r.Mode, &asOf, &knownAt, &r.ToolVersion, &created); err != nil {
			return nil, err
		}
		r.AsOf, _ = time.Parse(time.RFC3339Nano, asOf)
		r.KnownAt, _ = time.Parse(time.RFC3339Nano, knownAt)
		r.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, r)
	}
	return out, rows.Err()
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func defaultMode(m string) string {
	if m == "can" {
		return "can"
	}
	return "will"
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// LastPackument returns the most recent observation of a package's metadata.
//
// Observations are append-only, so this reads the newest row rather than
// mutating an existing one: the history of what we saw and when is the whole
// point of the table.
func (s *Store) LastPackument(ctx context.Context, ecosystem, name string) (string, time.Time, bool, bool) {
	var (
		sha      string
		observed string
		full     int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT body_sha256, observed_at, full FROM packument_obs
		   WHERE ecosystem=? AND name=? ORDER BY observed_at DESC LIMIT 1`,
		ecosystem, name).Scan(&sha, &observed, &full)
	if err != nil {
		return "", time.Time{}, false, false
	}
	t, err := time.Parse(time.RFC3339Nano, observed)
	if err != nil {
		return "", time.Time{}, false, false
	}
	return sha, t, full == 1, true
}

func (s *Store) RecordPackument(ctx context.Context, ecosystem, name, sha string, observedAt time.Time, full bool) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO packument_obs (ecosystem,name,observed_at,body_sha256,full)
		 VALUES (?,?,?,?,?)`,
		ecosystem, name, rfc(observedAt), sha, boolInt(full))
	return err
}

// RecordRef notes what a mutable reference pointed at right now.
//
// This is the one observation that can never be reconstructed later: no API
// exposes what a git tag or container tag pointed at in the past. A scan that
// does not write this down loses that instant permanently.
func (s *Store) RecordRef(ctx context.Context, refPURL, resolved string, observedAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO ref_obs (ref_purl,resolved,observed_at) VALUES (?,?,?)`,
		refPURL, resolved, rfc(observedAt))
	return err
}

// RecordVersionFacts stores publish times, which are immutable once known.
func (s *Store) RecordVersionFacts(ctx context.Context, ecosystem string, versions map[string]time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO version_facts (ecosystem,name,version,published_at) VALUES (?,?,?,?)`)
	if err != nil {
		return err
	}
	for k, t := range versions {
		name, ver, ok := strings.Cut(k, "@")
		if !ok || t.IsZero() {
			continue
		}
		if _, err := stmt.ExecContext(ctx, ecosystem, name, ver, rfc(t)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RefObservation is one sighting of what a mutable reference pointed at.
type RefObservation struct {
	Resolved   string
	ObservedAt time.Time
}

// RefHistory returns every sighting of a reference, oldest first. Two different
// resolutions for the same ref mean the tag was re-pointed underneath you.
func (s *Store) RefHistory(ctx context.Context, refPURL string) ([]RefObservation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT resolved, observed_at FROM ref_obs WHERE ref_purl=? ORDER BY observed_at`, refPURL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RefObservation
	for rows.Next() {
		var o RefObservation
		var at string
		if err := rows.Scan(&o.Resolved, &at); err != nil {
			return nil, err
		}
		o.ObservedAt, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, o)
	}
	return out, rows.Err()
}

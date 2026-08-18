package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/project"
)

// Project is a registry row plus the two counts that make the list useful.
//
// It deliberately carries no risk grade. A grade is a function of known_at and
// is not materialised anywhere; printing one per row would mean a full report
// per project, and caching one would un-bitemporalise the design the same way a
// stored advisory count would.
type Project struct {
	Num       int64
	Key       string
	Kind      string
	Name      string
	CreatedAt time.Time
	Runs      int
	LastScan  time.Time
	Paths     []string
}

// ProjectQuery filters the registry. The zero value asks for everything.
type ProjectQuery struct {
	Num       int64  // 0 = any
	KeyPrefix string // --org: matched as a prefix of key
	Limit     int    // 0 = no limit
}

// upsertProject records the identity and the location, and returns the number to
// stamp on the run.
//
// It takes a *sql.Tx rather than opening its own, so a project cannot end up in
// the registry without the run that created it — which would show as a project
// with zero runs and no way to tell whether the scan failed or the write did.
func upsertProject(ctx context.Context, tx *sql.Tx, id project.Identity, path, now string) (int64, error) {
	// DO UPDATE rather than DO NOTHING so a renamed repository's display name
	// follows the rename. The key is what identity rests on; the name is only
	// ever printed.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO projects (key,kind,name,created_at) VALUES (?,?,?,?)
		 ON CONFLICT(key) DO UPDATE SET name=excluded.name`,
		id.Key, id.Kind, id.Name, now); err != nil {
		return 0, err
	}
	var num int64
	if err := tx.QueryRowContext(ctx,
		`SELECT num FROM projects WHERE key=?`, id.Key).Scan(&num); err != nil {
		return 0, err
	}
	if path != "" {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO project_paths (num,path,first_seen,last_seen) VALUES (?,?,?,?)
			 ON CONFLICT(num,path) DO UPDATE SET last_seen=excluded.last_seen`,
			num, path, now, now); err != nil {
			return 0, err
		}
	}
	return num, nil
}

// Projects lists the registry, most recently scanned first.
//
// SQLite sorts NULLs last under DESC, which puts never-scanned projects — only
// reachable by hand-editing the database — at the bottom rather than the top.
func (s *Store) Projects(ctx context.Context, q ProjectQuery) ([]Project, error) {
	var sb strings.Builder
	sb.WriteString(`
		SELECT p.num, p.key, p.kind, p.name, p.created_at,
		       (SELECT count(*)          FROM runs r  WHERE r.project_num = p.num),
		       (SELECT max(r.created_at) FROM runs r  WHERE r.project_num = p.num),
		       (SELECT group_concat(pp.path, char(10))
		          FROM project_paths pp WHERE pp.num = p.num)
		  FROM projects p WHERE 1=1`)
	var args []any
	if q.Num != 0 {
		sb.WriteString(` AND p.num = ?`)
		args = append(args, q.Num)
	}
	if q.KeyPrefix != "" {
		// LIKE with an escaped prefix: a key can legitimately contain '_', which
		// LIKE treats as a wildcard, so --org foo_bar must not match fooXbar.
		sb.WriteString(` AND p.key LIKE ? ESCAPE '\'`)
		args = append(args, likePrefix(q.KeyPrefix))
	}
	sb.WriteString(` ORDER BY 7 DESC, p.num ASC`)
	if q.Limit > 0 {
		sb.WriteString(` LIMIT ?`)
		args = append(args, q.Limit)
	}

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Project
	for rows.Next() {
		var p Project
		var created string
		var last, paths sql.NullString
		if err := rows.Scan(&p.Num, &p.Key, &p.Kind, &p.Name, &created, &p.Runs, &last, &paths); err != nil {
			return nil, err
		}
		p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if last.Valid {
			p.LastScan, _ = time.Parse(time.RFC3339Nano, last.String)
		}
		if paths.Valid && paths.String != "" {
			p.Paths = strings.Split(paths.String, "\n")
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// likePrefix escapes the two LIKE metacharacters so a prefix filter matches
// literally.
func likePrefix(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s) + "%"
}

// RunsForProject returns a project's runs, newest first.
func (s *Store) RunsForProject(ctx context.Context, num int64) ([]Run, error) {
	return s.queryRuns(ctx, `WHERE project_num = ?`, num)
}

// UnclaimedRuns returns runs belonging to no project.
//
// Every run written before v5 against a local directory is permanently here: the
// target was a bare basename and the path was never recorded, so there is
// nothing to adopt them by. They stay reachable by run id, and the list says so
// rather than pretending the store is smaller than it is.
func (s *Store) UnclaimedRuns(ctx context.Context) ([]Run, error) {
	return s.queryRuns(ctx, `WHERE project_num IS NULL`)
}

// DeleteProjects removes projects and, by cascade, their runs and every derived
// row beneath them. Unclaimed runs are untouched.
func (s *Store) DeleteProjects(ctx context.Context, nums []int64) error {
	if len(nums) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, n := range nums {
		if _, err := tx.ExecContext(ctx, `DELETE FROM projects WHERE num = ?`, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CountRowsForTest and CountRowsForRunForTest exist so cascade behaviour can be
// asserted without exporting the *sql.DB. A cascade that quietly stopped
// cascading would leave orphaned rows that no query ever selects, so the only
// way to see it is to count.
func (s *Store) CountRowsForTest(ctx context.Context, table string) (int, error) {
	return s.count(ctx, `SELECT count(*) FROM `+safeTable(table))
}

func (s *Store) CountRowsForRunForTest(ctx context.Context, table, runID string) (int, error) {
	return s.count(ctx, `SELECT count(*) FROM `+safeTable(table)+` WHERE run_id = ?`, runID)
}

func (s *Store) count(ctx context.Context, q string, args ...any) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// safeTable allows only the table names these helpers are meant for. A table
// name cannot be a bound parameter, so the alternative is string interpolation
// with no guard at all.
func safeTable(t string) string {
	switch t {
	case "nodes", "edges", "instances", "package_rollup", "version_rollup",
		"runs", "projects", "project_paths",
		"advisories", "advisory_affects", "packument_obs", "depsdev_obs",
		"scorecard_obs", "ref_obs", "version_facts":
		return t
	}
	panic("store: unknown table " + t)
}

// migrateProjects creates the v5 registry and adopts the runs that can be
// adopted.
//
// A run whose target is a clone URL carries its own identity, so 208 of the 211
// runs in the store this was written for become projects here. A run whose
// target is a bare basename does not: openLocal recorded filepath.Base and
// discarded the path, so there is nothing to adopt it by. Those stay unclaimed
// permanently. Synthesising a path from the basename would produce a registry
// pointing at directories nobody chose, which is worse than an honest gap.
func (s *Store) migrateProjects() error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS projects (
		   num        INTEGER PRIMARY KEY AUTOINCREMENT,
		   key        TEXT NOT NULL UNIQUE,
		   kind       TEXT NOT NULL CHECK (kind IN ('remote','local')),
		   name       TEXT NOT NULL,
		   created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS project_paths (
		   num        INTEGER NOT NULL REFERENCES projects(num) ON DELETE CASCADE,
		   path       TEXT NOT NULL,
		   first_seen TEXT NOT NULL,
		   last_seen  TEXT NOT NULL,
		   PRIMARY KEY (num, path))`,
		// SQLite permits ADD COLUMN with a REFERENCES clause only when the
		// default is NULL, which is what an omitted default gives — and NULL is
		// the right default here anyway.
		`ALTER TABLE runs ADD COLUMN project_num INTEGER REFERENCES projects(num) ON DELETE CASCADE`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}

	rows, err := s.db.Query(`SELECT DISTINCT target FROM runs`)
	if err != nil {
		return err
	}
	var targets []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, target := range targets {
		// Canonical rejects anything without a host, which is exactly the local
		// basenames. No SQL LIKE heuristic is needed or wanted.
		key, name, ok := project.Canonical(target)
		if !ok {
			continue
		}
		num, err := upsertProject(context.Background(), tx,
			project.Identity{Key: key, Kind: project.KindRemote, Name: name}, "", now)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE runs SET project_num = ? WHERE target = ?`, num, target); err != nil {
			return err
		}
	}
	return tx.Commit()
}

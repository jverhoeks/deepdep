package store_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/jverhoeks/deepdep/internal/store"
)

// v4db builds a database exactly as v4 left it, with the given run targets, and
// returns its path. Hand-rolled rather than produced by an older binary because
// the migration has to be testable from source alone.
func v4db(t *testing.T, targets ...string) string {
	t.Helper()
	schema, err := os.ReadFile(filepath.Join("testdata", "schema_v4.sql"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v4.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatal(err)
	}
	for i, target := range targets {
		if _, err := db.Exec(
			`INSERT INTO runs (run_id,target,ref,mode,as_of,known_at,tool_version,bounds_json,created_at)
			 VALUES (?,?,?,?,?,?,?,?,?)`,
			string(rune('a'+i)), target, "ref", "will",
			"2026-08-01T00:00:00Z", "2026-08-01T00:00:00Z", "0.1.0", "{}",
			"2026-08-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("PRAGMA user_version = 4"); err != nil {
		t.Fatal(err)
	}
	return path
}

// The store this change was written for holds 208 remote runs whose target IS
// the clone URL, and 3 local runs whose path was never recorded. The first group
// is adoptable and the second is not, and the migration has to get the split
// exactly right rather than merely not erroring.
func TestMigrationAdoptsRemoteRunsAndLeavesLocalOnesUnclaimed(t *testing.T) {
	path := v4db(t,
		"https://github.com/o/one.git",
		"https://github.com/o/one.git", // same repo, second run
		"git@github.com:o/two.git",
		"data-platform", // a local scan: basename only, unadoptable
		"sqlengine",
	)

	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("got %d projects, want 2 (one per distinct remote)", len(ps))
	}
	byKey := map[string]store.Project{}
	for _, p := range ps {
		byKey[p.Key] = p
	}
	if got := byKey["github.com/o/one"].Runs; got != 2 {
		t.Errorf("github.com/o/one has %d runs, want 2", got)
	}
	if got := byKey["github.com/o/two"].Runs; got != 1 {
		t.Errorf("github.com/o/two has %d runs, want 1", got)
	}
	for _, p := range ps {
		if p.Kind != "remote" {
			t.Errorf("%s kind = %q, want remote", p.Key, p.Kind)
		}
		if len(p.Paths) != 0 {
			t.Errorf("%s paths = %v, want none — no path is recoverable from a clone URL", p.Key, p.Paths)
		}
	}

	un, err := s.UnclaimedRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(un) != 2 {
		t.Fatalf("got %d unclaimed runs, want 2 (data-platform, sqlengine)", len(un))
	}
}

// Opening twice must not double-adopt. Migration is gated on user_version, but
// the adoption is INSERT-shaped and a regression here would silently duplicate
// every project on the second open.
func TestMigrationIsIdempotent(t *testing.T) {
	path := v4db(t, "https://github.com/o/one.git")
	for i := 0; i < 2; i++ {
		s, err := store.Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i+1, err)
		}
		ps, err := s.Projects(context.Background(), store.ProjectQuery{})
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
		if len(ps) != 1 {
			t.Fatalf("open %d: got %d projects, want 1", i+1, len(ps))
		}
	}
}

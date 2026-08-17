package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// busy_timeout and foreign_keys are per-CONNECTION settings, and *sql.DB is a
// POOL. Setting them with one db.Exec configures whichever connection that call
// happened to borrow and leaves every other connection on the defaults —
// busy_timeout 0, foreign keys off. An org scan writing several repositories
// into one database then gets SQLITE_BUSY the moment two writers overlap, after
// all the cloning and registry traffic is already spent.
//
// This is an internal test because it has to inspect the pool itself: asking the
// Store would just route through whichever connection happened to be free.
func TestPragmasApplyToEveryPooledConnection(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	const conns = 8
	bad := make([]string, conns)
	var wg sync.WaitGroup
	// Every connection is held for the duration, so the pool is forced to open
	// fresh ones rather than handing the same configured connection back.
	start := make(chan struct{})
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			c, err := s.db.Conn(ctx)
			if err != nil {
				bad[i] = err.Error()
				return
			}
			defer c.Close()
			<-start

			var busy, fk int
			if err := c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
				bad[i] = err.Error()
				return
			}
			if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
				bad[i] = err.Error()
				return
			}
			if busy == 0 || fk != 1 {
				bad[i] = fmt.Sprintf("busy_timeout=%d foreign_keys=%d", busy, fk)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for i, b := range bad {
		if b != "" {
			t.Errorf("pooled connection %d came back unconfigured: %s", i, b)
		}
	}
}

// A --db path is user input and SQLite's URI form gives '?' and '#' meaning, so
// they have to survive the round trip into a DSN rather than silently truncate
// the path or be read as parameters.
func TestDSNKeepsAwkwardPathsIntact(t *testing.T) {
	// Each name is a DIRECTORY component, so a DSN that truncated at the
	// character would land the database somewhere else entirely rather than fail.
	for _, awkward := range []string{"plain", "why? not", "sharp#end", "100%", "a&b=c"} {
		full := filepath.Join(t.TempDir(), awkward, "d.db")
		s, err := Open(full)
		if err != nil {
			t.Errorf("Open(%q): %v", full, err)
			continue
		}
		s.Close()
		if _, err := os.Stat(full); err != nil {
			t.Errorf("Open(%q) reported success but wrote nothing there: %v", full, err)
		}
	}
}

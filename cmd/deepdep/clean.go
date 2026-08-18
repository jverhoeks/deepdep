package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jverhoeks/deepdep/internal/store"
)

// cleanCmd prunes runs and, with --purge, the projects themselves.
//
// It refuses an empty selection. Every re-scan appends a run row — newRunID
// mixes in UnixNano — so the store grows monotonically and this command will be
// reached for often; the bare form has to be inert.
func cleanCmd(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("clean", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	var (
		dbPath    = fs.String("db", defaultDBPath(), "")
		ref       = fs.String("project", "", "limit to one project (number, name or path substring)")
		keep      = fs.Int("keep", -1, "keep the newest N runs per project")
		olderThan = fs.Duration("older-than", 0, "delete runs created before now minus this")
		unclaimed = fs.Bool("unclaimed", false, "delete runs belonging to no project")
		purge     = fs.Bool("purge", false, "delete the project rows too, not just their runs")
		vacuum    = fs.Bool("vacuum", false, "reclaim file space afterwards (rewrites the database)")
		dryRun    = fs.Bool("dry-run", false, "print what would go, delete nothing")
		yes       = fs.Bool("yes", false, "skip the confirmation prompt")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Checked BEFORE opening the store, so a mistyped invocation does not create
	// a database file as a side effect of being rejected.
	if *keep < 0 && *olderThan == 0 && !*unclaimed && !*purge {
		return nil, fmt.Errorf(
			"clean selects nothing by default, on purpose.\n" +
				"Choose what goes: --keep N (newest N runs per project), --older-than D,\n" +
				"--unclaimed (runs with no project), or --purge (a whole project, with --project).")
	}
	if *purge && *ref == "" {
		return nil, fmt.Errorf("--purge needs --project: deleting every project in the store is not a default")
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx := context.Background()

	q := store.PruneQuery{Keep: *keep, Unclaimed: *unclaimed, Purge: *purge}
	if *olderThan > 0 {
		q.OlderThan = time.Now().Add(-*olderThan)
	}
	if *ref != "" {
		num, err := projectNumOf(ctx, db, *ref)
		if err != nil {
			return nil, err
		}
		q.Num = num
	}

	plan, err := db.PlanPrune(ctx, q)
	if err != nil {
		return nil, err
	}
	obs, err := db.ObservationCounts(ctx)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "WOULD DELETE\n  %d runs", len(plan.Runs))
	if len(plan.Projects) > 0 {
		fmt.Fprintf(&b, "\n  %d projects", len(plan.Projects))
	}
	fmt.Fprintf(&b, "\n  keeping %d runs\n", plan.KeptRuns)
	fmt.Fprintf(&b, "\nPRESERVED  (not run-scoped, and not regenerable)\n")
	for _, t := range sortedKeys(obs) {
		fmt.Fprintf(&b, "  %-18s %8d\n", t, obs[t])
	}
	fmt.Fprintf(&b, "  deps.dev serves only the current scorecard, so a deleted observation\n")
	fmt.Fprintf(&b, "  is the only copy. clean deletes from none of these tables.\n")

	if *dryRun {
		fmt.Fprintf(&b, "\n--dry-run: nothing was deleted.\n")
		return b.Bytes(), nil
	}
	if len(plan.Runs) == 0 && len(plan.Projects) == 0 {
		fmt.Fprintf(&b, "\nNothing selected.\n")
		return b.Bytes(), nil
	}
	if !*yes && !confirm(b.String()) {
		return []byte("cancelled.\n"), nil
	}

	if err := db.ApplyPrune(ctx, plan); err != nil {
		return nil, err
	}
	fmt.Fprintf(&b, "\nDeleted %d runs", len(plan.Runs))
	if len(plan.Projects) > 0 {
		fmt.Fprintf(&b, " and %d projects", len(plan.Projects))
	}
	fmt.Fprintf(&b, ".\n")

	if *vacuum {
		fmt.Fprintf(os.Stderr, "vacuuming (rewrites the whole database)...\n")
		if err := db.Vacuum(ctx); err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "Vacuumed.\n")
	}

	after, err := db.ObservationCounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range sortedKeys(obs) {
		if after[t] != obs[t] {
			// Belt and braces on the guarantee the tests assert. If this ever
			// fires, something deleted irreplaceable observations.
			return nil, fmt.Errorf("BUG: %s went from %d to %d rows during clean", t, obs[t], after[t])
		}
	}
	return b.Bytes(), nil
}

// projectNumOf resolves --project through the same rules as a reporting ref, so
// one spelling works everywhere.
func projectNumOf(ctx context.Context, db *store.Store, ref string) (int64, error) {
	runID, err := resolveRef(ctx, db, ref)
	if err != nil {
		return 0, err
	}
	ps, err := db.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		return 0, err
	}
	for _, p := range ps {
		runs, err := db.RunsForProject(ctx, p.Num)
		if err != nil {
			return 0, err
		}
		for _, r := range runs {
			if r.RunID == runID {
				return p.Num, nil
			}
		}
	}
	return 0, fmt.Errorf("%q resolved to run %s, which belongs to no project", ref, runID)
}

// confirm asks before destroying anything, and treats anything other than an
// explicit yes as a refusal — a scripted clean must opt in with --yes.
//
// The two non-interactive cases are distinguished because they look different to
// Stat: a pipe is not a character device, but /dev/null is, so redirecting from
// it reaches the prompt and then reads EOF. Both must refuse, and both deserve
// the hint rather than a bare "cancelled".
func confirm(preview string) bool {
	noTerminal := func() bool {
		fmt.Fprintln(os.Stderr, "no answer on stdin: re-run with --yes to confirm, or --dry-run to preview.")
		return false
	}

	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, preview)
		return noTerminal()
	}
	fmt.Fprint(os.Stderr, preview, "\nProceed? [y/N] ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr)
		return noTerminal()
	}
	return len(line) > 0 && (line[0] == 'y' || line[0] == 'Y')
}

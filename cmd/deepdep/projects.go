package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/jverhoeks/deepdep/internal/store"
)

// projectsCmd lists the registry, or one project's detail.
//
// The default is capped. 208 of the 209 projects in the store this was written
// for arrived from `org` scans — WriteRun upserts, so `org` populates the
// registry as a side effect — and dumping all of them would recreate the
// friction the registry exists to remove.
func projectsCmd(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("projects", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	var (
		dbPath = fs.String("db", defaultDBPath(), "")
		format = fs.String("format", "text", "text|json")
		limit  = fs.Int("limit", 25, "rows before truncating; 0 for all")
		all    = fs.Bool("all", false, "no limit")
		org    = fs.String("org", "", "only projects whose key starts with this (e.g. github.com/expressjs)")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx := context.Background()

	if fs.NArg() == 1 {
		return oneProject(ctx, db, fs.Arg(0), *format)
	}

	total, err := db.Projects(ctx, store.ProjectQuery{KeyPrefix: *org})
	if err != nil {
		return nil, err
	}
	shown := total
	truncated := 0
	if !*all && *limit > 0 && len(total) > *limit {
		shown = total[:*limit]
		truncated = len(total)
	}
	// Unclaimed runs belong to no project, so they cannot match a project
	// filter. Listing them under --org would offer them as results of a query
	// they were never candidates for.
	var un []store.Run
	if *org == "" {
		if un, err = db.UnclaimedRuns(ctx); err != nil {
			return nil, err
		}
	}

	if *format == "json" {
		return jsonBytes(map[string]any{
			"projects": shown, "total": len(total), "unclaimed_runs": un,
			"filtered": *org != "",
		})
	}
	return renderProjects(shown, un, truncated, *org), nil
}

// oneProject prints a project's locations and run history.
func oneProject(ctx context.Context, db *store.Store, ref, format string) ([]byte, error) {
	ps, err := db.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		return nil, err
	}
	var found *store.Project
	for i := range ps {
		if fmt.Sprint(ps[i].Num) == ref || ps[i].Name == ref || ps[i].Key == ref {
			found = &ps[i]
			break
		}
	}
	if found == nil {
		// Reuse the resolver so one ref spelling works everywhere, and so the
		// ambiguity message is written once.
		runID, rerr := resolveRef(ctx, db, ref)
		if rerr != nil {
			return nil, rerr
		}
		// Stop at the match. Continuing would run one query per remaining
		// project, and with 208 of them that is 207 queries for an answer
		// already in hand.
		for i := range ps {
			runs, err := db.RunsForProject(ctx, ps[i].Num)
			if err != nil {
				return nil, err
			}
			for _, r := range runs {
				if r.RunID == runID {
					found = &ps[i]
					break
				}
			}
			if found != nil {
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("run %s belongs to no project", runID)
		}
	}

	runs, err := db.RunsForProject(ctx, found.Num)
	if err != nil {
		return nil, err
	}
	if format == "json" {
		return jsonBytes(map[string]any{"project": found, "runs": runs})
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "PROJECT %d  %s\n", found.Num, found.Key)
	fmt.Fprintf(&b, "kind %s · %d runs\n", found.Kind, len(runs))
	if len(found.Paths) == 0 {
		fmt.Fprintf(&b, "\nLOCATIONS\n  none recorded\n")
	} else {
		fmt.Fprintf(&b, "\nLOCATIONS\n")
		for _, p := range found.Paths {
			fmt.Fprintf(&b, "  %s\n", p)
		}
	}
	fmt.Fprintf(&b, "\nRUNS\n")
	for _, r := range runs {
		fmt.Fprintf(&b, "  %s  %s  %-4s  %s\n",
			r.RunID, r.CreatedAt.Format("2006-01-02 15:04"), r.Mode, short(r.Ref))
	}
	fmt.Fprintf(&b, "\n`deepdep report %d` reports the newest.\n", found.Num)
	return b.Bytes(), nil
}

// renderProjects draws the list. truncated is the untruncated total, or 0;
// filter is the --org prefix in force, or "".
func renderProjects(ps []store.Project, unclaimed []store.Run, truncated int, filter string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, " %4s %-44s %5s  %-12s %s\n", "NUM", "NAME", "RUNS", "LAST SCAN", "LOCATIONS")
	for _, p := range ps {
		fmt.Fprintf(&b, " %4d %-44s %5d  %-12s %s\n",
			p.Num, truncate(p.Key, 44), p.Runs, stamp(p.LastScan), locations(p.Paths))
	}
	if len(ps) == 0 {
		// An empty registry and an over-narrow filter are different problems and
		// the fix for one is no use for the other.
		if filter != "" {
			fmt.Fprintf(&b, " no project key starts with %q\n", filter)
		} else {
			fmt.Fprintf(&b, " no projects yet — `deepdep scan <dir>` creates one\n")
		}
	}
	if truncated > 0 {
		fmt.Fprintf(&b, "\n %d of %d shown — --all for the rest, --org <host/owner> to filter\n",
			len(ps), truncated)
	}
	if len(unclaimed) > 0 {
		// Counted and named, never dropped: a list that hid these would read as
		// a smaller store than the one on disk.
		fmt.Fprintf(&b, "\n %d unclaimed runs — scanned before the registry existed, so their\n", len(unclaimed))
		fmt.Fprintf(&b, " directory was never recorded. Reachable by run id; re-scan to adopt.\n")
		for i, r := range unclaimed {
			if i == 5 {
				fmt.Fprintf(&b, "   ... %d more\n", len(unclaimed)-5)
				break
			}
			fmt.Fprintf(&b, "   %s  %s\n", r.RunID, truncate(r.Target, 44))
		}
	}
	return b.Bytes()
}

func locations(paths []string) string {
	switch len(paths) {
	case 0:
		return "—"
	case 1:
		return paths[0]
	default:
		return fmt.Sprintf("%s (+%d more)", paths[0], len(paths)-1)
	}
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02")
}

func jsonBytes(v any) ([]byte, error) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

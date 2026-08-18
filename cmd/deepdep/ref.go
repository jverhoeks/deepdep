package main

import (
	"context"
	"flag"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jverhoeks/deepdep/internal/store"
)

// runID16 matches the shape newRunID produces: sha256 truncated to 16 hex chars.
var runID16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

// resolveRef turns whatever the user typed into a run id.
//
// The order is deliberate and the first match wins: run id, project number,
// exact project name, then a unique substring of a name or a recorded path. An
// empty ref stays empty, because every reporting command already reads that as
// "the newest run".
//
// Ambiguity is an error listing the candidates. Guessing which of two
// repositories to report on is precisely the failure the project registry exists
// to remove, and a confident wrong report is worse than a question.
func resolveRef(ctx context.Context, db *store.Store, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil
	}

	if runID16.MatchString(ref) {
		runs, err := db.Runs(ctx, 100000)
		if err != nil {
			return "", err
		}
		for _, r := range runs {
			if r.RunID == ref {
				return ref, nil
			}
		}
		// Fall through: a 16-hex string is also a legal project name.
	}

	if n, err := strconv.ParseInt(ref, 10, 64); err == nil {
		ps, err := db.Projects(ctx, store.ProjectQuery{Num: n})
		if err != nil {
			return "", err
		}
		if len(ps) == 0 {
			return "", fmt.Errorf("no project %d — `deepdep projects` lists them", n)
		}
		return latestRunOf(ctx, db, ps[0])
	}

	all, err := db.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		return "", err
	}

	for _, p := range all {
		if p.Name == ref || p.Key == ref {
			return latestRunOf(ctx, db, p)
		}
	}

	needle := strings.ToLower(ref)
	var hits []store.Project
	for _, p := range all {
		if strings.Contains(strings.ToLower(p.Key), needle) ||
			strings.Contains(strings.ToLower(p.Name), needle) {
			hits = append(hits, p)
			continue
		}
		for _, path := range p.Paths {
			if strings.Contains(strings.ToLower(path), needle) {
				hits = append(hits, p)
				break
			}
		}
	}

	switch len(hits) {
	case 0:
		return "", fmt.Errorf("no run or project matching %q — `deepdep projects` lists them", ref)
	case 1:
		return latestRunOf(ctx, db, hits[0])
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "%q matches %d projects:\n", ref, len(hits))
		for _, p := range hits {
			fmt.Fprintf(&b, "  %-4d %s\n", p.Num, p.Key)
		}
		b.WriteString("be more specific, or use the number")
		return "", fmt.Errorf("%s", b.String())
	}
}

// latestRunOf is the project -> newest run step.
//
// An empty run list is an error rather than a fallthrough to the newest run in
// the store: reporting on some other repository because this one has no runs
// would be the org-scan bug that latestRunFor was written to fix, back again.
func latestRunOf(ctx context.Context, db *store.Store, p store.Project) (string, error) {
	runs, err := db.RunsForProject(ctx, p.Num)
	if err != nil {
		return "", err
	}
	if len(runs) == 0 {
		return "", fmt.Errorf("project %d (%s) has no stored runs — `deepdep scan` it first", p.Num, p.Key)
	}
	return runs[0].RunID, nil // RunsForProject is newest-first
}

// firstArg is the optional positional ref, or "" for none.
func firstArg(fs *flag.FlagSet) string {
	if fs.NArg() >= 1 {
		return fs.Arg(0)
	}
	return ""
}

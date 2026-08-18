package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/advisory"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
	"github.com/jverhoeks/deepdep/internal/supply"
)

// riskCmd reports supply-chain posture from deps.dev.
//
// Distinct from `audit`, which asks whether a version has a known flaw today.
// This asks how the code got here and what a future compromise would cost:
// a deprecated package nobody will patch, a release with no provenance, a repo
// that merges without review. Those are not vulnerabilities and must not be
// counted as such — hence a separate command with its own vocabulary.
func riskCmd(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("risk", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	var (
		dbPath     = fs.String("db", defaultDBPath(), "")
		state      = fs.String("state", "installed", "installed|possible|unknown|all")
		format     = fs.String("format", "text", "")
		base       = fs.String("depsdev", "https://api.deps.dev", "")
		osvBase    = fs.String("osv", "https://api.osv.dev", "")
		crossCheck = fs.Bool("cross-check", true, "compare deps.dev advisories against OSV")
		signal     = fs.String("signal", "", "show only packages carrying this signal code")
		limit      = fs.Int("limit", 25, "rows per signal section; 0 for all")
		knownAtStr = fs.String("known-at", "", "")
		timeout    = fs.Duration("timeout", 15*time.Minute, "")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// deps.dev serves only the newest scorecard for a project: no history
	// endpoint, no as-of parameter. Accepting --known-at and quietly returning
	// today's posture would be a record-and-ignore audit flag, which the design
	// forbids. Refuse, and point at the observations that make it answerable.
	if *knownAtStr != "" {
		return nil, fmt.Errorf(
			"--known-at is not answerable for supply-chain posture: deps.dev serves only " +
				"the current scorecard, and scorecard history is not reconstructible.\n" +
				"Past runs are queryable from scorecard_obs / depsdev_obs, which every " +
				"risk run appends to. `deepdep audit --known-at` does work — advisory " +
				"existence at an instant IS reconstructible from OSV published/withdrawn.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	db, err := store.Open(*dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// A ref is a run id, a project number, a project name, or a unique
	// substring of either. Resolution happens here rather than in the store so
	// the ambiguity message is written once.
	runID, err := resolveRef(ctx, db, firstArg(fs))
	if err != nil {
		return nil, err
	}
	// "all" is an empty filter, matching `audit` and `report`. Without it a
	// Dockerfile-only repo has no auditable state at all: with no lockfile there
	// is no effective resolution, so everything lands in `unknown`.
	want := rollup.State(*state)
	if *state == "all" {
		want = ""
	}
	targets, meta, err := db.AuditTargets(ctx, runID, want)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("run %s resolved no package versions in state %q.\n"+
			"With no lockfile an offline scan resolves nothing; re-scan online, or\n"+
			"use `deepdep report` which describes the coverage gap instead of failing",
			meta.RunID, *state)
	}

	client := supply.New(*base, nil)
	facts, err := client.Facts(ctx, targets)
	if err != nil {
		return nil, err
	}

	repos := make([]string, 0, len(facts))
	for _, f := range facts {
		repos = append(repos, f.SourceRepo)
	}
	projects, unreachable, err := client.Projects(ctx, repos)
	if err != nil {
		return nil, err
	}
	// A posture lookup that failed leaves that project unknown rather than
	// losing the whole report, but the loss is SAID rather than absorbed:
	// silently treating unreachable as unremarkable would read as "nothing
	// upstream is unmaintained".
	if unreachable > 0 {
		fmt.Fprintf(os.Stderr, "deepdep: %d of %d upstream projects were unreachable; their posture is unknown\n",
			unreachable, len(repos))
	}

	// Recording is best-effort — losing the archive must not lose the report the
	// user asked for — but it is NOT silent. A scorecard that failed to record
	// is gone for good, so the failure is surfaced, not swallowed.
	observedAt := time.Now().UTC()
	recErr := db.RecordSupply(ctx, facts, projects, observedAt)

	assessments := supply.Assess(facts, projects)

	var cross *crossCheckResult
	if *crossCheck {
		cross, err = compareAdvisories(ctx, *osvBase, targets, facts)
		if err != nil {
			return nil, err
		}
	}

	if *format == "json" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", " ")
		if err := enc.Encode(map[string]any{
			"run_id": meta.RunID, "ref": meta.Ref, "mode": meta.Mode,
			"state": *state, "checked": len(targets),
			"observed_at":     observedAt,
			"knowledge_basis": "current-records",
			"assessments":     assessments,
			"projects":        projects,
			"cross_check":     cross,
			"record_error":    errText(recErr),
		}); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return riskReport(meta, *state, observedAt, targets, facts, projects,
		assessments, cross, recErr, *signal, *limit), nil
}

// ---- OSV cross-check -----------------------------------------------------

type crossCheckResult struct {
	OSVOnly     []string `json:"osv_only,omitempty"`
	DepsDevOnly []string `json:"depsdev_only,omitempty"`
	Agreed      int      `json:"agreed"`
}

// compareAdvisories contrasts two independent matchers over the same inputs.
//
// deps.dev and OSV both draw on the OSV database, but each applies its own
// matching. A disagreement is not a second opinion about severity — it is a
// lead to run down, and the only way to notice that a clean report is clean
// because nothing matched rather than because nothing is wrong.
//
// Not every disagreement is a bug in one side. The known benign class is
// OSS-Fuzz: deps.dev attaches records like OSV-2022-485 (pkg:generic/duckdb,
// a GIT commit range over the C++ source) to the PyPI package that shares an
// upstream project, while an OSV purl query correctly does not — a commit range
// says nothing about which wheel shipped it. Report the delta; let a human
// classify it.
func compareAdvisories(ctx context.Context, osvBase string, targets []graph.NodeID,
	facts []supply.Fact) (*crossCheckResult, error) {

	// knownAt must match what `audit` uses (it defaults to now), not the zero
	// time. advisory.Check skips the whole bitemporal filter when knownAt is
	// zero, so a WITHDRAWN advisory would come back here and be reported as an
	// osv-only disagreement that audit never showed — a delta manufactured by
	// asking a different question, which is precisely what this compares against.
	findings, err := advisory.New(osvBase, nil).Check(ctx, targets, time.Now().UTC())
	if err != nil {
		return nil, err
	}

	osv := map[string]bool{}
	for _, f := range findings {
		osv[string(f.NodeID)+" "+f.Advisory.ID] = true
	}
	dd := map[string]bool{}
	for _, f := range facts {
		for _, id := range f.AdvisoryIDs {
			dd[string(f.NodeID)+" "+id] = true
		}
	}

	out := &crossCheckResult{}
	for k := range osv {
		if dd[k] {
			out.Agreed++
		} else {
			out.OSVOnly = append(out.OSVOnly, k)
		}
	}
	for k := range dd {
		if !osv[k] {
			out.DepsDevOnly = append(out.DepsDevOnly, k)
		}
	}
	sort.Strings(out.OSVOnly)
	sort.Strings(out.DepsDevOnly)
	return out, nil
}

// ---- report --------------------------------------------------------------

func riskReport(meta store.Run, state string, observedAt time.Time,
	targets []graph.NodeID, facts []supply.Fact, projects map[string]supply.Project,
	assessments []supply.Assessment, cross *crossCheckResult, recErr error,
	only string, limit int) []byte {

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "run %s  ref %s  mode %s\n", meta.RunID, short(meta.Ref), meta.Mode)
	fmt.Fprintf(&buf, "observed %s   knowledge_basis current-records\n",
		observedAt.Format("2006-01-02"))
	fmt.Fprintf(&buf, "checked %d %s package versions against deps.dev\n", len(targets), state)
	if recErr != nil {
		fmt.Fprintf(&buf, "WARNING: observations not recorded (%v); today's scorecards "+
			"are not retrievable later\n", recErr)
	}
	fmt.Fprintln(&buf)

	known := 0
	for _, f := range facts {
		if f.Known {
			known++
		}
	}
	fmt.Fprintf(&buf, "%d resolved in deps.dev, %d unlisted; %d distinct source projects, %d with a scorecard\n\n",
		known, len(facts)-known, len(projects), countScored(projects))

	// Group by signal so the report reads as "here is every deprecated package",
	// not as a per-package wall that buries the one class you can act on.
	bySignal := map[string][]supply.Assessment{}
	detail := map[string]map[graph.NodeID]string{}
	// Scorecard's own finding, kept per SIGNAL rather than per package: the
	// evidence is a property of the upstream project, and forty packages from
	// one repo would otherwise print the same workflow line forty times.
	evidence := map[string]map[string][]string{}
	repos := map[string]map[string]bool{}
	for _, a := range assessments {
		for _, s := range a.Signals {
			bySignal[s.Code] = append(bySignal[s.Code], a)
			if detail[s.Code] == nil {
				detail[s.Code] = map[graph.NodeID]string{}
				repos[s.Code] = map[string]bool{}
			}
			detail[s.Code][a.NodeID] = s.Detail
			if a.SourceRepo != "" {
				repos[s.Code][a.SourceRepo] = true
				if len(s.Evidence) > 0 {
					if evidence[s.Code] == nil {
						evidence[s.Code] = map[string][]string{}
					}
					evidence[s.Code][a.SourceRepo] = s.Evidence
				}
			}
		}
	}

	// Both counts, always. A Scorecard signal is a property of a PROJECT, and
	// rollup alone ships 25 per-platform binary packages from one repo — quoting
	// only the version count turns three upstream problems into twenty-eight and
	// makes the report read as far worse than it is.
	fmt.Fprintf(&buf, "signal summary — versions / distinct source projects\n")
	fmt.Fprintf(&buf, "(a package may carry several signals; nothing is summed)\n")
	for _, code := range supply.Codes() {
		if n := len(bySignal[code]); n > 0 {
			// Signals that fire BECAUSE there is no project print a dash: a zero
			// in the project column reads as a counting bug, not as "n/a".
			proj := "    -"
			if p := len(repos[code]); p > 0 {
				proj = fmt.Sprintf("%5d", p)
			}
			fmt.Fprintf(&buf, "  %-24s %5d %s\n", code, n, proj)
		}
	}

	codes := supply.Codes()
	if only != "" {
		codes = []string{only}
	}
	for _, code := range codes {
		list := bySignal[code]
		if len(list) == 0 {
			continue
		}
		if p := len(repos[code]); p > 0 {
			fmt.Fprintf(&buf, "\n%s — %d %s across %d projects\n",
				code, len(list), plural(len(list), "version"), p)
		} else {
			fmt.Fprintf(&buf, "\n%s — %d %s\n",
				code, len(list), plural(len(list), "version"))
		}
		sort.Slice(list, func(i, j int) bool { return list[i].NodeID < list[j].NodeID })
		shown := list
		if limit > 0 && len(shown) > limit {
			shown = shown[:limit]
		}
		for _, a := range shown {
			d := detail[code][a.NodeID]
			fmt.Fprintf(&buf, "  %-52s %s\n", label(a.NodeID), truncate(d, 68))
		}
		if len(shown) < len(list) {
			// Never truncate silently: an omitted tail reads as full coverage.
			fmt.Fprintf(&buf, "  ... %d more (--limit 0 for all, --signal %s to focus)\n",
				len(list)-len(shown), code)
		}
		// WHY, in the upstream scanner's own words, once per project.
		if ev := evidence[code]; len(ev) > 0 {
			names := make([]string, 0, len(ev))
			for r := range ev {
				names = append(names, r)
			}
			sort.Strings(names)
			fmt.Fprintf(&buf, "  why:\n")
			for i, r := range names {
				if limit > 0 && i >= limit {
					fmt.Fprintf(&buf, "    ... %d more projects\n", len(names)-i)
					break
				}
				fmt.Fprintf(&buf, "    %s\n", r)
				for j, w := range ev[r] {
					if j >= 3 {
						fmt.Fprintf(&buf, "      ... %d more\n", len(ev[r])-j)
						break
					}
					fmt.Fprintf(&buf, "      %s\n", elideMiddle(w, 108))
				}
			}
		}
	}

	if cross != nil {
		fmt.Fprintf(&buf, "\nadvisory cross-check (deps.dev vs OSV, same %d inputs, same known-at)\n", len(targets))
		fmt.Fprintf(&buf, "  agreed          %d\n", cross.Agreed)
		fmt.Fprintf(&buf, "  only in OSV     %d\n", len(cross.OSVOnly))
		fmt.Fprintf(&buf, "  only in deps.dev %d\n", len(cross.DepsDevOnly))
		for _, k := range cross.OSVOnly {
			fmt.Fprintf(&buf, "    osv-only      %s\n", strings.TrimPrefix(k, "pkg:"))
		}
		for _, k := range cross.DepsDevOnly {
			fmt.Fprintf(&buf, "    depsdev-only  %s\n", strings.TrimPrefix(k, "pkg:"))
		}
		if len(cross.OSVOnly)+len(cross.DepsDevOnly) > 0 {
			fmt.Fprintf(&buf, "  a delta is a lead, not a verdict: the common benign case is an\n")
			fmt.Fprintf(&buf, "  OSS-Fuzz record attached to an upstream project by a GIT commit\n")
			fmt.Fprintf(&buf, "  range, which says nothing about which published artifact shipped it\n")
		}
	}
	return buf.Bytes()
}

func countScored(projects map[string]supply.Project) int {
	n := 0
	for _, p := range projects {
		if p.HasScorecard {
			n++
		}
	}
	return n
}

// label renders a PURL for humans: percent-encoded npm scopes are correct
// identity but unreadable in a report.
func label(id graph.NodeID) string {
	s := strings.TrimPrefix(string(id), "pkg:")
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// elideMiddle shortens a line from the MIDDLE, because the actionable half of a
// Scorecard warning is the file:line at the END. Trailing truncation removed
// exactly the part a reader needs to go and look.
func elideMiddle(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	keepTail := n / 2
	keepHead := n - keepTail - 1
	return s[:keepHead] + "…" + s[len(s)-keepTail:]
}

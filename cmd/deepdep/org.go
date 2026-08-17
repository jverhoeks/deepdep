package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jverhoeks/deepdep/internal/forge"
)

// orgCmd scans every repository an organisation owns and reports the fleet.
//
// It is the same scan and the same report, run many times and then added up —
// deliberately, rather than as a second analysis path. A fleet number that
// disagreed with the per-repository number underneath it would be worse than no
// fleet number, and the only way to guarantee they agree is for one to be built
// out of the other.
//
// Two properties matter more than speed here:
//
//   - It is RESUMABLE. Scanning fifty repositories is tens of minutes and a
//     transient clone failure is a certainty, so a repository already in the
//     store is skipped unless --refresh is given.
//   - A failure is REPORTED, never dropped. A fleet summary that silently
//     omitted the repository whose clone timed out would read as a smaller,
//     cleaner organisation than the one that exists.
func orgCmd(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("org", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	var (
		dbPath      = fs.String("db", defaultDBPath(), "")
		cacheDir    = fs.String("cache-dir", defaultCacheDir(), "")
		format      = fs.String("format", "text", "text|json")
		mode        = fs.String("mode", "will", "will|can")
		workers     = fs.Int("workers", 4, "repositories scanned in parallel")
		limit       = fs.Int("limit", 0, "stop after N repositories (0 = all)")
		timeout     = fs.Duration("timeout", 5*time.Minute, "per-repository expansion bound")
		forks       = fs.Bool("forks", false, "include forks")
		archived    = fs.Bool("archived", false, "include archived repositories")
		refresh     = fs.Bool("refresh", false, "re-scan repositories already in the store")
		detail      = fs.Int("detail", 10, "repositories to show findings for (0 = none)")
		noPosture   = fs.Bool("no-posture", false, "skip deps.dev/Scorecard lookups")
		apiBase     = fs.String("api", "https://api.github.com", "")
		concurrency = fs.Int("concurrency", 32, "registry fetch workers per scan")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 1 {
		return nil, errors.New("usage: deepdep org [flags] <organisation-or-user>")
	}
	org := fs.Arg(0)

	ctx := context.Background()
	client := forge.New(*apiBase, forge.Token(), nil)
	repos, err := client.Org(ctx, org, forge.Options{
		IncludeForks: *forks, IncludeArchived: *archived, Limit: *limit,
	})
	if err != nil {
		return nil, err
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("no repositories to scan for %q", org)
	}
	fmt.Fprintf(os.Stderr, "%s: %d repositories\n", org, len(repos))

	done, err := alreadyScanned(ctx, *dbPath)
	if err != nil {
		return nil, err
	}

	results := make([]orgRepo, len(repos))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *workers))
	for i, r := range repos {
		i, r := i, r
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = scanAndReport(r, scanOpts{
				db: *dbPath, cache: *cacheDir, mode: *mode, timeout: *timeout,
				concurrency: *concurrency, posture: !*noPosture,
				skip: !*refresh && done[r.CloneURL],
			})
			fmt.Fprintf(os.Stderr, "  %-46s %s\n", r.FullName, results[i].status())
		}()
	}
	wg.Wait()

	doc := buildOrgReport(org, results)
	if *format == "json" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", " ")
		if err := enc.Encode(doc); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return renderOrg(doc, *detail), nil
}

type scanOpts struct {
	db, cache, mode string
	timeout         time.Duration
	concurrency     int
	posture, skip   bool
}

// orgRepo is one repository's outcome. Err is kept rather than discarded: the
// funnel in the summary is only honest if a failure is countable.
type orgRepo struct {
	Repo   forge.Repo `json:"repo"`
	Report *reportDoc `json:"report,omitempty"`
	Err    string     `json:"error,omitempty"`
	Cached bool       `json:"cached,omitempty"`
}

func (r orgRepo) status() string {
	switch {
	case r.Err != "":
		return "FAILED  " + truncate(r.Err, 60)
	case r.Report == nil:
		return "no report"
	case r.Report.Score.Suppressed:
		return "not graded  (" + r.found() + ")"
	default:
		return fmt.Sprintf("%s  %d/100  (%s)",
			r.Report.Score.Grade, r.Report.Score.Score, r.found())
	}
}

// found describes what the scan actually saw.
//
// Reporting only a package count read as "nothing here" for whole classes of
// repository that have plenty: a Terraform module or a GitHub Action has no
// registry packages at all, so `(0 packages)` was the line printed for a repo
// with a dozen pinned actions and a provider lockfile. Counting only the thing
// this tool happens to grade on, and calling that the whole finding, is the
// same mistake as calling an ungraded repository a clean one.
func (r orgRepo) found() string {
	parts := []string{fmt.Sprintf("%d packages", r.Report.Checked)}
	if r.Report.ActionsChecked > 0 {
		parts = append(parts, fmt.Sprintf("%d actions", r.Report.ActionsChecked))
	}
	if r.Report.Checked == 0 && r.Report.ActionsChecked == 0 {
		return "nothing expandable found"
	}
	return strings.Join(parts, ", ")
}

// scanAndReport drives the two existing commands rather than reimplementing
// them, so an org report can never drift from what `deepdep report` prints for
// the same repository.
func scanAndReport(r forge.Repo, o scanOpts) orgRepo {
	out := orgRepo{Repo: r}
	if !o.skip {
		args := []string{
			"--mode", o.mode, "--format", "json", "--db", o.db,
			"--cache-dir", o.cache, "--timeout", o.timeout.String(),
			"--concurrency", fmt.Sprint(o.concurrency), r.CloneURL,
		}
		if _, err := scan(args); err != nil {
			out.Err = err.Error()
			return out
		}
	} else {
		out.Cached = true
	}

	runID, err := latestRunFor(o.db, r.CloneURL)
	if err != nil || runID == "" {
		out.Err = "no stored run"
		return out
	}
	rep := []string{"--db", o.db, "--format", "json"}
	if !o.posture {
		rep = append(rep, "--posture=false")
	}
	rep = append(rep, runID)
	body, err := reportCmd(rep)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	var doc reportDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		out.Err = err.Error()
		return out
	}
	out.Report = &doc
	return out
}

// ---- fleet aggregation ---------------------------------------------------

type orgDoc struct {
	Org       string    `json:"org"`
	KnownAt   time.Time `json:"known_at"`
	Total     int       `json:"repositories"`
	Scanned   int       `json:"scanned"`
	Failed    int       `json:"failed"`
	Graded    int       `json:"graded"`
	Ungraded  int       `json:"ungraded_low_coverage"`
	Empty     int       `json:"ungraded_nothing_found"`
	MedianRaw int       `json:"median_score"`
	Grades    []count   `json:"grade_distribution"`

	Exposure []exposureRow `json:"exposure"`
	Surfaces orgSurfaces   `json:"surfaces"`
	Controls []count       `json:"controls"`
	Repos    []orgRow      `json:"repos"`
	Failures []orgFailure  `json:"failures"`
	Notes    []string      `json:"notes"`
}

type orgSurfaces struct {
	Actions      int `json:"ci_actions"`
	FlaggedRepos int `json:"repos_invoking_a_flagged_action"`
	// MovingRefs counts every first-party reference that can be repointed —
	// CI actions AND container base images together. They are not separated
	// here because the report they are summed from does not separate them, and
	// inventing a split the source cannot support would be a number nobody
	// could check.
	MovingRefs int `json:"moving_refs"`
	NoControls int `json:"repos_running_no_control"`
	Assessable int `json:"repos_with_readable_ci"`
}

type orgRow struct {
	Repo      string `json:"repo"`
	Grade     string `json:"grade"`
	Score     int    `json:"score"`
	Stars     int    `json:"stars"`
	Declared  int    `json:"declared"`
	Affected  int    `json:"declared_affected"`
	Inherited int    `json:"inherited"`
	Malicious int    `json:"malicious"`
	Critical  int    `json:"critical"`
	High      int    `json:"high"`
	Moving    int    `json:"moving_refs"`
	Controls  int    `json:"controls"`
	Suppress  string `json:"not_graded_because,omitempty"`
}

type orgFailure struct {
	Repo string `json:"repo"`
	Err  string `json:"error"`
}

const directSurfaces = "manifest ci dockerfile"

func buildOrgReport(org string, results []orgRepo) orgDoc {
	doc := orgDoc{
		Org: org, KnownAt: time.Now().UTC(), Total: len(results),
		Grades: []count{}, Exposure: []exposureRow{}, Controls: []count{},
		Repos: []orgRow{}, Failures: []orgFailure{},
		Notes: []string{
			"a repository that resolved no packages is reported as ungraded, not as clean",
			"CI-action advisories are not version-matched and are excluded from every grade",
		},
	}

	grade := map[string]int{}
	ctlCount := map[string]int{}
	bucket := map[string]*exposureRow{}
	var scores []int

	for _, r := range results {
		if r.Err != "" {
			doc.Failed++
			doc.Failures = append(doc.Failures, orgFailure{Repo: r.Repo.FullName, Err: r.Err})
			continue
		}
		if r.Report == nil {
			continue
		}
		doc.Scanned++
		rep := r.Report

		row := orgRow{
			Repo: r.Repo.FullName, Grade: rep.Score.Grade, Score: rep.Score.Score,
			Stars: r.Repo.Stars, Controls: len(rep.Controls),
			Malicious: len(rep.Malicious),
		}
		for _, e := range rep.Exposure {
			// Sum the direct surfaces; keep inherited separate. Collapsing them
			// would lose the only distinction that says whose job a finding is.
			if e.Reach == "direct" {
				row.Declared += e.Checked
				row.Affected += e.Affected
			} else {
				row.Inherited += e.Checked
			}
			key := e.Surface
			if e.Reach != "direct" {
				key = "inherited"
			}
			b := bucket[key]
			if b == nil {
				b = &exposureRow{Reach: e.Reach, Surface: e.Surface}
				bucket[key] = b
			}
			b.Checked += e.Checked
			b.Affected += e.Affected
			b.Malicious += e.Malicious
			b.Critical += e.Critical
			b.High += e.High
			b.Other += e.Other
		}
		for _, c := range rep.BySev {
			switch c.Name {
			case "CRITICAL":
				row.Critical = c.Versions
			case "HIGH":
				row.High = c.Versions
			}
		}
		row.Moving = rep.Coverage["unpinned-ref"]
		doc.Surfaces.MovingRefs += rep.Coverage["unpinned-ref"]
		doc.Surfaces.Actions += rep.ActionsChecked
		if len(rep.ActionAdvisories) > 0 {
			doc.Surfaces.FlaggedRepos++
		}
		if rep.ControlsAssessable {
			doc.Surfaces.Assessable++
			if len(rep.Controls) == 0 {
				doc.Surfaces.NoControls++
			}
			for _, c := range rep.Controls {
				ctlCount[string(c.Kind)]++
			}
		}

		if rep.Score.Suppressed {
			doc.Ungraded++
			// Two states, counted apart. A repository with no dependencies at all
			// is not one we failed to read, and the fleet line asserted the second
			// reason for both.
			if rep.Surface == 0 {
				doc.Empty++
			}
			row.Suppress = rep.Score.Reason
		} else {
			doc.Graded++
			grade[rep.Score.Grade]++
			scores = append(scores, rep.Score.Score)
		}
		doc.Repos = append(doc.Repos, row)
	}

	for _, g := range []string{"A", "B", "C", "D", "F"} {
		if grade[g] > 0 {
			doc.Grades = append(doc.Grades, count{Name: g, Versions: grade[g]})
		}
	}
	if len(scores) > 0 {
		sort.Ints(scores)
		doc.MedianRaw = scores[len(scores)/2]
	}
	for _, k := range strings.Fields(directSurfaces) {
		if b, ok := bucket[k]; ok {
			doc.Exposure = append(doc.Exposure, *b)
		}
	}
	if b, ok := bucket["inherited"]; ok {
		doc.Exposure = append(doc.Exposure, *b)
	}
	for _, k := range sortedIntKeys(ctlCount) {
		doc.Controls = append(doc.Controls, count{Name: k, Projects: ctlCount[k]})
	}

	// Worst first: malicious code, then criticals, then the raw score. The same
	// order the single-repository report uses, so a reader moving between them
	// is not re-learning the ranking.
	sort.SliceStable(doc.Repos, func(i, j int) bool {
		a, b := doc.Repos[i], doc.Repos[j]
		if a.Malicious != b.Malicious {
			return a.Malicious > b.Malicious
		}
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		return a.Score > b.Score
	})
	return doc
}

// ---- rendering -----------------------------------------------------------

func renderOrg(d orgDoc, detail int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "ORG  %s\n", d.Org)
	fmt.Fprintf(&b, "%d repositories · %d scanned · %d failed · known-at %s\n\n",
		d.Total, d.Scanned, d.Failed, d.KnownAt.Format("2006-01-02"))

	fmt.Fprintf(&b, "GRADES  (median %d/100, higher is worse)\n", d.MedianRaw)
	if len(d.Grades) == 0 {
		fmt.Fprintf(&b, "  none graded\n")
	}
	for _, g := range d.Grades {
		fmt.Fprintf(&b, "  %-2s %4d  %s\n", g.Name, g.Versions, bar(g.Versions, d.Graded))
	}
	if thin := d.Ungraded - d.Empty; thin > 0 {
		fmt.Fprintf(&b, "  --  %4d  not graded — too little of the closure was auditable.\n", thin)
		fmt.Fprintf(&b, "            These are UNASSESSED, not clean.\n")
	}
	if d.Empty > 0 {
		fmt.Fprintf(&b, "  --  %4d  not graded — no packages, actions or hooks found.\n", d.Empty)
	}

	if len(d.Exposure) > 0 {
		fmt.Fprintf(&b, "\nREACH  (who can fix it)\n")
		fmt.Fprintf(&b, "  %-22s %9s %9s %5s %5s %7s\n", "", "packages", "affected", "crit", "high", "rate")
		for _, e := range d.Exposure {
			name := "inherited (transitive)"
			if e.Reach == "direct" {
				name = "direct — " + e.Surface
			}
			rate := "-"
			if e.Checked > 0 {
				rate = fmt.Sprintf("%.1f%%", float64(e.Affected)/float64(e.Checked)*100)
			}
			fmt.Fprintf(&b, "  %-22s %9d %9d %5d %5d %7s\n",
				name, e.Checked, e.Affected, e.Critical, e.High, rate)
		}
	}

	fmt.Fprintf(&b, "\nBEYOND THE MANIFEST\n")
	fmt.Fprintf(&b, "  CI actions invoked                    %6d\n", d.Surfaces.Actions)
	fmt.Fprintf(&b, "  repos invoking a flagged action       %6d   %s\n",
		d.Surfaces.FlaggedRepos, share(d.Surfaces.FlaggedRepos, d.Scanned))
	fmt.Fprintf(&b, "  moving refs (actions + base images)   %6d\n", d.Surfaces.MovingRefs)
	fmt.Fprintf(&b, "  repos with readable CI                %6d\n", d.Surfaces.Assessable)
	fmt.Fprintf(&b, "  of those, running NO control          %6d   %s\n",
		d.Surfaces.NoControls, share(d.Surfaces.NoControls, d.Surfaces.Assessable))

	if len(d.Controls) > 0 {
		fmt.Fprintf(&b, "\nCONTROLS IN USE\n")
		for _, c := range d.Controls {
			fmt.Fprintf(&b, "  %-24s %4d   %s\n", c.Name, c.Projects,
				share(c.Projects, d.Surfaces.Assessable))
		}
	}

	fmt.Fprintf(&b, "\nREPOSITORIES  (worst first)\n")
	fmt.Fprintf(&b, "  %-38s %5s %6s %9s %9s %5s %5s %4s %4s\n",
		"", "grade", "score", "declared", "inherited", "crit", "high", "mal", "ctl")
	for _, r := range d.Repos {
		g := r.Grade
		if g == "" {
			g = "--"
		}
		fmt.Fprintf(&b, "  %-38s %5s %6d %9d %9d %5d %5d %4d %4d\n",
			truncate(r.Repo, 38), g, r.Score, r.Declared, r.Inherited,
			r.Critical, r.High, r.Malicious, r.Controls)
	}

	if detail > 0 {
		fmt.Fprintf(&b, "\nDETAIL  (worst %d)\n", min(detail, len(d.Repos)))
		for i, r := range d.Repos {
			if i >= detail {
				break
			}
			fmt.Fprintf(&b, "\n  %s — %s\n", r.Repo, gradeLine(r))
			if r.Suppress != "" {
				fmt.Fprintf(&b, "    %s\n", r.Suppress)
			}
			fmt.Fprintf(&b, "    %d declared (%d affected) · %d inherited · %d moving refs · %d controls\n",
				r.Declared, r.Affected, r.Inherited, r.Moving, r.Controls)
		}
	}

	if len(d.Failures) > 0 {
		fmt.Fprintf(&b, "\nFAILED  (%d) — counted, not dropped\n", len(d.Failures))
		for _, f := range d.Failures {
			fmt.Fprintf(&b, "  %-38s %s\n", truncate(f.Repo, 38), truncate(f.Err, 60))
		}
	}

	fmt.Fprintf(&b, "\nNOTES\n")
	for _, n := range d.Notes {
		fmt.Fprintf(&b, "  · %s\n", n)
	}
	fmt.Fprintf(&b, "\n  deepdep report <run-id> for any single repository above.\n")
	return b.Bytes()
}

func gradeLine(r orgRow) string {
	if r.Grade == "" {
		return "not graded"
	}
	return fmt.Sprintf("risk %s (%d/100)", r.Grade, r.Score)
}

func share(n, of int) string {
	if of == 0 {
		return ""
	}
	return fmt.Sprintf("%d%%", int(float64(n)/float64(of)*100+0.5))
}

func bar(n, of int) string {
	if of == 0 {
		return ""
	}
	w := int(float64(n) / float64(of) * 40)
	return strings.Repeat("█", w)
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/advisory"
	"github.com/jverhoeks/deepdep/internal/controls"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
	"github.com/jverhoeks/deepdep/internal/supply"
)

// reportCmd is the single deliverable: malicious packages, advisories and
// posture over one stored run.
//
// It is LAYERED, not scored. There is no 0-100 number here and there will not
// be one, for the same reason the rollup carries no worst-case package badge:
// any composite averages "this package was hostile and ran with your
// credentials" against "this project has no fuzzing harness", and the reader
// loses the only distinction that tells them what to do this morning. Each
// layer is reported with its own vocabulary and its own counts.
//
// The layers are ordered by what a reader should act on first, which is not the
// same as by how large the numbers are:
//
//  1. malicious   — hostile code that already executed. Nothing outranks this.
//  2. advisories  — known flaws in what installs, worst severity first.
//  3. posture     — repo-specific signals, split from ecosystem baseline.
//  4. coverage    — what we could not expand, so the clean parts are trustworthy.
func reportCmd(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	var (
		dbPath  = fs.String("db", defaultDBPath(), "")
		state   = fs.String("state", "all", "installed|possible|unknown|all")
		format  = fs.String("format", "text", "")
		osvBase = fs.String("osv", "https://api.osv.dev", "")
		ddBase  = fs.String("depsdev", "https://api.deps.dev", "")
		posture = fs.Bool("posture", true, "include deps.dev/Scorecard signals")
		timeout = fs.Duration("timeout", 20*time.Minute, "")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	db, err := store.Open(*dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	runID := ""
	if fs.NArg() == 1 {
		runID = fs.Arg(0)
	}

	// Defaults to every state. A report that led with malicious packages while
	// querying only `installed` would miss exactly the ones a Dockerfile RUN
	// line pulled in — which is where the Shai-Hulud packages showed up in
	// testing, since a Dockerfile leaves no lockfile instance.
	want := rollup.State(*state)
	if *state == "all" {
		want = ""
	}
	targets, meta, err := db.AuditTargets(ctx, runID, want)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no %s packages in run %q; scan first", *state, meta.RunID)
	}

	knownAt := time.Now().UTC()
	findings, err := advisory.New(*osvBase, nil).Check(ctx, targets, knownAt)
	if err != nil {
		return nil, err
	}

	var assessments []supply.Assessment
	if *posture {
		client := supply.New(*ddBase, nil)
		facts, err := client.Facts(ctx, targets)
		if err != nil {
			return nil, err
		}
		repos := make([]string, 0, len(facts))
		for _, f := range facts {
			repos = append(repos, f.SourceRepo)
		}
		projects, err := client.Projects(ctx, repos)
		if err != nil {
			return nil, err
		}
		if err := db.RecordSupply(ctx, facts, projects, knownAt); err != nil {
			return nil, err
		}
		assessments = supply.Assess(facts, projects)
	}

	owners, err := db.NodeOwners(ctx, meta.RunID)
	if err != nil {
		return nil, err
	}
	// Control detection is a query over the whole graph, not another scan: a CI
	// action is a node, a shell step is a node carrying its command, and a
	// recognised config file is a coverage frontier.
	allNodes, err := db.Nodes(ctx, meta.RunID)
	if err != nil {
		return nil, err
	}

	r := buildReport(meta, *state, knownAt, targets, findings, assessments, owners)
	r.Controls = controls.Detect(allNodes)
	r.MissingControls = controls.Missing(r.Controls)
	r.ControlsAssessable = controls.Assessable(allNodes)
	if *format == "json" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", " ")
		if err := enc.Encode(r); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return renderReport(r), nil
}

// ---- model ---------------------------------------------------------------

type reportDoc struct {
	RunID     string    `json:"run_id"`
	Ref       string    `json:"ref"`
	Mode      string    `json:"mode"`
	State     string    `json:"state"`
	AsOf      time.Time `json:"as_of"`
	KnownAt   time.Time `json:"known_at"`
	Checked   int       `json:"checked"`
	Malicious []finding `json:"malicious"`
	Advisory  []finding `json:"advisories"`
	BySev     []count   `json:"advisories_by_severity"`
	// RepoSignals are posture signals a maintainer of THIS repo can act on.
	// Baseline are the ones nearly every open-source dependency carries; keeping
	// them apart is what stops the biggest number from reading as the biggest
	// problem.
	RepoSignals        []count            `json:"repo_signals"`
	Baseline           []count            `json:"ecosystem_baseline"`
	ByOwner            []ownerRow         `json:"by_application"`
	Controls           []controls.Control `json:"controls"`
	ControlsAssessable bool               `json:"controls_assessable"`
	MissingControls    []controls.Kind    `json:"controls_missing"`
	Coverage           map[string]int     `json:"coverage_frontier"`
	Notes              map[string]string  `json:"notes"`
	Sources            map[string]string  `json:"sources"`
}

type finding struct {
	Severity string `json:"severity"`
	ID       string `json:"id"`
	CVE      string `json:"cve,omitempty"`
	Package  string `json:"package"`
	Owner    string `json:"application,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

type count struct {
	Name     string `json:"name"`
	Versions int    `json:"versions"`
	Projects int    `json:"projects,omitempty"`
	// Why is the upstream scanner's own finding, one line per project, so the
	// report says which workflow and which line rather than restating the rule.
	Why []string `json:"why,omitempty"`
}

type ownerRow struct {
	Name      string `json:"name"`
	Malicious int    `json:"malicious"`
	Critical  int    `json:"critical"`
	High      int    `json:"high"`
	Other     int    `json:"other"`
}

// baselineSignals are the posture signals that describe open-source publishing
// in general rather than this repository. 835 of 1151 packages lacking SLSA
// provenance is what the ecosystem looks like; reporting it alongside a
// deprecated package makes the report read as alarm rather than information.
var baselineSignals = map[string]bool{
	"unattested-source":       true,
	"no-scorecard":            true,
	"unpinned-upstream-build": true,
	"unsigned-releases":       true,
	"non-standard-license":    true,
}

func buildReport(meta store.Run, state string, knownAt time.Time,
	targets []graph.NodeID, findings []advisory.Finding,
	assessments []supply.Assessment, owners map[graph.NodeID][]string) reportDoc {

	r := reportDoc{
		RunID: meta.RunID, Ref: meta.Ref, Mode: meta.Mode, State: state,
		AsOf: meta.AsOf, KnownAt: knownAt, Checked: len(targets),
		Coverage: map[string]int{},
		Notes: map[string]string{
			"scoring": "none. Layers are reported separately; a composite would average " +
				"hostile code against a missing fuzzing harness.",
			"knowledge_basis": "advisories are replayable at any instant; Scorecard posture " +
				"is current-records only and cannot be reconstructed for the past.",
		},
		Sources: map[string]string{
			"malicious":  "OSV MAL- feed (OpenSSF malicious-packages), same query as advisories",
			"advisories": "OSV",
			"posture":    "deps.dev + OpenSSF Scorecard",
		},
	}

	sev := map[string]int{}
	byOwner := map[string]*ownerRow{}
	owned := func(id graph.NodeID) string {
		if o := owners[id]; len(o) > 0 {
			return strings.Join(o, ",")
		}
		return "-"
	}
	bump := func(id graph.NodeID, sevLabel string) {
		for _, name := range ownersOf(owners, id) {
			row := byOwner[name]
			if row == nil {
				row = &ownerRow{Name: name}
				byOwner[name] = row
			}
			switch sevLabel {
			case "MALICIOUS":
				row.Malicious++
			case "CRITICAL":
				row.Critical++
			case "HIGH":
				row.High++
			default:
				row.Other++
			}
		}
	}

	for _, f := range findings {
		sevLabel := f.Advisory.SeverityLabel()
		sev[sevLabel]++
		bump(f.NodeID, sevLabel)
		row := finding{
			Severity: sevLabel, ID: f.Advisory.ID, CVE: f.Advisory.CVE(),
			Package: label(f.NodeID), Owner: owned(f.NodeID),
			Summary: truncate(f.Advisory.Summary, 70),
		}
		if sevLabel == "MALICIOUS" {
			r.Malicious = append(r.Malicious, row)
		} else {
			r.Advisory = append(r.Advisory, row)
		}
	}
	sortFindings(r.Malicious)
	sortFindings(r.Advisory)

	for _, s := range []string{"CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"} {
		if sev[s] > 0 {
			r.BySev = append(r.BySev, count{Name: s, Versions: sev[s]})
		}
	}

	sigVers := map[string]int{}
	sigRepos := map[string]map[string]bool{}
	sigWhy := map[string]map[string]string{} // code -> project -> first warning
	for _, a := range assessments {
		for _, s := range a.Signals {
			sigVers[s.Code]++
			if sigRepos[s.Code] == nil {
				sigRepos[s.Code] = map[string]bool{}
				sigWhy[s.Code] = map[string]string{}
			}
			if a.SourceRepo != "" {
				sigRepos[s.Code][a.SourceRepo] = true
				if len(s.Evidence) > 0 {
					sigWhy[s.Code][a.SourceRepo] = s.Evidence[0]
				}
			}
		}
	}
	for _, code := range supply.Codes() {
		n := sigVers[code]
		if n == 0 {
			continue
		}
		c := count{Name: code, Versions: n, Projects: len(sigRepos[code])}
		for _, proj := range sortedKeys(sigWhy[code]) {
			c.Why = append(c.Why, proj+": "+sigWhy[code][proj])
		}
		if baselineSignals[code] {
			r.Baseline = append(r.Baseline, c)
		} else {
			r.RepoSignals = append(r.RepoSignals, c)
		}
	}

	names := make([]string, 0, len(byOwner))
	for n := range byOwner {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r.ByOwner = append(r.ByOwner, *byOwner[n])
	}
	sort.SliceStable(r.ByOwner, func(i, j int) bool {
		a, b := r.ByOwner[i], r.ByOwner[j]
		if a.Malicious != b.Malicious {
			return a.Malicious > b.Malicious
		}
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		return a.High > b.High
	})
	return r
}

func ownersOf(owners map[graph.NodeID][]string, id graph.NodeID) []string {
	if o := owners[id]; len(o) > 0 {
		return o
	}
	return []string{"-"}
}

func sortFindings(f []finding) {
	sort.Slice(f, func(i, j int) bool {
		if severityRank(f[i].Severity) != severityRank(f[j].Severity) {
			return severityRank(f[i].Severity) > severityRank(f[j].Severity)
		}
		if f[i].Package != f[j].Package {
			return f[i].Package < f[j].Package
		}
		return f[i].ID < f[j].ID
	})
}

// ---- rendering -----------------------------------------------------------

func renderReport(r reportDoc) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "run %s  ref %s  mode %s  state %s\n", r.RunID, short(r.Ref), r.Mode, r.State)
	fmt.Fprintf(&b, "as-of %s   known-at %s   %d package versions\n\n",
		r.AsOf.Format("2006-01-02"), r.KnownAt.Format("2006-01-02"), r.Checked)

	fmt.Fprintf(&b, "1. MALICIOUS PACKAGES  (%d)\n", len(r.Malicious))
	if len(r.Malicious) == 0 {
		fmt.Fprintf(&b, "   none. Source: OSV MAL- feed (OpenSSF malicious-packages).\n")
	} else {
		fmt.Fprintf(&b, "   hostile code that already ran with your build's credentials.\n")
		for _, f := range r.Malicious {
			fmt.Fprintf(&b, "   %-16s %-44s %-14s %s\n", f.ID, f.Package, f.Owner, f.Summary)
		}
	}

	fmt.Fprintf(&b, "\n2. ADVISORIES  (%d across the closure)\n", len(r.Advisory))
	if len(r.Advisory) == 0 {
		fmt.Fprintf(&b, "   none known at %s.\n", r.KnownAt.Format("2006-01-02"))
	} else {
		for _, c := range r.BySev {
			fmt.Fprintf(&b, "   %-9s %d\n", c.Name, c.Versions)
		}
		fmt.Fprintln(&b)
		for i, f := range r.Advisory {
			if i == 20 {
				fmt.Fprintf(&b, "   ... %d more (--format json for all)\n", len(r.Advisory)-20)
				break
			}
			fmt.Fprintf(&b, "   %-9s %-18s %-42s %-14s %s\n",
				f.Severity, orDash(f.CVE), f.Package, f.Owner, f.Summary)
		}
	}

	fmt.Fprintf(&b, "\n3. POSTURE\n")
	if len(r.RepoSignals) == 0 && len(r.Baseline) == 0 {
		fmt.Fprintf(&b, "   not collected (--posture=false)\n")
	} else {
		fmt.Fprintf(&b, "   actionable for this repository        versions  projects\n")
		for _, c := range r.RepoSignals {
			fmt.Fprintf(&b, "     %-32s %8d %9s\n", c.Name, c.Versions, orDashN(c.Projects))
			// The upstream scanner's own words, so the row is actionable rather
			// than a restatement of the rule.
			for i, w := range c.Why {
				if i >= 3 {
					fmt.Fprintf(&b, "        ... %d more projects\n", len(c.Why)-i)
					break
				}
				fmt.Fprintf(&b, "        %s\n", elideMiddle(w, 104))
			}
		}
		fmt.Fprintf(&b, "   ecosystem baseline — what open-source publishing looks like,\n")
		fmt.Fprintf(&b, "   not a property of this repo:\n")
		for _, c := range r.Baseline {
			fmt.Fprintf(&b, "     %-32s %8d %9s\n", c.Name, c.Versions, orDashN(c.Projects))
		}
	}

	if len(r.ByOwner) > 0 {
		fmt.Fprintf(&b, "\n4. BY APPLICATION\n")
		fmt.Fprintf(&b, "   %-40s %10s %9s %5s %6s\n", "", "malicious", "critical", "high", "other")
		for _, o := range r.ByOwner {
			fmt.Fprintf(&b, "   %-40s %10d %9d %5d %6d\n", o.Name, o.Malicious, o.Critical, o.High, o.Other)
		}
	}

	fmt.Fprintf(&b, "\n5. CONTROLS IN USE  (what this repo already runs)\n")
	if !r.ControlsAssessable {
		// Evidence of absence vs absence of evidence. kubernetes runs Prow and
		// has no .github/workflows at all; reporting "none" there would say
		// "runs nothing" when the truth is "their CI is somewhere we cannot see".
		fmt.Fprintf(&b, "   NOT ASSESSABLE: no GitHub Actions or GitLab CI configuration found.\n")
		fmt.Fprintf(&b, "   This repository's pipeline lives somewhere deepdep does not read\n")
		fmt.Fprintf(&b, "   (Prow, Jenkins, Buildkite, an internal system). Nothing follows about\n")
		fmt.Fprintf(&b, "   which controls it does or does not run.\n")
	} else if len(r.Controls) == 0 {
		fmt.Fprintf(&b, "   none detected\n")
	} else {
		for _, c := range r.Controls {
			tag := ""
			if c.Commercial {
				tag = "  [commercial]"
			}
			fmt.Fprintf(&b, "   %-20s %-24s %s%s\n", c.Kind, c.Tool,
				truncate(strings.Join(c.Evidence, ", "), 46), tag)
		}
	}
	if len(r.MissingControls) > 0 && r.ControlsAssessable {
		// The actionable half. "Runs CodeQL" is mildly interesting; "runs no
		// dependency scanner and no secret scanner" is the finding, and only a
		// tool that knows the full checklist can say it.
		var names []string
		for _, k := range r.MissingControls {
			names = append(names, string(k))
		}
		fmt.Fprintf(&b, "   not detected: %s\n", strings.Join(names, ", "))
		fmt.Fprintf(&b, "   (absence of evidence in CI: a control run outside this repo is invisible here)\n")
	}

	fmt.Fprintf(&b, "\nno composite score: layers are reported separately, because any single\n")
	fmt.Fprintf(&b, "number averages hostile code against a missing fuzzing harness.\n")
	fmt.Fprintf(&b, "posture is current-records only — Scorecard history is not reconstructible.\n")
	return b.Bytes()
}

func orDashN(n int) string {
	if n == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", n)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/advisory"
	"github.com/jverhoeks/deepdep/internal/controls"
	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/reach"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/score"
	"github.com/jverhoeks/deepdep/internal/store"
	"github.com/jverhoeks/deepdep/internal/supply"
	"github.com/jverhoeks/deepdep/internal/walk"
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
	// Zero targets is a REPORT, not an error. A repo with no lockfile scanned
	// offline resolves no versions at all — django does exactly this — and the
	// honest output is a coverage-suppressed report naming the reason, not a
	// failure that looks like the tool broke.
	knownAt := time.Now().UTC()
	var findings []advisory.Finding
	if len(targets) > 0 {
		findings, err = advisory.New(*osvBase, nil).Check(ctx, targets, knownAt)
		if err != nil {
			return nil, err
		}
	}

	var assessments []supply.Assessment
	if *posture && len(targets) > 0 {
		client := supply.New(*ddBase, nil)
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

	pins, err := db.PinningCounts(ctx, meta.RunID)
	if err != nil {
		return nil, err
	}

	// Which of this repository's own files name each package. Severity ranks
	// findings; this is what says whether the fix is a line in package.json or a
	// wait on somebody else's release.
	surfaces, err := db.Surfaces(ctx, meta.RunID)
	if err != nil {
		return nil, err
	}

	// CI actions get their own query because OSV will not answer a PURL for
	// them. Their findings stay in their own field for the same reason: the
	// answer is version-less and must not be counted as if a version matched.
	actionTargets, err := db.ActionTargets(ctx, meta.RunID)
	if err != nil {
		return nil, err
	}
	var actionFindings []advisory.ActionAdvisory
	if len(actionTargets) > 0 {
		actionFindings, err = advisory.New(*osvBase, nil).CheckActions(ctx, actionTargets, knownAt)
		if err != nil {
			return nil, err
		}
	}

	// Reachability needs the edge list and the per-node pinning, which nothing
	// else in the report reads.
	pkgEdges, err := db.PackageEdges(ctx, meta.RunID)
	if err != nil {
		return nil, err
	}
	pinning, err := db.PinningByNode(ctx, meta.RunID)
	if err != nil {
		return nil, err
	}

	r := buildReport(meta, *state, knownAt, targets, findings, assessments, owners, allNodes, surfaces)
	computeReach(&r, findings, assessments, surfaces, pkgEdges, pinning)
	r.ActionsChecked = len(actionTargets)
	r.ActionAdvisories = actionFindings
	if r.ActionAdvisories == nil {
		r.ActionAdvisories = []advisory.ActionAdvisory{}
	}
	r.Controls = controls.Detect(allNodes)
	r.MissingControls = controls.Missing(r.Controls)
	r.ControlsAssessable = controls.Assessable(allNodes)
	r.Score = computeScore(r, pins)
	switch *format {
	case "json":
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", " ")
		if err := enc.Encode(r); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "mermaid":
		surfaceFiles, err := db.SurfaceFiles(ctx, meta.RunID)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := emit.Mermaid(&buf,
			mermaidInput(r, meta, surfaceFiles, findings, actionFindings, allNodes)); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return renderReport(r), nil
}

// mermaidInput turns the report into the diagram's flat input.
//
// It reads the findings the report already computed rather than re-querying, so
// the picture cannot disagree with the text underneath it — a diagram that
// showed a different set of criticals than the table above it would be worse
// than no diagram.
func mermaidInput(r reportDoc, meta store.Run, files []store.SurfaceFile,
	findings []advisory.Finding, actions []advisory.ActionAdvisory,
	nodes []graph.Node) emit.MermaidInput {

	// Severity and count per affected node, worst severity winning.
	type agg struct {
		sev   string
		count int
		note  string
	}
	hit := map[graph.NodeID]*agg{}
	bump := func(id graph.NodeID, sev, note string) {
		a := hit[id]
		if a == nil {
			a = &agg{}
			hit[id] = a
		}
		a.count++
		if severityRank(sev) > severityRank(a.sev) {
			a.sev = sev
		}
		if note != "" {
			a.note = note
		}
	}
	for _, f := range findings {
		bump(f.NodeID, f.Advisory.SeverityLabel(), "")
	}
	for _, a := range actions {
		// The weaker claim keeps its qualifier all the way into the picture.
		bump(a.NodeID, a.Advisory.SeverityLabel(), "not version-matched")
	}

	moving := map[graph.NodeID]bool{}
	for _, n := range nodes {
		if n.Reason == graph.ReasonUnpinnedRef {
			moving[n.ID] = true
		}
	}

	out := emit.MermaidInput{
		Repo: meta.Target, Ref: meta.Ref, Grade: r.Score.Grade,
	}
	if r.Score.Suppressed {
		out.Grade = "not graded"
	}
	for _, f := range files {
		mf := emit.MermaidFile{Kind: f.Kind, Path: f.Path, Names: len(f.Names), Moving: f.Moving}
		for _, id := range f.Names {
			a, ok := hit[id]
			if !ok {
				continue // clean, and counted in Names rather than drawn
			}
			mf.Hits = append(mf.Hits, emit.MermaidHit{
				Label: label(id), Severity: a.sev, Count: a.count,
				Moving: moving[id], Note: a.note,
			})
		}
		sort.SliceStable(mf.Hits, func(i, j int) bool {
			if severityRank(mf.Hits[i].Severity) != severityRank(mf.Hits[j].Severity) {
				return severityRank(mf.Hits[i].Severity) > severityRank(mf.Hits[j].Severity)
			}
			return mf.Hits[i].Label < mf.Hits[j].Label
		})
		out.Files = append(out.Files, mf)
	}
	return out
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
	RepoSignals []count    `json:"repo_signals"`
	Baseline    []count    `json:"ecosystem_baseline"`
	ByOwner     []ownerRow `json:"by_application"`
	// Exposure splits every finding by whether THIS repository names the
	// affected artifact. Severity says how bad it is; reach says who can fix it,
	// and the second question is the one a maintainer acts on first.
	Exposure []exposureRow `json:"exposure"`
	// ActionAdvisories are a weaker claim than Advisory and are kept apart for
	// that reason alone — see advisory.ActionAdvisory.
	//
	// They now reach the score at score.ActionClaimWeight rather than being
	// excluded from it. The old rule — an unverified ref must not move a grade —
	// was right about the strength of the claim and wrong about the consequence:
	// for the 17% of repositories with no packages at all, excluding refs meant
	// there was nothing left to grade, so a repository with a HIGH advisory in a
	// pinned action scored exactly like one with none. Discounted and visible
	// beats absent.
	ActionsChecked   int                       `json:"actions_checked"`
	ActionAdvisories []advisory.ActionAdvisory `json:"action_advisories"`
	// IndirectRisk is what carries no advisory TODAY but is how one arrives: an
	// unmaintained upstream will not ship the fix, and a floating version can
	// change under a rebuild with nothing committed here. Kept apart from
	// Advisory because a risk is not a finding and printing them together would
	// make the report read as alarm.
	IndirectRisk []count `json:"indirect_risk"`
	// Introducers attribute inherited findings to the direct dependencies whose
	// subtrees contain them, and Plan is the greedy shortest route through them.
	Introducers []reach.Introducer `json:"introducers,omitempty"`
	Plan        []reach.Introducer `json:"upgrade_plan,omitempty"`
	PlanClears  int                `json:"upgrade_plan_clears"`
	PlanOf      int                `json:"upgrade_plan_of"`
	// Unattributed are inherited findings under NO direct dependency, which no
	// bump clears; PlanCapped says the plan stopped at its limit instead. The
	// two produce the same shortfall and want opposite responses.
	Unattributed int  `json:"unattributed"`
	PlanCapped   bool `json:"upgrade_plan_capped"`
	// DirectIssues and IndirectIssues count FINDINGS, so a package named by two
	// surfaces is one issue rather than two.
	DirectIssues   int `json:"direct_issues"`
	IndirectIssues int `json:"indirect_issues"`
	// ActionNodes is the ref surface's size and ActionsMoving how many of those
	// refs are a branch or tag rather than a SHA.
	ActionNodes        int                `json:"action_nodes"`
	ActionsMoving      int                `json:"actions_moving"`
	Score              score.Result       `json:"score"`
	PackageNodes       int                `json:"package_nodes"`
	Surface            int                `json:"gradable_surface"`
	Auditable          float64            `json:"auditable_share"`
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
	// Surfaces are the repository's own files that name this package. Empty
	// means transitive: nothing here asked for it, and the fix belongs to
	// whoever did.
	Surfaces []string `json:"surfaces,omitempty"`
}

// planDepth is how many upgrades the plan proposes. Enough to show the shape of
// the work and short enough to be read as a starting point rather than a backlog.
const planDepth = 5

// computeReach fills the two sections an INHERITED finding needs and the older
// exposure table cannot give: what carries risk without carrying an advisory,
// and which of this repository's own dependencies would clear the most.
//
// It is separate from buildReport because it needs the edge list and the
// per-node pinning, and neither belongs in a signature that already carries
// nine arguments.
func computeReach(r *reportDoc, findings []advisory.Finding,
	assessments []supply.Assessment, surfaces map[graph.NodeID][]string,
	edges []reach.Edge, pinning map[graph.NodeID]string) {

	isDirect := func(id graph.NodeID) bool { return len(surfaces[id]) > 0 }

	// --- indirect risk -----------------------------------------------------
	//
	// Restricted to the signals a maintainer can act on. The ecosystem baseline —
	// unsigned releases, no SLSA provenance — describes open-source publishing in
	// general and would bury the four lines that mean something.
	sig := map[string]int{}
	for _, a := range assessments {
		if isDirect(a.NodeID) {
			continue
		}
		for _, s := range a.Signals {
			if !baselineSignals[s.Code] {
				sig[s.Code]++
			}
		}
	}
	r.IndirectRisk = []count{}
	for _, code := range supply.Codes() {
		if sig[code] > 0 {
			r.IndirectRisk = append(r.IndirectRisk, count{Name: code, Versions: sig[code]})
		}
	}
	var floating int
	for id, pin := range pinning {
		if pin == "floating" && !isDirect(id) {
			floating++
		}
	}
	if floating > 0 {
		r.IndirectRisk = append(r.IndirectRisk,
			count{Name: "floating-version", Versions: floating})
	}

	// --- direct vs inherited ------------------------------------------------
	//
	// Counted per FINDING, not by summing the exposure rows. A package named in
	// both package.json and a Dockerfile appears in two rows on purpose — they
	// are two lines to edit — but it is still one advisory, and adding the rows
	// up reported it twice.
	affected := map[graph.NodeID]bool{}
	for _, f := range findings {
		if isDirect(f.NodeID) {
			r.DirectIssues++
		} else {
			r.IndirectIssues++
			affected[f.NodeID] = true
		}
	}

	// --- blast radius ------------------------------------------------------
	var direct []graph.NodeID
	for id := range surfaces {
		if graph.IsPackage(id) {
			direct = append(direct, id)
		}
	}
	sort.Slice(direct, func(i, j int) bool { return direct[i] < direct[j] })

	a := reach.Analyse(direct, affected, edges, planDepth)
	r.Introducers = a.Introducers
	r.Plan = a.Plan
	r.PlanClears = a.Clears
	r.PlanOf = a.Affected
	r.Unattributed = a.Unattributed()
	r.PlanCapped = a.Capped
}

// exposureRow is one reach bucket. Direct rows are per surface, because
// "upgrade a line in package.json", "bump a base image" and "pin a CI action"
// are three different pieces of work owned by three different habits.
//
// Checked is the denominator on purpose. A repository with 12 direct and 3,400
// transitive packages that reports 4 direct and 40 transitive findings is not
// ten times safer on its own dependencies — it is three times worse, and only
// the rate says so.
type exposureRow struct {
	Reach     string `json:"reach"` // direct | indirect
	Surface   string `json:"surface,omitempty"`
	Checked   int    `json:"checked"`
	Affected  int    `json:"affected"`
	Malicious int    `json:"malicious"`
	Critical  int    `json:"critical"`
	High      int    `json:"high"`
	Other     int    `json:"other"`
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
	assessments []supply.Assessment, owners map[graph.NodeID][]string,
	nodes []graph.Node, surfaces map[graph.NodeID][]string) reportDoc {

	r := reportDoc{
		RunID: meta.RunID, Ref: meta.Ref, Mode: meta.Mode, State: state,
		AsOf: meta.AsOf, KnownAt: knownAt, Checked: len(targets),
		// Initialised, not left nil: a nil slice marshals as `null`, and a
		// consumer parsing the JSON should not have to null-guard every field
		// to tell "no findings" from "field absent".
		Malicious: []finding{}, Advisory: []finding{}, BySev: []count{},
		RepoSignals: []count{}, Baseline: []count{}, ByOwner: []ownerRow{},
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
			Summary:  truncate(f.Advisory.Summary, 70),
			Surfaces: surfaces[f.NodeID],
		}
		if sevLabel == "MALICIOUS" {
			r.Malicious = append(r.Malicious, row)
		} else {
			r.Advisory = append(r.Advisory, row)
		}
	}
	sortFindings(r.Malicious)
	sortFindings(r.Advisory)
	r.Exposure = computeExposure(targets, findings, surfaces)

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
	// Coverage: what we could NOT read. Without it the score would treat a repo
	// where 15% of packages were auditable the same as one at 95%, and its
	// zero findings would read as a clean bill.
	var pkgNodes, resolved int
	for _, n := range nodes {
		// The ref surface — CI actions and pre-commit hooks — is counted in BOTH
		// halves of coverage. Every one of them is auditable by construction: OSV
		// answers for an action by name, so naming it is all that is required, and
		// ActionTargets returns them all.
		//
		// It therefore only ever raises coverage, and no repository that is graded
		// today can lose its grade to this. What it fixes is the opposite case: a
		// repository whose entire supply chain is six pinned actions had a
		// coverage of 0/0, was told it was too sparse to grade, and had in fact
		// been read completely.
		//
		// No `continue`: an action pinned to a branch is still a coverage-frontier
		// entry below, and dropping out of the loop here silently emptied the
		// unpinned-ref bucket that the hygiene term now reads.
		if graph.IsAction(n.ID) {
			r.ActionNodes++
			if n.Reason == graph.ReasonUnpinnedRef {
				r.ActionsMoving++
			}
		}
		if graph.IsPackage(n.ID) {
			// A node we decided will not be installed is not a gap in our
			// knowledge. A dependency's own devDependencies and a Python extra
			// nobody asked for are frontiers because the walk correctly STOPPED
			// there, and counting them as unread packages made coverage read as
			// 44% for axios — where the closure is in fact complete for
			// everything that installs. Across 131 repositories that suppressed
			// every single grade, which said more about the metric than about
			// any repository.
			if !walk.NotInstalled(n.Reason) {
				pkgNodes++
				if n.Completeness == graph.Resolved {
					resolved++
				}
			}
		}
		// Inferred is a SUCCESS: we named the package from a shell line. Only
		// Declared and Opaque nodes are frontiers, and listing an inference
		// under "could not expand" reads as a failure to do the thing we did.
		if n.Reason != "" && (n.Completeness == graph.Declared || n.Completeness == graph.Opaque) {
			r.Coverage[n.Reason]++
		}
	}
	r.PackageNodes = pkgNodes
	// The denominator is the whole gradable surface and the numerator is what was
	// actually audited on it. Actions appear in both because all of them are.
	r.Surface = pkgNodes + r.ActionNodes
	if r.Surface > 0 {
		r.Auditable = float64(len(targets)+r.ActionNodes) / float64(r.Surface)
		if r.Auditable > 1 {
			r.Auditable = 1
		}
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

// computeExposure buckets the audited packages, and the findings against them,
// by who can fix them.
//
// A package named by two surfaces is counted in both, and deliberately: a
// version pinned in requirements.txt AND installed again by a Dockerfile RUN
// line is two lines to edit, in two files, that can drift apart. Reporting it
// once would understate the work and hide the drift. The rows therefore do not
// sum to the audited total, which is why each carries its own denominator.
func computeExposure(targets []graph.NodeID, findings []advisory.Finding,
	surfaces map[graph.NodeID][]string) []exposureRow {

	const indirect = "" // the surface of a package nobody here named

	rows := map[string]*exposureRow{}
	row := func(surface string) *exposureRow {
		r, ok := rows[surface]
		if !ok {
			reach := "direct"
			if surface == indirect {
				reach = "indirect"
			}
			r = &exposureRow{Reach: reach, Surface: surface}
			rows[surface] = r
		}
		return r
	}
	// bucketsOf is the same lookup for the denominator and for the findings, so
	// the two can never disagree about where a package belongs.
	bucketsOf := func(id graph.NodeID) []string {
		if s := surfaces[id]; len(s) > 0 {
			return s
		}
		return []string{indirect}
	}

	for _, id := range targets {
		for _, s := range bucketsOf(id) {
			row(s).Checked++
		}
	}

	affected := map[string]map[graph.NodeID]bool{}
	for _, f := range findings {
		for _, s := range bucketsOf(f.NodeID) {
			r := row(s)
			switch f.Advisory.SeverityLabel() {
			case "MALICIOUS":
				r.Malicious++
			case "CRITICAL":
				r.Critical++
			case "HIGH":
				r.High++
			default:
				r.Other++
			}
			if affected[s] == nil {
				affected[s] = map[graph.NodeID]bool{}
			}
			affected[s][f.NodeID] = true
		}
	}
	for s, set := range affected {
		row(s).Affected = len(set)
	}

	// Ordered by what a reader should look at first: the surfaces they own,
	// hardest-to-notice last, then everything they inherited.
	out := []exposureRow{}
	for _, s := range []string{
		store.SurfaceManifest, store.SurfaceCI, store.SurfaceDockerfile, indirect,
	} {
		if r, ok := rows[s]; ok {
			out = append(out, *r)
		}
	}
	return out
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

	// The score first, with its arithmetic immediately under it. A number a
	// reader cannot take apart is a number they have to either trust or ignore,
	// and neither is useful.
	if r.Score.Suppressed {
		fmt.Fprintf(&b, "RISK  —  NOT GRADED\n")
		fmt.Fprintf(&b, "  %s\n", r.Score.Reason)
	} else {
		fmt.Fprintf(&b, "RISK  %s  (%d/100, higher is worse)\n", r.Score.Grade, r.Score.Score)
		if r.Score.Reason != "" {
			fmt.Fprintf(&b, "  %s\n", r.Score.Reason)
		}
	}
	for _, t := range r.Score.Terms {
		if t.Name == "malicious" && t.Points == 0 && len(r.Malicious) == 0 {
			fmt.Fprintf(&b, "  %-17s %-52s   none\n", t.Name, t.Detail)
			continue
		}
		fmt.Fprintf(&b, "  %-17s %-52s %+5.0f / %d\n", t.Name, truncate(t.Detail, 52), t.Points, t.Max)
	}
	fmt.Fprintf(&b, "  %d%% of %d dependencies were auditable (%d packages, %d refs)\n\n",
		int(r.Auditable*100+0.5), r.Surface, r.PackageNodes, r.ActionNodes)

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
			// The leading mark is the whole point of the reach split: a reader
			// scanning this list needs to see, without a second query, which
			// rows they can fix themselves this morning.
			mark := " "
			if len(f.Surfaces) > 0 {
				mark = "*"
			}
			fmt.Fprintf(&b, " %s %-9s %-18s %-42s %-14s %s\n",
				mark, f.Severity, orDash(f.CVE), f.Package, f.Owner, f.Summary)
		}
		fmt.Fprintf(&b, "   * = named in this repository's own files\n")
	}

	if len(r.Exposure) > 0 {
		fmt.Fprintf(&b, "\n2b. REACH  (who can fix it)\n")
		fmt.Fprintf(&b, "   %-22s %8s %9s %5s %5s %6s %7s\n",
			"", "checked", "malicious", "crit", "high", "other", "rate")
		for _, e := range r.Exposure {
			name := "inherited (transitive)"
			if e.Reach == "direct" {
				name = "direct — " + e.Surface
			}
			rate := "-"
			if e.Checked > 0 {
				rate = fmt.Sprintf("%.1f%%", float64(e.Affected)/float64(e.Checked)*100)
			}
			fmt.Fprintf(&b, "   %-22s %8d %9d %5d %5d %6d %7s\n",
				name, e.Checked, e.Malicious, e.Critical, e.High, e.Other, rate)
		}
		fmt.Fprintf(&b, "   rate = share of that surface's packages carrying at least one advisory.\n")
		fmt.Fprintf(&b, "   A package named by two surfaces is counted in both: two lines to edit.\n")

		// The split stated as a sentence, not left to be read out of the table.
		// "every one of these is inherited" and "half are yours to edit" are
		// different mornings, and the numbers alone do not say which this is.
		//
		// Read off the per-finding counts rather than by adding the rows above:
		// the table counts a package named by two surfaces twice, on purpose.
		dIssues, iIssues := r.DirectIssues, r.IndirectIssues
		switch {
		case dIssues == 0 && iIssues > 0:
			fmt.Fprintf(&b, "   ALL %d are inherited: none is a line in a file here.\n", iIssues)
		case iIssues == 0 && dIssues > 0:
			fmt.Fprintf(&b, "   All %d are DIRECT: every one is a line in a file here.\n", dIssues)
		case dIssues > 0:
			fmt.Fprintf(&b, "   %d direct (yours to edit), %d inherited.\n", dIssues, iIssues)
		}
	}

	fmt.Fprintf(&b, "\n2c. CI ACTIONS WITH PUBLISHED ADVISORIES  (%d of %d invoked)\n",
		len(r.ActionAdvisories), r.ActionsChecked)
	if r.ActionsChecked == 0 {
		fmt.Fprintf(&b, "   no CI actions in this closure.\n")
	} else if len(r.ActionAdvisories) == 0 {
		fmt.Fprintf(&b, "   none known at %s.\n", r.KnownAt.Format("2006-01-02"))
	} else {
		for _, a := range r.ActionAdvisories {
			fmt.Fprintf(&b, "   %-9s %-18s %-30s ref %-12s %s\n",
				a.Advisory.SeverityLabel(), orDash(a.Advisory.CVE()), a.Action,
				orDash(a.Ref), truncate(a.Advisory.Summary, 46))
		}
		fmt.Fprintf(&b, "\n   NOT version-matched. OSV answers for CI actions only WITHOUT a\n")
		fmt.Fprintf(&b, "   version — its records carry no purl and state ranges in a versioning\n")
		fmt.Fprintf(&b, "   that refs do not follow — so this says the action has an advisory, not\n")
		fmt.Fprintf(&b, "   that your ref is inside it. Go and look. It scores at %.0f%% weight for\n",
			score.ActionClaimWeight*100)
		fmt.Fprintf(&b, "   the same reason: the claim is weaker, not absent.\n")
	}

	if len(r.IndirectRisk) > 0 {
		fmt.Fprintf(&b, "\n2d. INDIRECT RISK  (no advisory today)\n")
		for _, c := range r.IndirectRisk {
			note := ""
			if c.Name == "floating-version" {
				note = "   a rebuild can move these"
			}
			fmt.Fprintf(&b, "   %-28s %8d%s\n", c.Name, c.Versions, note)
		}
		fmt.Fprintf(&b, "   Not findings. This is how a finding arrives: an unmaintained\n")
		fmt.Fprintf(&b, "   package will not ship the fix when one is needed.\n")
	}

	if len(r.Introducers) > 0 {
		fmt.Fprintf(&b, "\n2e. BLAST RADIUS  (which of your dependencies brought these in)\n")
		fmt.Fprintf(&b, "   %-46s %8s %10s\n", "direct dependency", "affected", "only here")
		for i, in := range r.Introducers {
			if i >= planDepth {
				fmt.Fprintf(&b, "   ... %d more (--format json for all)\n", len(r.Introducers)-planDepth)
				break
			}
			fmt.Fprintf(&b, "   %-46s %8d %10s\n",
				truncate(label(in.Direct), 46), in.Affected, orDashN(in.Exclusive))
		}
		fmt.Fprintf(&b, "   \"only here\" is what THIS bump alone clears. A package pulled in by\n")
		fmt.Fprintf(&b, "   four dependencies is not fixed by upgrading one of them.\n")
		if len(r.Plan) > 0 {
			fmt.Fprintf(&b, "\n   Shortest route: %d %s %s %d of %d affected packages.\n",
				len(r.Plan), plural(len(r.Plan), "bump"),
				map[bool]string{true: "clears", false: "clear"}[len(r.Plan) == 1],
				r.PlanClears, r.PlanOf)
			for _, in := range r.Plan {
				fmt.Fprintf(&b, "     %-46s +%d\n", truncate(label(in.Direct), 46), in.New)
			}
			// Naming WHY the plan falls short. Capped means keep going;
			// unattributed means no bump reaches them and something else must.
			if r.PlanCapped {
				fmt.Fprintf(&b, "   Capped at %d. More bumps would clear the rest.\n", planDepth)
			}
			if r.Unattributed > 0 {
				fmt.Fprintf(&b, "   %d reach no direct dependency: no bump here clears %s.\n",
					r.Unattributed, plural2(r.Unattributed, "it", "them"))
			}
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

	if len(r.Coverage) > 0 {
		fmt.Fprintf(&b, "\n4b. COVERAGE FRONTIER  (where the walk stopped)\n")
		var decided bool
		for _, k := range sortedIntKeys(r.Coverage) {
			// Two different things stop a walk, and only one of them is a gap.
			note := ""
			if walk.NotInstalled(k) {
				note, decided = "  decided, not unread", true
			}
			fmt.Fprintf(&b, "   %-22s %d%s\n", k, r.Coverage[k], note)
		}
		if decided {
			fmt.Fprintf(&b, "   marked rows are frontiers the walk stopped at ON PURPOSE — nothing\n")
			fmt.Fprintf(&b, "   installs what is past them — so they do not count against coverage.\n")
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

// computeScore assembles the score's inputs from the report that was just built,
// so the number can never disagree with the sections above it.
func computeScore(r reportDoc, pins map[string]int) score.Result {
	in := score.Input{
		Checked:            r.Checked,
		Malicious:          len(r.Malicious),
		ActionsChecked:     r.ActionsChecked,
		Floating:           pins["floating"],
		Pinned:             pins["pinned"],
		Locked:             pins["locked"],
		ActionsFloating:    r.ActionsMoving,
		ActionsPinned:      r.ActionNodes - r.ActionsMoving,
		ControlsMissing:    len(r.MissingControls),
		ControlsTotal:      len(controls.Kinds),
		ControlsAssessable: r.ControlsAssessable,
		Auditable:          r.Auditable,
		Surface:            r.Surface,
	}
	// One action can carry several advisories; the severity counts are per REF,
	// matching how the package counts are per version. Counting rows instead
	// would let one much-discussed action outweigh a dozen quiet ones.
	worst := map[graph.NodeID]string{}
	for _, a := range r.ActionAdvisories {
		sev := a.Advisory.SeverityLabel()
		if severityRank(sev) > severityRank(worst[a.NodeID]) {
			worst[a.NodeID] = sev
		}
	}
	for _, sev := range worst {
		switch sev {
		case "CRITICAL":
			in.ActionCritical++
		case "HIGH":
			in.ActionHigh++
		case "MODERATE":
			in.ActionModerate++
		}
	}
	for _, c := range r.BySev {
		switch c.Name {
		case "CRITICAL":
			in.Critical = c.Versions
		case "HIGH":
			in.High = c.Versions
		case "MODERATE":
			in.Moderate = c.Versions
		}
	}
	for _, c := range r.RepoSignals {
		switch c.Name {
		case "unmaintained":
			in.Unmaintained = c.Versions
		case "dangerous-workflow":
			in.DangerousWorkflow = c.Versions
		case "unreviewed-code":
			in.UnreviewedCode = c.Versions
		}
	}
	return score.Compute(in)
}

func sortedIntKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// plural2 picks between two irregular forms, where plural's "add an s" does not
// apply.
func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Package score reduces a report to one number, and shows its working.
//
// A composite score is a lossy summary by construction: it averages "this
// package was hostile and ran with your credentials" against "this project has
// no fuzzing harness". That objection is real and this package does not pretend
// otherwise — it answers it structurally instead.
//
//   - Every term is printed with its inputs and its contribution, so a reader
//     can see which one dominated and argue with that term specifically rather
//     than with the number.
//   - A malicious package CLAMPS the grade to F. Averaging hostile code into a
//     68 is the exact failure the objection describes, so it is made impossible
//     rather than merely unlikely.
//   - Below a coverage threshold there is NO grade. A repository where 15% of
//     packages were auditable has not earned an A by having no findings.
//
// The score is a headline over the layered report, never a replacement for it.
package score

import (
	"fmt"
	"math"
)

// Weights are the maximum contribution of each term, and they are exported so
// the number can be recomputed or disagreed with rather than taken on trust.
const (
	MaxVuln     = 45 // known-vulnerable packages, severity-weighted
	MaxHygiene  = 20 // floating versions: what a rebuild can change under you
	MaxControls = 20 // security tooling absent from CI
	MaxPosture  = 15 // upstream projects that are unmaintained or CI-unsafe
)

// MinCoverage is the auditable share below which no grade is issued. Under it
// the inputs are too sparse for the arithmetic to mean anything, and a
// confident letter would be the most misleading thing the tool could print.
const MinCoverage = 0.5

// ActionClaimWeight is the share of the vulnerability budget that advisories
// against CI actions and pre-commit hooks may ever reach: a ref surface with
// nothing but criticals scores ActionClaimWeight × MaxVuln, no more.
//
// OSV answers an action query by NAME: "this action has a published advisory",
// never "the ref you pinned is affected". Counting that as if a version had
// matched would upgrade the weaker claim the report is careful to keep weak —
// and the discount is the reason these can be scored at all rather than excluded
// as they previously were.
//
// It scales POINTS, not the finding count. Weighting the count instead put the
// factor inside the density's square root, where it delivered its own square
// root — a stated half arriving as 0.845 near saturation, which is where the
// discount is the only thing standing between an unverified claim and an F.
//
// The irony is deliberate and worth stating: an action pinned to a TAG could be
// version-matched, and one pinned to a SHA — the better practice — cannot.
const ActionClaimWeight = 0.5

// SaturationDensity is the severity-weighted findings-per-package ratio at which
// the vulnerability term maxes out, where a critical counts 10, a high 3 and a
// moderate 1. 0.35 is roughly "one critical per thirty packages" — bad enough
// that distinguishing degrees beyond it serves nobody.
const SaturationDensity = 0.35

// Input is everything the score reads. Every field is a count the report
// already computed; nothing here re-queries a network.
type Input struct {
	Checked   int // package versions audited
	Malicious int

	Critical int
	High     int
	Moderate int

	// ActionsChecked and the ActionN counts are the ref surface: CI actions and
	// pre-commit hooks. They are kept apart from Checked rather than added to it
	// because Checked is also the denominator of the POSTURE term, which comes
	// from Scorecard records that exist only for packages. Folding 17 actions
	// into it would dilute that term for every repository that has both.
	ActionsChecked int
	ActionCritical int
	ActionHigh     int
	ActionModerate int

	Floating int // versions no exact constraint holds
	Pinned   int
	Locked   int
	// ActionsFloating and ActionsPinned are the same hygiene question asked of
	// refs: a SHA is reproducible, a tag or branch is whatever it points at
	// today. Without these, a repository whose actions are all `@main` and one
	// whose actions are all `@sha` scored identically.
	ActionsFloating int
	ActionsPinned   int

	ControlsMissing    int
	ControlsTotal      int
	ControlsAssessable bool

	// Posture counts are per-VERSION, from the repo-specific signal set.
	Unmaintained      int
	DangerousWorkflow int
	UnreviewedCode    int

	// Auditable is the share of the gradable surface that could be checked at
	// all — packages AND refs, since a repository may have only the latter.
	Auditable float64
	// Surface is the size of that gradable surface. Zero means there was nothing
	// to grade, which is a different state from having read too little of it,
	// and the two must not print the same reason.
	Surface int
}

// Term is one contribution, with the evidence that produced it.
type Term struct {
	Name   string  `json:"name"`
	Detail string  `json:"detail"`
	Points float64 `json:"points"`
	Max    int     `json:"max"`
}

// Result is the score and its working.
type Result struct {
	// Grade is A..F, or "" when coverage was too thin to issue one.
	Grade string `json:"grade"`
	Score int    `json:"score"` // 0 best, 100 worst
	// Suppressed is set when coverage was insufficient; Grade is then empty and
	// Score must not be presented as a verdict.
	Suppressed bool   `json:"suppressed"`
	Reason     string `json:"reason,omitempty"`
	Terms      []Term `json:"terms"`
}

// Compute derives the score. Deterministic, no I/O, no hidden state.
func Compute(in Input) Result {
	r := Result{Terms: []Term{}}

	// --- malicious -----------------------------------------------------
	// Not a weighted term. Hostile code that already executed is a different
	// KIND of finding, and a number that can average it away is not worth
	// having.
	mal := Term{Name: "malicious", Max: 100,
		Detail: fmt.Sprintf("%d packages", in.Malicious)}
	if in.Malicious > 0 {
		mal.Points = 100
		mal.Detail += " — clamps the grade to F"
	}
	r.Terms = append(r.Terms, mal)

	// --- known vulnerabilities -----------------------------------------
	// Severity-weighted DENSITY, not a raw count: 60 criticals in 6510 packages
	// and 60 in 100 are not the same repository, and a count alone punishes
	// size rather than risk.
	//
	// The two surfaces are scored on SEPARATE curves and then summed, rather than
	// pooled into one density. Pooling was wrong twice over. It diluted package
	// findings — 3 findings in 100 packages became 3 in 117 once refs joined the
	// denominator — and it applied ActionClaimWeight inside a square root, where
	// a weight delivers its own square root: 0.5 arrived as 0.845 at the point it
	// mattered most, so the discount was neither half nor visible.
	vuln := clamp(
		densityPoints(weightedSeverity(in.Critical, in.High, in.Moderate), in.Checked)+
			ActionClaimWeight*densityPoints(
				weightedSeverity(in.ActionCritical, in.ActionHigh, in.ActionModerate),
				in.ActionsChecked),
		MaxVuln)
	vulnDetail := fmt.Sprintf("%d critical, %d high, %d moderate in %d packages",
		in.Critical, in.High, in.Moderate, in.Checked)
	if in.ActionsChecked > 0 {
		vulnDetail += fmt.Sprintf("; %d name-matched in %d refs at %.0f%% weight",
			in.ActionCritical+in.ActionHigh+in.ActionModerate, in.ActionsChecked,
			ActionClaimWeight*100)
	}
	r.Terms = append(r.Terms, Term{Name: "vulnerabilities", Max: MaxVuln, Points: vuln,
		Detail: vulnDetail})

	// --- hygiene --------------------------------------------------------
	// Floating means no exact constraint holds this version: the next rebuild
	// can move it without a single line changing in the repository.
	//
	// Refs count here on the same terms. `uses: actions/checkout@main` is the
	// purest form of the thing this term measures — the next run can execute
	// different code with nothing in the repository having changed — and leaving
	// it out meant pinning every action earned a repository nothing at all.
	var hyg float64
	floating := in.Floating + in.ActionsFloating
	total := in.Floating + in.Pinned + in.Locked + in.ActionsFloating + in.ActionsPinned
	share := 0.0
	if total > 0 {
		share = float64(floating) / float64(total)
		hyg = share * MaxHygiene
	}
	hygDetail := fmt.Sprintf("%.0f%% floating (%d of %d unheld by any exact constraint)",
		share*100, floating, total)
	if in.ActionsFloating+in.ActionsPinned > 0 {
		hygDetail += fmt.Sprintf("; %d of %d refs moving",
			in.ActionsFloating, in.ActionsFloating+in.ActionsPinned)
	}
	r.Terms = append(r.Terms, Term{Name: "hygiene", Max: MaxHygiene, Points: hyg,
		Detail: hygDetail})

	// --- controls -------------------------------------------------------
	var ctl float64
	ctlDetail := "no readable CI — not scored"
	if in.ControlsAssessable && in.ControlsTotal > 0 {
		ctl = float64(in.ControlsMissing) / float64(in.ControlsTotal) * MaxControls
		ctlDetail = fmt.Sprintf("%d of %d categories absent from CI",
			in.ControlsMissing, in.ControlsTotal)
	}
	r.Terms = append(r.Terms, Term{Name: "controls", Max: MaxControls, Points: ctl, Detail: ctlDetail})

	// --- upstream posture ------------------------------------------------
	// Only the signals a maintainer can act on. The ecosystem baseline —
	// unsigned releases, no SLSA provenance — describes open-source publishing
	// in 2026 and would drown every repository equally.
	var pos float64
	posShare := 0.0
	if in.Checked > 0 {
		bad := float64(in.Unmaintained) + float64(in.DangerousWorkflow)*4 + float64(in.UnreviewedCode)
		posShare = bad / float64(in.Checked)
		pos = clamp(posShare*MaxPosture, MaxPosture)
	}
	r.Terms = append(r.Terms, Term{Name: "upstream posture", Max: MaxPosture, Points: pos,
		Detail: fmt.Sprintf("%d unmaintained, %d dangerous-workflow, %d unreviewed",
			in.Unmaintained, in.DangerousWorkflow, in.UnreviewedCode)})

	// --- total -----------------------------------------------------------
	sum := vuln + hyg + ctl + pos
	if in.Malicious > 0 {
		sum = 100
	}
	r.Score = int(sum + 0.5)
	if r.Score > 100 {
		r.Score = 100
	}

	// Coverage is a CONFIDENCE qualifier, never another penalty: a repo we
	// could barely read is not thereby risky, it is unassessed. Adding points
	// for it would punish the tool's own gaps.
	//
	// Nothing-to-grade and too-little-read are different states and had been
	// printing the same sentence. A repository with no dependencies at all was
	// told that 0% of its packages were auditable, which reads as a failure to
	// read it rather than as an accurate description of an empty supply chain.
	switch {
	case in.Surface == 0:
		r.Suppressed = true
		r.Reason = "no packages, actions or hooks were found; there is nothing to grade"
		return r
	case in.Auditable < MinCoverage:
		r.Suppressed = true
		r.Reason = fmt.Sprintf("only %.0f%% of the %d dependencies found were auditable; too sparse to grade",
			in.Auditable*100, in.Surface)
		return r
	}

	switch {
	case in.Malicious > 0:
		r.Grade = "F"
		r.Reason = "a known-malicious package is present"
	case r.Score >= 70:
		r.Grade = "F"
	case r.Score >= 50:
		r.Grade = "D"
	case r.Score >= 35:
		r.Grade = "C"
	case r.Score >= 20:
		r.Grade = "B"
	default:
		r.Grade = "A"
	}
	return r
}

// weightedSeverity is the one place severities become numbers. A critical is
// worth ten moderates and a high three, so a single critical is not lost among
// the noise of a large closure.
func weightedSeverity(critical, high, moderate int) float64 {
	return float64(critical)*10 + float64(high)*3 + float64(moderate)
}

// densityPoints converts a severity-weighted finding count over a surface into
// points out of MaxVuln.
//
// Square root, not linear. A linear term with a realistic saturation point gives
// airflow's 36 HIGH across 3676 packages a single point out of 45, and one with
// an aggressive saturation point saturates react and next.js alike — losing
// exactly the resolution that matters at the bad end. The curve keeps both ends
// readable: airflow ~14, react ~34, next.js ~45.
func densityPoints(weighted float64, checked int) float64 {
	if checked <= 0 {
		return 0
	}
	return MaxVuln * math.Sqrt(min1(weighted/float64(checked)/SaturationDensity))
}

func clamp(v float64, max int) float64 {
	if v > float64(max) {
		return float64(max)
	}
	if v < 0 {
		return 0
	}
	return v
}

func min1(v float64) float64 {
	if v > 1 {
		return 1
	}
	return v
}

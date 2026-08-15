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

	Floating int // versions no exact constraint holds
	Pinned   int
	Locked   int

	ControlsMissing    int
	ControlsTotal      int
	ControlsAssessable bool

	// Posture counts are per-VERSION, from the repo-specific signal set.
	Unmaintained      int
	DangerousWorkflow int
	UnreviewedCode    int

	// Auditable is the share of package nodes that could be checked at all.
	Auditable float64
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
	var vuln float64
	if in.Checked > 0 {
		weighted := float64(in.Critical)*10 + float64(in.High)*3 + float64(in.Moderate)
		density := weighted / float64(in.Checked)
		// Square root, not linear. A linear term with a realistic saturation
		// point gives airflow's 36 HIGH across 3676 packages a single point out
		// of 45, and one with an aggressive one saturates react and next.js
		// alike — losing exactly the resolution that matters at the bad end.
		// The curve keeps both ends readable: airflow ~14, react ~34,
		// next.js ~45.
		vuln = clamp(MaxVuln*math.Sqrt(min1(density/SaturationDensity)), MaxVuln)
	}
	r.Terms = append(r.Terms, Term{Name: "vulnerabilities", Max: MaxVuln, Points: vuln,
		Detail: fmt.Sprintf("%d critical, %d high, %d moderate in %d packages",
			in.Critical, in.High, in.Moderate, in.Checked)})

	// --- hygiene --------------------------------------------------------
	// Floating means no exact constraint holds this version: the next rebuild
	// can move it without a single line changing in the repository.
	var hyg float64
	total := in.Floating + in.Pinned + in.Locked
	share := 0.0
	if total > 0 {
		share = float64(in.Floating) / float64(total)
		hyg = share * MaxHygiene
	}
	r.Terms = append(r.Terms, Term{Name: "hygiene", Max: MaxHygiene, Points: hyg,
		Detail: fmt.Sprintf("%.0f%% floating (%d of %d versions unheld by any exact constraint)",
			share*100, in.Floating, total)})

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
	if in.Auditable < MinCoverage {
		r.Suppressed = true
		r.Reason = fmt.Sprintf("only %.0f%% of packages were auditable; too sparse to grade",
			in.Auditable*100)
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

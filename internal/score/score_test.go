package score_test

import (
	"math"
	"testing"

	"github.com/jverhoeks/deepdep/internal/score"
)

func base() score.Input {
	return score.Input{
		Checked: 1000, Pinned: 900, Locked: 100,
		ControlsTotal: 9, ControlsMissing: 0, ControlsAssessable: true,
		Auditable: 1.0, Surface: 1000,
	}
}

// A repository whose whole supply chain is CI actions and pre-commit hooks used
// to be ungraded whatever it did, because coverage counted only PACKAGE nodes:
// six pinned actions gave 0/0, and the reason printed was "too sparse to grade"
// for a repository that had in fact been read completely. 17% of the scanned
// fleet was in this state.
func TestRefOnlyRepositoryIsGradable(t *testing.T) {
	in := score.Input{
		ActionsChecked: 6, ActionsPinned: 6,
		ControlsTotal: 9, ControlsMissing: 2, ControlsAssessable: true,
		Auditable: 1.0, Surface: 6,
	}
	got := score.Compute(in)
	if got.Suppressed {
		t.Fatalf("suppressed a fully-read repository: %s", got.Reason)
	}
	if got.Grade != "A" {
		t.Errorf("grade = %q (score %d), want A for six pinned, advisory-free refs",
			got.Grade, got.Score)
	}
}

// Pinning must be what EARNS that grade, not the absence of anything to count.
// Actions never reached version_rollup, so hygiene read 0 of 0 versions and an
// all-@main repository scored identically to an all-@sha one.
func TestMovingRefsCostHygiene(t *testing.T) {
	pinned := score.Input{ActionsChecked: 6, ActionsPinned: 6,
		ControlsTotal: 9, ControlsAssessable: true, Auditable: 1.0, Surface: 6}
	moving := score.Input{ActionsChecked: 6, ActionsFloating: 6,
		ControlsTotal: 9, ControlsAssessable: true, Auditable: 1.0, Surface: 6}
	p, m := score.Compute(pinned), score.Compute(moving)
	if m.Score <= p.Score {
		t.Errorf("six @main refs scored %d and six @sha refs %d; pinning must count",
			m.Score, p.Score)
	}
	if m.Score-p.Score != score.MaxHygiene {
		t.Errorf("hygiene gap = %d, want the full %d: every ref is moving",
			m.Score-p.Score, score.MaxHygiene)
	}
}

// An advisory against an action is a NAME match — "this action has one" — not
// "the SHA you pinned is affected". It must move the grade, or a repository
// whose only dependency carries a HIGH is indistinguishable from a clean one;
// and it must move it LESS than a version-matched finding, or the report's
// careful weaker claim is silently upgraded.
func TestActionAdvisoriesCountAtADiscount(t *testing.T) {
	clean := score.Input{ActionsChecked: 6, ActionsPinned: 6,
		ControlsTotal: 9, ControlsAssessable: true, Auditable: 1.0, Surface: 6}
	hit := clean
	hit.ActionHigh = 1
	if score.Compute(hit).Score <= score.Compute(clean).Score {
		t.Error("a HIGH advisory in the only dependency did not move the score")
	}

	// Same finding, same surface size, matched against a package version. The
	// RATIO is asserted, not merely the ordering: weighting the finding count
	// instead of the points put the factor inside the density's square root,
	// where a stated half arrived as 0.845 — an ordering-only assertion passes
	// against that and cannot tell the intended discount from a nullified one.
	matched := score.Input{Checked: 6, Pinned: 6, High: 1,
		ControlsTotal: 9, ControlsAssessable: true, Auditable: 1.0, Surface: 6}
	weak := score.Input{ActionsChecked: 6, ActionsPinned: 6, ActionHigh: 1,
		ControlsTotal: 9, ControlsAssessable: true, Auditable: 1.0, Surface: 6}
	mv, wv := vulnPoints(t, matched), vulnPoints(t, weak)
	if got := wv / mv; math.Abs(got-score.ActionClaimWeight) > 1e-9 {
		t.Errorf("name-matched scored %.3f of version-matched (%.1f vs %.1f); want exactly %.2f",
			got, wv, mv, score.ActionClaimWeight)
	}
}

// A ref surface may never dominate the vulnerability budget, however many
// advisories it carries.
func TestActionAdvisoriesAreCappedAtTheirShare(t *testing.T) {
	in := score.Input{ActionsChecked: 3, ActionsPinned: 3, ActionCritical: 3,
		ControlsTotal: 9, ControlsAssessable: true, Auditable: 1.0, Surface: 3}
	want := score.ActionClaimWeight * score.MaxVuln
	if got := vulnPoints(t, in); math.Abs(got-want) > 1e-9 {
		t.Errorf("a wholly critical ref surface scored %.1f of %d; want the %.1f cap",
			got, score.MaxVuln, want)
	}
}

// Package findings must not be diluted by the ref surface. Pooling both into one
// density turned 3 findings in 100 packages into 3 in 117 the moment a workflow
// file appeared, quietly improving the grade of every repository that has CI.
func TestRefsDoNotDilutePackageFindings(t *testing.T) {
	without := score.Input{Checked: 100, Pinned: 100, High: 3,
		ControlsTotal: 9, ControlsAssessable: true, Auditable: 1.0, Surface: 100}
	with := without
	with.ActionsChecked, with.ActionsPinned, with.Surface = 17, 17, 117
	if a, b := vulnPoints(t, without), vulnPoints(t, with); math.Abs(a-b) > 1e-9 {
		t.Errorf("adding 17 advisory-free refs moved the term %.2f -> %.2f", a, b)
	}
}

func vulnPoints(t *testing.T, in score.Input) float64 {
	t.Helper()
	for _, term := range score.Compute(in).Terms {
		if term.Name == "vulnerabilities" {
			return term.Points
		}
	}
	t.Fatal("no vulnerabilities term")
	return 0
}

// Nothing-to-grade and too-little-read are different states. A repository with
// no dependencies at all was told 0% of its packages were auditable, which reads
// as our failure to read it rather than as an empty supply chain.
func TestEmptyAndUnreadableSuppressDifferently(t *testing.T) {
	empty := score.Compute(score.Input{ControlsTotal: 9, ControlsAssessable: true})
	thin := score.Compute(score.Input{Checked: 1, Surface: 10, Auditable: 0.1,
		ControlsTotal: 9, ControlsAssessable: true})
	if !empty.Suppressed || !thin.Suppressed {
		t.Fatal("both states must suppress the grade")
	}
	if empty.Reason == thin.Reason {
		t.Errorf("both printed %q; an empty repo and an unread one are not the same finding",
			empty.Reason)
	}
}

// TestMaliciousClampsToF is the rule the whole design turns on. Averaging
// hostile code that already ran with your credentials into a mid-range number
// is the exact failure a composite score is accused of, so it is made
// impossible rather than merely unlikely.
func TestMaliciousClampsToF(t *testing.T) {
	in := base() // otherwise a perfect repository
	in.Malicious = 1
	got := score.Compute(in)
	if got.Grade != "F" {
		t.Errorf("grade = %q, want F", got.Grade)
	}
	if got.Score != 100 {
		t.Errorf("score = %d, want 100", got.Score)
	}
	if got.Reason == "" {
		t.Error("the clamp must say why, or an F on a clean repo looks like a bug")
	}
}

// TestLowCoverageSuppressesTheGrade. home-assistant had 15% of its packages
// auditable and zero findings. That is not an A; it is an unanswered question,
// and a confident letter would be the most misleading thing we could print.
func TestLowCoverageSuppressesTheGrade(t *testing.T) {
	in := base()
	in.Auditable = 0.15
	got := score.Compute(in)
	if got.Grade != "" {
		t.Errorf("grade = %q, want none at 15%% coverage", got.Grade)
	}
	if !got.Suppressed || got.Reason == "" {
		t.Error("suppression must be explicit and explained")
	}
	// Terms are still computed: the reader can see what little was measured.
	if len(got.Terms) == 0 {
		t.Error("terms must survive suppression")
	}
}

// TestCoverageIsNotAPenalty: a repo we could barely read is unassessed, not
// risky. Charging points for our own blind spots would invert the meaning.
func TestCoverageIsNotAPenalty(t *testing.T) {
	full, thin := base(), base()
	thin.Auditable = 0.6 // above the threshold, but well below full
	if score.Compute(full).Score != score.Compute(thin).Score {
		t.Error("coverage changed the score; it may only gate the grade")
	}
}

// TestSeverityIsDensityNotCount: 60 criticals in 6510 packages and 60 in 100
// are not the same repository. A raw count punishes size rather than risk.
func TestSeverityIsDensityNotCount(t *testing.T) {
	big, small := base(), base()
	big.Checked, big.Critical = 6510, 60
	small.Checked, small.Critical = 100, 60
	b, s := score.Compute(big), score.Compute(small)
	if s.Score <= b.Score {
		t.Errorf("small repo %d must score worse than large repo %d for the same count",
			s.Score, b.Score)
	}
}

// TestCleanRepoScoresA — the scale has to reach the good end, or a grade
// carries no information.
func TestCleanRepoScoresA(t *testing.T) {
	got := score.Compute(base())
	if got.Grade != "A" {
		t.Errorf("grade = %q (score %d), want A for a clean fully-pinned repo with all controls",
			got.Grade, got.Score)
	}
}

// TestUnreadableCIIsNotScored: kubernetes runs Prow. Charging it 20 points for
// "no controls" would be a claim about their engineering rather than about our
// coverage.
func TestUnreadableCIIsNotScored(t *testing.T) {
	in := base()
	in.ControlsAssessable, in.ControlsMissing = false, 9
	for _, term := range score.Compute(in).Terms {
		if term.Name == "controls" && term.Points != 0 {
			t.Errorf("controls scored %v with no readable CI", term.Points)
		}
	}
}

// TestEveryTermShowsItsInputs. The number is only defensible if a reader can
// see which term produced it and disagree with that term.
func TestEveryTermShowsItsInputs(t *testing.T) {
	in := base()
	in.Critical, in.Floating, in.Pinned = 3, 200, 700
	in.Unmaintained, in.ControlsMissing = 40, 4
	for _, term := range score.Compute(in).Terms {
		if term.Detail == "" {
			t.Errorf("term %q carries no evidence", term.Name)
		}
		if term.Points > float64(term.Max) {
			t.Errorf("term %q = %v exceeds its cap %d", term.Name, term.Points, term.Max)
		}
	}
}

// TestScoreIsBounded regardless of how bad the inputs get.
func TestScoreIsBounded(t *testing.T) {
	in := score.Input{
		Checked: 10, Critical: 5000, High: 9000, Moderate: 9000,
		Floating: 10, ControlsTotal: 9, ControlsMissing: 9, ControlsAssessable: true,
		Unmaintained: 9000, DangerousWorkflow: 9000, UnreviewedCode: 9000,
		Auditable: 1.0, Surface: 10,
	}
	got := score.Compute(in)
	if got.Score > 100 || got.Score < 0 {
		t.Errorf("score = %d, out of range", got.Score)
	}
	if got.Grade != "F" {
		t.Errorf("grade = %q, want F", got.Grade)
	}
}

package score_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/score"
)

func base() score.Input {
	return score.Input{
		Checked: 1000, Pinned: 900, Locked: 100,
		ControlsTotal: 9, ControlsMissing: 0, ControlsAssessable: true,
		Auditable: 1.0,
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
		Auditable: 1.0,
	}
	got := score.Compute(in)
	if got.Score > 100 || got.Score < 0 {
		t.Errorf("score = %d, out of range", got.Score)
	}
	if got.Grade != "F" {
		t.Errorf("grade = %q, want F", got.Grade)
	}
}

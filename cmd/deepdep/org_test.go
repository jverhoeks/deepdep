package main

import (
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/forge"
	"github.com/jverhoeks/deepdep/internal/score"
)

func repoResult(name string, r reportDoc) orgRepo {
	return orgRepo{Repo: forge.Repo{FullName: name}, Report: &r}
}

// A fleet summary that quietly omitted the repository whose clone timed out
// would read as a smaller, cleaner organisation than the one that exists. The
// funnel is only honest if a failure is countable.
func TestOrgReportCountsFailuresRatherThanDroppingThem(t *testing.T) {
	d := buildOrgReport("acme", []orgRepo{
		repoResult("acme/ok", reportDoc{Score: score.Result{Grade: "B", Score: 30}}),
		{Repo: forge.Repo{FullName: "acme/broken"}, Err: "context deadline exceeded"},
	})
	if d.Total != 2 || d.Scanned != 1 || d.Failed != 1 {
		t.Errorf("funnel = total %d scanned %d failed %d, want 2/1/1", d.Total, d.Scanned, d.Failed)
	}
	if len(d.Failures) != 1 || d.Failures[0].Repo != "acme/broken" {
		t.Errorf("failure not named: %+v", d.Failures)
	}
	out := string(renderOrg(d, 0))
	if !strings.Contains(out, "acme/broken") {
		t.Errorf("a failed repository must appear in the output:\n%s", out)
	}
}

// A repository too sparse to grade is UNASSESSED, not clean. Rolling it into
// the grade distribution would let a repo nobody could read improve an average.
func TestOrgReportKeepsUngradedOutOfTheDistribution(t *testing.T) {
	d := buildOrgReport("acme", []orgRepo{
		repoResult("acme/graded", reportDoc{Score: score.Result{Grade: "C", Score: 40}}),
		repoResult("acme/sparse", reportDoc{Score: score.Result{
			Suppressed: true, Reason: "only 12% of packages were auditable"}}),
	})
	if d.Graded != 1 || d.Ungraded != 1 {
		t.Errorf("graded %d ungraded %d, want 1/1", d.Graded, d.Ungraded)
	}
	total := 0
	for _, g := range d.Grades {
		total += g.Versions
	}
	if total != 1 {
		t.Errorf("grade distribution counts %d, want only the graded one", total)
	}
	out := string(renderOrg(d, 0))
	if !strings.Contains(out, "UNASSESSED, not clean") {
		t.Errorf("ungraded repositories must not read as clean:\n%s", out)
	}
}

// Worst first, and malicious code outranks everything — the same order the
// single-repository report uses, so a reader moving between them is not
// re-learning the ranking.
func TestOrgReportRanksMaliciousAboveEverything(t *testing.T) {
	d := buildOrgReport("acme", []orgRepo{
		repoResult("acme/many-crits", reportDoc{
			Score: score.Result{Grade: "F", Score: 90},
			BySev: []count{{Name: "CRITICAL", Versions: 40}}}),
		repoResult("acme/one-worm", reportDoc{
			Score:     score.Result{Grade: "F", Score: 100},
			Malicious: []finding{{ID: "MAL-2025-1", Package: "npm/x@1"}}}),
	})
	if d.Repos[0].Repo != "acme/one-worm" {
		t.Errorf("ranked %q first; hostile code outranks any number of criticals",
			d.Repos[0].Repo)
	}
}

// The reach split must survive aggregation: summing direct into inherited would
// destroy the only distinction that says whose job a finding is.
func TestOrgReportKeepsDirectAndInheritedApart(t *testing.T) {
	d := buildOrgReport("acme", []orgRepo{
		repoResult("acme/a", reportDoc{Score: score.Result{Grade: "C"}, Exposure: []exposureRow{
			{Reach: "direct", Surface: "manifest", Checked: 10, Affected: 2, Critical: 1},
			{Reach: "indirect", Checked: 500, Affected: 5},
		}}),
		repoResult("acme/b", reportDoc{Score: score.Result{Grade: "C"}, Exposure: []exposureRow{
			{Reach: "direct", Surface: "manifest", Checked: 20, Affected: 1},
			{Reach: "indirect", Checked: 300, Affected: 3},
		}}),
	})
	var direct, inherited *exposureRow
	for i := range d.Exposure {
		if d.Exposure[i].Reach == "direct" {
			direct = &d.Exposure[i]
		} else {
			inherited = &d.Exposure[i]
		}
	}
	if direct == nil || direct.Checked != 30 || direct.Affected != 3 || direct.Critical != 1 {
		t.Errorf("direct bucket = %+v, want 30 checked / 3 affected / 1 critical", direct)
	}
	if inherited == nil || inherited.Checked != 800 || inherited.Affected != 8 {
		t.Errorf("inherited bucket = %+v, want 800 checked / 8 affected", inherited)
	}
	if d.Repos[0].Declared+d.Repos[1].Declared != 30 {
		t.Error("per-repo declared counts must sum to the org's direct total")
	}
}

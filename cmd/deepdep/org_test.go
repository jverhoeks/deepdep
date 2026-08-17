package main

import (
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/forge"
	"github.com/jverhoeks/deepdep/internal/reach"
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
		// Surface is what separates "we read too little of it" from "there was
		// nothing to read", and the two must not print the same line.
		repoResult("acme/sparse", reportDoc{Surface: 40, Score: score.Result{
			Suppressed: true, Reason: "only 12% of packages were auditable"}}),
		repoResult("acme/empty", reportDoc{Surface: 0, Score: score.Result{
			Suppressed: true, Reason: "nothing to grade"}}),
	})
	if d.Graded != 1 || d.Ungraded != 2 || d.Empty != 1 {
		t.Errorf("graded %d ungraded %d empty %d, want 1/2/1", d.Graded, d.Ungraded, d.Empty)
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
	if !strings.Contains(out, "no packages, actions or hooks found") {
		t.Errorf("an empty repository must not be reported as one we failed to read:\n%s", out)
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

// The fleet blast radius exists to find the upgrade worth doing ONCE. Nine
// repositories on nine versions of one library are still one upgrade to plan, so
// the rollup keys on the name — keying on the versioned id scattered them into
// nine rows of one repository each, which is exactly the shape that hides it.
func TestOrgBlastRadiusCollapsesVersionsAndRanksByRepos(t *testing.T) {
	d := buildOrgReport("acme", []orgRepo{
		repoResult("acme/one", reportDoc{
			Surface: 10, Score: score.Result{Grade: "C", Score: 40},
			Introducers: []reach.Introducer{
				{Direct: "pkg:cargo/tauri@2.0.0", Affected: 5},
				{Direct: "pkg:npm/lodash@4.0.0", Affected: 40},
			},
			IndirectRisk: []count{{Name: "unmaintained", Versions: 3}},
		}),
		repoResult("acme/two", reportDoc{
			Surface: 10, Score: score.Result{Grade: "B", Score: 25},
			// A DIFFERENT version of the same library: one upgrade, not two.
			Introducers: []reach.Introducer{
				{Direct: "pkg:cargo/tauri@2.11.1", Affected: 4},
			},
			IndirectRisk: []count{{Name: "unmaintained", Versions: 2}},
		}),
	})

	if len(d.Introducers) != 2 {
		t.Fatalf("got %d introducers, want 2 after collapsing versions: %+v",
			len(d.Introducers), d.Introducers)
	}
	top := d.Introducers[0]
	if top.Name != "cargo/tauri" {
		t.Errorf("top = %q (repos %d, affected %d); want cargo/tauri — two repositories "+
			"outrank one repository's larger count", top.Name, top.Repos, top.Affected)
	}
	if top.Repos != 2 || top.Affected != 9 {
		t.Errorf("tauri = %d repos / %d affected, want 2 / 9", top.Repos, top.Affected)
	}

	risk := map[string]int{}
	for _, c := range d.IndirectRisk {
		risk[c.Name] = c.Versions
	}
	if risk["unmaintained"] != 5 {
		t.Errorf("unmaintained = %d, want 5 summed across the fleet", risk["unmaintained"])
	}

	// The render is the deliverable; both blocks are gated on non-empty slices
	// and had never executed.
	out := string(renderOrg(d, 0))
	for _, want := range []string{"BLAST RADIUS", "cargo/tauri", "INDIRECT RISK", "unmaintained"} {
		if !strings.Contains(out, want) {
			t.Errorf("fleet report is missing %q:\n%s", want, out)
		}
	}
}

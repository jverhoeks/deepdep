package supply

import (
	"sort"
	"strings"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// Signal is one named supply-chain observation about a package version.
//
// There is deliberately no composite score. A 0-100 number would average a
// deprecated package that nobody will ever patch together with a project that
// merely lacks a fuzzing harness, and the reader would lose exactly the
// distinction that makes the report actionable — the same reason the rollup
// carries no worst-case package badge.
type Signal struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// Assessment is every signal for one package version.
type Assessment struct {
	NodeID     graph.NodeID `json:"node_id"`
	SourceRepo string       `json:"source_repo,omitempty"`
	Signals    []Signal     `json:"signals,omitempty"`
}

// Has reports whether the assessment carries a given signal code.
func (a Assessment) Has(code string) bool {
	for _, s := range a.Signals {
		if s.Code == code {
			return true
		}
	}
	return false
}

// scorecardRule maps an OpenSSF Scorecard check to a signal.
//
// atOrBelow is the threshold on a 0-10 score. Most are 0 because those checks
// are effectively binary: Branch-Protection scores 0 when it is simply off.
// Pinned-Dependencies is graded, so a low-but-nonzero score still means most of
// the project's own build floats.
var scorecardRules = []struct {
	check     string
	atOrBelow int
	code      string
	detail    string
}{
	{"Maintained", 0, "unmaintained",
		"no commit or issue activity in the last 90 days, or the repo is archived"},
	{"Dangerous-Workflow", 0, "dangerous-workflow",
		"CI workflow has an untrusted-input injection or untrusted checkout pattern"},
	{"Code-Review", 0, "unreviewed-code",
		"changes merge without review; one compromised maintainer account is sufficient"},
	{"Branch-Protection", 0, "no-branch-protection",
		"release branch accepts force-push and unreviewed direct commits"},
	{"Token-Permissions", 0, "overprivileged-ci",
		"CI grants write-all tokens to workflow steps"},
	{"Pinned-Dependencies", 2, "unpinned-upstream-build",
		"the project's own build pulls floating dependencies"},
	{"Signed-Releases", 0, "unsigned-releases",
		"releases are published without signatures"},
}

// Assess turns raw deps.dev documents into named signals.
//
// A Scorecard score of -1 means THE CHECK DID NOT RUN — "no releases found" for
// Signed-Releases, "packaging workflow not detected" for Packaging. Treating it
// as a zero would bury the genuine zeros under hundreds of non-findings, so
// every rule below tests `>= 0` first.
func Assess(facts []Fact, projects map[string]Project) []Assessment {
	out := make([]Assessment, 0, len(facts))
	for _, f := range facts {
		a := Assessment{NodeID: f.NodeID, SourceRepo: f.SourceRepo}

		if !f.Queried {
			// Outside deps.dev's coverage (a container image, an OS package).
			// Silent by design: it is neither a finding nor a gap in the data,
			// just a question this source cannot answer.
			out = append(out, a)
			continue
		}
		if !f.Known {
			// Not "clean" — unexamined. An internal package, a private-index
			// package, and a typosquat-shaped name all land here.
			// A workspace package resolved from a local path lands here and is
			// benign; a name resolved from an index is the dependency-confusion
			// surface. deps.dev cannot tell them apart, so neither do we — but
			// saying "unlisted" without saying what to check would leave the
			// reader with a count and no next step.
			a.Signals = append(a.Signals, Signal{"unlisted",
				"no public registry record; check whether it resolves from a local " +
					"path (benign) or by name from an index (confusable)"})
			out = append(out, a)
			continue
		}

		if f.Deprecated {
			d := f.DeprecatedReason
			if d == "" {
				d = "publisher marked this version deprecated"
			}
			a.Signals = append(a.Signals, Signal{"deprecated", d})
		}

		switch {
		case len(f.Licenses) == 0:
			a.Signals = append(a.Signals, Signal{"no-license",
				"no license recorded; redistribution terms are undetermined"})
		case hasNonStandardLicense(f.Licenses):
			a.Signals = append(a.Signals, Signal{"non-standard-license",
				strings.Join(f.Licenses, ", ")})
		}

		switch {
		case f.SourceRepo == "":
			a.Signals = append(a.Signals, Signal{"no-source-repo",
				"published artifact is not attributable to any source repository"})
		case f.RepoProvenance != "SLSA_ATTESTATION":
			// The scorecard below describes a repo linked only by publisher
			// metadata. It may not be the source of what actually installed.
			a.Signals = append(a.Signals, Signal{"unattested-source",
				"source repo linked by " + strings.ToLower(f.RepoProvenance) +
					" only; provenance not verified"})
		}

		if p, ok := projects[f.SourceRepo]; ok && p.HasScorecard {
			for _, r := range scorecardRules {
				score, ran := p.Checks[r.check]
				if !ran || score < 0 { // -1 == check did not run
					continue
				}
				if score <= r.atOrBelow {
					a.Signals = append(a.Signals, Signal{r.code, r.detail})
				}
			}
		} else if f.SourceRepo != "" {
			a.Signals = append(a.Signals, Signal{"no-scorecard",
				"no OpenSSF Scorecard for " + f.SourceRepo})
		}

		out = append(out, a)
	}
	return out
}

func hasNonStandardLicense(ls []string) bool {
	for _, l := range ls {
		if strings.EqualFold(l, "non-standard") || l == "" {
			return true
		}
	}
	return false
}

// signalOrder ranks signals for a report read top-down. It is a presentation
// order, not a severity score: nothing sums these.
var signalOrder = map[string]int{
	"deprecated":              0,
	"unlisted":                1,
	"unmaintained":            2,
	"dangerous-workflow":      3,
	"unreviewed-code":         4,
	"no-branch-protection":    5,
	"overprivileged-ci":       6,
	"no-source-repo":          7,
	"unsigned-releases":       8,
	"unpinned-upstream-build": 9,
	"no-license":              10,
	"non-standard-license":    11,
	"unattested-source":       12,
	"no-scorecard":            13,
}

// Rank returns a signal's presentation order; unknown codes sort last.
func Rank(code string) int {
	if r, ok := signalOrder[code]; ok {
		return r
	}
	return len(signalOrder)
}

// Codes returns every signal code in presentation order.
func Codes() []string {
	out := make([]string, 0, len(signalOrder))
	for c := range signalOrder {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return Rank(out[i]) < Rank(out[j]) })
	return out
}

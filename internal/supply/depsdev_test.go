package supply_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/supply"
)

// TestFactsCorrelateByIndexNotByEchoedPURL is the whole reason this client is
// hand-written. deps.dev normalises the purl it echoes back: an underscore
// becomes a dash, "5.0" becomes "5.0.0". A client that keys results on that
// echo attributes one package's facts to another.
func TestFactsCorrelateByIndexNotByEchoedPURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"responses":[
          {"request":{"purl":"pkg:pypi/annotated-types@0.7.0"},
           "result":{"version":{"isDeprecated":false,"licenses":["MIT"]}}},
          {"request":{"purl":"pkg:pypi/boolean-py@5.0.0"},
           "result":{"version":{"isDeprecated":true,"deprecatedReason":"moved"}}}
        ]}`)
	}))
	defer srv.Close()

	// Neither input string appears verbatim in the response.
	in := []graph.NodeID{"pkg:pypi/annotated_types@0.7.0", "pkg:pypi/boolean-py@5.0"}
	got, err := supply.New(srv.URL, srv.Client()).Facts(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("facts = %d, want 2", len(got))
	}
	for i, want := range in {
		if got[i].NodeID != want {
			t.Errorf("fact[%d].NodeID = %q, want %q — results must keep the CALLER's id", i, got[i].NodeID, want)
		}
	}
	if got[0].Deprecated {
		t.Error("annotated-types marked deprecated: facts crossed between packages")
	}
	if !got[1].Deprecated {
		t.Error("boolean-py lost its deprecation: facts crossed between packages")
	}
}

// TestMissingResultIsUnknownNotClean guards the failure mode where an internal
// or private-index package silently reads as "no risk found".
func TestMissingResultIsUnknownNotClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"responses":[
          {"request":{"purl":"pkg:pypi/chameleon-cli@0.1.0"}},
          {"request":{"purl":"pkg:npm/nanoid@3.3.17"},
           "result":{"version":{"licenses":["MIT"]}}}
        ]}`)
	}))
	defer srv.Close()

	got, err := supply.New(srv.URL, srv.Client()).Facts(context.Background(),
		[]graph.NodeID{"pkg:pypi/chameleon-cli@0.1.0", "pkg:npm/nanoid@3.3.17"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Known {
		t.Error("a response with no result must be Known=false")
	}
	if !got[1].Known {
		t.Error("a response with a result must be Known=true")
	}

	as := supply.Assess(got, nil)
	if !as[0].Has("unlisted") {
		t.Errorf("unknown package signals = %+v, want unlisted", as[0].Signals)
	}
}

// TestFactsChunkAtHundred pins the batch size. The server caps at 100 and
// returns a nextPageToken instead of an error, so sending more loses packages
// with no diagnostic at all.
func TestFactsChunkAtHundred(t *testing.T) {
	var (
		mu    sync.Mutex
		sizes []int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Requests []struct {
				PURL string `json:"purl"`
			} `json:"requests"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		sizes = append(sizes, len(body.Requests))
		mu.Unlock()

		var sb strings.Builder
		sb.WriteString(`{"responses":[`)
		for i, rq := range body.Requests {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"request":{"purl":%q},"result":{"version":{"licenses":["MIT"]}}}`, rq.PURL)
		}
		sb.WriteString(`]}`)
		fmt.Fprint(w, sb.String())
	}))
	defer srv.Close()

	var in []graph.NodeID
	for i := 0; i < 250; i++ {
		in = append(in, graph.NodeID(fmt.Sprintf("pkg:npm/p%03d@1.0.0", i)))
	}
	c := supply.New(srv.URL, srv.Client())
	got, err := c.Facts(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 250 {
		t.Fatalf("facts = %d, want 250", len(got))
	}
	for _, n := range sizes {
		if n > 100 {
			t.Errorf("sent a batch of %d; deps.dev silently truncates above 100", n)
		}
	}
	for i, f := range got {
		if f.NodeID != in[i] || !f.Known {
			t.Fatalf("fact[%d] = %+v, want %q known", i, f, in[i])
		}
	}
}

// TestShortBatchResponseIsAnError: index correlation is only sound when the
// response is the same length as the request. Guessing which entries were
// dropped is worse than failing.
func TestShortBatchResponseIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"responses":[{"request":{"purl":"a"},"result":{"version":{}}}],
                        "nextPageToken":"more"}`)
	}))
	defer srv.Close()

	_, err := supply.New(srv.URL, srv.Client()).Facts(context.Background(),
		[]graph.NodeID{"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"})
	if err == nil {
		t.Fatal("a truncated batch must be an error, never a silently short answer")
	}
	if !strings.Contains(err.Error(), "index correlation") {
		t.Errorf("err = %v, want it to name the reason", err)
	}
}

// TestScorecardMinusOneIsNotAFinding: -1 means the check DID NOT RUN.
func TestScorecardMinusOneIsNotAFinding(t *testing.T) {
	facts := []supply.Fact{{
		NodeID: "pkg:npm/x@1.0.0", Queried: true, Known: true, Licenses: []string{"MIT"},
		SourceRepo: "github.com/o/r", RepoProvenance: "SLSA_ATTESTATION",
	}}
	projects := map[string]supply.Project{"github.com/o/r": {
		ID: "github.com/o/r", HasScorecard: true,
		Checks: map[string]supply.Check{
			"Signed-Releases":     {Score: -1}, // no releases found — not a weakness
			"Pinned-Dependencies": {Score: -1},
			"Maintained":          {Score: 10},
			"Code-Review": {Score: 0, Reason: "found 1/30 approved changesets", // a REAL zero
				Warnings: []string{"no reviews found: .github/workflows/ci.yml:12"}},
		},
	}}

	a := supply.Assess(facts, projects)[0]
	if a.Has("unsigned-releases") || a.Has("unpinned-upstream-build") {
		t.Errorf("signals = %+v; score -1 means the check did not run", a.Signals)
	}
	if !a.Has("unreviewed-code") {
		t.Errorf("signals = %+v, want unreviewed-code from the genuine 0", a.Signals)
	}
}

// TestUnverifiedSourceLinkIsFlagged: a scorecard reached through publisher
// metadata may describe a repo that is not the source of what installed.
func TestUnverifiedSourceLinkIsFlagged(t *testing.T) {
	attested := supply.Assess([]supply.Fact{{
		NodeID: "pkg:npm/a@1.0.0", Queried: true, Known: true, Licenses: []string{"MIT"},
		SourceRepo: "github.com/o/r", RepoProvenance: "SLSA_ATTESTATION",
	}}, map[string]supply.Project{"github.com/o/r": {HasScorecard: true, Checks: map[string]supply.Check{}}})[0]
	if attested.Has("unattested-source") {
		t.Error("an SLSA-attested source link must not be flagged")
	}

	metadata := supply.Assess([]supply.Fact{{
		NodeID: "pkg:npm/b@1.0.0", Queried: true, Known: true, Licenses: []string{"MIT"},
		SourceRepo: "github.com/o/r", RepoProvenance: "UNVERIFIED_METADATA",
	}}, map[string]supply.Project{"github.com/o/r": {HasScorecard: true, Checks: map[string]supply.Check{}}})[0]
	if !metadata.Has("unattested-source") {
		t.Errorf("signals = %+v, want unattested-source", metadata.Signals)
	}
}

// TestProjectsDedupeAndEncodeSlashes: every @babel/* package shares one project,
// and the project id's slashes are part of a single path segment.
func TestProjectsDedupeAndEncodeSlashes(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		fmt.Fprint(w, `{"starsCount":42,"scorecard":{"overallScore":6.5,"checks":[
          {"name":"Maintained","score":10},
          {"name":"Dangerous-Workflow","score":0,"reason":"dangerous workflow patterns detected",
           "details":["Warn: untrusted code checkout: .github/workflows/ci.yml:26",
                      "Info: this line is context, not a finding"]}]}}`)
	}))
	defer srv.Close()

	got, _, err := supply.New(srv.URL, srv.Client()).Projects(context.Background(),
		[]string{"github.com/babel/babel", "github.com/babel/babel", "", "github.com/ai/nanoid"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("projects = %d, want 2 (deduped, empty dropped)", len(got))
	}
	if len(paths) != 2 {
		t.Fatalf("fetched %d times, want 2 — duplicates must not refetch", len(paths))
	}
	for _, p := range paths {
		if strings.Count(p, "/") != 3 { // /v3/projects/<one-segment>
			t.Errorf("path %q leaks the id's slashes into the URL path", p)
		}
	}
	if got["github.com/ai/nanoid"].Checks["Maintained"].Score != 10 {
		t.Errorf("scorecard not parsed: %+v", got["github.com/ai/nanoid"])
	}
}

// TestDeprecatedLeadsWithItsReason — the most actionable signal must carry the
// publisher's own words, not a generic label.
func TestDeprecatedCarriesPublisherReason(t *testing.T) {
	a := supply.Assess([]supply.Fact{{
		NodeID: "pkg:npm/request@2.88.2", Queried: true, Known: true, Licenses: []string{"Apache-2.0"},
		Deprecated: true, DeprecatedReason: "request has been deprecated, see issues/3142",
		SourceRepo: "github.com/request/request", RepoProvenance: "SLSA_ATTESTATION",
	}}, nil)[0]

	if supply.Rank("deprecated") != 0 {
		t.Error("deprecated must lead the presentation order")
	}
	for _, s := range a.Signals {
		if s.Code == "deprecated" {
			if !strings.Contains(s.Detail, "issues/3142") {
				t.Errorf("detail = %q, want the publisher's reason", s.Detail)
			}
			return
		}
	}
	t.Errorf("no deprecated signal in %+v", a.Signals)
}

// TestUnsupportedEcosystemsAreNotQueried.
//
// deps.dev indexes language ecosystems only, and rejects anything else with a
// 400 that fails the WHOLE batch — one pkg:oci digest aborted a 1400-package
// report. Filtering also keeps container images and OS packages out of the
// `unlisted` bucket, where they would read as three hundred typosquat alarms
// rather than "this source does not cover that question".
func TestUnsupportedEcosystemsAreNotQueried(t *testing.T) {
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Requests []struct {
				PURL string `json:"purl"`
			} `json:"requests"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		var sb strings.Builder
		sb.WriteString(`{"responses":[`)
		for i, rq := range body.Requests {
			sent = append(sent, rq.PURL)
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"request":{"purl":%q},"result":{"version":{"licenses":["MIT"]}}}`, rq.PURL)
		}
		sb.WriteString(`]}`)
		fmt.Fprint(w, sb.String())
	}))
	defer srv.Close()

	in := []graph.NodeID{
		"pkg:npm/lodash@4.17.21",
		"pkg:oci/apache/spark@sha256:e334db96?tag=4.1.2",
		"pkg:deb/debian/curl@7.88.1-10",
		"pkg:pypi/requests@2.32.3",
	}
	got, err := supply.New(srv.URL, srv.Client()).Facts(context.Background(), in)
	if err != nil {
		t.Fatalf("an unsupported purl must not fail the batch: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("facts = %d, want %d — one per input regardless", len(got), len(in))
	}
	for _, s := range sent {
		if strings.HasPrefix(s, "pkg:oci/") || strings.HasPrefix(s, "pkg:deb/") {
			t.Errorf("sent an unsupported purl to deps.dev: %q", s)
		}
	}
	want := map[graph.NodeID]bool{
		"pkg:npm/lodash@4.17.21":                         true,
		"pkg:oci/apache/spark@sha256:e334db96?tag=4.1.2": false,
		"pkg:deb/debian/curl@7.88.1-10":                  false,
		"pkg:pypi/requests@2.32.3":                       true,
	}
	for i, f := range got {
		if f.Queried != want[in[i]] {
			t.Errorf("%s Queried = %v, want %v", in[i], f.Queried, want[in[i]])
		}
	}

	// An unqueried package must produce no signals at all — not `unlisted`.
	for _, a := range supply.Assess(got, nil) {
		if strings.HasPrefix(string(a.NodeID), "pkg:oci/") && a.Has("unlisted") {
			t.Errorf("%s flagged unlisted, but deps.dev was never asked", a.NodeID)
		}
	}
}

// TestScorecardEvidenceIsCapturedAndInfoLinesAreNot.
//
// "CI workflow has an untrusted-input injection pattern" is a rule description
// that fits every flagged project; only Scorecard's own detail says WHICH
// workflow and WHICH line. Scorecard mixes Info lines into the same array as
// context, and several describe settings that are CORRECT — Branch-Protection
// lists "'force pushes' disabled" as Info — so treating them as reasons would
// report good hygiene as a finding.
func TestScorecardEvidenceIsCapturedAndInfoLinesAreNot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"scorecard":{"checks":[
          {"name":"Dangerous-Workflow","score":0,"reason":"dangerous workflow patterns detected",
           "details":["Warn: untrusted code checkout '${{ github.event.pull_request.number }}': .github/workflows/ci.yml:26",
                      "Info: not a finding"]},
          {"name":"Branch-Protection","score":0,"reason":"branch protection not enabled",
           "details":["Info: 'force pushes' disabled on branch 'main'"]}]}}`)
	}))
	defer srv.Close()

	projects, _, err := supply.New(srv.URL, srv.Client()).Projects(context.Background(), []string{"github.com/o/r"})
	if err != nil {
		t.Fatal(err)
	}
	dw := projects["github.com/o/r"].Checks["Dangerous-Workflow"]
	if dw.Reason == "" {
		t.Error("the check's reason was dropped")
	}
	if len(dw.Warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly the Warn line", dw.Warnings)
	}
	if !strings.Contains(dw.Warnings[0], "ci.yml:26") {
		t.Errorf("warning = %q, want the file and line", dw.Warnings[0])
	}
	if strings.Contains(dw.Warnings[0], "Warn:") {
		t.Errorf("warning = %q, want the prefix stripped", dw.Warnings[0])
	}
	// An Info-only check must carry no evidence: "'force pushes' disabled" is
	// good news and must never be printed as a reason the check failed.
	if bp := projects["github.com/o/r"].Checks["Branch-Protection"]; len(bp.Warnings) != 0 {
		t.Errorf("Info lines leaked into evidence: %v", bp.Warnings)
	}

	// And it reaches the signal.
	a := supply.Assess([]supply.Fact{{
		NodeID: "pkg:npm/x@1.0.0", Queried: true, Known: true, Licenses: []string{"MIT"},
		SourceRepo: "github.com/o/r", RepoProvenance: "SLSA_ATTESTATION",
	}}, projects)[0]
	for _, s := range a.Signals {
		if s.Code == "dangerous-workflow" {
			if len(s.Evidence) == 0 {
				t.Error("the signal carries no evidence; the report can only print the generic rule")
			}
			return
		}
	}
	t.Error("no dangerous-workflow signal")
}

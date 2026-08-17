// Package advisory enriches a closure with known vulnerabilities from OSV.
//
// Enrichment is deliberately separate from scanning. Which advisories exist is a
// function of KNOWLEDGE TIME, a query parameter — not a property of the run — so
// baking counts into the scan would un-bitemporalise the whole design. A stored
// run can be re-audited against any instant.
package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// Advisory is one vulnerability record, reduced to what a report needs.
type Advisory struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	// Severity is the QUALITATIVE band (CRITICAL/HIGH/...) or empty. A CVSS
	// vector never goes here: "CVSS_V3:CVSS:3.1/AV:N/AC:L/..." is not a band,
	// sorts as unknown, and rendered one row per vector in a report as though
	// each were its own severity class.
	Severity string `json:"severity"`
	// CVSS is the vector when the record carries one, kept for reference.
	CVSS      string    `json:"cvss,omitempty"`
	Published time.Time `json:"published"`
	Withdrawn time.Time `json:"withdrawn,omitempty"`
	Aliases   []string  `json:"aliases,omitempty"`
}

// Malicious reports whether this record says the package version WAS hostile,
// rather than that it has a flaw.
//
// OSV ingests the OpenSSF malicious-packages feed as MAL-YYYY-NNNNN, and those
// records carry NO severity field — so a naive report sorts the Shai-Hulud worm
// below a moderate ReDoS and labels it "UNKNOWN". The distinction is a
// CATEGORY, not a CVSS band: a CVE says this code has a flaw, a MAL record says
// this code was hostile and you installed it.
func (a Advisory) Malicious() bool {
	if strings.HasPrefix(a.ID, "MAL-") {
		return true
	}
	for _, al := range a.Aliases {
		if strings.HasPrefix(al, "MAL-") {
			return true
		}
	}
	return false
}

// SeverityLabel is what a report should print: the malicious CATEGORY when it
// applies, the CVSS band otherwise.
func (a Advisory) SeverityLabel() string {
	if a.Malicious() {
		return "MALICIOUS"
	}
	if a.Severity == "" {
		return "UNKNOWN"
	}
	return a.Severity
}

// CVE returns the CVE alias if the record has one; OSV ids are often GHSA.
func (a Advisory) CVE() string {
	for _, al := range a.Aliases {
		if strings.HasPrefix(al, "CVE-") {
			return al
		}
	}
	if strings.HasPrefix(a.ID, "CVE-") {
		return a.ID
	}
	return ""
}

// dedupe collapses records that describe the SAME vulnerability in the same
// package.
//
// OSV carries a GHSA record and a CVE record for one flaw, aliased to each
// other, and only the GHSA side usually has a qualitative severity. Listing
// both doubled every authlib finding and made eleven vulnerabilities read as
// twenty-one. The rated record wins; where neither is rated, the id decides so
// the choice is deterministic.
// Dedupe is exported for testing the collapse rule directly.
func Dedupe(in []Finding) []Finding { return dedupe(in) }

func dedupe(in []Finding) []Finding {
	best := map[string]Finding{}
	for _, f := range in {
		key := string(f.NodeID) + "\x00" + f.Advisory.CVE()
		if f.Advisory.CVE() == "" {
			key = string(f.NodeID) + "\x00" + f.Advisory.ID
		}
		cur, ok := best[key]
		if !ok || better(f.Advisory, cur.Advisory) {
			best[key] = f
		}
	}
	out := make([]Finding, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeID != out[j].NodeID {
			return out[i].NodeID < out[j].NodeID
		}
		return out[i].Advisory.ID < out[j].Advisory.ID
	})
	return out
}

func better(a, b Advisory) bool {
	if (a.Severity != "") != (b.Severity != "") {
		return a.Severity != "" // a rated record beats an unrated one
	}
	if (a.Summary != "") != (b.Summary != "") {
		return a.Summary != ""
	}
	return a.ID < b.ID
}

// Finding pairs a package version with an advisory affecting it.
type Finding struct {
	NodeID   graph.NodeID `json:"node_id"`
	Advisory Advisory     `json:"advisory"`
}

// Client queries OSV.
type Client struct {
	base   string
	client *http.Client

	mu    sync.Mutex
	vulns map[string]Advisory // id -> record, fetched once
}

func New(base string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(base, "/"), client: hc, vulns: map[string]Advisory{}}
}

// batchLimit is OSV's documented maximum queries per querybatch request.
const batchLimit = 1000

type batchQuery struct {
	Package struct {
		PURL      string `json:"purl,omitempty"`
		Name      string `json:"name,omitempty"`
		Ecosystem string `json:"ecosystem,omitempty"`
	} `json:"package"`
}

// ActionsEcosystem is OSV's name for GitHub Actions advisories.
//
// They are reachable ONLY by ecosystem+name, and only without a version.
// Verified against OSV in August 2026, for GHSA-mrrh-fwg8-r2c3 — the
// tj-actions/changed-files compromise, the single most cited CI supply-chain
// incident:
//
//	{"purl":"pkg:github/tj-actions/changed-files@45.0.7"}       -> {}
//	{"purl":"pkg:githubactions/tj-actions/changed-files@45.0.7"} -> {}
//	{"name":"tj-actions/changed-files","ecosystem":"GitHub Actions",
//	 "version":"45.0.7"}                                         -> {}
//	{"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"}
//	                        -> GHSA-mcph-m25j-8j63, GHSA-mrrh-fwg8-r2c3
//
// The records carry a null purl and their ranges are stated in a versioning the
// tags do not follow (a ref is `v45`, or a SHA). So the advisory for the most
// cited CI supply-chain compromise is IN the database and every PURL-keyed
// scanner reports the repository using it as clean.
const ActionsEcosystem = "GitHub Actions"

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	} `json:"results"`
}

// ActionAdvisory is deliberately not a Finding.
//
// A Finding says "this exact version is affected", because OSV matched a version
// against the advisory's ranges. For a CI action nothing matched a version:
// OSV answers only the version-less question, so the claim is "this action has a
// published advisory and your ref may or may not be inside it". Those are
// different claims, and a shared type would let the weaker one be counted,
// scored and reported as the stronger one.
//
// It is still worth reporting, loudly. It is the difference between a scanner
// that told you nothing about tj-actions/changed-files and one that told you to
// go and look.
type ActionAdvisory struct {
	NodeID   graph.NodeID `json:"node_id"`
	Action   string       `json:"action"`
	Ref      string       `json:"ref"` // the ref actually in use, unverified against the advisory
	Advisory Advisory     `json:"advisory"`
}

// CheckActions asks OSV about CI actions, which no PURL query reaches.
//
// It runs the same batch, fetch and bitemporal filter as Check — an advisory
// published after the knowledge instant is still not something you could have
// known — and then rewraps into the weaker claim.
func (c *Client) CheckActions(ctx context.Context, ids []graph.NodeID, knownAt time.Time) ([]ActionAdvisory, error) {
	var actions []graph.NodeID
	for _, id := range ids {
		if _, ok := ActionName(id); ok {
			actions = append(actions, id)
		}
	}
	if len(actions) == 0 {
		return nil, nil
	}
	found, err := c.Check(ctx, actions, knownAt)
	if err != nil {
		return nil, err
	}
	out := make([]ActionAdvisory, 0, len(found))
	for _, f := range found {
		name, _ := ActionName(f.NodeID)
		out = append(out, ActionAdvisory{
			NodeID: f.NodeID, Action: name, Ref: refOf(f.NodeID), Advisory: f.Advisory,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].Advisory.ID < out[j].Advisory.ID
	})
	return out, nil
}

func refOf(id graph.NodeID) string {
	s := string(id)
	i := strings.LastIndex(s, "@")
	if i < 0 {
		return ""
	}
	s = s[i+1:]
	if j := strings.IndexAny(s, "#?"); j >= 0 {
		s = s[:j]
	}
	return s
}

// queryFor turns a node id into the one query shape OSV will answer for it.
//
// PURL is right for every registry ecosystem and wrong for GitHub Actions, for
// the reasons on ActionsEcosystem. An action is asked about by name, without a
// version — which means the answer is "this action has an advisory", not "your
// ref is affected". Callers must carry that weaker claim through instead of
// upgrading it, which is why ActionAdvisory exists as its own type rather than
// as another Finding.
func queryFor(id graph.NodeID) batchQuery {
	var q batchQuery
	if name, ok := ActionName(id); ok {
		q.Package.Name = name
		q.Package.Ecosystem = ActionsEcosystem
		return q
	}
	// A Terraform provider is distributed as a plugin binary but developed as a
	// Go repository, and that is the only name OSV files its advisories under.
	// The node keeps its own honest identity; only the QUERY is translated.
	if purl, ok := TerraformProviderPURL(id); ok {
		q.Package.PURL = purl
		return q
	}
	if purl, ok := TerraformCLIPURL(id); ok {
		q.Package.PURL = purl
		return q
	}
	q.Package.PURL = string(id)
	return q
}

// TerraformCLIPURL maps the Terraform binary's node id to the Go module its
// advisories are filed against.
//
// The node is pkg:terraform-cli rather than pkg:golang on purpose. Identifying
// it as a Go module made the walker expand Terraform's own 2,000-module build
// tree — dependencies this repository neither chose nor can change. Only the
// query is translated.
func TerraformCLIPURL(id graph.NodeID) (string, bool) {
	s := string(id)
	const prefix = "pkg:terraform-cli/"
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	version := ""
	if i := strings.Index(s, "@"); i >= 0 {
		version = s[i+1:]
	}
	if i := strings.IndexAny(version, "?#"); i >= 0 {
		version = version[:i]
	}
	out := "pkg:golang/github.com/hashicorp/terraform"
	if version != "" {
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		out += "@" + version
	}
	return out, true
}

// TerraformProviderPURL maps a Terraform provider node id to the Go module PURL
// its advisories are filed against.
//
// A provider named hashicorp/aws is developed as
// github.com/hashicorp/terraform-provider-aws. Coverage is real but thin — aws
// and vault have advisories, google and kubernetes have none — so this widens
// what can be found without ever pretending the node was a Go module: identity
// stays pkg:terraform, because that is what the configuration declares, what the
// registry serves and what the lockfile pins.
//
// Terraform's own version needs no mapping: it is already identified as
// github.com/hashicorp/terraform, which IS what OSV knows.
func TerraformProviderPURL(id graph.NodeID) (string, bool) {
	s := string(id)
	const prefix = "pkg:terraform/"
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	s = strings.TrimPrefix(s, prefix)

	version := ""
	if i := strings.Index(s, "@"); i >= 0 {
		version, s = s[i+1:], s[:i]
	}
	if i := strings.IndexAny(version, "?#"); i >= 0 {
		version = version[:i]
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}

	parts := strings.Split(s, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	module := "github.com/" + parts[0] + "/terraform-provider-" + parts[1]

	// Go module tags carry a leading v; Terraform versions never do. Querying
	// without it finds nothing for a version-specific lookup.
	if version != "" && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	out := "pkg:golang/" + module
	if version != "" {
		out += "@" + version
	}
	return out, true
}

// ActionName recovers `owner/repo` from a GitHub Actions node id, which is what
// OSV keys its records on. A reusable workflow carries its path as a PURL
// subpath; the advisory is about the repository, so the subpath is dropped.
func ActionName(id graph.NodeID) (string, bool) {
	s := string(id)
	if !strings.HasPrefix(s, "pkg:github/") {
		return "", false
	}
	s = strings.TrimPrefix(s, "pkg:github/")
	if i := strings.IndexAny(s, "@#?"); i >= 0 {
		s = s[:i]
	}
	if s == "" || !strings.Contains(s, "/") {
		return "", false
	}
	return s, true
}

// Check maps each PURL to the advisories affecting it.
//
// Two stages, because that is what the API offers: querybatch returns ids only
// (cheaply, 1000 at a time), then each distinct id is fetched once for its
// details. Packages usually share advisories, so the second stage is far smaller
// than the first.
func (c *Client) Check(ctx context.Context, purls []graph.NodeID, knownAt time.Time) ([]Finding, error) {
	var found []Finding
	idsFor := map[graph.NodeID][]string{}
	need := map[string]bool{}

	for start := 0; start < len(purls); start += batchLimit {
		end := min(start+batchLimit, len(purls))
		chunk := purls[start:end]

		var body struct {
			Queries []batchQuery `json:"queries"`
		}
		for _, p := range chunk {
			body.Queries = append(body.Queries, queryFor(p))
		}
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		resp, err := c.post(ctx, "/v1/querybatch", buf)
		if err != nil {
			return nil, err
		}
		var br batchResponse
		if err := json.Unmarshal(resp, &br); err != nil {
			return nil, fmt.Errorf("querybatch: %w", err)
		}
		// Results are positional: result[i] belongs to query[i].
		for i, r := range br.Results {
			if i >= len(chunk) {
				break
			}
			for _, v := range r.Vulns {
				idsFor[chunk[i]] = append(idsFor[chunk[i]], v.ID)
				need[v.ID] = true
			}
		}
	}

	ids := make([]string, 0, len(need))
	for id := range need {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if err := c.fetchAll(ctx, ids); err != nil {
		return nil, err
	}

	nodes := make([]graph.NodeID, 0, len(idsFor))
	for n := range idsFor {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i] < nodes[j] })

	for _, n := range nodes {
		for _, id := range idsFor[n] {
			a, ok := c.vulns[id]
			if !ok {
				continue
			}
			// Bitemporal filter: an advisory that did not exist yet at the
			// knowledge instant is not something we could have known, and a
			// withdrawn one is not something we still know.
			if !knownAt.IsZero() {
				if !a.Published.IsZero() && a.Published.After(knownAt) {
					continue
				}
				if !a.Withdrawn.IsZero() && !a.Withdrawn.After(knownAt) {
					continue
				}
			}
			found = append(found, Finding{NodeID: n, Advisory: a})
		}
	}
	return dedupe(found), nil
}

// fetchAll retrieves each advisory once, with bounded concurrency.
func (c *Client) fetchAll(ctx context.Context, ids []string) error {
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	var firstErr error

	for _, id := range ids {
		c.mu.Lock()
		_, have := c.vulns[id]
		c.mu.Unlock()
		if have {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			a, err := c.fetch(ctx, id)
			c.mu.Lock()
			defer c.mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			c.vulns[id] = a
		}(id)
	}
	wg.Wait()
	return firstErr
}

type osvRecord struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Published string   `json:"published"`
	Withdrawn string   `json:"withdrawn"`
	Aliases   []string `json:"aliases"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func (c *Client) fetch(ctx context.Context, id string) (Advisory, error) {
	body, err := c.get(ctx, "/v1/vulns/"+id)
	if err != nil {
		return Advisory{}, err
	}
	var r osvRecord
	if err := json.Unmarshal(body, &r); err != nil {
		return Advisory{}, fmt.Errorf("vuln %s: %w", id, err)
	}
	a := Advisory{ID: r.ID, Summary: r.Summary, Aliases: r.Aliases}
	a.Published, _ = time.Parse(time.RFC3339, r.Published)
	if r.Withdrawn != "" {
		a.Withdrawn, _ = time.Parse(time.RFC3339, r.Withdrawn)
	}
	// The qualitative rating is the only thing that belongs in Severity.
	// Deriving a band from a CVSS vector means implementing the CVSS formula;
	// until that exists, an unrated record is honestly UNKNOWN and its vector is
	// carried separately rather than impersonating a band.
	a.Severity = r.DatabaseSpecific.Severity
	for _, s := range r.Severity {
		if s.Score != "" {
			a.CVSS = s.Score
			break
		}
	}
	return a, nil
}

func (c *Client) post(ctx context.Context, p string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+p, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *Client) get(ctx context.Context, p string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+p, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv %s: %s", req.URL.Path, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

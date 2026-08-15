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
	ID        string    `json:"id"`
	Summary   string    `json:"summary"`
	Severity  string    `json:"severity"`
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
		PURL string `json:"purl"`
	} `json:"package"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	} `json:"results"`
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
			var q batchQuery
			q.Package.PURL = string(p)
			body.Queries = append(body.Queries, q)
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
	return found, nil
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
	// Prefer the qualitative rating; fall back to the CVSS vector.
	a.Severity = r.DatabaseSpecific.Severity
	if a.Severity == "" {
		for _, s := range r.Severity {
			if s.Score != "" {
				a.Severity = s.Type + ":" + s.Score
				break
			}
		}
	}
	if a.Severity == "" {
		a.Severity = "UNKNOWN"
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

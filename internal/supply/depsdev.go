// Package supply derives supply-chain risk signals from deps.dev.
//
// This is a different question from `deepdep audit`. An advisory says "this
// version has a known flaw". A supply-chain signal says "this is how the code
// got here, and how much a future compromise of it would cost you" — the package
// is deprecated and nobody will patch it, its releases carry no provenance, its
// source repo merges without review, its CI hands out write tokens.
//
// Two things the deps.dev API does that will silently corrupt a naive client:
//
//   - purlbatch echoes a NORMALISED purl back in `request`, not the one you
//     sent. `pkg:pypi/annotated_types@0.7.0` comes back as `annotated-types`,
//     and `boolean-py@5.0` comes back as `5.0.0`. Correlating results by that
//     echo silently misattributes facts between packages. We correlate by
//     INDEX, which the API does preserve — verified including misses in the
//     middle of a batch.
//   - purlbatch caps at 100 requests and returns a nextPageToken rather than an
//     error. Send 1000 and you get 100 answers and no complaint. We chunk at
//     100 so a short answer is impossible by construction.
package supply

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// batchLimit is the server's real cap. Exceeding it truncates SILENTLY.
const batchLimit = 100

// supported are the ecosystems deps.dev actually indexes. Anything else is
// rejected with a 400 that fails the WHOLE batch — one pkg:oci digest aborted a
// 1400-package report — so unsupported types are filtered before the request
// rather than discovered by the server.
var supported = map[string]bool{
	"npm": true, "pypi": true, "cargo": true, "maven": true,
	"golang": true, "nuget": true,
}

func queryable(id graph.NodeID) bool {
	s := strings.TrimPrefix(string(id), "pkg:")
	typ, _, _ := strings.Cut(s, "/")
	return supported[typ]
}

// Fact is what deps.dev knows about one exact package version.
//
// Known separates "deps.dev says this is fine" from "deps.dev has never heard
// of this". An internal package, a package pulled from a private index, or a
// typo'd name all come back with no result — reporting that as clean is the
// failure mode this field exists to prevent.
type Fact struct {
	NodeID graph.NodeID `json:"node_id"`
	// Queried separates "deps.dev has never heard of this" from "we never
	// asked". deps.dev covers language ecosystems only, so a container image or
	// an OS package is outside its remit — reporting those as `unlisted`
	// alongside a typosquat would be three hundred false alarms.
	Queried          bool      `json:"queried"`
	Known            bool      `json:"known"`
	Deprecated       bool      `json:"deprecated,omitempty"`
	DeprecatedReason string    `json:"deprecated_reason,omitempty"`
	Licenses         []string  `json:"licenses,omitempty"`
	AdvisoryIDs      []string  `json:"advisory_ids,omitempty"`
	PublishedAt      time.Time `json:"published_at,omitempty"`
	Attested         bool      `json:"attested,omitempty"` // a VERIFIED provenance attestation

	// SourceRepo is the project the scorecard will describe, and RepoProvenance
	// is how strongly it is attached. SLSA_ATTESTATION means the published
	// artifact itself vouches for the repo; UNVERIFIED_METADATA means somebody
	// typed a URL into package metadata. Flattening the two would let a
	// scorecard for an unrelated repo launder a package's reputation.
	SourceRepo     string `json:"source_repo,omitempty"`
	RepoProvenance string `json:"repo_provenance,omitempty"`
}

// Check is one Scorecard result.
//
// Score alone says a check failed; Reason and Warnings say WHY, with the file
// and line. "CI workflow has an untrusted-input injection pattern" is a rule
// description that fits every project; "untrusted code checkout ... :
// .github/workflows/ci-capability-policy.yml:26" is a thing somebody can go and
// fix.
type Check struct {
	Score  int    `json:"score"` // -1 means DID NOT RUN
	Reason string `json:"reason,omitempty"`
	// Warnings are the Warn/Error details only. Scorecard mixes Info lines into
	// the same array to give context, and several of them describe settings that
	// are CORRECT — Branch-Protection lists "'force pushes' disabled" as Info —
	// so surfacing them as reasons would report good hygiene as a finding.
	Warnings []string `json:"warnings,omitempty"`
}

// Project is a source repository plus its most recent OpenSSF Scorecard.
type Project struct {
	ID            string           `json:"id"`
	Stars         int              `json:"stars,omitempty"`
	HasScorecard  bool             `json:"has_scorecard"`
	ScorecardDate time.Time        `json:"scorecard_date,omitempty"`
	OverallScore  float64          `json:"overall_score,omitempty"`
	Checks        map[string]Check `json:"checks,omitempty"`
}

// Client queries deps.dev. No authentication: the API is free and unmetered.
type Client struct {
	base   string
	client *http.Client
	// Concurrency was measured, not guessed: 60 parallel project fetches
	// completed in 0.27s with no throttling.
	workers int
}

func New(base string, hc *http.Client) *Client {
	if base == "" {
		base = "https://api.deps.dev"
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{base: strings.TrimSuffix(base, "/"), client: hc, workers: 12}
}

// ---- version facts -------------------------------------------------------

type batchResponse struct {
	Responses []struct {
		Request struct {
			PURL string `json:"purl"` // NORMALISED — never correlate on this
		} `json:"request"`
		Result *struct {
			Version *versionDoc `json:"version"`
		} `json:"result"`
	} `json:"responses"`
}

type versionDoc struct {
	PublishedAt      time.Time `json:"publishedAt"`
	IsDeprecated     bool      `json:"isDeprecated"`
	DeprecatedReason string    `json:"deprecatedReason"`
	Licenses         []string  `json:"licenses"`
	AdvisoryKeys     []struct {
		ID string `json:"id"`
	} `json:"advisoryKeys"`
	Attestations []struct {
		Verified bool `json:"verified"`
	} `json:"attestations"`
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationProvenance string `json:"relationProvenance"`
		RelationType       string `json:"relationType"`
	} `json:"relatedProjects"`
}

// Facts resolves every purl, in order, one Fact per input.
//
// The returned slice is index-aligned with purls even for packages deps.dev has
// never seen, so a caller can never quietly lose a package between the two.
func (c *Client) Facts(ctx context.Context, purls []graph.NodeID) ([]Fact, error) {
	out := make([]Fact, len(purls))
	// Only the queryable subset is sent, and the results are mapped back by
	// index into the FULL slice so a caller still gets one Fact per input.
	var ask []graph.NodeID
	var askIdx []int
	for i, p := range purls {
		out[i] = Fact{NodeID: p}
		if queryable(p) {
			out[i].Queried = true
			ask = append(ask, p)
			askIdx = append(askIdx, i)
		}
	}

	type chunk struct{ lo, hi int }
	var chunks []chunk
	for lo := 0; lo < len(ask); lo += batchLimit {
		hi := min(lo+batchLimit, len(ask))
		chunks = append(chunks, chunk{lo, hi})
	}

	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, c.workers)
	for _, ch := range chunks {
		wg.Add(1)
		go func(ch chunk) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			facts, err := c.factBatch(ctx, ask[ch.lo:ch.hi])
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			for j, f := range facts {
				i := askIdx[ch.lo+j]
				f.Queried = true
				out[i] = f
			}
		}(ch)
	}
	wg.Wait()
	return out, firstErr
}

func (c *Client) factBatch(ctx context.Context, purls []graph.NodeID) ([]Fact, error) {
	reqs := make([]map[string]string, len(purls))
	for i, p := range purls {
		reqs[i] = map[string]string{"purl": string(p)}
	}
	body, err := json.Marshal(map[string]any{"requests": reqs})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/v3alpha/purlbatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("deps.dev purlbatch: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	var br batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, err
	}
	// Index correlation is only sound if the response is the same length as the
	// request. A short response means the API changed its batching contract, and
	// guessing which packages were dropped is worse than failing.
	if len(br.Responses) != len(purls) {
		return nil, fmt.Errorf("deps.dev returned %d responses for %d requests; "+
			"index correlation is unsafe", len(br.Responses), len(purls))
	}

	out := make([]Fact, len(purls))
	for i, r := range br.Responses {
		f := Fact{NodeID: purls[i]}
		if r.Result != nil && r.Result.Version != nil {
			applyVersion(&f, r.Result.Version)
		}
		out[i] = f
	}
	return out, nil
}

func applyVersion(f *Fact, v *versionDoc) {
	f.Known = true
	f.Deprecated = v.IsDeprecated
	f.DeprecatedReason = v.DeprecatedReason
	f.Licenses = v.Licenses
	f.PublishedAt = v.PublishedAt
	for _, a := range v.Attestations {
		if a.Verified {
			f.Attested = true
			break
		}
	}
	for _, k := range v.AdvisoryKeys {
		f.AdvisoryIDs = append(f.AdvisoryIDs, k.ID)
	}
	sort.Strings(f.AdvisoryIDs)

	// One project can be linked several times with different provenance. Prefer
	// the attested claim; fall back to metadata, and record which we took.
	for _, p := range v.RelatedProjects {
		if p.RelationType != "SOURCE_REPO" {
			continue
		}
		if f.SourceRepo == "" || p.RelationProvenance == "SLSA_ATTESTATION" {
			f.SourceRepo = p.ProjectKey.ID
			f.RepoProvenance = p.RelationProvenance
		}
		if f.RepoProvenance == "SLSA_ATTESTATION" {
			break
		}
	}
}

// ---- projects and scorecards --------------------------------------------

type projectDoc struct {
	StarsCount int `json:"starsCount"`
	Scorecard  *struct {
		Date         time.Time `json:"date"`
		OverallScore float64   `json:"overallScore"`
		Checks       []struct {
			Name    string   `json:"name"`
			Score   int      `json:"score"`
			Reason  string   `json:"reason"`
			Details []string `json:"details"`
		} `json:"checks"`
	} `json:"scorecard"`
}

// Projects fetches each distinct project once.
//
// Deduplication matters more than it looks: every @babel/* package resolves to
// github.com/babel/babel, so a thousand packages is typically half as many
// projects. There is no batch endpoint, so this is one request each.
// Projects looks up each project, returning what resolved, how many did not,
// and an error only when NOTHING did.
func (c *Client) Projects(ctx context.Context, ids []string) (map[string]Project, int, error) {
	seen := map[string]bool{}
	var uniq []string
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		uniq = append(uniq, id)
	}
	sort.Strings(uniq)

	var (
		mu       sync.Mutex
		out      = map[string]Project{}
		failed   int
		firstErr error
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, c.workers)
	for _, id := range uniq {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			p, err := c.project(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			out[id] = p
		}(id)
	}
	wg.Wait()

	// Posture is an ENRICHMENT and one of four scoring terms. One unreachable
	// project must degrade that project to unknown, not lose the repository's
	// whole report — a fleet run lost 8 of its first 46 repositories to a single
	// throttled lookup each.
	//
	// A TOTAL outage is different and stays an error: reporting every project as
	// unknown would read as "nothing upstream is unmaintained", which is a wrong
	// answer rather than a partial one.
	//
	// The count is returned rather than swallowed so the caller can say what was
	// lost. A silent partial is the failure mode this tool exists to avoid.
	if len(uniq) > 0 && failed == len(uniq) {
		return out, failed, firstErr
	}
	return out, failed, nil
}

// depsDevMaxAttempts bounds retries so an outage fails rather than hangs.
const depsDevMaxAttempts = 4

// getWithRetry fetches a deps.dev endpoint, retrying the statuses that mean
// "ask again later" rather than "no".
//
// Without this a 429 became a hard error the moment a scan asked about enough
// projects quickly enough — which is exactly what widening the closure and
// removing the resolver's serialisation did.
func (c *Client) getWithRetry(ctx context.Context, endpoint string) ([]byte, int, error) {
	var lastStatus string
	for attempt := 0; attempt < depsDevMaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, 0, err
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			wait := depsDevRetryAfter(resp.Header.Get("Retry-After"), time.Duration(1<<attempt)*250*time.Millisecond)
			resp.Body.Close()
			lastStatus = resp.Status
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil, http.StatusNotFound, nil
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, resp.StatusCode, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		return b, http.StatusOK, err
	}
	return nil, 0, fmt.Errorf("%s after %d attempts", lastStatus, depsDevMaxAttempts)
}

// depsDevRetryAfter reads the header, sent as whole seconds, falling back to the
// caller's computed backoff.
func depsDevRetryAfter(h string, fallback time.Duration) time.Duration {
	if h == "" {
		return fallback
	}
	secs, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || secs < 0 {
		return fallback
	}
	return time.Duration(secs) * time.Second
}

func (c *Client) project(ctx context.Context, id string) (Project, error) {
	p := Project{ID: id}
	// The whole id is one path segment, so every slash inside it must encode.
	// url.PathEscape leaves "/" alone, which yields a 404 that reads as "no
	// such project" rather than "you built the URL wrong".
	endpoint := c.base + "/v3/projects/" + url.QueryEscape(id)

	body, status, err := c.getWithRetry(ctx, endpoint)
	if err != nil {
		return p, fmt.Errorf("deps.dev project %s: %w", id, err)
	}
	if status == http.StatusNotFound {
		return p, nil // unknown project, not an error
	}

	var doc projectDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return p, err
	}
	p.Stars = doc.StarsCount
	if doc.Scorecard != nil {
		p.HasScorecard = true
		p.ScorecardDate = doc.Scorecard.Date
		p.OverallScore = doc.Scorecard.OverallScore
		p.Checks = map[string]Check{}
		for _, ck := range doc.Scorecard.Checks {
			c := Check{Score: ck.Score, Reason: ck.Reason}
			for _, d := range ck.Details {
				if strings.HasPrefix(d, "Warn:") || strings.HasPrefix(d, "Error:") {
					c.Warnings = append(c.Warnings, strings.TrimSpace(
						strings.TrimPrefix(strings.TrimPrefix(d, "Warn:"), "Error:")))
				}
			}
			p.Checks[ck.Name] = c
		}
	}
	return p, nil
}

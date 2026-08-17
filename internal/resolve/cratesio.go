package resolve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/version"
)

// CratesResolver reads crates from the crates.io SPARSE INDEX.
//
// Not from /api/v1. That was the obvious choice and it is the wrong one: the API
// rate-limits hard, and a fleet scan earned 352 nodes marked error:ratelimit
// across three repositories — a whole Rust closure degrading to Declared with no
// failure line anywhere, so the numbers looked real and were not. Backoff alone
// did not fix it, because a several-hundred-crate closure cannot be paced to the
// API's tolerance without timing the scan out. That trades a wrong answer for no
// answer.
//
// The sparse index is what Cargo itself uses. It is a static CDN with no rate
// limit, and one request returns EVERY version of a crate together with that
// version's dependencies, yanked flag and publish time — so it also halves the
// request count against the API's two-call shape.
type CratesResolver struct {
	base   string
	cache  cache.Cache
	client *http.Client
	maxAge time.Duration
	now    func() time.Time
	obs    Observations

	mu   sync.Mutex
	docs map[string][]crateLine
}

// cratesMaxAttempts bounds retries so a CDN having a bad day fails the request
// instead of hanging the scan.
const cratesMaxAttempts = 4

func NewCratesResolver(base string, c cache.Cache, hc *http.Client, maxAge time.Duration, now func() time.Time) *CratesResolver {
	if hc == nil {
		hc = http.DefaultClient
	}
	if now == nil {
		now = time.Now
	}
	return &CratesResolver{
		base: strings.TrimRight(base, "/"), cache: c, client: hc,
		maxAge: maxAge, now: now,
		docs: map[string][]crateLine{},
	}
}

func (r *CratesResolver) WithObservations(o Observations) *CratesResolver {
	r.obs = o
	return r
}

func (r *CratesResolver) Ecosystem() string { return "cargo" }

// crateLine is one line of an index file: one published version.
type crateLine struct {
	Name    string `json:"name"`
	Vers    string `json:"vers"`
	Yanked  bool   `json:"yanked"`
	PubTime string `json:"pubtime"`
	Deps    []struct {
		Name     string `json:"name"`
		Req      string `json:"req"`
		Kind     string `json:"kind"` // normal | dev | build
		Optional bool   `json:"optional"`
		Package  string `json:"package"`
	} `json:"deps"`
}

// indexPath is the index's directory layout, keyed by name length. Getting it
// wrong 404s every crate whose name is shorter than four characters — cc, log,
// rand — which are among the most depended-upon crates there are.
//
//	1 char:  1/a
//	2 chars: 2/cc
//	3 chars: 3/l/log
//	4+:      se/rd/serde
func indexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 0:
		return ""
	case 1:
		return "1/" + n
	case 2:
		return "2/" + n
	case 3:
		return "3/" + n[:1] + "/" + n
	default:
		return n[:2] + "/" + n[2:4] + "/" + n
	}
}

func (r *CratesResolver) fetch(ctx context.Context, name string) ([]crateLine, error) {
	r.mu.Lock()
	if d, ok := r.docs[name]; ok {
		r.mu.Unlock()
		return d, nil
	}
	r.mu.Unlock()

	p := indexPath(name)
	if p == "" {
		return nil, fmt.Errorf("crates.io: empty crate name")
	}
	body, err := r.get(ctx, "/"+p)
	if err != nil {
		return nil, err
	}

	var lines []crateLine
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024) // a busy crate's line is large
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var l crateLine
		if err := json.Unmarshal(b, &l); err != nil {
			continue // one malformed line must not lose the whole crate
		}
		lines = append(lines, l)
	}

	r.mu.Lock()
	r.docs[name] = lines
	r.mu.Unlock()
	return lines, nil
}

// Versions lists published versions.
//
// Yanked versions are EXCLUDED. A yank means no new resolution can select the
// version, so offering it in can-mode would report a state Cargo will not
// produce. A lockfile already pinning a yanked version still resolves, because
// that goes through the effective layer rather than asking here.
func (r *CratesResolver) Versions(ctx context.Context, name string, _ bool) ([]VersionInfo, error) {
	lines, err := r.fetch(ctx, name)
	if err != nil {
		return nil, err
	}
	var out []VersionInfo
	for _, l := range lines {
		if l.Yanked {
			continue
		}
		pv, err := version.Cargo.Parse(l.Vers)
		if err != nil {
			continue
		}
		info := VersionInfo{Version: pv}
		// pubtime is what makes --as-of work for Cargo. It is a recent addition
		// to the index and older lines omit it; a zero time means "unknown",
		// which callers already treat as "cannot filter".
		if l.PubTime != "" {
			if t, err := time.Parse(time.RFC3339, l.PubTime); err == nil {
				info.PublishedAt = t
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// Requirements reads one version's dependencies out of the index line already
// fetched for Versions — so it costs no request at all.
//
// Dev dependencies are excluded here and ONLY here. A crate's own dev
// dependencies build its tests and are never built by a consumer, so walking
// them adds a large tree nobody installs. That is not a narrowing of the
// "everything reachable" decision, which governs the scanned repository's own
// manifest, where dev dependencies really are built.
func (r *CratesResolver) Requirements(ctx context.Context, name string, v version.Version) ([]Requirement, error) {
	lines, err := r.fetch(ctx, name)
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if l.Vers != v.String() {
			continue
		}
		var out []Requirement
		for _, d := range l.Deps {
			if d.Kind == "dev" {
				continue
			}
			// `package` carries the real crate when a dependency was renamed;
			// that is what is fetched and what advisories attach to.
			target := d.Name
			if d.Package != "" {
				target = d.Package
			}
			scope := graph.Prod
			if d.Optional {
				scope = graph.Optional
			}
			out = append(out, Requirement{Name: target, Constraint: d.Req, Scope: scope})
		}
		return out, nil
	}
	return nil, nil
}

// get fetches an index path.
//
// Index files are MUTABLE — a new release appends a line — so they are not put
// in the immutable content cache. The CDN's own caching plus the per-run memo
// above is what keeps this cheap.
func (r *CratesResolver) get(ctx context.Context, path string) ([]byte, error) {
	var lastStatus string
	for attempt := 0; attempt < cratesMaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+path, nil)
		if err != nil {
			return nil, err
		}
		// crates.io asks for a descriptive User-Agent and can refuse without one.
		req.Header.Set("User-Agent", "deepdep (https://github.com/jverhoeks/deepdep)")
		resp, err := r.client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			wait := retryAfter(resp.Header.Get("Retry-After"), time.Duration(1<<attempt)*250*time.Millisecond)
			resp.Body.Close()
			lastStatus = resp.Status
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("crates.io %s: %s", path, resp.Status)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		return body, err
	}
	return nil, fmt.Errorf("crates.io %s: %s after %d attempts", path, lastStatus, cratesMaxAttempts)
}

// retryAfter reads the header, which is sent as whole seconds. A missing or
// unreadable value falls back to the caller's computed backoff.
func retryAfter(h string, fallback time.Duration) time.Duration {
	if h == "" {
		return fallback
	}
	secs, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || secs < 0 {
		return fallback
	}
	return time.Duration(secs) * time.Second
}

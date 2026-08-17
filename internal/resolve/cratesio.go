package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/version"
)

// CratesResolver reads crates from a crates.io-compatible index.
//
// /api/v1/crates/<name> returns every version together with its creation time
// in one request, so listing versions costs a single call — the same property
// that makes npm range expansion affordable. Dependencies need a second call per
// version, like PyPI.
type CratesResolver struct {
	base   string
	cache  cache.Cache
	client *http.Client
	maxAge time.Duration
	now    func() time.Time
	obs    Observations

	mu   sync.Mutex
	docs map[string]*cratesDoc

	// paceMu serialises the pacing decision. crates.io asks crawlers for about
	// one request a second and enforces it with 429s; a fleet scan runs many
	// workers at once and earns them immediately.
	paceMu   sync.Mutex
	nextSlot time.Time
	interval time.Duration
}

// cratesInterval is the minimum gap between requests from one process. It is
// deliberately close to crates.io's published crawler guidance rather than as
// fast as the server will tolerate: being throttled costs a whole repository's
// Rust closure, and the cache makes a re-scan free anyway.
const cratesInterval = 250 * time.Millisecond

// cratesMaxAttempts bounds retries so a server that is down fails the request
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
		docs:     map[string]*cratesDoc{},
		interval: cratesInterval,
	}
}

func (r *CratesResolver) WithObservations(o Observations) *CratesResolver {
	r.obs = o
	return r
}

func (r *CratesResolver) Ecosystem() string { return "cargo" }

type cratesDoc struct {
	Versions []struct {
		Num       string    `json:"num"`
		CreatedAt time.Time `json:"created_at"`
		Yanked    bool      `json:"yanked"`
	} `json:"versions"`
}

type cratesDeps struct {
	Dependencies []struct {
		CrateID  string `json:"crate_id"`
		Req      string `json:"req"`
		Kind     string `json:"kind"` // normal | dev | build
		Optional bool   `json:"optional"`
	} `json:"dependencies"`
}

func (r *CratesResolver) fetchCrate(ctx context.Context, name string) (*cratesDoc, error) {
	r.mu.Lock()
	if d, ok := r.docs[name]; ok {
		r.mu.Unlock()
		return d, nil
	}
	r.mu.Unlock()

	body, err := r.get(ctx, "/api/v1/crates/"+url.PathEscape(name))
	if err != nil {
		return nil, err
	}
	var d cratesDoc
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("crates.io %s: %w", name, err)
	}

	r.mu.Lock()
	r.docs[name] = &d
	r.mu.Unlock()
	return &d, nil
}

// Versions lists published versions.
//
// Yanked versions are EXCLUDED. A yank means the version can no longer be
// selected by a new resolution, so including it in can-mode would report a
// reachable state that Cargo will not produce. A lockfile that already pins a
// yanked version still resolves through the effective layer, which reads the
// lockfile rather than asking here.
func (r *CratesResolver) Versions(ctx context.Context, name string, _ bool) ([]VersionInfo, error) {
	d, err := r.fetchCrate(ctx, name)
	if err != nil {
		return nil, err
	}
	var out []VersionInfo
	for _, v := range d.Versions {
		if v.Yanked {
			continue
		}
		pv, err := version.Cargo.Parse(v.Num)
		if err != nil {
			continue
		}
		out = append(out, VersionInfo{Version: pv, PublishedAt: v.CreatedAt})
	}
	return out, nil
}

// Requirements reads one version's dependencies.
//
// Dev dependencies are excluded here and ONLY here. A crate's own dev
// dependencies are used to test that crate and are never built by a consumer,
// so walking them would add a large tree that nobody installs. This is not a
// narrowing of the "everything reachable" decision: that decision governs the
// scanned repository's own manifest, where dev dependencies really are built.
func (r *CratesResolver) Requirements(ctx context.Context, name string, v version.Version) ([]Requirement, error) {
	body, err := r.get(ctx, "/api/v1/crates/"+url.PathEscape(name)+"/"+url.PathEscape(v.String())+"/dependencies")
	if err != nil {
		return nil, err
	}
	var d cratesDeps
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("crates.io %s@%s: %w", name, v.String(), err)
	}

	var out []Requirement
	for _, dep := range d.Dependencies {
		if dep.Kind == "dev" {
			continue
		}
		scope := graph.Prod
		if dep.Optional {
			scope = graph.Optional
		}
		out = append(out, Requirement{
			Name:       dep.CrateID,
			Constraint: dep.Req,
			Scope:      scope,
		})
	}
	return out, nil
}

// pace blocks until this process may make its next request.
//
// The slot is claimed under the lock and the SLEEP happens outside it, so
// concurrent callers queue up at one-per-interval instead of all waking
// together and firing at once.
func (r *CratesResolver) pace(ctx context.Context) error {
	r.paceMu.Lock()
	now := time.Now()
	slot := r.nextSlot
	if slot.Before(now) {
		slot = now
	}
	r.nextSlot = slot.Add(r.interval)
	r.paceMu.Unlock()

	d := time.Until(slot)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// delayRequests pushes every pending slot back, so one 429 slows the whole
// process rather than only the request that happened to receive it.
func (r *CratesResolver) delayRequests(d time.Duration) {
	r.paceMu.Lock()
	defer r.paceMu.Unlock()
	if until := time.Now().Add(d); until.After(r.nextSlot) {
		r.nextSlot = until
	}
}

func (r *CratesResolver) get(ctx context.Context, path string) ([]byte, error) {
	var lastStatus string
	for attempt := 0; attempt < cratesMaxAttempts; attempt++ {
		if err := r.pace(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+path, nil)
		if err != nil {
			return nil, err
		}
		// crates.io requires a descriptive User-Agent and returns 403 without one.
		req.Header.Set("User-Agent", "deepdep (https://github.com/jverhoeks/deepdep)")
		resp, err := r.client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			// Honour Retry-After when given; otherwise back off geometrically.
			// A 429 surfaced as an error marks the node "error:ratelimit" and a
			// whole Rust repository degrades to Declared with no failure line —
			// numbers that look real and are not.
			wait := retryAfter(resp.Header.Get("Retry-After"), r.interval<<attempt)
			resp.Body.Close()
			lastStatus = resp.Status
			r.delayRequests(wait)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("crates.io %s: %s", path, resp.Status)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		return body, err
	}
	return nil, fmt.Errorf("crates.io %s: %s after %d attempts", path, lastStatus, cratesMaxAttempts)
}

// retryAfter reads the header, which crates.io sends as whole seconds. A missing
// or unreadable value falls back to the caller's computed backoff.
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

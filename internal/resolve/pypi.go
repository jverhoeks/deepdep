package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/version"
)

// PyPIResolver reads project metadata from a PyPI-compatible index.
//
// The JSON API returns every release together with its upload times in one
// request, so listing versions costs a single call per package — the same
// property that makes npm range expansion affordable.
//
// Requirements are a different story: PyPI only exposes requires_dist for ONE
// version at a time, so a per-version fetch is unavoidable. That is why the
// observation cache matters more here than for npm.
type PyPIResolver struct {
	base   string
	cache  cache.Cache
	client *http.Client
	maxAge time.Duration
	now    func() time.Time
	obs    Observations

	mu     sync.Mutex
	flight singleflight
	memo   map[string]observation
	docs   map[string]*pypiProject
}

func NewPyPIResolver(base string, c cache.Cache, hc *http.Client, maxAge time.Duration, now func() time.Time) *PyPIResolver {
	if hc == nil {
		hc = http.DefaultClient
	}
	if now == nil {
		now = time.Now
	}
	return &PyPIResolver{
		base: strings.TrimRight(base, "/"), cache: c, client: hc,
		maxAge: maxAge, now: now,
		memo: map[string]observation{},
		docs: map[string]*pypiProject{},
	}
}

func (r *PyPIResolver) WithObservations(o Observations) *PyPIResolver {
	r.obs = o
	return r
}

func (r *PyPIResolver) Ecosystem() string { return "pypi" }

type pypiProject struct {
	Info struct {
		RequiresDist []string `json:"requires_dist"`
		Version      string   `json:"version"`
	} `json:"info"`
	Releases map[string][]struct {
		UploadTime string `json:"upload_time_iso_8601"`
		Yanked     bool   `json:"yanked"`
	} `json:"releases"`
}

// fetch returns a project document, from memo, from the blob cache, or from the
// index.
//
// The state mutex is held ONLY while touching state, never across the HTTP
// request. It used to wrap the whole function, which serialised every download
// in the process and made --concurrency inert. singleflight preserves what the
// wide lock was really buying: concurrent callers for the same key share one
// fetch instead of racing to repeat it.
func (r *PyPIResolver) fetch(ctx context.Context, name, ver string) (*pypiProject, error) {
	key := name + "\x00" + ver
	if doc, ok := r.cached(ctx, name, ver, key); ok {
		return doc, nil
	}
	v, err := r.flight.Do(key, func() (any, error) {
		// Re-check under the flight: a caller that queued behind the winner
		// would otherwise refetch what the winner has just stored.
		if doc, ok := r.cached(ctx, name, ver, key); ok {
			return doc, nil
		}
		return r.download(ctx, name, ver, key)
	})
	if err != nil {
		return nil, err
	}
	return v.(*pypiProject), nil
}

// cached answers from the in-process memo or the blob cache, taking the state
// mutex only for as long as that takes.
func (r *PyPIResolver) cached(ctx context.Context, name, ver, key string) (*pypiProject, bool) {
	r.mu.Lock()
	o, have := r.memo[key]
	if !have && r.obs != nil && ver == "" {
		if sha, at, _, ok := r.obs.LastPackument(ctx, "pypi", name); ok {
			o, have = observation{sha: sha, observedAt: at}, true
			r.memo[key] = o
		}
	}
	if !have || r.now().Sub(o.observedAt) >= r.maxAge {
		r.mu.Unlock()
		return nil, false
	}
	if doc, ok := r.docs[key]; ok {
		r.mu.Unlock()
		return doc, true
	}
	r.mu.Unlock()

	// Blob reads touch the filesystem, so they happen outside the lock too.
	body, ok := r.cache.GetBlob(o.sha)
	if !ok {
		return nil, false
	}
	doc, err := decodePyPI(body)
	if err != nil {
		return nil, false
	}
	r.mu.Lock()
	r.docs[key] = doc
	r.mu.Unlock()
	return doc, true
}

func (r *PyPIResolver) download(ctx context.Context, name, ver, key string) (*pypiProject, error) {
	u := r.base + "/pypi/" + url.PathEscape(name)
	if ver != "" {
		u += "/" + url.PathEscape(ver)
	}
	u += "/json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi %s: %s", name, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	doc, err := decodePyPI(body)
	if err != nil {
		return nil, fmt.Errorf("pypi %s: %w", name, err)
	}

	sha, err := r.cache.PutBlob(body)
	if err != nil {
		return nil, err
	}
	seen := r.now()
	r.mu.Lock()
	r.memo[key] = observation{sha: sha, observedAt: seen}
	r.docs[key] = doc
	r.mu.Unlock()
	if r.obs != nil && ver == "" {
		if err := r.obs.RecordPackument(ctx, "pypi", name, sha, seen, true); err != nil {
			return nil, err
		}
	}
	return doc, nil
}

func decodePyPI(b []byte) (*pypiProject, error) {
	var p pypiProject
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *PyPIResolver) Versions(ctx context.Context, name string, _ bool) ([]VersionInfo, error) {
	doc, err := r.fetch(ctx, name, "")
	if err != nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(doc.Releases))
	for raw, files := range doc.Releases {
		v, err := version.PEP440.Parse(raw)
		if err != nil {
			continue
		}
		// A release with no files was never installable; a fully yanked one has
		// been withdrawn. Neither is something a resolver can select.
		var usable bool
		var earliest time.Time
		for _, f := range files {
			if f.Yanked {
				continue
			}
			usable = true
			if t, err := time.Parse(time.RFC3339, f.UploadTime); err == nil {
				if earliest.IsZero() || t.Before(earliest) {
					earliest = t
				}
			}
		}
		if !usable {
			continue
		}
		out = append(out, VersionInfo{Version: v, PublishedAt: earliest})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return version.PEP440.Compare(out[i].Version, out[j].Version) < 0
	})
	return out, nil
}

// extraRe pulls the extra name out of an environment marker, so optional
// dependencies are tagged rather than reported as unconditional.
var extraRe = regexp.MustCompile(`extra\s*==\s*['"]([^'"]+)['"]`)

func (r *PyPIResolver) Requirements(ctx context.Context, name string, v version.Version) ([]Requirement, error) {
	doc, err := r.fetch(ctx, name, v.String())
	if err != nil {
		return nil, err
	}
	var out []Requirement
	for _, raw := range doc.Info.RequiresDist {
		scope := graph.Prod
		if extraRe.MatchString(raw) {
			// Only installed when the extra is requested.
			scope = graph.Optional
		}
		dep, spec, ok := parsePEP508(raw)
		if !ok {
			continue
		}
		out = append(out, Requirement{Name: dep, Constraint: spec, Scope: scope})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var pep508 = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$`)

func parsePEP508(s string) (name, spec string, ok bool) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ";"); i >= 0 {
		s = s[:i]
	}
	m := pep508.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	spec = strings.TrimSpace(m[2])
	spec = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(spec, "("), ")"))
	if strings.HasPrefix(spec, "@") {
		spec = "" // direct URL reference: pinned to a location, not a version
	}
	return m[1], spec, true
}

package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/version"
)

// abbreviatedAccept asks for the install-oriented packument. Verified against
// the real registry: it returns EVERY published version together with that
// version's own dependencies in a single request (react: 2.8 MB, versus 6.9 MB
// for the full document). That is what makes expanding a whole range space cost
// one HTTP call per package rather than one per version.
const abbreviatedAccept = "application/vnd.npm.install-v1+json"

// NPMResolver reads packuments from an npm registry.
type NPMResolver struct {
	base   string
	cache  cache.Cache
	client *http.Client
	maxAge time.Duration
	now    func() time.Time

	// obs is the durable observation record. Without it, every process starts
	// cold and --max-metadata-age can never help across invocations.
	obs Observations

	mu   sync.Mutex
	memo map[string]observation // in-process view, avoids re-querying the store
	docs map[string]*packument  // parsed, keyed by name+form
}

type observation struct {
	sha        string
	observedAt time.Time
	full       bool
}

func NewNPMResolver(base string, c cache.Cache, hc *http.Client, maxAge time.Duration, now func() time.Time) *NPMResolver {
	if hc == nil {
		hc = http.DefaultClient
	}
	if now == nil {
		now = time.Now
	}
	return &NPMResolver{
		base: strings.TrimRight(base, "/"), cache: c, client: hc,
		maxAge: maxAge, now: now,
		memo: map[string]observation{},
		docs: map[string]*packument{},
	}
}

// WithObservations attaches a durable observation record, making repeat scans
// incremental across processes and populating the bitemporal substrate.
func (r *NPMResolver) WithObservations(o Observations) *NPMResolver {
	r.obs = o
	return r
}

func (r *NPMResolver) Ecosystem() string { return "npm" }

type packumentVersion struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type packument struct {
	Versions map[string]packumentVersion `json:"versions"`
	// Time is present ONLY in the full document. The abbreviated form omits it
	// entirely, which is why --as-of has to escalate.
	Time map[string]string `json:"time"`
}

// fetch returns the packument, re-fetching when the stored observation is older
// than maxAge or is too thin for what the caller needs.
//
// A packument is a mutable document, so it is NOT eligible for the immutable
// cache's never-expire contract. It is stored as an observation — a body plus
// the instant we saw it — and revalidated by age.
func (r *NPMResolver) fetch(ctx context.Context, name string, full bool) (*packument, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	o, have := r.memo[name]
	if !have && r.obs != nil {
		// Cold process: ask the durable record what we last saw.
		if sha, at, wasFull, ok := r.obs.LastPackument(ctx, "npm", name); ok {
			o, have = observation{sha: sha, observedAt: at, full: wasFull}, true
			r.memo[name] = o
		}
	}
	// A stored abbreviated body cannot satisfy a request that needs publish times.
	if have && (o.full || !full) && r.now().Sub(o.observedAt) < r.maxAge {
		if doc, ok := r.docs[docKey(name, o.full)]; ok {
			return doc, nil
		}
		if body, ok := r.cache.GetBlob(o.sha); ok {
			if doc, err := decode(body); err == nil {
				r.docs[docKey(name, o.full)] = doc
				return doc, nil
			}
		}
	}

	body, err := r.get(ctx, name, full)
	if err != nil {
		return nil, err
	}
	sha, err := r.cache.PutBlob(body)
	if err != nil {
		return nil, err
	}
	doc, err := decode(body)
	if err != nil {
		return nil, fmt.Errorf("packument %s: %w", name, err)
	}
	seen := r.now()
	r.memo[name] = observation{sha: sha, observedAt: seen, full: full}
	r.docs[docKey(name, full)] = doc
	if r.obs != nil {
		if err := r.obs.RecordPackument(ctx, "npm", name, sha, seen, full); err != nil {
			return nil, err
		}
	}
	return doc, nil
}

func docKey(name string, full bool) string {
	if full {
		return name + "\x00full"
	}
	return name + "\x00abbrev"
}

func decode(b []byte) (*packument, error) {
	var p packument
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *NPMResolver) get(ctx context.Context, name string, full bool) ([]byte, error) {
	// A scoped name's slash must survive as a path separator per the registry's
	// URL scheme, so escape the segments individually.
	esc := strings.Join(splitEscape(name), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+"/"+esc, nil)
	if err != nil {
		return nil, err
	}
	if !full {
		req.Header.Set("Accept", abbreviatedAccept)
	} else {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry %s: %s", name, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func splitEscape(name string) []string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return parts
}

func (r *NPMResolver) Versions(ctx context.Context, name string, needPublished bool) ([]VersionInfo, error) {
	doc, err := r.fetch(ctx, name, needPublished)
	if err != nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(doc.Versions))
	for raw := range doc.Versions {
		v, err := version.NPM.Parse(raw)
		if err != nil {
			continue // registries do carry a few unparseable historical versions
		}
		info := VersionInfo{Version: v}
		if ts, ok := doc.Time[raw]; ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				info.PublishedAt = t
			}
		}
		out = append(out, info)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return version.NPM.Compare(out[i].Version, out[j].Version) < 0
	})
	return out, nil
}

func (r *NPMResolver) Requirements(ctx context.Context, name string, v version.Version) ([]Requirement, error) {
	doc, err := r.fetch(ctx, name, false)
	if err != nil {
		return nil, err
	}
	pv, ok := doc.Versions[v.String()]
	if !ok {
		return nil, fmt.Errorf("%s@%s not in packument", name, v)
	}

	var out []Requirement
	add := func(deps map[string]string, scope graph.Scope) {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names) // deterministic expansion order
		for _, n := range names {
			// Follow npm aliases ("npm:real-name@^1.2.3") to the package that is
			// actually installed — that is what advisories attach to.
			name, spec := version.NPMAlias(n, deps[n])
			out = append(out, Requirement{Name: name, Constraint: spec, Scope: scope})
		}
	}
	add(pv.Dependencies, graph.Prod)
	add(pv.DevDependencies, graph.Dev)
	add(pv.PeerDependencies, graph.Peer)
	add(pv.OptionalDependencies, graph.Optional)
	return out, nil
}

package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/gomod"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/version"
)

// GoProxyResolver reads modules from a Go module proxy.
//
// The proxy protocol suits this tool unusually well. Every response for a given
// version is IMMUTABLE by specification — @v/<version>.mod and @v/<version>.info
// can never change once published — so they go in the content cache
// unconditionally, with none of the packument revalidation npm and PyPI need.
// Only @v/list is mutable, because new versions appear.
//
// It also means one fetch per version for requirements, like PyPI and unlike
// npm. A .mod file is small, and the immutable cache makes a re-scan free.
type GoProxyResolver struct {
	base   string
	cache  cache.Cache
	client *http.Client
	maxAge time.Duration
	now    func() time.Time
	obs    Observations

	mu   sync.Mutex
	list map[string][]VersionInfo
}

func NewGoProxyResolver(base string, c cache.Cache, hc *http.Client, maxAge time.Duration, now func() time.Time) *GoProxyResolver {
	if hc == nil {
		hc = http.DefaultClient
	}
	if now == nil {
		now = time.Now
	}
	return &GoProxyResolver{
		base: strings.TrimRight(base, "/"), cache: c, client: hc,
		maxAge: maxAge, now: now,
		list: map[string][]VersionInfo{},
	}
}

func (r *GoProxyResolver) WithObservations(o Observations) *GoProxyResolver {
	r.obs = o
	return r
}

func (r *GoProxyResolver) Ecosystem() string { return "golang" }

// escapeModule applies the proxy's case encoding.
//
// Module paths are case-sensitive but many filesystems are not, so the protocol
// replaces every capital with "!" followed by its lowercase. Skipping this is
// not a subtle degradation: every module with a capital in its path — a great
// many of them, github.com/Masterminds/semver among the most common — 404s, and
// the failure looks like "that module does not exist".
func escapeModule(mod string) string {
	var b strings.Builder
	for _, c := range mod {
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(c + ('a' - 'A'))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// Versions lists published versions, newest first.
//
// @v/list is plain text, one version per line, and carries NO timestamps. When
// they are needed — --as-of replays a past instant and must ignore versions that
// did not exist yet — each version's .info is fetched for its Time field. That
// is a request per version, so it is done only when actually asked for.
func (r *GoProxyResolver) Versions(ctx context.Context, name string, needPublished bool) ([]VersionInfo, error) {
	r.mu.Lock()
	if v, ok := r.list[name]; ok && !needPublished {
		r.mu.Unlock()
		return v, nil
	}
	r.mu.Unlock()

	body, err := r.get(ctx, name, "@v/list", false)
	if err != nil {
		return nil, err
	}

	var out []VersionInfo
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		v, err := version.Go.Parse(line)
		if err != nil {
			continue // the proxy lists only valid versions; skip anything odd
		}
		info := VersionInfo{Version: v}
		if needPublished {
			if t, ok := r.publishedAt(ctx, name, line); ok {
				info.PublishedAt = t
			}
		}
		out = append(out, info)
	}

	// @v/list omits prereleases and, for some modules, everything: a module with
	// no tags is served only as pseudo-versions. An empty list is a real answer
	// ("nothing published under a tag"), not an error, and the caller's frontier
	// handling is what makes that visible.
	r.mu.Lock()
	if !needPublished {
		r.list[name] = out
	}
	r.mu.Unlock()
	return out, nil
}

// goInfo is the @v/<version>.info document.
type goInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

func (r *GoProxyResolver) publishedAt(ctx context.Context, name, ver string) (time.Time, bool) {
	body, err := r.get(ctx, name, "@v/"+ver+".info", true)
	if err != nil {
		return time.Time{}, false
	}
	var info goInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return time.Time{}, false
	}
	return info.Time, !info.Time.IsZero()
}

// Requirements reads one version's own go.mod from the proxy.
//
// Only DIRECT requirements are returned. A dependency's go.mod also lists its
// indirect requirements, but those are that module's record of ITS build list —
// walking them here would add the same modules again at every level and count
// one package many times over. The walker reaches them through their own
// module's requirements instead.
func (r *GoProxyResolver) Requirements(ctx context.Context, name string, v version.Version) ([]Requirement, error) {
	body, err := r.get(ctx, name, "@v/"+v.String()+".mod", true)
	if err != nil {
		return nil, err
	}

	// A replace directive in a DEPENDENCY's go.mod is ignored by Go itself —
	// only the MAIN module's replacements take effect — so the replacements
	// parsed here are deliberately discarded. Applying them would report a
	// module the build will never use.
	reqs, _ := gomod.Parse(body)
	var out []Requirement
	for _, req := range reqs {
		if req.Indirect {
			continue
		}
		out = append(out, Requirement{
			Name:       req.Module,
			Constraint: req.Version,
			Scope:      graph.Prod,
		})
	}
	return out, nil
}

// get fetches a proxy path, using the content cache when the document is
// immutable.
//
// Immutability is per-path and comes from the protocol: .mod and .info for a
// given version can never change, so they are cached without revalidation. list
// is mutable and is refetched, bounded by maxAge the same way npm and PyPI
// metadata is.
func (r *GoProxyResolver) get(ctx context.Context, module, suffix string, immutable bool) ([]byte, error) {
	key := cache.Key("golang", module, suffix)
	if immutable && r.cache != nil {
		if b, ok := r.cache.Get(key); ok {
			return b, nil
		}
	}

	// Both halves are escaped, and each exactly once: a version can carry a
	// capital too (+Incompatible, or a prerelease tag), and the separators
	// between them must stay literal.
	url := r.base + "/" + escapeModule(module) + "/" + escapeModule(suffix)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("goproxy %s/%s: %s", module, suffix, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if immutable && r.cache != nil {
		_ = r.cache.Put(key, body)
	}
	return body, nil
}

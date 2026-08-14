package walk

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/resolve"
	"github.com/jverhoeks/deepdep/internal/source"
	"github.com/jverhoeks/deepdep/internal/version"
)

// Walker expands a repository into its closure.
//
// Bounds.Version.Mode selects which question is being answered:
// ModeLatest gives the "will" closure (what installs today), ModeAll gives the
// "can" closure (everything a future install could pull).
type Walker struct {
	bounds    Bounds
	resolvers map[string]resolve.Resolver
	registry  *extract.Registry
	// schemes is keyed by ecosystem. Version semantics are not shared: npm
	// ranges and PEP 440 specifiers disagree about ordering, about what "~"
	// means, and about pre-releases, so one scheme cannot serve both.
	schemes map[string]version.VersionScheme
}

func New(b Bounds, resolvers map[string]resolve.Resolver, reg *extract.Registry,
	schemes map[string]version.VersionScheme) *Walker {
	return &Walker{bounds: b.withDefaults(), resolvers: resolvers, registry: reg, schemes: schemes}
}

// req is one unresolved dependency: a raw range that still has to be turned into
// concrete versions.
type req struct {
	from  graph.NodeID
	eco   string
	name  string
	spec  string
	scope graph.Scope
	depth int
}

func (w *Walker) Walk(ctx context.Context, s source.Source, root graph.NodeID) (*graph.Graph, error) {
	g := graph.New()
	g.Add(graph.Node{ID: root, Completeness: graph.Resolved, Name: s.Repo(), Version: s.Ref()})

	frontier, err := w.seed(ctx, s, g, root)
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex // guards g and visited
	visited := map[graph.NodeID]bool{}

	reason := graph.ReasonBoundDepth
	for depth := 1; len(frontier) > 0 && depth <= w.bounds.MaxDepth; depth++ {
		next, err := w.expandLevel(ctx, g, &mu, visited, frontier, depth)
		if err != nil {
			return nil, err
		}
		frontier = next
		// A deadline is a bound like any other. Returning an error here would
		// throw away everything already resolved; naming the frontier keeps the
		// partial answer usable and honest about where it stops.
		if ctx.Err() != nil {
			reason = graph.ReasonTimeout
			break
		}
	}

	// Anything still queued was cut off by a bound. Record it rather than
	// dropping it: an unexplored frontier is a finding, not an omission.
	for _, r := range frontier {
		w.markDeclared(g, r, reason)
	}
	return g, nil
}

// seed runs every matching extractor and converts root edges into requirements.
func (w *Walker) seed(ctx context.Context, s source.Source, g *graph.Graph, root graph.NodeID) ([]req, error) {
	var out []req
	// Read only what an extractor actually claims.
	claimed := func(p string) bool { return len(w.registry.For(p)) > 0 }
	err := s.WalkIf(claimed, func(f source.File) error {
		for _, e := range w.registry.For(f.Path) {
			edges, nodes, err := e.Extract(ctx, f)
			if err != nil {
				return err
			}
			// Extractor-supplied metadata carries completeness only the
			// extractor could know (a moving tag, an opaque run step).
			for _, n := range nodes {
				n.Source = f.Path
				g.Add(n)
			}
			for _, ed := range edges {
				if ed.From == "" {
					ed.From = root // only the walker knows the root's identity
				}
				eco, name, ver, err := split(ed.To)
				if err != nil {
					return err
				}
				if ver != "" {
					// Already concrete. Only synthesise a node if the extractor
					// did not supply one: it knows things we do not (that a
					// `run:` step is Opaque, that a SHA ref is Resolved), and
					// overwriting would silently promote an opaque frontier into
					// an ordinary declared dependency.
					if !g.Has(ed.To) {
						g.Add(graph.Node{ID: ed.To, Ecosystem: eco, Name: name, Version: ver,
							Completeness: graph.Declared, Reason: graph.ReasonUnpinnedRef, Source: f.Path})
					}
					g.Link(ed)
					continue
				}
				out = append(out, req{
					from: ed.From, eco: eco, name: name,
					spec: ed.Spec, scope: ed.Scope, depth: 1,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// expandLevel resolves one whole BFS level concurrently and returns the next.
func (w *Walker) expandLevel(ctx context.Context, g *graph.Graph, mu *sync.Mutex,
	visited map[graph.NodeID]bool, level []req, depth int) ([]req, error) {

	var (
		wg       sync.WaitGroup
		sem      = make(chan struct{}, w.bounds.Concurrency)
		next     []req
		firstErr error
	)

	for _, r := range level {
		r := r
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			kids, err := w.expandOne(ctx, g, mu, visited, r, depth)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			next = append(next, kids...)
		}()
	}
	wg.Wait()
	return next, firstErr
}

func (w *Walker) expandOne(ctx context.Context, g *graph.Graph, mu *sync.Mutex,
	visited map[graph.NodeID]bool, r req, depth int) ([]req, error) {

	res, ok := w.resolvers[r.eco]
	if !ok {
		mu.Lock()
		w.markDeclared(g, r, graph.ReasonOffline)
		mu.Unlock()
		return nil, nil
	}
	scheme, ok := w.schemes[r.eco]
	if !ok {
		// No version semantics for this ecosystem: expanding with the wrong
		// syntax would invent ranges, so record it instead.
		mu.Lock()
		w.markDeclared(g, r, "no-scheme")
		mu.Unlock()
		return nil, nil
	}

	needPublished := !w.bounds.AsOf.IsZero()
	infos, err := res.Versions(ctx, r.name, needPublished)
	if err != nil {
		mu.Lock()
		if ctx.Err() != nil {
			w.markDeclared(g, r, graph.ReasonTimeout)
		} else {
			w.markDeclared(g, r, "error:"+errKind(err))
		}
		mu.Unlock()
		return nil, nil
	}

	avail, err := w.filterAsOf(r, infos)
	if err != nil {
		return nil, err
	}

	// A lockfile has already decided what installs. Honour it in will-mode so the
	// answer matches the package manager; can-mode deliberately ignores it, since
	// its whole question is what the declared range would permit without a lock.
	//
	// The pin is applied by FILTERING candidates, never by synthesising a
	// constraint string: "2.32.3" is a valid npm range but not a valid PEP 440
	// specifier, and building one would be per-ecosystem syntax the walker has no
	// business knowing.
	var chosen []version.Version
	if pinned, ok := w.bounds.Pins[r.eco+"/"+r.name]; ok && w.bounds.Version.Mode == version.ModeLatest {
		for _, v := range avail {
			if v.String() == pinned {
				chosen = append(chosen, v)
				break
			}
		}
		if len(chosen) == 0 {
			mu.Lock()
			w.markDeclared(g, r, "error:pin-not-found")
			mu.Unlock()
			return nil, nil
		}
	} else {
		var err error
		chosen, err = scheme.Enumerate(r.spec, avail, w.bounds.Version)
		if err != nil {
			mu.Lock()
			w.markDeclared(g, r, "error:badrange")
			mu.Unlock()
			return nil, nil
		}
	}

	var kids []req
	for _, v := range chosen {
		id, err := graph.NodeIDFor(r.eco, r.name, v.String())
		if err != nil {
			return nil, err
		}

		mu.Lock()
		overCap := len(g.Nodes()) >= w.bounds.MaxNodes
		if overCap {
			g.Add(graph.Node{ID: id, Ecosystem: r.eco, Name: r.name, Version: v.String(),
				Completeness: graph.Declared, Reason: graph.ReasonBoundNodes})
			g.Link(graph.Edge{From: r.from, To: id, Kind: graph.DependsOn, Spec: r.spec, Scope: r.scope})
			mu.Unlock()
			continue
		}
		g.Add(graph.Node{ID: id, Ecosystem: r.eco, Name: r.name, Version: v.String(),
			Completeness: graph.Resolved, PublishedAt: publishedOf(infos, v)})
		g.Link(graph.Edge{From: r.from, To: id, Kind: graph.DependsOn, Spec: r.spec, Scope: r.scope})
		seen := visited[id]
		visited[id] = true
		mu.Unlock()

		if seen {
			continue // memoised: the subtree is already in the graph
		}

		reqs, err := res.Requirements(ctx, r.name, v)
		if err != nil {
			continue
		}
		for _, q := range reqs {
			child := req{
				from: id, eco: r.eco, name: q.Name,
				spec: q.Constraint, scope: q.Scope, depth: depth + 1,
			}
			if why, skip := skipScope(r.eco, q.Scope); skip {
				// Not installed, so not part of the closure — but recorded rather
				// than dropped, so "we chose not to expand this" stays visible and
				// filterable instead of looking like it does not exist.
				mu.Lock()
				w.markDeclared(g, child, why)
				mu.Unlock()
				continue
			}
			kids = append(kids, child)
		}
	}
	return kids, nil
}

// skipScope decides whether a transitive dependency of this kind actually gets
// installed. The answer is ecosystem-specific and the two big ecosystems
// disagree, so this cannot be one global rule.
func skipScope(eco string, s graph.Scope) (string, bool) {
	switch s {
	case graph.Dev:
		// Dev dependencies are installed for the ROOT project only, and those
		// arrive through the seed. A dev edge reached through a package is not
		// installed by anyone.
		return "dev-not-installed", true
	case graph.Optional:
		if eco == "pypi" {
			// Python extras are opt-in: nothing installs pkg[extra] unless a
			// dependent explicitly asked for that extra. Walking them anyway
			// pulls the whole optional universe — pyobjc alone declares 300+
			// framework subpackages, and fsspec 50 cloud backends.
			//
			// LIMITATION: extras requested explicitly (pydantic[email]) are also
			// skipped, because the requested extra is not yet carried along the
			// edge. That under-reports; the frontier makes it visible.
			return "extra-not-requested", true
		}
		// npm optionalDependencies ARE installed by default; failure to build is
		// tolerated, but the package is fetched and its code is present.
		return "", false
	}
	return "", false
}

// filterAsOf drops versions that did not exist yet at the requested instant.
//
// If the caller asked for a historical resolution but the registry gave us no
// publish times, we fail. Recording an audit flag and then ignoring it would
// produce an answer that looks reproducible and is not.
func (w *Walker) filterAsOf(r req, infos []resolve.VersionInfo) ([]version.Version, error) {
	if w.bounds.AsOf.IsZero() {
		out := make([]version.Version, 0, len(infos))
		for _, i := range infos {
			out = append(out, i.Version)
		}
		return out, nil
	}

	known := false
	for _, i := range infos {
		if !i.PublishedAt.IsZero() {
			known = true
			break
		}
	}
	if !known && len(infos) > 0 {
		return nil, fmt.Errorf("--as-of requested but %s/%s has no publish times: cannot resolve historically",
			r.eco, r.name)
	}

	var out []version.Version
	for _, i := range infos {
		if i.PublishedAt.IsZero() || !i.PublishedAt.After(w.bounds.AsOf) {
			out = append(out, i.Version)
		}
	}
	return out, nil
}

func publishedOf(infos []resolve.VersionInfo, v version.Version) time.Time {
	for _, i := range infos {
		if i.Version.String() == v.String() {
			return i.PublishedAt
		}
	}
	return time.Time{}
}

// markDeclared records an unexpanded requirement as a frontier node.
func (w *Walker) markDeclared(g *graph.Graph, r req, reason string) {
	id, err := graph.NodeIDFor(r.eco, r.name, "")
	if err != nil {
		return
	}
	g.Add(graph.Node{ID: id, Ecosystem: r.eco, Name: r.name,
		Completeness: graph.Declared, Reason: reason, Note: r.spec})
	g.Link(graph.Edge{From: r.from, To: id, Kind: graph.DependsOn, Spec: r.spec, Scope: r.scope})
}

func split(id graph.NodeID) (eco, name, ver string, err error) {
	p, err := packageurl.FromString(string(id))
	if err != nil {
		return "", "", "", err
	}
	name = p.Name
	if p.Namespace != "" {
		name = p.Namespace + "/" + p.Name
	}
	return p.Type, name, p.Version, nil
}

// errKind classifies a fetch failure into a machine-readable Reason suffix, so
// "the registry 404'd" stays queryable and distinct from "we hit a bound".
func errKind(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "404"), strings.Contains(s, "Not Found"):
		return "404"
	case strings.Contains(s, "429"), strings.Contains(s, "rate"):
		return "ratelimit"
	}
	return "fetch"
}

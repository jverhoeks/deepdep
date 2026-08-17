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
	// reason is set only for requirements we deliberately do not expand, so the
	// marking can be batched under one lock instead of taken per skip.
	reason string
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
				// One unparseable file must not abort the repository.
				//
				// A single PEP 735 construct we did not handle killed an entire
				// airflow scan — 300MB of repo reported as nothing at all. The
				// tool's whole premise is that a blind spot gets NAMED rather
				// than silently swallowing the answer, and an aborted run is the
				// most complete swallow there is. The file becomes a frontier
				// carrying the parser's own error, and the walk continues.
				n := extract.ParseErrorNode(e.Name(), f.Path, err)
				g.Add(n)
				g.Link(graph.Edge{From: root, To: n.ID, Kind: graph.Installs})
				continue
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

	// One lock for the whole candidate set, not one per version.
	//
	// The previous shape took the global mutex once per chosen version, and in
	// can-mode a single requirement expands to as many versions as the bound
	// allows — so sixteen workers spent their time queueing on the same lock
	// rather than on the registry. Everything that needs the lock is decided in
	// one pass; the network calls happen outside it.
	type candidate struct {
		id graph.NodeID
		v  version.Version
	}
	var (
		kids   []req
		unseen []candidate
	)

	mu.Lock()
	for _, v := range chosen {
		id, err := graph.NodeIDFor(r.eco, r.name, v.String())
		if err != nil {
			mu.Unlock()
			return nil, err
		}
		if g.Len() >= w.bounds.MaxNodes {
			g.Add(graph.Node{ID: id, Ecosystem: r.eco, Name: r.name, Version: v.String(),
				Completeness: graph.Declared, Reason: graph.ReasonBoundNodes})
			g.Link(graph.Edge{From: r.from, To: id, Kind: graph.DependsOn, Spec: r.spec, Scope: r.scope})
			continue
		}
		g.Add(graph.Node{ID: id, Ecosystem: r.eco, Name: r.name, Version: v.String(),
			Completeness: graph.Resolved, PublishedAt: publishedOf(infos, v)})
		g.Link(graph.Edge{From: r.from, To: id, Kind: graph.DependsOn, Spec: r.spec, Scope: r.scope})
		if visited[id] {
			continue // memoised: the subtree is already in the graph
		}
		visited[id] = true
		unseen = append(unseen, candidate{id, v})
	}
	mu.Unlock()

	var skipped []req
	for _, c := range unseen {
		reqs, err := res.Requirements(ctx, r.name, c.v)
		if err != nil {
			continue
		}
		for _, q := range reqs {
			child := req{
				from: c.id, eco: r.eco, name: q.Name,
				spec: q.Constraint, scope: q.Scope, depth: depth + 1,
			}
			if why, skip := skipScope(r.eco, q.Scope); skip {
				// Not installed, so not part of the closure — but recorded rather
				// than dropped, so "we chose not to expand this" stays visible and
				// filterable instead of looking like it does not exist.
				child.reason = why
				skipped = append(skipped, child)
				continue
			}
			kids = append(kids, child)
		}
	}

	if len(skipped) > 0 {
		mu.Lock()
		for _, c := range skipped {
			w.markDeclared(g, c, c.reason)
		}
		mu.Unlock()
	}
	return kids, nil
}

// Reasons for a frontier the walker chose not to cross because nothing would
// install what is on the other side. They are DECISIONS, not blind spots, and
// consumers must be able to tell the two apart: counting them as unexplored
// coverage suppressed the grade of every repository in a 131-repo fleet, which
// said more about the metric than about the repositories.
const (
	ReasonDevNotInstalled = "dev-not-installed"
	// ReasonExtraNotRequested is no longer PRODUCED: optional dependencies are
	// walked in every ecosystem now (see skipScope). It is retained because runs
	// stored before that change still carry it, and NotInstalled must go on
	// classifying those correctly — deleting it would silently reclassify every
	// historical run's frontier as an unexplored blind spot and suppress its
	// grade.
	ReasonExtraNotRequested = "extra-not-requested"
)

// NotInstalled reports whether a frontier reason means "deliberately out of the
// install" rather than "we could not see past this".
func NotInstalled(reason string) bool {
	return reason == ReasonDevNotInstalled || reason == ReasonExtraNotRequested
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
		return ReasonDevNotInstalled, true
	case graph.Optional:
		// Optional dependencies are WALKED, in every ecosystem. The closure takes
		// the widest reading: an extra or a feature-gated crate is code a
		// consumer can switch on without the repository it belongs to changing a
		// line, so it is genuinely reachable and belongs in the answer.
		//
		// PyPI extras used to be skipped here. The rationale was real — pyobjc
		// declares 300+ framework subpackages and fsspec 50 cloud backends — but
		// it is an argument about SIZE, and size is what MaxNodes and MaxDepth
		// exist to bound. Trading a wrong answer for a small one is the trade
		// this tool is meant not to make: on one Poetry repository it left 125
		// packages behind `extra-not-requested` against 55 resolved.
		//
		// npm optionalDependencies were never skipped: they are installed by
		// default, and a failure to build is tolerated rather than preventing the
		// fetch. This now matches.
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
	// The declared range does NOT go on the node.
	//
	// A range is per-occurrence: seven parents can want seven different ranges
	// of the same package, and the node is deduplicated, so whichever concurrent
	// worker arrives last decides what Note says. Two runs of an identical scan
	// then differ — react emitted "^7.2.0" and "^7.18.9" for the same node on
	// consecutive runs — which breaks the reproducibility guarantee outright.
	//
	// Edge.Spec below already records every range, once per parent, losing
	// nothing. Third time this codebase has had to relearn that multiplicity
	// belongs on edges.
	g.Add(graph.Node{ID: id, Ecosystem: r.eco, Name: r.name,
		Completeness: graph.Declared, Reason: reason})
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

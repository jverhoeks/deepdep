package graph

import (
	"slices"
	"strings"
)

// Graph is the heterogeneous closure.
//
// Identity is deduplicated; paths are not. A package pulled in by seven parents
// is ONE node with seven inbound edges, and "why is this here?" must be able to
// answer with all seven chains. Deduping the node is what makes caching, CVE
// lookup and the walker's visited-set work; keeping every edge is what preserves
// provenance.
//
// Graph is not safe for concurrent use; the walker owns synchronisation.
type Graph struct {
	nodes    map[NodeID]Node
	edges    []Edge
	edgeSeen map[Edge]bool
	inbound  map[NodeID][]Edge
}

func New() *Graph {
	return &Graph{
		nodes:    map[NodeID]Node{},
		edgeSeen: map[Edge]bool{},
		inbound:  map[NodeID][]Edge{},
	}
}

// Add inserts a node, or upgrades one already present.
//
// Completeness moves upward only. A node first seen as Declared because a bound
// was hit, then later reached within bounds, becomes Resolved; it can never
// regress. On upgrade the incoming node replaces the old wholesale, which also
// drops the stale Reason ("bound:depth" is no longer true once we resolved it,
// and leaving it would lie in the audit output).
func (g *Graph) Add(n Node) {
	if old, ok := g.nodes[n.ID]; ok {
		if rank(n.Completeness) <= rank(old.Completeness) {
			return
		}
	}
	g.nodes[n.ID] = n
}

// Link records a relation, ignoring an exact duplicate of one already recorded.
func (g *Graph) Link(e Edge) {
	if g.edgeSeen[e] {
		return
	}
	g.edgeSeen[e] = true
	g.edges = append(g.edges, e)
	g.inbound[e.To] = append(g.inbound[e.To], e)
}

func (g *Graph) Node(id NodeID) Node { return g.nodes[id] }

// Len is the node count, in constant time.
//
// It exists because the walker checked its node bound with len(g.Nodes()),
// which allocates a slice of every node and SORTS it — O(n log n) plus an
// allocation of the whole graph — once per candidate version, per requirement,
// while holding the walker's global mutex. In can-mode, where every requirement
// expands to many versions, that turned the bound check into the dominant cost
// and serialised all sixteen workers behind it.
func (g *Graph) Len() int { return len(g.nodes) }

func (g *Graph) Has(id NodeID) bool {
	_, ok := g.nodes[id]
	return ok
}

func (g *Graph) Edges() []Edge { return g.edges }

// InboundTo returns every edge pointing at id — one per dependency thread.
func (g *Graph) InboundTo(id NodeID) []Edge { return g.inbound[id] }

// Nodes returns nodes sorted by ID. Go map iteration order is randomised, so
// without this two identical runs would emit different byte streams and the
// reproducibility guarantee would be untestable.
func (g *Graph) Nodes() []Node {
	out := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	slices.SortFunc(out, func(a, b Node) int {
		return strings.Compare(string(a.ID), string(b.ID))
	})
	return out
}

// PathsTo walks inbound edges breadth-first and returns up to maxPaths chains
// from a root down to id, shortest first.
//
// Bounded on purpose: the number of distinct paths is exponential in a dense
// DAG. This answers "show me how this got here" for a human. It is NOT how
// PathCount is computed — len(PathsTo(id, n)) is just min(n, truth), which is
// useless as a statistic; the rollup pass counts paths with a DP over the SCC
// condensation instead.
func (g *Graph) PathsTo(id NodeID, maxPaths int) [][]NodeID {
	var out [][]NodeID
	type item struct {
		node NodeID
		path []NodeID
	}
	queue := []item{{id, []NodeID{id}}}
	for len(queue) > 0 && len(out) < maxPaths {
		cur := queue[0]
		queue = queue[1:]

		in := g.InboundTo(cur.node)
		if len(in) == 0 { // a root
			out = append(out, cur.path)
			continue
		}
		for _, e := range in {
			if slices.Contains(cur.path, e.From) {
				continue // cycle guard: npm graphs really do contain them
			}
			next := make([]NodeID, 0, len(cur.path)+1)
			next = append(next, e.From)
			next = append(next, cur.path...)
			queue = append(queue, item{e.From, next})
		}
	}
	return out
}

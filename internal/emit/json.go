// Package emit renders a closure.
//
// The native JSON graph is the PRIMARY artifact. CycloneDX and SPDX describe one
// resolved bill of materials and have no way to express a version-range space,
// so they are lossy projections of the "will" slice — useful for interop, but
// not the product.
package emit

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// Meta is the provenance every run carries.
//
// KnownAt is recorded even though v1 has no advisory enrichment to consume it.
// Omitting the field now would foreclose bitemporal replay later: a run that
// never wrote down its knowledge instant cannot be re-audited against it.
type Meta struct {
	AsOf        time.Time `json:"as_of"`
	KnownAt     time.Time `json:"known_at"`
	Ref         string    `json:"ref"`
	Repo        string    `json:"repo"`
	Mode        string    `json:"mode"`
	ToolVersion string    `json:"tool_version"`
	Bounds      any       `json:"bounds,omitempty"`
}

type summary struct {
	Total    int `json:"total"`
	Resolved int `json:"resolved"`
	Declared int `json:"declared"`
	Inferred int `json:"inferred"`
	Opaque   int `json:"opaque"`
}

type document struct {
	Meta
	Summary   summary      `json:"summary"`
	BoundsHit []string     `json:"bounds_hit"`
	Nodes     []graph.Node `json:"nodes"`
	Edges     []graph.Edge `json:"edges"`
}

// JSON writes the full graph, deterministically.
func JSON(w io.Writer, g *graph.Graph, m Meta) error {
	nodes := g.Nodes() // already sorted by ID
	edges := append([]graph.Edge(nil), g.Edges()...)
	// The sort key must cover every field the graph deduplicates on. A package
	// can be both a prod and a peer dependency of the same parent under the same
	// range: those are two distinct edges differing ONLY in scope, so leaving
	// scope out of the comparator leaves their order undefined and the output
	// non-reproducible.
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Spec != b.Spec {
			return a.Spec < b.Spec
		}
		return a.Scope < b.Scope
	})

	var s summary
	reasons := map[string]bool{}
	for _, n := range nodes {
		s.Total++
		switch n.Completeness {
		case graph.Resolved:
			s.Resolved++
		case graph.Declared:
			s.Declared++
		case graph.Inferred:
			s.Inferred++
		case graph.Opaque:
			s.Opaque++
		}
		if n.Reason != "" {
			reasons[n.Reason] = true
		}
	}
	// Naming why the closure stopped is part of the answer: a silently shorter
	// list reads as "we covered everything" when we did not.
	hit := make([]string, 0, len(reasons))
	for r := range reasons {
		hit = append(hit, r)
	}
	sort.Strings(hit)

	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(document{Meta: m, Summary: s, BoundsHit: hit, Nodes: nodes, Edges: edges})
}

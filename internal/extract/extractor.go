// Package extract turns files in a repository into graph edges.
//
// This is the plugin seam that makes the tool extensible: every new supply-chain
// source the user thinks of — Dockerfiles, pre-commit configs, Python manifests,
// Cargo.toml — lands as one more Extractor behind an unchanged core.
package extract

import (
	"context"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// Extractor discovers what a single file pulls in.
//
// Extract returns BOTH edges and node metadata. Only the extractor knows a
// node's completeness — that `uses: org/repo@v4` is a moving tag and must be
// Declared, or that a `run:` step is Opaque. Returned nodes may be partial; the
// walker merges them with Graph.Add, which upgrades monotonically. There is no
// side-channel second method, because a polymorphic registry can only call what
// the interface declares.
type Extractor interface {
	Name() string
	Match(path string) bool
	Extract(ctx context.Context, f source.File) ([]graph.Edge, []graph.Node, error)
}

// Registry dispatches files to the extractors that claim them.
type Registry struct{ extractors []Extractor }

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(e Extractor) { r.extractors = append(r.extractors, e) }

// For returns every extractor willing to handle path. More than one may claim a
// file; all of them run.
func (r *Registry) For(path string) []Extractor {
	var out []Extractor
	for _, e := range r.extractors {
		if e.Match(path) {
			out = append(out, e)
		}
	}
	return out
}

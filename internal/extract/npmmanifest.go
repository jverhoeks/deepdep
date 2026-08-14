package extract

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
	"github.com/jverhoeks/deepdep/internal/version"
)

// NPMManifest reads package.json.
//
// It emits VERSION-LESS targets carrying the raw declared range. That is the
// whole point: the manifest says "^4.17.0", not "4.17.21". Resolving a range to
// one pin here would throw away the range space before the walker ever sees it,
// and the range space is what distinguishes "can" from "will".
type NPMManifest struct{}

func (NPMManifest) Name() string { return "npm-manifest" }

func (NPMManifest) Match(p string) bool {
	if path.Base(p) != "package.json" {
		return false
	}
	// Anything under node_modules is an installed artifact, not a declaration.
	for _, seg := range strings.Split(p, "/") {
		if seg == "node_modules" {
			return false
		}
	}
	return true
}

type npmManifestDoc struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func (NPMManifest) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	var doc npmManifestDoc
	if err := json.Unmarshal(f.Data, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", f.Path, err)
	}

	var edges []graph.Edge
	add := func(deps map[string]string, scope graph.Scope) error {
		// Sorted so extraction is deterministic; map order would leak into output.
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			// "npm:real-name@^1.2.3" installs a different package under an alias.
			// Follow it: the aliased package is what actually gets pulled in.
			name, spec := version.NPMAlias(n, deps[n])
			id, err := graph.NPMNodeID(name, "") // version-less: still just a range
			if err != nil {
				return fmt.Errorf("%s: %w", f.Path, err)
			}
			edges = append(edges, graph.Edge{
				From:  "", // the walker rewrites this to the run's root node
				To:    id,
				Kind:  graph.DependsOn,
				Spec:  spec,
				Scope: scope,
			})
		}
		return nil
	}

	for _, g := range []struct {
		deps  map[string]string
		scope graph.Scope
	}{
		{doc.Dependencies, graph.Prod},
		{doc.DevDependencies, graph.Dev},
		{doc.PeerDependencies, graph.Peer},
		{doc.OptionalDependencies, graph.Optional},
	} {
		if err := add(g.deps, g.scope); err != nil {
			return nil, nil, err
		}
	}

	// No nodes: a version-less target has no metadata the manifest can supply.
	// The resolver mints concrete version nodes later.
	return edges, nil, nil
}

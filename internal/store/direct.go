package store

import (
	"context"
	"sort"
	"strings"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
)

// Surface names the kind of file in WHICH THIS REPOSITORY writes a dependency
// down. It is the difference between a finding a maintainer can fix by editing
// one line and a finding they can only wait for someone else to fix.
const (
	SurfaceManifest   = "manifest"   // package.json, requirements.txt, go.mod, ...
	SurfaceCI         = "ci"         // a workflow's uses:, image:, or install step
	SurfaceDockerfile = "dockerfile" // FROM, and apt/apk/pip lines in RUN
)

// Surfaces reports, for every node, which of the repository's own files name it.
//
// "Direct" cannot mean "one edge from the root", which is what the rollup's
// Direct column means. A base image is named in a Dockerfile and a CI action is
// named in a workflow, and both hang off a FILE node rather than off the root —
// so a root-only definition classifies `FROM python:3.12` and
// `uses: actions/checkout@v4` as *transitive*, which is precisely backwards.
// They are the most direct things in the repository: a maintainer changes them
// by editing one line, with nobody upstream to wait for.
//
// The rule is therefore structural rather than positional: a node is
// first-party if something that is NOT a package points at it. Only the root
// and the build-file nodes are non-packages with outbound edges — every
// extractor hangs its findings off one or the other — so this identifies
// exactly the set of artifacts the repository names itself, at any depth.
//
// A node can be named by several surfaces at once (a package pinned in
// requirements.txt and installed again in a Dockerfile RUN line), so the value
// is a sorted slice and not a single label. Nodes absent from the map are
// transitive: nothing in this repository asked for them by name.
func (s *Store) Surfaces(ctx context.Context, runID string) (map[graph.NodeID][]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT from_id, to_id, spec FROM edges WHERE run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := map[graph.NodeID]map[string]bool{}
	for rows.Next() {
		var from, to, spec string
		if err := rows.Scan(&from, &to, &spec); err != nil {
			return nil, err
		}
		if graph.IsPackage(graph.NodeID(from)) {
			continue // an upstream package pulling in another: transitive
		}
		// Root edges are two different things wearing one shape. An extractor's
		// edge carries the declared range; effective.Merge's carries nothing,
		// because it records where npm PLACED a package rather than that anyone
		// asked for it. npm hoists nearly every transitive package to the top
		// level, so counting placements as declarations turned axios' 60
		// declared dependencies into 122 — and would have reported a hoisted
		// sub-sub-dependency's CVE as the maintainer's own line to fix.
		//
		// Build-file edges are exempt: a Dockerfile's FROM and a workflow's
		// uses: are declarations that have no range to carry.
		if !strings.HasPrefix(from, extract.BuildFilePrefix) && spec == "" &&
			graph.IsPackage(graph.NodeID(to)) {
			continue
		}
		id := graph.NodeID(to)
		if seen[id] == nil {
			seen[id] = map[string]bool{}
		}
		seen[id][surfaceOf(from)] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make(map[graph.NodeID][]string, len(seen))
	for id, kinds := range seen {
		list := make([]string, 0, len(kinds))
		for k := range kinds {
			list = append(list, k)
		}
		sort.Strings(list)
		out[id] = list
	}
	return out, nil
}

// ActionTargets lists the CI actions a run invoked.
//
// They are not in version_rollup and never will be: an action is not a package
// version, and treating it as one is what inflated every "checked N packages"
// claim before graph.IsPackage existed. But they ARE the most direct dependency
// a repository has, and OSV holds advisories for them, so they need their own
// way out of the store.
func (s *Store) ActionTargets(ctx context.Context, runID string) ([]graph.NodeID, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM nodes WHERE run_id=? AND id LIKE 'pkg:github/%' ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []graph.NodeID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, graph.NodeID(id))
	}
	return out, rows.Err()
}

// surfaceOf reads the surface back off the id of whatever named the node.
//
// Build-file nodes carry their kind in the PURL name component, which is why
// BuildFilePrefix is exported and documented as stable. Anything else with
// outbound edges is the run's root, and the root's own edges are the ones an
// extractor emitted from a manifest.
func surfaceOf(from string) string {
	if !strings.HasPrefix(from, extract.BuildFilePrefix) {
		return SurfaceManifest
	}
	kind, _, _ := strings.Cut(strings.TrimPrefix(from, extract.BuildFilePrefix), "@")
	switch kind {
	case "dockerfile":
		return SurfaceDockerfile
	default:
		// workflow, gitlab-ci, and any CI format added later. They differ in
		// syntax and not in what a reader does about them.
		return SurfaceCI
	}
}

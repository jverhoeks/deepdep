package store

import (
	"context"
	"strings"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
)

// ManifestSurfaceLabel stands for every manifest at once.
//
// Manifest extractors emit their edges straight to the repository root, so the
// graph cannot say which of a monorepo's 693 package.json files declared a
// package — Dockerfiles and workflows can, because they hang their findings off
// a file node. The plural is deliberate: a reader must not take this for one
// file.
const ManifestSurfaceLabel = "all manifests"

// SurfaceFile is one build-definition file and everything it names.
//
// Surfaces() answers "which KIND of file names this package", which is what the
// reach split needs. A diagram needs the other direction and one level finer:
// which file, by path, and what did that particular file pull in. A repository
// with 94 workflows has 94 different answers, and collapsing them loses exactly
// the attribution the file nodes exist to preserve.
type SurfaceFile struct {
	ID   graph.NodeID
	Kind string // dockerfile | ci | manifest
	Path string
	// Names is everything this file pulls in, whether or not it is auditable —
	// a base image and a CI action are named here even though no advisory
	// database will answer for them.
	Names []graph.NodeID
	// Moving counts the names on a reference that can be repointed: a tag
	// rather than a digest, a branch rather than a SHA.
	Moving int
}

// SurfaceFiles groups a run's first-party artifacts by the file that names them.
//
// The root is returned as a synthetic "manifest" entry rather than one entry per
// manifest, and that is a limitation rather than a choice: manifest extractors
// emit their edges straight to the repository root, so the graph cannot say
// which of a monorepo's 693 package.json files declared a package. Dockerfiles
// and workflows can, because they hang their findings off a file node. The
// synthetic entry is labelled so a reader is not misled into thinking one
// manifest was responsible.
func (s *Store) SurfaceFiles(ctx context.Context, runID string) ([]SurfaceFile, error) {
	reason := map[graph.NodeID]string{}
	nodes, err := s.Nodes(ctx, runID)
	if err != nil {
		return nil, err
	}
	label := map[graph.NodeID]string{}
	for _, n := range nodes {
		reason[n.ID] = n.Reason
		if n.Note != "" && strings.HasPrefix(string(n.ID), extract.BuildFilePrefix) {
			label[n.ID] = n.Note // the path, carried verbatim by BuildFileNode
		}
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT from_id, to_id, spec FROM edges WHERE run_id = ? ORDER BY from_id, to_id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byFile := map[graph.NodeID]*SurfaceFile{}
	order := []graph.NodeID{}
	for rows.Next() {
		var from, to, spec string
		if err := rows.Scan(&from, &to, &spec); err != nil {
			return nil, err
		}
		if graph.IsPackage(graph.NodeID(from)) {
			continue // one upstream package pulling in another: not first-party
		}
		// A build file's own node is named BY the root; it is a file, not a
		// dependency, and listing it as one would put every Dockerfile in the
		// root's package list.
		if strings.HasPrefix(to, extract.BuildFilePrefix) {
			continue
		}
		// Same placement rule as Surfaces: a root edge with no spec is where npm
		// hoisted something, not something the repository asked for.
		isFile := strings.HasPrefix(from, extract.BuildFilePrefix)
		if !isFile && spec == "" && graph.IsPackage(graph.NodeID(to)) {
			continue
		}

		key := graph.NodeID(from)
		f, ok := byFile[key]
		if !ok {
			f = &SurfaceFile{ID: key, Kind: surfaceOf(from)}
			if isFile {
				f.Path = label[key]
			} else {
				f.Path = ManifestSurfaceLabel
			}
			byFile[key] = f
			order = append(order, key)
		}
		f.Names = append(f.Names, graph.NodeID(to))
		if reason[graph.NodeID(to)] == graph.ReasonUnpinnedRef {
			f.Moving++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]SurfaceFile, 0, len(order))
	for _, id := range order {
		out = append(out, *byFile[id])
	}
	return out, nil
}

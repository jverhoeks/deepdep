package store

import (
	"context"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/reach"
)

// PackageEdges returns the package-to-package edges of a run, which is the graph
// reachability walks.
//
// Non-package endpoints are dropped here rather than in the caller. A build file,
// a shell step and a workflow are all legitimate nodes with outbound edges, and
// leaving them in would let a walk pass THROUGH a Dockerfile node from one
// application into another's dependencies — attributing a finding to a direct
// dependency that has nothing to do with it.
func (s *Store) PackageEdges(ctx context.Context, runID string) ([]reach.Edge, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT from_id, to_id FROM edges WHERE run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []reach.Edge
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			return nil, err
		}
		if !graph.IsPackage(graph.NodeID(from)) || !graph.IsPackage(graph.NodeID(to)) {
			continue
		}
		out = append(out, reach.Edge{From: graph.NodeID(from), To: graph.NodeID(to)})
	}
	return out, rows.Err()
}

// PinningByNode returns how firmly each package version is held: "pinned",
// "locked", "floating" or "" when the rollup could not say.
//
// PinningCounts answers the same question in aggregate and is what the score
// reads. This returns it per node so the report can ask it of one part of the
// closure — "how much of what we INHERITED can move under us" is a different
// question from the repository-wide ratio, and the answers routinely differ.
func (s *Store) PinningByNode(ctx context.Context, runID string) (map[graph.NodeID]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, pinning FROM version_rollup WHERE run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[graph.NodeID]string{}
	for rows.Next() {
		var id, pin string
		if err := rows.Scan(&id, &pin); err != nil {
			return nil, err
		}
		out[graph.NodeID(id)] = pin
	}
	return out, rows.Err()
}

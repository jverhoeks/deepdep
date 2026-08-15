package emit

import (
	"path"
	"sort"
	"strings"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/graph"
)

// Unit is one deliverable inside a repository: an application's package
// environment, one container image, or the shared pipeline.
//
// A monorepo's single 1384-component BOM answers nobody's question. "What does
// the backend ship?" and "what goes into cli/Dockerfile?" are different
// documents, and the handbook's own prescription for multi-layer products is
// one SBOM per layer merged hierarchically — which needs the layers to exist as
// separate documents first.
type Unit struct {
	Name  string // backend, cli, cli/Dockerfile, _repo
	Kind  string // application | image | repository
	Graph *graph.Graph
	Root  graph.NodeID
}

// Split partitions a closure into per-deliverable subgraphs.
//
// Three assignment rules, in order:
//
//  1. An instance's locator directory names an APPLICATION. The lockfile
//     already decided what installs where, so this is read, not inferred.
//  2. Everything reachable from a Dockerfile's file node belongs to that IMAGE.
//  3. Whatever is left — the CI pipeline, its steps and base images, the
//     coverage frontiers — goes to a single REPOSITORY unit.
//
// Rule 3 is the one worth stating out loud. Repo-level artifacts have no
// instance locator and belong to no application. Duplicating them into every
// per-app document would inflate each one and double-count the union; dropping
// them would make every document look cleaner than the repository is. They get
// their own document instead, which is also what a hierarchical merge expects.
//
// A node may appear in several units — a base image shared by two Dockerfiles,
// a package installed by two apps. That is correct: each document must stand
// alone, and the merge re-establishes the relationships.
func Split(g *graph.Graph, inst []effective.Instance, root graph.NodeID) []Unit {
	byID := map[graph.NodeID]graph.Node{}
	for _, n := range g.Nodes() {
		byID[n.ID] = n
	}
	out := map[graph.NodeID][]graph.Edge{}
	for _, e := range g.Edges() {
		out[e.From] = append(out[e.From], e)
	}

	members := map[string]map[graph.NodeID]bool{}
	kinds := map[string]string{}
	add := func(unit, kind string, id graph.NodeID) {
		if members[unit] == nil {
			members[unit] = map[graph.NodeID]bool{}
			kinds[unit] = kind
		}
		members[unit][id] = true
	}

	claimed := map[graph.NodeID]bool{root: true}

	// 1. Applications, from the effective resolution.
	for _, i := range inst {
		dir, _, ok := strings.Cut(i.Locator, "#")
		if !ok || dir == "" {
			dir = "." // a single-project repo has no directory prefix
		}
		add(dir, "application", i.NodeID)
		claimed[i.NodeID] = true
	}

	// 2. Images, from each Dockerfile's file node.
	for _, n := range g.Nodes() {
		if !isFileNode(n) {
			continue
		}
		unit := n.Note // the file path
		claimed[n.ID] = true
		for _, id := range reachable(out, n.ID) {
			// A build step is not a component and never becomes one, but it is
			// claimed so it does not fall through to the repository unit.
			claimed[id] = true
			if !isBuildStep(byID[id]) {
				add(unit, "image", id)
			}
		}
		if members[unit] == nil {
			add(unit, "image", n.ID) // a FROM-less Dockerfile still gets a document
			delete(members[unit], n.ID)
		}
	}

	// 3. Everything else.
	for _, n := range g.Nodes() {
		if claimed[n.ID] || isBuildStep(n) {
			continue
		}
		add("_repo", "repository", n.ID)
	}

	names := make([]string, 0, len(members))
	for u := range members {
		names = append(names, u)
	}
	sort.Strings(names)

	units := make([]Unit, 0, len(names))
	for _, name := range names {
		units = append(units, Unit{
			Name:  name,
			Kind:  kinds[name],
			Graph: subgraph(g, byID, members[name], root, name, kinds[name]),
			Root:  unitRoot(name),
		})
	}
	return units
}

// subgraph rebuilds a standalone closure for one unit.
//
// The unit gets a SYNTHETIC root so its document has a metadata.component of its
// own — "backend", not "the whole repository". Edges are the induced subgraph
// plus a root edge to anything with no surviving parent, so nothing floats
// unattached and dependencies[] stays connected.
func subgraph(g *graph.Graph, byID map[graph.NodeID]graph.Node,
	member map[graph.NodeID]bool, repoRoot graph.NodeID, name, kind string) *graph.Graph {

	sub := graph.New()
	rootID := unitRoot(name)
	sub.Add(graph.Node{
		ID: rootID, Name: path.Base(name), Version: unitVersion,
		Ecosystem: "generic", Completeness: graph.Resolved, Note: kind + " " + name,
	})
	for id := range member {
		sub.Add(byID[id])
	}

	hasParent := map[graph.NodeID]bool{}
	for _, e := range g.Edges() {
		if !member[e.From] || !member[e.To] {
			continue
		}
		sub.Link(e)
		hasParent[e.To] = true
	}
	for id := range member {
		if !hasParent[id] {
			sub.Link(graph.Edge{From: rootID, To: id, Kind: graph.DependsOn})
		}
	}
	_ = repoRoot
	return sub
}

// unitVersion is a placeholder: a unit's own version lives in its manifest, and
// inventing one would be a fact we did not read.
const unitVersion = "unversioned"

func unitRoot(name string) graph.NodeID {
	return graph.NodeID("pkg:generic/" + sanitiseUnit(name) + "@" + unitVersion)
}

// sanitiseUnit keeps the PURL parseable. Slashes would be read as a namespace
// separator and split "quickstart/demos/energy-utility/data" into pieces.
func sanitiseUnit(s string) string {
	r := strings.NewReplacer("/", ".", " ", "-")
	s = r.Replace(strings.TrimPrefix(s, "./"))
	if s == "." || s == "" {
		return "root"
	}
	return s
}

func reachable(out map[graph.NodeID][]graph.Edge, from graph.NodeID) []graph.NodeID {
	seen := map[graph.NodeID]bool{from: true}
	queue := []graph.NodeID{from}
	var res []graph.NodeID
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range out[cur] {
			if seen[e.To] {
				continue
			}
			seen[e.To] = true
			res = append(res, e.To)
			queue = append(queue, e.To)
		}
	}
	return res
}

// Package reach answers the question an inherited advisory always raises: this
// package is not in any file I own, so what can I actually do about it?
//
// Severity says how bad a finding is and the exposure table says whether anyone
// here named the affected package. Neither says which of a repository's OWN
// dependencies dragged it in — and for a transitive finding that is the entire
// actionable content. A maintainer cannot edit a line for `spin@0.4.10`; they
// can bump the direct dependency whose subtree contains it.
package reach

import (
	"sort"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// Edge is a dependency edge, narrowed to the two fields reachability needs.
type Edge struct{ From, To graph.NodeID }

// Introducer is one direct dependency and the inherited findings underneath it.
type Introducer struct {
	// Direct is the dependency this repository names in one of its own files.
	Direct graph.NodeID `json:"direct"`
	// Affected is how many distinct affected packages sit in its subtree.
	Affected int `json:"affected"`
	// Exclusive is how many of those are reachable through NO other direct
	// dependency — the ones this bump alone would clear. The gap between the two
	// is the honest part: a package pulled in by four direct dependencies is not
	// fixed by upgrading one of them, and a list showing only Affected would
	// promise four fixes where one exists.
	Exclusive int `json:"exclusive"`
	// New is set only on plan entries: how many the pick clears that earlier
	// picks in the same plan did not.
	New int `json:"new,omitempty"`
}

// Analysis is the whole answer, computed in one pass over the graph.
type Analysis struct {
	// Introducers rank direct dependencies by how much sits beneath them.
	Introducers []Introducer `json:"introducers,omitempty"`
	// Plan is the greedy shortest route, at most PlanLimit long.
	Plan []Introducer `json:"plan,omitempty"`
	// Clears is how many affected packages Plan accounts for.
	Clears int `json:"clears"`
	// Affected is every inherited finding's package.
	Affected int `json:"affected"`
	// Attributed is how many of those sit under at least one direct dependency.
	//
	// The gap matters and used to be invisible. "5 bumps clear 83 of 85" has two
	// very different causes — a plan cut short by its limit, where a sixth bump
	// finishes the job, and packages that no direct dependency reaches at all,
	// where no bump does. A reader acts differently on each, and the same
	// sentence was printed for both. Unattributed findings are UNASSIGNED, not
	// unimportant, in the same way an ungraded repository is unassessed and not
	// clean.
	Attributed int `json:"attributed"`
	// Capped reports that Plan stopped at its limit with work left.
	Capped bool `json:"capped"`
}

// Unattributed is the count no bump in the plan can clear.
func (a Analysis) Unattributed() int { return a.Affected - a.Attributed }

// subtrees maps each direct dependency to the affected packages beneath it.
//
// Only INDIRECT findings are attributed. A direct dependency that is itself
// affected is already a line the maintainer can edit, and folding that into the
// blast radius would count the easy fix twice — which is also why a walk stops
// when it meets another direct dependency rather than absorbing its subtree.
func subtrees(direct []graph.NodeID, affected map[graph.NodeID]bool, edges []Edge) map[graph.NodeID]map[graph.NodeID]bool {
	adj := map[graph.NodeID][]graph.NodeID{}
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	isDirect := make(map[graph.NodeID]bool, len(direct))
	for _, d := range direct {
		isDirect[d] = true
	}

	out := map[graph.NodeID]map[graph.NodeID]bool{}
	for _, d := range direct {
		hit := map[graph.NodeID]bool{}
		// Iterative, with a visited set: dependency graphs contain cycles, and a
		// recursive walk over one does not return.
		seen := map[graph.NodeID]bool{d: true}
		queue := []graph.NodeID{d}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, next := range adj[cur] {
				if seen[next] {
					continue
				}
				seen[next] = true
				if isDirect[next] {
					continue
				}
				if affected[next] {
					hit[next] = true
				}
				queue = append(queue, next)
			}
		}
		if len(hit) > 0 {
			out[d] = hit
		}
	}
	return out
}

// Analyse attributes inherited findings to direct dependencies and plans the
// shortest route through them.
//
// One pass builds the subtrees and everything else is derived from them. Two
// entry points each walking the graph was the earlier shape, and the report
// called both — twice the work per repository, 186 times over a fleet.
func Analyse(direct []graph.NodeID, affected map[graph.NodeID]bool, edges []Edge, planLimit int) Analysis {
	a := Analysis{Affected: len(affected)}
	if len(direct) == 0 || len(affected) == 0 {
		return a
	}
	sets := subtrees(direct, affected, edges)

	// Reaching one affected package from two direct dependencies is normal — npm
	// and Cargo closures overlap heavily — so the subtrees are kept whole rather
	// than assigning each finding to a single owner.
	owners := map[graph.NodeID]int{}
	for _, hit := range sets {
		for id := range hit {
			owners[id]++
		}
	}
	a.Attributed = len(owners)

	a.Introducers = make([]Introducer, 0, len(sets))
	for d, hit := range sets {
		in := Introducer{Direct: d, Affected: len(hit)}
		for id := range hit {
			if owners[id] == 1 {
				in.Exclusive++
			}
		}
		a.Introducers = append(a.Introducers, in)
	}
	sort.Slice(a.Introducers, func(i, j int) bool {
		x, y := a.Introducers[i], a.Introducers[j]
		if x.Affected != y.Affected {
			return x.Affected > y.Affected
		}
		if x.Exclusive != y.Exclusive {
			return x.Exclusive > y.Exclusive
		}
		return x.Direct < y.Direct // deterministic across runs
	})

	// Greedy, not optimal: minimum set cover is NP-hard, and this is read as
	// "start here", not as a proof. Picking by MARGINAL gain rather than by raw
	// Affected is what makes the list worth printing — the second-largest subtree
	// is often a subset of the largest, and ranking by size alone recommends a
	// second bump that clears nothing new.
	remaining := make(map[graph.NodeID]map[graph.NodeID]bool, len(sets))
	for d, hit := range sets {
		remaining[d] = hit
	}
	done := map[graph.NodeID]bool{}
	for planLimit > 0 && len(a.Plan) < planLimit {
		var best graph.NodeID
		var gain int
		for d, hit := range remaining {
			n := 0
			for id := range hit {
				if !done[id] {
					n++
				}
			}
			// Ties broken by name so two runs of one scan agree.
			if n > gain || (n > 0 && n == gain && d < best) {
				best, gain = d, n
			}
		}
		if gain == 0 {
			break
		}
		for id := range remaining[best] {
			done[id] = true
		}
		a.Plan = append(a.Plan, Introducer{
			Direct: best, Affected: len(remaining[best]), New: gain,
		})
		delete(remaining, best)
	}
	a.Clears = len(done)
	a.Capped = a.Clears < a.Attributed
	return a
}

// Package rollup derives the flat, actionable package list from the graph.
//
// Two views serve different needs. The graph answers "why is this here?" with
// full provenance; nobody scans ten thousand nodes to decide what to fix. This
// package produces the table they actually read, and the graph is what they
// drill into from a row.
package rollup

import (
	"sort"

	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/version"
)

// PathCap bounds the path counter. Path counts grow combinatorially, so the
// arithmetic saturates and anything at the cap is reported as "10000+" rather
// than as a precise-looking wrong number.
const PathCap = 10000

// State answers "will this land on disk?".
//
// It is ORTHOGONAL to graph.Completeness, which answers "how well do we know
// this?". A package can be Possible and fully resolved (we know exactly which
// version a future install could pull), or Installed and merely inferred (it
// lands on disk but we guessed it from a shell line). One enum cannot say both.
type State string

const (
	// Installed: present in the effective resolution — this lands on disk today.
	Installed State = "installed"
	// Possible: reachable only through the can-closure. A future install could
	// pull it, but today's resolution does not.
	Possible State = "possible"
	// Unknown: no effective resolution was available (no lockfile, no
	// simulation). Calling this "possible" would lie in the other direction.
	Unknown State = "unknown"
)

// Pinning answers "what is holding this version in place, and how firmly?".
//
// It is a THIRD axis, independent of State (will it land on disk?) and
// Completeness (how well do we know it?). Two packages can both be installed at
// 4.6.1 and carry completely different exposure:
//
//	pyproject: ">4.5.0" + lock 4.6.1  -> Locked. Regenerate the lock and it moves.
//	pyproject: "==4.6.1"              -> Pinned. Regenerating changes nothing.
//
// Collapsing them would report the same risk for the two, which is the mistake
// the axis exists to prevent.
type Pinning string

const (
	// Pinned: every declared constraint reaching this package admits exactly one
	// version. The manifest itself is the constraint.
	Pinned Pinning = "pinned"
	// Locked: a lockfile fixes the version, but a declared range is wider — so a
	// lock regeneration can move it without any manifest change.
	Locked Pinning = "locked"
	// Floating: nothing fixes it. The next install decides.
	Floating Pinning = "floating"
)

// KNOWN LIMITATION. Can-mode expands each declared range independently, so a
// package carrying a hard pin from one parent and a wider range from another
// still shows the wider range's versions as Possible. A real resolver
// intersects those constraints, and the pinned version is the only one it could
// ever choose.
//
// This over-approximates rather than under-approximates, which is the safe
// direction for a security report, but it is genuinely imprecise: read a
// Possible row alongside the Pinning of its siblings before acting on it.
// Removing it needs constraint intersection across the whole graph — real
// solver work, and a separate piece.

// VersionStatus is one concrete version's row.
type VersionStatus struct {
	NodeID  graph.NodeID `json:"node_id"`
	Version string       `json:"version"`
	State   State        `json:"state"`
	Pinning Pinning      `json:"pinning"`
	// DeclaredSpec is the widest constraint that reaches this package. With
	// Pinning=Locked it is the range a lock regeneration is free to move within,
	// which is the number a reviewer actually needs.
	DeclaredSpec string `json:"declared_spec,omitempty"`
	Instances    int    `json:"instances"` // on-disk copies: 1 hoisted, >1 nested
	Paths        int    `json:"paths"`     // distinct chains reaching it
}

// PackageEntry is one (ecosystem, name) row.
//
// There is deliberately no single worst-case status badge: it would equate a
// hypothetical risk (possible + vulnerable) with a real one (installed +
// vulnerable), which is the one distinction this tool exists to make. Counts are
// stored; the UI derives badges.
type PackageEntry struct {
	Ecosystem         string             `json:"ecosystem"`
	Name              string             `json:"name"`
	Direct            bool               `json:"direct"`
	Versions          []VersionStatus    `json:"versions"`
	InstanceCount     int                `json:"instance_count"`
	PathCount         int                `json:"path_count"`
	WorstCompleteness graph.Completeness `json:"worst_completeness"`
}

type Result struct {
	Packages []PackageEntry
	Versions []VersionStatus
}

// Compute derives both rollups in one pass over the graph.
func Compute(g *graph.Graph, inst []effective.Instance, root graph.NodeID) Result {
	return ComputeWith(g, inst, root, nil)
}

// ComputeWith adds the pinning axis, using one scheme PER ECOSYSTEM.
//
// Exactness is syntax, and the syntaxes disagree: "==4.12.2" is an exact pin in
// PEP 440 and meaningless to npm, while a bare "1.2.3" is exact in npm and
// invalid in PEP 440. Judging every package with one scheme silently mislabels
// the other ecosystem's pins. An ecosystem with no scheme keeps the axis unset
// rather than being guessed at.
func ComputeWith(g *graph.Graph, inst []effective.Instance, root graph.NodeID,
	schemes map[string]version.VersionScheme) Result {
	paths := countPaths(g, root)

	// Collect every declared constraint reaching each node. A package can be
	// required by several parents under different ranges.
	specs := map[graph.NodeID][]string{}
	// byName is the offline join. Without a registry the walker never resolves a
	// range to a version, so the declared range sits on an edge to the
	// VERSION-LESS node (pkg:pypi/flask) while the installed version arrives
	// separately from the lockfile as pkg:pypi/flask@3.0.0 — a different node.
	// The two never meet, and every offline run reported "locked" with no record
	// of what it was locked AWAY from, which is the whole point of the
	// distinction: ">4.5.0 plus a lockfile" and "==4.6.1" install the same
	// version and carry completely different exposure.
	byName := map[string][]string{}
	for _, e := range g.Edges() {
		if e.Spec == "" {
			continue
		}
		specs[e.To] = append(specs[e.To], e.Spec)
		if eco, name, ver, err := splitPURL(e.To); err == nil && ver == "" {
			byName[eco+"\x00"+name] = append(byName[eco+"\x00"+name], e.Spec)
		}
	}

	instances := map[graph.NodeID]int{}
	for _, i := range inst {
		instances[i.NodeID]++
	}
	haveResolution := len(inst) > 0

	direct := map[graph.NodeID]bool{}
	for _, e := range g.Edges() {
		if e.From == root {
			direct[e.To] = true
		}
	}

	var versions []VersionStatus
	byPkg := map[string]*PackageEntry{}

	for _, n := range g.Nodes() {
		if n.ID == root {
			continue
		}
		key := n.Ecosystem + "\x00" + n.Name
		p, ok := byPkg[key]
		if !ok {
			p = &PackageEntry{
				Ecosystem:         n.Ecosystem,
				Name:              n.Name,
				WorstCompleteness: n.Completeness,
			}
			byPkg[key] = p
		}
		if direct[n.ID] {
			p.Direct = true
		}
		if worse(n.Completeness, p.WorstCompleteness) {
			p.WorstCompleteness = n.Completeness
		}

		// A version-less node is an unresolved REQUIREMENT — a range nobody
		// expanded — not a version. It still tells us the package is depended on
		// and that our knowledge of it is incomplete, both recorded above, but
		// listing it as a version row would invent a version that does not exist.
		if n.Version == "" {
			p.PathCount = satAdd(p.PathCount, paths[n.ID])
			continue
		}
		// A build file, a shell step and a container image all carry a version
		// field and none of them is a package version. Rolling them up put 195
		// non-packages and 3 packages into kubernetes' version list, which
		// overstated the audited count, sent build-file PURLs to OSV, and
		// counted shell steps as floating dependencies.
		if !graph.IsPackage(n.ID) {
			continue
		}

		st := stateOf(instances[n.ID], haveResolution)
		declared := specs[n.ID]
		if len(declared) == 0 {
			declared = byName[n.Ecosystem+"\x00"+n.Name]
		}
		pin, widest := pinningOf(declared, instances[n.ID] > 0, schemes[n.Ecosystem])
		vs := VersionStatus{
			NodeID:       n.ID,
			Version:      n.Version,
			State:        st,
			Pinning:      pin,
			DeclaredSpec: widest,
			Instances:    instances[n.ID],
			Paths:        paths[n.ID],
		}
		versions = append(versions, vs)
		p.Versions = append(p.Versions, vs)
		p.InstanceCount += vs.Instances
		p.PathCount = satAdd(p.PathCount, vs.Paths)
	}

	packages := make([]PackageEntry, 0, len(byPkg))
	for _, p := range byPkg {
		sort.Slice(p.Versions, func(i, j int) bool { return p.Versions[i].Version < p.Versions[j].Version })
		packages = append(packages, *p)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Ecosystem != packages[j].Ecosystem {
			return packages[i].Ecosystem < packages[j].Ecosystem
		}
		return packages[i].Name < packages[j].Name
	})
	sort.Slice(versions, func(i, j int) bool { return versions[i].NodeID < versions[j].NodeID })

	return Result{Packages: packages, Versions: versions}
}

// pinningOf classifies how firmly a version is held, and returns the widest
// declared constraint reaching it.
//
// The rule: if ANY declared constraint is exact, the package is Pinned.
// Resolution takes the INTERSECTION of every constraint reaching a copy, so one
// exact constraint binds it no matter how wide the others are — a lock
// regeneration has nowhere to move it. Only when every constraint is a range is
// the lockfile doing the work, and that lock can be regenerated away: Locked.
func pinningOf(specs []string, hasInstance bool, scheme version.VersionScheme) (Pinning, string) {
	if scheme == nil || len(specs) == 0 {
		if hasInstance {
			return Locked, ""
		}
		return Floating, ""
	}
	widest := ""
	for _, sp := range specs {
		if scheme.IsExact(sp) {
			return Pinned, sp
		}
		if widest == "" {
			widest = sp
		}
	}
	if hasInstance {
		return Locked, widest
	}
	return Floating, widest
}

func stateOf(instances int, haveResolution bool) State {
	switch {
	case instances > 0:
		return Installed
	case haveResolution:
		return Possible
	default:
		return Unknown
	}
}

// completenessRank orders "how bad" a completeness value is, worst first.
func completenessRank(c graph.Completeness) int {
	switch c {
	case graph.Opaque:
		return 3
	case graph.Declared:
		return 2
	case graph.Inferred:
		return 1
	default: // Resolved and the zero value
		return 0
	}
}

func worse(a, b graph.Completeness) bool { return completenessRank(a) > completenessRank(b) }

func satAdd(a, b int) int {
	if a+b > PathCap || a+b < 0 {
		return PathCap
	}
	return a + b
}

// countPaths counts distinct chains from root to every node in one linear DP
// pass over the SCC condensation.
//
// Two things force this shape. Path counts are exponential, so the arithmetic
// saturates. And npm graphs contain cycles, where counting simple paths is
// #P-complete — condensing each strongly connected component to a single vertex
// makes the problem a DAG again, and "how many ways does this get pulled in?"
// over components is what a human means anyway.
func countPaths(g *graph.Graph, root graph.NodeID) map[graph.NodeID]int {
	comp, members := tarjan(g)

	// Build the condensation's adjacency and in-degrees.
	adj := map[int]map[int]bool{}
	indeg := map[int]int{}
	for c := range members {
		indeg[c] = 0
	}
	for _, e := range g.Edges() {
		cf, okf := comp[e.From]
		ct, okt := comp[e.To]
		if !okf || !okt || cf == ct {
			continue
		}
		if adj[cf] == nil {
			adj[cf] = map[int]bool{}
		}
		if !adj[cf][ct] {
			adj[cf][ct] = true
			indeg[ct]++
		}
	}

	count := map[int]int{}
	if rc, ok := comp[root]; ok {
		count[rc] = 1
	}

	// Kahn's algorithm over the condensation.
	var queue []int
	for c, d := range indeg {
		if d == 0 {
			queue = append(queue, c)
		}
	}
	sort.Ints(queue) // deterministic
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		for next := range adj[c] {
			count[next] = satAdd(count[next], count[c])
			indeg[next]--
			if indeg[next] == 0 {
				queue = append(queue, next)
			}
		}
	}

	out := map[graph.NodeID]int{}
	for c, ids := range members {
		for _, id := range ids {
			out[id] = count[c]
		}
	}
	return out
}

// tarjan returns each node's SCC id and the members of each component.
func tarjan(g *graph.Graph) (map[graph.NodeID]int, map[int][]graph.NodeID) {
	out := map[graph.NodeID]map[graph.NodeID]bool{}
	for _, e := range g.Edges() {
		if out[e.From] == nil {
			out[e.From] = map[graph.NodeID]bool{}
		}
		out[e.From][e.To] = true
	}

	var (
		index   = map[graph.NodeID]int{}
		low     = map[graph.NodeID]int{}
		onStack = map[graph.NodeID]bool{}
		stack   []graph.NodeID
		next    int
		compID  int
		comp    = map[graph.NodeID]int{}
		members = map[int][]graph.NodeID{}
	)

	// Iterative to avoid blowing the goroutine stack on deep graphs.
	type frame struct {
		node graph.NodeID
		kids []graph.NodeID
		i    int
	}
	nodes := g.Nodes()

	var strongConnect func(v graph.NodeID)
	strongConnect = func(v graph.NodeID) {
		stackFrames := []frame{{node: v, kids: sortedKeys(out[v])}}
		index[v], low[v] = next, next
		next++
		stack = append(stack, v)
		onStack[v] = true

		for len(stackFrames) > 0 {
			f := &stackFrames[len(stackFrames)-1]
			if f.i < len(f.kids) {
				w := f.kids[f.i]
				f.i++
				if _, seen := index[w]; !seen {
					index[w], low[w] = next, next
					next++
					stack = append(stack, w)
					onStack[w] = true
					stackFrames = append(stackFrames, frame{node: w, kids: sortedKeys(out[w])})
				} else if onStack[w] {
					low[f.node] = min(low[f.node], index[w])
				}
				continue
			}
			// done with this node
			v := f.node
			stackFrames = stackFrames[:len(stackFrames)-1]
			if len(stackFrames) > 0 {
				parent := stackFrames[len(stackFrames)-1].node
				low[parent] = min(low[parent], low[v])
			}
			if low[v] == index[v] {
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					comp[w] = compID
					members[compID] = append(members[compID], w)
					if w == v {
						break
					}
				}
				compID++
			}
		}
	}

	for _, n := range nodes {
		if _, seen := index[n.ID]; !seen {
			strongConnect(n.ID)
		}
	}
	return comp, members
}

func sortedKeys(m map[graph.NodeID]bool) []graph.NodeID {
	out := make([]graph.NodeID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// splitPURL reports a node id's ecosystem, name and version. A version-less id
// is a REQUIREMENT (a range nobody expanded), not a package version.
func splitPURL(id graph.NodeID) (eco, name, ver string, err error) {
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

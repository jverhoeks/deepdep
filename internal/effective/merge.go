package effective

import (
	"strings"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// Merge folds a lockfile's effective resolution into the graph.
//
// This implements the resolution policy "will prefers the lockfile". A lockfile
// is not a guess — npm already decided, wrote down exact versions, and recorded
// the on-disk path of every copy. Those are facts about what will be installed,
// so they belong in the graph as Resolved nodes even when the registry was never
// consulted. Without this, an offline scan of a repo that HAS a lockfile would
// report nothing installed, and `will` would disagree with `npm ls` on every
// real repository.
//
// The nesting in locators carries real dependency structure: a copy at
// node_modules/b/node_modules/lodash exists because b needed it. Top-level
// copies are attached to root.
//
// A root attachment here is PLACEMENT, not declaration. npm hoists nearly every
// transitive package to the top level, so most of these edges say "this ended up
// at node_modules/x", not "this repository asked for x". They carry no Spec, and
// that absence is load-bearing: a declared dependency always arrives from an
// extractor with the raw range on the edge, so an empty Spec on a root edge is
// the mark of a hoisted placement. store.Surfaces relies on it to keep axios'
// 60 declared dependencies from reading as 122.
func ecosystemOf(id graph.NodeID) string {
	s := string(id)
	if !strings.HasPrefix(s, "pkg:") {
		return ""
	}
	rest := s[len("pkg:"):]
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return ""
}

func Merge(g *graph.Graph, inst []Instance, root graph.NodeID) {
	if len(inst) == 0 {
		return
	}
	byLocator := make(map[string]graph.NodeID, len(inst))
	for _, i := range inst {
		byLocator[i.Locator] = i.NodeID
	}

	for _, i := range inst {
		name, version := splitID(i)
		eco := ecosystemOf(i.NodeID)
		g.Add(graph.Node{
			ID:           i.NodeID,
			Ecosystem:    eco,
			Name:         name,
			Version:      version,
			Completeness: graph.Resolved,
			Source:       "lockfile",
		})

		from := root
		if i.ParentLocator != "" {
			if parent, ok := byLocator[i.ParentLocator]; ok {
				from = parent
			}
		}
		g.Link(graph.Edge{From: from, To: i.NodeID, Kind: graph.DependsOn, Scope: graph.Prod})
	}
}

// splitID recovers a display name and version from an instance. The locator
// gives the name (including any @scope) and the PURL gives the version.
// splitID recovers a display name and version from an instance.
//
// The name comes from the PURL rather than the locator, because locators are
// package-manager-specific: an npm one is a node_modules path while a uv one is
// just the distribution name.
func splitID(i Instance) (name, version string) {
	s := string(i.NodeID)
	if idx := strings.LastIndex(s, "@"); idx > 0 {
		version = s[idx+1:]
		s = s[:idx]
	}
	if idx := strings.IndexByte(s, '/'); idx > 0 {
		name = s[idx+1:]
	}
	name = strings.ReplaceAll(name, "%40", "@")
	return name, version
}

// Pins maps "ecosystem/name" to the exact version a lockfile chose.
//
// Only unambiguous pins are returned: when a package is nested at two different
// versions there is no single answer, so it is omitted rather than guessed.
func Pins(inst []Instance) map[string]string {
	byName := map[string]map[string]bool{}
	for _, i := range inst {
		name, ver := splitID(i)
		eco := ecosystemOf(i.NodeID)
		if name == "" || ver == "" || eco == "" {
			continue
		}
		key := eco + "/" + name
		if byName[key] == nil {
			byName[key] = map[string]bool{}
		}
		byName[key][ver] = true
	}
	out := map[string]string{}
	for name, vers := range byName {
		if len(vers) != 1 {
			continue // nested at conflicting versions; no single pin exists
		}
		for v := range vers {
			out[name] = v // name already carries its "ecosystem/" prefix
		}
	}
	return out
}

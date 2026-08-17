package extract

import (
	"context"
	"path"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/gomod"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// GoMod reads go.mod.
//
// go.mod is unusual among manifests in that it already carries EXACT versions:
// Minimal Version Selection means the file records the selected build list, not
// a set of ranges to be solved later. So requirements come out Resolved rather
// than Declared, which is what lets a Go repository be audited at all — an
// advisory query needs a version.
//
// It is parsed by hand rather than with golang.org/x/mod/modfile. The file is
// line-oriented and the four directives that matter are trivially recognised;
// pulling in a dependency to read a dependency manifest is a poor trade for a
// tool whose entire subject is dependency weight.
type GoMod struct{}

func (GoMod) Name() string { return "gomod" }

func (GoMod) Match(p string) bool {
	if path.Base(p) != "go.mod" {
		return false
	}
	// vendor/ holds copies of OTHER modules' manifests. Reading them would
	// report their requirements as this repository's own.
	for _, seg := range strings.Split(p, "/") {
		if seg == "vendor" {
			return false
		}
	}
	return true
}

func (GoMod) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	reqs, replaces := gomod.Parse(f.Data)

	var (
		edges []graph.Edge
		nodes []graph.Node
	)
	// Sorted for determinism: the map of replacements would otherwise leak its
	// iteration order into the output.
	sort.Slice(reqs, func(i, j int) bool { return reqs[i].Module < reqs[j].Module })

	for _, r := range reqs {
		// `// indirect` requirements are NOT declarations. MVS makes the main
		// module record the full selected build list, so those lines are the
		// recorded RESULT of resolution — much closer to a lockfile than to a
		// manifest. They are read by effective.GoMod instead.
		//
		// The distinction is load-bearing, not cosmetic. store.Surfaces calls a
		// node first-party when a non-package node points at it, and everything
		// here hangs off the go.mod file node — so emitting indirect edges would
		// report several hundred modules as dependencies a maintainer can fix by
		// editing one line, which is exactly backwards.
		if r.Indirect {
			continue
		}
		module, ver := r.Module, r.Version
		if rep, ok := replaces[r.Module]; ok {
			if rep.Local {
				// A local replace points at a directory in this repository or
				// beside it. There is no published module to resolve, and asking
				// proxy.golang.org for one would 404 forever. Record it as a
				// frontier so the edge survives and says why it stops here.
				n := localReplaceNode(r.Module, rep.Target)
				n.Source = f.Path
				nodes = append(nodes, n)
				edges = append(edges, graph.Edge{
					To: n.ID, Kind: graph.DependsOn, Scope: graph.Prod, Spec: ver,
				})
				continue
			}
			// A replace to another module retargets the build entirely: the
			// original is never fetched, so reporting it would name a package
			// that is not there.
			module = rep.Target
			if rep.Version != "" {
				ver = rep.Version
			}
		}

		id, err := graph.NodeIDFor(packageurl.TypeGolang, module, ver)
		if err != nil {
			// One unparseable module path must not cost the whole repository its
			// scan; the coverage extractor still reports the file.
			continue
		}
		edges = append(edges, graph.Edge{
			To: id, Kind: graph.DependsOn, Scope: graph.Prod, Spec: ver,
		})
		nodes = append(nodes, graph.Node{
			ID:        id,
			Ecosystem: packageurl.TypeGolang,
			Name:      module,
			Version:   ver,
			// go.mod names the version the build actually selects. This is a
			// fact, not a range to be narrowed later.
			Completeness: graph.Resolved,
			ResolvedRef:  ver,
			Source:       f.Path,
		})
	}
	return edges, nodes, nil
}

// localReplaceNode describes a module replaced by a path on disk.
func localReplaceNode(module, target string) graph.Node {
	id, err := graph.NodeIDFor(packageurl.TypeGeneric, "local-module/"+module, "")
	if err != nil {
		id = graph.NodeID("pkg:generic/local-module")
	}
	return graph.Node{
		ID:        id,
		Ecosystem: packageurl.TypeGeneric,
		Name:      module,
		Version:   target,
		// Declared, not Opaque: this is perfectly analysable source, it simply
		// is not a published package and so has no registry or advisory record.
		Completeness: graph.Declared,
		Reason:       "local-replace",
		Note:         "replaced by " + target,
	}
}

package effective

import (
	"context"
	"path"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/gomod"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// GoMod reads the selected build list out of go.mod.
//
// Go has no separate lockfile, and the file that looks like one is the wrong
// one. go.sum records a checksum for every module version ever CONSIDERED,
// including versions Minimal Version Selection rejected and modules only needed
// to verify others; reading it as the install set routinely doubles the answer.
//
// go.mod is the lockfile. Since Go 1.17 the main module's go.mod carries the
// complete selected build list — direct requirements plus every transitive one
// marked `// indirect` — and MVS makes those versions exact. That is precisely
// what an effective resolver is for.
//
// Like Python and unlike npm, a Go build is FLAT: one version of each module,
// no nesting, so every module has exactly one instance.
type GoMod struct{}

func (GoMod) PackageManager() string { return "go" }

func (GoMod) Resolve(_ context.Context, s source.Source) ([]Instance, error) {
	var out []Instance

	// EVERY go.mod, not just the root one. A repository routinely holds several
	// modules, and reading only the top-level one reports an empty build for all
	// the rest.
	err := s.WalkIf(func(p string) bool {
		if path.Base(p) != "go.mod" {
			return false
		}
		// vendor/ holds other modules' manifests; their requirements are not
		// this build's selected versions.
		for _, seg := range strings.Split(p, "/") {
			if seg == "vendor" {
				return false
			}
		}
		return true
	}, func(f source.File) error {
		dir := path.Dir(f.Path)
		reqs, replaces := gomod.Parse(f.Data)
		for _, r := range reqs {
			module, ver := r.Module, r.Version
			if rep, ok := replaces[r.Module]; ok {
				if rep.Local {
					// Replaced by a directory: nothing is fetched, so nothing is
					// installed from a registry. The extractor reports it as a
					// frontier; inventing an instance here would claim a version
					// that was never resolved.
					continue
				}
				module = rep.Target
				if rep.Version != "" {
					ver = rep.Version
				}
			}
			id, err := graph.NodeIDFor(packageurl.TypeGolang, module, ver)
			if err != nil {
				continue
			}
			// Scoped by directory: two modules in one repository can legitimately
			// select different versions of the same dependency, and collapsing
			// them would hide one of the two.
			out = append(out, Instance{
				Locator:     dir + "#" + module,
				NodeID:      id,
				DerivedFrom: "lockfile",
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

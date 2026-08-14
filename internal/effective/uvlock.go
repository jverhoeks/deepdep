package effective

import (
	"context"
	"fmt"
	"path"
	"sort"

	"github.com/BurntSushi/toml"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// UVLock reads uv.lock.
//
// Unlike npm, Python installs a FLAT environment: exactly one version of each
// distribution, with no nesting. So every package here has exactly one instance
// and the locator is just the name — the Instance model still fits, because
// Locator was always meant to be an opaque package-manager-specific string.
type UVLock struct{}

func (UVLock) PackageManager() string { return "uv" }

type uvLockDoc struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"package"`
}

func (UVLock) Resolve(_ context.Context, s source.Source) ([]Instance, error) {
	var (
		out   []Instance
		fatal error
	)
	// EVERY uv.lock, not just one at the root. A monorepo routinely holds one
	// per component, and reading only the root reports an empty environment for
	// all the others.
	err := s.WalkIf(func(p string) bool { return path.Base(p) == "uv.lock" }, func(f source.File) error {
		var d uvLockDoc
		if _, err := toml.Decode(string(f.Data), &d); err != nil {
			fatal = fmt.Errorf("%s: %w", f.Path, err)
			return nil
		}
		dir := path.Dir(f.Path)
		for _, p := range d.Package {
			if p.Name == "" || p.Version == "" {
				continue // a workspace member or a URL-pinned entry
			}
			// The locator is scoped by directory: two components can legitimately
			// lock different versions of the same distribution, and collapsing
			// them would hide one of the two.
			out = append(out, Instance{
				Locator:     dir + "#" + p.Name,
				NodeID:      graph.PyPINodeID(p.Name, p.Version),
				DerivedFrom: "lockfile",
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if fatal != nil {
		return nil, fatal
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Locator < out[j].Locator })
	return out, nil
}

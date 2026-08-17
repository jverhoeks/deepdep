package effective

import (
	"context"
	"fmt"
	"path"

	"github.com/BurntSushi/toml"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// PoetryLock reads poetry.lock.
//
// Like uv and unlike npm, a Python environment is FLAT: exactly one version of
// each distribution, no nesting, so every package has one instance and the
// locator is just the name.
//
// This is what makes Poetry repositories auditable at all. The manifest carries
// carets, but the lockfile carries the exact versions Poetry already chose — so
// even an offline scan reports what really installs, and every advisory query
// has a version to ask about.
type PoetryLock struct{}

func (PoetryLock) PackageManager() string { return "poetry" }

type poetryLockDoc struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"package"`
}

func (PoetryLock) Resolve(_ context.Context, s source.Source) ([]Instance, error) {
	var (
		out   []Instance
		fatal error
	)
	// EVERY poetry.lock, not just the root one: a monorepo routinely holds one
	// per component, and reading only the root reports an empty environment for
	// all the others.
	err := s.WalkIf(func(p string) bool { return path.Base(p) == "poetry.lock" }, func(f source.File) error {
		var d poetryLockDoc
		if _, err := toml.Decode(string(f.Data), &d); err != nil {
			fatal = fmt.Errorf("%s: %w", f.Path, err)
			return nil
		}
		dir := path.Dir(f.Path)
		for _, p := range d.Package {
			if p.Name == "" || p.Version == "" {
				continue
			}
			// Scoped by directory: two components can legitimately lock different
			// versions of the same distribution, and collapsing them hides one.
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
	return out, nil
}

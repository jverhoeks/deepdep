package effective

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// CargoLock reads Cargo.lock.
//
// A Cargo build is FLAT in the sense that matters here: the lockfile lists one
// entry per (name, version), and a crate may legitimately appear at two
// versions when semver-incompatible requirements coexist. Both are really
// built, so both are instances — collapsing them by name would hide one.
type CargoLock struct{}

func (CargoLock) PackageManager() string { return "cargo" }

type cargoLockDoc struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Source  string `toml:"source"`
	} `toml:"package"`
}

func (CargoLock) Resolve(_ context.Context, s source.Source) ([]Instance, error) {
	var (
		out   []Instance
		fatal error
	)
	err := s.WalkIf(func(p string) bool {
		if path.Base(p) != "Cargo.lock" {
			return false
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == "vendor" || seg == "target" {
				return false
			}
		}
		return true
	}, func(f source.File) error {
		var d cargoLockDoc
		if _, err := toml.Decode(string(f.Data), &d); err != nil {
			fatal = fmt.Errorf("%s: %w", f.Path, err)
			return nil
		}
		dir := path.Dir(f.Path)
		for _, p := range d.Package {
			if p.Name == "" || p.Version == "" {
				continue
			}
			// An entry with NO source is a workspace member — this repository's
			// own crate, not something fetched. Recording it as an installed
			// dependency would count the project as its own dependency.
			if p.Source == "" {
				continue
			}
			id, err := graph.NodeIDFor(packageurl.TypeCargo, p.Name, p.Version)
			if err != nil {
				continue
			}
			// Keyed by name AND version: a crate present twice at incompatible
			// versions is two real builds, and one locator would hide one.
			out = append(out, Instance{
				Locator:     dir + "#" + p.Name + "@" + p.Version,
				NodeID:      id,
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

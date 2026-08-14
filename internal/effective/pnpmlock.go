package effective

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// PnpmLock reads pnpm-lock.yaml.
//
// pnpm installs into a content-addressed store and symlinks a strict tree, so
// unlike npm there is exactly one copy of each (name, version) — the nesting
// that npm uses to resolve conflicts does not exist here. The Instance model
// still fits because Locator was always an opaque package-manager-specific
// string.
type PnpmLock struct{}

func (PnpmLock) PackageManager() string { return "pnpm" }

type pnpmLockDoc struct {
	LockfileVersion any                  `yaml:"lockfileVersion"`
	Packages        map[string]yaml.Node `yaml:"packages"`
	Snapshots       map[string]yaml.Node `yaml:"snapshots"`
}

// parsePnpmKey handles the two key spellings pnpm has used:
//
//	v9+:  "@babel/code-frame@7.24.7"  or  "lodash@4.17.21"
//	v6:   "/@babel/code-frame@7.24.7" or  "/lodash/4.17.21"
//
// A peer-dependency suffix in parentheses is dropped: "vue@3.4.0(typescript@5)"
// is still just vue 3.4.0 on disk.
func parsePnpmKey(k string) (name, version string, ok bool) {
	k = strings.TrimPrefix(k, "/")
	if i := strings.Index(k, "("); i > 0 {
		k = k[:i]
	}
	if i := strings.LastIndex(k, "@"); i > 0 {
		name, version = k[:i], k[i+1:]
		if name != "" && version != "" && !strings.Contains(version, "/") {
			return name, version, true
		}
	}
	// The old "/name/version" spelling.
	if i := strings.LastIndex(k, "/"); i > 0 {
		name, version = k[:i], k[i+1:]
		if name != "" && version != "" {
			return name, version, true
		}
	}
	return "", "", false
}

func (PnpmLock) Resolve(_ context.Context, s source.Source) ([]Instance, error) {
	var (
		out   []Instance
		fatal error
	)
	err := s.WalkIf(func(p string) bool { return path.Base(p) == "pnpm-lock.yaml" }, func(f source.File) error {
		var d pnpmLockDoc
		if err := yaml.Unmarshal(f.Data, &d); err != nil {
			fatal = fmt.Errorf("%s: %w", f.Path, err)
			return nil
		}
		dir := path.Dir(f.Path)
		keys := d.Packages
		if len(keys) == 0 {
			keys = d.Snapshots // some v9 files carry versions only under snapshots
		}
		seen := map[string]bool{}
		for k := range keys {
			name, ver, ok := parsePnpmKey(k)
			if !ok || seen[name+"@"+ver] {
				continue
			}
			seen[name+"@"+ver] = true
			id, err := graph.NPMNodeID(name, ver)
			if err != nil {
				continue
			}
			out = append(out, Instance{
				Locator:     dir + "#" + name + "@" + ver,
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
	sort.Slice(out, func(i, j int) bool { return out[i].Locator < out[j].Locator })
	return out, nil
}

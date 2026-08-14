package effective

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// NPMLock reads package-lock.json v2/v3.
//
// The lockfile's `packages` map IS the effective tree: its keys are the on-disk
// paths npm will create. We read it verbatim rather than recomputing placement —
// npm already did the work, and reimplementing arborist's peer-dependency
// placement is a well-known rabbit hole with no payoff here.
type NPMLock struct{}

func (NPMLock) PackageManager() string { return "npm" }

type npmLockDoc struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version string `json:"version"`
		Link    bool   `json:"link"`
	} `json:"packages"`
}

func (NPMLock) Resolve(_ context.Context, s source.Source) ([]Instance, error) {
	var (
		doc   *npmLockDoc
		fatal error
	)
	err := s.WalkIf(func(p string) bool { return p == "package-lock.json" }, func(f source.File) error {
		var d npmLockDoc
		if err := json.Unmarshal(f.Data, &d); err != nil {
			fatal = fmt.Errorf("%s: %w", f.Path, err)
			return nil
		}
		doc = &d
		return nil
	})
	if err != nil {
		return nil, err
	}
	if fatal != nil {
		return nil, fatal
	}
	if doc == nil {
		// No lockfile: there is no effective resolution to report. Callers mark
		// installedness `unknown` rather than guessing.
		return nil, nil
	}

	locators := make([]string, 0, len(doc.Packages))
	for k := range doc.Packages {
		locators = append(locators, k)
	}
	sort.Strings(locators)

	var out []Instance
	for _, loc := range locators {
		p := doc.Packages[loc]
		// "" is the root project; a link is a workspace symlink, not an
		// installed third-party copy; no version means nothing to identify.
		if loc == "" || p.Link || p.Version == "" {
			continue
		}
		name, ok := nameFromLocator(loc)
		if !ok {
			continue
		}
		id, err := graph.NPMNodeID(name, p.Version)
		if err != nil {
			return nil, err
		}
		out = append(out, Instance{
			Locator:       loc,
			NodeID:        id,
			ParentLocator: parentLocator(loc),
			DerivedFrom:   "lockfile",
		})
	}
	return out, nil
}

// nameFromLocator recovers the package name from an install path. The name is
// whatever follows the LAST node_modules segment, keeping an @scope intact.
func nameFromLocator(loc string) (string, bool) {
	i := strings.LastIndex(loc, "node_modules/")
	if i < 0 {
		return "", false
	}
	name := loc[i+len("node_modules/"):]
	if name == "" {
		return "", false
	}
	return name, true
}

// parentLocator is the enclosing package for a nested copy, or "" for a hoisted
// one at the top level.
func parentLocator(loc string) string {
	i := strings.LastIndex(loc, "/node_modules/")
	if i < 0 {
		return ""
	}
	return loc[:i]
}

package extract

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// Cargo reads Cargo.toml.
//
// Every dependency table is read — runtime, dev, build and per-target — and
// optional dependencies behind features are included too. That is the widest
// reading, taken deliberately: a feature-gated crate is code that a downstream
// consumer can switch on without this repository changing a line, so leaving it
// out would understate the surface. The scope on each edge records which table
// it came from, so a reader can still tell them apart.
type Cargo struct{}

func (Cargo) Name() string { return "cargo" }

func (Cargo) Match(p string) bool {
	if path.Base(p) != "Cargo.toml" {
		return false
	}
	// vendor/ and target/ hold other crates' manifests and build output; their
	// dependencies are not this crate's declarations.
	for _, seg := range strings.Split(p, "/") {
		if seg == "vendor" || seg == "target" {
			return false
		}
	}
	return true
}

// cargoDep covers both spellings of a dependency value. Cargo accepts either a
// bare string ("1.2.3") or a table ({version = "1.2", optional = true}), and a
// parser that handles only the string silently drops every table-form
// dependency — which is most of the interesting ones.
type cargoDep struct {
	Version  string
	Path     string
	Git      string
	Package  string // rename: the crate actually pulled in
	Optional bool
}

func (d *cargoDep) UnmarshalTOML(v any) error {
	switch t := v.(type) {
	case string:
		d.Version = t
		return nil
	case map[string]any:
		if s, ok := t["version"].(string); ok {
			d.Version = s
		}
		if s, ok := t["path"].(string); ok {
			d.Path = s
		}
		if s, ok := t["git"].(string); ok {
			d.Git = s
		}
		if s, ok := t["package"].(string); ok {
			d.Package = s
		}
		if b, ok := t["optional"].(bool); ok {
			d.Optional = b
		}
		return nil
	default:
		return fmt.Errorf("unrecognised dependency value %T", v)
	}
}

type cargoDoc struct {
	Package *struct {
		Name string `toml:"name"`
	} `toml:"package"`
	Dependencies      map[string]cargoDep `toml:"dependencies"`
	DevDependencies   map[string]cargoDep `toml:"dev-dependencies"`
	BuildDependencies map[string]cargoDep `toml:"build-dependencies"`
	Target            map[string]struct {
		Dependencies      map[string]cargoDep `toml:"dependencies"`
		DevDependencies   map[string]cargoDep `toml:"dev-dependencies"`
		BuildDependencies map[string]cargoDep `toml:"build-dependencies"`
	} `toml:"target"`
}

func (Cargo) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	var doc cargoDoc
	if _, err := toml.Decode(string(f.Data), &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", f.Path, err)
	}

	var edges []graph.Edge
	add := func(deps map[string]cargoDep, scope graph.Scope) {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names) // map order would otherwise leak into the output
		for _, n := range names {
			d := deps[n]
			// `package = "real-name"` renames a crate locally. What is actually
			// pulled in — and what advisories attach to — is the real one.
			crate := n
			if d.Package != "" {
				crate = d.Package
			}
			// A path or git dependency is not a crates.io package: there is
			// nothing to resolve and no advisory record. Skipping it entirely
			// would hide the edge, so it keeps its edge and no version.
			if d.Path != "" || d.Git != "" {
				continue
			}
			id, err := graph.NodeIDFor(packageurl.TypeCargo, crate, "")
			if err != nil {
				continue
			}
			sc := scope
			if d.Optional {
				sc = graph.Optional
			}
			edges = append(edges, graph.Edge{
				To: id, Kind: graph.DependsOn, Spec: d.Version, Scope: sc,
			})
		}
	}

	add(doc.Dependencies, graph.Prod)
	add(doc.DevDependencies, graph.Dev)
	// A build dependency runs code on the build machine, so it is production
	// exposure in the sense that matters here, not a development convenience.
	add(doc.BuildDependencies, graph.Prod)

	// Per-target tables are the same dependencies conditioned on a platform.
	// Sorted so a multi-target manifest extracts deterministically.
	targets := make([]string, 0, len(doc.Target))
	for k := range doc.Target {
		targets = append(targets, k)
	}
	sort.Strings(targets)
	for _, k := range targets {
		add(doc.Target[k].Dependencies, graph.Prod)
		add(doc.Target[k].DevDependencies, graph.Dev)
		add(doc.Target[k].BuildDependencies, graph.Prod)
	}

	return edges, nil, nil
}

package extract

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
	"github.com/jverhoeks/deepdep/internal/version"
)

// Poetry reads the [tool.poetry] tables of pyproject.toml.
//
// It is a SECOND extractor over the same file as PyProject, not a replacement.
// The two read disjoint tables — PyProject reads PEP 621 [project], this reads
// [tool.poetry] — and Registry.For runs every extractor that claims a path, so a
// file carrying both is read correctly by both.
//
// Constraints are translated into PEP 440 range syntax rather than parsed with
// Poetry semantics in place. Poetry's dialect really is different (its caret and
// tilde come from Cargo, and its bare version means exact), but every form has
// an exact PEP 440 equivalent, so translating keeps ONE version scheme per
// ecosystem — which the walker, the rollup and the pinning analysis all assume.
// See version.PoetryToPEP440.
type Poetry struct{}

// poetryDialect is looked up once by name rather than referenced directly, so
// this extractor depends on the dialect REGISTRY rather than on one dialect's
// identity — which is what lets a future manifest (Pipenv, PDM) reuse the seam
// without the version package growing a special case per extractor.
var poetryDialect = mustDialect("poetry")

func mustDialect(name string) version.Dialect {
	d, ok := version.DialectFor(name)
	if !ok {
		// A dialect that failed to register would look exactly like a manifest
		// with no dependencies, so this is not survivable at runtime.
		panic("extract: no such constraint dialect: " + name)
	}
	return d
}

func (Poetry) Name() string { return "poetry" }

func (Poetry) Match(p string) bool {
	if path.Base(p) != "pyproject.toml" {
		return false
	}
	return !inPythonEnv(p)
}

type poetryDep struct {
	Version  string
	Optional bool
	// Path, URL and Git dependencies are not PyPI packages at all.
	NonRegistry bool
}

// UnmarshalTOML accepts every spelling Poetry allows: a bare string, a table, or
// a LIST of tables for a dependency declared per-platform. Handling only the
// string silently drops the table form, which is where extras and optionality
// live.
func (d *poetryDep) UnmarshalTOML(v any) error {
	switch t := v.(type) {
	case string:
		d.Version = t
		return nil
	case map[string]any:
		if s, ok := t["version"].(string); ok {
			d.Version = s
		}
		if b, ok := t["optional"].(bool); ok {
			d.Optional = b
		}
		for _, k := range []string{"path", "url", "git"} {
			if _, ok := t[k]; ok {
				d.NonRegistry = true
			}
		}
		return nil
	case []map[string]any:
		// Several constraints for one name, split by python version or platform.
		// The first is taken and the rest are a known simplification: the node is
		// the same package either way, and the version comes from the lockfile in
		// will-mode regardless.
		if len(t) > 0 {
			return d.UnmarshalTOML(t[0])
		}
		return nil
	case []any:
		if len(t) > 0 {
			return d.UnmarshalTOML(t[0])
		}
		return nil
	default:
		return fmt.Errorf("unrecognised dependency value %T", v)
	}
}

type poetryDoc struct {
	Tool struct {
		Poetry struct {
			Dependencies    map[string]poetryDep `toml:"dependencies"`
			DevDependencies map[string]poetryDep `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]poetryDep `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

func (Poetry) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	var doc poetryDoc
	if _, err := toml.Decode(string(f.Data), &doc); err != nil {
		// A pyproject.toml that is not Poetry's is not an error here; PyProject
		// reads the same file and reports its own problems.
		return nil, nil, nil
	}
	p := doc.Tool.Poetry

	var (
		edges []graph.Edge
		nodes []graph.Node
	)
	add := func(deps map[string]poetryDep, scope graph.Scope) {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names) // map order would otherwise leak into the output
		for _, n := range names {
			d := deps[n]
			// `python` is an interpreter requirement, not a package. There is no
			// pypi.org/project/python, so a node for it would be a permanent
			// unresolvable frontier in every Poetry repository.
			if strings.EqualFold(n, "python") {
				continue
			}
			if d.NonRegistry {
				continue
			}
			id := graph.PyPINodeID(n, "")
			sc := scope
			if d.Optional {
				// An optional Poetry dependency is an extra: nothing installs it
				// unless a dependant asks for that extra by name.
				sc = graph.Optional
			}
			spec, err := poetryDialect.Translate(d.Version)
			if err != nil {
				// Alternation has no PEP 440 equivalent. Record the package with
				// no constraint and say why, rather than inventing a span that
				// claims versions the author excluded.
				nodes = append(nodes, graph.Node{
					ID:           id,
					Ecosystem:    "pypi",
					Name:         n,
					Completeness: graph.Declared,
					Reason:       "poetry-alternation",
					Note:         d.Version,
					Source:       f.Path,
				})
				edges = append(edges, graph.Edge{To: id, Kind: graph.DependsOn, Scope: sc})
				continue
			}
			edges = append(edges, graph.Edge{
				To: id, Kind: graph.DependsOn, Spec: spec, Scope: sc,
			})
		}
	}

	add(p.Dependencies, graph.Prod)
	// The legacy spelling. Projects that predate dependency groups still use it,
	// and it is the only place their test dependencies are declared.
	add(p.DevDependencies, graph.Dev)

	groups := make([]string, 0, len(p.Group))
	for k := range p.Group {
		groups = append(groups, k)
	}
	sort.Strings(groups)
	for _, k := range groups {
		add(p.Group[k].Dependencies, graph.Dev)
	}

	return edges, nodes, nil
}

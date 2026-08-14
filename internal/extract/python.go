package extract

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// normalisePyPI applies PEP 503 name normalisation.
//
// PyPI treats names case-insensitively and folds runs of -, _ and . together, so
// "Typing_Extensions" and "typing-extensions" are the same project. Skipping this
// would split one package across several nodes and quietly understate how many
// paths reach it.
var pypiSepRe = regexp.MustCompile(`[-_.]+`)

func normalisePyPI(name string) string {
	return pypiSepRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

func pypiNodeID(name, version string) graph.NodeID {
	p := packageurl.NewPackageURL(packageurl.TypePyPi, "", normalisePyPI(name), version, nil, "")
	return graph.NodeID(p.ToString())
}

// pep508Re splits a requirement string into name, extras, and the rest.
var pep508Re = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$`)

// parseRequirement pulls the package name and version specifier out of a PEP 508
// requirement string.
//
// Environment markers after ';' are dropped from the specifier but not from the
// closure: a dependency that only installs on Windows is still a dependency, and
// treating it as absent would understate the surface.
func parseRequirement(s string) (name, spec string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", false
	}
	// Drop the environment marker.
	if i := strings.Index(s, ";"); i >= 0 {
		s = s[:i]
	}
	m := pep508Re.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	name = m[1]
	spec = strings.TrimSpace(m[3])
	// PEP 508 permits parenthesised specifiers: "urllib3 (>=1.26,<3)".
	spec = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(spec, "("), ")"))
	if strings.HasPrefix(spec, "@") {
		// A direct URL reference pins to a URL, not a version.
		return name, "", true
	}
	return name, spec, true
}

// ---------------------------------------------------------------- pyproject ---

// PyProject reads PEP 621 metadata from pyproject.toml.
//
// Only the standard tables are read: [project], [project.optional-dependencies]
// and PEP 735 [dependency-groups]. Poetry's [tool.poetry.dependencies] uses its
// own constraint dialect (carets, tildes) that is NOT PEP 440, so parsing it
// here with PEP 440 semantics would produce confidently wrong ranges. It stays a
// declared frontier until it gets its own scheme.
type PyProject struct{}

func (PyProject) Name() string { return "pyproject" }

func (PyProject) Match(p string) bool {
	if path.Base(p) != "pyproject.toml" {
		return false
	}
	return !inPythonEnv(p)
}

type pyProjectDoc struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]string `toml:"dependency-groups"`
}

func (PyProject) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	var doc pyProjectDoc
	if _, err := toml.Decode(string(f.Data), &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", f.Path, err)
	}

	var edges []graph.Edge
	add := func(reqs []string, scope graph.Scope) {
		for _, r := range reqs {
			name, spec, ok := parseRequirement(r)
			if !ok {
				continue
			}
			edges = append(edges, graph.Edge{
				From: "", To: pypiNodeID(name, ""),
				Kind: graph.DependsOn, Spec: spec, Scope: scope,
			})
		}
	}

	add(doc.Project.Dependencies, graph.Prod)
	// Extras are opt-in, so they map to Optional rather than Prod.
	for _, g := range sortedStringKeys(doc.Project.OptionalDependencies) {
		add(doc.Project.OptionalDependencies[g], graph.Optional)
	}
	// PEP 735 groups are development-time by construction.
	for _, g := range sortedStringKeys(doc.DependencyGroups) {
		add(doc.DependencyGroups[g], graph.Dev)
	}
	return edges, nil, nil
}

func sortedStringKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------------------- requirements ---

// Requirements reads pip requirements files.
type Requirements struct{}

func (Requirements) Name() string { return "requirements" }

func (Requirements) Match(p string) bool {
	if inPythonEnv(p) {
		return false
	}
	dir, base := path.Split(p)
	if strings.TrimSuffix(dir, "/") == "requirements" && strings.HasSuffix(base, ".txt") {
		return true
	}
	return (strings.HasPrefix(base, "requirements") || strings.HasPrefix(base, "constraints")) &&
		(strings.HasSuffix(base, ".txt") || strings.HasSuffix(base, ".in"))
}

// inPythonEnv keeps installed virtualenv contents out of the results: those
// describe what is on this disk, not what the project declares.
func inPythonEnv(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case ".venv", "venv", "site-packages", "node_modules":
			return true
		}
	}
	return false
}

func (Requirements) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	var (
		edges []graph.Edge
		nodes []graph.Node
	)
	for _, raw := range strings.Split(string(f.Data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A trailing comment is only a comment when whitespace precedes the hash.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}

		if strings.HasPrefix(line, "-") {
			// An index URL decides where EVERY package in the file comes from, so
			// it belongs in a supply-chain report even though it declares nothing.
			if u, ok := indexOption(line); ok {
				n := hashedNode("index-url", u)
				n.Completeness, n.Reason, n.Source = graph.Declared, "registry-redirect", f.Path
				nodes = append(nodes, n)
				edges = append(edges, graph.Edge{From: "", To: n.ID, Kind: graph.Installs})
			}
			// -r/-e/-c and other options carry no direct requirement.
			continue
		}
		// A VCS or URL requirement pins to a location, not a version.
		if strings.Contains(line, "://") {
			n := hashedNode("url-requirement", line)
			n.Completeness, n.Reason, n.Source = graph.Declared, graph.ReasonUnpinnedRef, f.Path
			nodes = append(nodes, n)
			edges = append(edges, graph.Edge{From: "", To: n.ID, Kind: graph.DependsOn})
			continue
		}

		name, spec, ok := parseRequirement(line)
		if !ok {
			continue
		}
		edges = append(edges, graph.Edge{
			From: "", To: pypiNodeID(name, ""),
			Kind: graph.DependsOn, Spec: spec, Scope: graph.Prod,
		})
	}
	return edges, nodes, nil
}

func indexOption(line string) (string, bool) {
	for _, opt := range []string{"--index-url", "--extra-index-url", "-i", "--find-links", "-f"} {
		if rest, ok := strings.CutPrefix(line, opt); ok {
			rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "="))
			if rest != "" {
				return rest, true
			}
		}
	}
	return "", false
}

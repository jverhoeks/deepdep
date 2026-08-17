package extract

import (
	"context"
	"fmt"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// PreCommit reads .pre-commit-config.yaml.
//
// The catalogue already called this the highest-leverage surface there is, and
// expanding it makes that concrete: each entry names a REMOTE repository that
// pre-commit clones and EXECUTES on an ordinary `git commit`, with the
// developer's credentials, before any review has happened. Nothing has to be
// "installed" for it to run.
//
// Hooks are identified as GitHub Actions are — pkg:github/owner/repo@rev —
// because that is what they are: a repository pinned at a ref. It also means
// they inherit the same advisory treatment, and the same honest weakness: a
// mutable rev is Declared, not Resolved, because a tag can be repointed and no
// API says what it pointed at in the past.
type PreCommit struct{}

func (PreCommit) Name() string { return "pre-commit" }

func (PreCommit) Match(p string) bool {
	switch path.Base(p) {
	case ".pre-commit-config.yaml", ".pre-commit-config.yml", ".pre-commit-hooks.yaml":
		return true
	}
	return false
}

type preCommitDoc struct {
	Repos []struct {
		Repo  string `yaml:"repo"`
		Rev   string `yaml:"rev"`
		Hooks []struct {
			ID                     string   `yaml:"id"`
			AdditionalDependencies []string `yaml:"additional_dependencies"`
		} `yaml:"hooks"`
	} `yaml:"repos"`
}

func (PreCommit) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	var doc preCommitDoc
	if err := yaml.Unmarshal(f.Data, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", f.Path, err)
	}

	var (
		edges []graph.Edge
		nodes []graph.Node
	)
	for _, r := range doc.Repos {
		// `repo: local` and `repo: meta` are pre-commit's own pseudo-sources:
		// the hook is defined in this repository or built in. Neither is fetched
		// and neither is a dependency on anyone.
		switch strings.TrimSpace(r.Repo) {
		case "", "local", "meta":
			continue
		}

		if id, ok := gitRepoNodeID(r.Repo, r.Rev); ok {
			n := graph.Node{
				ID: id, Ecosystem: packageurl.TypeGithub,
				Name: repoSlug(r.Repo), Version: r.Rev, Source: f.Path,
			}
			if shaRe.MatchString(r.Rev) {
				n.Completeness = graph.Resolved
				n.ResolvedRef = r.Rev
			} else {
				// A tag can be repointed at any time and no API exposes what it
				// pointed at in the past, so this stays Declared until a SHA is
				// observed — the same rule GitHub Actions refs follow.
				n.Completeness = graph.Declared
				n.Reason = graph.ReasonUnpinnedRef
			}
			nodes = append(nodes, n)
			edges = append(edges, graph.Edge{To: id, Kind: graph.Invokes, Scope: graph.Dev})
		}

		// additional_dependencies are installed into the hook's own environment
		// by pip or npm. They are real packages that real code imports, and they
		// are invisible to every other manifest in the repository.
		for _, h := range r.Hooks {
			for _, dep := range h.AdditionalDependencies {
				if e, ok := preCommitDependency(dep); ok {
					edges = append(edges, e)
				}
			}
		}
	}
	return edges, nodes, nil
}

// preCommitDependency turns one additional_dependencies entry into an edge.
//
// The ecosystem is decided by the hook's language, which is not stated on the
// dependency itself. PyPI is assumed because the overwhelming majority of
// pre-commit hooks are Python; a Node hook's dependency will resolve to nothing
// and surface as an unresolvable frontier rather than as a wrong package.
func preCommitDependency(dep string) (graph.Edge, bool) {
	dep = strings.TrimSpace(dep)
	if dep == "" || strings.HasPrefix(dep, "-") {
		return graph.Edge{}, false
	}
	name, spec := dep, ""
	// PEP 508 spellings that appear here: pkg==1.2.3, pkg>=1.0, pkg[extra]==1.0
	if i := strings.IndexAny(dep, "=<>!~"); i > 0 {
		name, spec = dep[:i], dep[i:]
	}
	if i := strings.Index(name, "["); i > 0 {
		name = name[:i] // extras ride along; the package is the same distribution
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "/:@") {
		return graph.Edge{}, false // a URL or VCS spec, not a distribution name
	}
	return graph.Edge{
		To:    graph.PyPINodeID(name, ""),
		Kind:  graph.DependsOn,
		Spec:  strings.TrimSpace(spec),
		Scope: graph.Dev,
	}, true
}

// gitRepoNodeID turns a hook repository URL into a node id.
func gitRepoNodeID(repo, rev string) (graph.NodeID, bool) {
	slug := repoSlug(repo)
	parts := strings.Split(slug, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	p := packageurl.NewPackageURL(packageurl.TypeGithub, parts[0], parts[1], rev, nil, "")
	return graph.NodeID(p.ToString()), true
}

// repoSlug reduces a clone URL to owner/repo.
func repoSlug(repo string) string {
	s := strings.TrimSpace(repo)
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimPrefix(s, "git@")
	for _, p := range []string{"https://", "http://", "ssh://"} {
		s = strings.TrimPrefix(s, p)
	}
	s = strings.ReplaceAll(s, "github.com:", "github.com/")
	if i := strings.Index(s, "github.com/"); i >= 0 {
		s = s[i+len("github.com/"):]
	}
	return strings.Trim(s, "/")
}

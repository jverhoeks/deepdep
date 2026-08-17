package extract_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func pcExtract(t *testing.T, body string) ([]graph.Edge, map[graph.NodeID]graph.Node) {
	t.Helper()
	edges, nodes, err := extract.PreCommit{}.Extract(context.Background(), source.File{
		Path: ".pre-commit-config.yaml", Data: []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	by := map[graph.NodeID]graph.Node{}
	for _, n := range nodes {
		by[n.ID] = n
	}
	return edges, by
}

// Each entry names a remote repository that pre-commit clones and EXECUTES on
// an ordinary commit, with the developer's credentials, before review.
func TestPreCommitExtractsHookRepositories(t *testing.T) {
	_, nodes := pcExtract(t, `
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: 2c8dce6094fa2b4b668e74f694ca63ceffd38614
    hooks:
      - id: ruff
`)
	mutable, ok := nodes["pkg:github/pre-commit/pre-commit-hooks@v4.6.0"]
	if !ok {
		t.Fatalf("hook repo missing from %v", nodes)
	}
	// A tag can be repointed and no API says what it pointed at in the past.
	if mutable.Completeness != graph.Declared || mutable.Reason != graph.ReasonUnpinnedRef {
		t.Errorf("tag-pinned hook = %q/%q, want declared/unpinned-ref",
			mutable.Completeness, mutable.Reason)
	}
	pinned, ok := nodes["pkg:github/astral-sh/ruff-pre-commit@2c8dce6094fa2b4b668e74f694ca63ceffd38614"]
	if !ok {
		t.Fatalf("sha-pinned hook missing from %v", nodes)
	}
	if pinned.Completeness != graph.Resolved {
		t.Errorf("sha-pinned hook = %q, want resolved", pinned.Completeness)
	}
}

// additional_dependencies are installed into the hook's environment and are
// invisible to every other manifest in the repository.
func TestPreCommitExtractsAdditionalDependencies(t *testing.T) {
	edges, _ := pcExtract(t, `
repos:
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies:
          - types-requests==2.31.0
          - pydantic[email]>=2.0
`)
	got := map[string]string{}
	for _, e := range edges {
		got[string(e.To)] = e.Spec
	}
	if got["pkg:pypi/types-requests"] != "==2.31.0" {
		t.Errorf("types-requests spec = %q, want ==2.31.0 (%v)", got["pkg:pypi/types-requests"], got)
	}
	// Extras ride along; the distribution installed is the same one.
	if _, ok := got["pkg:pypi/pydantic"]; !ok {
		t.Errorf("pydantic[email] did not resolve to the pydantic distribution: %v", got)
	}
}

// `local` and `meta` are pre-commit's own pseudo-sources: nothing is fetched
// and nobody is depended on.
func TestPreCommitIgnoresLocalAndMetaRepos(t *testing.T) {
	edges, nodes := pcExtract(t, `
repos:
  - repo: local
    hooks:
      - id: my-script
  - repo: meta
    hooks:
      - id: check-hooks-apply
`)
	if len(edges) != 0 || len(nodes) != 0 {
		t.Errorf("pseudo-sources produced %d edges and %d nodes, want none", len(edges), len(nodes))
	}
}

func TestPreCommitMatch(t *testing.T) {
	m := extract.PreCommit{}
	for _, p := range []string{".pre-commit-config.yaml", ".pre-commit-config.yml"} {
		if !m.Match(p) {
			t.Errorf("Match(%q) = false", p)
		}
	}
	if m.Match("README.md") {
		t.Error("Match(README.md) = true")
	}
}

package extract_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func poetryExtract(t *testing.T, body string) ([]graph.Edge, []graph.Node) {
	t.Helper()
	edges, nodes, err := extract.Poetry{}.Extract(context.Background(), source.File{
		Path: "pyproject.toml", Data: []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	return edges, nodes
}

func specFor(edges []graph.Edge, id string) (string, bool) {
	for _, e := range edges {
		if string(e.To) == id {
			return e.Spec, true
		}
	}
	return "", false
}

// The whole point: a caret becomes a real PEP 440 range, so the walker can
// expand it with the scheme PyPI metadata already uses.
func TestPoetryTranslatesConstraints(t *testing.T) {
	edges, _ := poetryExtract(t, `
[tool.poetry.dependencies]
python = "^3.10"
boto3 = "^1.34.119"
requests = "2.32.3"
`)
	if _, ok := specFor(edges, "pkg:pypi/python"); ok {
		t.Error("python is an interpreter requirement, not a package")
	}
	if got, _ := specFor(edges, "pkg:pypi/boto3"); got != ">=1.34.119,<2.0.0" {
		t.Errorf("boto3 spec = %q, want the translated caret", got)
	}
	// A bare version is EXACT in Poetry, unlike Cargo.
	if got, _ := specFor(edges, "pkg:pypi/requests"); got != "==2.32.3" {
		t.Errorf("requests spec = %q, want ==2.32.3", got)
	}
}

// Both the legacy dev-dependencies table and current dependency groups carry
// real test dependencies; a project using either must not read as having none.
func TestPoetryReadsLegacyDevAndGroups(t *testing.T) {
	edges, _ := poetryExtract(t, `
[tool.poetry.dependencies]
requests = "^2.0"

[tool.poetry.dev-dependencies]
pytest = "^8.0"

[tool.poetry.group.lint.dependencies]
ruff = "^0.4"
`)
	byID := map[string]graph.Scope{}
	for _, e := range edges {
		byID[string(e.To)] = e.Scope
	}
	if len(byID) != 3 {
		t.Fatalf("got %d dependencies, want 3: %v", len(byID), byID)
	}
	if byID["pkg:pypi/pytest"] != graph.Dev || byID["pkg:pypi/ruff"] != graph.Dev {
		t.Errorf("dev dependencies were not scoped dev: %v", byID)
	}
}

// The table form is where optionality lives; handling only strings drops it.
func TestPoetryTableFormAndOptional(t *testing.T) {
	edges, _ := poetryExtract(t, `
[tool.poetry.dependencies]
cement = {version = "^3.0.10", extras = ["colorlog"]}
extra-thing = {version = "^1.0", optional = true}
`)
	if got, ok := specFor(edges, "pkg:pypi/cement"); !ok || got != ">=3.0.10,<4.0.0" {
		t.Errorf("cement spec = %q, want the table form to be read", got)
	}
	for _, e := range edges {
		if string(e.To) == "pkg:pypi/extra-thing" && e.Scope != graph.Optional {
			t.Errorf("an optional dependency was scoped %q", e.Scope)
		}
	}
}

// Alternation has no PEP 440 equivalent. It must produce an honest frontier
// rather than a span claiming versions the author excluded.
func TestPoetryAlternationBecomesAFrontier(t *testing.T) {
	edges, nodes := poetryExtract(t, `
[tool.poetry.dependencies]
weird = "^1.0 || ^2.0"
`)
	if got, _ := specFor(edges, "pkg:pypi/weird"); got != "" {
		t.Errorf("spec = %q, want empty rather than an invented range", got)
	}
	found := false
	for _, n := range nodes {
		if n.Reason == "poetry-alternation" {
			found = true
		}
	}
	if !found {
		t.Error("no frontier node recorded the untranslatable constraint")
	}
}

// A path or git dependency is not a PyPI package; naming one would attribute a
// stranger's advisories to local code.
func TestPoetryNonRegistryDependenciesAreSkipped(t *testing.T) {
	edges, _ := poetryExtract(t, `
[tool.poetry.dependencies]
local = {path = "../local"}
requests = "^2.0"
`)
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want only requests", len(edges))
	}
}

// A PEP 621 pyproject.toml must pass through untouched: the two extractors read
// disjoint tables of the same file and both run.
func TestPoetryIgnoresPEP621Projects(t *testing.T) {
	edges, _ := poetryExtract(t, `
[project]
name = "app"
dependencies = ["requests>=2.0"]
`)
	if len(edges) != 0 {
		t.Errorf("got %d edges from a PEP 621 file; PyProject owns those tables", len(edges))
	}
}

package extract_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func pyEdges(t *testing.T, e extract.Extractor, path, body string) map[graph.NodeID]graph.Edge {
	t.Helper()
	edges, _, err := e.Extract(context.Background(), source.File{Path: path, Data: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	out := map[graph.NodeID]graph.Edge{}
	for _, ed := range edges {
		out[ed.To] = ed
	}
	return out
}

func TestPyProjectPEP621Dependencies(t *testing.T) {
	got := pyEdges(t, extract.PyProject{}, "pyproject.toml", `
[project]
name = "app"
dependencies = [
  "requests>4.5.0",
  "urllib3 (>=1.26,<3)",
  "pydantic[email]==2.5.0",
  "tomli ; python_version < '3.11'",
]

[project.optional-dependencies]
dev = ["pytest>=8"]

[dependency-groups]
lint = ["ruff==0.5.0"]
`)
	for _, c := range []struct {
		id    graph.NodeID
		spec  string
		scope graph.Scope
	}{
		{"pkg:pypi/requests", ">4.5.0", graph.Prod},
		{"pkg:pypi/urllib3", ">=1.26,<3", graph.Prod},
		{"pkg:pypi/pydantic", "==2.5.0", graph.Prod},
		{"pkg:pypi/tomli", "", graph.Prod},
		{"pkg:pypi/pytest", ">=8", graph.Optional},
		{"pkg:pypi/ruff", "==0.5.0", graph.Dev},
	} {
		e, ok := got[c.id]
		if !ok {
			t.Errorf("missing %s; got %v", c.id, keysE(got))
			continue
		}
		if e.Spec != c.spec {
			t.Errorf("%s spec = %q, want %q", c.id, e.Spec, c.spec)
		}
		if e.Scope != c.scope {
			t.Errorf("%s scope = %q, want %q", c.id, e.Scope, c.scope)
		}
	}
}

// PyPI names are case-insensitive and treat -, _ and . as equivalent, so they
// must be normalised or the same package appears as several nodes.
func TestPyProjectNormalisesNames(t *testing.T) {
	got := pyEdges(t, extract.PyProject{}, "pyproject.toml", `
[project]
dependencies = ["Typing_Extensions>=4", "zope.interface>=5"]
`)
	for _, want := range []graph.NodeID{"pkg:pypi/typing-extensions", "pkg:pypi/zope-interface"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing normalised %s; got %v", want, keysE(got))
		}
	}
}

func TestRequirementsTxt(t *testing.T) {
	got := pyEdges(t, extract.Requirements{}, "requirements.txt", `
# comment
requests>=2.0    # trailing comment
urllib3==2.2.1
pydantic[email]>=2,<3
-e ./local-pkg
--index-url https://internal.example.com/simple
git+https://github.com/psf/requests@main#egg=requests-git

tomli; python_version < "3.11"
`)
	for _, c := range []struct {
		id   graph.NodeID
		spec string
	}{
		{"pkg:pypi/requests", ">=2.0"},
		{"pkg:pypi/urllib3", "==2.2.1"},
		{"pkg:pypi/pydantic", ">=2,<3"},
		{"pkg:pypi/tomli", ""},
	} {
		e, ok := got[c.id]
		if !ok {
			t.Errorf("missing %s; got %v", c.id, keysE(got))
			continue
		}
		if e.Spec != c.spec {
			t.Errorf("%s spec = %q, want %q", c.id, e.Spec, c.spec)
		}
	}
}

// --index-url redirects where every package comes from. It declares no
// dependency, yet it is one of the highest-leverage lines in the file.
func TestRequirementsIndexUrlIsSurfaced(t *testing.T) {
	_, nodes, err := extract.Requirements{}.Extract(context.Background(), source.File{
		Path: "requirements.txt",
		Data: []byte("--index-url https://internal.example.com/simple\nrequests>=2\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var sawIndex bool
	for _, n := range nodes {
		if n.Name == "index-url" {
			sawIndex = true
			if n.Completeness != graph.Declared {
				t.Errorf("index-url completeness = %q, want declared", n.Completeness)
			}
		}
	}
	if !sawIndex {
		t.Error("--index-url must be reported: it repoints every dependency in the file")
	}
}

func TestPythonMatch(t *testing.T) {
	if !(extract.PyProject{}).Match("pyproject.toml") {
		t.Error("pyproject.toml should match")
	}
	if (extract.PyProject{}).Match("requirements.txt") {
		t.Error("pyproject extractor must not claim requirements.txt")
	}
	r := extract.Requirements{}
	for _, p := range []string{"requirements.txt", "requirements/dev.txt", "requirements-dev.txt"} {
		if !r.Match(p) {
			t.Errorf("should match %q", p)
		}
	}
	if r.Match(".venv/lib/requirements.txt") {
		t.Error("must not match inside a virtualenv")
	}
}

func TestMalformedPyProjectSurfaces(t *testing.T) {
	_, _, err := extract.PyProject{}.Extract(context.Background(),
		source.File{Path: "pyproject.toml", Data: []byte("[project\nbroken")})
	if err == nil {
		t.Error("malformed TOML must surface an error")
	}
}

func keysE(m map[graph.NodeID]graph.Edge) []graph.NodeID {
	var out []graph.NodeID
	for k := range m {
		out = append(out, k)
	}
	return out
}

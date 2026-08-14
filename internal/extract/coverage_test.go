package extract_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func TestCoverageRecognisesRemoteInstallingTools(t *testing.T) {
	for _, p := range []string{
		"Dockerfile", "docker/Dockerfile.ci", "docker-compose.yml",
		".pre-commit-config.yaml", ".mise.toml", ".tool-versions",
		"ansible.cfg", "playbook.yml", "requirements.yml",
		"infra/main.tf", ".terraform.lock.hcl", "Chart.yaml", "flake.nix",
		"Brewfile", ".gitmodules", "Makefile", "justfile",
		"go.mod", "Cargo.toml",
		"pom.xml", "Gemfile", "composer.json", "pnpm-lock.yaml", "bun.lockb",
		".npmrc", "Jenkinsfile", ".circleci/config.yml",
		"renovate.json", "install.sh", ".github/actions/build/action.yml",
	} {
		if !(extract.Coverage{}).Match(p) {
			t.Errorf("%q should be recognised as a supply-chain surface", p)
		}
	}
}

func TestCoverageIgnoresWhatWeAlreadyParseAndVendoredTrees(t *testing.T) {
	for _, p := range []string{
		"package.json",             // real extractor exists
		".github/workflows/ci.yml", // real extractor exists
		"README.md", "src/main.go", // not supply chain
		"node_modules/x/Dockerfile", // someone else's build
		"vendor/y/Makefile",
		"third_party/z/go.mod",
	} {
		if (extract.Coverage{}).Match(p) {
			t.Errorf("%q must not be reported as an unanalysed frontier", p)
		}
	}
}

// A file we cannot expand must appear as a NAMED frontier. Silently omitting it
// reads as "this repo has no Dockerfile", which is worse than saying nothing.
func TestCoverageEmitsNamedDeclaredFrontier(t *testing.T) {
	f := source.File{Path: "Dockerfile", Data: []byte("FROM alpine")}
	edges, nodes, err := extract.Coverage{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || len(edges) != 1 {
		t.Fatalf("got %d nodes / %d edges, want 1 each", len(nodes), len(edges))
	}
	n := nodes[0]
	if n.Completeness != graph.Declared {
		t.Errorf("completeness = %q, want declared — a Dockerfile is analysable, just not yet", n.Completeness)
	}
	if n.Reason != "no-extractor" {
		t.Errorf("reason = %q, want no-extractor", n.Reason)
	}
	if !strings.Contains(n.Note, "Dockerfile") || n.Source != "Dockerfile" {
		t.Errorf("node must name the file it saw: %+v", n)
	}
	if n.Name != "docker" {
		t.Errorf("tool = %q, want docker", n.Name)
	}
}

func TestCoverageDistinguishesTools(t *testing.T) {
	tool := func(p string) string {
		_, nodes, _ := extract.Coverage{}.Extract(context.Background(), source.File{Path: p})
		if len(nodes) == 0 {
			return ""
		}
		return nodes[0].Name
	}
	for p, want := range map[string]string{
		".mise.toml":              "mise",
		".tool-versions":          "asdf",
		"playbook.yml":            "ansible",
		"infra/main.tf":           "terraform",
		".npmrc":                  "npm-registry",
		"renovate.json":           "renovate",
		".pre-commit-config.yaml": "pre-commit",
	} {
		if got := tool(p); got != want {
			t.Errorf("%q -> %q, want %q", p, got, want)
		}
	}
}

func TestToolsCatalogueIsNonTrivial(t *testing.T) {
	if got := len(extract.Tools()); got < 60 {
		t.Errorf("catalogue lists %d tool/category pairs, expected a broad surface", got)
	}
}

// Git hooks and install hooks execute code on an ordinary developer action,
// often before any review. They are the highest-leverage surface in the
// catalogue, so each must be recognised AND classified as a hook.
func TestGitAndInstallHooksAreClassifiedAsHooks(t *testing.T) {
	for _, p := range []string{
		".pre-commit-config.yaml",
		".husky/pre-commit", ".huskyrc.json",
		"lefthook.yml", ".simple-git-hooks.json", ".lintstagedrc",
		"commitlint.config.js", ".overcommit.yml", "Dangerfile",
		".githooks/pre-push", ".envrc",
		".pnpmfile.cjs",
		".yarn/releases/yarn-4.0.0.cjs", ".yarn/plugins/plugin-x.cjs",
		"patches/lodash+4.17.21.patch",
		"install.sh",
	} {
		_, nodes, err := extract.Coverage{}.Extract(context.Background(), source.File{Path: p})
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 1 {
			t.Errorf("%q not recognised", p)
			continue
		}
		if !strings.Contains(nodes[0].Note, "(hook)") {
			t.Errorf("%q classified as %q, want hook — it executes code", p, nodes[0].Note)
		}
	}
}

// Python has many competing package managers and a repo often uses several.
func TestPythonEcosystemsCovered(t *testing.T) {
	// pyproject.toml, requirements*.txt and uv.lock are absent on purpose: they
	// have real extractors now, so they are analysed rather than reported as a
	// frontier. What remains here is the Python tooling still unexpanded.
	want := map[string]string{
		"setup.py": "setuptools", "setup.cfg": "setuptools",
		"poetry.lock": "poetry", "Pipfile.lock": "pipenv", "pdm.lock": "pdm",
		"requirements-dev.lock": "rye", "hatch.toml": "hatch",
		"pixi.lock": "pixi", "environment.yml": "conda", "conda-lock.yml": "conda",
		"tox.ini": "tox", "noxfile.py": "nox", ".python-version": "pyenv",
		".condarc": "conda", ".pypirc": "pypi-registry",
	}
	assertTools(t, want)
}

// The JS side has four package managers plus registries and monorepo runners.
func TestJavaScriptEcosystemsCovered(t *testing.T) {
	want := map[string]string{
		"npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "pnpm", "pnpm-workspace.yaml": "pnpm",
		"yarn.lock": "yarn", "bun.lockb": "bun", "bun.lock": "bun", "bunfig.toml": "bun",
		"deno.json": "deno", "deno.lock": "deno", "import_map.json": "deno", "jsr.json": "jsr",
		"turbo.json": "js-monorepo", "nx.json": "js-monorepo", "lerna.json": "js-monorepo",
		".nvmrc": "node-version", ".volta.json": "volta",
		".npmrc": "npm-registry", ".yarnrc.yml": "npm-registry",
	}
	assertTools(t, want)
}

func assertTools(t *testing.T, want map[string]string) {
	t.Helper()
	for p, tool := range want {
		_, nodes, err := extract.Coverage{}.Extract(context.Background(), source.File{Path: p})
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 1 {
			t.Errorf("%q not recognised at all", p)
			continue
		}
		if nodes[0].Name != tool {
			t.Errorf("%q -> %q, want %q", p, nodes[0].Name, tool)
		}
	}
}

package extract

import (
	"path"
	"sort"
	"strings"
)

// Category says what KIND of supply-chain surface a file is. It matters for
// triage: a manifest declares what you get, but a hook decides what RUNS on your
// machine, often before any review has happened.
type Category string

const (
	// Manifest declares dependencies, usually as ranges.
	Manifest Category = "manifest"
	// Lockfile pins exactly what a resolution produced.
	Lockfile Category = "lockfile"
	// Hook executes code on a git or install event — commit, push, postinstall.
	// These are the highest-leverage surface: nothing needs to be "installed" for
	// them to run, and they run with your credentials.
	Hook Category = "hook"
	// RegistryConfig redirects where artifacts are fetched FROM. It declares no
	// dependency, yet it can silently repoint every one of them.
	RegistryConfig Category = "registry"
	// Toolchain pins or installs interpreters and binaries, typically by
	// downloading them.
	Toolchain Category = "toolchain"
	// Orchestrator runs other builds, images or pipelines.
	Orchestrator Category = "orchestrator"
	// Bot changes your dependencies on a schedule, without a human in the loop.
	Bot Category = "bot"
)

type entry struct {
	tool     string
	category Category
	match    func(dir, base string) bool
}

// catalogue is the frontier: files that pull in or execute something, which no
// extractor expands yet. Files a real extractor already handles are absent by
// design — this list is what we walk past, not an inventory of what we support.
var catalogue = []entry{
	// ---- git hooks and commit-time execution -------------------------------
	// These run code on your machine on an ordinary git operation. pre-commit and
	// lefthook fetch and execute REMOTE repositories pinned in their config.
	{"pre-commit", Hook, exact(".pre-commit-config.yaml", ".pre-commit-config.yml", ".pre-commit-hooks.yaml")},
	{"husky", Hook, func(d, b string) bool {
		return strings.HasPrefix(d, ".husky") ||
			b == ".huskyrc" || b == ".huskyrc.json" || b == ".huskyrc.js" || b == "husky.config.js"
	}},
	{"lefthook", Hook, exact("lefthook.yml", "lefthook.yaml", "lefthook.toml", ".lefthook.yml", ".lefthook.yaml")},
	{"simple-git-hooks", Hook, exact(".simple-git-hooks.json", "simple-git-hooks.json")},
	{"lint-staged", Hook, exact(".lintstagedrc", ".lintstagedrc.json", ".lintstagedrc.js", "lint-staged.config.js")},
	{"commitlint", Hook, func(_, b string) bool {
		return strings.HasPrefix(b, "commitlint.config.") || strings.HasPrefix(b, ".commitlintrc")
	}},
	{"overcommit", Hook, exact(".overcommit.yml")},
	{"danger", Hook, func(_, b string) bool { return b == "Dangerfile" || strings.HasPrefix(b, "dangerfile.") }},
	{"githooks-dir", Hook, func(d, _ string) bool { return d == "githooks" || d == ".githooks" }},
	{"direnv", Hook, exact(".envrc")},
	// pnpm executes this file during resolution, so it can rewrite any dependency.
	{"pnpm-hooks", Hook, exact(".pnpmfile.cjs", "pnpmfile.js", ".pnpmfile.js")},
	{"patch-package", Hook, func(d, b string) bool { return d == "patches" && strings.HasSuffix(b, ".patch") }},

	// ---- JavaScript / TypeScript -------------------------------------------
	{"npm", Lockfile, exact("npm-shrinkwrap.json")},
	{"pnpm", Lockfile, exact("pnpm-lock.yaml")},
	{"pnpm", Manifest, exact("pnpm-workspace.yaml")},
	{"yarn", Lockfile, exact("yarn.lock")},
	// A vendored yarn binary and its plugins are executable code committed to the
	// repository that no manifest declares.
	{"yarn-berry", Hook, func(d, _ string) bool {
		return strings.HasPrefix(d, ".yarn/releases") || strings.HasPrefix(d, ".yarn/plugins")
	}},
	{"bun", Lockfile, exact("bun.lockb", "bun.lock")},
	{"bun", Manifest, exact("bunfig.toml")},
	{"deno", Manifest, exact("deno.json", "deno.jsonc")},
	{"deno", Lockfile, exact("deno.lock")},
	{"deno", Manifest, exact("import_map.json", "importMap.json")},
	{"jsr", Manifest, exact("jsr.json", "jsr.jsonc")},
	{"js-monorepo", Orchestrator, exact("lerna.json", "nx.json", "turbo.json", "rush.json")},
	{"volta", Toolchain, exact(".volta.json")},
	{"node-version", Toolchain, exact(".nvmrc", ".node-version")},
	{"npm-registry", RegistryConfig, exact(".npmrc", ".yarnrc", ".yarnrc.yml")},

	// ---- Python ------------------------------------------------------------
	// pyproject.toml, requirements*.txt and uv.lock have real extractors and are
	// deliberately absent: this list is the frontier, not an inventory.
	{"setuptools", Manifest, exact("setup.py", "setup.cfg", "MANIFEST.in")},
	{"poetry", Lockfile, exact("poetry.lock")},
	{"poetry", Manifest, exact("poetry.toml")},
	{"pipenv", Manifest, exact("Pipfile")},
	{"pipenv", Lockfile, exact("Pipfile.lock")},
	{"pdm", Lockfile, exact("pdm.lock")},
	{"pdm", Manifest, exact("pdm.toml", ".pdm-python")},
	{"uv", Manifest, exact("uv.toml")},
	{"rye", Lockfile, exact("requirements.lock", "requirements-dev.lock")},
	{"hatch", Manifest, exact("hatch.toml")},
	{"pixi", Manifest, exact("pixi.toml")},
	{"pixi", Lockfile, exact("pixi.lock")},
	{"conda", Manifest, exact("environment.yml", "environment.yaml", "meta.yaml")},
	{"conda", Lockfile, exact("conda-lock.yml", "conda-lock.yaml")},
	{"conda", RegistryConfig, exact(".condarc")},
	{"tox", Orchestrator, exact("tox.ini")},
	{"nox", Orchestrator, exact("noxfile.py")},
	{"buildout", Manifest, exact("buildout.cfg")},
	{"pyenv", Toolchain, exact(".python-version")},
	{"pypi-registry", RegistryConfig, exact("pip.conf", ".pypirc")},

	// ---- containers and infrastructure -------------------------------------
	{"docker", Manifest, func(_, b string) bool {
		return b == "Dockerfile" || strings.HasPrefix(b, "Dockerfile.") || strings.HasSuffix(b, ".dockerfile")
	}},
	{"docker-compose", Orchestrator, exact("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")},
	{"terraform", Manifest, func(_, b string) bool { return strings.HasSuffix(b, ".tf") }},
	{"terraform", Lockfile, exact(".terraform.lock.hcl")},
	{"helm", Manifest, exact("Chart.yaml")},
	{"helm", Lockfile, exact("Chart.lock")},
	{"kustomize", Orchestrator, exact("kustomization.yaml", "kustomization.yml")},
	{"skaffold", Orchestrator, exact("skaffold.yaml")},
	{"ansible", Manifest, func(_, b string) bool {
		return b == "ansible.cfg" || b == "galaxy.yml" || b == "site.yml" ||
			b == "requirements.yml" || strings.HasPrefix(b, "playbook")
	}},
	{"vagrant", Orchestrator, exact("Vagrantfile")},
	{"devcontainer", Orchestrator, func(d, b string) bool {
		return b == "devcontainer.json" || b == ".devcontainer.json" || strings.HasPrefix(d, ".devcontainer")
	}},

	// ---- toolchain managers -------------------------------------------------
	{"mise", Toolchain, exact(".mise.toml", "mise.toml", ".mise/config.toml")},
	{"asdf", Toolchain, exact(".tool-versions")},
	{"proto", Toolchain, exact(".prototools")},
	{"nix", Manifest, exact("flake.nix", "default.nix", "shell.nix")},
	{"nix", Lockfile, exact("flake.lock")},
	{"homebrew", Manifest, exact("Brewfile")},
	{"homebrew", Lockfile, exact("Brewfile.lock.json")},

	// ---- other language ecosystems ------------------------------------------
	// go.mod has a real extractor and is deliberately absent, like pyproject.toml
	// and uv.lock above: Coverage reports what we could NOT expand, so listing an
	// expanded file here makes the document contradict itself.
	//
	// go.sum stays. It is genuinely unexpanded, and deliberately so — it records
	// every version ever CONSIDERED, including ones MVS rejected, so it is not
	// the install set and must not be read as one.
	{"go", Lockfile, exact("go.sum")},
	{"cargo", Manifest, exact("Cargo.toml")},
	{"cargo", Lockfile, exact("Cargo.lock")},
	{"maven", Manifest, exact("pom.xml")},
	{"gradle", Manifest, func(_, b string) bool {
		return b == "build.gradle" || b == "build.gradle.kts" || b == "libs.versions.toml"
	}},
	{"bundler", Manifest, exact("Gemfile")},
	{"bundler", Lockfile, exact("Gemfile.lock")},
	{"composer", Manifest, exact("composer.json")},
	{"composer", Lockfile, exact("composer.lock")},
	{"nuget", Manifest, func(_, b string) bool { return strings.HasSuffix(b, ".csproj") || b == "paket.dependencies" }},
	{"nuget", Lockfile, exact("packages.lock.json")},
	{"swift", Manifest, exact("Package.swift")},
	{"swift", Lockfile, exact("Package.resolved")},
	{"cocoapods", Manifest, exact("Podfile")},
	{"cocoapods", Lockfile, exact("Podfile.lock")},
	{"pub", Manifest, exact("pubspec.yaml")},
	{"pub", Lockfile, exact("pubspec.lock")},
	{"bazel", Orchestrator, exact("WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel", "MODULE.bazel.lock")},
	{"pants", Orchestrator, exact("pants.toml")},
	{"earthly", Orchestrator, exact("Earthfile")},
	{"dagger", Orchestrator, exact("dagger.json")},
	{"git-submodules", Manifest, exact(".gitmodules")},

	// ---- build and CI --------------------------------------------------------
	{"make", Orchestrator, exact("Makefile", "makefile", "GNUmakefile")},
	{"just", Orchestrator, exact("justfile", "Justfile", ".justfile")},
	{"task", Orchestrator, exact("Taskfile.yml", "Taskfile.yaml")},
	// .gitlab-ci.yml is handled by GitLabCI; the rest still have no extractor.
	{"ci", Orchestrator, exact("Jenkinsfile", "azure-pipelines.yml", ".drone.yml",
		"bitbucket-pipelines.yml", "cloudbuild.yaml", ".travis.yml", "buildkite.yml", ".woodpecker.yml")},
	{"ci", Orchestrator, func(d, b string) bool { return d == ".circleci" && strings.HasPrefix(b, "config.") }},
	{"local-action", Orchestrator, func(d, b string) bool {
		return (b == "action.yml" || b == "action.yaml") && strings.Contains(d, ".github")
	}},
	{"bootstrap-script", Hook, exact("install.sh", "bootstrap.sh", "setup.sh", "get.sh")},

	// ---- automation that changes dependencies for you ------------------------
	{"renovate", Bot, exact("renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json")},
	{"dependabot", Bot, exact("dependabot.yml", "dependabot.yaml")},
}

func exact(names ...string) func(dir, base string) bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return func(_, b string) bool { return set[b] }
}

// skipTree holds trees that describe somebody else's build, not ours.
var skipTree = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"third_party":  true,
	"testdata":     true,
	".git":         true,
}

// lookup finds the tool and category responsible for a path.
func lookup(p string) (string, Category, bool) {
	dir, base := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	for _, seg := range strings.Split(dir, "/") {
		if skipTree[seg] {
			return "", "", false
		}
	}
	for _, c := range catalogue {
		if c.match(dir, base) {
			return c.tool, c.category, true
		}
	}
	return "", "", false
}

// Tool describes one recognised surface.
type Tool struct {
	Name     string
	Category Category
}

// Tools lists every recognised tool, for documentation and for deciding which
// extractor to write next.
func Tools() []Tool {
	seen := map[string]bool{}
	var out []Tool
	for _, c := range catalogue {
		k := c.tool + "\x00" + string(c.category)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, Tool{Name: c.tool, Category: c.category})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Category < out[j].Category
	})
	return out
}

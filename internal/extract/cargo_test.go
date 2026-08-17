package extract_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func cargoExtract(t *testing.T, body string) []graph.Edge {
	t.Helper()
	edges, _, err := extract.Cargo{}.Extract(context.Background(), source.File{
		Path: "Cargo.toml", Data: []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	return edges
}

// Cargo accepts a dependency as either a bare string or a table. A parser that
// handles only the string silently drops every table-form dependency — which is
// where features, renames and optionality live.
func TestCargoReadsBothDependencySpellings(t *testing.T) {
	edges := cargoExtract(t, `
[package]
name = "app"

[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }
`)
	if len(edges) != 2 {
		t.Fatalf("got %d edges, want 2 — the table form was dropped", len(edges))
	}
	for _, e := range edges {
		if e.Spec == "" {
			t.Errorf("edge to %s carries no version requirement", e.To)
		}
	}
}

// Every dependency table counts, and the scope records which one it came from.
// A build dependency runs code on the build machine, so it is production
// exposure rather than a development convenience.
func TestCargoReadsEveryDependencyTable(t *testing.T) {
	edges := cargoExtract(t, `
[package]
name = "app"

[dependencies]
serde = "1.0"

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"

[target.'cfg(unix)'.dependencies]
nix = "0.27"
`)
	got := map[string]graph.Scope{}
	for _, e := range edges {
		got[string(e.To)] = e.Scope
	}
	if len(got) != 4 {
		t.Fatalf("got %d dependencies, want 4: %v", len(got), got)
	}
	if got["pkg:cargo/criterion"] != graph.Dev {
		t.Errorf("criterion scope = %q, want dev", got["pkg:cargo/criterion"])
	}
	if got["pkg:cargo/cc"] != graph.Prod {
		t.Errorf("cc scope = %q, want prod — a build script runs real code", got["pkg:cargo/cc"])
	}
	if _, ok := got["pkg:cargo/nix"]; !ok {
		t.Error("a per-target dependency was dropped")
	}
}

// An optional dependency is gated behind a feature. Per the widest reading it
// is included — a consumer can switch it on without this repository changing —
// but it must be marked so the difference stays visible.
func TestCargoOptionalDependencyIsMarked(t *testing.T) {
	edges := cargoExtract(t, `
[package]
name = "app"

[dependencies]
serde = { version = "1.0", optional = true }
`)
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	if edges[0].Scope != graph.Optional {
		t.Errorf("scope = %q, want optional — it is feature-gated", edges[0].Scope)
	}
}

// `package = "real"` renames a crate locally. The thing actually pulled in, and
// the thing advisories attach to, is the real crate — not the local alias.
func TestCargoRenameFollowsTheRealCrate(t *testing.T) {
	edges := cargoExtract(t, `
[package]
name = "app"

[dependencies]
my-alias = { version = "1.0", package = "serde" }
`)
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	if string(edges[0].To) != "pkg:cargo/serde" {
		t.Errorf("resolved to %s, want the renamed-to crate pkg:cargo/serde", edges[0].To)
	}
}

// A path or git dependency is not a crates.io package: nothing to resolve, no
// advisory record. Reporting it as the published crate of that name would be
// worse than omitting it — it would attribute someone else's advisories to
// local code.
func TestCargoPathAndGitDependenciesAreNotCratesIOPackages(t *testing.T) {
	edges := cargoExtract(t, `
[package]
name = "app"

[dependencies]
local = { path = "../local" }
forked = { git = "https://example.com/f.git" }
serde = "1.0"
`)
	for _, e := range edges {
		if string(e.To) == "pkg:cargo/local" || string(e.To) == "pkg:cargo/forked" {
			t.Errorf("%s was reported as a published crate", e.To)
		}
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want only serde", len(edges))
	}
}

func TestCargoMatch(t *testing.T) {
	m := extract.Cargo{}
	if !m.Match("Cargo.toml") || !m.Match("crates/x/Cargo.toml") {
		t.Error("a real manifest was not matched")
	}
	for _, p := range []string{"Cargo.lock", "vendor/x/Cargo.toml", "target/y/Cargo.toml"} {
		if m.Match(p) {
			t.Errorf("Match(%q) = true; that is not this crate's declaration", p)
		}
	}
}

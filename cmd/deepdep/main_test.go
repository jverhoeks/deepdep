package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
)

func fixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"fx","dependencies":{"is-string":"^1.0.0"}}`)
	write("package-lock.json", `{
      "lockfileVersion":3,
      "packages":{"":{"name":"fx"},"node_modules/is-string":{"version":"1.0.7"}}
    }`)
	write(".github/workflows/ci.yml",
		"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - run: make all\n")
	return dir
}

type doc struct {
	AsOf    string `json:"as_of"`
	KnownAt string `json:"known_at"`
	Summary struct {
		Total, Opaque, Declared int
	} `json:"summary"`
	BoundsHit []string `json:"bounds_hit"`
	Nodes     []struct {
		ID           string `json:"id"`
		Completeness string `json:"completeness"`
		Reason       string `json:"reason"`
		Note         string `json:"note"`
	} `json:"nodes"`
}

func TestEndToEndOfflinePersistsAndRollsUp(t *testing.T) {
	dir := fixtureRepo(t)
	db := filepath.Join(t.TempDir(), "d.db")

	out, err := run([]string{"scan", "--mode", "will", "--format", "json", "--offline", "--db", db, dir})
	if err != nil {
		t.Fatal(err)
	}
	var got doc
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// `run: make all` is statically undecidable. Reporting a clean graph that
	// dropped it would be a wrong answer.
	if got.Summary.Opaque < 1 {
		t.Error("`run: make all` must surface as an opaque frontier node")
	}

	var action struct{ id, comp, reason string }
	for _, n := range got.Nodes {
		if n.ID == "pkg:github/actions/checkout@v4" {
			action.id, action.comp, action.reason = n.ID, n.Completeness, n.Reason
		}
	}
	if action.id == "" {
		t.Fatal("CI action missing from the closure — a workflow pulls in code too")
	}
	if action.comp != "declared" || action.reason != "unpinned-ref" {
		t.Errorf("moving tag = %+v, want declared/unpinned-ref", action)
	}

	// offline means nothing was resolved, and that must be visible.
	if len(got.BoundsHit) == 0 {
		t.Error("bounds_hit must record why the closure stopped")
	}

	s, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pkgs, err := s.Packages(context.Background(), "", store.PackageQuery{Name: "is-string"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("is-string rollup rows = %d, want 1", len(pkgs))
	}
	if len(pkgs[0].Versions) == 0 {
		t.Fatal("no version rows for is-string")
	}
	if pkgs[0].Versions[0].State != rollup.Installed {
		t.Errorf("is-string state = %q, want installed (the lockfile pins 1.0.7)",
			pkgs[0].Versions[0].State)
	}
}

// --as-of is an audit flag: it must fail loudly rather than be recorded and
// quietly ignored.
func TestAsOfOfflineIsAnError(t *testing.T) {
	dir := fixtureRepo(t)
	_, err := run([]string{"scan", "--as-of", "2020-01-01T00:00:00Z", "--offline", "--no-db", dir})
	if err == nil {
		t.Error("--as-of must error when publish times are unavailable")
	}
}

func TestBothTimeAxesAlwaysRecorded(t *testing.T) {
	dir := fixtureRepo(t)
	out, err := run([]string{"scan", "--offline", "--no-db", dir})
	if err != nil {
		t.Fatal(err)
	}
	var got doc
	json.Unmarshal(out, &got)
	if got.AsOf == "" || got.KnownAt == "" {
		t.Errorf("as_of=%q known_at=%q; both axes must always be recorded", got.AsOf, got.KnownAt)
	}
}

func TestCycloneDXFormat(t *testing.T) {
	dir := fixtureRepo(t)
	out, err := run([]string{"scan", "--format", "cyclonedx", "--offline", "--no-db", dir})
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q", bom.BOMFormat)
	}
}

func TestUnknownSubcommandErrors(t *testing.T) {
	if _, err := run([]string{"frobnicate"}); err == nil {
		t.Error("unknown subcommand must error")
	}
	if _, err := run(nil); err == nil {
		t.Error("no args must error with usage")
	}
}

func gitRepoWithDepChange(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	commit := func(rng, ver, msg string) {
		os.WriteFile(filepath.Join(dir, "package.json"),
			[]byte(`{"name":"a","dependencies":{"is-string":"`+rng+`"}}`), 0o644)
		os.WriteFile(filepath.Join(dir, "package-lock.json"),
			[]byte(`{"lockfileVersion":3,"packages":{"":{"name":"a"},"node_modules/is-string":{"version":"`+ver+`"}}}`), 0o644)
		git("add", "-A")
		git("commit", "-qm", msg)
	}
	git("init", "-q")
	commit("^1.0.0", "1.0.5", "add")
	commit("^1.0.0", "1.0.7", "bump")
	return dir
}

// The JSON path must actually contain the encoded changes. It once returned an
// empty buffer because the return arguments were evaluated before the encode.
func TestHistoryJSONIsNotEmpty(t *testing.T) {
	dir := gitRepoWithDepChange(t)
	out, err := run([]string{"history", "--format", "json", dir})
	if err != nil {
		t.Fatal(err)
	}
	var changes []struct {
		Name          string `json:"name"`
		Kind          string `json:"kind"`
		FromInstalled string `json:"from_installed"`
		ToInstalled   string `json:"to_installed"`
	}
	if err := json.Unmarshal(out, &changes); err != nil {
		t.Fatalf("history --format json produced %q: %v", out, err)
	}
	if len(changes) < 2 {
		t.Fatalf("changes = %d, want at least 2", len(changes))
	}
	var bumped bool
	for _, c := range changes {
		if c.Kind == "version-changed" && c.FromInstalled == "1.0.5" && c.ToInstalled == "1.0.7" {
			bumped = true
		}
	}
	if !bumped {
		t.Errorf("lockfile-only bump missing from %+v", changes)
	}
}

func TestHistoryPackageFilter(t *testing.T) {
	dir := gitRepoWithDepChange(t)
	out, err := run([]string{"history", "--package", "nonexistent", "--format", "json", dir})
	if err != nil {
		t.Fatal(err)
	}
	var changes []map[string]any
	if err := json.Unmarshal(out, &changes); err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Errorf("filter returned %d changes for a package that was never used", len(changes))
	}
}

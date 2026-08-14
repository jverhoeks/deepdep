package history_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jverhoeks/deepdep/internal/history"
)

// repo builds a git repository whose is-string dependency moves over time,
// including one commit that changes ONLY the lockfile and one that changes
// nothing relevant.
func repo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	commitDate := "2024-01-15T10:00:00Z"
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
			"GIT_COMMITTER_DATE="+commitDate)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(rng, ver, msg string) {
		t.Helper()
		write("package.json", fmt.Sprintf(`{"name":"app","dependencies":{"is-string":"%s"}}`, rng))
		write("package-lock.json", fmt.Sprintf(
			`{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/is-string":{"version":"%s"}}}`, ver))
		git("add", "-A")
		git("commit", "-qm", msg)
	}

	git("init", "-q")
	commit("^1.0.0", "1.0.5", "add is-string")
	commit("^1.0.0", "1.0.7", "bump lockfile only") // range unchanged
	// a commit that touches nothing dependency-related
	write("README.md", "hello")
	git("add", "-A")
	git("commit", "-qm", "docs")
	commit("^1.1.0", "1.1.0", "widen range")
	return dir
}

func TestCandidatesSkipUnrelatedCommits(t *testing.T) {
	dir := repo(t)
	got, err := history.Candidates(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 3 dependency commits; the README-only commit must not appear.
	if len(got) != 3 {
		t.Fatalf("candidates = %d, want 3 (README commit must be skipped)", len(got))
	}
	// Every commit in this fixture shares a committer date, exactly as a scripted
	// series does. Ordering must therefore come from the commit graph.
	want := []string{"add is-string", "bump lockfile only", "widen range"}
	for i, w := range want {
		if got[i].Subject != w {
			t.Errorf("candidate %d = %q, want %q (ordering must follow the graph, not the clock)",
				i, got[i].Subject, w)
		}
	}
}

func TestChangesDetectLockfileOnlyBump(t *testing.T) {
	dir := repo(t)
	changes, err := history.Changes(context.Background(), dir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	byMsg := map[string][]history.Change{}
	for _, c := range changes {
		byMsg[c.Subject] = append(byMsg[c.Subject], c)
	}

	if got := byMsg["add is-string"]; len(got) != 1 || got[0].Kind != history.Added {
		t.Fatalf("first commit = %+v, want one Added", got)
	}

	// The declared range never moved here; only the lockfile did. A range-only
	// diff would miss this entirely, which is the whole reason to read both.
	bump := byMsg["bump lockfile only"]
	if len(bump) != 1 {
		t.Fatalf("lockfile-only bump produced %d changes, want 1", len(bump))
	}
	if bump[0].Kind != history.VersionChanged {
		t.Errorf("kind = %q, want version-changed", bump[0].Kind)
	}
	if bump[0].FromInstalled != "1.0.5" || bump[0].ToInstalled != "1.0.7" {
		t.Errorf("installed %q -> %q, want 1.0.5 -> 1.0.7", bump[0].FromInstalled, bump[0].ToInstalled)
	}
	if bump[0].FromDeclared != bump[0].ToDeclared {
		t.Errorf("declared range should be unchanged, got %q -> %q", bump[0].FromDeclared, bump[0].ToDeclared)
	}

	widen := byMsg["widen range"]
	if len(widen) != 1 {
		t.Fatalf("range widening produced %d changes, want 1", len(widen))
	}
	if widen[0].Kind != history.RangeChanged {
		t.Errorf("kind = %q, want range-changed", widen[0].Kind)
	}
	if widen[0].FromDeclared != "^1.0.0" || widen[0].ToDeclared != "^1.1.0" {
		t.Errorf("declared %q -> %q", widen[0].FromDeclared, widen[0].ToDeclared)
	}
	if widen[0].ToInstalled != "1.1.0" {
		t.Errorf("installed to = %q, want 1.1.0", widen[0].ToInstalled)
	}
}

func TestChangesCarryCommitProvenance(t *testing.T) {
	dir := repo(t)
	changes, err := history.Changes(context.Background(), dir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) == 0 {
		t.Fatal("no changes")
	}
	for _, c := range changes {
		if len(c.Commit) < 7 {
			t.Errorf("change %+v has no commit sha", c)
		}
		if c.When.IsZero() {
			t.Errorf("change %+v has no timestamp", c)
		}
		if c.Name == "" {
			t.Errorf("change %+v has no package name", c)
		}
	}
}

func TestRemovalIsReported(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"a","dependencies":{"left-pad":"^1.0.0"}}`), 0o644)
	run("init", "-q")
	run("add", "-A")
	run("commit", "-qm", "add")
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"a"}`), 0o644)
	run("add", "-A")
	run("commit", "-qm", "drop")

	changes, err := history.Changes(context.Background(), dir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var removed bool
	for _, c := range changes {
		if c.Kind == history.Removed && c.Name == "left-pad" {
			removed = true
		}
	}
	if !removed {
		t.Errorf("dropping a dependency must be reported; got %+v", changes)
	}
}

// Watching only npm files meant a Python or Rust repository reported no history
// at all — indistinguishable from "nothing ever changed".
func TestCandidatesTrackNonNPMManifests(t *testing.T) {
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
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	git("init", "-q")
	write("pyproject.toml", "[project]\ndependencies = [\"requests>4.5.0\"]\n")
	git("add", "-A")
	git("commit", "-qm", "python deps")

	write("README.md", "docs")
	git("add", "-A")
	git("commit", "-qm", "docs only")

	write("Cargo.toml", "[dependencies]\nserde = \"1.0\"\n")
	git("add", "-A")
	git("commit", "-qm", "rust deps")

	got, err := history.Candidates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("candidates = %d, want 2 (pyproject and Cargo commits, not the README one)", len(got))
	}
	if got[0].Subject != "python deps" || got[1].Subject != "rust deps" {
		t.Errorf("got %q then %q", got[0].Subject, got[1].Subject)
	}
}

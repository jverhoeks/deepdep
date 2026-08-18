package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jverhoeks/deepdep/internal/project"
)

// gitRepo makes a one-commit repository, optionally with an origin remote, and
// returns its absolute path.
func gitRepo(t *testing.T, remote string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"app"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-qm", "one")
	if remote != "" {
		run("remote", "add", "origin", remote)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	// macOS hands out /var/folders symlinked from /private/var, and the origin
	// records what filepath.Abs produced, so the expectation has to match it.
	return abs
}

// The two facts openLocal already has must survive: the absolute path it
// computes and then discards, and the remote on the repository it has open.
func TestLocalSourceReportsItsPathAndRemote(t *testing.T) {
	dir := gitRepo(t, "git@github.com:o/r.git")

	s, err := openLocal(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	got := s.Origin()
	if got.Kind != project.KindLocal {
		t.Errorf("Kind = %q, want %q", got.Kind, project.KindLocal)
	}
	if got.Remote != "git@github.com:o/r.git" {
		t.Errorf("Remote = %q, want the origin remote", got.Remote)
	}
	if got.Path != dir {
		t.Errorf("Path = %q, want %q", got.Path, dir)
	}
}

// A directory with no remote is still scannable and still gets a path. Before
// this change the path was the thing that made two same-named directories
// indistinguishable in the store.
func TestLocalSourceWithoutARemoteStillReportsThePath(t *testing.T) {
	dir := gitRepo(t, "")

	s, err := openLocal(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	got := s.Origin()
	if got.Remote != "" {
		t.Errorf("Remote = %q, want empty", got.Remote)
	}
	if got.Path != dir {
		t.Errorf("Path = %q, want %q", got.Path, dir)
	}
}

// A cache clone's directory is deepdep's, not the user's. Recording it as a
// location would invite someone to go and edit it, and it is a hash of the URL
// besides. openCloned must overwrite what openLocal filled in — the same
// override the Repo() identity already needs, on the same code path.
func TestClonedSourceReportsTheRemoteAndNoPath(t *testing.T) {
	origin := gitRepo(t, "")
	cache := t.TempDir()

	for _, label := range []string{"first open (clone)", "second open (cache hit)"} {
		s, err := openRemote(context.Background(), origin, cache, "", "")
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		got := s.Origin()
		if got.Kind != project.KindRemote {
			t.Errorf("%s: Kind = %q, want %q", label, got.Kind, project.KindRemote)
		}
		if got.Remote != origin {
			t.Errorf("%s: Remote = %q, want %q", label, got.Remote, origin)
		}
		if got.Path != "" {
			t.Errorf("%s: Path = %q, want empty — that is deepdep's cache directory, not the user's checkout",
				label, got.Path)
		}
	}
}

// The in-memory source is not a project. Downstream packages (walk, effective,
// rollup) test against it, and those runs must not create registry rows.
func TestStaticSourceHasNoOrigin(t *testing.T) {
	if got := Static(nil).Origin(); got != (project.Origin{}) {
		t.Fatalf("Origin() = %+v, want the zero value", got)
	}
}

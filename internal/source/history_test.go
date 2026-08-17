package source_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jverhoeks/deepdep/internal/source"
)

// Time travel is only meaningful if we can read a tree as it stood at an old
// commit WITHOUT checking it out. This builds a two-commit repo and asserts the
// old content comes back while the worktree is left untouched.
func TestReadsHistoricalCommitWithoutCheckout(t *testing.T) {
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
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	run("init", "-q")
	write(`{"name":"app","dependencies":{"lodash":"^3.0.0"}}`)
	run("add", "-A")
	run("commit", "-qm", "v1")
	run("tag", "v1.0.0")

	write(`{"name":"app","dependencies":{"lodash":"^4.0.0"}}`)
	run("add", "-A")
	run("commit", "-qm", "v2")

	read := func(at string) string {
		t.Helper()
		s, err := source.Open(context.Background(), dir, t.TempDir(), at, "")
		if err != nil {
			t.Fatalf("Open(at=%q): %v", at, err)
		}
		var got string
		s.Walk(func(f source.File) error {
			if f.Path == "package.json" {
				got = string(f.Data)
			}
			return nil
		})
		return got
	}

	if got := read("v1.0.0"); got != `{"name":"app","dependencies":{"lodash":"^3.0.0"}}` {
		t.Errorf("at tag v1.0.0 got %q, want the OLD manifest", got)
	}
	if got := read(""); got != `{"name":"app","dependencies":{"lodash":"^4.0.0"}}` {
		t.Errorf("at HEAD got %q, want the current manifest", got)
	}

	// the worktree must be exactly as we left it
	cur, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) != `{"name":"app","dependencies":{"lodash":"^4.0.0"}}` {
		t.Errorf("history read mutated the worktree: %q", cur)
	}
}

func TestRefIsTheResolvedCommitSHA(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Run()
	}
	os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644)
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-qm", "c"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	s, err := source.Open(context.Background(), dir, t.TempDir(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Ref()) != 40 {
		t.Errorf("Ref() = %q, want a 40-char SHA so runs are reproducible", s.Ref())
	}
}

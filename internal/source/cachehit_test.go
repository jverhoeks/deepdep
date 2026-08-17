package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A cached clone must still know WHICH remote it came from.
//
// openRemote sets the identity after cloning, but the cache-hit path returns
// early and skipped it, so the run was stored under the cache directory's hash
// instead of the URL. That silently breaks `org` twice over: latestRunFor looks
// a run up by clone URL and reports "no stored run", and alreadyScanned never
// matches, so resumability stops resuming and every repository is rescanned.
//
// The bug only appears on the SECOND open, which is why a single-scan test
// would not have caught it.
func TestCachedCloneKeepsItsRemoteIdentity(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	origin := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = origin
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(origin, "package.json"), []byte(`{"name":"app"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-qm", "one")

	cache := t.TempDir()
	for i, label := range []string{"first open (clone)", "second open (cache hit)"} {
		s, err := openRemote(context.Background(), origin, cache, "", "")
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got := s.Repo(); got != origin {
			t.Errorf("%s: Repo() = %q, want the remote %q — run %d would be stored under the wrong target",
				label, got, origin, i+1)
		}
	}
}

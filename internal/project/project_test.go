package project_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/project"
)

// Every spelling of the same repository has to land on one key, because the
// registry's whole purpose is that two scans of one repository are one project.
func TestCanonicalCollapsesEverySpellingOfOneRepo(t *testing.T) {
	for _, remote := range []string{
		"git@github.com:o/r.git",
		"git@github.com:o/r",
		"https://github.com/o/r.git",
		"https://github.com/o/r",
		"https://github.com/o/r/",
		"ssh://git@github.com/o/r.git",
		"HTTPS://GitHub.com/o/r.git",
		"https://github.com:443/o/r.git",
	} {
		key, name, ok := project.Canonical(remote)
		if !ok {
			t.Errorf("Canonical(%q) = not ok, want a key", remote)
			continue
		}
		if key != "github.com/o/r" {
			t.Errorf("Canonical(%q) key = %q, want %q", remote, key, "github.com/o/r")
		}
		if name != "o/r" {
			t.Errorf("Canonical(%q) name = %q, want %q", remote, name, "o/r")
		}
	}
}

// A clone URL can carry a credential. Storing it would put a token in the
// registry, in plaintext, in a file users copy around.
func TestCanonicalDropsCredentials(t *testing.T) {
	key, _, ok := project.Canonical("https://x-access-token:ghp_secret@github.com/o/r.git")
	if !ok {
		t.Fatal("not ok")
	}
	if key != "github.com/o/r" {
		t.Fatalf("key = %q, want %q", key, "github.com/o/r")
	}
}

// Anything without a host is not a remote. This is also the filter that keeps
// the migration off the pre-v5 local runs, whose target is a bare basename.
func TestCanonicalRejectsWhatIsNotARemote(t *testing.T) {
	for _, in := range []string{"", "   ", "data-platform", "sqlengine", "/Users/x/src/app", "https://github.com", "https://github.com/"} {
		if key, _, ok := project.Canonical(in); ok {
			t.Errorf("Canonical(%q) = %q, ok — want rejected", in, key)
		}
	}
}

// Identity prefers the remote, because a repository cloned to two directories
// is one project with two locations.
func TestOfPrefersTheRemoteOverThePath(t *testing.T) {
	id, ok := project.Of(project.Origin{
		Kind: project.KindLocal, Remote: "git@github.com:o/r.git", Path: "/Users/x/src/r",
	})
	if !ok {
		t.Fatal("not ok")
	}
	if id.Key != "github.com/o/r" || id.Kind != project.KindRemote || id.Name != "o/r" {
		t.Fatalf("got %+v, want key github.com/o/r kind remote name o/r", id)
	}
}

// A directory with no remote is still scannable, so it still gets a project —
// keyed by its absolute path, which is the only durable thing about it.
func TestOfFallsBackToThePathForANonGitTree(t *testing.T) {
	id, ok := project.Of(project.Origin{Kind: project.KindLocal, Path: "/Users/x/src/data-platform"})
	if !ok {
		t.Fatal("not ok")
	}
	if id.Key != "/Users/x/src/data-platform" || id.Kind != project.KindLocal || id.Name != "data-platform" {
		t.Fatalf("got %+v", id)
	}
}

// A run with neither fact — the static in-memory source — is not a project.
func TestOfRejectsAnEmptyOrigin(t *testing.T) {
	if id, ok := project.Of(project.Origin{}); ok {
		t.Fatalf("got %+v, want rejected", id)
	}
}

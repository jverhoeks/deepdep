package source_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/source"
)

func walkPaths(t *testing.T, s source.Source) []string {
	t.Helper()
	var got []string
	if err := s.Walk(func(f source.File) error {
		got = append(got, f.Path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	return got
}

func TestLocalSourceWalksTreeSkippingNoise(t *testing.T) {
	dir := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("package.json", `{"name":"x"}`)
	mk(".github/workflows/ci.yml", "on: push")
	mk("node_modules/x/package.json", "{}")
	mk("vendor/y/go.mod", "module y")
	mk(".git/config", "x")

	s, err := source.Open(context.Background(), dir, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".github/workflows/ci.yml", "package.json"}
	if got := walkPaths(t, s); !reflect.DeepEqual(got, want) {
		t.Errorf("walked %v, want %v", got, want)
	}
}

func TestLocalSourcePathsAreRelativeAndSlashed(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "web"), 0o755)
	os.WriteFile(filepath.Join(dir, "web", "package.json"), []byte("{}"), 0o644)

	s, _ := source.Open(context.Background(), dir, t.TempDir(), "")
	got := walkPaths(t, s)
	if len(got) != 1 || got[0] != "web/package.json" {
		t.Errorf("got %v, want [web/package.json]", got)
	}
	if strings.HasPrefix(got[0], "/") {
		t.Error("paths must be repo-relative")
	}
}

func TestStaticSourceForDownstreamTests(t *testing.T) {
	s := source.Static([]source.File{
		{Path: "package.json", Data: []byte(`{"name":"root"}`)},
		{Path: ".github/workflows/ci.yml", Data: []byte("on: push")},
	})
	want := []string{".github/workflows/ci.yml", "package.json"}
	if got := walkPaths(t, s); !reflect.DeepEqual(got, want) {
		t.Errorf("walked %v, want %v", got, want)
	}
	if s.Ref() == "" {
		t.Error("Static must report a non-empty Ref so emitted runs always carry one")
	}
}

func TestWalkPropagatesCallbackError(t *testing.T) {
	s := source.Static([]source.File{{Path: "a", Data: nil}, {Path: "b", Data: nil}})
	sentinel := os.ErrInvalid
	err := s.Walk(func(f source.File) error { return sentinel })
	if err == nil {
		t.Fatal("Walk must surface a callback error, not swallow it")
	}
}

// A symlink to a directory arrives from WalkDir with IsDir() false, so a naive
// read fails outright — this killed a scan of a real repository. Not following
// symlinks is also the right posture: one in an untrusted repo can point
// anywhere on the machine.
func TestSymlinksAreSkippedNotRead(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x"}`), 0o644)
	os.MkdirAll(filepath.Join(dir, "real"), 0o755)
	os.WriteFile(filepath.Join(dir, "real", "inner.json"), []byte("{}"), 0o644)

	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "linkdir")); err != nil {
		t.Skip("symlinks unsupported here")
	}
	if err := os.Symlink("/etc/hosts", filepath.Join(dir, "escape.json")); err != nil {
		t.Skip("symlinks unsupported here")
	}

	s, err := source.Open(context.Background(), dir, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	got := walkPaths(t, s)
	want := []string{"package.json", "real/inner.json"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("walked %v, want %v — symlinks must be skipped", got, want)
	}
}

// Reading every file to discover that no extractor wants it dominates the
// runtime on real repositories: one Rust target/ directory held 56k files and
// turned a scan into a five-minute timeout. WalkIf must not read what nobody
// claimed, and build trees must not be descended at all.
func TestWalkIfReadsOnlyClaimedFilesAndSkipsBuildTrees(t *testing.T) {
	dir := t.TempDir()
	mk := func(rel string, size int) {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, make([]byte, size), 0o644)
	}
	mk("package.json", 10)
	mk("big.bin", 1<<20)
	for _, noisy := range []string{"target", "dist", ".venv", "__pycache__", "node_modules"} {
		mk(noisy+"/junk.json", 1<<20)
	}

	s, err := source.Open(context.Background(), dir, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	var read []string
	var bytesRead int
	err = s.WalkIf(
		func(p string) bool { return p == "package.json" },
		func(f source.File) error {
			read = append(read, f.Path)
			bytesRead += len(f.Data)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != 1 || read[0] != "package.json" {
		t.Errorf("read %v, want only package.json", read)
	}
	if bytesRead > 1024 {
		t.Errorf("read %d bytes; unclaimed files must never be opened", bytesRead)
	}

	// And the build trees must not even be walked.
	all := walkPaths(t, s)
	for _, p := range all {
		for _, noisy := range []string{"target/", "dist/", ".venv/", "__pycache__/", "node_modules/"} {
			if strings.HasPrefix(p, noisy) {
				t.Errorf("descended into build tree: %s", p)
			}
		}
	}
}

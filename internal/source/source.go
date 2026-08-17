// Package source turns a target — a local git directory or a remote URL — into
// a walkable tree of files, optionally as that tree stood at some point in the
// repository's history.
//
// Input is a git repo rather than any directory precisely so the closure can be
// recomputed at an arbitrary past commit. That is one of the three time axes the
// tool reasons about (see the plan's Time travel section).
package source

import (
	"context"
	"fmt"
	"os"
	"sort"
)

// File is one file in the tree, with a repo-relative slash-separated path.
type File struct {
	Path string
	Data []byte
}

// Source is a tree of files plus the provenance needed to reproduce the run.
type Source interface {
	// Walk visits every file, reading each one.
	Walk(func(File) error) error
	// WalkIf reads ONLY the files want() claims. Repositories routinely contain
	// tens of thousands of build artefacts; reading them all to discover that no
	// extractor wants any of them dominates the runtime.
	WalkIf(want func(path string) bool, fn func(File) error) error
	// Ref is the resolved commit SHA (or a sentinel for non-git sources).
	Ref() string
	// Repo identifies the origin for the run's root node.
	Repo() string
}

// Token is a forge credential used to clone repositories that are not public.
//
// It is a named type rather than a fifth bare string so that it cannot be passed
// in the wrong position, and it is threaded in from the caller rather than read
// from the environment here: knowing where credentials come from is the command
// layer's job, and a package that walks files should not go looking for one.
type Token string

// Open resolves a target. An existing path on disk is walked directly;
// anything else is treated as a remote URL and cloned.
//
// at is a git revision (tag, SHA or date). When set, the clone must carry full
// history — a shallow clone cannot reach past commits — so it changes how the
// remote is fetched, not just how it is read.
func Open(ctx context.Context, target, cacheDir, at string, tok Token) (Source, error) {
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		return openLocal(target, at)
	}
	if at != "" && target == "" {
		return nil, fmt.Errorf("--at requires a target")
	}
	return openRemote(ctx, target, cacheDir, at, tok)
}

// staticSource is an in-memory tree. Downstream packages (walk, effective,
// rollup) test against it so they need neither a temp directory nor a git repo.
type staticSource struct{ files []File }

// Static returns an in-memory Source over the given files.
func Static(files []File) Source {
	cp := append([]File(nil), files...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].Path < cp[j].Path })
	return &staticSource{files: cp}
}

func (s *staticSource) Walk(fn func(File) error) error {
	return s.WalkIf(func(string) bool { return true }, fn)
}

func (s *staticSource) WalkIf(want func(string) bool, fn func(File) error) error {
	for _, f := range s.files {
		if !want(f.Path) {
			continue
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

func (s *staticSource) Ref() string  { return "static" }
func (s *staticSource) Repo() string { return "static" }

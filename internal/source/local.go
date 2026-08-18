package source

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/project"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
)

// skipDirs are never descended into. node_modules and vendor hold INSTALLED
// artifacts; we reason about what a manifest declares and what a lockfile
// resolved to, not about whatever happens to be on this disk right now.
var skipDirs = map[string]bool{
	".git": true,
	// Installed or vendored third-party trees describe someone else's build.
	"node_modules": true, "vendor": true, "third_party": true,
	"site-packages": true, ".venv": true, "venv": true,
	// Build output. A Rust target/ alone can hold 50k+ files, which dwarfs
	// everything we actually care about.
	"target": true, "dist": true, "build": true, "out": true,
	".next": true, ".nuxt": true, ".gradle": true, ".terraform": true,
	// Tool caches.
	"__pycache__": true, ".pytest_cache": true, ".mypy_cache": true,
	".ruff_cache": true, ".tox": true, ".nox": true, ".cache": true,
}

type localSource struct {
	dir  string
	ref  string
	repo string
	// origin is what the project registry keys on: the absolute path, and the
	// remote if this tree has one.
	origin project.Origin
	// tree is non-nil when reading a historical commit rather than the worktree.
	tree *object.Tree
	// commitTime is the committer timestamp of the revision --at resolved to.
	commitTime time.Time
}

// CommitTime reports when the resolved commit was made.
//
// Callers use it to default --as-of, because resolving a 2023 source tree
// against today's registry silently mixes two different instants and produces an
// answer that never existed.
func (s *localSource) CommitTime() (time.Time, bool) {
	return s.commitTime, !s.commitTime.IsZero()
}

func openLocal(dir, at string) (Source, error) {
	repoName := filepath.Base(dir)
	abs, err := filepath.Abs(dir)
	if err == nil {
		repoName = filepath.Base(abs) // filepath.Base(".") is "." otherwise
	} else {
		abs = ""
	}
	s := &localSource{
		dir: dir, ref: "worktree", repo: repoName,
		origin: project.Origin{Kind: project.KindLocal, Path: abs},
	}

	repo, err := git.PlainOpen(dir)
	if err != nil {
		// Not a git repo. Still walkable; the run just carries no commit — and
		// no remote, which is why Origin falls back to the path.
		return s, nil
	}
	// The remote is read here rather than by the caller because this is the only
	// place holding an open repository, and it was already being opened.
	if rem, err := repo.Remote("origin"); err == nil {
		if urls := rem.Config().URLs; len(urls) > 0 {
			s.origin.Remote = urls[0]
		}
	}
	if head, err := repo.Head(); err == nil {
		s.ref = head.Hash().String()
	}
	if at == "" {
		return s, nil
	}
	tree, sha, when, err := treeAt(repo, at)
	if err != nil {
		return nil, err
	}
	s.tree, s.ref, s.commitTime = tree, sha, when
	return s, nil
}

// treeAt resolves a revision and returns its tree WITHOUT checking anything out,
// so a history query never disturbs the working directory.
func treeAt(repo *git.Repository, at string) (*object.Tree, string, time.Time, error) {
	h, err := repo.ResolveRevision(plumbing.Revision(at))
	if err != nil {
		// "reference not found" alone leaves the user guessing whether they
		// mistyped, whether the ref exists, or whether the clone is too shallow
		// to contain it. Express tags releases as "4.18.0", not "v4.18.0", and
		// the bare error made that a five-minute detour.
		return nil, "", time.Time{}, fmt.Errorf("--at %q: %w%s", at, err, nearbyRefs(repo, at))
	}
	commit, err := repo.CommitObject(*h)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return tree, h.String(), commit.Committer.When, nil
}

func (s *localSource) Ref() string  { return s.ref }
func (s *localSource) Repo() string { return s.repo }

func (s *localSource) Origin() project.Origin { return s.origin }

func (s *localSource) Walk(fn func(File) error) error {
	return s.WalkIf(func(string) bool { return true }, fn)
}

func (s *localSource) WalkIf(want func(string) bool, fn func(File) error) error {
	if s.tree != nil {
		return s.walkTree(want, fn)
	}
	return s.walkDisk(want, fn)
}

func (s *localSource) walkDisk(want func(string) bool, fn func(File) error) error {
	return filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != s.dir && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Only regular files. WalkDir does not follow symlinks, so a symlink to a
		// directory arrives here with IsDir() false and would fail to read. Not
		// following them is also the right posture: a symlink in an untrusted
		// repository can point anywhere on the machine.
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(s.dir, p)
		if err != nil {
			return err
		}
		slashed := filepath.ToSlash(rel)
		if !want(slashed) {
			return nil // never read a file nobody asked for
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return fn(File{Path: slashed, Data: b})
	})
}

func (s *localSource) walkTree(want func(string) bool, fn func(File) error) error {
	iter := s.tree.Files()
	defer iter.Close()
	return iter.ForEach(func(f *object.File) error {
		if skipped(f.Name) || !want(f.Name) {
			return nil
		}
		body, err := f.Contents()
		if err != nil {
			return err
		}
		return fn(File{Path: f.Name, Data: []byte(body)})
	})
}

func skipped(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if skipDirs[seg] {
			return true
		}
	}
	return false
}

// nearbyRefs suggests refs that resemble what was asked for, so a near-miss is
// self-correcting. Best effort: it appends nothing if it cannot enumerate.
func nearbyRefs(repo *git.Repository, at string) string {
	iter, err := repo.References()
	if err != nil {
		return ""
	}
	probe := strings.ToLower(strings.TrimPrefix(at, "v"))
	var hits []string
	_ = iter.ForEach(func(r *plumbing.Reference) error {
		if !r.Name().IsTag() && !r.Name().IsBranch() {
			return nil
		}
		short := r.Name().Short()
		if strings.Contains(strings.ToLower(short), probe) && len(hits) < 5 {
			hits = append(hits, short)
		}
		return nil
	})
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return "; did you mean " + strings.Join(hits, ", ") + "?"
}

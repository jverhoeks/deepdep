// Package history answers "when did this dependency change, and to what?".
//
// This is the repository time axis, distinct from the two the walker reasons
// about. Resolution time asks which versions existed; knowledge time asks which
// advisories were known; this asks when WE changed what we depend on.
//
// It reads both the manifest and the lockfile, because they move independently:
// a lockfile bump changes what is installed while the declared range stays put,
// and a diff of ranges alone would miss it entirely.
package history

import (
	"context"
	"sort"
	"time"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/source"
)

// watched are the files whose content decides what gets installed. Only commits
// that touch one of them can change the answer, so everything else is skipped —
// that is what keeps this cheap on a repository with thousands of commits.
//
// This list spans ecosystems deliberately: watching only npm files meant a
// Python or Rust repository reported no dependency history at all, which reads
// as "nothing ever changed" rather than "we did not look".
var watched = []string{
	"package.json", "package-lock.json", "npm-shrinkwrap.json",
	"pnpm-lock.yaml", "yarn.lock", "bun.lock",
	"pyproject.toml", "requirements.txt", "poetry.lock", "uv.lock",
	"Pipfile", "Pipfile.lock", "pdm.lock", "setup.py", "setup.cfg",
	"Cargo.toml", "Cargo.lock",
	"go.mod", "go.sum",
	"Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
	"pom.xml", "build.gradle", "build.gradle.kts",
}

// Commit is one point in the repository's dependency history.
type Commit struct {
	SHA     string
	When    time.Time
	Author  string
	Subject string
}

// Kind classifies what moved.
type Kind string

const (
	Added          Kind = "added"
	Removed        Kind = "removed"
	RangeChanged   Kind = "range-changed"   // the declared constraint moved
	VersionChanged Kind = "version-changed" // only the lockfile moved
)

// Change is one dependency movement, with the commit that caused it.
type Change struct {
	Name          string    `json:"name"`
	Kind          Kind      `json:"kind"`
	FromDeclared  string    `json:"from_declared,omitempty"`
	ToDeclared    string    `json:"to_declared,omitempty"`
	FromInstalled string    `json:"from_installed,omitempty"`
	ToInstalled   string    `json:"to_installed,omitempty"`
	Commit        string    `json:"commit"`
	When          time.Time `json:"when"`
	Author        string    `json:"author"`
	Subject       string    `json:"subject"`
}

// Candidates returns, oldest first, the commits where a watched file's content
// actually changed.
func Candidates(dir string) ([]Commit, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return nil, err
	}
	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	iter, err := repo.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var commits []*object.Commit
	if err := iter.ForEach(func(c *object.Commit) error {
		commits = append(commits, c)
		return nil
	}); err != nil {
		return nil, err
	}
	// go-git yields newest first, following parent links; reverse to move forward
	// through history.
	//
	// Order comes from the commit GRAPH, never from timestamps. Committer dates
	// are attacker- and script-controlled, frequently identical across a scripted
	// series, and can even run backwards after a rebase — sorting by them would
	// silently scramble the sequence and invert every reported change.
	for i, j := 0, len(commits)-1; i < j; i, j = i+1, j-1 {
		commits[i], commits[j] = commits[j], commits[i]
	}

	var (
		out  []Commit
		prev map[string]plumbing.Hash
	)
	for _, c := range commits {
		cur, err := watchedHashes(c)
		if err != nil {
			return nil, err
		}
		if !sameHashes(prev, cur) {
			out = append(out, Commit{
				SHA:     c.Hash.String(),
				When:    c.Committer.When,
				Author:  c.Author.Name,
				Subject: subject(c.Message),
			})
		}
		prev = cur
	}
	return out, nil
}

// watchedHashes reads only the blob hashes of the watched files — comparing
// those is far cheaper than materialising and parsing every commit's tree.
func watchedHashes(c *object.Commit) (map[string]plumbing.Hash, error) {
	tree, err := c.Tree()
	if err != nil {
		return nil, err
	}
	out := map[string]plumbing.Hash{}
	for _, p := range watched {
		e, err := tree.FindEntry(p)
		if err != nil {
			continue // absent at this commit
		}
		out[p] = e.Hash
	}
	return out, nil
}

func sameHashes(a, b map[string]plumbing.Hash) bool {
	if a == nil || len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func subject(msg string) string {
	for i := 0; i < len(msg); i++ {
		if msg[i] == '\n' {
			return msg[:i]
		}
	}
	return msg
}

// snapshot is what the repo declared and what it would install, at one commit.
type snapshot struct {
	declared  map[string]string // package -> raw range
	installed map[string]string // package -> exact version from the lockfile
}

// Changes walks the dependency history and reports every movement.
//
// Each candidate commit is read offline: the lockfile already records exact
// versions, so no registry is consulted and the whole history costs nothing but
// local git reads.
func Changes(ctx context.Context, dir, cacheDir string) ([]Change, error) {
	commits, err := Candidates(dir)
	if err != nil {
		return nil, err
	}

	var (
		out  []Change
		prev *snapshot
	)
	for _, c := range commits {
		cur, err := snapshotAt(ctx, dir, cacheDir, c.SHA)
		if err != nil {
			return nil, err
		}
		out = append(out, diff(prev, cur, c)...)
		prev = cur
	}
	return out, nil
}

func snapshotAt(ctx context.Context, dir, cacheDir, sha string) (*snapshot, error) {
	// dir is a directory already on disk — history walks a clone it was handed,
	// so there is nothing to authenticate against.
	src, err := source.Open(ctx, dir, cacheDir, sha, "")
	if err != nil {
		return nil, err
	}

	s := &snapshot{declared: map[string]string{}, installed: map[string]string{}}

	man := extract.NPMManifest{}
	if err := src.WalkIf(man.Match, func(f source.File) error {
		edges, _, err := man.Extract(ctx, f)
		if err != nil {
			return nil // a manifest that did not parse at that commit is not fatal here
		}
		for _, e := range edges {
			if name, ok := npmName(string(e.To)); ok {
				s.declared[name] = e.Spec
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	inst, err := effective.NPMLock{}.Resolve(ctx, src)
	if err != nil {
		return s, nil // an unparseable lockfile leaves installed empty, not fatal
	}
	for _, i := range inst {
		name, ver := instName(i)
		if name != "" {
			s.installed[name] = ver
		}
	}
	return s, nil
}

func diff(prev, cur *snapshot, c Commit) []Change {
	if prev == nil {
		// First observed state: everything declared is newly added.
		var out []Change
		for _, name := range sortedKeys(cur.declared) {
			out = append(out, Change{
				Name: name, Kind: Added,
				ToDeclared: cur.declared[name], ToInstalled: cur.installed[name],
				Commit: c.SHA, When: c.When, Author: c.Author, Subject: c.Subject,
			})
		}
		return out
	}

	seen := map[string]bool{}
	var out []Change

	for _, name := range sortedKeys(cur.declared) {
		seen[name] = true
		oldRange, had := prev.declared[name]
		newRange := cur.declared[name]
		oldVer, newVer := prev.installed[name], cur.installed[name]

		switch {
		case !had:
			out = append(out, mk(name, Added, "", newRange, "", newVer, c))
		case oldRange != newRange:
			out = append(out, mk(name, RangeChanged, oldRange, newRange, oldVer, newVer, c))
		case oldVer != newVer:
			// The declared range did not move; only the lockfile did. This is the
			// case a range-only diff misses.
			out = append(out, mk(name, VersionChanged, oldRange, newRange, oldVer, newVer, c))
		}
	}
	for _, name := range sortedKeys(prev.declared) {
		if !seen[name] {
			out = append(out, mk(name, Removed, prev.declared[name], "", prev.installed[name], "", c))
		}
	}
	return out
}

func mk(name string, k Kind, fromR, toR, fromV, toV string, c Commit) Change {
	return Change{
		Name: name, Kind: k,
		FromDeclared: fromR, ToDeclared: toR,
		FromInstalled: fromV, ToInstalled: toV,
		Commit: c.SHA, When: c.When, Author: c.Author, Subject: c.Subject,
	}
}

// npmName recovers a package name from a version-less npm PURL.
func npmName(purl string) (string, bool) {
	const prefix = "pkg:npm/"
	if len(purl) <= len(prefix) || purl[:len(prefix)] != prefix {
		return "", false
	}
	name := purl[len(prefix):]
	// %40 is the percent-encoded @ of a scope.
	if len(name) > 3 && name[:3] == "%40" {
		name = "@" + name[3:]
	}
	return name, true
}

func instName(i effective.Instance) (string, string) {
	name, _ := npmName(string(i.NodeID))
	// strip the trailing @version the PURL carries
	for k := len(name) - 1; k > 0; k-- {
		if name[k] == '@' {
			return name[:k], name[k+1:]
		}
	}
	return name, ""
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

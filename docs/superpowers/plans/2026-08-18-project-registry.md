# Project Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every scan a durable, human-nameable project so `deepdep risk 3` works, and give the store a way to prune itself without destroying irreplaceable observations.

**Architecture:** A new `internal/project` package canonicalises a git remote into an identity key. `source.Source` gains `Origin()` and stops discarding the absolute path and remote it already reads. Schema v5 adds `projects` and `project_paths`, plus a nullable `runs.project_num` that leaves `runs.target` and therefore org-scan resume semantics untouched. Two new commands — `projects` and `clean` — plus a shared ref resolver that lets `report`/`risk`/`audit` take a project number where they take a run id.

**Tech Stack:** Go 1.26.5, `modernc.org/sqlite` (pure Go, no cgo), `go-git/v6`. Standard library `testing`, no assertion library. No new module dependencies.

**Spec:** `docs/superpowers/specs/2026-08-18-projects-and-web-explorer-design.md`

## Global Constraints

- **Stages 1–3 only.** This plan stops before `finding_obs`, the `internal/report` extraction, and `serve`. Do not add them.
- **No new module dependencies.** `go.mod`'s require block does not grow. In particular do not reach for `github.com/mattn/go-isatty` — it is present only as an indirect dependency and promoting it to direct is a supply-chain change in a supply-chain tool.
- **`runs.target` keeps its current meaning.** Never write a canonical remote into it. `alreadyScanned` (`cmd/deepdep/org_store.go`) keys on it, and changing it makes a local scan silently suppress a remote scan during an org run.
- **The observation tables are never deleted from.** `advisories`, `advisory_affects`, `packument_obs`, `depsdev_obs`, `scorecard_obs`, `ref_obs`, `version_facts` are not run-scoped and are not regenerable — `scorecard_obs` holds 47,557 rows deps.dev will not serve again.
- **`schemaVersion` goes from 4 to 5.** Fresh databases get everything from `schema.sql`; existing ones get an `if v > 0 && v < 5` branch. This is the established pattern at `internal/store/store.go:105-163`.
- **Tests reach no network.** Tests needing a git repository shell out to `git` and `t.Skip("git not available")` when `exec.LookPath` fails, following `internal/source/cachehit_test.go`.
- **House comment style.** Comments state why a decision was made and what breaks otherwise, in prose. Match the density of the file being edited.
- **Run tests with** `go test ./...` from the repository root. There is no Makefile and no CI config.

---

### Task 1: `internal/project` — canonical identity

The registry's whole correctness rests on `git@github.com:o/r.git` and `https://github.com/o/r` naming the same thing, and on a URL carrying a token never reaching the database.

**Files:**
- Create: `internal/project/project.go`
- Test: `internal/project/project_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `project.Origin{Kind, Remote, Path string}` — Task 2 fills it, Task 3 stores it
  - `project.KindRemote = "remote"`, `project.KindLocal = "local"`
  - `project.Identity{Key, Kind, Name string}`
  - `project.Canonical(remote string) (key, name string, ok bool)` — Task 4's migration calls this directly
  - `project.Of(o Origin) (Identity, bool)` — Task 3 calls this

- [ ] **Step 1: Write the failing test**

Create `internal/project/project_test.go`:

```go
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/project/ -v`
Expected: FAIL — the package does not exist yet (`no required module provides package`).

- [ ] **Step 3: Write the implementation**

Create `internal/project/project.go`:

```go
// Package project turns what a scan knows about its origin — a remote URL and a
// directory on disk — into the durable identity of the thing being scanned.
//
// A run is an event: this tree, at this ref, at this instant. A project is what
// the runs are about, and it needs a different key. `internal/source` records
// only filepath.Base of the scanned directory, so two directories named
// data-platform are indistinguishable in the store and collide in the org
// scan's resume logic. Identity is the canonical remote, because a repository
// cloned to two directories is one repository.
package project

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	KindRemote = "remote"
	KindLocal  = "local"
)

// Origin is what a run is about, as distinct from the tree that was read.
//
// Either field may be empty and neither can be the sole identity: a remote scan
// has no local path, and a non-git directory has no remote.
type Origin struct {
	Kind   string // KindRemote, KindLocal, or "" when neither is known
	Remote string // raw remote URL, uncanonicalised; empty for a non-git tree
	Path   string // absolute path of the scanned directory; empty for a remote scan
}

// Identity is the registry row an Origin implies. Key is unique; Name is for
// display only and is never matched against.
type Identity struct {
	Key  string
	Kind string
	Name string
}

// scpLike matches git's SCP-ish remote syntax, which is not a URL and so cannot
// be handed to url.Parse: git@github.com:o/r.git. Anchored at the start with a
// character class excluding ':' and '/' so that ssh://git@host/o/r — which IS a
// URL and contains an '@' — falls through to the parser instead.
var scpLike = regexp.MustCompile(`^[A-Za-z0-9._-]+@([^:/]+):(.+)$`)

// Canonical reduces a remote URL to a stable key and a display name.
//
// ok is false for anything with no host, which is the same test that keeps the
// v5 migration away from pre-v5 local runs: their target is a bare basename.
func Canonical(remote string) (key, name string, ok bool) {
	s := strings.TrimSpace(remote)
	if s == "" {
		return "", "", false
	}

	var host, path string
	if m := scpLike.FindStringSubmatch(s); m != nil {
		host, path = m[1], m[2]
	} else {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", "", false
		}
		// Hostname() drops the port, and userinfo lives on u.User rather than
		// u.Host — which is what keeps a token out of the key, and out of the
		// database, when someone clones with a credential in the URL.
		host, path = u.Hostname(), u.Path
	}

	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if path == "" {
		return "", "", false
	}

	// The key is fully lowercased so github.com/O/R and github.com/o/r are one
	// project; the name keeps the original case because it is what gets printed.
	return strings.ToLower(host + "/" + path), path, true
}

// Of resolves an Origin to the project it belongs to.
//
// The remote wins when there is one. That is the "paths are locations" rule: two
// worktrees of one repository are one project, and the path is recorded beside
// it rather than instead of it.
func Of(o Origin) (Identity, bool) {
	if key, name, ok := Canonical(o.Remote); ok {
		return Identity{Key: key, Kind: KindRemote, Name: name}, true
	}
	if o.Path != "" {
		return Identity{Key: o.Path, Kind: KindLocal, Name: filepath.Base(o.Path)}, true
	}
	return Identity{}, false
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/project/ -v`
Expected: PASS, six tests.

- [ ] **Step 5: Commit**

```bash
git add internal/project/
git commit -m "feat(project): canonical identity for a scanned repository

A run is an event; a project is what the runs are about. Identity is the
canonical remote so that git@host:o/r and https://host/o/r are one
project, lowercased so case-typed variants do not split, with the port
and any userinfo dropped — the latter is what keeps a token out of the
registry when someone clones with a credential in the URL.

ok=false for anything without a host, which doubles as the filter that
keeps the migration away from local runs whose target is a basename."
```

---

### Task 2: `Source.Origin()` — stop discarding the path and the remote

`openLocal` computes `filepath.Abs(dir)` and throws it away, and holds an open `*git.Repository` without ever asking it for a remote.

**Files:**
- Modify: `internal/source/source.go` — add `Origin()` to the interface and to `staticSource`
- Modify: `internal/source/local.go:53-77` — `openLocal` fills the origin
- Modify: `internal/source/clone.go:104-115` — `openCloned` overrides it
- Test: `internal/source/origin_test.go`

**Interfaces:**
- Consumes: `project.Origin`, `project.KindLocal`, `project.KindRemote` from Task 1.
- Produces: `source.Source.Origin() project.Origin` — Task 3's scan call site reads it.

- [ ] **Step 1: Write the failing test**

Create `internal/source/origin_test.go`:

```go
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/source/ -run Origin -v`
Expected: FAIL to compile — `s.Origin undefined (type Source has no field or method Origin)`.

- [ ] **Step 3: Add `Origin()` to the interface and the static source**

In `internal/source/source.go`, add the import `"github.com/jverhoeks/deepdep/internal/project"` and extend the interface after `Repo()`:

```go
	// Repo identifies the origin for the run's root node.
	Repo() string
	// Origin identifies the durable thing the run is ABOUT, which is not the
	// same question as Repo(). Repo() names the root node; Origin() is what the
	// project registry keys on, and it needs the absolute path and the remote —
	// two facts openLocal computed and discarded, which is why two directories
	// named data-platform were one target in the store.
	Origin() project.Origin
```

and at the bottom, beside the other `staticSource` methods:

```go
// An in-memory tree is nobody's repository, so it is not a project either.
func (s *staticSource) Origin() project.Origin { return project.Origin{} }
```

- [ ] **Step 4: Fill the origin in `openLocal`**

In `internal/source/local.go`, add `"github.com/jverhoeks/deepdep/internal/project"` to the imports, add a field to `localSource`:

```go
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

func (s *localSource) Origin() project.Origin { return s.origin }
```

and rewrite the head of `openLocal` so the absolute path is kept rather than reduced to its basename:

```go
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
```

Note the shadowing: the original code reused `err` from `filepath.Abs` and then again from `git.PlainOpen`. Keep them distinct as written above.

- [ ] **Step 5: Override the origin in `openCloned`**

In `internal/source/clone.go`, extend the existing identity fix-up:

```go
	if ls, ok := s.(*localSource); ok {
		ls.repo = url
		// The path openLocal filled in is deepdep's cache directory — a hash of
		// this URL — not a checkout the user chose. Recording it as a project
		// location would point the registry at a directory nobody asked for.
		ls.origin = project.Origin{Kind: project.KindRemote, Remote: url}
	}
```

and add `"github.com/jverhoeks/deepdep/internal/project"` to that file's imports.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/source/ -v`
Expected: PASS, including the pre-existing `TestCachedCloneKeepsItsRemoteIdentity`.

- [ ] **Step 7: Run the whole suite**

Run: `go test ./...`
Expected: PASS. Any other implementation of `Source` outside this package would now fail to compile; there is none, but this is how you find out.

- [ ] **Step 8: Commit**

```bash
git add internal/source/
git commit -m "feat(source): report the origin, instead of discarding it

openLocal computed filepath.Abs and used it only to take a basename, and
held an open *git.Repository without ever asking for a remote. Both facts
are what a project registry needs, and losing them is why two directories
named data-platform are one runs.target — which alreadyScanned keys on,
so they already collided in org-scan resume logic.

openCloned overwrites the path: a cache clone lives in a directory named
after a hash of the URL, and offering that as a project location would
point users at a checkout they did not make."
```

---

### Task 3: Schema v5 and the project upsert

**Files:**
- Modify: `internal/store/schema.sql` — add `projects`, `project_paths`, `runs.project_num`
- Modify: `internal/store/store.go:36` — `schemaVersion = 5`
- Modify: `internal/store/store.go:105-163` — the `v > 0 && v < 5` branch
- Modify: `internal/store/store.go:188-283` — `WriteRun` takes options and upserts
- Create: `internal/store/project.go` — project reads and the upsert helper
- Test: `internal/store/project_test.go`

**Interfaces:**
- Consumes: `project.Origin`, `project.Identity`, `project.Of` from Task 1.
- Produces:
  - `store.WriteOption`, `store.WithOrigin(project.Origin) WriteOption`
  - `store.WriteRun(ctx, m, g, inst, res, opts ...WriteOption) (string, error)` — variadic, so the ten existing test call sites keep compiling
  - `store.Project{Num int64; Key, Kind, Name string; CreatedAt, LastScan time.Time; Runs int; Paths []string}`
  - `store.ProjectQuery{Num int64; KeyPrefix string; Limit int}`
  - `store.Projects(ctx, ProjectQuery) ([]Project, error)`
  - `store.RunsForProject(ctx, num int64) ([]Run, error)`
  - `store.UnclaimedRuns(ctx) ([]Run, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/store/project_test.go`:

```go
package store_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/project"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
)

// Scanning the same repository twice is two runs and ONE project. If it were two
// projects the registry would be no more useful than the run list it replaces.
func TestSecondScanOfARepoIsTheSameProject(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")
	o := project.Origin{Kind: project.KindLocal, Remote: "git@github.com:o/r.git", Path: "/src/r"}

	for i := 0; i < 2; i++ {
		if _, err := s.WriteRun(ctx, sampleMeta(), g, nil, res, store.WithOrigin(o)); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("got %d projects, want 1", len(ps))
	}
	if ps[0].Key != "github.com/o/r" {
		t.Errorf("Key = %q, want github.com/o/r", ps[0].Key)
	}
	if ps[0].Runs != 2 {
		t.Errorf("Runs = %d, want 2", ps[0].Runs)
	}
	if len(ps[0].Paths) != 1 || ps[0].Paths[0] != "/src/r" {
		t.Errorf("Paths = %v, want [/src/r] — recorded once, not once per run", ps[0].Paths)
	}
}

// "Paths are locations": one repository checked out twice is one project that
// knows about both directories.
func TestTwoCheckoutsOfOneRepoAreTwoLocations(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")

	for _, p := range []string{"/src/r", "/work/r"} {
		o := project.Origin{Kind: project.KindLocal, Remote: "https://github.com/o/r.git", Path: p}
		if _, err := s.WriteRun(ctx, sampleMeta(), g, nil, res, store.WithOrigin(o)); err != nil {
			t.Fatal(err)
		}
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("got %d projects, want 1", len(ps))
	}
	if len(ps[0].Paths) != 2 {
		t.Fatalf("Paths = %v, want both checkouts", ps[0].Paths)
	}
}

// A run written without an origin — the static source, or --no-db's absence of
// one — must not invent a project, and must stay reportable by run id.
func TestARunWithoutAnOriginIsUnclaimed(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	g := sampleGraph()

	runID, err := s.WriteRun(ctx, sampleMeta(), g, nil, rollup.Compute(g, nil, "root"))
	if err != nil {
		t.Fatal(err)
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 {
		t.Fatalf("got %d projects, want 0", len(ps))
	}
	un, err := s.UnclaimedRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(un) != 1 || un[0].RunID != runID {
		t.Fatalf("UnclaimedRuns = %+v, want the one run %s", un, runID)
	}
}

// Deleting a project takes its runs and their derived rows with it. This is the
// ON DELETE CASCADE chain the schema header promises; it works only because
// foreign_keys(1) rides in the DSN, applying to every pooled connection.
func TestDeletingAProjectCascadesToItsDerivedRows(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")
	o := project.Origin{Kind: project.KindRemote, Remote: "https://github.com/o/r.git"}

	if _, err := s.WriteRun(ctx, sampleMeta(), g, nil, res, store.WithOrigin(o)); err != nil {
		t.Fatal(err)
	}
	// A second, unclaimed run that must SURVIVE the delete.
	keep, err := s.WriteRun(ctx, sampleMeta(), g, nil, res)
	if err != nil {
		t.Fatal(err)
	}

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProjects(ctx, []int64{ps[0].Num}); err != nil {
		t.Fatal(err)
	}

	runs, err := s.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].RunID != keep {
		t.Fatalf("runs = %+v, want only the unclaimed %s", runs, keep)
	}
	for _, table := range []string{"nodes", "edges", "version_rollup", "package_rollup"} {
		n, err := s.CountRowsForTest(ctx, table)
		if err != nil {
			t.Fatal(err)
		}
		want, err := s.CountRowsForRunForTest(ctx, table, keep)
		if err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("%s: %d rows total but %d for the surviving run — the cascade left orphans", table, n, want)
		}
	}
}
```

`DeleteProjects` arrives in this task; `CountRowsForTest` and `CountRowsForRunForTest` are small exported test helpers added in Step 4.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/store/ -run Project -v`
Expected: FAIL to compile — `undefined: store.WithOrigin`.

- [ ] **Step 3: Extend the schema**

In `internal/store/schema.sql`, add `project_num` to the `runs` table definition and the two new tables immediately after it:

```sql
CREATE TABLE runs (
  run_id       TEXT PRIMARY KEY,
  target       TEXT NOT NULL,
  ref          TEXT NOT NULL,
  mode         TEXT NOT NULL CHECK (mode IN ('will','can')),
  as_of        TEXT NOT NULL,   -- resolution time
  known_at     TEXT NOT NULL,   -- knowledge time; independent of as_of
  tool_version TEXT NOT NULL,
  bounds_json  TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  -- The project this run is about. NULL is legitimate and permanent for runs
  -- written before v5, whose local paths were never recorded and cannot be
  -- reconstructed; they stay reportable by run id.
  --
  -- target is deliberately NOT redefined to the canonical remote. alreadyScanned
  -- keys on it, so a local scan of a repository would then suppress the remote
  -- scan of that same repository mid-org-run, and the summary would call a
  -- repository scanned when what was read was somebody's working copy.
  project_num  INTEGER REFERENCES projects(num) ON DELETE CASCADE
);

-- A project is the durable thing runs are about. Identity is the canonical
-- remote; a directory with no remote falls back to its absolute path.
--
-- num is AUTOINCREMENT rather than a bare INTEGER PRIMARY KEY so a deleted
-- project's number is never reissued to a different project later. `deepdep
-- report 3` has to keep meaning one thing.
CREATE TABLE projects (
  num        INTEGER PRIMARY KEY AUTOINCREMENT,
  key        TEXT NOT NULL UNIQUE,
  kind       TEXT NOT NULL CHECK (kind IN ('remote','local')),
  name       TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Where a project has been seen on disk. Many rows per project: one repository
-- cloned to two directories is one project with two locations.
CREATE TABLE project_paths (
  num        INTEGER NOT NULL REFERENCES projects(num) ON DELETE CASCADE,
  path       TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (num, path)
);
```

SQLite does not require `projects` to be declared before `runs` references it, because foreign keys are resolved at statement time.

- [ ] **Step 4: Add the project reads and the upsert**

Bump `schemaVersion` to `5` at `internal/store/store.go:36`.

Create `internal/store/project.go`:

```go
package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/project"
)

// Project is a registry row plus the two counts that make the list useful.
//
// It deliberately carries no risk grade. A grade is a function of known_at and
// is not materialised anywhere; printing one per row would mean a full report
// per project, and caching one would un-bitemporalise the design the same way a
// stored advisory count would.
type Project struct {
	Num       int64
	Key       string
	Kind      string
	Name      string
	CreatedAt time.Time
	Runs      int
	LastScan  time.Time
	Paths     []string
}

// ProjectQuery filters the registry. The zero value asks for everything.
type ProjectQuery struct {
	Num       int64  // 0 = any
	KeyPrefix string // --org: matched as a prefix of key
	Limit     int    // 0 = no limit
}

// upsertProject records the identity and the location, and returns the number to
// stamp on the run.
//
// It takes a *sql.Tx rather than opening its own, so a project cannot end up in
// the registry without the run that created it — which would show as a project
// with zero runs and no way to tell whether the scan failed or the write did.
func upsertProject(ctx context.Context, tx *sql.Tx, id project.Identity, path, now string) (int64, error) {
	// DO UPDATE rather than DO NOTHING so a renamed repository's display name
	// follows the rename. The key is what identity rests on; the name is only
	// ever printed.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO projects (key,kind,name,created_at) VALUES (?,?,?,?)
		 ON CONFLICT(key) DO UPDATE SET name=excluded.name`,
		id.Key, id.Kind, id.Name, now); err != nil {
		return 0, err
	}
	var num int64
	if err := tx.QueryRowContext(ctx,
		`SELECT num FROM projects WHERE key=?`, id.Key).Scan(&num); err != nil {
		return 0, err
	}
	if path != "" {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO project_paths (num,path,first_seen,last_seen) VALUES (?,?,?,?)
			 ON CONFLICT(num,path) DO UPDATE SET last_seen=excluded.last_seen`,
			num, path, now, now); err != nil {
			return 0, err
		}
	}
	return num, nil
}

// Projects lists the registry, most recently scanned first.
//
// SQLite sorts NULLs last under DESC, which puts never-scanned projects — only
// reachable by hand-editing the database — at the bottom rather than the top.
func (s *Store) Projects(ctx context.Context, q ProjectQuery) ([]Project, error) {
	sb := strings.Builder{}
	sb.WriteString(`
		SELECT p.num, p.key, p.kind, p.name, p.created_at,
		       (SELECT count(*)          FROM runs r  WHERE r.project_num = p.num),
		       (SELECT max(r.created_at) FROM runs r  WHERE r.project_num = p.num),
		       (SELECT group_concat(pp.path, char(10))
		          FROM project_paths pp WHERE pp.num = p.num)
		  FROM projects p WHERE 1=1`)
	var args []any
	if q.Num != 0 {
		sb.WriteString(` AND p.num = ?`)
		args = append(args, q.Num)
	}
	if q.KeyPrefix != "" {
		// LIKE with an escaped prefix: a key can legitimately contain '_', which
		// LIKE treats as a wildcard, so --org foo_bar must not match fooXbar.
		sb.WriteString(` AND p.key LIKE ? ESCAPE '\'`)
		args = append(args, likePrefix(q.KeyPrefix))
	}
	sb.WriteString(` ORDER BY 7 DESC, p.num ASC`)
	if q.Limit > 0 {
		sb.WriteString(` LIMIT ?`)
		args = append(args, q.Limit)
	}

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Project
	for rows.Next() {
		var p Project
		var created string
		var last, paths sql.NullString
		if err := rows.Scan(&p.Num, &p.Key, &p.Kind, &p.Name, &created, &p.Runs, &last, &paths); err != nil {
			return nil, err
		}
		p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if last.Valid {
			p.LastScan, _ = time.Parse(time.RFC3339Nano, last.String)
		}
		if paths.Valid && paths.String != "" {
			p.Paths = strings.Split(paths.String, "\n")
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// likePrefix escapes the two LIKE metacharacters so a prefix filter matches
// literally.
func likePrefix(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s) + "%"
}

// RunsForProject returns a project's runs, newest first.
func (s *Store) RunsForProject(ctx context.Context, num int64) ([]Run, error) {
	return s.queryRuns(ctx, `WHERE project_num = ?`, num)
}

// UnclaimedRuns returns runs belonging to no project.
//
// Every run written before v5 against a local directory is permanently here: the
// target was a bare basename and the path was never recorded, so there is
// nothing to adopt them by. They stay reachable by run id, and the list says so
// rather than pretending the store is smaller than it is.
func (s *Store) UnclaimedRuns(ctx context.Context) ([]Run, error) {
	return s.queryRuns(ctx, `WHERE project_num IS NULL`)
}

// DeleteProjects removes projects and, by cascade, their runs and every derived
// row beneath them. Unclaimed runs are untouched.
func (s *Store) DeleteProjects(ctx context.Context, nums []int64) error {
	if len(nums) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, n := range nums {
		if _, err := tx.ExecContext(ctx, `DELETE FROM projects WHERE num = ?`, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CountRowsForTest and CountRowsForRunForTest exist so cascade behaviour can be
// asserted without exporting the *sql.DB. A cascade that quietly stopped
// cascading would leave orphaned rows that no query ever selects, so the only
// way to see it is to count.
func (s *Store) CountRowsForTest(ctx context.Context, table string) (int, error) {
	return s.count(ctx, `SELECT count(*) FROM `+safeTable(table))
}

func (s *Store) CountRowsForRunForTest(ctx context.Context, table, runID string) (int, error) {
	return s.count(ctx, `SELECT count(*) FROM `+safeTable(table)+` WHERE run_id = ?`, runID)
}

func (s *Store) count(ctx context.Context, q string, args ...any) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// safeTable allows only the table names these helpers are meant for. A table
// name cannot be a bound parameter, so the alternative is string interpolation
// with no guard at all.
func safeTable(t string) string {
	switch t {
	case "nodes", "edges", "instances", "package_rollup", "version_rollup",
		"runs", "projects", "project_paths",
		"advisories", "advisory_affects", "packument_obs", "depsdev_obs",
		"scorecard_obs", "ref_obs", "version_facts":
		return t
	}
	panic("store: unknown table " + t)
}
```

Refactor `Runs` in `internal/store/store.go:434` to share its row-scanning with `queryRuns`, so `RunsForProject` and `UnclaimedRuns` cannot drift from it:

```go
func (s *Store) Runs(ctx context.Context, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.queryRuns(ctx, `ORDER BY created_at DESC, rowid DESC LIMIT ?`, limit)
}

// queryRuns is the single place run rows are scanned. Three callers select
// different subsets and they must not disagree about what a Run is.
func (s *Store) queryRuns(ctx context.Context, clause string, args ...any) ([]Run, error) {
	q := `SELECT run_id,target,ref,mode,as_of,known_at,tool_version,created_at FROM runs ` + clause
	if !strings.Contains(clause, "ORDER BY") {
		q += ` ORDER BY created_at DESC, rowid DESC`
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Run
	for rows.Next() {
		var r Run
		var asOf, knownAt, created string
		if err := rows.Scan(&r.RunID, &r.Target, &r.Ref, &r.Mode, &asOf, &knownAt, &r.ToolVersion, &created); err != nil {
			return nil, err
		}
		r.AsOf, _ = time.Parse(time.RFC3339Nano, asOf)
		r.KnownAt, _ = time.Parse(time.RFC3339Nano, knownAt)
		r.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, r)
	}
	return out, rows.Err()
}
```

- [ ] **Step 5: Make `WriteRun` accept and record an origin**

In `internal/store/store.go`, add above `WriteRun`:

```go
// WriteOption adjusts what WriteRun records beyond the graph itself.
//
// Variadic rather than a sixth parameter because ten existing call sites pass no
// origin and should not have to say so.
type WriteOption func(*writeOpts)

type writeOpts struct{ origin project.Origin }

// WithOrigin links the run to a project, creating it if this is the first time
// that repository has been seen.
func WithOrigin(o project.Origin) WriteOption {
	return func(w *writeOpts) { w.origin = o }
}
```

change the signature and add the upsert before the `runs` insert:

```go
func (s *Store) WriteRun(ctx context.Context, m emit.Meta, g *graph.Graph,
	inst []effective.Instance, res rollup.Result, opts ...WriteOption) (string, error) {

	var w writeOpts
	for _, o := range opts {
		o(&w)
	}

	runID := newRunID(m, g)
	bounds, _ := json.Marshal(m.Bounds)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339Nano)

	// NULL when the caller supplied no origin, or supplied one with neither a
	// remote nor a path — the in-memory source. Such a run is unclaimed and
	// still perfectly reportable by run id.
	var projectNum any
	if id, ok := project.Of(w.origin); ok {
		n, err := upsertProject(ctx, tx, id, w.origin.Path, now)
		if err != nil {
			return "", err
		}
		projectNum = n
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO runs (run_id,target,ref,mode,as_of,known_at,tool_version,bounds_json,created_at,project_num)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		runID, m.Repo, m.Ref, defaultMode(m.Mode), rfc(m.AsOf), rfc(m.KnownAt), m.ToolVersion, string(bounds), now, projectNum,
	); err != nil {
		return "", err
	}
```

Add `"github.com/jverhoeks/deepdep/internal/project"` to that file's imports. The rest of `WriteRun` is unchanged.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/store/ -v`
Expected: PASS, including all pre-existing store tests unchanged.

- [ ] **Step 7: Pass the origin from `scan`**

In `cmd/deepdep/main.go:565`:

```go
		if _, err := db.WriteRun(persistCtx, m, g, inst, res, store.WithOrigin(src.Origin())); err != nil {
```

Check the local variable name for the `source.Source` at `cmd/deepdep/main.go:429` — it is `src` — and use whatever is actually there.

- [ ] **Step 8: Verify end to end against a real scan**

```bash
go build -o /tmp/deepdep ./cmd/deepdep
/tmp/deepdep scan . --db /tmp/t.db --offline
sqlite3 /tmp/t.db "SELECT num,key,kind,name FROM projects; SELECT path FROM project_paths; SELECT run_id,target,project_num FROM runs;"
```

Expected: one project keyed on this repository's canonical remote, one path row holding this checkout's absolute path, and a run whose `target` is still `2026-08-13-deepdependency` with a non-NULL `project_num`.

- [ ] **Step 9: Commit**

```bash
git add internal/store/ cmd/deepdep/main.go
git commit -m "feat(store): projects as a layer over runs, schema v5

A run is an event and there are 211 of them; what was missing is the
durable thing they are about. projects is keyed on the canonical remote
with project_paths recording where it has been seen, so one repository
checked out twice is one project with two locations.

runs.target keeps its meaning and gains a nullable project_num beside
it. Redefining target to the remote would have been the tidier schema
and would make a local scan suppress the remote scan of the same
repository mid-org-run, since alreadyScanned keys on it.

The upsert runs inside WriteRun's transaction: a project must not be able
to exist without the run that created it. WithOrigin is variadic so the
ten call sites that have no origin do not have to say so."
```

---

### Task 4: Adopt the 208 existing remote runs

**Files:**
- Modify: `internal/store/store.go:105-163` — the `v > 0 && v < 5` migration branch
- Create: `internal/store/testdata/schema_v4.sql`
- Test: `internal/store/migrate_test.go`

**Interfaces:**
- Consumes: `project.Canonical` from Task 1; the v5 tables from Task 3.
- Produces: nothing new. Migration is a side effect of `store.Open`.

- [ ] **Step 1: Create the v4 fixture**

Take the previous revision of `schema.sql` — the one before Task 3 touched it — addressed by that file's own history rather than by `HEAD~1`, which depends on how many other commits happen to sit in between:

```bash
mkdir -p internal/store/testdata
git show "$(git log --format=%H -1 --skip=1 -- internal/store/schema.sql):internal/store/schema.sql" \
  > internal/store/testdata/schema_v4.sql
```

Then gate on the content, not on the revision arithmetic — this is the check that makes the step safe:

```bash
grep -c "CREATE TABLE projects" internal/store/testdata/schema_v4.sql   # MUST print 0
grep -c "CREATE TABLE runs"     internal/store/testdata/schema_v4.sql   # MUST print 1
```

If the first prints anything but `0`, the wrong revision was extracted and the migration test would be asserting against a v5 schema — which would pass while testing nothing. Stop and find the right one with `git log --oneline -- internal/store/schema.sql`.

- [ ] **Step 2: Write the failing test**

Create `internal/store/migrate_test.go`:

```go
package store_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/jverhoeks/deepdep/internal/store"
)

// v4db builds a database exactly as v4 left it, with the given run targets, and
// returns its path. Hand-rolled rather than produced by an older binary because
// the migration has to be testable from source alone.
func v4db(t *testing.T, targets ...string) string {
	t.Helper()
	schema, err := os.ReadFile(filepath.Join("testdata", "schema_v4.sql"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v4.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatal(err)
	}
	for i, target := range targets {
		if _, err := db.Exec(
			`INSERT INTO runs (run_id,target,ref,mode,as_of,known_at,tool_version,bounds_json,created_at)
			 VALUES (?,?,?,?,?,?,?,?,?)`,
			[]byte{byte('a' + i)}, target, "ref", "will",
			"2026-08-01T00:00:00Z", "2026-08-01T00:00:00Z", "0.1.0", "{}",
			"2026-08-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("PRAGMA user_version = 4"); err != nil {
		t.Fatal(err)
	}
	return path
}

// The store this change was written for holds 208 remote runs whose target IS
// the clone URL, and 3 local runs whose path was never recorded. The first group
// is adoptable and the second is not, and the migration has to get the split
// exactly right rather than merely not erroring.
func TestMigrationAdoptsRemoteRunsAndLeavesLocalOnesUnclaimed(t *testing.T) {
	path := v4db(t,
		"https://github.com/o/one.git",
		"https://github.com/o/one.git", // same repo, second run
		"git@github.com:o/two.git",
		"data-platform", // a local scan: basename only, unadoptable
		"sqlengine",
	)

	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	ps, err := s.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("got %d projects, want 2 (one per distinct remote)", len(ps))
	}
	byKey := map[string]store.Project{}
	for _, p := range ps {
		byKey[p.Key] = p
	}
	if got := byKey["github.com/o/one"].Runs; got != 2 {
		t.Errorf("github.com/o/one has %d runs, want 2", got)
	}
	if got := byKey["github.com/o/two"].Runs; got != 1 {
		t.Errorf("github.com/o/two has %d runs, want 1", got)
	}
	for _, p := range ps {
		if p.Kind != "remote" {
			t.Errorf("%s kind = %q, want remote", p.Key, p.Kind)
		}
		if len(p.Paths) != 0 {
			t.Errorf("%s paths = %v, want none — no path is recoverable from a clone URL", p.Key, p.Paths)
		}
	}

	un, err := s.UnclaimedRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(un) != 2 {
		t.Fatalf("got %d unclaimed runs, want 2 (data-platform, sqlengine)", len(un))
	}
}

// Opening twice must not double-adopt. Migration is gated on user_version, but
// the adoption is INSERT-shaped and a regression here would silently duplicate
// every project on the second open.
func TestMigrationIsIdempotent(t *testing.T) {
	path := v4db(t, "https://github.com/o/one.git")
	for i := 0; i < 2; i++ {
		s, err := store.Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i+1, err)
		}
		ps, err := s.Projects(context.Background(), store.ProjectQuery{})
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
		if len(ps) != 1 {
			t.Fatalf("open %d: got %d projects, want 1", i+1, len(ps))
		}
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/store/ -run Migration -v`
Expected: FAIL — `no such table: projects`, because the v5 branch does not exist yet.

- [ ] **Step 4: Write the migration branch**

In `internal/store/store.go`, add before the final `PRAGMA user_version` exec:

```go
	if v > 0 && v < 5 {
		if err := s.migrateProjects(); err != nil {
			return err
		}
	}
```

and add to `internal/store/project.go`:

```go
// migrateProjects creates the v5 registry and adopts the runs that can be
// adopted.
//
// A run whose target is a clone URL carries its own identity, so 208 of the 211
// runs in the store this was written for become projects here. A run whose
// target is a bare basename does not: openLocal recorded filepath.Base and
// discarded the path, so there is nothing to adopt it by. Those stay unclaimed
// permanently. Synthesising a path from the basename would produce a registry
// pointing at directories nobody chose, which is worse than an honest gap.
func (s *Store) migrateProjects() error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS projects (
		   num        INTEGER PRIMARY KEY AUTOINCREMENT,
		   key        TEXT NOT NULL UNIQUE,
		   kind       TEXT NOT NULL CHECK (kind IN ('remote','local')),
		   name       TEXT NOT NULL,
		   created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS project_paths (
		   num        INTEGER NOT NULL REFERENCES projects(num) ON DELETE CASCADE,
		   path       TEXT NOT NULL,
		   first_seen TEXT NOT NULL,
		   last_seen  TEXT NOT NULL,
		   PRIMARY KEY (num, path))`,
		// SQLite permits ADD COLUMN with a REFERENCES clause only when the
		// default is NULL, which is what an omitted default gives — and NULL is
		// the right default here anyway.
		`ALTER TABLE runs ADD COLUMN project_num INTEGER REFERENCES projects(num) ON DELETE CASCADE`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}

	rows, err := s.db.Query(`SELECT DISTINCT target FROM runs`)
	if err != nil {
		return err
	}
	var targets []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, target := range targets {
		// Canonical rejects anything without a host, which is exactly the local
		// basenames. No SQL LIKE heuristic is needed or wanted.
		key, name, ok := project.Canonical(target)
		if !ok {
			continue
		}
		num, err := upsertProject(context.Background(), tx,
			project.Identity{Key: key, Kind: project.KindRemote, Name: name}, "", now)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE runs SET project_num = ? WHERE target = ?`, num, target); err != nil {
			return err
		}
	}
	return tx.Commit()
}
```

Add `"context"` and `"time"` to `internal/store/project.go`'s imports if not already present.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/store/ -v`
Expected: PASS.

- [ ] **Step 6: Migrate the real database, on a copy**

```bash
cp ~/.local/share/deepdep/deepdep.db /tmp/real.db
go build -o /tmp/deepdep ./cmd/deepdep
/tmp/deepdep projects --db /tmp/real.db 2>/dev/null || sqlite3 /tmp/real.db "PRAGMA user_version;"
sqlite3 /tmp/real.db "SELECT count(*) FROM projects;"
sqlite3 /tmp/real.db "SELECT count(*) FROM runs WHERE project_num IS NULL;"
```

`projects` does not exist as a command until Task 5, so trigger the migration by any command that opens the store — `/tmp/deepdep report --db /tmp/real.db` will do. Expected: `user_version` 5, **208** projects, **3** unclaimed runs. If the numbers differ, stop and find out why before continuing; those are the numbers the spec commits to.

Work on the copy. Do not migrate `~/.local/share/deepdep/deepdep.db` until the whole plan is reviewed.

- [ ] **Step 7: Commit**

```bash
git add internal/store/
git commit -m "feat(store): adopt the runs that carry their own identity

208 of 211 stored runs have a clone URL for a target, so they can become
projects with no new information. The other 3 are local scans whose
target is a bare basename: openLocal discarded the path, so nothing can
adopt them and they stay unclaimed permanently.

The filter is project.Canonical returning ok=false for anything without
a host, rather than a SQL LIKE heuristic that would have to guess at the
same distinction with less information.

Verified on a copy of the 849MB store: 208 adopted, 3 unclaimed."
```

---

### Task 5: `deepdep projects` and ref resolution

**Files:**
- Create: `cmd/deepdep/ref.go`
- Create: `cmd/deepdep/projects.go`
- Modify: `cmd/deepdep/main.go:44-77` — the `usage` string
- Modify: `cmd/deepdep/main.go:86-105` — the `run` dispatch
- Modify: `cmd/deepdep/main.go:223-225` (`auditCmd`), `cmd/deepdep/risk.go:70-72`, `cmd/deepdep/report.go` — resolve the positional argument
- Test: `cmd/deepdep/ref_test.go`, `cmd/deepdep/projects_test.go`

**Interfaces:**
- Consumes: `store.Projects`, `store.ProjectQuery`, `store.RunsForProject`, `store.UnclaimedRuns` from Task 3.
- Produces:
  - `resolveRef(ctx context.Context, db *store.Store, ref string) (string, error)` — returns a run id, or `""` for an empty ref meaning "newest". Task 6 does not use it; `audit`/`risk`/`report` do.
  - `projectsCmd(args []string) ([]byte, error)`

- [ ] **Step 1: Write the failing test for resolution**

Create `cmd/deepdep/ref_test.go`:

```go
package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/project"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
)

// seed builds a store with one run per remote and returns it with the run ids in
// the order the remotes were given.
func seed(t *testing.T, remotes ...string) (*store.Store, []string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	g := graph.New()
	g.Add(graph.Node{ID: "root", Completeness: graph.Resolved})
	ts := time.Unix(1765000000, 0).UTC()
	m := emit.Meta{AsOf: ts, KnownAt: ts, Ref: "abc", Repo: "fx", Mode: "will", ToolVersion: "0.1.0"}
	res := rollup.Compute(g, nil, "root")

	var ids []string
	for _, r := range remotes {
		id, err := s.WriteRun(context.Background(), m, g, []effective.Instance(nil), res,
			store.WithOrigin(project.Origin{Kind: project.KindRemote, Remote: r}))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return s, ids
}

// A run id must keep working: every existing `deepdep report <run-id>`
// invocation goes through this path.
func TestResolveRefAcceptsARunID(t *testing.T) {
	s, ids := seed(t, "https://github.com/o/one.git")
	got, err := resolveRef(context.Background(), s, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if got != ids[0] {
		t.Fatalf("got %q, want %q", got, ids[0])
	}
}

// The point of the whole change: `deepdep risk 2`.
func TestResolveRefAcceptsAProjectNumber(t *testing.T) {
	s, ids := seed(t, "https://github.com/o/one.git", "https://github.com/o/two.git")
	ps, err := s.Projects(context.Background(), store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		got, err := resolveRef(context.Background(), s, strconv.FormatInt(p.Num, 10))
		if err != nil {
			t.Fatalf("%d: %v", p.Num, err)
		}
		if got != ids[0] && got != ids[1] {
			t.Fatalf("project %d resolved to %q, which is not one of the seeded runs", p.Num, got)
		}
	}
}

// A name, and a prefix of one, both resolve — that is what makes this friendlier
// than a 16-hex string.
func TestResolveRefAcceptsANameAndAUniquePrefix(t *testing.T) {
	s, _ := seed(t, "https://github.com/o/alpha.git", "https://github.com/o/beta.git")
	for _, ref := range []string{"o/alpha", "alpha", "github.com/o/alpha"} {
		if _, err := resolveRef(context.Background(), s, ref); err != nil {
			t.Errorf("resolveRef(%q): %v", ref, err)
		}
	}
}

// Guessing which of two repositories to report on is the exact failure this
// change exists to remove, so ambiguity must be an error that names both.
func TestResolveRefRefusesToGuessBetweenCandidates(t *testing.T) {
	s, _ := seed(t, "https://github.com/o/alpha-one.git", "https://github.com/o/alpha-two.git")
	_, err := resolveRef(context.Background(), s, "alpha")
	if err == nil {
		t.Fatal("resolved an ambiguous ref instead of erroring")
	}
	for _, want := range []string{"alpha-one", "alpha-two"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name candidate %q", err, want)
		}
	}
}

// An empty ref keeps meaning "the newest run", which is what `deepdep risk` with
// no argument has always done.
func TestResolveRefEmptyMeansNewest(t *testing.T) {
	s, _ := seed(t, "https://github.com/o/one.git")
	got, err := resolveRef(context.Background(), s, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("got %q, want the empty string so AuditTargets picks the newest", got)
	}
}

// A number that is not a project is an error naming what was looked for, not a
// silent fallthrough to a name search that would match nothing either.
func TestResolveRefRejectsAnUnknownNumber(t *testing.T) {
	s, _ := seed(t, "https://github.com/o/one.git")
	if _, err := resolveRef(context.Background(), s, "999"); err == nil {
		t.Fatal("resolved project 999")
	}
}
```

The imports for this file are `context`, `path/filepath`, `strconv`, `strings`, `testing`, `time`, plus `internal/effective`, `internal/emit`, `internal/graph`, `internal/project`, `internal/rollup` and `internal/store`.

`latestRunOf`'s "project has no stored runs" branch is asserted in Task 6, where `store.DeleteRuns` exists to create the condition. Reaching for it here would couple the two tasks.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/deepdep/ -run ResolveRef -v`
Expected: FAIL to compile — `undefined: resolveRef`.

- [ ] **Step 3: Write the resolver**

Create `cmd/deepdep/ref.go`:

```go
package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jverhoeks/deepdep/internal/store"
)

// runID16 matches the shape newRunID produces: sha256 truncated to 16 hex chars.
var runID16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

// resolveRef turns whatever the user typed into a run id.
//
// The order is deliberate and the first match wins: run id, project number,
// exact project name, then a unique substring of a name or a recorded path. An
// empty ref stays empty, because every reporting command already reads that as
// "the newest run".
//
// Ambiguity is an error listing the candidates. Guessing which of two
// repositories to report on is precisely the failure the project registry exists
// to remove, and a confident wrong report is worse than a question.
func resolveRef(ctx context.Context, db *store.Store, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil
	}

	if runID16.MatchString(ref) {
		runs, err := db.Runs(ctx, 100000)
		if err != nil {
			return "", err
		}
		for _, r := range runs {
			if r.RunID == ref {
				return ref, nil
			}
		}
		// Fall through: a 16-hex string is also a legal project name.
	}

	if n, err := strconv.ParseInt(ref, 10, 64); err == nil {
		ps, err := db.Projects(ctx, store.ProjectQuery{Num: n})
		if err != nil {
			return "", err
		}
		if len(ps) == 0 {
			return "", fmt.Errorf("no project %d — `deepdep projects` lists them", n)
		}
		return latestRunOf(ctx, db, ps[0])
	}

	all, err := db.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		return "", err
	}

	for _, p := range all {
		if p.Name == ref || p.Key == ref {
			return latestRunOf(ctx, db, p)
		}
	}

	needle := strings.ToLower(ref)
	var hits []store.Project
	for _, p := range all {
		if strings.Contains(strings.ToLower(p.Key), needle) ||
			strings.Contains(strings.ToLower(p.Name), needle) {
			hits = append(hits, p)
			continue
		}
		for _, path := range p.Paths {
			if strings.Contains(strings.ToLower(path), needle) {
				hits = append(hits, p)
				break
			}
		}
	}

	switch len(hits) {
	case 0:
		return "", fmt.Errorf("no run or project matching %q — `deepdep projects` lists them", ref)
	case 1:
		return latestRunOf(ctx, db, hits[0])
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "%q matches %d projects:\n", ref, len(hits))
		for _, p := range hits {
			fmt.Fprintf(&b, "  %-4d %s\n", p.Num, p.Key)
		}
		b.WriteString("be more specific, or use the number")
		return "", fmt.Errorf("%s", b.String())
	}
}

// latestRunOf is the project -> newest run step.
//
// An empty run list is an error rather than a fallthrough to the newest run in
// the store: reporting on some other repository because this one has no runs
// would be the org-scan bug that latestRunFor was written to fix, back again.
func latestRunOf(ctx context.Context, db *store.Store, p store.Project) (string, error) {
	runs, err := db.RunsForProject(ctx, p.Num)
	if err != nil {
		return "", err
	}
	if len(runs) == 0 {
		return "", fmt.Errorf("project %d (%s) has no stored runs — `deepdep scan` it first", p.Num, p.Key)
	}
	return runs[0].RunID, nil // RunsForProject is newest-first
}
```

- [ ] **Step 4: Run the resolver tests to verify they pass**

Run: `go test ./cmd/deepdep/ -run ResolveRef -v`
Expected: PASS, five tests.

- [ ] **Step 5: Write the failing test for the list**

Create `cmd/deepdep/projects_test.go`:

```go
package main

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/store"
)

// The list is the answer to "I can't find the run id", so it has to show the
// number, the name, and where the thing lives.
func TestRenderProjectsShowsNumberNameAndLocations(t *testing.T) {
	s, _ := seed(t, "https://github.com/o/one.git", "https://github.com/o/two.git")
	ps, err := s.Projects(context.Background(), store.ProjectQuery{})
	if err != nil {
		t.Fatal(err)
	}

	got := string(renderProjects(ps, nil, 0))
	for _, want := range []string{"NUM", "github.com/o/one", "github.com/o/two"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// Unclaimed runs are counted and named rather than dropped. A list that omitted
// them would read as a smaller, tidier store than the one on disk — the same
// rule `org` follows for repositories that failed to clone.
func TestRenderProjectsNamesUnclaimedRuns(t *testing.T) {
	s, _ := seed(t, "https://github.com/o/one.git")
	un, err := s.UnclaimedRuns(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is unclaimed in a freshly seeded store, so assert the wording
	// appears when there IS something, using a synthetic run.
	un = append(un, store.Run{RunID: "deadbeefdeadbeef", Target: "data-platform"})

	got := string(renderProjects(nil, un, 0))
	if !strings.Contains(got, "unclaimed") {
		t.Errorf("output does not mention unclaimed runs:\n%s", got)
	}
	if !strings.Contains(got, "data-platform") {
		t.Errorf("output does not name the unclaimed target:\n%s", got)
	}
}

// 209 rows on the store this was written for would recreate the friction the
// change exists to remove, so the default is capped and says it capped.
func TestRenderProjectsSaysWhenItTruncated(t *testing.T) {
	ps := make([]store.Project, 25)
	for i := range ps {
		ps[i] = store.Project{Num: int64(i + 1), Key: "github.com/o/r", Kind: "remote", Name: "o/r"}
	}
	got := string(renderProjects(ps, nil, 209))
	if !strings.Contains(got, "209") || !strings.Contains(got, "--all") {
		t.Errorf("truncation is silent; output should name the total and --all:\n%s", got)
	}
}
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `go test ./cmd/deepdep/ -run RenderProjects -v`
Expected: FAIL to compile — `undefined: renderProjects`.

- [ ] **Step 7: Write the command**

Create `cmd/deepdep/projects.go`:

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/store"
)

// projectsCmd lists the registry, or one project's detail.
//
// The default is capped. 208 of the 209 projects in the store this was written
// for arrived from `org` scans — WriteRun upserts, so `org` populates the
// registry as a side effect — and dumping all of them would recreate the
// friction the registry exists to remove.
func projectsCmd(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("projects", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	var (
		dbPath = fs.String("db", defaultDBPath(), "")
		format = fs.String("format", "text", "text|json")
		limit  = fs.Int("limit", 25, "rows before truncating; 0 for all")
		all    = fs.Bool("all", false, "no limit")
		org    = fs.String("org", "", "only projects whose key starts with this (e.g. github.com/expressjs)")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx := context.Background()

	if fs.NArg() == 1 {
		return oneProject(ctx, db, fs.Arg(0), *format)
	}

	total, err := db.Projects(ctx, store.ProjectQuery{KeyPrefix: *org})
	if err != nil {
		return nil, err
	}
	shown := total
	truncated := 0
	if !*all && *limit > 0 && len(total) > *limit {
		shown = total[:*limit]
		truncated = len(total)
	}
	un, err := db.UnclaimedRuns(ctx)
	if err != nil {
		return nil, err
	}

	if *format == "json" {
		return jsonBytes(map[string]any{
			"projects": shown, "total": len(total), "unclaimed_runs": un,
		})
	}
	return renderProjects(shown, un, truncated), nil
}

// oneProject prints a project's locations and run history.
func oneProject(ctx context.Context, db *store.Store, ref, format string) ([]byte, error) {
	ps, err := db.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		return nil, err
	}
	var found *store.Project
	for i := range ps {
		if fmt.Sprint(ps[i].Num) == ref || ps[i].Name == ref || ps[i].Key == ref {
			found = &ps[i]
			break
		}
	}
	if found == nil {
		// Reuse the resolver so one ref spelling works everywhere, and so the
		// ambiguity message is written once.
		runID, rerr := resolveRef(ctx, db, ref)
		if rerr != nil {
			return nil, rerr
		}
		for i := range ps {
			runs, err := db.RunsForProject(ctx, ps[i].Num)
			if err != nil {
				return nil, err
			}
			for _, r := range runs {
				if r.RunID == runID {
					found = &ps[i]
					break
				}
			}
		}
		if found == nil {
			return nil, fmt.Errorf("run %s belongs to no project", runID)
		}
	}

	runs, err := db.RunsForProject(ctx, found.Num)
	if err != nil {
		return nil, err
	}
	if format == "json" {
		return jsonBytes(map[string]any{"project": found, "runs": runs})
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "PROJECT %d  %s\n", found.Num, found.Key)
	fmt.Fprintf(&b, "kind %s · %d runs\n", found.Kind, len(runs))
	if len(found.Paths) == 0 {
		fmt.Fprintf(&b, "\nLOCATIONS\n  none recorded\n")
	} else {
		fmt.Fprintf(&b, "\nLOCATIONS\n")
		for _, p := range found.Paths {
			fmt.Fprintf(&b, "  %s\n", p)
		}
	}
	fmt.Fprintf(&b, "\nRUNS\n")
	for _, r := range runs {
		fmt.Fprintf(&b, "  %s  %s  %-4s  %s\n",
			r.RunID, r.CreatedAt.Format("2006-01-02 15:04"), r.Mode, short(r.Ref))
	}
	fmt.Fprintf(&b, "\n`deepdep report %d` reports the newest.\n", found.Num)
	return b.Bytes(), nil
}

// renderProjects draws the list. truncated is the untruncated total, or 0.
func renderProjects(ps []store.Project, unclaimed []store.Run, truncated int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, " %-4s %-44s %5s  %-12s %s\n", "NUM", "NAME", "RUNS", "LAST SCAN", "LOCATIONS")
	for _, p := range ps {
		fmt.Fprintf(&b, " %-4d %-44s %5d  %-12s %s\n",
			p.Num, truncate(p.Key, 44), p.Runs, stamp(p.LastScan), locations(p.Paths))
	}
	if len(ps) == 0 {
		fmt.Fprintf(&b, " no projects yet — `deepdep scan <dir>` creates one\n")
	}
	if truncated > 0 {
		fmt.Fprintf(&b, "\n %d of %d shown — --all for the rest, --org <host/owner> to filter\n",
			len(ps), truncated)
	}
	if len(unclaimed) > 0 {
		// Counted and named, never dropped: a list that hid these would read as
		// a smaller store than the one on disk.
		fmt.Fprintf(&b, "\n %d unclaimed runs — scanned before the registry existed, so their\n", len(unclaimed))
		fmt.Fprintf(&b, " directory was never recorded. Reachable by run id; re-scan to adopt.\n")
		for i, r := range unclaimed {
			if i == 5 {
				fmt.Fprintf(&b, "   ... %d more\n", len(unclaimed)-5)
				break
			}
			fmt.Fprintf(&b, "   %s  %s\n", r.RunID, truncate(r.Target, 44))
		}
	}
	return b.Bytes()
}

func locations(paths []string) string {
	switch len(paths) {
	case 0:
		return "—"
	case 1:
		return paths[0]
	default:
		return fmt.Sprintf("%s (+%d more)", paths[0], len(paths)-1)
	}
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02")
}

func jsonBytes(v any) ([]byte, error) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
```

Check whether `truncate`, `short` and `jsonBytes` already exist in `package main` — `truncate` and `short` do (used by `org.go` and `report.go`). If a JSON helper already exists, use it and delete `jsonBytes`. Do not define a second one; `strings` may then be an unused import.

- [ ] **Step 8: Wire the dispatch, the usage text, and the three reporting commands**

In `cmd/deepdep/main.go`, add to `run`:

```go
	case "projects":
		return projectsCmd(args[1:])
```

and to `usage`, after the `org` line:

```
deepdep projects[flags] [ref]         every project the store knows, and where it lives
```

In `auditCmd` (`cmd/deepdep/main.go:223-225`), `riskCmd` (`cmd/deepdep/risk.go:70-72`) and `reportCmd`, replace the bare positional read:

```go
	runID := ""
	if fs.NArg() == 1 {
		runID = fs.Arg(0)
	}
```

with

```go
	// A ref is a run id, a project number, a project name, or a unique
	// substring of either. Resolution happens here rather than in the store so
	// the ambiguity message is written once.
	runID, err := resolveRef(ctx, db, firstArg(fs))
	if err != nil {
		return nil, err
	}
```

Add to `cmd/deepdep/ref.go`:

```go
// firstArg is the optional positional ref, or "" for none.
func firstArg(fs *flag.FlagSet) string {
	if fs.NArg() >= 1 {
		return fs.Arg(0)
	}
	return ""
}
```

and `"flag"` to its imports. In each command, `db` and `ctx` are already in scope at that point — check the ordering and move the `resolveRef` call below `store.Open` if it is not.

Also change the three usage lines so `[run-id]` reads `[ref]`.

- [ ] **Step 9: Run everything**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 10: Verify against the migrated copy**

```bash
go build -o /tmp/deepdep ./cmd/deepdep
/tmp/deepdep projects --db /tmp/real.db
/tmp/deepdep projects --db /tmp/real.db --org github.com/expressjs
/tmp/deepdep projects 1 --db /tmp/real.db
```

Expected: 25 rows and a "25 of 208 shown" line; the org filter narrowing to expressjs; project 1's detail listing its runs. Confirm the unclaimed block names `data-platform` and `sqlengine`.

- [ ] **Step 11: Commit**

```bash
git add cmd/deepdep/
git commit -m "feat(cli): deepdep projects, and a ref anywhere a run id went

resolveRef takes a run id, a project number, a name, or a unique
substring of a name or path, first match wins. Ambiguity is an error
listing the candidates: guessing which of two repositories to report on
is the failure the registry exists to remove, and a confident wrong
report is worse than a question. An empty ref still means the newest run,
so every existing invocation keeps working.

The list is capped at 25 and says so. 208 of 209 projects in the store
this was written for came from org scans, and dumping them all would
recreate the friction being fixed. Unclaimed runs are counted and named
rather than omitted, on the same rule org follows for failed clones."
```

---

### Task 6: `deepdep clean`

**Files:**
- Create: `internal/store/prune.go`
- Create: `cmd/deepdep/clean.go`
- Modify: `cmd/deepdep/main.go` — dispatch and usage
- Test: `internal/store/prune_test.go`, `cmd/deepdep/clean_test.go`

**Interfaces:**
- Consumes: `store.Projects`, `store.DeleteProjects`, `safeTable` from Task 3.
- Produces:
  - `store.PruneQuery{Num int64; Keep int; OlderThan time.Time; Unclaimed, Purge bool}`
  - `store.PrunePlan{Runs []string; Projects []int64; KeptRuns int}`
  - `store.PlanPrune(ctx, PruneQuery) (PrunePlan, error)`
  - `store.ApplyPrune(ctx, PrunePlan) error`
  - `store.DeleteRuns(ctx, ids []string) error`
  - `store.Vacuum(ctx) error`
  - `store.ObservationCounts(ctx) (map[string]int, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/store/prune_test.go`:

```go
package store_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/project"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/store"
)

func seedRuns(t *testing.T, s *store.Store, remote string, n int) []string {
	t.Helper()
	g := sampleGraph()
	res := rollup.Compute(g, nil, "root")
	var ids []string
	for i := 0; i < n; i++ {
		id, err := s.WriteRun(context.Background(), sampleMeta(), g, nil, res,
			store.WithOrigin(project.Origin{Kind: project.KindRemote, Remote: remote}))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

// newRunID mixes in UnixNano, so every re-scan appends a run row forever. "Keep
// the newest N per project" is therefore the form of cleanup that matters.
func TestKeepNRetainsTheNewestPerProject(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seedRuns(t, s, "https://github.com/o/one.git", 4)
	seedRuns(t, s, "https://github.com/o/two.git", 3)

	plan, err := s.PlanPrune(ctx, store.PruneQuery{Keep: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Runs) != 3 {
		t.Fatalf("plan deletes %d runs, want 3 (4-2 plus 3-2)", len(plan.Runs))
	}
	if err := s.ApplyPrune(ctx, plan); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"github.com/o/one", "github.com/o/two"} {
		ps, err := s.Projects(ctx, store.ProjectQuery{})
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range ps {
			if p.Key == key && p.Runs != 2 {
				t.Errorf("%s has %d runs after --keep 2", key, p.Runs)
			}
		}
	}
}

// The plan and the apply must describe the same deletion, or --dry-run is a
// different code path from the real thing and stops being a preview.
func TestPlanAndApplyAgree(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seedRuns(t, s, "https://github.com/o/one.git", 3)

	plan, err := s.PlanPrune(ctx, store.PruneQuery{Keep: 1})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPrune(ctx, plan); err != nil {
		t.Fatal(err)
	}
	after, err := s.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(before)-len(after) != len(plan.Runs) {
		t.Fatalf("plan said %d runs, apply removed %d", len(plan.Runs), len(before)-len(after))
	}
}

// THE test. scorecard_obs holds 47,557 rows deps.dev will not serve again — it
// serves only the current scorecard, so a deleted one is gone for good. Nothing
// in clean may touch these tables, and the only way to see a regression is to
// count before and after.
func TestPruneNeverTouchesTheObservationTables(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seedRuns(t, s, "https://github.com/o/one.git", 2)
	if err := s.PutScorecardForTest(ctx, "github.com/o/one", 7.5); err != nil {
		t.Fatal(err)
	}

	before, err := s.ObservationCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before["scorecard_obs"] == 0 {
		t.Fatal("fixture wrote no observation, so the test would pass vacuously")
	}

	plan, err := s.PlanPrune(ctx, store.PruneQuery{Purge: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPrune(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := s.Vacuum(ctx); err != nil {
		t.Fatal(err)
	}

	after, err := s.ObservationCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for table, n := range before {
		if after[table] != n {
			t.Errorf("%s: %d rows before, %d after — clean destroyed observations it cannot recreate",
				table, n, after[table])
		}
	}
	runs, err := s.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Errorf("purge left %d runs", len(runs))
	}
}

// An empty selection deletes nothing rather than everything. A cleanup command
// whose bare form wipes the store is a footgun with a countdown.
func TestPlanPruneWithNoSelectionSelectsNothing(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seedRuns(t, s, "https://github.com/o/one.git", 3)

	plan, err := s.PlanPrune(ctx, store.PruneQuery{Keep: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Runs) != 0 || len(plan.Projects) != 0 {
		t.Fatalf("plan = %+v, want empty", plan)
	}
}
```

`PutScorecardForTest` is a test-only writer added in Step 3; there is currently no production writer for `scorecard_obs` reachable from the store's exported API used here, and the test must not pass vacuously.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/store/ -run Prune -v`
Expected: FAIL to compile — `undefined: store.PruneQuery`.

- [ ] **Step 3: Write the store side**

Create `internal/store/prune.go`:

```go
package store

import (
	"context"
	"fmt"
	"time"
)

// PruneQuery selects what to delete. The zero value selects NOTHING.
//
// That is the important property. A cleanup command whose empty form means
// "everything" is a footgun, so emptiness has to be the safe answer here rather
// than being caught by a flag check in the CLI that a future caller might skip.
type PruneQuery struct {
	Num       int64     // 0 = every project
	Keep      int       // keep the newest N runs per project; <0 = keep all
	OlderThan time.Time // zero = no age filter
	Unclaimed bool      // also delete runs belonging to no project
	Purge     bool      // delete the project rows too, not just their runs
}

// PrunePlan is exactly what will be deleted. Producing it is separate from
// applying it so --dry-run previews the real thing rather than an approximation
// of it.
type PrunePlan struct {
	Runs     []string
	Projects []int64
	KeptRuns int
}

// PlanPrune works out what a query selects, touching nothing.
func (s *Store) PlanPrune(ctx context.Context, q PruneQuery) (PrunePlan, error) {
	var plan PrunePlan

	ps, err := s.Projects(ctx, ProjectQuery{Num: q.Num})
	if err != nil {
		return plan, err
	}

	for _, p := range ps {
		runs, err := s.RunsForProject(ctx, p.Num) // newest first
		if err != nil {
			return plan, err
		}
		if q.Purge {
			plan.Projects = append(plan.Projects, p.Num)
			for _, r := range runs {
				plan.Runs = append(plan.Runs, r.RunID)
			}
			continue
		}
		for i, r := range runs {
			switch {
			case q.Keep >= 0 && i >= q.Keep:
			case !q.OlderThan.IsZero() && r.CreatedAt.Before(q.OlderThan):
			default:
				plan.KeptRuns++
				continue
			}
			plan.Runs = append(plan.Runs, r.RunID)
		}
	}

	if q.Unclaimed {
		un, err := s.UnclaimedRuns(ctx)
		if err != nil {
			return plan, err
		}
		for _, r := range un {
			if !q.OlderThan.IsZero() && !r.CreatedAt.Before(q.OlderThan) {
				plan.KeptRuns++
				continue
			}
			plan.Runs = append(plan.Runs, r.RunID)
		}
	}
	return plan, nil
}

// ApplyPrune executes a plan in one transaction.
//
// Deleting a run is one DELETE: nodes, edges, instances and both rollups hang
// off it with ON DELETE CASCADE, and foreign_keys(1) is in the DSN so the
// cascade applies on every pooled connection. It deletes from no other table —
// see ObservationCounts for what must survive and why.
func (s *Store) ApplyPrune(ctx context.Context, plan PrunePlan) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range plan.Runs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM runs WHERE run_id = ?`, id); err != nil {
			return err
		}
	}
	for _, num := range plan.Projects {
		if _, err := tx.ExecContext(ctx, `DELETE FROM projects WHERE num = ?`, num); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteRuns removes runs by id and nothing else.
func (s *Store) DeleteRuns(ctx context.Context, ids []string) error {
	return s.ApplyPrune(ctx, PrunePlan{Runs: ids})
}

// observationTables are append-only records of mutable things, and none of them
// is run-scoped.
//
// scorecard_obs is the reason this list is enforced rather than merely
// documented: deps.dev serves only the CURRENT scorecard, with no history
// endpoint and no as-of parameter, so recording one on every run is the only
// thing that makes "what was this project's Code-Review score six months ago"
// answerable. Deleting a row is destroying the only copy.
var observationTables = []string{
	"advisories", "advisory_affects", "packument_obs", "depsdev_obs",
	"scorecard_obs", "ref_obs", "version_facts",
}

// ObservationCounts reports what cleanup preserved, so the guarantee is visible
// in the command's output and assertable in a test.
func (s *Store) ObservationCounts(ctx context.Context) (map[string]int, error) {
	out := make(map[string]int, len(observationTables))
	for _, t := range observationTables {
		n, err := s.count(ctx, `SELECT count(*) FROM `+safeTable(t))
		if err != nil {
			return nil, fmt.Errorf("count %s: %w", t, err)
		}
		out[t] = n
	}
	return out, nil
}

// Vacuum reclaims file space. Slow — it rewrites the whole database, which for
// the store this was written for is 849MB — so it is opt-in at the CLI.
func (s *Store) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `VACUUM`)
	return err
}

// PutScorecardForTest writes one scorecard observation.
//
// Test-only: it exists so the preservation test cannot pass vacuously against an
// empty table, which it otherwise would, since nothing in this package writes
// scorecard_obs yet.
func (s *Store) PutScorecardForTest(ctx context.Context, projectID string, score float64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scorecard_obs (project_id,observed_at,scorecard_date,overall_score,stars,checks_json)
		 VALUES (?,?,?,?,?,?)`,
		projectID, time.Now().UTC().Format(time.RFC3339Nano), "", score, 0, "{}")
	return err
}
```

- [ ] **Step 4: Run the store tests to verify they pass**

Run: `go test ./internal/store/ -v`
Expected: PASS.

If `TestPruneNeverTouchesTheObservationTables` fails at the `Vacuum` call rather than at an assertion, that is SQLite refusing to rewrite the file while the pool holds another connection open — not a design problem. Checkpoint the WAL first:

```go
func (s *Store) Vacuum(ctx context.Context) error {
	// VACUUM rewrites the whole file and cannot run with other connections
	// active on it. Checkpointing first collapses the WAL so the rewrite has
	// nothing outstanding to wait on.
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `VACUUM`)
	return err
}
```

Do not paper over it with a retry loop; if it still fails, the cause is a leaked `*sql.Rows` somewhere and that is worth finding.

- [ ] **Step 5: Write the failing CLI test**

Create `cmd/deepdep/clean_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

// `deepdep clean` on its own must not be a store-wiping command.
func TestCleanWithNoFlagsRefuses(t *testing.T) {
	_, err := cleanCmd([]string{"--db", "/tmp/does-not-matter.db"})
	if err == nil {
		t.Fatal("clean with no selection succeeded; it must refuse")
	}
	if !strings.Contains(err.Error(), "--keep") {
		t.Errorf("error %q should point at the flags that select something", err)
	}
}
```

- [ ] **Step 6: Run it to verify it fails**

Run: `go test ./cmd/deepdep/ -run Clean -v`
Expected: FAIL to compile — `undefined: cleanCmd`.

- [ ] **Step 7: Write the command**

Create `cmd/deepdep/clean.go`:

```go
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/jverhoeks/deepdep/internal/store"
)

// cleanCmd prunes runs and, with --purge, the projects themselves.
//
// It refuses an empty selection. Every re-scan appends a run row — newRunID
// mixes in UnixNano — so the store grows monotonically and this command will be
// reached for often; the bare form has to be inert.
func cleanCmd(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("clean", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	var (
		dbPath    = fs.String("db", defaultDBPath(), "")
		ref       = fs.String("project", "", "limit to one project (number, name or path substring)")
		keep      = fs.Int("keep", -1, "keep the newest N runs per project")
		olderThan = fs.Duration("older-than", 0, "delete runs created before now minus this")
		unclaimed = fs.Bool("unclaimed", false, "delete runs belonging to no project")
		purge     = fs.Bool("purge", false, "delete the project rows too, not just their runs")
		vacuum    = fs.Bool("vacuum", false, "reclaim file space afterwards (rewrites the database)")
		dryRun    = fs.Bool("dry-run", false, "print what would go, delete nothing")
		yes       = fs.Bool("yes", false, "skip the confirmation prompt")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if *keep < 0 && *olderThan == 0 && !*unclaimed && !*purge {
		return nil, fmt.Errorf(
			"clean selects nothing by default, on purpose.\n" +
				"Choose what goes: --keep N (newest N runs per project), --older-than D,\n" +
				"--unclaimed (runs with no project), or --purge (a whole project, with --project).")
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx := context.Background()

	q := store.PruneQuery{
		Keep: *keep, Unclaimed: *unclaimed, Purge: *purge,
	}
	if *olderThan > 0 {
		q.OlderThan = time.Now().Add(-*olderThan)
	}
	if *ref != "" {
		num, err := projectNumOf(ctx, db, *ref)
		if err != nil {
			return nil, err
		}
		q.Num = num
	} else if *purge {
		return nil, fmt.Errorf("--purge needs --project: deleting every project in the store is not a default")
	}

	plan, err := db.PlanPrune(ctx, q)
	if err != nil {
		return nil, err
	}

	obs, err := db.ObservationCounts(ctx)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "WOULD DELETE\n  %d runs", len(plan.Runs))
	if len(plan.Projects) > 0 {
		fmt.Fprintf(&b, "\n  %d projects", len(plan.Projects))
	}
	fmt.Fprintf(&b, "\n  keeping %d runs\n", plan.KeptRuns)
	fmt.Fprintf(&b, "\nPRESERVED  (not run-scoped, and not regenerable)\n")
	for _, t := range sortedKeys(obs) {
		fmt.Fprintf(&b, "  %-18s %8d\n", t, obs[t])
	}
	fmt.Fprintf(&b, "  deps.dev serves only the current scorecard, so a deleted observation\n")
	fmt.Fprintf(&b, "  is the only copy. clean deletes from none of these tables.\n")

	if *dryRun {
		fmt.Fprintf(&b, "\n--dry-run: nothing was deleted.\n")
		return b.Bytes(), nil
	}
	if len(plan.Runs) == 0 && len(plan.Projects) == 0 {
		fmt.Fprintf(&b, "\nNothing selected.\n")
		return b.Bytes(), nil
	}
	if !*yes && !confirm(b.String()) {
		return []byte("cancelled.\n"), nil
	}

	if err := db.ApplyPrune(ctx, plan); err != nil {
		return nil, err
	}
	fmt.Fprintf(&b, "\nDeleted %d runs", len(plan.Runs))
	if len(plan.Projects) > 0 {
		fmt.Fprintf(&b, " and %d projects", len(plan.Projects))
	}
	fmt.Fprintf(&b, ".\n")

	if *vacuum {
		fmt.Fprintf(os.Stderr, "vacuuming (rewrites the whole database)...\n")
		if err := db.Vacuum(ctx); err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "Vacuumed.\n")
	}

	after, err := db.ObservationCounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range sortedKeys(obs) {
		if after[t] != obs[t] {
			// Belt and braces on the guarantee the tests assert. If this ever
			// fires, something deleted irreplaceable observations.
			return nil, fmt.Errorf("BUG: %s went from %d to %d rows during clean", t, obs[t], after[t])
		}
	}
	return b.Bytes(), nil
}

// projectNumOf resolves --project through the same rules as a reporting ref, so
// one spelling works everywhere.
func projectNumOf(ctx context.Context, db *store.Store, ref string) (int64, error) {
	runID, err := resolveRef(ctx, db, ref)
	if err != nil {
		return 0, err
	}
	ps, err := db.Projects(ctx, store.ProjectQuery{})
	if err != nil {
		return 0, err
	}
	for _, p := range ps {
		runs, err := db.RunsForProject(ctx, p.Num)
		if err != nil {
			return 0, err
		}
		for _, r := range runs {
			if r.RunID == runID {
				return p.Num, nil
			}
		}
	}
	return 0, fmt.Errorf("%q resolved to run %s, which belongs to no project", ref, runID)
}

// confirm asks before destroying anything, and treats a non-terminal stdin as a
// refusal rather than a yes — a piped clean must opt in with --yes.
func confirm(preview string) bool {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, preview)
		fmt.Fprintln(os.Stderr, "stdin is not a terminal: re-run with --yes to confirm, or --dry-run to preview.")
		return false
	}
	fmt.Fprint(os.Stderr, preview, "\nProceed? [y/N] ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	return len(line) > 0 && (line[0] == 'y' || line[0] == 'Y')
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

- [ ] **Step 8: Wire the dispatch and usage**

In `cmd/deepdep/main.go`:

```go
	case "clean":
		return cleanCmd(args[1:])
```

and in `usage`, after the `projects` line:

```
deepdep clean   [flags]               prune runs; --keep N, --older-than D, --unclaimed, --purge
```

- [ ] **Step 9: Run everything**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 10: Verify on the copy**

```bash
go build -o /tmp/deepdep ./cmd/deepdep
sqlite3 /tmp/real.db "SELECT count(*) FROM scorecard_obs;"     # note this number
/tmp/deepdep clean --db /tmp/real.db                            # expect the refusal
/tmp/deepdep clean --db /tmp/real.db --keep 1 --dry-run
/tmp/deepdep clean --db /tmp/real.db --keep 1 --yes
sqlite3 /tmp/real.db "SELECT count(*) FROM scorecard_obs;"     # must be unchanged
sqlite3 /tmp/real.db "SELECT count(*) FROM runs;"
```

Expected: the bare form refuses; `--keep 1` removes exactly the one duplicate run (`github.com/o/one` equivalent — on this database, one target has 2 runs); `scorecard_obs` is byte-for-byte the same count.

- [ ] **Step 11: Commit**

```bash
git add internal/store/ cmd/deepdep/
git commit -m "feat(cli): deepdep clean, which cannot destroy an observation

--keep N is the form that matters: newRunID mixes in UnixNano, so every
re-scan appends a run row forever and the store only grows.

Three safety properties, each with a test. The empty PruneQuery selects
nothing, so emptiness is safe in the store rather than only in a CLI flag
check a future caller could skip. Plan and apply are separate, so
--dry-run previews the real deletion instead of an approximation.
And the observation tables are counted before and after: scorecard_obs
holds rows deps.dev will not serve again, because it serves only the
current scorecard, so a deleted one is the only copy. The command prints
what it preserved and errors out if the count ever moves."
```

---

### Task 7: Document the commands

**Files:**
- Modify: `README.md:5-16` — the synopsis block
- Modify: `README.md` — a new section after the org section

**Interfaces:**
- Consumes: everything above. Produces no code.

- [ ] **Step 1: Update the synopsis**

In `README.md`, the opening block becomes:

```
deepdep scan   .                     # build the closure
deepdep projects                     # what is in the store, and where it lives
deepdep report                       # risk grade, CVEs, posture, controls
deepdep report 3                     # ...for project 3
deepdep report --format json         # the same, for a pipeline
deepdep report --format mermaid      # the surfaces, as a diagram
deepdep org    <org|user>            # every repository an org owns, ranked
deepdep clean  --keep 3              # prune old runs, keep the observations
```

- [ ] **Step 2: Add the section**

After the org section, add:

````markdown
## What is in the store

A run is an event: this tree, at this ref, resolved at this instant. Scanning the
same repository twice is two runs, deliberately — that is how `history` works.
But it means the store fills up with events, and until now the only handle on one
was a 16-character hash printed by no command.

A **project** is the durable thing runs are about. Identity is the canonical
remote, so `git@github.com:o/r.git` and `https://github.com/o/r` are one project,
and a repository checked out twice is one project with two locations.

```
$ deepdep projects
 NUM  NAME                                      RUNS  LAST SCAN    LOCATIONS
   1  github.com/schubergphilis-ep/…-mcaf-role     1  2026-08-17   —
 209  github.com/acme/data-platform                2  2026-08-18   ~/src/data-platform

 25 of 208 shown — --all for the rest, --org <host/owner> to filter
```

The number works anywhere a run id did:

```
deepdep report 209        # newest run for that project
deepdep risk   data-pl    # a unique substring works too
deepdep projects 209      # its locations and its run history
```

An ambiguous reference is an error listing the candidates rather than a guess.
Reporting on the wrong repository is the failure this exists to prevent.

The list carries **no risk grade**, deliberately. A grade is a function of
`known_at`; materialising one per project would make it a stale number that
looks current.

### Pruning without losing anything

```
deepdep clean --keep 3               # newest 3 runs per project
deepdep clean --older-than 720h      # anything over 30 days
deepdep clean --unclaimed            # runs from before the registry existed
deepdep clean --project 209 --purge  # that project and its runs
```

`deepdep clean` with no flags deletes nothing and says so.

What it never deletes: `advisories`, `packument_obs`, `depsdev_obs`,
`scorecard_obs`, `ref_obs`, `version_facts`. Those are not run-scoped and they
are not regenerable — deps.dev serves only the *current* scorecard, with no
history endpoint, so an observation recorded during a scan last March is the only
copy that will ever exist. Deleting it would quietly remove the ability to answer
"what was this project's Code-Review score six months ago", which is the whole
reason those tables are append-only. `clean` prints what it preserved.

### Runs from before the registry

A local scan used to record only the *basename* of the directory, so
`~/src/a/data-platform` and `~/work/b/data-platform` were the same target. Those
runs cannot be adopted into projects — the path was never written down — so they
list as `unclaimed` and stay reachable by run id. Re-scan to adopt one. Guessing
a path from a basename would point the registry at a directory nobody chose.
````

- [ ] **Step 3: Verify the examples**

Run each command in the new section against `/tmp/real.db` with `--db` and confirm the shape of the output matches what is documented. Fix the README to match reality, not the reverse.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: projects, and what clean will not delete

Documents why the list carries no grade and why the observation tables
are exempt from cleanup — a scorecard deps.dev has already replaced is
the only copy that will ever exist, so 'clean' has to be explicit that
it does not touch them."
```

---

## Self-Review

**Spec coverage.** Stage 1 (`internal/project` + `Origin()`) is Tasks 1–2. Stage 2 (schema v5 + migration) is Tasks 3–4, including the adoption numbers the spec commits to (208/3) asserted in Task 4 Step 6. Stage 3 (`projects`, `clean`, ref resolution) is Tasks 5–6, covering every flag the spec lists: `--limit`/`--all`/`--org` on `projects`, and `--project`/`--keep`/`--older-than`/`--unclaimed`/`--purge`/`--vacuum`/`--dry-run`/`--yes` on `clean`. All three of the spec's stated safety properties have named tests. The spec's `deepdep projects` output shape appears in Task 5 and again in Task 7. `runs.target` is left alone, stated as a Global Constraint and as a schema comment. Stages 4–6 (`finding_obs`, the `internal/report` extraction, `serve`) are explicitly excluded.

**Deliberately deferred to the stage that needs it:** the spec's README amendment about `serve` being a daemon belongs to stage 6, not here — Task 7 documents only what these three stages ship.

**Type consistency.** `project.Origin`/`Identity`/`Canonical`/`Of` are used with the same signatures in Tasks 2, 3 and 4. `store.WithOrigin` is variadic in Task 3 and called that way in Tasks 3, 5 and 6. `Project.Num` is `int64` throughout, including `ProjectQuery.Num`, `PruneQuery.Num` and `PrunePlan.Projects`. `resolveRef` returns `(string, error)` and is called identically in Task 5 (three commands) and Task 6 (`projectNumOf`). `safeTable` is defined in Task 3 and consumed by `ObservationCounts` in Task 6. `queryRuns` is introduced in Task 3 and backs `Runs`, `RunsForProject` and `UnclaimedRuns`.

**Two places the plan tells the implementer to check reality rather than trust it:** whether `truncate`/`short`/a JSON helper already exist in `package main` (Task 5 Step 7), and the local variable name of the `source.Source` in `scan` (Task 3 Step 7). Both are cheap greps and both would otherwise be a redeclaration or a wrong identifier.

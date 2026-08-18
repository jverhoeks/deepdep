package main

import (
	"context"
	"path/filepath"
	"strconv"
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

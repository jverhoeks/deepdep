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

	got := string(renderProjects(ps, nil, 0, ""))
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
	un := []store.Run{{RunID: "deadbeefdeadbeef", Target: "data-platform"}}

	got := string(renderProjects(nil, un, 0, ""))
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
	got := string(renderProjects(ps, nil, 209, ""))
	if !strings.Contains(got, "209") || !strings.Contains(got, "--all") {
		t.Errorf("truncation is silent; output should name the total and --all:\n%s", got)
	}
}

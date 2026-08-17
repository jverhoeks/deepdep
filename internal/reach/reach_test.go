package reach_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/reach"
)

func edges(pairs ...string) []reach.Edge {
	var out []reach.Edge
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, reach.Edge{From: graph.NodeID(pairs[i]), To: graph.NodeID(pairs[i+1])})
	}
	return out
}

func affectedSet(ids ...string) map[graph.NodeID]bool {
	m := map[graph.NodeID]bool{}
	for _, id := range ids {
		m[graph.NodeID(id)] = true
	}
	return m
}

func directs(ids ...string) []graph.NodeID {
	out := make([]graph.NodeID, len(ids))
	for i, id := range ids {
		out[i] = graph.NodeID(id)
	}
	return out
}

// The headline claim: a finding nobody here named is still someone's to fix, and
// the blast radius says whose.
func TestIntroducersAttributesInheritedFindings(t *testing.T) {
	got := reach.Introducers(
		directs("app", "cli"),
		affectedSet("spin", "webpki"),
		edges("app", "actix", "actix", "spin", "cli", "webpki"),
	)
	if len(got) != 2 {
		t.Fatalf("got %d introducers, want 2: %+v", len(got), got)
	}
	if got[0].Direct != "app" || got[0].Affected != 1 {
		t.Errorf("first = %+v, want app with 1", got[0])
	}
}

// Dependency graphs contain cycles. A recursive walk over one does not return,
// and a visited set is the only thing standing between this and a hung scan.
func TestIntroducersTerminatesOnCycles(t *testing.T) {
	done := make(chan []reach.Introducer, 1)
	go func() {
		done <- reach.Introducers(
			directs("app"),
			affectedSet("c"),
			edges("app", "a", "a", "b", "b", "c", "c", "a"),
		)
	}()
	got := <-done
	if len(got) != 1 || got[0].Affected != 1 {
		t.Errorf("got %+v, want app reaching the one affected package", got)
	}
}

// A package pulled in by four direct dependencies is not fixed by upgrading one
// of them. Reporting only Affected would promise four fixes where none exists on
// its own, so Exclusive is what a reader acts on.
func TestExclusiveSeparatesTheRealFixFromTheSharedOne(t *testing.T) {
	got := reach.Introducers(
		directs("a", "b"),
		affectedSet("shared", "onlyA"),
		edges("a", "shared", "b", "shared", "a", "onlyA"),
	)
	by := map[graph.NodeID]reach.Introducer{}
	for _, in := range got {
		by[in.Direct] = in
	}
	if by["a"].Affected != 2 || by["a"].Exclusive != 1 {
		t.Errorf("a = %+v, want 2 affected of which 1 exclusive", by["a"])
	}
	if by["b"].Affected != 1 || by["b"].Exclusive != 0 {
		t.Errorf("b = %+v, want 1 affected and nothing only it can clear", by["b"])
	}
}

// A direct dependency's own advisory is a line the maintainer can already edit.
// Counting it in another dependency's blast radius would report the easy fix
// twice and inflate whichever subtree happens to contain it.
func TestDirectFindingsAreNotAttributedToOtherDirects(t *testing.T) {
	got := reach.Introducers(
		directs("a", "b"),
		affectedSet("b"), // b is direct AND affected
		edges("a", "b"),
	)
	if len(got) != 0 {
		t.Errorf("got %+v, want nothing: b's advisory is b's own line to fix", got)
	}
}

// The point of the greedy pass. The second-largest subtree is a SUBSET of the
// largest here, so ranking by raw size would recommend a second bump that clears
// nothing new.
func TestCoverPicksByMarginalGainNotSize(t *testing.T) {
	// big covers x,y,z; subset covers x,y; other covers w alone.
	e := edges(
		"big", "x", "big", "y", "big", "z",
		"subset", "x", "subset", "y",
		"other", "w",
	)
	picks, cleared := reach.Cover(
		directs("big", "subset", "other"),
		affectedSet("x", "y", "z", "w"),
		e, 2,
	)
	if cleared != 4 {
		t.Errorf("cleared %d of 4", cleared)
	}
	if len(picks) != 2 {
		t.Fatalf("got %d picks, want 2: %+v", len(picks), picks)
	}
	if picks[0].Direct != "big" {
		t.Errorf("first pick = %s, want big", picks[0].Direct)
	}
	if picks[1].Direct != "other" {
		t.Errorf("second pick = %s, want other; subset adds nothing big did not",
			picks[1].Direct)
	}
	if picks[1].New != 1 {
		t.Errorf("second pick New = %d, want 1", picks[1].New)
	}
}

// Ordering must not depend on map iteration, or two reports of one scan differ.
func TestIntroducersAreDeterministic(t *testing.T) {
	d := directs("a", "b", "c")
	aff := affectedSet("p", "q")
	e := edges("a", "p", "b", "q", "c", "p")
	first := reach.Introducers(d, aff, e)
	for i := 0; i < 20; i++ {
		got := reach.Introducers(d, aff, e)
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("run %d differs at %d: %+v vs %+v", i, j, got[j], first[j])
			}
		}
	}
}

func TestEmptyInputsAreNotAnError(t *testing.T) {
	if got := reach.Introducers(nil, affectedSet("x"), nil); got != nil {
		t.Errorf("no direct dependencies should attribute nothing, got %+v", got)
	}
	if got := reach.Introducers(directs("a"), nil, nil); got != nil {
		t.Errorf("no findings should attribute nothing, got %+v", got)
	}
	if _, cleared := reach.Cover(directs("a"), affectedSet("x"), nil, 0); cleared != 0 {
		t.Error("a zero limit must plan nothing")
	}
}

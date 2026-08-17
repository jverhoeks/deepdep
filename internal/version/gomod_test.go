package version_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/version"
)

// Go's ordering is canonical semver, but the forms that actually appear in a
// go.mod are the ones a naive semver parser gets wrong and gets wrong SILENTLY:
// pseudo-versions, +incompatible, and the mandatory leading v.
func TestGoVersionOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int // -1 a<b, 0 equal, +1 a>b
	}{
		{"v1.2.3", "v1.2.4", -1},
		{"v1.2.3", "v1.10.0", -1}, // not string order
		{"v1.2.3", "v1.2.3", 0},
		{"v2.0.0", "v10.0.0", -1},

		// A prerelease sorts BELOW its release.
		{"v1.2.3-rc1", "v1.2.3", -1},
		{"v1.2.3-alpha", "v1.2.3-beta", -1},

		// A pseudo-version is a prerelease of the version it derives from, so it
		// sorts below the release and above the previous one.
		{"v0.0.0-20191109021931-daa7c04131f5", "v0.0.1", -1},
		{"v1.2.3-0.20191109021931-daa7c04131f5", "v1.2.3", -1},
		// Two pseudo-versions order by their embedded timestamp.
		{"v0.0.0-20191109021931-daa7c04131f5", "v0.0.0-20201109021931-aaaaaaaaaaaa", -1},

		// +incompatible is build metadata: it does NOT affect ordering, and a
		// scheme that compared it as a string would call these different.
		{"v2.0.0+incompatible", "v2.0.0", 0},
		{"v2.0.0+incompatible", "v2.0.1", -1},
	}
	for _, c := range cases {
		a, err := version.Go.Parse(c.a)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.a, err)
			continue
		}
		b, err := version.Go.Parse(c.b)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.b, err)
			continue
		}
		if got := sign(version.Go.Compare(a, b)); got != c.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// The heart of the scheme. `require x v1.2.3` is a LOWER BOUND, not a pin and
// not a range: Go selects the maximum requirement across the whole module
// graph, so any published version at or above the bound can end up in a build
// when some other module asks for more. Treating it as a pin would understate
// what a rebuild can reach; treating it as npm's caret would invent an upper
// bound Go does not have.
func TestGoRequireIsALowerBound(t *testing.T) {
	cases := []struct {
		v, constraint string
		want          bool
	}{
		{"v1.2.3", "v1.2.3", true},  // the bound itself
		{"v1.2.4", "v1.2.3", true},  // above the bound
		{"v2.0.0", "v1.2.3", true},  // NO upper bound — this is not caret
		{"v1.2.2", "v1.2.3", false}, // below
		{"v1.2.3-rc1", "v1.2.3", false},
	}
	for _, c := range cases {
		v, err := version.Go.Parse(c.v)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.v, err)
		}
		got, err := version.Go.Satisfies(v, c.constraint)
		if err != nil {
			t.Errorf("Satisfies(%s, %s): %v", c.v, c.constraint, err)
			continue
		}
		if got != c.want {
			t.Errorf("Satisfies(%s, %s) = %v, want %v", c.v, c.constraint, got, c.want)
		}
	}
}

// A require names one version, so it is exact in the sense the walker asks
// about: there is a single version to pin to when nothing else raises it.
func TestGoRequireIsExact(t *testing.T) {
	if !version.Go.IsExact("v1.2.3") {
		t.Error("IsExact(v1.2.3) = false; a require names one version")
	}
	if version.Go.IsExact(">=v1.2.3") {
		t.Error("IsExact(>=v1.2.3) = true; an explicit range names more than one")
	}
}

// Enumerate drives `can` mode: everything at or above the bound, newest first,
// bounded so a module with hundreds of tags does not explode the graph.
func TestGoEnumerateReturnsEverythingAtOrAboveTheBound(t *testing.T) {
	var avail []version.Version
	for _, s := range []string{"v1.2.2", "v1.2.3", "v1.3.0", "v2.0.0"} {
		v, err := version.Go.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		avail = append(avail, v)
	}

	got, err := version.Go.Enumerate("v1.2.3", avail, version.BoundPolicy{Mode: version.ModeAll})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("ModeAll from v1.2.3 = %d versions, want 3 (v1.2.3, v1.3.0, v2.0.0)", len(got))
	}

	// ModeLatest is what MVS actually selects when nothing else raises the
	// bound... which is the bound itself, NOT the newest published version.
	// This is where Go differs most sharply from npm and is easy to get wrong.
	got, err = version.Go.Enumerate("v1.2.3", avail, version.BoundPolicy{Mode: version.ModeLatest})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "v1.2.3" {
		t.Fatalf("ModeLatest from v1.2.3 = %v, want [v1.2.3] — MVS selects the minimum that satisfies", got)
	}

	got, err = version.Go.Enumerate("v1.2.3", avail, version.BoundPolicy{Mode: version.ModePinned})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "v1.2.3" {
		t.Fatalf("ModePinned from v1.2.3 = %v, want [v1.2.3]", got)
	}
}

func TestGoRejectsNonVersions(t *testing.T) {
	for _, s := range []string{"", "1.2.3.4.5", "not-a-version", "latest"} {
		if _, err := version.Go.Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded; want an error rather than a silent zero version", s)
		}
	}
}

// Go tolerates a missing v prefix nowhere in go.mod, but module authors and
// tooling both produce bare semver in adjacent places; accepting it keeps one
// stray input from failing a whole repository's scan.
func TestGoAcceptsBareSemver(t *testing.T) {
	v, err := version.Go.Parse("1.2.3")
	if err != nil {
		t.Fatalf("Parse(1.2.3): %v", err)
	}
	if v.String() != "v1.2.3" {
		t.Errorf("Parse(1.2.3).String() = %q, want the canonical %q", v.String(), "v1.2.3")
	}
}

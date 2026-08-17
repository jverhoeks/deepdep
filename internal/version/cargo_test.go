package version_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/version"
)

func cargoSat(t *testing.T, v, constraint string) bool {
	t.Helper()
	pv, err := version.Cargo.Parse(v)
	if err != nil {
		t.Fatalf("Parse(%q): %v", v, err)
	}
	ok, err := version.Cargo.Satisfies(pv, constraint)
	if err != nil {
		t.Fatalf("Satisfies(%q, %q): %v", v, constraint, err)
	}
	return ok
}

// A bare version in Cargo.toml is a CARET, not a pin. `serde = "1.0.0"` accepts
// every 1.x. Reading it as an exact pin would report a repository as fully
// pinned when a rebuild can move it across the whole major series.
func TestCargoBareVersionIsCaret(t *testing.T) {
	cases := []struct {
		v, c string
		want bool
	}{
		{"1.0.0", "1.0.0", true},
		{"1.5.0", "1.0.0", true},  // a caret, so later minors match
		{"1.0.9", "1.0.0", true},
		{"2.0.0", "1.0.0", false}, // but not the next major
		{"0.9.0", "1.0.0", false},
	}
	for _, c := range cases {
		if got := cargoSat(t, c.v, c.c); got != c.want {
			t.Errorf("%q satisfies %q = %v, want %v", c.v, c.c, got, c.want)
		}
	}
}

// THE silent-failure case. Below 1.0.0 the caret is much narrower, because
// Cargo treats the first NON-ZERO component as the breaking one:
//
//	^0.2.3 allows >=0.2.3 <0.3.0   — not <1.0.0
//	^0.0.3 allows >=0.0.3 <0.0.4   — only that patch
//
// Applying the >=1.0 rule to a 0.x crate silently widens the range across
// breaking releases, and about half of crates.io is 0.x.
func TestCargoPreOneCaretIsNarrower(t *testing.T) {
	cases := []struct {
		v, c string
		want bool
	}{
		{"0.2.3", "0.2.3", true},
		{"0.2.9", "0.2.3", true},
		{"0.3.0", "0.2.3", false}, // 0.3 is breaking for a 0.2 dependant
		{"0.9.0", "0.2.3", false},
		{"1.0.0", "0.2.3", false},

		{"0.0.3", "0.0.3", true},
		{"0.0.4", "0.0.3", false}, // every 0.0.x is breaking
	}
	for _, c := range cases {
		if got := cargoSat(t, c.v, c.c); got != c.want {
			t.Errorf("%q satisfies %q = %v, want %v", c.v, c.c, got, c.want)
		}
	}
}

// Tilde is narrower than caret: it pins the minor when one is given.
func TestCargoTilde(t *testing.T) {
	cases := []struct {
		v, c string
		want bool
	}{
		{"1.2.3", "~1.2.3", true},
		{"1.2.9", "~1.2.3", true},
		{"1.3.0", "~1.2.3", false},
		{"1.2.0", "~1.2", true},
		{"1.3.0", "~1.2", false},
		{"1.9.0", "~1", true}, // only the major is given, so the minor is free
		{"2.0.0", "~1", false},
	}
	for _, c := range cases {
		if got := cargoSat(t, c.v, c.c); got != c.want {
			t.Errorf("%q satisfies %q = %v, want %v", c.v, c.c, got, c.want)
		}
	}
}

func TestCargoComparatorsWildcardsAndConjunctions(t *testing.T) {
	cases := []struct {
		v, c string
		want bool
	}{
		{"1.2.3", "*", true},
		{"9.9.9", "*", true},
		{"1.5.0", "1.*", true},
		{"2.0.0", "1.*", false},
		{"1.2.3", "=1.2.3", true},
		{"1.2.4", "=1.2.3", false},
		{"1.5.0", ">=1.2.3", true},
		{"1.0.0", ">=1.2.3", false},
		{"1.5.0", ">=1.2.3, <2.0.0", true},  // comma is AND
		{"2.5.0", ">=1.2.3, <2.0.0", false},
	}
	for _, c := range cases {
		if got := cargoSat(t, c.v, c.c); got != c.want {
			t.Errorf("%q satisfies %q = %v, want %v", c.v, c.c, got, c.want)
		}
	}
}

// A prerelease is only reachable when the constraint itself mentions one —
// otherwise `serde = "1.0"` would start matching 2.0.0-alpha through some
// comparison accident.
func TestCargoPrereleasesAreOptIn(t *testing.T) {
	if cargoSat(t, "1.1.0-alpha", "1.0.0") {
		t.Error("a prerelease matched a plain caret constraint")
	}
	if !cargoSat(t, "1.0.0-alpha.2", ">=1.0.0-alpha.1, <1.0.0") {
		t.Error("a prerelease did not match a constraint that names one")
	}
}

// IsExact separates a hard pin from a range. Only `=1.2.3` pins in Cargo; a
// bare version does NOT, which is the whole point of the first test here.
func TestCargoIsExact(t *testing.T) {
	if !version.Cargo.IsExact("=1.2.3") {
		t.Error(`IsExact("=1.2.3") = false; that is Cargo's only exact form`)
	}
	for _, c := range []string{"1.2.3", "^1.2.3", "~1.2.3", "*", ">=1.0"} {
		if version.Cargo.IsExact(c) {
			t.Errorf("IsExact(%q) = true; it admits more than one version", c)
		}
	}
}

func TestCargoEnumerate(t *testing.T) {
	var avail []version.Version
	for _, s := range []string{"1.0.0", "1.2.0", "1.9.0", "2.0.0"} {
		v, err := version.Cargo.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		avail = append(avail, v)
	}

	// will-mode: Cargo picks the newest that satisfies, unlike Go.
	got, err := version.Cargo.Enumerate("1.0.0", avail, version.BoundPolicy{Mode: version.ModeLatest})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "1.9.0" {
		t.Fatalf("ModeLatest = %v, want [1.9.0] — the newest matching the caret", got)
	}

	got, err = version.Cargo.Enumerate("1.0.0", avail, version.BoundPolicy{Mode: version.ModeAll})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("ModeAll = %v, want the three 1.x versions", got)
	}
}

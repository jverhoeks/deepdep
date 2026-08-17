package version_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/version"
)

// The caret rule is the single highest-risk piece of version semantics in this
// tool: it is shared by Cargo and Poetry, it is silent when wrong, and about
// half of both ecosystems sits below 1.0.0 where the rule changes shape.
//
// It bounds by the leftmost NON-ZERO component, and when everything is zero it
// falls back to how much was WRITTEN.
func TestCaretUpperBound(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3", "2.0.0"},
		{"1.2", "2.0.0"},
		{"1", "2.0.0"},

		// Below 1.0.0 the minor is the breaking component.
		{"0.2.3", "0.3.0"},
		{"0.2", "0.3.0"},

		// Below 0.1.0 every patch is breaking.
		{"0.0.3", "0.0.4"},

		// All zero: the bound follows how many components were written.
		{"0", "1.0.0"},
		{"0.0", "0.1.0"},
		{"0.0.0", "0.0.1"},
	}
	for _, c := range cases {
		r, err := version.ParseRelease(c.in)
		if err != nil {
			t.Errorf("ParseRelease(%q): %v", c.in, err)
			continue
		}
		if got := r.CaretUpper().String(); got != c.want {
			t.Errorf("caret upper bound of %q = %q, want %q", c.in, got, c.want)
		}
	}
}

// Tilde pins every component to the LEFT of the last one written, so how many
// were written is load-bearing here too.
func TestTildeUpperBound(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3", "1.3.0"},
		{"1.2", "1.3.0"},
		{"1", "2.0.0"}, // only the major written, so the minor is free
		{"0.2.3", "0.3.0"},
	}
	for _, c := range cases {
		r, err := version.ParseRelease(c.in)
		if err != nil {
			t.Errorf("ParseRelease(%q): %v", c.in, err)
			continue
		}
		if got := r.TildeUpper().String(); got != c.want {
			t.Errorf("tilde upper bound of %q = %q, want %q", c.in, got, c.want)
		}
	}
}

// A prerelease or build suffix rides along on the lower bound and must not
// disturb the bounding arithmetic.
func TestParseReleaseIgnoresSuffixes(t *testing.T) {
	for _, in := range []string{"1.2.3-alpha.1", "1.2.3+build.5", "1.2.3-rc1+meta"} {
		r, err := version.ParseRelease(in)
		if err != nil {
			t.Fatalf("ParseRelease(%q): %v", in, err)
		}
		if got := r.CaretUpper().String(); got != "2.0.0" {
			t.Errorf("caret upper of %q = %q, want 2.0.0", in, got)
		}
	}
}

func TestParseReleaseRejectsNonNumeric(t *testing.T) {
	for _, in := range []string{"", "abc", "1.x.3", "*"} {
		if _, err := version.ParseRelease(in); err == nil {
			t.Errorf("ParseRelease(%q) succeeded; want an error rather than a silent zero", in)
		}
	}
}

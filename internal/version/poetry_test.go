package version_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/version"
)

// Poetry's constraint dialect is not PEP 440, but every form except one
// translates into PEP 440 range syntax EXACTLY. Translating is a different
// operation from misparsing: the result means precisely what the author wrote,
// and it then goes through the same PEP 440 machinery PyPI metadata uses.
func TestPoetryConstraintsTranslateToPEP440(t *testing.T) {
	cases := []struct{ in, want string }{
		// Caret bounds by the leftmost non-zero component, as in Cargo.
		{"^1.2.3", ">=1.2.3,<2.0.0"},
		{"^1.2", ">=1.2,<2.0.0"},
		{"^1", ">=1,<2.0.0"},
		{"^0.2.3", ">=0.2.3,<0.3.0"},
		{"^0.0.3", ">=0.0.3,<0.0.4"},

		// Tilde pins the component to the left of the last one written.
		{"~1.2.3", ">=1.2.3,<1.3.0"},
		{"~1.2", ">=1.2,<1.3.0"},
		{"~1", ">=1,<2.0.0"},

		// PEP 440's own ~= is a DIFFERENT operator and passes through untouched.
		{"~=1.2.3", "~=1.2.3"},

		// Wildcards.
		{"*", ""},
		{"1.*", ">=1,<2.0.0"},
		{"1.2.*", ">=1.2,<1.3.0"},

		// A bare version is EXACT in Poetry — unlike Cargo, where it is a caret.
		{"1.2.3", "==1.2.3"},

		// Explicit comparators are already PEP 440 and pass through.
		{">=1.2.3", ">=1.2.3"},
		{">=1.2.3,<2.0.0", ">=1.2.3,<2.0.0"},
		{">=1.2.3 <2.0.0", ">=1.2.3,<2.0.0"}, // space-separated means AND
		{"", ""},
	}
	for _, c := range cases {
		got, err := version.PoetryToPEP440(c.in)
		if err != nil {
			t.Errorf("PoetryToPEP440(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("PoetryToPEP440(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// PEP 440 cannot express alternation. Inventing a single range that spans both
// arms would claim versions the author excluded, so this must fail loudly and
// let the caller record an honest frontier instead.
func TestPoetryAlternationIsRefusedNotApproximated(t *testing.T) {
	for _, in := range []string{">=1.0 <2.0 || >=3.0", "^1.0 || ^2.0"} {
		if got, err := version.PoetryToPEP440(in); err == nil {
			t.Errorf("PoetryToPEP440(%q) = %q with no error; PEP 440 has no OR and the gap must be reported", in, got)
		}
	}
}

// The translations must actually hold against the PEP 440 scheme that consumes
// them — this is the property the whole approach rests on.
func TestPoetryTranslationsSatisfyCorrectly(t *testing.T) {
	cases := []struct {
		v, poetry string
		want      bool
	}{
		{"1.5.0", "^1.2.3", true},
		{"2.0.0", "^1.2.3", false},
		{"0.2.9", "^0.2.3", true},
		{"0.3.0", "^0.2.3", false}, // the pre-1.0 rule, end to end
		{"1.2.9", "~1.2.3", true},
		{"1.3.0", "~1.2.3", false},
		{"1.2.3", "1.2.3", true},
		{"1.2.4", "1.2.3", false}, // a bare version is exact
	}
	for _, c := range cases {
		spec, err := version.PoetryToPEP440(c.poetry)
		if err != nil {
			t.Fatalf("PoetryToPEP440(%q): %v", c.poetry, err)
		}
		v, err := version.PEP440.Parse(c.v)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.v, err)
		}
		got, err := version.PEP440.Satisfies(v, spec)
		if err != nil {
			t.Fatalf("Satisfies(%q, %q from %q): %v", c.v, spec, c.poetry, err)
		}
		if got != c.want {
			t.Errorf("%q satisfies %q (translated to %q) = %v, want %v", c.v, c.poetry, spec, got, c.want)
		}
	}
}

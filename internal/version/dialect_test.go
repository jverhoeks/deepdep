package version_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/version"
)

// A dialect must resolve by name, so an extractor can name the syntax its
// manifest uses without knowing which scheme consumes the result.
func TestDialectLookup(t *testing.T) {
	d, ok := version.DialectFor("poetry")
	if !ok {
		t.Fatalf("poetry not registered; registry holds %v", version.DialectNames())
	}
	if d.Ecosystem() != "pypi" {
		t.Errorf("poetry targets %q, want pypi", d.Ecosystem())
	}
	if _, ok := version.DialectFor("nope"); ok {
		t.Error("an unknown dialect resolved")
	}
}

// The contract that makes the whole approach safe: a dialect's output must be
// valid input to its ecosystem's NATIVE scheme. If that breaks, the translation
// is producing text nothing downstream can read.
func TestEveryDialectProducesItsEcosystemsNativeSyntax(t *testing.T) {
	native := map[string]version.VersionScheme{
		"pypi":   version.PEP440,
		"npm":    version.NPM,
		"cargo":  version.Cargo,
		"golang": version.Go,
	}
	// Forms every caret/tilde dialect should handle.
	specs := []string{"^1.2.3", "~1.2", "1.2.3", ">=1.0,<2.0", "*", "1.*"}

	for _, name := range version.DialectNames() {
		d, _ := version.DialectFor(name)
		scheme, ok := native[d.Ecosystem()]
		if !ok {
			t.Errorf("dialect %q targets ecosystem %q, which has no scheme", name, d.Ecosystem())
			continue
		}
		probe, err := scheme.Parse("1.2.3")
		if err != nil {
			t.Fatalf("%s: %v", d.Ecosystem(), err)
		}
		for _, s := range specs {
			out, err := d.Translate(s)
			if err != nil {
				t.Errorf("%s.Translate(%q): %v", name, s, err)
				continue
			}
			// An empty result means "any version", which every scheme accepts.
			if _, err := scheme.Satisfies(probe, out); err != nil {
				t.Errorf("%s translated %q to %q, which its own ecosystem cannot parse: %v",
					name, s, out, err)
			}
		}
	}
}

// A dialect must refuse rather than approximate. A translation that quietly
// widened or narrowed a range is the confidently-wrong answer this tool exists
// to avoid.
func TestDialectRefusesWhatItCannotTranslateExactly(t *testing.T) {
	d, _ := version.DialectFor("poetry")
	if got, err := d.Translate("^1.0 || ^2.0"); err == nil {
		t.Errorf("Translate returned %q for an alternation; PEP 440 has no OR", got)
	}
}

package version_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/jverhoeks/deepdep/internal/version"
)

type corpus struct {
	Include     [][2]string `json:"range_include"` // [range, version] -> must satisfy
	Exclude     [][2]string `json:"range_exclude"` // [range, version] -> must NOT satisfy
	Comparisons [][2]string `json:"comparisons"`   // [greater, lesser]
}

func load(t *testing.T) corpus {
	t.Helper()
	b, err := os.ReadFile("testdata/node-semver.json")
	if err != nil {
		t.Fatal(err)
	}
	var c corpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	// Guard against a stubbed corpus. These are node-semver's own strict-mode
	// fixtures (loose-parsing cases filtered out); the counts are 94/78/17.
	if len(c.Include) < 90 || len(c.Exclude) < 70 || len(c.Comparisons) < 15 {
		t.Fatalf("corpus looks stubbed: %d include, %d exclude, %d comparisons",
			len(c.Include), len(c.Exclude), len(c.Comparisons))
	}
	return c
}

func TestNPMRangeInclude(t *testing.T) {
	for _, c := range load(t).Include {
		rng, ver := c[0], c[1]
		v, err := version.NPM.Parse(ver)
		if err != nil {
			t.Errorf("Parse(%q): %v", ver, err)
			continue
		}
		ok, err := version.NPM.Satisfies(v, rng)
		if err != nil {
			t.Errorf("Satisfies(%q, %q): %v", ver, rng, err)
			continue
		}
		if !ok {
			t.Errorf("Satisfies(%q, %q) = false, want true", ver, rng)
		}
	}
}

func TestNPMRangeExclude(t *testing.T) {
	for _, c := range load(t).Exclude {
		rng, ver := c[0], c[1]
		v, err := version.NPM.Parse(ver)
		if err != nil {
			continue // unparseable versions are trivially excluded
		}
		ok, err := version.NPM.Satisfies(v, rng)
		if err != nil {
			continue // unparseable ranges are trivially excluded
		}
		if ok {
			t.Errorf("Satisfies(%q, %q) = true, want false", ver, rng)
		}
	}
}

func TestNPMComparisons(t *testing.T) {
	for _, c := range load(t).Comparisons {
		hi, err := version.NPM.Parse(c[0])
		if err != nil {
			t.Errorf("Parse(%q): %v", c[0], err)
			continue
		}
		lo, err := version.NPM.Parse(c[1])
		if err != nil {
			t.Errorf("Parse(%q): %v", c[1], err)
			continue
		}
		if got := version.NPM.Compare(hi, lo); got <= 0 {
			t.Errorf("Compare(%q, %q) = %d, want > 0", c[0], c[1], got)
		}
		if got := version.NPM.Compare(lo, hi); got >= 0 {
			t.Errorf("Compare(%q, %q) = %d, want < 0", c[1], c[0], got)
		}
		if got := version.NPM.Compare(hi, hi); got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", c[0], c[0], got)
		}
	}
}

func TestBuildMetadataIgnoredInComparison(t *testing.T) {
	a, _ := version.NPM.Parse("1.2.3+build.1")
	b, _ := version.NPM.Parse("1.2.3+build.2")
	if version.NPM.Compare(a, b) != 0 {
		t.Error("build metadata must not affect precedence (semver §10)")
	}
}

func parseAll(t *testing.T, ss ...string) []version.Version {
	t.Helper()
	var out []version.Version
	for _, s := range ss {
		v, err := version.NPM.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		out = append(out, v)
	}
	return out
}

func TestEnumerateModes(t *testing.T) {
	avail := parseAll(t, "1.0.0", "1.1.0", "1.2.0", "1.3.0", "2.0.0")

	latest, err := version.NPM.Enumerate("^1.0.0", avail, version.BoundPolicy{Mode: version.ModeLatest})
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 1 || latest[0].String() != "1.3.0" {
		t.Errorf("ModeLatest = %v, want [1.3.0] — this is the `will` answer", latest)
	}

	all, err := version.NPM.Enumerate("^1.0.0", avail, version.BoundPolicy{Mode: version.ModeAll, MaxVersionsPerRange: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].String() != "1.3.0" || all[1].String() != "1.2.0" {
		t.Errorf("ModeAll bounded = %v, want newest-first [1.3.0 1.2.0]", all)
	}

	unbounded, _ := version.NPM.Enumerate("^1.0.0", avail, version.BoundPolicy{Mode: version.ModeAll})
	if len(unbounded) != 4 {
		t.Errorf("ModeAll unbounded = %d versions, want 4 — this is the `can` answer", len(unbounded))
	}

	pinned, _ := version.NPM.Enumerate("1.2.0", avail, version.BoundPolicy{Mode: version.ModePinned})
	if len(pinned) != 1 || pinned[0].String() != "1.2.0" {
		t.Errorf("ModePinned = %v, want [1.2.0]", pinned)
	}
}

func TestEnumerateEmptyWhenNothingSatisfies(t *testing.T) {
	avail := parseAll(t, "1.0.0", "1.1.0")
	got, err := version.NPM.Enumerate("^9.0.0", avail, version.BoundPolicy{Mode: version.ModeAll})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

// The can/will distinction in miniature: a range with several satisfying
// versions yields one version under ModeLatest and many under ModeAll. If these
// ever collapse to the same answer the product thesis is gone.
func TestCanIsStrictlyLargerThanWill(t *testing.T) {
	avail := parseAll(t, "4.17.0", "4.17.15", "4.17.20", "4.17.21")
	will, _ := version.NPM.Enumerate("^4.17.0", avail, version.BoundPolicy{Mode: version.ModeLatest})
	can, _ := version.NPM.Enumerate("^4.17.0", avail, version.BoundPolicy{Mode: version.ModeAll})
	if len(can) <= len(will) {
		t.Fatalf("can = %d versions, will = %d; can must be strictly larger", len(can), len(will))
	}
}

// npm aliases appear throughout real dependency trees (rimraf's, for one). The
// alias name is only a directory; the package actually installed is the aliased
// one, and that is what advisories attach to.
func TestNPMAlias(t *testing.T) {
	for _, c := range []struct{ name, spec, wantName, wantSpec string }{
		{"string-width-cjs", "npm:string-width@^4.2.0", "string-width", "^4.2.0"},
		{"alias", "npm:@scope/pkg@~1.2.3", "@scope/pkg", "~1.2.3"},
		{"plain", "^1.0.0", "plain", "^1.0.0"},
		{"bare", "npm:target", "target", "*"},
	} {
		gotName, gotSpec := version.NPMAlias(c.name, c.spec)
		if gotName != c.wantName || gotSpec != c.wantSpec {
			t.Errorf("NPMAlias(%q,%q) = (%q,%q), want (%q,%q)",
				c.name, c.spec, gotName, gotSpec, c.wantName, c.wantSpec)
		}
	}
}

// A hard manifest pin and a soft lockfile pin over a wide range install the same
// version today, but only the second moves when the lockfile is regenerated.
func TestNPMIsExact(t *testing.T) {
	for _, c := range []struct {
		constraint string
		want       bool
	}{
		{"1.2.3", true}, {"=1.2.3", true}, {"= 1.2.3", true}, {"v1.2.3", true},
		{"1.2.3-beta.1", true},
		{"^1.2.3", false}, {"~1.2.3", false}, {">=1.2.3", false}, {">1.2.0 <2.0.0", false},
		{"1.2.x", false}, {"*", false}, {"", false}, {"1.2.3 || 1.3.0", false},
		{"1.0.0 - 2.0.0", false},
	} {
		if got := version.NPM.IsExact(c.constraint); got != c.want {
			t.Errorf("IsExact(%q) = %v, want %v", c.constraint, got, c.want)
		}
	}
}

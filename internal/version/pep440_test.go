package version_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/version"
)

func TestPEP440ParseAndNormalise(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"1.0", "1.0"},
		{"1.0.0", "1.0.0"},
		{"1!2.0", "1!2.0"},
		{"1.0a1", "1.0a1"},
		{"1.0.dev3", "1.0.dev3"},
		{"1.0.post1", "1.0.post1"},
		{"1.0+local.1", "1.0+local.1"},
		{"  1.0  ", "1.0"},
		{"v1.0", "1.0"},
		// PEP 440 normalises spellings of the same release.
		{"1.0alpha1", "1.0a1"},
		{"1.0-rc1", "1.0rc1"},
		{"1.0preview2", "1.0rc2"},
		{"1.0-1", "1.0.post1"},
	} {
		v, err := version.PEP440.Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if v.String() != c.want {
			t.Errorf("Parse(%q).String() = %q, want %q", c.in, v.String(), c.want)
		}
	}
	for _, bad := range []string{"", "abc", "1.0.0.0.x", "!1.0"} {
		if _, err := version.PEP440.Parse(bad); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
}

// The ordering rules from PEP 440: dev < pre < release < post, epochs dominate,
// and a shorter release tuple is zero-padded rather than treated as smaller.
func TestPEP440Ordering(t *testing.T) {
	ascending := []string{
		"1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0",
		"1.0.post1", "1.0.1", "1.1", "2.0", "1!1.0",
	}
	for i := 1; i < len(ascending); i++ {
		lo, err := version.PEP440.Parse(ascending[i-1])
		if err != nil {
			t.Fatal(err)
		}
		hi, err := version.PEP440.Parse(ascending[i])
		if err != nil {
			t.Fatal(err)
		}
		if version.PEP440.Compare(lo, hi) >= 0 {
			t.Errorf("%s should sort below %s", ascending[i-1], ascending[i])
		}
	}
}

func TestPEP440ZeroPaddingAndLocalIgnored(t *testing.T) {
	eq := func(a, b string) {
		t.Helper()
		x, _ := version.PEP440.Parse(a)
		y, _ := version.PEP440.Parse(b)
		if version.PEP440.Compare(x, y) != 0 {
			t.Errorf("%s and %s should compare equal", a, b)
		}
	}
	eq("1.0", "1.0.0")
	eq("1.0", "1.0.0.0")
	// A local segment does not participate in ordering against the public version.
	eq("1.0+abc", "1.0+xyz")
}

func TestPEP440Specifiers(t *testing.T) {
	for _, c := range []struct {
		v, spec string
		want    bool
	}{
		{"4.6.1", ">4.5.0", true},
		{"4.5.0", ">4.5.0", false},
		{"4.6.1", ">=4.6.1", true},
		{"4.6.1", "==4.6.1", true},
		{"4.6.2", "==4.6.1", false},
		{"4.6.1", "!=4.6.1", false},
		{"4.6.2", "!=4.6.1", true},
		{"1.4.5", "==1.4.*", true},
		{"1.5.0", "==1.4.*", false},
		{"1.4.5", "!=1.4.*", false},
		// ~= is compatible-release: ~=2.2 means >=2.2, ==2.*
		{"2.3", "~=2.2", true},
		{"3.0", "~=2.2", false},
		{"2.2.1", "~=2.2.0", true},
		{"2.3.0", "~=2.2.0", false},
		// comma-separated specifiers are ANDed
		{"1.5", ">=1.0,<2.0", true},
		{"2.5", ">=1.0,<2.0", false},
		{"1.5", ">=1.0, <2.0", true},
		// an empty specifier accepts anything
		{"9.9", "", true},
		// PEP 440 specifier semantics do NOT filter pre-releases: 2.0b1 really is
		// >= 1.0. Skipping pre-releases is an installer policy, applied in
		// Enumerate, not a property of the specifier. Verified against packaging.
		{"2.0b1", ">=1.0", true},
		{"2.0b1", ">=2.0b1", true},
		{"1.0a1", ">=1.0", false}, // simply because 1.0a1 < 1.0
		{"1.0a1", "<=1.0", true},
		{"1.0a1", "<1.0", false},     // guard: same release as the bound
		{"1.0.post1", ">1.0", false}, // mirror guard
		{"1.1.post1", ">1.0", true},
	} {
		v, err := version.PEP440.Parse(c.v)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.v, err)
			continue
		}
		got, err := version.PEP440.Satisfies(v, c.spec)
		if err != nil {
			t.Errorf("Satisfies(%q, %q): %v", c.v, c.spec, err)
			continue
		}
		if got != c.want {
			t.Errorf("Satisfies(%q, %q) = %v, want %v", c.v, c.spec, got, c.want)
		}
	}
}

// The pinning axis needs to tell a hard Python pin from a range a lockfile
// happens to hold.
func TestPEP440IsExact(t *testing.T) {
	for _, c := range []struct {
		spec string
		want bool
	}{
		{"==4.6.1", true},
		{"===4.6.1", true},
		{"==4.6.*", false},
		{">4.5.0", false},
		{">=4.6.1", false},
		{"~=4.6.1", false},
		{"", false},
		{">=1.0,<2.0", false},
		{"==1.0,!=1.0", false},
	} {
		if got := version.PEP440.IsExact(c.spec); got != c.want {
			t.Errorf("IsExact(%q) = %v, want %v", c.spec, got, c.want)
		}
	}
}

func TestPEP440Enumerate(t *testing.T) {
	var avail []version.Version
	for _, s := range []string{"4.4.0", "4.5.0", "4.6.0", "4.6.1", "5.0.0"} {
		v, err := version.PEP440.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		avail = append(avail, v)
	}
	will, _ := version.PEP440.Enumerate(">4.5.0", avail, version.BoundPolicy{Mode: version.ModeLatest})
	if len(will) != 1 || will[0].String() != "5.0.0" {
		t.Errorf("ModeLatest = %v, want [5.0.0]", will)
	}
	can, _ := version.PEP440.Enumerate(">4.5.0", avail, version.BoundPolicy{Mode: version.ModeAll})
	if len(can) != 3 {
		t.Errorf("ModeAll = %v, want 3 versions above 4.5.0", can)
	}
	pinned, _ := version.PEP440.Enumerate("==4.6.1", avail, version.BoundPolicy{Mode: version.ModePinned})
	if len(pinned) != 1 || pinned[0].String() != "4.6.1" {
		t.Errorf("ModePinned = %v, want [4.6.1]", pinned)
	}
}

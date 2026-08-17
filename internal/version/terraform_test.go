package version_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/version"
)

// Terraform's ~> is the "pessimistic" operator: it allows only the RIGHT-MOST
// written component to increment. It looks like Cargo's and Poetry's ~ and
// behaves differently at two components, which is the sort of difference that
// is silent when wrong:
//
//	~> 1.2.0   ->  >=1.2.0, <1.3.0     ~1.2.0 (cargo) -> <1.3.0   same
//	~> 1.2     ->  >=1.2,   <2.0.0     ~1.2   (cargo) -> <1.3.0   DIFFERENT
func TestPessimisticUpperBound(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.0", "1.3.0"}, // right-most is patch, so minor may move
		{"5.31.0", "5.32.0"},
		{"1.2", "2.0.0"}, // right-most is minor, so major may move
		{"5.31", "6.0.0"},
		{"1", "2.0.0"}, // only a major written
	}
	for _, c := range cases {
		r, err := version.ParseRelease(c.in)
		if err != nil {
			t.Errorf("ParseRelease(%q): %v", c.in, err)
			continue
		}
		if got := r.PessimisticUpper().String(); got != c.want {
			t.Errorf("~> %s upper bound = %q, want %q", c.in, got, c.want)
		}
	}
}

// It must NOT be the same as the tilde Cargo and Poetry share, or one of the
// two ecosystems is silently given the other's ranges.
func TestPessimisticDiffersFromCargoTildeAtTwoComponents(t *testing.T) {
	r, err := version.ParseRelease("1.2")
	if err != nil {
		t.Fatal(err)
	}
	if r.PessimisticUpper().String() == r.TildeUpper().String() {
		t.Errorf("~> 1.2 and ~1.2 both bound at %s; they are different operators",
			r.TildeUpper())
	}
}

func terraformSat(t *testing.T, v, constraint string) bool {
	t.Helper()
	pv, err := version.Terraform.Parse(v)
	if err != nil {
		t.Fatalf("Parse(%q): %v", v, err)
	}
	ok, err := version.Terraform.Satisfies(pv, constraint)
	if err != nil {
		t.Fatalf("Satisfies(%q, %q): %v", v, constraint, err)
	}
	return ok
}

func TestTerraformConstraints(t *testing.T) {
	cases := []struct {
		v, c string
		want bool
	}{
		{"5.31.0", "~> 5.31.0", true},
		{"5.31.9", "~> 5.31.0", true},
		{"5.32.0", "~> 5.31.0", false},
		{"5.99.0", "~> 5.31", true}, // two components: the minor may move
		{"6.0.0", "~> 5.31", false},

		{"1.5.0", ">= 1.0", true},
		{"0.9.0", ">= 1.0", false},
		{"1.5.0", ">= 1.0, < 2.0", true},
		{"2.0.0", ">= 1.0, < 2.0", false},
		{"5.31.0", "5.31.0", true}, // a bare version is EXACT in Terraform
		{"5.31.1", "5.31.0", false},
		{"5.31.0", "= 5.31.0", true},
		{"5.31.0", "!= 5.31.0", false},
		{"5.31.1", "!= 5.31.0", true},
		{"5.31.0", "", true}, // no constraint means any
	}
	for _, c := range cases {
		if got := terraformSat(t, c.v, c.c); got != c.want {
			t.Errorf("%q satisfies %q = %v, want %v", c.v, c.c, got, c.want)
		}
	}
}

// A bare version pins in Terraform, so it is exact; ~> and >= are not.
func TestTerraformIsExact(t *testing.T) {
	for _, c := range []string{"5.31.0", "= 5.31.0"} {
		if !version.Terraform.IsExact(c) {
			t.Errorf("IsExact(%q) = false; it names one version", c)
		}
	}
	for _, c := range []string{"~> 5.31", ">= 1.0", ">= 1.0, < 2.0", ""} {
		if version.Terraform.IsExact(c) {
			t.Errorf("IsExact(%q) = true; it admits more than one version", c)
		}
	}
}

// Provider versions carry no leading v, unlike the Go module tags they are
// built from. Mixing the two mints two nodes for one provider.
func TestTerraformVersionsHaveNoVPrefix(t *testing.T) {
	v, err := version.Terraform.Parse("5.31.0")
	if err != nil {
		t.Fatal(err)
	}
	if v.String() != "5.31.0" {
		t.Errorf("String() = %q, want 5.31.0 with no v", v.String())
	}
}

// An exact constraint is a complete answer without a registry: it says which
// version, and that version can be sent to an advisory database. Terraform has
// no resolver in this tool, so without this every declared provider sat in the
// auditable denominator and could never reach the numerator.
func TestTerraformExactNamesItsVersion(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"3.5.1", "3.5.1"},   // bare is exact in Terraform, unlike Cargo
		{"= 3.5.1", "3.5.1"}, // the operator is not part of the version
		{"=3.5.1", "3.5.1"},  // spacing is optional
		{" 3.5.1 ", "3.5.1"}, //
		{"v3.5.1", "3.5.1"},  // providers carry no v; strip it rather than mint a twin
	} {
		got, ok := version.Terraform.(version.ExactVersion).Exact(c.in)
		if !ok || got != c.want {
			t.Errorf("Exact(%q) = %q,%v; want %q,true", c.in, got, ok, c.want)
		}
	}
}

// Anything that admits more than one version must refuse, or the walker would
// mint a node for a version nobody pinned.
func TestTerraformExactRefusesRanges(t *testing.T) {
	for _, in := range []string{"~> 3.5", ">= 3.5", "> 3.0, < 4.0", "!= 3.5.1", "", "3.*"} {
		if got, ok := version.Terraform.(version.ExactVersion).Exact(in); ok {
			t.Errorf("Exact(%q) = %q,true; a range names no single version", in, got)
		}
	}
}

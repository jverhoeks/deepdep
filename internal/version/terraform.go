package version

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Terraform implements Terraform's version constraint semantics, used for both
// the CLI itself and for providers and modules.
//
// It gets its own scheme rather than borrowing one because its "~>" is the
// PESSIMISTIC operator: only the right-most written component may increment. It
// looks like Cargo's and Poetry's "~" and differs from them at two components —
// `~> 1.2` allows all of 1.x where `~1.2` stops below 1.3.0 — so sharing an
// implementation would hand one ecosystem the other's ranges, a whole major
// series wide and entirely silent.
//
// It is also not Go's scheme, even though a provider is built from a Go module
// and its advisories are filed against one. Go has no ranges at all: a require
// is a lower bound resolved by Minimal Version Selection, and applying that here
// would ignore every upper bound a Terraform configuration states.
//
// Versions carry NO leading v, unlike the Go module tags behind them. Mixing the
// two mints two nodes for one provider.
var Terraform VersionScheme = terraformScheme{}

type terraformScheme struct{}

// ---------------------------------------------------------------- version ---

type terraformVersion struct {
	major, minor, patch int
	pre                 []string
	raw                 string
}

func (v terraformVersion) String() string { return v.raw }

var terraformRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)

func (terraformScheme) Parse(s string) (Version, error) {
	s = strings.TrimSpace(s)
	m := terraformRe.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("not a Terraform version: %q", s)
	}
	v := terraformVersion{raw: strings.TrimPrefix(s, "v")}
	v.major, _ = strconv.Atoi(m[1])
	if m[2] != "" {
		v.minor, _ = strconv.Atoi(m[2])
	}
	if m[3] != "" {
		v.patch, _ = strconv.Atoi(m[3])
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, nil
}

func (terraformScheme) Compare(a, b Version) int {
	x, y := a.(terraformVersion), b.(terraformVersion)
	if c := cmpInt(x.major, y.major); c != 0 {
		return c
	}
	if c := cmpInt(x.minor, y.minor); c != 0 {
		return c
	}
	if c := cmpInt(x.patch, y.patch); c != 0 {
		return c
	}
	return cmpGoPre(x.pre, y.pre) // semver §11 prerelease ordering
}

// ------------------------------------------------------------- constraint ---

// IsExact reports a hard pin. A bare version pins in Terraform — unlike Cargo,
// where a bare version is a caret — and so does an explicit "=".
func (terraformScheme) IsExact(constraint string) bool {
	c := strings.TrimSpace(constraint)
	if c == "" {
		return false
	}
	if strings.Contains(c, ",") {
		return false
	}
	c = strings.TrimSpace(strings.TrimPrefix(c, "="))
	if strings.ContainsAny(c, "<>~!*") {
		return false
	}
	_, err := Terraform.Parse(c)
	return err == nil
}

// terraformTerm is one comparator plus its version.
type terraformTerm struct {
	op string // "", "=", "!=", ">", ">=", "<", "<=", "~>"
	v  terraformVersion
	r  Release
}

func (s terraformScheme) Satisfies(v Version, constraint string) (bool, error) {
	tv, ok := v.(terraformVersion)
	if !ok {
		return false, fmt.Errorf("version %q is not a Terraform version", v.String())
	}
	terms, err := s.parse(constraint)
	if err != nil {
		return false, err
	}
	for _, t := range terms { // comma-separated terms are ANDed
		if !s.matches(tv, t) {
			return false, nil
		}
	}
	return true, nil
}

func (s terraformScheme) matches(v terraformVersion, t terraformTerm) bool {
	c := s.Compare(v, t.v)
	switch t.op {
	case "", "=":
		return c == 0
	case "!=":
		return c != 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case "~>":
		if c < 0 {
			return false
		}
		u := t.r.PessimisticUpper()
		upper := terraformVersion{major: u.Major, minor: u.Minor, patch: u.Patch}
		return s.Compare(v, upper) < 0
	}
	return false
}

var terraformTermRe = regexp.MustCompile(`^(~>|>=|<=|!=|>|<|=)?\s*(.+)$`)

func (s terraformScheme) parse(constraint string) ([]terraformTerm, error) {
	var out []terraformTerm
	for _, part := range strings.Split(constraint, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		m := terraformTermRe.FindStringSubmatch(part)
		if m == nil {
			return nil, fmt.Errorf("unrecognised Terraform constraint %q", part)
		}
		raw := strings.TrimSpace(m[2])
		v, err := s.Parse(raw)
		if err != nil {
			return nil, err
		}
		r, err := ParseRelease(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, terraformTerm{op: m[1], v: v.(terraformVersion), r: r})
	}
	return out, nil
}

// Enumerate expands a constraint. Terraform resolves to the NEWEST version
// satisfying every term, so ModeLatest is max-satisfying.
func (s terraformScheme) Enumerate(constraint string, available []Version, p BoundPolicy) ([]Version, error) {
	var ok []Version
	for _, v := range available {
		sat, err := s.Satisfies(v, constraint)
		if err != nil {
			return nil, err
		}
		if sat {
			ok = append(ok, v)
		}
	}
	sort.Slice(ok, func(i, j int) bool { return s.Compare(ok[i], ok[j]) > 0 }) // newest first
	if len(ok) == 0 {
		return nil, nil
	}
	switch p.Mode {
	case ModePinned, ModeLatest:
		return ok[:1], nil
	default:
		if p.MaxVersionsPerRange > 0 && len(ok) > p.MaxVersionsPerRange {
			ok = ok[:p.MaxVersionsPerRange]
		}
		return ok, nil
	}
}

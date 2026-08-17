package version

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Cargo implements Cargo's version requirement semantics.
//
// Cargo is semver-ordered like npm but its DEFAULT is different in a way that
// matters: a bare requirement is a caret, so `serde = "1.0"` accepts every 1.x.
// Reading that as an exact pin would report a repository as fully pinned when a
// rebuild can move it across a whole major series.
//
// The rule that is easiest to get wrong, and silent when wrong, is the pre-1.0
// caret. Cargo treats the leftmost NON-ZERO component as the breaking one:
//
//	^1.2.3  →  >=1.2.3, <2.0.0
//	^0.2.3  →  >=0.2.3, <0.3.0   (not <1.0.0)
//	^0.0.3  →  >=0.0.3, <0.0.4   (only that patch)
//
// Roughly half of crates.io is still 0.x, so applying the >=1.0 rule there
// silently widens the range across releases the ecosystem considers breaking.
var Cargo VersionScheme = cargoScheme{}

type cargoScheme struct{}

// ---------------------------------------------------------------- version ---

type cargoVersion struct {
	major, minor, patch int
	pre                 []string
	raw                 string
}

func (v cargoVersion) String() string { return v.raw }

var cargoRe = regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)

func (cargoScheme) Parse(s string) (Version, error) {
	s = strings.TrimSpace(s)
	m := cargoRe.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("not a Cargo version: %q", s)
	}
	v := cargoVersion{raw: s}
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

// Compare is plain semver ordering; build metadata is ignored, as semver says.
func (cargoScheme) Compare(a, b Version) int {
	x, y := a.(cargoVersion), b.(cargoVersion)
	if c := cmpInt(x.major, y.major); c != 0 {
		return c
	}
	if c := cmpInt(x.minor, y.minor); c != 0 {
		return c
	}
	if c := cmpInt(x.patch, y.patch); c != 0 {
		return c
	}
	return cmpGoPre(x.pre, y.pre) // identical semver §11 prerelease rules
}

// ------------------------------------------------------------- constraint ---

// IsExact reports a hard pin. `=1.2.3` is Cargo's ONLY exact form — a bare
// version is a caret, which is the difference this whole scheme exists to keep.
func (cargoScheme) IsExact(constraint string) bool {
	c := strings.TrimSpace(constraint)
	if !strings.HasPrefix(c, "=") {
		return false
	}
	_, err := Cargo.Parse(strings.TrimSpace(c[1:]))
	return err == nil
}

// bounds is a half-open interval [lo, hi). A nil hi means unbounded above.
type cargoBounds struct {
	lo, hi   *cargoVersion
	loClosed bool // lo is inclusive
	hiClosed bool // hi is inclusive (only produced by <=)
}

func (s cargoScheme) Satisfies(v Version, constraint string) (bool, error) {
	cv, ok := v.(cargoVersion)
	if !ok {
		return false, fmt.Errorf("version %q is not a Cargo version", v.String())
	}
	sets, err := s.parseConstraint(constraint)
	if err != nil {
		return false, err
	}
	// A prerelease is only reachable when the constraint itself names one.
	// Otherwise `serde = "1.0"` would start matching 2.0.0-alpha by accident,
	// which is neither what Cargo does nor what anyone means.
	if len(cv.pre) > 0 && !constraintMentionsPre(sets) {
		return false, nil
	}
	for _, b := range sets { // comma-separated parts are ANDed
		if !s.within(cv, b) {
			return false, nil
		}
	}
	return true, nil
}

func constraintMentionsPre(sets []cargoBounds) bool {
	for _, b := range sets {
		if b.lo != nil && len(b.lo.pre) > 0 {
			return true
		}
		if b.hi != nil && len(b.hi.pre) > 0 {
			return true
		}
	}
	return false
}

func (s cargoScheme) within(v cargoVersion, b cargoBounds) bool {
	if b.lo != nil {
		c := s.Compare(v, *b.lo)
		if c < 0 || (c == 0 && !b.loClosed) {
			return false
		}
	}
	if b.hi != nil {
		c := s.Compare(v, *b.hi)
		if c > 0 || (c == 0 && !b.hiClosed) {
			return false
		}
	}
	return true
}

// parseConstraint turns one requirement string into interval bounds.
func (s cargoScheme) parseConstraint(constraint string) ([]cargoBounds, error) {
	var out []cargoBounds
	for _, part := range strings.Split(constraint, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		b, err := s.parseOne(part)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return []cargoBounds{{}}, nil // an empty requirement matches anything
	}
	return out, nil
}

func (s cargoScheme) parseOne(part string) (cargoBounds, error) {
	switch {
	case part == "*" || part == "":
		return cargoBounds{}, nil

	case strings.HasPrefix(part, ">="):
		v, err := s.parsePartial(part[2:])
		if err != nil {
			return cargoBounds{}, err
		}
		return cargoBounds{lo: &v, loClosed: true}, nil

	case strings.HasPrefix(part, "<="):
		v, err := s.parsePartial(part[2:])
		if err != nil {
			return cargoBounds{}, err
		}
		return cargoBounds{hi: &v, hiClosed: true}, nil

	case strings.HasPrefix(part, ">"):
		v, err := s.parsePartial(part[1:])
		if err != nil {
			return cargoBounds{}, err
		}
		return cargoBounds{lo: &v}, nil

	case strings.HasPrefix(part, "<"):
		v, err := s.parsePartial(part[1:])
		if err != nil {
			return cargoBounds{}, err
		}
		return cargoBounds{hi: &v}, nil

	case strings.HasPrefix(part, "="):
		v, err := s.parsePartial(part[1:])
		if err != nil {
			return cargoBounds{}, err
		}
		return cargoBounds{lo: &v, loClosed: true, hi: &v, hiClosed: true}, nil

	case strings.HasPrefix(part, "~"):
		return s.tilde(strings.TrimSpace(part[1:]))

	case strings.HasPrefix(part, "^"):
		return s.caret(strings.TrimSpace(part[1:]))

	case strings.ContainsAny(part, "*xX"):
		// A wildcard bounds whatever was written to its LEFT, exactly like tilde
		// on a partial version. Any number of components can be starred —
		// "3.*.*" appears in the wild — so truncate at the FIRST wildcard rather
		// than trimming one suffix, which left "3.*" behind and failed to parse.
		kept := leadingNumericComponents(part)
		if kept == "" {
			return cargoBounds{}, nil // "*.*" is still just anything
		}
		return s.tilde(kept)

	default:
		// A bare version is a caret. This is the default that makes Cargo
		// different from a pinning ecosystem.
		return s.caret(part)
	}
}

// parsePartial accepts "1", "1.2" and "1.2.3", filling omitted components with
// zero. Cargo comparators are written against partial versions all the time.
func (s cargoScheme) parsePartial(str string) (cargoVersion, error) {
	v, err := s.Parse(strings.TrimSpace(str))
	if err != nil {
		return cargoVersion{}, err
	}
	return v.(cargoVersion), nil
}

// caret bounds by the leftmost NON-ZERO component. The rule itself lives on
// Release, shared with the Poetry dialect, so the pre-1.0 case — the one that is
// silent when wrong — has a single implementation.
func (s cargoScheme) caret(str string) (cargoBounds, error) {
	return s.bounded(str, Release.CaretUpper)
}

// tilde pins every component to the LEFT of the last one written: ~1.2.3 and
// ~1.2 both allow <1.3.0, while ~1 allows <2.0.0.
func (s cargoScheme) tilde(str string) (cargoBounds, error) {
	return s.bounded(str, Release.TildeUpper)
}

// bounded turns a partial version plus one of Release's bounding rules into a
// half-open interval.
func (s cargoScheme) bounded(str string, upper func(Release) Release) (cargoBounds, error) {
	lo, err := s.parsePartial(str)
	if err != nil {
		return cargoBounds{}, err
	}
	r, err := ParseRelease(str)
	if err != nil {
		return cargoBounds{}, err
	}
	u := upper(r)
	hi := cargoVersion{major: u.Major, minor: u.Minor, patch: u.Patch, raw: u.String()}
	return cargoBounds{lo: &lo, loClosed: true, hi: &hi}, nil
}

// Enumerate expands a requirement. Unlike Go, Cargo resolves to the NEWEST
// version satisfying the requirement, so ModeLatest is max-satisfying.
func (s cargoScheme) Enumerate(constraint string, available []Version, p BoundPolicy) ([]Version, error) {
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

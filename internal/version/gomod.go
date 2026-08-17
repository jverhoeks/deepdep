package version

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Go implements Go module version semantics.
//
// The ORDERING is canonical semver. The CONSTRAINT model is not a range model at
// all, and that is the whole reason this scheme exists rather than reusing NPM.
//
// `require example.com/x v1.2.3` is a LOWER BOUND. Go builds with Minimal
// Version Selection: it takes the maximum requirement for each module across the
// entire module graph and uses exactly that, never "the newest that matches".
// So there are three different right answers here, and npm's scheme gives the
// wrong one for two of them:
//
//   - what a build selects today, absent any other requirement, is the bound
//     ITSELF — the minimum, not the maximum available;
//   - what a rebuild can reach is anything at or above the bound, because some
//     other module raising its own requirement is precisely what moves you;
//   - there is no upper bound. A caret model would invent one, and a pin model
//     would deny the second point entirely.
//
// A major version above 1 lives at a different module path (…/v2), so the
// absence of an upper bound does not mean v2 silently replaces v1: it means a
// module that genuinely requires …/v2 has said so under another name.
var Go VersionScheme = goScheme{}

type goScheme struct{}

// ---------------------------------------------------------------- version ---

type goVersion struct {
	major, minor, patch int
	pre                 []string // dot-separated prerelease identifiers
	canonical           string   // always carries the leading v
}

func (v goVersion) String() string { return v.canonical }

// goRe matches canonical Go versions. Build metadata is captured so it can be
// DISCARDED: semver says metadata is ignored for ordering, and "+incompatible"
// — which Go appends to a v2+ module that has no /v2 path — is exactly that.
// Comparing it as text would report v2.0.0+incompatible and v2.0.0 as different
// versions of the same module and split the node in two.
var goRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)

func (goScheme) Parse(s string) (Version, error) {
	s = strings.TrimSpace(s)
	m := goRe.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("not a Go module version: %q", s)
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])

	v := goVersion{major: maj, minor: min, patch: pat}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	// Canonicalise: always a leading v, never the build metadata. Both halves
	// matter — the v so ids match what go.mod writes, the drop so
	// v2.0.0+incompatible and v2.0.0 mint one node rather than two.
	v.canonical = fmt.Sprintf("v%d.%d.%d", maj, min, pat)
	if m[4] != "" {
		v.canonical += "-" + m[4]
	}
	return v, nil
}

// A pseudo-version is v0.0.0-20191109021931-daa7c04131f5: a prerelease whose
// identifiers are a timestamp and a commit prefix. Nothing special is needed to
// ORDER them — semver prerelease comparison already puts them below the release
// they derive from, and orders two of them by the timestamp that leads their
// identifier list, because it compares numerically and left to right.
func (s goScheme) Compare(a, b Version) int {
	x, y := a.(goVersion), b.(goVersion)
	if c := cmpInt(x.major, y.major); c != 0 {
		return c
	}
	if c := cmpInt(x.minor, y.minor); c != 0 {
		return c
	}
	if c := cmpInt(x.patch, y.patch); c != 0 {
		return c
	}
	return cmpGoPre(x.pre, y.pre)
}

// cmpGoPre implements semver §11: a version WITH a prerelease sorts below the
// same version without one, and identifiers compare numerically when both are
// numeric, otherwise as text.
func cmpGoPre(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1 // a release outranks a prerelease
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aNum := toInt(a[i])
		bn, bNum := toInt(b[i])
		switch {
		case aNum && bNum:
			if c := cmpInt(an, bn); c != 0 {
				return c
			}
		case aNum:
			return -1 // numeric identifiers sort below alphanumeric
		case bNum:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a), len(b))
}

func toInt(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// ------------------------------------------------------------- constraint ---

// IsExact reports whether the constraint names a single version.
//
// A bare `require` version does, in the sense the walker asks about: absent any
// other module raising the bound, that is the one version the build gets. An
// explicitly written comparator does not.
func (goScheme) IsExact(constraint string) bool {
	c := strings.TrimSpace(constraint)
	if c == "" {
		return false
	}
	if strings.ContainsAny(c, "<>=!*,| ") {
		return false
	}
	_, err := Go.Parse(c)
	return err == nil
}

// Satisfies asks whether v could be the version MVS ends up selecting for a
// module required at `constraint`. That is v >= bound, with no upper limit.
func (s goScheme) Satisfies(v Version, constraint string) (bool, error) {
	bound, err := s.bound(constraint)
	if err != nil {
		return false, err
	}
	gv, ok := v.(goVersion)
	if !ok {
		return false, fmt.Errorf("version %q is not a Go version", v.String())
	}
	return s.Compare(gv, bound) >= 0, nil
}

// bound extracts the lower bound from a constraint. A bare version IS the bound;
// a leading >= or > is tolerated because go.mod does not write one but adjacent
// tooling and hand-written config sometimes do.
func (s goScheme) bound(constraint string) (goVersion, error) {
	c := strings.TrimSpace(constraint)
	c = strings.TrimPrefix(c, ">=")
	c = strings.TrimPrefix(c, ">")
	c = strings.TrimSpace(c)
	v, err := s.Parse(c)
	if err != nil {
		return goVersion{}, err
	}
	return v.(goVersion), nil
}

// Enumerate expands a requirement into the versions a build could use.
//
// The modes mean genuinely different things here, and the difference is the
// point of the scheme:
//
//   - ModePinned and ModeLatest both yield the BOUND. Under MVS the selected
//     version is the minimum that satisfies every requirement, so "what will be
//     installed" is the requirement itself — not the newest release. An npm-
//     shaped implementation returning max-satisfying would report an upgrade
//     nobody is getting.
//   - ModeAll yields every published version at or above the bound: the set a
//     rebuild can reach once some other module in the graph asks for more.
func (s goScheme) Enumerate(constraint string, available []Version, p BoundPolicy) ([]Version, error) {
	bound, err := s.bound(constraint)
	if err != nil {
		return nil, err
	}

	var at []Version
	for _, v := range available {
		gv, ok := v.(goVersion)
		if !ok {
			continue
		}
		if s.Compare(gv, bound) >= 0 {
			at = append(at, gv)
		}
	}
	sort.Slice(at, func(i, j int) bool { return s.Compare(at[i], at[j]) > 0 }) // newest first

	switch p.Mode {
	case ModePinned, ModeLatest:
		// The bound itself, whether or not the registry listed it: a module can
		// require a version that has since been retracted, and the build still
		// selects it. Returning nothing there would silently drop the dependency.
		for _, v := range at {
			if s.Compare(v.(goVersion), bound) == 0 {
				return []Version{v}, nil
			}
		}
		return []Version{bound}, nil
	default:
		if p.MaxVersionsPerRange > 0 && len(at) > p.MaxVersionsPerRange {
			at = at[:p.MaxVersionsPerRange]
		}
		return at, nil
	}
}

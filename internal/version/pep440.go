package version

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// PEP440 implements Python's versioning and specifier semantics.
//
// This is not a dialect of semver, which is why it gets its own scheme rather
// than a flag on the npm one: releases have arbitrary length and are
// zero-padded, epochs override everything, post-releases sort ABOVE the release
// they follow, dev-releases below it, and "~=" means something no semver
// operator expresses.
var PEP440 VersionScheme = pep440Scheme{}

type pep440Scheme struct{}

type pep440Version struct {
	epoch   int
	release []int
	preTag  string // "a", "b", "rc"; empty when not a pre-release
	preNum  int
	post    int // -1 when absent
	dev     int // -1 when absent
	local   string
	raw     string
}

func (v pep440Version) String() string { return v.raw }

var pep440Re = regexp.MustCompile(`^\s*v?` +
	`(?:(\d+)!)?` + // epoch
	`(\d+(?:\.\d+)*)` + // release
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?` + // pre-release
	`(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d+)?))?` + // post-release
	`(?:[-_.]?(dev)[-_.]?(\d+)?)?` + // dev-release
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?` + // local
	`\s*$`)

// normalisePre folds PEP 440's accepted spellings onto the canonical three.
func normalisePre(tag string) string {
	switch tag {
	case "alpha":
		return "a"
	case "beta":
		return "b"
	case "c", "pre", "preview":
		return "rc"
	}
	return tag
}

func (pep440Scheme) Parse(s string) (Version, error) { return parsePEP440(s) }

func parsePEP440(s string) (pep440Version, error) {
	m := pep440Re.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440Version{}, fmt.Errorf("invalid PEP 440 version %q", s)
	}
	v := pep440Version{post: -1, dev: -1}
	if m[1] != "" {
		v.epoch, _ = strconv.Atoi(m[1])
	}
	for _, seg := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(seg)
		if err != nil {
			return pep440Version{}, fmt.Errorf("invalid release segment %q", seg)
		}
		v.release = append(v.release, n)
	}
	if m[3] != "" {
		v.preTag = normalisePre(m[3])
		v.preNum = atoiOr(m[4], 0)
	}
	switch {
	case m[5] != "": // the "1.0-1" implicit post form
		v.post = atoiOr(m[5], 0)
	case m[6] != "":
		v.post = atoiOr(m[7], 0)
	}
	if m[8] != "" {
		v.dev = atoiOr(m[9], 0)
	}
	v.local = m[10]
	v.raw = renderPEP440(v)
	return v, nil
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func renderPEP440(v pep440Version) string {
	var b strings.Builder
	if v.epoch != 0 {
		fmt.Fprintf(&b, "%d!", v.epoch)
	}
	for i, n := range v.release {
		if i > 0 {
			b.WriteByte('.')
		}
		fmt.Fprintf(&b, "%d", n)
	}
	if v.preTag != "" {
		fmt.Fprintf(&b, "%s%d", v.preTag, v.preNum)
	}
	if v.post >= 0 {
		fmt.Fprintf(&b, ".post%d", v.post)
	}
	if v.dev >= 0 {
		fmt.Fprintf(&b, ".dev%d", v.dev)
	}
	if v.local != "" {
		b.WriteByte('+')
		b.WriteString(v.local)
	}
	return b.String()
}

func (pep440Scheme) Compare(a, b Version) int {
	av, aok := a.(pep440Version)
	bv, bok := b.(pep440Version)
	if !aok || !bok {
		return strings.Compare(a.String(), b.String())
	}
	return comparePEP440(av, bv)
}

// comparePEP440 orders by epoch, then release (zero-padded to equal length),
// then the pre/post/dev triple. The local segment is deliberately ignored: it
// does not participate in ordering against a public version.
func comparePEP440(a, b pep440Version) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	// A shorter release tuple is zero-padded, so 1.0 and 1.0.0 are equal.
	for i := 0; i < len(a.release) || i < len(b.release); i++ {
		if c := cmpInt(at(a.release, i), at(b.release, i)); c != 0 {
			return c
		}
	}
	return cmpInt(rank(a), rank(b))
}

func at(xs []int, i int) int {
	if i < len(xs) {
		return xs[i]
	}
	return 0
}

// rank flattens the pre/post/dev ordering onto a single comparable integer:
// dev < pre < release < post, with the numeric suffix breaking ties inside each
// band. The bands are spaced far enough apart that suffixes cannot cross them.
func rank(v pep440Version) int {
	const band = 1 << 20
	switch {
	case v.dev >= 0 && v.preTag == "" && v.post < 0:
		return -3*band + v.dev
	case v.preTag != "":
		tag := map[string]int{"a": 0, "b": 1, "rc": 2}[v.preTag]
		r := -2*band + tag*(band/4) + v.preNum
		if v.dev >= 0 {
			r-- // a dev of a pre-release sorts just below it
		}
		return r
	case v.post >= 0:
		r := band + v.post
		if v.dev >= 0 {
			r--
		}
		return r
	default:
		return 0
	}
}

// ------------------------------------------------------------- specifiers ---

type pep440Spec struct {
	op       string
	raw      string
	v        pep440Version
	wildcard bool // "==1.4.*"
}

func parsePEP440Specs(s string) ([]pep440Spec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil // no constraint accepts everything
	}
	var out []pep440Spec
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		op := ""
		for _, cand := range []string{"===", "==", "!=", "<=", ">=", "~=", "<", ">"} {
			if strings.HasPrefix(part, cand) {
				op = cand
				break
			}
		}
		if op == "" {
			return nil, fmt.Errorf("unrecognised specifier %q", part)
		}
		rest := strings.TrimSpace(strings.TrimPrefix(part, op))
		sp := pep440Spec{op: op, raw: rest}
		if strings.HasSuffix(rest, ".*") {
			sp.wildcard = true
			rest = strings.TrimSuffix(rest, ".*")
		}
		if op == "===" {
			out = append(out, sp) // arbitrary equality is a string comparison
			continue
		}
		v, err := parsePEP440(rest)
		if err != nil {
			return nil, err
		}
		sp.v = v
		out = append(out, sp)
	}
	return out, nil
}

// prefixMatch implements "==1.4.*": the candidate's release must start with the
// specifier's release segments.
func prefixMatch(v, want pep440Version) bool {
	if v.epoch != want.epoch {
		return false
	}
	for i, n := range want.release {
		if at(v.release, i) != n {
			return false
		}
	}
	return true
}

// sameBase reports whether two versions share an epoch and release tuple,
// ignoring pre/post/dev/local. The "<" and ">" guards are defined in terms of it.
func sameBase(a, b pep440Version) bool {
	if a.epoch != b.epoch {
		return false
	}
	for i := 0; i < len(a.release) || i < len(b.release); i++ {
		if at(a.release, i) != at(b.release, i) {
			return false
		}
	}
	return true
}

func (s pep440Spec) test(v pep440Version) bool {
	switch s.op {
	case "===":
		return v.raw == s.raw
	case "==":
		if s.wildcard {
			return prefixMatch(v, s.v)
		}
		return comparePEP440(v, s.v) == 0
	case "!=":
		if s.wildcard {
			return !prefixMatch(v, s.v)
		}
		return comparePEP440(v, s.v) != 0
	case "<=":
		return comparePEP440(v, s.v) <= 0
	case ">=":
		return comparePEP440(v, s.v) >= 0
	case "<":
		if comparePEP440(v, s.v) >= 0 {
			return false
		}
		// A pre-release of the SAME release as the bound is excluded: "<1.0" is
		// asking for something genuinely older, not 1.0a1. Verified against
		// packaging: 1.0a1 fails "<1.0" but passes "<1.0a2" and "<=1.0".
		if s.v.preTag == "" && s.v.dev < 0 && (v.preTag != "" || v.dev >= 0) && sameBase(v, s.v) {
			return false
		}
		return true
	case ">":
		if comparePEP440(v, s.v) <= 0 {
			return false
		}
		// Mirror guard: a post-release of the same release does not count as
		// "greater" — ">1.0" excludes 1.0.post1 but allows 1.1.post1.
		if s.v.post < 0 && v.post >= 0 && sameBase(v, s.v) {
			return false
		}
		return true
	case "~=":
		// Compatible release: >= the given version, and equal up to but not
		// including its last segment. "~=2.2" is ">=2.2, ==2.*".
		if comparePEP440(v, s.v) < 0 {
			return false
		}
		upper := s.v
		if len(upper.release) > 1 {
			upper.release = upper.release[:len(upper.release)-1]
		}
		return prefixMatch(v, upper)
	}
	return false
}

func (pep440Scheme) IsExact(constraint string) bool {
	specs, err := parsePEP440Specs(constraint)
	if err != nil || len(specs) != 1 {
		return false
	}
	s := specs[0]
	return (s.op == "==" && !s.wildcard) || s.op == "==="
}

func (pep440Scheme) Satisfies(v Version, constraint string) (bool, error) {
	pv, ok := v.(pep440Version)
	if !ok {
		return false, fmt.Errorf("version %v is not a PEP 440 version", v)
	}
	specs, err := parsePEP440Specs(constraint)
	if err != nil {
		return false, err
	}
	// No blanket pre-release exclusion here. That is an npm rule; PEP 440
	// specifier semantics are pure comparison plus the two guards above, and
	// ">=1.0" genuinely does match 2.0b1. Skipping pre-releases is an INSTALLER
	// policy, so it lives in Enumerate where the selection happens.
	for _, s := range specs {
		if !s.test(pv) {
			return false, nil
		}
	}
	return true, nil
}

// isPre reports whether a version is a pre-release or dev-release.
func (v pep440Version) isPre() bool { return v.preTag != "" || v.dev >= 0 }

// mentionsPre reports whether any specifier names a pre-release, which is how a
// requirement opts in to them.
func mentionsPre(specs []pep440Spec) bool {
	for _, s := range specs {
		if s.v.isPre() {
			return true
		}
	}
	return false
}

func (s pep440Scheme) Enumerate(constraint string, available []Version, p BoundPolicy) ([]Version, error) {
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

	// Installer policy, distinct from specifier semantics: pip will not select a
	// pre-release unless the requirement asked for one — or unless nothing else
	// satisfies, which is how a pre-release-only package still resolves.
	specs, err := parsePEP440Specs(constraint)
	if err == nil && !mentionsPre(specs) {
		var stable []Version
		for _, v := range ok {
			if !v.(pep440Version).isPre() {
				stable = append(stable, v)
			}
		}
		if len(stable) > 0 {
			ok = stable
		}
	}

	sort.SliceStable(ok, func(i, j int) bool { return s.Compare(ok[i], ok[j]) > 0 }) // newest first
	if len(ok) == 0 {
		return nil, nil
	}
	switch p.Mode {
	case ModePinned:
		specs, err := parsePEP440Specs(constraint)
		if err == nil && len(specs) == 1 && specs[0].op == "==" && !specs[0].wildcard {
			for _, v := range ok {
				if comparePEP440(v.(pep440Version), specs[0].v) == 0 {
					return []Version{v}, nil
				}
			}
			return nil, nil
		}
		return ok[:1], nil
	case ModeLatest:
		return ok[:1], nil
	default:
		if p.MaxVersionsPerRange > 0 && len(ok) > p.MaxVersionsPerRange {
			ok = ok[:p.MaxVersionsPerRange]
		}
		return ok, nil
	}
}

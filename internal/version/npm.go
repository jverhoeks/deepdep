package version

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// NPM implements node-semver's strict-mode semantics.
//
// Loose parsing and includePrerelease are deliberately out of scope: they are
// opt-in behaviours in node-semver and nothing in a manifest requests them.
// Correctness here is validated against node-semver's own fixture corpus rather
// than hand-written cases — this is the heart of the can/will distinction and
// reimplementing it is a known bug farm.
var NPM VersionScheme = npmScheme{}

type npmScheme struct{}

// NPMAlias resolves npm's alias syntax, where a dependency is declared under one
// name but installs a different package:
//
//	"string-width-cjs": "npm:string-width@^4.2.0"
//
// The alias name only decides the directory on disk; the package actually pulled
// in — and therefore the thing advisories attach to — is the aliased one. It
// returns the effective (name, constraint), or the inputs unchanged.
func NPMAlias(name, spec string) (string, string) {
	const prefix = "npm:"
	if !strings.HasPrefix(spec, prefix) {
		return name, spec
	}
	rest := strings.TrimPrefix(spec, prefix)
	// A scoped target keeps its leading @, so look for the separator after it.
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return rest, "*" // "npm:pkg" with no range pins nothing
	}
	return rest[:at], rest[at+1:]
}

// ---------------------------------------------------------------- version ---

type npmVersion struct {
	major, minor, patch int
	pre                 []string // dot-separated prerelease identifiers
	raw                 string
}

func (v npmVersion) String() string { return v.raw }

var versionRe = regexp.MustCompile(
	`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?` +
		`(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

func (npmScheme) Parse(s string) (Version, error) { return parseNPM(s) }

func parseNPM(s string) (npmVersion, error) {
	t := strings.TrimSpace(s)
	m := versionRe.FindStringSubmatch(t)
	if m == nil {
		return npmVersion{}, fmt.Errorf("invalid semver %q", s)
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])
	var pre []string
	if m[4] != "" {
		pre = strings.Split(m[4], ".")
	}
	// raw excludes build metadata: it does not participate in precedence
	// (semver §10), so two versions differing only in build are the same node.
	raw := fmt.Sprintf("%d.%d.%d", maj, min, pat)
	if m[4] != "" {
		raw += "-" + m[4]
	}
	return npmVersion{major: maj, minor: min, patch: pat, pre: pre, raw: raw}, nil
}

func (npmScheme) Compare(a, b Version) int {
	av, aok := a.(npmVersion)
	bv, bok := b.(npmVersion)
	if !aok || !bok {
		return strings.Compare(a.String(), b.String())
	}
	return compareNPM(av, bv)
}

func compareNPM(a, b npmVersion) int {
	if c := cmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpInt(a.patch, b.patch); c != 0 {
		return c
	}
	return comparePre(a.pre, b.pre)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// comparePre implements semver §11: a version WITH a prerelease has lower
// precedence than the same version without one; identifiers compare numerically
// when both numeric, otherwise lexically, with numeric ranking below
// alphanumeric; a longer identifier list wins when all preceding fields match.
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1 // release > prerelease
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aNum := toNum(a[i])
		bn, bNum := toNum(b[i])
		switch {
		case aNum && bNum:
			if c := cmpInt(an, bn); c != 0 {
				return c
			}
		case aNum:
			return -1 // numeric < alphanumeric
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

func toNum(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ------------------------------------------------------------- comparators ---

type comparator struct {
	op  string // ">=", ">", "<=", "<", "="; empty op means "match anything"
	v   npmVersion
	any bool
}

func (c comparator) test(v npmVersion) bool {
	if c.any {
		return true
	}
	cmp := compareNPM(v, c.v)
	switch c.op {
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	default: // "="
		return cmp == 0
	}
}

var (
	hyphenRe  = regexp.MustCompile(`^\s*([0-9A-Za-z-.+*xX]+)\s+-\s+([0-9A-Za-z-.+*xX]+)\s*$`)
	opSpaceRe = regexp.MustCompile(`(?:\^|~>|~|<=|>=|<|>|=)\s+`)
	opSplitRe = regexp.MustCompile(`^(\^|~>|~|<=|>=|<|>|=)?\s*(.*)$`)
)

// parseRange turns a range string into an OR of AND-sets of comparators.
func parseRange(s string) ([][]comparator, error) {
	var out [][]comparator
	for _, part := range strings.Split(s, "||") {
		set, err := parseComparatorSet(part)
		if err != nil {
			return nil, err
		}
		out = append(out, set)
	}
	return out, nil
}

func parseComparatorSet(part string) ([]comparator, error) {
	part = strings.TrimSpace(part)
	if part == "" {
		return []comparator{{any: true}}, nil // "" and "*" match anything
	}
	if m := hyphenRe.FindStringSubmatch(part); m != nil {
		return hyphenComparators(m[1], m[2])
	}
	// Collapse "> 1.0.0" / ">=   1.0.0" into ">1.0.0" so whitespace splitting
	// yields comparators rather than orphaned operators.
	part = opSpaceRe.ReplaceAllStringFunc(part, func(s string) string {
		return strings.TrimRight(s, " \t")
	})

	var set []comparator
	for _, tok := range strings.Fields(part) {
		cs, err := desugar(tok)
		if err != nil {
			return nil, err
		}
		set = append(set, cs...)
	}
	if len(set) == 0 {
		return []comparator{{any: true}}, nil
	}
	return set, nil
}

// partial is a possibly-incomplete version such as "1", "1.2", "1.2.x", "*".
type partial struct {
	major, minor, patch int
	xMajor, xMinor      bool
	xPatch              bool
	pre                 string
}

func isX(s string) bool {
	return s == "" || s == "x" || s == "X" || s == "*"
}

func parsePartial(s string) (partial, error) {
	var p partial
	s = strings.TrimSpace(s)
	// A "v" prefix is permitted inside a range too, e.g. "~v0.5.4-pre".
	if len(s) > 1 && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 { // build metadata is irrelevant
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i > 0 {
		p.pre = s[i+1:]
		s = s[:i]
	}
	if isX(s) {
		p.xMajor, p.xMinor, p.xPatch = true, true, true
		return p, nil
	}
	seg := strings.Split(s, ".")
	get := func(i int) (int, bool, error) {
		if i >= len(seg) || isX(seg[i]) {
			return 0, true, nil
		}
		n, err := strconv.Atoi(seg[i])
		if err != nil {
			return 0, false, fmt.Errorf("invalid version segment %q", seg[i])
		}
		return n, false, nil
	}
	var err error
	if p.major, p.xMajor, err = get(0); err != nil {
		return p, err
	}
	if p.minor, p.xMinor, err = get(1); err != nil {
		return p, err
	}
	if p.patch, p.xPatch, err = get(2); err != nil {
		return p, err
	}
	// An x at one level implies x at every level below it.
	if p.xMajor {
		p.xMinor, p.xPatch = true, true
	} else if p.xMinor {
		p.xPatch = true
	}
	return p, nil
}

func mk(op string, major, minor, patch int, pre string) comparator {
	raw := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	if pre != "" {
		raw += "-" + pre
	}
	var pp []string
	if pre != "" {
		pp = strings.Split(pre, ".")
	}
	return comparator{op: op, v: npmVersion{major: major, minor: minor, patch: patch, pre: pp, raw: raw}}
}

func anyComp() []comparator  { return []comparator{{any: true}} }
func noneComp() []comparator { return []comparator{mk("<", 0, 0, 0, "0")} }

func desugar(tok string) ([]comparator, error) {
	m := opSplitRe.FindStringSubmatch(tok)
	op, rest := m[1], strings.TrimSpace(m[2])
	p, err := parsePartial(rest)
	if err != nil {
		return nil, err
	}
	switch op {
	case "^":
		return caret(p), nil
	case "~", "~>":
		return tilde(p), nil
	default:
		return xrange(op, p), nil
	}
}

// caret: compatible within the leftmost non-zero segment.
func caret(p partial) []comparator {
	switch {
	case p.xMajor:
		return anyComp()
	case p.xMinor:
		return []comparator{mk(">=", p.major, 0, 0, ""), mk("<", p.major+1, 0, 0, "0")}
	case p.xPatch:
		if p.major == 0 {
			return []comparator{mk(">=", p.major, p.minor, 0, ""), mk("<", p.major, p.minor+1, 0, "0")}
		}
		return []comparator{mk(">=", p.major, p.minor, 0, ""), mk("<", p.major+1, 0, 0, "0")}
	}
	lo := mk(">=", p.major, p.minor, p.patch, p.pre)
	switch {
	case p.major == 0 && p.minor == 0:
		return []comparator{lo, mk("<", p.major, p.minor, p.patch+1, "0")}
	case p.major == 0:
		return []comparator{lo, mk("<", p.major, p.minor+1, 0, "0")}
	}
	return []comparator{lo, mk("<", p.major+1, 0, 0, "0")}
}

// tilde: patch-level changes if a minor is given, minor-level otherwise.
func tilde(p partial) []comparator {
	switch {
	case p.xMajor:
		return anyComp()
	case p.xMinor:
		return []comparator{mk(">=", p.major, 0, 0, ""), mk("<", p.major+1, 0, 0, "0")}
	case p.xPatch:
		return []comparator{mk(">=", p.major, p.minor, 0, ""), mk("<", p.major, p.minor+1, 0, "0")}
	}
	return []comparator{
		mk(">=", p.major, p.minor, p.patch, p.pre),
		mk("<", p.major, p.minor+1, 0, "0"),
	}
}

// xrange handles bare and operator-prefixed partial versions: "1.2.x", ">1.2",
// "<=2", "1.2.3".
func xrange(op string, p partial) []comparator {
	anyX := p.xMajor || p.xMinor || p.xPatch
	if op == "=" && anyX {
		op = ""
	}
	if p.xMajor {
		if op == ">" || op == "<" {
			return noneComp() // ">*" and "<*" match nothing
		}
		return anyComp()
	}
	if op != "" && op != "=" && anyX {
		major, minor, patch := p.major, p.minor, 0
		if p.xMinor {
			minor = 0
		}
		pre := ""
		switch op {
		case ">":
			op = ">="
			if p.xMinor {
				major, minor, patch = major+1, 0, 0
			} else {
				minor, patch = minor+1, 0
			}
		case "<=":
			op = "<"
			if p.xMinor {
				major++
			} else {
				minor++
			}
		}
		if op == "<" {
			pre = "0"
		}
		return []comparator{mk(op, major, minor, patch, pre)}
	}
	switch {
	case p.xMinor: // "1" -> >=1.0.0 <2.0.0-0
		return []comparator{mk(">=", p.major, 0, 0, ""), mk("<", p.major+1, 0, 0, "0")}
	case p.xPatch: // "1.2" -> >=1.2.0 <1.3.0-0
		return []comparator{mk(">=", p.major, p.minor, 0, ""), mk("<", p.major, p.minor+1, 0, "0")}
	}
	if op == "" {
		op = "="
	}
	return []comparator{mk(op, p.major, p.minor, p.patch, p.pre)}
}

func hyphenComparators(from, to string) ([]comparator, error) {
	f, err := parsePartial(from)
	if err != nil {
		return nil, err
	}
	t, err := parsePartial(to)
	if err != nil {
		return nil, err
	}
	var set []comparator
	switch {
	case f.xMajor: // open lower bound
	case f.xMinor:
		set = append(set, mk(">=", f.major, 0, 0, ""))
	case f.xPatch:
		set = append(set, mk(">=", f.major, f.minor, 0, ""))
	default:
		set = append(set, mk(">=", f.major, f.minor, f.patch, f.pre))
	}
	switch {
	case t.xMajor: // open upper bound
	case t.xMinor:
		set = append(set, mk("<", t.major+1, 0, 0, "0"))
	case t.xPatch:
		set = append(set, mk("<", t.major, t.minor+1, 0, "0"))
	default:
		set = append(set, mk("<=", t.major, t.minor, t.patch, t.pre))
	}
	if len(set) == 0 {
		return anyComp(), nil
	}
	return set, nil
}

// IsExact reports whether the constraint pins exactly one version.
//
// This is what distinguishes "the manifest says 1.2.3" from "the manifest says
// ^1.2.0 and a lockfile happens to hold it at 1.2.3". Both install the same
// version today; only the second moves when someone regenerates the lockfile.
func (npmScheme) IsExact(constraint string) bool {
	sets, err := parseRange(constraint)
	if err != nil || len(sets) != 1 || len(sets[0]) != 1 {
		return false
	}
	c := sets[0][0]
	return !c.any && (c.op == "=" || c.op == "")
}

// -------------------------------------------------------------- satisfies ---

func (npmScheme) Satisfies(v Version, constraint string) (bool, error) {
	nv, ok := v.(npmVersion)
	if !ok {
		return false, fmt.Errorf("version %v is not an npm version", v)
	}
	sets, err := parseRange(constraint)
	if err != nil {
		return false, err
	}
	for _, set := range sets {
		if testSet(set, nv) {
			return true, nil
		}
	}
	return false, nil
}

// testSet applies one AND-set, then npm's prerelease rule.
//
// A prerelease version only satisfies a set if some comparator in that SAME set
// was itself written with a prerelease on the same major.minor.patch. This is
// what stops "^1.2.3" from quietly matching "2.0.0-alpha", and it is the rule
// most often got wrong — it is per-comparator-set, not global.
func testSet(set []comparator, v npmVersion) bool {
	for _, c := range set {
		if !c.test(v) {
			return false
		}
	}
	if len(v.pre) == 0 {
		return true
	}
	for _, c := range set {
		if c.any || len(c.v.pre) == 0 {
			continue
		}
		if c.v.major == v.major && c.v.minor == v.minor && c.v.patch == v.patch {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------- enumerate ---

func (s npmScheme) Enumerate(constraint string, available []Version, p BoundPolicy) ([]Version, error) {
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
	sort.SliceStable(ok, func(i, j int) bool { return s.Compare(ok[i], ok[j]) > 0 }) // newest first
	if len(ok) == 0 {
		return nil, nil
	}

	switch p.Mode {
	case ModePinned:
		want, err := parseNPM(strings.TrimSpace(constraint))
		if err != nil {
			return ok[:1], nil // not an exact pin; fall back to the highest
		}
		for _, v := range ok {
			if compareNPM(v.(npmVersion), want) == 0 {
				return []Version{v}, nil
			}
		}
		return nil, nil
	case ModeLatest:
		return ok[:1], nil
	default: // ModeAll — the "can" answer
		if p.MaxVersionsPerRange > 0 && len(ok) > p.MaxVersionsPerRange {
			ok = ok[:p.MaxVersionsPerRange]
		}
		return ok, nil
	}
}

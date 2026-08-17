package version

import (
	"fmt"
	"regexp"
	"strings"
)

// PoetryDialect translates Poetry's constraint syntax into PEP 440.
//
// Poetry declares PyPI packages in a syntax PyPI does not use: its caret and
// tilde come from Cargo, and its bare version means EXACT where Cargo's means
// caret. Feeding "^1.2.3" to a PEP 440 parser would invent a range, which is why
// pyproject.toml's Poetry tables went unread for so long (see python.go).
//
// Translating is a different operation from misparsing. Every form below has an
// exact PEP 440 equivalent, so the output means precisely what the author wrote
// and then goes through the same scheme PyPI's own metadata uses.
//
// The caret and tilde bounds come from Release, shared with Cargo, so the
// pre-1.0 rule has one implementation rather than two that could drift.
var PoetryDialect Dialect = poetryDialect{}

type poetryDialect struct{}

func (poetryDialect) Name() string      { return "poetry" }
func (poetryDialect) Ecosystem() string { return "pypi" }

// PoetryToPEP440 translates a Poetry constraint. It is kept as a function for
// callers that want the dialect by name at compile time.
func PoetryToPEP440(spec string) (string, error) { return PoetryDialect.Translate(spec) }

func (d poetryDialect) Translate(spec string) (string, error) {
	s := strings.TrimSpace(spec)
	if s == "" || s == "*" {
		return "", nil
	}
	// PEP 440 has no OR at any level. Collapsing alternation into one span would
	// claim versions the author excluded, so it is refused and the caller
	// records an honest frontier.
	if strings.Contains(s, "||") {
		return "", fmt.Errorf("poetry alternation %q has no PEP 440 equivalent", spec)
	}

	parts := splitPoetryConjunction(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t, err := d.term(p)
		if err != nil {
			return "", err
		}
		if t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, ","), nil
}

// splitPoetryConjunction splits on commas and on the spaces BETWEEN terms,
// without splitting inside a term like ">= 1.2".
func splitPoetryConjunction(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		for _, t := range poetryTermRe.FindAllString(f, -1) {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

var poetryTermRe = regexp.MustCompile(`[~^><=!]*\s*[0-9][0-9A-Za-z.*+!-]*`)

func (d poetryDialect) term(p string) (string, error) {
	p = strings.TrimSpace(p)
	switch {
	case p == "" || p == "*":
		return "", nil

	// PEP 440's compatible-release operator is NOT Poetry's tilde. They look
	// alike, mean different things, and this one is already native.
	case strings.HasPrefix(p, "~="):
		return p, nil

	case strings.HasPrefix(p, "^"):
		return bounded(strings.TrimSpace(p[1:]), Release.CaretUpper)

	case strings.HasPrefix(p, "~"):
		return bounded(strings.TrimSpace(p[1:]), Release.TildeUpper)

	case strings.HasPrefix(p, ">="), strings.HasPrefix(p, "<="),
		strings.HasPrefix(p, "=="), strings.HasPrefix(p, "!="),
		strings.HasPrefix(p, ">"), strings.HasPrefix(p, "<"):
		return strings.ReplaceAll(p, " ", ""), nil

	case strings.ContainsAny(p, "*xX"):
		// A wildcard bounds whatever stands to its LEFT. Any number of
		// components can be starred, so truncate at the FIRST one.
		kept := leadingNumericComponents(p)
		if kept == "" {
			return "", nil // "*.*" is still just anything
		}
		return bounded(kept, Release.TildeUpper)

	default:
		// A bare version is EXACT in Poetry, where Cargo's is a caret. Getting
		// this backwards claims versions the author never allowed.
		return "==" + p, nil
	}
}

// bounded renders ">=lower,<upper" using one of Release's bounding rules.
func bounded(v string, upper func(Release) Release) (string, error) {
	r, err := ParseRelease(v)
	if err != nil {
		return "", err
	}
	return ">=" + v + ",<" + upper(r).String(), nil
}

// leadingNumericComponents keeps the components up to the first wildcard.
func leadingNumericComponents(s string) string {
	var kept []string
	for _, c := range strings.Split(strings.TrimSpace(s), ".") {
		if c == "" || c == "*" || c == "x" || c == "X" {
			break
		}
		kept = append(kept, c)
	}
	return strings.Join(kept, ".")
}

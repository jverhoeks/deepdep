package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PoetryToPEP440 translates a Poetry constraint into PEP 440 range syntax.
//
// Poetry's dialect is genuinely not PEP 440 — it borrows Cargo's caret and
// tilde, and its bare version means EXACT where Cargo's means caret. Feeding
// "^1.2.3" to a PEP 440 parser would produce a confidently wrong range, which is
// why pyproject.toml's Poetry tables went unread for so long.
//
// Translating is a different operation from misparsing. Every form below has an
// exact PEP 440 equivalent, so the output means precisely what the author wrote
// and can then go through the same machinery PyPI's own metadata uses — one
// version scheme for the ecosystem, which is what the rest of the tool assumes.
//
// The single exception is alternation. Poetry accepts "^1.0 || ^2.0" and PEP 440
// has no OR at any level. Collapsing that to one span would claim versions the
// author excluded, so it is refused and the caller records a frontier instead.
//
// The cost of translating is display fidelity: a report shows the translated
// ">=1.2.3,<2.0.0" rather than the "^1.2.3" that was written. That is a fair
// trade for keeping one scheme per ecosystem, and the translation is printed in
// terms the reader can check against the source.
func PoetryToPEP440(spec string) (string, error) {
	s := strings.TrimSpace(spec)
	if s == "" || s == "*" {
		return "", nil
	}
	if strings.Contains(s, "||") {
		return "", fmt.Errorf("poetry alternation %q has no PEP 440 equivalent", spec)
	}

	// Poetry separates conjunctions with a comma OR whitespace; PEP 440 uses a
	// comma. Normalise before splitting so both spellings are handled once.
	parts := splitPoetryConjunction(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t, err := poetryTerm(p)
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
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' })
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		// A term is an optional operator immediately followed by a version, so
		// ">=1.0 <2.0" is two terms while ">= 1.0" is one.
		for _, t := range poetryTermRe.FindAllString(f, -1) {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

var poetryTermRe = regexp.MustCompile(`[~^><=!]*\s*[0-9][0-9A-Za-z.*+!-]*`)

func poetryTerm(p string) (string, error) {
	p = strings.TrimSpace(p)
	switch {
	case p == "" || p == "*":
		return "", nil

	// PEP 440's compatible-release operator is NOT Poetry's tilde and must pass
	// through untouched. They look alike and mean different things.
	case strings.HasPrefix(p, "~="):
		return p, nil

	case strings.HasPrefix(p, "^"):
		return caretRange(strings.TrimSpace(p[1:]))

	case strings.HasPrefix(p, "~"):
		return tildeRange(strings.TrimSpace(p[1:]))

	case strings.HasPrefix(p, ">="), strings.HasPrefix(p, "<="),
		strings.HasPrefix(p, "=="), strings.HasPrefix(p, "!="),
		strings.HasPrefix(p, ">"), strings.HasPrefix(p, "<"):
		return strings.ReplaceAll(p, " ", ""), nil

	case strings.HasSuffix(p, ".*"):
		// 1.* and 1.2.* bound the last component written, exactly like tilde on
		// a partial version.
		return tildeRange(strings.TrimSuffix(p, ".*"))

	default:
		// A bare version is EXACT in Poetry. This is the difference from Cargo
		// and it goes the safer way: reading it as a caret would claim versions
		// the author did not allow.
		return "==" + p, nil
	}
}

// caretRange bounds by the leftmost NON-ZERO component, the rule Poetry takes
// from Cargo. Below 1.0.0 it is much narrower, and getting that wrong widens the
// range across releases the ecosystem treats as breaking.
func caretRange(v string) (string, error) {
	maj, min, pat, given, err := splitNumeric(v)
	if err != nil {
		return "", err
	}
	var upper string
	switch {
	case maj > 0:
		upper = fmt.Sprintf("%d.0.0", maj+1)
	case min > 0:
		upper = fmt.Sprintf("0.%d.0", min+1)
	case pat > 0:
		upper = fmt.Sprintf("0.0.%d", pat+1)
	default:
		// All zero, so the bound follows how much was WRITTEN.
		switch given {
		case 1:
			upper = "1.0.0"
		case 2:
			upper = "0.1.0"
		default:
			upper = "0.0.1"
		}
	}
	return ">=" + v + ",<" + upper, nil
}

// tildeRange pins every component left of the last one written: ~1.2.3 and ~1.2
// both stop below 1.3.0, while ~1 stops below 2.0.0.
func tildeRange(v string) (string, error) {
	maj, min, _, given, err := splitNumeric(v)
	if err != nil {
		return "", err
	}
	if given == 1 {
		return fmt.Sprintf(">=%s,<%d.0.0", v, maj+1), nil
	}
	return fmt.Sprintf(">=%s,<%d.%d.0", v, maj, min+1), nil
}

func splitNumeric(v string) (maj, min, pat, given int, err error) {
	// Only the release segment matters for bounding; a prerelease or local
	// suffix rides along on the lower bound untouched.
	base := v
	if i := strings.IndexAny(base, "-+"); i >= 0 {
		base = base[:i]
	}
	parts := strings.Split(base, ".")
	given = len(parts)
	nums := make([]int, 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, convErr := strconv.Atoi(parts[i])
		if convErr != nil {
			return 0, 0, 0, 0, fmt.Errorf("not a numeric version component in %q", v)
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], given, nil
}

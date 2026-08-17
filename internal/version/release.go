package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Release is a numeric release segment together with how many components were
// actually WRITTEN.
//
// The written count is not bookkeeping, it is semantics. "^0" and "^0.0" bound
// differently even though both parse to 0.0.0, and a caret or tilde cannot be
// computed correctly without knowing which was typed.
type Release struct {
	Major, Minor, Patch int
	// Given is how many dot-separated components the constraint carried: 1 for
	// "1", 2 for "1.2", 3 for "1.2.3".
	Given int
}

func (r Release) String() string {
	return fmt.Sprintf("%d.%d.%d", r.Major, r.Minor, r.Patch)
}

// ParseRelease reads the numeric release segment, discarding any prerelease or
// build suffix. Those ride along on a lower bound and must not disturb the
// bounding arithmetic.
func ParseRelease(s string) (Release, error) {
	base := strings.TrimSpace(s)
	if i := strings.IndexAny(base, "-+"); i >= 0 {
		base = base[:i]
	}
	if base == "" {
		return Release{}, fmt.Errorf("not a release version: %q", s)
	}
	parts := strings.Split(base, ".")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	r := Release{Given: len(strings.Split(base, "."))}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return Release{}, fmt.Errorf("not a numeric version component in %q", s)
		}
		nums[i] = n
	}
	r.Major, r.Minor, r.Patch = nums[0], nums[1], nums[2]
	return r, nil
}

// CaretUpper returns the exclusive upper bound of a caret constraint.
//
// This is ONE implementation on purpose. Cargo and Poetry share the rule — both
// take it from Cargo — and it is the highest-risk piece of version semantics
// here: it is silent when wrong, and roughly half of each ecosystem sits below
// 1.0.0 where its shape changes. Two copies would drift, and the drift would not
// show up as a failure, only as a slightly wrong range.
//
// The bound is set by the leftmost NON-ZERO component, because that is the one
// the ecosystem treats as breaking:
//
//	^1.2.3 -> <2.0.0      ^0.2.3 -> <0.3.0      ^0.0.3 -> <0.0.4
//
// When every component is zero there is no non-zero component to key on, so the
// bound follows how much was written instead.
func (r Release) CaretUpper() Release {
	switch {
	case r.Major > 0:
		return Release{Major: r.Major + 1, Given: 3}
	case r.Minor > 0:
		return Release{Minor: r.Minor + 1, Given: 3}
	case r.Patch > 0:
		return Release{Patch: r.Patch + 1, Given: 3}
	}
	switch r.Given {
	case 1: // ^0
		return Release{Major: 1, Given: 3}
	case 2: // ^0.0
		return Release{Minor: 1, Given: 3}
	default: // ^0.0.0
		return Release{Patch: 1, Given: 3}
	}
}

// TildeUpper returns the exclusive upper bound of a tilde constraint: everything
// left of the last component written is pinned.
//
//	~1.2.3 -> <1.3.0      ~1.2 -> <1.3.0      ~1 -> <2.0.0
func (r Release) TildeUpper() Release {
	if r.Given == 1 {
		return Release{Major: r.Major + 1, Given: 3}
	}
	return Release{Major: r.Major, Minor: r.Minor + 1, Given: 3}
}

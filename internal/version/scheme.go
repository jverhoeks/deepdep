// Package version holds per-ecosystem version semantics.
//
// There is no such thing as "a semver resolver". npm semver, PEP 440, Cargo's
// caret, Maven ranges and RubyGems ~> are genuinely different semantics, not
// dialects of one thing. Every ecosystem gets its own VersionScheme.
package version

// Version is an interface, deliberately. A concrete {Major,Minor,Patch,Pre}
// struct cannot represent PEP 440 epochs and post/dev releases, Maven's
// arbitrary segments and qualifier ordering, Go pseudo-versions, or a GitHub
// action ref ("v4", a branch name, a commit SHA) — all of which later ecosystem
// plugins must push through this same type. Comparison lives on the scheme, so
// widening the set of ecosystems moves nothing else.
type Version interface {
	String() string
}

// VersionMode selects how much of a range's satisfying space to expand. This is
// the switch between the two answers the tool exists to give.
type VersionMode string

const (
	// ModePinned: only an exact match. Used when a lockfile already decided.
	ModePinned VersionMode = "pinned"
	// ModeLatest: the highest satisfying version — what npm would install today.
	// This produces the "will" closure.
	ModeLatest VersionMode = "latest"
	// ModeAll: every satisfying version — what a future install could pull.
	// This produces the "can" closure, and is a conservative upper bound rather
	// than a prediction: npm itself always picks max-satisfying.
	ModeAll VersionMode = "all"
)

// BoundPolicy bounds range expansion. Without MaxVersionsPerRange, `can` mode on
// a popular package with hundreds of published versions explodes.
type BoundPolicy struct {
	Mode VersionMode
	// MaxVersionsPerRange keeps the newest N satisfying versions. Zero means
	// unbounded.
	MaxVersionsPerRange int
}

// VersionScheme is one ecosystem's version semantics.
type VersionScheme interface {
	Parse(s string) (Version, error)
	// IsExact reports whether a constraint admits exactly one version, e.g. npm
	// "1.2.3" or PEP 440 "==1.2.3". It is per-ecosystem because the syntaxes
	// differ, and it is what separates a hard manifest pin from a soft lockfile
	// pin over a wide range.
	IsExact(constraint string) bool
	Compare(a, b Version) int
	Satisfies(v Version, constraint string) (bool, error)
	Enumerate(constraint string, available []Version, p BoundPolicy) ([]Version, error)
}

// ExactVersion is an OPTIONAL scheme capability: naming the single version an
// exact constraint denotes, without asking a registry what exists.
//
// IsExact already reports that a constraint admits one version; this returns
// which one. The pair only looks redundant. An exact constraint is a complete
// answer on its own — `version = "3.5.1"` in a Terraform required_providers
// block names 3.5.1 and nothing else — so an ecosystem with no resolver behind
// it can still produce an auditable version rather than an unresolved frontier.
//
// It is a separate interface, and returns the version as a string, so that
// stripping "=" and any other per-ecosystem constraint syntax stays inside the
// scheme. The walker must not learn that syntax: it is the same rule that keeps
// it from synthesising constraint strings when applying a lockfile pin.
type ExactVersion interface {
	// Exact returns the version an exact constraint names. The bool is false
	// whenever IsExact would be false, and whenever the version does not parse.
	Exact(constraint string) (string, bool)
}

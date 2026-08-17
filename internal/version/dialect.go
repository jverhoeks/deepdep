package version

import "sort"

// Dialect is a constraint syntax that is NOT its ecosystem's native one.
//
// Some manifests declare dependencies for an ecosystem in a syntax that
// ecosystem's own tooling does not use. Poetry writes Cargo-style carets for
// PyPI packages; Pipenv and PDM have their own spellings; a future manifest will
// have another. Every one of them names packages that resolve, are advised on,
// and are compared as ordinary members of their ecosystem.
//
// The alternative — a version scheme per MANIFEST rather than per ecosystem —
// was tried on paper and rejected. It requires a dialect tag to travel with
// every requirement through the graph, the walker, the store and the rollup, and
// it splits an ecosystem's version ORDERING across implementations that must
// agree but have no way to check.
//
// Translation keeps exactly one scheme per ecosystem. The dialect converts the
// constraint at the point of extraction, where the offending text is still in
// hand and a failure can be reported against the file that contained it; from
// there the constraint is ordinary and every downstream layer stays unaware.
//
// A Dialect must be EXACT. It is not a place for approximation: a translation
// that widened or narrowed a range would be the confidently-wrong answer this
// tool exists to avoid. Where a form has no equivalent — Poetry's `||`
// alternation against PEP 440, which has no OR at any level — it must return an
// error so the caller can record an honest frontier instead.
type Dialect interface {
	// Name identifies the dialect, matching the tool that defines it.
	Name() string
	// Ecosystem is the PURL type whose native syntax Translate produces.
	Ecosystem() string
	// Translate rewrites one constraint into that native syntax. It returns an
	// error rather than an approximation when no equivalent exists.
	Translate(constraint string) (string, error)
}

// dialects is the registry. It is a fixed map rather than an init-time
// registration hook: the set is small, knowable by reading this file, and a
// dialect that silently failed to register would look exactly like a manifest
// with no dependencies.
var dialects = map[string]Dialect{
	PoetryDialect.Name(): PoetryDialect,
}

// DialectFor looks a dialect up by name.
func DialectFor(name string) (Dialect, bool) {
	d, ok := dialects[name]
	return d, ok
}

// DialectNames lists the registered dialects, sorted. Used by `deepdep tools`
// and by tests that assert the registry matches what is documented.
func DialectNames() []string {
	out := make([]string, 0, len(dialects))
	for n := range dialects {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Package walk drives extractors and resolvers to a bounded closure.
package walk

import (
	"time"

	"github.com/jverhoeks/deepdep/internal/version"
)

// Bounds keeps the closure finite.
//
// Defaults are chosen from real npm shapes: trees run 10–15 levels deep, so a
// shallow MaxDepth would leave a Declared frontier exactly where an ordinary
// SBOM tool reports concrete packages. Depth costs almost nothing under
// BFS-with-visited; MaxNodes is the bound that actually bites.
type Bounds struct {
	MaxDepth    int
	MaxNodes    int
	Concurrency int
	Version     version.BoundPolicy
	// AsOf is resolution time. Zero means "now" and disables filtering.
	AsOf time.Time
	// Pins maps "ecosystem/name" to the exact version a lockfile already chose.
	// In will-mode that decision is authoritative: "what installs today" means
	// the lockfile when there is one, which is also what `npm ls` reports.
	// Can-mode ignores pins, because its question is what a future install could
	// pull once the lock is regenerated.
	Pins map[string]string
}

// Defaults returns the shipping bounds.
func Defaults() Bounds {
	return Bounds{
		MaxDepth:    32,
		MaxNodes:    50000,
		Concurrency: 16,
		Version:     version.BoundPolicy{Mode: version.ModeLatest, MaxVersionsPerRange: 25},
	}
}

func (b Bounds) withDefaults() Bounds {
	if b.MaxDepth <= 0 {
		b.MaxDepth = 32
	}
	if b.MaxNodes <= 0 {
		b.MaxNodes = 50000
	}
	if b.Concurrency <= 0 {
		b.Concurrency = 16
	}
	if b.Version.Mode == "" {
		b.Version.Mode = version.ModeLatest
	}
	return b
}

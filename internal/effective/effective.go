// Package effective answers "what would actually be installed?".
//
// This is a DIFFERENT question from the closure. The closure says what can be
// reached; the effective resolution says what lands on disk, at which path, in
// how many copies. npm hoists a package to one shared copy where ranges allow
// and nests separate copies where they conflict, so the same package name can
// legitimately be installed several times at several versions.
package effective

import (
	"context"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// Instance is one on-disk copy.
//
// Locator is an opaque, package-manager-specific string — an npm node_modules
// path, a yarn PnP locator, a pnpm store path. Keeping it opaque is what lets
// one model serve package managers whose layouts are otherwise incompatible.
type Instance struct {
	Locator       string
	NodeID        graph.NodeID
	ParentLocator string
	// DerivedFrom is "lockfile" when read verbatim from a resolved lockfile, or
	// "simulated" when we computed the placement ourselves. Callers surface the
	// difference: one is fact, the other is inference.
	DerivedFrom string
}

// EffectiveResolver projects one package manager's resolution onto disk.
type EffectiveResolver interface {
	PackageManager() string
	Resolve(ctx context.Context, s source.Source) ([]Instance, error)
}

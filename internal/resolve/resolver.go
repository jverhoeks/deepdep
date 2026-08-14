// Package resolve expands a package name into the versions a registry offers
// and each version's own requirements.
//
// Resolution is registry-API-only. Nothing here ever executes code from the
// analyzed repository: no npm install, no pip install, no build. That is the
// central trust property of the tool — an analyzer that runs untrusted
// postinstall scripts to learn a dependency graph is a liability, not a tool.
package resolve

import (
	"context"
	"time"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/version"
)

// VersionInfo is a published version plus when it appeared.
//
// PublishedAt is what makes --as-of possible: replaying a past instant means
// ignoring versions that did not exist yet. A zero value means "unknown", which
// callers must treat as "cannot filter" rather than "always existed" when the
// user actually asked for a historical resolution.
type VersionInfo struct {
	Version     version.Version
	PublishedAt time.Time
}

// Requirement is one declared dependency of one concrete version.
type Requirement struct {
	Name       string
	Constraint string // the raw range, never a resolved pin
	Scope      graph.Scope
}

// Resolver is one ecosystem's registry client.
type Resolver interface {
	Ecosystem() string
	// Versions lists every published version. needPublished asks for publish
	// timestamps, which some registries only expose via a heavier document.
	Versions(ctx context.Context, name string, needPublished bool) ([]VersionInfo, error)
	Requirements(ctx context.Context, name string, v version.Version) ([]Requirement, error)
}

// Observations is the durable record of mutable documents we have fetched.
//
// A packument changes under us, so it can never live in the immutable cache.
// Recording (subject, body digest, when we saw it) is what makes a re-scan
// incremental across processes — and it is the substrate the bitemporal audit
// layer is built on. Resolvers work without one; they just re-fetch every time.
type Observations interface {
	// LastPackument returns the most recent observation of a package's metadata.
	LastPackument(ctx context.Context, ecosystem, name string) (sha string, observedAt time.Time, full bool, ok bool)
	RecordPackument(ctx context.Context, ecosystem, name, sha string, observedAt time.Time, full bool) error
}

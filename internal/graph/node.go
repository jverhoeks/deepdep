package graph

import "time"

// Completeness answers "how well do we know this?". It is orthogonal to a
// package's install State (installed/possible/unknown), which answers "will this
// land on disk?". Collapsing the two loses the distinction that makes the output
// trustworthy: a node can be possible+resolved (we know exactly which version a
// future install could pull) or installed+inferred (it lands on disk but we only
// guessed it from a shell line).
type Completeness string

const (
	// Resolved: exact version confirmed by the registry.
	Resolved Completeness = "resolved"
	// Declared: not expanded — a bound was hit, or the ref is mutable/unpinned.
	Declared Completeness = "declared"
	// Inferred: derived heuristically (parsed from RUN apt-get, hoisting simulation).
	Inferred Completeness = "inferred"
	// Opaque: statically undecidable (RUN make install, curl | sh).
	Opaque Completeness = "opaque"
)

// rank orders completeness so Add can upgrade monotonically. Higher wins.
func rank(c Completeness) int {
	switch c {
	case Resolved:
		return 3
	case Inferred:
		return 2
	case Declared:
		return 1
	default: // Opaque and the zero value
		return 0
	}
}

// Reason values. Machine-readable because an auditor needs "we hit a bound"
// queryable and distinct from "the registry 404'd"; free-text Note is not enough.
const (
	ReasonBoundDepth  = "bound:depth"
	ReasonBoundNodes  = "bound:nodes"
	ReasonOffline     = "offline"
	ReasonUnpinnedRef = "unpinned-ref"
	ReasonTimeout     = "bound:timeout"
)

// Node is one artifact: a package version, a container image, a CI action, or an
// opaque frontier where the closure becomes unknowable.
type Node struct {
	ID           NodeID       `json:"id"`
	Ecosystem    string       `json:"ecosystem,omitempty"`
	Name         string       `json:"name,omitempty"`
	Version      string       `json:"version,omitempty"`
	Completeness Completeness `json:"completeness"`
	Reason       string       `json:"reason,omitempty"`
	PublishedAt  time.Time    `json:"published_at,omitempty"`
	// ResolvedRef is the observed SHA or digest behind a mutable ref. Named to
	// avoid colliding with the Resolved completeness constant. Recorded on every
	// scan because tag->SHA history is NOT retroactively reconstructible: if we
	// do not write it down now, that instant is lost forever.
	ResolvedRef string `json:"resolved_ref,omitempty"`
	Source      string `json:"source,omitempty"`
	Note        string `json:"note,omitempty"`
}

package graph

// EdgeKind is how one artifact pulls in another. Package dependency is only one
// of the ways code ends up executing in a build.
type EdgeKind string

const (
	DependsOn EdgeKind = "depends_on" // manifest dependency
	BuildsOn  EdgeKind = "builds_on"  // OCI FROM / container image
	Invokes   EdgeKind = "invokes"    // CI uses:
	Installs  EdgeKind = "installs"   // toolchain installer, apt-get, opaque run step
)

// Scope drives the walker's expansion rules. npm installs devDependencies of the
// ROOT manifest only, so transitive dev edges must not be walked.
type Scope string

const (
	Prod     Scope = "prod"
	Dev      Scope = "dev"
	Peer     Scope = "peer"
	Optional Scope = "optional"
)

// Edge is one "pulls in" relation.
//
// Edges are deduplicated only on the FULL tuple. Two different parents depending
// on the same package are two distinct edges and both must survive — that
// multiplicity is exactly the "which threads pull this in?" information. But an
// identical relation seen twice (re-extraction, a can-mode revisit) must not
// double-insert, or every path count and rollup statistic silently inflates.
//
// Spec is named for the store: "constraint" is a reserved word in SQL.
type Edge struct {
	From  NodeID   `json:"from"`
	To    NodeID   `json:"to"`
	Kind  EdgeKind `json:"kind"`
	Spec  string   `json:"spec,omitempty"` // raw declared range, e.g. "^1.2.0"
	Scope Scope    `json:"scope,omitempty"`
}

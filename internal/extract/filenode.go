package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"path"

	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// BuildFilePrefix marks a node that stands for a build-definition FILE — a
// Dockerfile, a workflow, a CI config — rather than for something the build
// pulls in.
//
// Emitters key on this prefix, so it is exported and must stay stable.
const BuildFilePrefix = "pkg:generic/buildfile/"

// BuildFileNode identifies one build-definition file.
//
// Every extractor that reads such a file hangs its findings off this node
// instead of off the repository root, because attribution is PER-OCCURRENCE and
// nodes are deduplicated by id. `python:3.12-slim` used by four Dockerfiles is
// one node whose Source names only the first of them; `actions/checkout@v4` used
// by six workflows is one node whose Source names only the first. Without a file
// node the other five report having pulled in nothing, which is a silent
// omission dressed as a clean result.
//
// Edges carry multiplicity, nodes do not — so the attribution has to live on an
// edge, and that needs a distinct node at the other end.
//
// The path travels as the PURL subpath so two files stay distinct AND stay
// readable in a report; the hash keeps the version component well-formed.
func BuildFileNode(kind, p string) graph.Node {
	sum := sha256.Sum256([]byte(p))
	id := hex.EncodeToString(sum[:])[:12]
	u := packageurl.NewPackageURL(packageurl.TypeGeneric, "buildfile", kind, id, nil, "")
	return graph.Node{
		ID:        graph.NodeID(u.ToString() + "#" + p),
		Ecosystem: packageurl.TypeGeneric,
		Name:      path.Base(p),
		Version:   id,
		// Resolved: we read the file in full. Whether we could expand everything
		// INSIDE it is recorded on those nodes, not on this one.
		Completeness: graph.Resolved,
		Source:       p,
		Note:         p,
	}
}

// ReasonParseError marks a supply-chain file we recognised, tried to read, and
// could not.
const ReasonParseError = "error:parse"

// ParseErrorNode records a file whose parser failed.
//
// Distinct from a `no-extractor` frontier, and the difference matters to whoever
// reads the report: no-extractor means nobody has taught the tool this format
// yet, parse-error means we DO handle the format and this particular file broke
// us — which is a bug report, not a roadmap item. The parser's own message is
// carried verbatim so it is actionable without a re-run.
func ParseErrorNode(extractor, p string, err error) graph.Node {
	sum := sha256.Sum256([]byte(extractor + "\x00" + p))
	id := hex.EncodeToString(sum[:])[:12]
	u := packageurl.NewPackageURL(packageurl.TypeGeneric, "unparsed", path.Base(p), id, nil, "")
	return graph.Node{
		ID:           graph.NodeID(u.ToString() + "#" + p),
		Ecosystem:    packageurl.TypeGeneric,
		Name:         path.Base(p),
		Version:      id,
		Completeness: graph.Declared,
		Reason:       ReasonParseError,
		Source:       p,
		Note:         extractor + ": " + err.Error(),
	}
}

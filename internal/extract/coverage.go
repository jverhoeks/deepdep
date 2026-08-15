package extract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// Coverage reports supply-chain files that this build knows about but cannot yet
// expand.
//
// Every other extractor answers "what does this file pull in?". This one answers
// the question that actually determines whether the report can be trusted: "what
// did we see and walk past?". A scanner that silently omits a Dockerfile, an
// ansible playbook or a .mise.toml reads as though the repository has no such
// dependencies, which is a wrong answer rather than a partial one.
//
// Detected files become Declared frontier nodes with reason no-extractor. That
// also turns "which ecosystems should we support next?" into an evidence-backed
// question: run it across your repositories and count.
type Coverage struct{}

func (Coverage) Name() string { return "coverage" }

// Fallback: Coverage reports what we could NOT expand, so it must not fire on a
// file a real extractor already handled. The catalogue still LISTS those tools
// (`deepdep tools`) — recognition and non-expansion are different claims.
func (Coverage) Fallback() bool { return true }

func (Coverage) Match(p string) bool {
	_, _, ok := lookup(p)
	return ok
}

func (Coverage) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	tool, category, ok := lookup(f.Path)
	if !ok {
		return nil, nil, nil
	}
	sum := sha256.Sum256([]byte(f.Path))
	id := hex.EncodeToString(sum[:])[:12]
	p := packageurl.NewPackageURL(packageurl.TypeGeneric, "unanalysed", tool, id,
		packageurl.QualifiersFromMap(map[string]string{"category": string(category)}), "")

	n := graph.Node{
		ID:        graph.NodeID(p.ToString()),
		Ecosystem: packageurl.TypeGeneric,
		Name:      tool,
		Version:   id,
		// Declared, not Opaque: these files are perfectly analysable, we simply
		// have not written the extractor yet. Opaque is reserved for things that
		// are undecidable in principle, like `curl | sh`.
		Completeness: graph.Declared,
		Reason:       "no-extractor",
		Source:       f.Path,
		Note:         tool + " (" + string(category) + ") not yet expanded: " + f.Path,
	}
	return []graph.Edge{{From: "", To: n.ID, Kind: graph.Installs}}, []graph.Node{n}, nil
}

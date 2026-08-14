package emit

import (
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// CycloneDX writes a standards-compliant SBOM.
//
// This is a LOSSY PROJECTION of the "will" slice and nothing more. CycloneDX
// describes one resolved bill of materials; it cannot express a range space, a
// declared-but-unexpanded frontier, or an opaque shell step. Everything that is
// not Resolved is dropped here, which is exactly why the native JSON graph — not
// this — is the primary artifact.
func CycloneDX(w io.Writer, g *graph.Graph, m Meta) error {
	components := make([]cdx.Component, 0)
	for _, n := range g.Nodes() {
		if n.Completeness != graph.Resolved {
			continue
		}
		components = append(components, cdx.Component{
			BOMRef:     string(n.ID),
			Type:       cdx.ComponentTypeLibrary,
			Name:       n.Name,
			Version:    n.Version,
			PackageURL: string(n.ID),
		})
	}

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "deepdep",
				Version: m.ToolVersion,
			}},
		},
	}
	bom.Components = &components

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.EncodeVersion(bom, cdx.SpecVersion1_6)
}

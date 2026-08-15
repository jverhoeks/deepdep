package emit

import (
	"fmt"
	"io"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// Facts is registry-derived enrichment for one package version, supplied by the
// caller because the emitter has no store access.
//
// SourceRepo doubles as the supplier claim, with RepoProvenance recording how
// strongly it is attached. NTIA field 1 is "the entity that creates, defines and
// identifies the component" — the publishing project, NOT the registry that
// served the bytes. Filling supplier from registry.npmjs.org would pass a
// conformance check while answering a different question.
type Facts struct {
	Licenses       []string
	SourceRepo     string
	RepoProvenance string // SLSA_ATTESTATION | UNVERIFIED_METADATA
}

// CycloneDXOptions carries what a standards-conformant BOM needs beyond the graph.
type CycloneDXOptions struct {
	// Author is NTIA field 6. It defaults to the tool, which is honest but
	// usually wrong: the author is the organisation publishing the SBOM.
	Author string
	// Enrichment is keyed by node ID. Empty is legitimate — it means `deepdep
	// risk` has not run — and is reported as a named gap rather than rendering
	// as components that merely happen to have no licence.
	Enrichment map[graph.NodeID]Facts
	// Formulation adds the MBOM view: pipelines, base images and build steps.
	Formulation bool
}

// CycloneDX writes a CycloneDX 1.6 BOM.
//
// Still a lossy projection — CycloneDX cannot express a version-range space, so
// `can` mode collapses here and the native JSON graph remains the primary
// artifact. But it is no longer a projection of the RESOLVED slice only.
//
// Frontier nodes are emitted as components carrying their completeness and
// reason as properties. That is deliberate: NTIA practice #3 requires "known
// unknowns" to be flagged explicitly, and a BOM that silently omits a Dockerfile
// it could not expand reads as "this repo has none" — the exact failure this
// tool exists to avoid.
func CycloneDX(w io.Writer, g *graph.Graph, m Meta, opt CycloneDXOptions) error {
	var (
		components []cdx.Component
		isComp     = map[graph.NodeID]bool{}
		root       cdx.Component
		rootID     graph.NodeID
		noSupplier int
	)

	for _, n := range g.Nodes() {
		if isRoot(n, m) {
			rootID = n.ID
			root = cdx.Component{
				BOMRef:     string(n.ID),
				Type:       cdx.ComponentTypeApplication,
				Name:       orRepo(n.Name, m.Repo),
				Version:    n.Version,
				PackageURL: string(n.ID),
			}
			isComp[n.ID] = true
			continue
		}
		// An opaque shell step is not a component; it is a build STEP, and it
		// belongs in formulation. Listing `RUN make install` under components[]
		// as a library would be a category error that no consumer can undo.
		if isBuildStep(n) {
			continue
		}

		c := cdx.Component{
			BOMRef:     string(n.ID),
			Type:       componentType(n),
			Name:       n.Name,
			Version:    n.Version,
			PackageURL: string(n.ID),
		}
		if c.Name == "" {
			c.Name = string(n.ID) // NTIA field 2 must never be empty
		}

		f := opt.Enrichment[n.ID]
		if len(f.Licenses) > 0 {
			c.Licenses = licensesOf(f.Licenses)
		}
		if f.SourceRepo != "" {
			c.Supplier = &cdx.OrganizationalEntity{Name: supplierOf(f.SourceRepo)}
			c.ExternalReferences = &[]cdx.ExternalReference{{
				Type: cdx.ERTypeVCS, URL: "https://" + f.SourceRepo,
			}}
		} else {
			noSupplier++
		}

		c.Properties = propsFor(n, f)
		components = append(components, c)
		isComp[n.ID] = true
	}

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		// NTIA field 7. AsOf is the RESOLUTION instant, which is what the
		// document describes; wall-clock creation time would drift between two
		// runs of the same historical query and break reproducibility.
		Timestamp: orNowRFC3339(m.AsOf),
		Authors:   &[]cdx.OrganizationalContact{{Name: authorOf(opt.Author, m)}},
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeApplication, Name: "deepdep", Version: m.ToolVersion,
		}}},
		Properties: metaProps(m, opt, noSupplier, len(components)),
	}
	if rootID != "" {
		bom.Metadata.Component = &root
	}
	bom.Components = &components
	bom.Dependencies = dependenciesOf(g, isComp, rootID)

	if opt.Formulation {
		bom.Formulation = formulationOf(g, m)
	}

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.EncodeVersion(bom, cdx.SpecVersion1_6)
}

// dependenciesOf renders NTIA field 5.
//
// The presence rule carries meaning, and CycloneDX defines it precisely: a
// component ABSENT from dependencies[] has unknown dependencies; a component
// present with an empty dependsOn is known to have none. That maps exactly onto
// completeness — we walked the resolved ones and know they are leaves, and we
// did NOT walk the frontier ones. Emitting an empty array for a frontier node
// would assert knowledge we do not have.
//
// Refs are also filtered to components actually in the document. A dependsOn
// pointing at an omitted build step is a dangling ref, which makes the whole BOM
// fail validation.
func dependenciesOf(g *graph.Graph, isComp map[graph.NodeID]bool, root graph.NodeID) *[]cdx.Dependency {
	out := map[graph.NodeID]map[string]bool{}
	for _, n := range g.Nodes() {
		if !isComp[n.ID] {
			continue
		}
		if n.ID != root && n.Completeness != graph.Resolved {
			continue // unknown, not empty — leave it out
		}
		out[n.ID] = map[string]bool{}
	}
	for _, e := range g.Edges() {
		if out[e.From] == nil || !isComp[e.To] {
			continue
		}
		out[e.From][string(e.To)] = true
	}

	deps := make([]cdx.Dependency, 0, len(out))
	for ref, set := range out {
		on := make([]string, 0, len(set))
		for d := range set {
			on = append(on, d)
		}
		sort.Strings(on)
		d := cdx.Dependency{Ref: string(ref), Dependencies: &on}
		deps = append(deps, d)
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return &deps
}

func componentType(n graph.Node) cdx.ComponentType {
	switch {
	case strings.HasPrefix(string(n.ID), "pkg:oci/"):
		return cdx.ComponentTypeContainer
	case strings.HasPrefix(string(n.ID), "pkg:github/"),
		strings.HasPrefix(string(n.ID), "pkg:gitlab/"):
		return cdx.ComponentTypeApplication
	case n.Reason == "no-extractor":
		// A file we saw and could not expand. CycloneDX has a type for exactly
		// this, and it keeps the frontier from masquerading as a library.
		return cdx.ComponentTypeFile
	}
	return cdx.ComponentTypeLibrary
}

// isBuildStep reports whether a node is a shell invocation rather than an
// artifact. These go to formulation.
func isBuildStep(n graph.Node) bool {
	return strings.HasPrefix(string(n.ID), "pkg:generic/opaque@")
}

func isRoot(n graph.Node, m Meta) bool {
	return m.Ref != "" && strings.HasSuffix(string(n.ID), "@"+m.Ref)
}

func propsFor(n graph.Node, f Facts) *[]cdx.Property {
	p := []cdx.Property{{Name: "deepdep:completeness", Value: string(n.Completeness)}}
	if n.Reason != "" {
		p = append(p, cdx.Property{Name: "deepdep:reason", Value: n.Reason})
	}
	if n.Source != "" {
		p = append(p, cdx.Property{Name: "deepdep:source-file", Value: n.Source})
	}
	if n.ResolvedRef != "" {
		p = append(p, cdx.Property{Name: "deepdep:resolved-ref", Value: n.ResolvedRef})
	}
	if n.Note != "" {
		p = append(p, cdx.Property{Name: "deepdep:note", Value: n.Note})
	}
	// How strongly the supplier claim is attached. An SLSA attestation means the
	// artifact itself vouches for the repo; publisher metadata means somebody
	// typed a URL. Flattening them would let an unrelated repo launder a
	// package's provenance.
	if f.RepoProvenance != "" {
		p = append(p, cdx.Property{Name: "deepdep:supplier-provenance",
			Value: strings.ToLower(f.RepoProvenance)})
	}
	return &p
}

func metaProps(m Meta, opt CycloneDXOptions, noSupplier, total int) *[]cdx.Property {
	p := []cdx.Property{
		{Name: "deepdep:mode", Value: m.Mode},
		{Name: "deepdep:known-at", Value: orNowRFC3339(m.KnownAt)},
		// CISA SBOM Type. deepdep reads manifests, lockfiles and pipeline
		// definitions; it never observes a build, so this is a Source SBOM and
		// claiming Build would be false.
		{Name: "deepdep:cisa-sbom-type", Value: "source"},
	}
	if m.Ref != "" {
		p = append(p, cdx.Property{Name: "deepdep:git-ref", Value: m.Ref})
	}
	// Gaps are named, never silent: 1154 components with no licence because the
	// enrichment step was never run is a different document from 1154 components
	// genuinely without licences, and a consumer cannot tell them apart.
	if len(opt.Enrichment) == 0 {
		p = append(p, cdx.Property{Name: "deepdep:enrichment",
			Value: "none: licences and suppliers absent; run `deepdep risk` to populate them"})
	}
	if noSupplier > 0 {
		p = append(p, cdx.Property{Name: "deepdep:components-without-supplier",
			Value: fmt.Sprintf("%d of %d", noSupplier, total)})
	}
	return &p
}

// supplierOf reduces a project id to the publishing organisation:
// github.com/babel/babel -> babel. That is the entity NTIA field 1 asks for.
func supplierOf(repo string) string {
	parts := strings.Split(repo, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return repo
}

// licensesOf routes each string to the CycloneDX slot that can actually hold it.
//
// Three different slots, and picking the wrong one produces a document that
// decodes cleanly and fails the official schema:
//
//	"MIT"                      -> license.id          (validated against an 811-entry enum)
//	"Apache-2.0 OR MIT"        -> license.expression  (an SPDX EXPRESSION, not an id)
//	"Commons Clause"           -> license.name        (free text; honest about being unmatched)
//
// deps.dev returns expressions freely, and they are what broke the first
// version of this: 20 schema violations, all of them an expression stuffed into
// the id field, invisible to the Go decoder.
func licensesOf(ls []string) *cdx.Licenses {
	out := make(cdx.Licenses, 0, len(ls))
	for _, l := range ls {
		l = strings.TrimSpace(l)
		if l == "" || strings.EqualFold(l, "non-standard") {
			// An id slot filled with "non-standard" is worse than empty: it
			// validates while telling a licence scanner nothing.
			continue
		}
		switch {
		case isSPDXExpression(l):
			out = append(out, cdx.LicenseChoice{Expression: l})
		case spdxIDs[l]:
			out = append(out, cdx.LicenseChoice{License: &cdx.License{ID: l}})
		default:
			out = append(out, cdx.LicenseChoice{License: &cdx.License{Name: l}})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

// isSPDXExpression detects the compound forms. The operators are case-sensitive
// per the SPDX spec, so "MIT and Apache-2.0" is NOT an expression — it is a
// free-text string that happens to read like one, and belongs in name.
func isSPDXExpression(l string) bool {
	if strings.ContainsAny(l, "()") {
		return true
	}
	for _, op := range []string{" OR ", " AND ", " WITH "} {
		if strings.Contains(l, op) {
			return true
		}
	}
	return false
}

func authorOf(author string, m Meta) string {
	if author != "" {
		return author
	}
	return "deepdep " + m.ToolVersion
}

func orRepo(name, repo string) string {
	if name != "" {
		return name
	}
	if repo != "" {
		return repo
	}
	return "root"
}

package emit_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
)

// bom is the subset of CycloneDX these tests assert on.
type bom struct {
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Timestamp string `json:"timestamp"`
		Authors   []struct {
			Name string `json:"name"`
		} `json:"authors"`
		Component *struct {
			BOMRef string `json:"bom-ref"`
			Type   string `json:"type"`
			Name   string `json:"name"`
		} `json:"component"`
		Properties []struct{ Name, Value string } `json:"properties"`
	} `json:"metadata"`
	Components []struct {
		BOMRef     string `json:"bom-ref"`
		Type       string `json:"type"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		PackageURL string `json:"purl"`
		Supplier   *struct {
			Name string `json:"name"`
		} `json:"supplier"`
		Licenses []struct {
			License struct{ ID string } `json:"license"`
		} `json:"licenses"`
		Properties []struct{ Name, Value string } `json:"properties"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
	Formulation []struct {
		Workflows []struct {
			Name  string `json:"name"`
			Steps []struct {
				Name     string `json:"name"`
				Commands []struct {
					Executed string `json:"executed"`
				} `json:"commands"`
			} `json:"steps"`
			ResourceReferences []struct {
				Ref string `json:"ref"`
			} `json:"resourceReferences"`
		} `json:"workflows"`
	} `json:"formulation"`
}

func encode(t *testing.T, g *graph.Graph, m emit.Meta, o emit.CycloneDXOptions) bom {
	t.Helper()
	var buf bytes.Buffer
	if err := emit.CycloneDX(&buf, g, m, o); err != nil {
		t.Fatal(err)
	}
	var b bom
	if err := json.Unmarshal(buf.Bytes(), &b); err != nil {
		t.Fatalf("emitted invalid JSON: %v", err)
	}
	return b
}

// fixture mirrors a real scan: a root, two packages, a base image, a CI
// template and an opaque build step.
func fixture() (*graph.Graph, emit.Meta) {
	g := graph.New()
	root := graph.NodeID("pkg:generic/app@deadbeef")
	g.Add(graph.Node{ID: root, Name: "app", Version: "deadbeef", Completeness: graph.Resolved})
	g.Add(graph.Node{ID: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Completeness: graph.Resolved})
	g.Add(graph.Node{ID: "pkg:npm/ms@2.1.3", Name: "ms", Version: "2.1.3", Completeness: graph.Resolved})
	g.Add(graph.Node{ID: "pkg:oci/node@24-alpine", Name: "node", Version: "24-alpine",
		Completeness: graph.Declared, Reason: graph.ReasonUnpinnedRef, Source: ".gitlab-ci.yml"})
	g.Add(graph.Node{ID: "pkg:generic/unanalysed/docker-compose@abc123", Name: "docker-compose",
		Completeness: graph.Declared, Reason: "no-extractor", Source: "docker-compose.yml"})
	g.Add(graph.Node{ID: "pkg:generic/opaque@aaaa1111", Completeness: graph.Opaque,
		Note: "apt-get install -y python3", Source: ".gitlab-ci.yml"})

	g.Link(graph.Edge{From: root, To: "pkg:npm/lodash@4.17.21", Kind: graph.DependsOn, Spec: "^4.0.0", Scope: graph.Prod})
	g.Link(graph.Edge{From: "pkg:npm/lodash@4.17.21", To: "pkg:npm/ms@2.1.3", Kind: graph.DependsOn, Spec: "^2.0.0", Scope: graph.Prod})
	g.Link(graph.Edge{From: root, To: "pkg:oci/node@24-alpine", Kind: graph.BuildsOn})
	g.Link(graph.Edge{From: root, To: "pkg:generic/opaque@aaaa1111", Kind: graph.Installs})
	g.Link(graph.Edge{From: root, To: "pkg:generic/unanalysed/docker-compose@abc123", Kind: graph.Installs})

	return g, emit.Meta{
		AsOf: time.Unix(1765000000, 0).UTC(), KnownAt: time.Unix(1765000000, 0).UTC(),
		Ref: "deadbeef", Repo: "app", Mode: "will", ToolVersion: "0.1.0",
	}
}

// TestNTIAMinimumElements is the handbook's own conformance test, inlined.
func TestNTIAMinimumElements(t *testing.T) {
	g, m := fixture()
	b := encode(t, g, m, emit.CycloneDXOptions{Enrichment: map[graph.NodeID]emit.Facts{
		"pkg:npm/lodash@4.17.21": {Licenses: []string{"MIT"}, SourceRepo: "github.com/lodash/lodash",
			RepoProvenance: "SLSA_ATTESTATION"},
	}})

	if b.Metadata.Timestamp == "" {
		t.Error("NTIA field 7 (timestamp) missing")
	}
	if len(b.Metadata.Authors) == 0 || b.Metadata.Authors[0].Name == "" {
		t.Error("NTIA field 6 (author) missing")
	}
	if b.Metadata.Component == nil || b.Metadata.Component.BOMRef == "" {
		t.Error("metadata.component (the subject of the BOM) missing")
	}
	for _, c := range b.Components {
		if c.Name == "" {
			t.Errorf("NTIA field 2 (name) empty for %s", c.BOMRef)
		}
		if c.PackageURL == "" {
			t.Errorf("NTIA field 4 (unique identifier) missing for %s", c.BOMRef)
		}
	}
	if len(b.Dependencies) == 0 {
		t.Fatal("NTIA field 5 (dependency relationships) missing entirely")
	}

	var lodash bool
	for _, c := range b.Components {
		if c.BOMRef != "pkg:npm/lodash@4.17.21" {
			continue
		}
		lodash = true
		if c.Supplier == nil || c.Supplier.Name != "lodash" {
			t.Errorf("NTIA field 1: supplier = %+v, want the publishing org", c.Supplier)
		}
		if len(c.Licenses) != 1 || c.Licenses[0].License.ID != "MIT" {
			t.Errorf("licence = %+v, want MIT", c.Licenses)
		}
	}
	if !lodash {
		t.Error("lodash missing from components")
	}
}

// TestNoDanglingDependencyRefs: every ref and every dependsOn target must exist
// as a component (or be the metadata component). A dangling ref invalidates the
// whole BOM, and opaque build steps are deliberately not components.
func TestNoDanglingDependencyRefs(t *testing.T) {
	g, m := fixture()
	b := encode(t, g, m, emit.CycloneDXOptions{Formulation: true})

	known := map[string]bool{}
	for _, c := range b.Components {
		known[c.BOMRef] = true
	}
	if b.Metadata.Component != nil {
		known[b.Metadata.Component.BOMRef] = true
	}
	for _, d := range b.Dependencies {
		if !known[d.Ref] {
			t.Errorf("dependencies[].ref %q is not a component in this document", d.Ref)
		}
		for _, on := range d.DependsOn {
			if !known[on] {
				t.Errorf("dependsOn %q (from %q) is not a component in this document", on, d.Ref)
			}
		}
	}
}

// TestBuildStepsAreNotComponents: `apt-get install` is a build step, not a
// library. Listing it under components[] is a category error a consumer cannot
// undo.
func TestBuildStepsAreNotComponents(t *testing.T) {
	g, m := fixture()
	b := encode(t, g, m, emit.CycloneDXOptions{Formulation: true})
	for _, c := range b.Components {
		if c.BOMRef == "pkg:generic/opaque@aaaa1111" {
			t.Fatal("an opaque shell step must not appear in components[]")
		}
	}
}

// TestFrontierNodesAreEmittedAsKnownUnknowns — NTIA practice #3. A BOM that
// silently omits a docker-compose.yml it could not expand reads as "this repo
// has none".
func TestFrontierNodesAreEmittedAsKnownUnknowns(t *testing.T) {
	g, m := fixture()
	b := encode(t, g, m, emit.CycloneDXOptions{})

	for _, c := range b.Components {
		if c.BOMRef != "pkg:generic/unanalysed/docker-compose@abc123" {
			continue
		}
		if c.Type != "file" {
			t.Errorf("unexpanded file type = %q, want file", c.Type)
		}
		props := map[string]string{}
		for _, p := range c.Properties {
			props[p.Name] = p.Value
		}
		if props["deepdep:completeness"] != "declared" || props["deepdep:reason"] != "no-extractor" {
			t.Errorf("frontier props = %v, want completeness+reason", props)
		}
		return
	}
	t.Error("the unexpanded docker-compose.yml was dropped from the BOM")
}

// TestDependencyPresenceMeansKnown: CycloneDX distinguishes "known to have no
// dependencies" (present, empty dependsOn) from "dependencies unknown" (absent).
// That maps onto completeness, and asserting the wrong one is a false claim.
func TestDependencyPresenceMeansKnown(t *testing.T) {
	g, m := fixture()
	b := encode(t, g, m, emit.CycloneDXOptions{})

	refs := map[string]bool{}
	for _, d := range b.Dependencies {
		refs[d.Ref] = true
	}
	if !refs["pkg:npm/ms@2.1.3"] {
		t.Error("a resolved leaf must be PRESENT with an empty dependsOn (known to have none)")
	}
	if refs["pkg:oci/node@24-alpine"] {
		t.Error("an unexpanded frontier must be ABSENT from dependencies[] (unknown, not empty)")
	}
}

// TestMissingEnrichmentIsANamedGap: 1154 components with no licence because the
// enrichment step never ran is a different document from 1154 genuinely
// licence-free components, and a consumer cannot tell them apart unaided.
func TestMissingEnrichmentIsANamedGap(t *testing.T) {
	g, m := fixture()
	b := encode(t, g, m, emit.CycloneDXOptions{})

	props := map[string]string{}
	for _, p := range b.Metadata.Properties {
		props[p.Name] = p.Value
	}
	if props["deepdep:enrichment"] == "" {
		t.Error("an unenriched BOM must say so in metadata.properties")
	}
	if props["deepdep:components-without-supplier"] == "" {
		t.Error("the supplier gap must be counted, not silent")
	}
	if props["deepdep:cisa-sbom-type"] != "source" {
		t.Errorf("cisa-sbom-type = %q, want source — deepdep never observes a build",
			props["deepdep:cisa-sbom-type"])
	}
}

// TestFormulationCarriesPipelineEvidence: base images and build steps are what
// an ordinary SBOM has no vocabulary for.
func TestFormulationCarriesPipelineEvidence(t *testing.T) {
	g, m := fixture()
	b := encode(t, g, m, emit.CycloneDXOptions{Formulation: true})

	if len(b.Formulation) == 0 || len(b.Formulation[0].Workflows) == 0 {
		t.Fatal("no formulation emitted")
	}
	var found bool
	for _, w := range b.Formulation[0].Workflows {
		if w.Name != ".gitlab-ci.yml" {
			continue
		}
		found = true
		if len(w.Steps) != 1 || w.Steps[0].Commands[0].Executed != "apt-get install -y python3" {
			t.Errorf("steps = %+v, want the shell command verbatim", w.Steps)
		}
		if len(w.ResourceReferences) != 1 || w.ResourceReferences[0].Ref != "pkg:oci/node@24-alpine" {
			t.Errorf("resourceReferences = %+v, want the base image bom-ref", w.ResourceReferences)
		}
	}
	if !found {
		t.Error("the .gitlab-ci.yml workflow is missing from formulation")
	}
}

// TestFormulationPreservesDocumentOrder pins the property the step ordering
// relies on: the graph keeps edges in insertion order, and the walker's seed
// phase is sequential, so "checkout, restore, compile, test" survives. If a
// future concurrent seed scrambles this, formulation silently starts lying
// about build order — so it is asserted rather than assumed.
func TestFormulationPreservesDocumentOrder(t *testing.T) {
	g := graph.New()
	root := graph.NodeID("pkg:generic/app@deadbeef")
	g.Add(graph.Node{ID: root, Name: "app", Version: "deadbeef", Completeness: graph.Resolved})

	want := []string{"checkout", "restore", "compile", "test"}
	for i, cmd := range want {
		id := graph.NodeID("pkg:generic/opaque@step" + string(rune('a'+i)))
		g.Add(graph.Node{ID: id, Completeness: graph.Opaque, Note: cmd, Source: "ci.yml"})
		g.Link(graph.Edge{From: root, To: id, Kind: graph.Installs})
	}

	b := encode(t, g, emit.Meta{Ref: "deadbeef", Repo: "app"}, emit.CycloneDXOptions{Formulation: true})
	if len(b.Formulation) == 0 || len(b.Formulation[0].Workflows) != 1 {
		t.Fatal("expected exactly one workflow")
	}
	var got []string
	for _, s := range b.Formulation[0].Workflows[0].Steps {
		got = append(got, s.Commands[0].Executed)
	}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("step order = %v, want %v (edge insertion order must be preserved)", got, want)
		}
	}
}

// TestDeterministicAcrossRuns — byte-identical emission is a global constraint.
func TestCycloneDXIsDeterministic(t *testing.T) {
	var a, c bytes.Buffer
	for _, w := range []*bytes.Buffer{&a, &c} {
		g, m := fixture()
		if err := emit.CycloneDX(w, g, m, emit.CycloneDXOptions{Formulation: true,
			Enrichment: map[graph.NodeID]emit.Facts{
				"pkg:npm/lodash@4.17.21": {Licenses: []string{"MIT"}, SourceRepo: "github.com/lodash/lodash"},
			}}); err != nil {
			t.Fatal(err)
		}
	}
	if a.String() != c.String() {
		t.Fatal("emission is nondeterministic — a map iteration leaked into the output")
	}
}

// TestLicenseSlotRouting: the CycloneDX schema validates license.id against an
// 811-entry SPDX enum. deps.dev returns EXPRESSIONS ("Apache-2.0 OR MIT") as
// freely as ids, and putting one in the id slot yields a document that decodes
// cleanly and fails the official schema — 20 times, on the first real run.
func TestLicenseSlotRouting(t *testing.T) {
	cases := []struct{ in, slot, want string }{
		{"MIT", "id", "MIT"},
		{"Apache-2.0 OR MIT", "expression", "Apache-2.0 OR MIT"},
		{"MPL-2.0 AND (Apache-2.0 OR MIT)", "expression", "MPL-2.0 AND (Apache-2.0 OR MIT)"},
		{"GPL-2.0-or-later WITH Bison-exception-2.2", "expression", "GPL-2.0-or-later WITH Bison-exception-2.2"},
		{"Commons Clause", "name", "Commons Clause"},
		// Lower-case operators are NOT SPDX expressions; free text that reads
		// like one must not be promoted into the expression slot.
		{"MIT and Apache-2.0", "name", "MIT and Apache-2.0"},
	}
	for _, c := range cases {
		g, m := fixture()
		b := encode(t, g, m, emit.CycloneDXOptions{Enrichment: map[graph.NodeID]emit.Facts{
			"pkg:npm/lodash@4.17.21": {Licenses: []string{c.in}},
		}})
		var raw map[string]any
		for _, comp := range b.Components {
			if comp.BOMRef == "pkg:npm/lodash@4.17.21" {
				raw = licenseRaw(t, g, m, c.in)
			}
		}
		if raw == nil {
			t.Fatalf("%q: lodash missing", c.in)
		}
		switch c.slot {
		case "expression":
			if raw["expression"] != c.want {
				t.Errorf("%q -> %v, want expression=%q", c.in, raw, c.want)
			}
		default:
			lic, _ := raw["license"].(map[string]any)
			if lic == nil || lic[c.slot] != c.want {
				t.Errorf("%q -> %v, want license.%s=%q", c.in, raw, c.slot, c.want)
			}
		}
	}
}

// licenseRaw re-encodes and digs out lodash's first licence entry untyped, so
// the test sees the actual JSON slot rather than a Go struct field.
func licenseRaw(t *testing.T, g *graph.Graph, m emit.Meta, license string) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := emit.CycloneDX(&buf, g, m, emit.CycloneDXOptions{
		Enrichment: map[graph.NodeID]emit.Facts{
			"pkg:npm/lodash@4.17.21": {Licenses: []string{license}},
		}}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct {
			BOMRef   string           `json:"bom-ref"`
			Licenses []map[string]any `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Components {
		if c.BOMRef == "pkg:npm/lodash@4.17.21" && len(c.Licenses) > 0 {
			return c.Licenses[0]
		}
	}
	return nil
}

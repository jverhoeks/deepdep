package emit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
)

func meta() emit.Meta {
	ts := time.Unix(1765000000, 0).UTC()
	return emit.Meta{
		AsOf: ts, KnownAt: ts, Ref: "deadbeef", Repo: "fixture",
		Mode: "can", ToolVersion: "0.1.0",
	}
}

// Go randomises map iteration, so without explicit ordering two identical runs
// emit different bytes and the reproducibility guarantee cannot be tested.
func TestJSONIsByteIdenticalAcrossRuns(t *testing.T) {
	build := func() *graph.Graph {
		g := graph.New()
		for i := 0; i < 200; i++ {
			id := graph.NodeID(fmt.Sprintf("pkg:npm/p%03d@1.0.0", i))
			g.Add(graph.Node{ID: id, Completeness: graph.Resolved})
			g.Link(graph.Edge{From: "root", To: id, Kind: graph.DependsOn, Spec: "^1.0.0"})
		}
		return g
	}
	var a, b bytes.Buffer
	if err := emit.JSON(&a, build(), meta()); err != nil {
		t.Fatal(err)
	}
	if err := emit.JSON(&b, build(), meta()); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("emission is nondeterministic — map order leaked into output")
	}
}

func TestJSONRecordsBothTimeAxesAndFrontiers(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: "pkg:npm/lodash@4.17.21", Completeness: graph.Resolved})
	g.Add(graph.Node{ID: "pkg:generic/opaque@abc123", Completeness: graph.Opaque, Note: "make install"})
	g.Add(graph.Node{ID: "pkg:npm/x@1.0.0", Completeness: graph.Declared, Reason: graph.ReasonBoundDepth})
	g.Add(graph.Node{ID: "pkg:github/actions/checkout@v4", Completeness: graph.Declared, Reason: graph.ReasonUnpinnedRef})

	var buf bytes.Buffer
	if err := emit.JSON(&buf, g, meta()); err != nil {
		t.Fatal(err)
	}

	var out struct {
		AsOf    string `json:"as_of"`
		KnownAt string `json:"known_at"`
		Ref     string `json:"ref"`
		Mode    string `json:"mode"`
		Summary struct {
			Total, Resolved, Declared, Inferred, Opaque int
		} `json:"summary"`
		BoundsHit []string `json:"bounds_hit"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.AsOf == "" || out.KnownAt == "" {
		t.Error("both time axes must be recorded, even though v1 consumes only one")
	}
	if out.Ref != "deadbeef" {
		t.Errorf("ref = %q", out.Ref)
	}
	if out.Summary.Total != 4 || out.Summary.Opaque != 1 || out.Summary.Declared != 2 {
		t.Errorf("summary = %+v", out.Summary)
	}
	// A bound that fired must be shouted, not left for the reader to infer from
	// a suspiciously round node count.
	if len(out.BoundsHit) == 0 {
		t.Error("bounds_hit must name the reasons the closure stopped")
	}
}

// TestCycloneDXKeepsFrontiersDropsBuildSteps replaces an earlier assertion that
// the BOM contained ONLY resolved components. That was wrong twice over: NTIA
// practice #3 requires "known unknowns" to be flagged rather than omitted, and
// dependencies[] cannot reference a node the document dropped. What genuinely
// does not belong is a shell step — `RUN make install` is not a library, and it
// is carried in formulation instead.
func TestCycloneDXKeepsFrontiersDropsBuildSteps(t *testing.T) {
	g := graph.New()
	g.Add(graph.Node{ID: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Completeness: graph.Resolved})
	g.Add(graph.Node{ID: "pkg:generic/opaque@abc123", Name: "opaque", Completeness: graph.Opaque, Note: "make install"})
	g.Add(graph.Node{ID: "pkg:npm/x@1.0.0", Name: "x", Version: "1.0.0", Completeness: graph.Declared, Reason: "bound:depth"})

	var buf bytes.Buffer
	if err := emit.CycloneDX(&buf, g, meta(), emit.CycloneDXOptions{}); err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			PURL       string                         `json:"purl"`
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q", bom.BOMFormat)
	}

	got := map[string]map[string]string{}
	for _, c := range bom.Components {
		props := map[string]string{}
		for _, p := range c.Properties {
			props[p.Name] = p.Value
		}
		got[c.PURL] = props
	}
	if _, ok := got["pkg:generic/opaque@abc123"]; ok {
		t.Error("a shell step must not be a component")
	}
	if got["pkg:npm/lodash@4.17.21"]["deepdep:completeness"] != "resolved" {
		t.Errorf("lodash props = %v", got["pkg:npm/lodash@4.17.21"])
	}
	if got["pkg:npm/x@1.0.0"]["deepdep:reason"] != "bound:depth" {
		t.Errorf("a bounded frontier must be emitted WITH its reason, got %v", got["pkg:npm/x@1.0.0"])
	}
}

// A package can be both a prod and a peer dependency of the same parent under
// the same range. Those are two distinct edges differing only in scope, so the
// sort key must include scope or their order is undefined and output is not
// reproducible. This is a real failure found by the acceptance check, not a
// hypothetical.
func TestEdgeOrderIsTotalIncludingScope(t *testing.T) {
	build := func() *graph.Graph {
		g := graph.New()
		for i := 0; i < 60; i++ {
			to := graph.NodeID(fmt.Sprintf("pkg:npm/p%03d@1.0.0", i))
			g.Add(graph.Node{ID: to, Completeness: graph.Resolved})
			for _, sc := range []graph.Scope{graph.Peer, graph.Prod, graph.Optional} {
				g.Link(graph.Edge{From: "root", To: to, Kind: graph.DependsOn, Spec: "^1.0.0", Scope: sc})
			}
		}
		return g
	}
	var a, b bytes.Buffer
	if err := emit.JSON(&a, build(), meta()); err != nil {
		t.Fatal(err)
	}
	if err := emit.JSON(&b, build(), meta()); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("edges differing only in scope have no defined order")
	}
}

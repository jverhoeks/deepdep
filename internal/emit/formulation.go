package emit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// formulationOf renders the MBOM view: how the artifact is built, not what it
// contains.
//
// CycloneDX `formulation` models workflows → tasks → steps, with inputs
// (source refs, container base images), outputs and resource references. That is
// the shape of the question "what does the pipeline pull in?", which an ordinary
// SBOM has no vocabulary for — a base image and a third-party CI action execute
// with the build's credentials but appear in no components[] list.
//
// Resolution is FILE level, not job level. One workflow per pipeline file; no
// tasks[]. Job membership is per-occurrence data and nodes are deduplicated by
// id, so it does not survive into the graph — data-platform has 4 `invokes`
// edges against 2 template nodes and 72 `installs` edges against 26 step nodes.
// Recovering job granularity needs the pipeline FILE to become a node so the
// multiplicity lives on edges. Until then this says so in a property rather than
// inventing a task structure it cannot support.
func formulationOf(g *graph.Graph, m Meta) *[]cdx.Formula {
	byID := map[graph.NodeID]graph.Node{}
	for _, n := range g.Nodes() {
		byID[n.ID] = n
	}

	// Step ORDER comes from edge insertion order, which is extraction order:
	// the walker's seed phase is sequential (WalkIf → one extractor → one edge
	// at a time), and extractors emit in document order. That makes "checkout,
	// restore, compile, test" survive, which is most of what a build view is
	// for. TestFormulationPreservesDocumentOrder pins the property so a future
	// concurrent seed cannot silently scramble it.
	type wf struct {
		steps []cdx.TaskStep
		refs  []cdx.ResourceReferenceChoice
		seen  map[graph.NodeID]bool
	}
	files := map[string]*wf{}
	var order []string

	for _, e := range g.Edges() {
		n, ok := byID[e.To]
		if !ok || n.Source == "" {
			continue
		}
		// Only two things make a file a workflow: it runs commands, or it pulls
		// in something that executes. Grouping on "any non-DependsOn edge" turned
		// all 46 coverage frontiers into workflows — a .npmrc listed as a build
		// pipeline whose sole resource is itself. A frontier marker is a
		// component (a known unknown), never a workflow.
		switch {
		case e.Kind == graph.BuildsOn, e.Kind == graph.Invokes:
			// a base image, an action, a called template
		case e.Kind == graph.Installs && isBuildStep(n):
			// a shell command
		default:
			continue
		}
		w := files[n.Source]
		if w == nil {
			w = &wf{seen: map[graph.NodeID]bool{}}
			files[n.Source] = w
			order = append(order, n.Source)
		}
		if w.seen[n.ID] {
			continue
		}
		w.seen[n.ID] = true

		if isBuildStep(n) {
			w.steps = append(w.steps, cdx.TaskStep{
				Name:     stepName(n.Note),
				Commands: &[]cdx.TaskCommand{{Executed: n.Note}},
			})
			continue
		}
		// A base image or a called action/template: an INPUT to the build, and
		// a bom-ref into components[] so the two views join.
		w.refs = append(w.refs, cdx.ResourceReferenceChoice{Ref: string(n.ID)})
	}

	out := make([]cdx.Formula, 0, 1)
	workflows := make([]cdx.Workflow, 0, len(order))
	for _, path := range order {
		w := files[path]
		if len(w.steps) == 0 && len(w.refs) == 0 {
			continue
		}
		flow := cdx.Workflow{
			BOMRef: "deepdep-workflow-" + shortHash(path),
			UID:    path,
			Name:   path,
			// Always `build`. Inferring `test` or `deploy` from step text would be
			// a heuristic dressed as a fact, and CycloneDX gives no way to mark a
			// task type as guessed.
			TaskTypes: &[]cdx.TaskType{cdx.TaskTypeBuild},
			Properties: &[]cdx.Property{
				{Name: "deepdep:resolution", Value: "file-level; job/task grouping is not recoverable from a deduplicated graph"},
				{Name: "deepdep:step-order", Value: "document order as extracted"},
			},
		}
		if len(w.steps) > 0 {
			flow.Steps = &w.steps
		}
		if len(w.refs) > 0 {
			refs := w.refs
			flow.ResourceReferences = &refs
			inputs := make([]cdx.TaskInput, 0, len(refs))
			for i := range refs {
				r := refs[i]
				inputs = append(inputs, cdx.TaskInput{Resource: &r})
			}
			flow.Inputs = &inputs
		}
		if !m.AsOf.IsZero() {
			flow.TimeStart = m.AsOf.UTC().Format(time.RFC3339)
		}
		workflows = append(workflows, flow)
	}
	if len(workflows) == 0 {
		return nil
	}

	out = append(out, cdx.Formula{
		BOMRef:    "deepdep-formulation",
		Workflows: &workflows,
	})
	return &out
}

// stepName is a one-line label. The full command always survives in
// Commands[].Executed, so truncating here loses nothing.
func stepName(cmd string) string {
	line := strings.TrimSpace(cmd)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if len(line) > 72 {
		line = line[:71] + "…"
	}
	if line == "" {
		return "step"
	}
	return line
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func orNowRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

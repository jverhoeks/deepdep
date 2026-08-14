package extract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// GHActions reads GitHub Actions workflows.
//
// This is where the tool stops being a package scanner. One workflow file yields
// three different node types — third-party actions, container images, and opaque
// shell frontiers — none of which appear in any SBOM, and all of which execute
// with the same privileges as the build.
type GHActions struct{}

func (GHActions) Name() string { return "github-actions" }

func (GHActions) Match(p string) bool {
	dir, file := path.Split(p)
	if strings.TrimSuffix(dir, "/") != ".github/workflows" {
		return false
	}
	ext := path.Ext(file)
	return ext == ".yml" || ext == ".yaml"
}

// A 40-character hex ref is a commit SHA: immutable, and the only form of
// `uses:` that is genuinely pinned. Everything else is a tag or branch that the
// upstream owner can silently re-point.
var shaRe = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

type workflow struct {
	Jobs map[string]struct {
		Uses      string `yaml:"uses"` // reusable workflow call
		Container struct {
			Image string `yaml:"image"`
		} `yaml:"container"`
		Steps []struct {
			Uses string `yaml:"uses"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func (GHActions) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	var wf workflow
	if err := yaml.Unmarshal(f.Data, &wf); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", f.Path, err)
	}

	var (
		edges []graph.Edge
		nodes []graph.Node
		seen  = map[graph.NodeID]bool{}
	)
	emit := func(n graph.Node, kind graph.EdgeKind) {
		if seen[n.ID] {
			return
		}
		seen[n.ID] = true
		n.Source = f.Path
		nodes = append(nodes, n)
		edges = append(edges, graph.Edge{From: "", To: n.ID, Kind: kind})
	}

	// Sorted job names keep extraction deterministic; YAML maps decode unordered.
	for _, name := range sortedJobs(wf) {
		job := wf.Jobs[name]

		if job.Uses != "" {
			n, err := usesNode(job.Uses)
			if err != nil {
				return nil, nil, err
			}
			emit(n, graph.Invokes)
		}
		if img := job.Container.Image; img != "" {
			n, err := imageNode(img)
			if err != nil {
				return nil, nil, err
			}
			emit(n, graph.BuildsOn)
		}
		for _, s := range job.Steps {
			switch {
			case s.Uses != "":
				if strings.HasPrefix(s.Uses, "docker://") {
					n, err := imageNode(strings.TrimPrefix(s.Uses, "docker://"))
					if err != nil {
						return nil, nil, err
					}
					emit(n, graph.BuildsOn)
					continue
				}
				n, err := usesNode(s.Uses)
				if err != nil {
					return nil, nil, err
				}
				emit(n, graph.Invokes)
			case s.Run != "":
				emit(opaqueNode(s.Run), graph.Installs)
			}
		}
	}
	return edges, nodes, nil
}

func sortedJobs(wf workflow) []string {
	out := make([]string, 0, len(wf.Jobs))
	for k := range wf.Jobs {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ { // small n; insertion sort avoids an import
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// usesNode parses `org/repo@ref` and `org/repo/path/to/workflow.yml@ref`.
//
// The path becomes a PURL subpath rather than being discarded: two reusable
// workflows in one repository are different things and must not collapse into a
// single node.
func usesNode(uses string) (graph.Node, error) {
	spec, ref, _ := strings.Cut(uses, "@")
	parts := strings.Split(spec, "/")
	if len(parts) < 2 {
		return graph.Node{}, fmt.Errorf("unrecognised uses: %q", uses)
	}
	org, repo := parts[0], parts[1]
	subpath := strings.Join(parts[2:], "/")

	p := packageurl.NewPackageURL(packageurl.TypeGithub, org, repo, ref, nil, subpath)
	n := graph.Node{
		ID:        graph.NodeID(p.ToString()),
		Ecosystem: packageurl.TypeGithub,
		Name:      org + "/" + repo,
		Version:   ref,
	}
	if shaRe.MatchString(ref) {
		n.Completeness = graph.Resolved
		n.ResolvedRef = ref
	} else {
		// A tag or branch can be re-pointed at any time, and no API exposes what
		// it pointed at in the past — so this is Declared until we observe a SHA.
		n.Completeness = graph.Declared
		n.Reason = graph.ReasonUnpinnedRef
	}
	return n, nil
}

// imageNode parses `name:tag`, including a registry host and namespace.
//
// v1 records the tag as the PURL version and marks the node Declared. The oci
// PURL type properly wants an immutable digest as the version with the tag in a
// ?tag= qualifier; digest resolution arrives with the OCI extractor, at which
// point these become Resolved.
func imageNode(image string) (graph.Node, error) {
	ref := image
	name := image
	if i := strings.LastIndex(image, ":"); i > 0 && !strings.Contains(image[i:], "/") {
		name, ref = image[:i], image[i+1:]
	} else {
		ref = "latest"
	}

	namespace := ""
	if i := strings.LastIndex(name, "/"); i >= 0 {
		namespace, name = name[:i], name[i+1:]
	}
	p := packageurl.NewPackageURL(packageurl.TypeOCI, namespace, name, ref, nil, "")
	return graph.Node{
		ID:           graph.NodeID(p.ToString()),
		Ecosystem:    packageurl.TypeOCI,
		Name:         name,
		Version:      ref,
		Completeness: graph.Declared,
		Reason:       graph.ReasonUnpinnedRef,
	}, nil
}

// opaqueNode records a shell step we cannot analyse.
//
// `RUN make install` and `curl | sh` are statically undecidable. Reporting a
// clean graph that quietly dropped them would be a wrong answer; naming the
// eleven places the closure becomes unknowable is the feature.
func opaqueNode(cmd string) graph.Node {
	n := hashedNode("opaque", cmd)
	n.Completeness = graph.Opaque
	return n
}

// hashedNode mints a stable identity for something that has no natural version:
// a shell command, a URL, a template name. Two identical subjects collapse to
// one node, which is what makes "the same command in five jobs" read as one
// frontier rather than five.
func hashedNode(kind, subject string) graph.Node {
	sum := sha256.Sum256([]byte(subject))
	id := hex.EncodeToString(sum[:])[:12]
	p := packageurl.NewPackageURL(packageurl.TypeGeneric, "", kind, id, nil, "")
	return graph.Node{
		ID:        graph.NodeID(p.ToString()),
		Ecosystem: packageurl.TypeGeneric,
		Name:      kind,
		Version:   id,
		Note:      strings.TrimSpace(subject),
	}
}

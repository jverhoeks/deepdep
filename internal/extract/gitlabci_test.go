package extract_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func glExtract(t *testing.T, body string) (map[graph.NodeID]graph.EdgeKind, map[graph.NodeID]graph.Node) {
	t.Helper()
	f := source.File{Path: ".gitlab-ci.yml", Data: []byte(body)}
	edges, nodes, err := extract.GitLabCI{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one edge is root-anchored: root -> the CI file. Everything else
	// hangs off that file node, which is what keeps attribution per-occurrence
	// when several pipeline files share an action or an image.
	kinds := map[graph.NodeID]graph.EdgeKind{}
	var file graph.NodeID
	for _, e := range edges {
		if e.From == "" {
			if file != "" {
				t.Errorf("second root edge to %q; want exactly one, to the file node", e.To)
			}
			file = e.To
			continue
		}
		if e.From != file {
			t.Errorf("edge From = %q, want the CI file node %q", e.From, file)
		}
		kinds[e.To] = e.Kind
	}
	if file == "" {
		t.Fatal("no root edge to a file node")
	}
	byID := map[graph.NodeID]graph.Node{}
	for _, n := range nodes {
		if n.ID == file {
			continue // scaffolding for attribution, not a finding
		}
		byID[n.ID] = n
	}
	return kinds, byID
}

// include: is where GitLab pulls in other people's pipelines — by URL, by
// project, or as a component. Each one is code that runs in your CI.
func TestGitLabIncludesPullRemotePipelines(t *testing.T) {
	kinds, nodes := glExtract(t, `
include:
  - remote: https://example.com/shared/pipeline.yml
  - project: mygroup/ci-templates
    ref: v1.2.3
    file: /templates/build.yml
  - project: othergroup/unpinned
    file: /a.yml
  - component: gitlab.com/components/sonarqube@1.0.0
  - template: Security/SAST.gitlab-ci.yml
`)
	var sawRemote, sawTemplate bool
	for id := range kinds {
		s := string(id)
		if strings.Contains(s, "remote-include") {
			sawRemote = true
		}
		if strings.Contains(s, "gitlab-template") {
			sawTemplate = true
		}
	}
	if !sawRemote {
		t.Errorf("remote include missing; got %v", keys(kinds))
	}
	if !sawTemplate {
		t.Errorf("gitlab template include missing; got %v", keys(kinds))
	}

	pinned := graph.NodeID("pkg:gitlab/mygroup/ci-templates@v1.2.3#/templates/build.yml")
	if kinds[pinned] != graph.Invokes {
		t.Errorf("pinned project include missing or wrong kind; got %v", keys(kinds))
	}
	// A project include with no ref follows the default branch, so it can change
	// under you between runs.
	var unpinned bool
	for id, n := range nodes {
		if strings.Contains(string(id), "othergroup/unpinned") {
			unpinned = true
			if n.Completeness != graph.Declared || n.Reason != graph.ReasonUnpinnedRef {
				t.Errorf("include without ref = %q/%q, want declared/unpinned-ref", n.Completeness, n.Reason)
			}
		}
	}
	if !unpinned {
		t.Errorf("unpinned project include missing; got %v", keys(kinds))
	}

	comp := graph.NodeID("pkg:gitlab/components/sonarqube@1.0.0")
	if kinds[comp] != graph.Invokes {
		t.Errorf("CI/CD component missing; got %v", keys(kinds))
	}
	if n := nodes[comp]; n.Completeness != graph.Resolved {
		t.Errorf("component pinned to 1.0.0 = %q, want resolved", n.Completeness)
	}
}

func TestGitLabImagesAndServices(t *testing.T) {
	kinds, nodes := glExtract(t, `
default:
  image: python:3.12-slim
build:
  image:
    name: registry.example.com/team/builder:2.1
  services:
    - postgres:16
    - name: redis:7-alpine
  script:
    - make all
test:
  image: python:3.12-slim
  script: pytest
`)
	for _, id := range []graph.NodeID{
		"pkg:oci/python@3.12-slim",
		"pkg:oci/redis@7-alpine",
		"pkg:oci/postgres@16",
	} {
		if kinds[id] != graph.BuildsOn {
			t.Errorf("%s missing or wrong kind; got %v", id, keys(kinds))
		}
		if n := nodes[id]; n.Completeness != graph.Declared || n.Reason != graph.ReasonUnpinnedRef {
			t.Errorf("%s = %q/%q, want declared/unpinned-ref (a tag can be repointed)", id, n.Completeness, n.Reason)
		}
	}
	// A registry-qualified image keeps its namespace so two builders do not collide.
	var sawPrivate bool
	for id := range kinds {
		if strings.Contains(string(id), "builder@2.1") {
			sawPrivate = true
		}
	}
	if !sawPrivate {
		t.Errorf("registry-qualified image missing; got %v", keys(kinds))
	}
}

func TestGitLabScriptsBecomeOpaque(t *testing.T) {
	_, nodes := glExtract(t, `
build:
  before_script:
    - curl -sSf https://example.com/i.sh | sh
  script:
    - make all
  after_script:
    - ./cleanup.sh
`)
	var opaque int
	for _, n := range nodes {
		if n.Completeness == graph.Opaque {
			opaque++
		}
	}
	if opaque != 3 {
		t.Errorf("opaque steps = %d, want 3 (before_script, script, after_script all execute)", opaque)
	}
}

func TestGitLabMatch(t *testing.T) {
	e := extract.GitLabCI{}
	for _, p := range []string{".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/build.yml"} {
		if !e.Match(p) {
			t.Errorf("should match %q", p)
		}
	}
	for _, p := range []string{"package.json", ".github/workflows/ci.yml", "docs/x.yml"} {
		if e.Match(p) {
			t.Errorf("must not match %q", p)
		}
	}
}

func TestGitLabMalformedSurfacesError(t *testing.T) {
	f := source.File{Path: ".gitlab-ci.yml", Data: []byte("include:\n  - [unbalanced")}
	if _, _, err := (extract.GitLabCI{}).Extract(context.Background(), f); err == nil {
		t.Error("malformed YAML must surface an error")
	}
}

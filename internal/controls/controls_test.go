package controls_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/controls"
	"github.com/jverhoeks/deepdep/internal/graph"
)

func detect(nodes ...graph.Node) map[string]controls.Control {
	out := map[string]controls.Control{}
	for _, c := range controls.Detect(nodes) {
		out[c.Tool] = c
	}
	return out
}

func step(cmd string) graph.Node {
	return graph.Node{ID: graph.NodeID("pkg:generic/opaque@" + cmd),
		Completeness: graph.Opaque, Note: cmd, Source: ".github/workflows/ci.yml"}
}

func action(name string) graph.Node {
	return graph.Node{ID: graph.NodeID("pkg:github/" + name + "@v1"),
		Completeness: graph.Declared, Source: ".github/workflows/ci.yml"}
}

// TestMentionIsNotUsage is the whole risk in this detector. A step that greps
// for the string "trivy", or writes a file called sbom.json, is not running a
// scanner — and crediting a repository with a control it does not have is
// worse than reporting nothing, because it closes the question.
func TestMentionIsNotUsage(t *testing.T) {
	got := detect(
		step("echo 'TODO: add trivy scanning'"),
		step("cat sbom.json | jq ."),
		step("grep -r semgrep docs/"),
		step("cp cosign.pub /tmp/"),
	)
	if len(got) != 0 {
		t.Errorf("controls detected from mere mentions: %v", got)
	}
}

// TestInvocationIsUsage — the same words as the head of a command.
func TestInvocationIsUsage(t *testing.T) {
	got := detect(
		step("trivy image --severity HIGH myapp:latest"),
		step("syft dir:. -o cyclonedx-json=sbom.json"),
		step("sudo CI=1 /usr/local/bin/gitleaks detect --source ."),
		step("make build && govulncheck ./..."),
	)
	for _, want := range []string{"Trivy", "Syft", "gitleaks", "govulncheck"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missed %s; got %v", want, keys(got))
		}
	}
	// The path prefix and the leading sudo/env must not defeat the match.
	if got["gitleaks"].Kind != controls.Secrets {
		t.Errorf("gitleaks kind = %q", got["gitleaks"].Kind)
	}
}

// TestSubcommandIsRequired: `npm audit` is a scanner, `npm ci` is not. Treating
// the binary alone as the control would credit every JavaScript repo on earth
// with dependency scanning.
func TestSubcommandIsRequired(t *testing.T) {
	if got := detect(step("npm ci --frozen-lockfile")); len(got) != 0 {
		t.Errorf("plain npm counted as a control: %v", keys(got))
	}
	got := detect(step("npm audit --audit-level=high"), step("cargo deny check"))
	if _, ok := got["npm audit"]; !ok {
		t.Errorf("npm audit missed; got %v", keys(got))
	}
	if _, ok := got["cargo-deny"]; !ok {
		t.Errorf("cargo deny missed; got %v", keys(got))
	}
}

// TestActionsAreMatchedRegardlessOfPinning: a SHA-pinned action and a moving
// tag are the same tool, and pinning is reported separately as its own signal.
func TestActionsAreMatchedRegardlessOfPinning(t *testing.T) {
	got := detect(
		action("github/codeql-action"),
		graph.Node{ID: "pkg:github/aquasecurity/trivy-action@0f2bd1c9a1b7c5b0f8a5f0f2f1b3c4d5e6f70819",
			Completeness: graph.Resolved, Source: ".github/workflows/scan.yml"},
	)
	for _, want := range []string{"CodeQL", "Trivy"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missed %s; got %v", want, keys(got))
		}
	}
}

// TestCommercialToolsAreMarked so a reader can account for paid products
// separately from open-source tooling.
func TestCommercialToolsAreMarked(t *testing.T) {
	got := detect(action("snyk/actions"), action("github/codeql-action"))
	if !got["Snyk"].Commercial {
		t.Error("Snyk must be marked commercial")
	}
	if got["CodeQL"].Commercial {
		t.Error("CodeQL is not a commercial product")
	}
}

// TestBotsComeFromTheCoverageFrontier: a dependabot config is never expanded,
// but the file's presence IS the control.
func TestBotsComeFromTheCoverageFrontier(t *testing.T) {
	got := detect(graph.Node{
		ID:           "pkg:generic/unanalysed/dependabot@abc123?category=bot",
		Completeness: graph.Declared, Reason: "no-extractor",
		Source: ".github/dependabot.yml"})
	if _, ok := got["Dependabot"]; !ok {
		t.Errorf("dependabot not detected; got %v", keys(got))
	}
}

// TestMissingIsReportedAgainstTheFullChecklist. Absence is only statable
// against a known list, and it is the actionable half of the answer.
func TestMissingIsReportedAgainstTheFullChecklist(t *testing.T) {
	found := controls.Detect([]graph.Node{action("github/codeql-action")})
	missing := controls.Missing(found)
	if len(missing) != len(controls.Kinds)-1 {
		t.Errorf("missing = %v, want every kind but static-analysis", missing)
	}
	for _, k := range missing {
		if k == controls.SAST {
			t.Error("static-analysis reported missing while CodeQL was detected")
		}
	}
}

func keys(m map[string]controls.Control) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestNoCIMeansNotAssessable.
//
// kubernetes runs Prow and has no .github/workflows at all. Reporting "no
// controls detected" there says "this project runs nothing", when the truth is
// "their CI is somewhere we cannot read". Absence of evidence and evidence of
// absence are different findings.
func TestNoCIMeansNotAssessable(t *testing.T) {
	dockerOnly := []graph.Node{
		{ID: "pkg:generic/buildfile/dockerfile@abc#Dockerfile", Completeness: graph.Resolved},
		{ID: "pkg:oci/alpine@3.20", Completeness: graph.Declared},
	}
	if controls.Assessable(dockerOnly) {
		t.Error("a repo with Dockerfiles but no pipeline must not be assessable for CI controls")
	}
	withCI := append(dockerOnly, graph.Node{
		ID: "pkg:generic/buildfile/workflow@def#.github/workflows/ci.yml", Completeness: graph.Resolved})
	if !controls.Assessable(withCI) {
		t.Error("a repo with a workflow file is assessable")
	}
	gitlab := []graph.Node{{ID: "pkg:generic/buildfile/gitlab-ci@ghi#.gitlab-ci.yml", Completeness: graph.Resolved}}
	if !controls.Assessable(gitlab) {
		t.Error("GitLab CI counts too")
	}
}

// Package controls detects the security tooling a repository already runs.
//
// The closure already contains the evidence: a CI action is a
// `pkg:github/owner/repo` node, a shell step is an opaque node carrying its
// command, and a recognised-but-unexpanded config file is a coverage frontier.
// Detecting controls is therefore a query over the graph, not another scan.
//
// The useful half of the answer is what is MISSING. "This repo runs CodeQL" is
// mildly interesting; "this repo runs no dependency scanner and no secret
// scanner" is the finding, and it can only be stated by a tool that knows the
// full list it was looking for.
package controls

import (
	"sort"
	"strings"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// Kind groups controls by the question they answer.
type Kind string

const (
	SCA       Kind = "dependency-scanning" // known-vulnerable packages
	SBOM      Kind = "sbom"                // inventory generation
	SAST      Kind = "static-analysis"     // code flaws
	Secrets   Kind = "secret-scanning"     // committed credentials
	IaC       Kind = "iac-scanning"        // terraform/k8s misconfiguration
	Container Kind = "container-scanning"  // image contents and Dockerfile lint
	Signing   Kind = "signing"             // provenance and attestation
	Updates   Kind = "dependency-updates"  // automated bumps
	Hardening Kind = "ci-hardening"        // runner and workflow hardening
)

// Kinds is the full checklist, in reporting order. Absence is only reportable
// against a known list, so this is the list.
var Kinds = []Kind{SCA, Container, SBOM, SAST, Secrets, IaC, Signing, Updates, Hardening}

// Control is one detected tool.
type Control struct {
	Kind Kind   `json:"kind"`
	Tool string `json:"tool"`
	// Commercial marks a paid/hosted product, which a reader may want to
	// account for separately from open-source tooling.
	Commercial bool     `json:"commercial,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
}

// actions maps a GitHub/GitLab action repository to what it does. Matched on
// owner/repo with the ref stripped, because a pinned SHA and a moving tag are
// the same tool.
var actions = map[string]Control{
	"github/codeql-action":                     {Kind: SAST, Tool: "CodeQL"},
	"aquasecurity/trivy-action":                {Kind: Container, Tool: "Trivy"},
	"anchore/scan-action":                      {Kind: Container, Tool: "Grype"},
	"anchore/sbom-action":                      {Kind: SBOM, Tool: "Syft"},
	"cyclonedx/gh-node-module-generatebom":     {Kind: SBOM, Tool: "CycloneDX"},
	"semgrep/semgrep-action":                   {Kind: SAST, Tool: "Semgrep"},
	"returntocorp/semgrep-action":              {Kind: SAST, Tool: "Semgrep"},
	"snyk/actions":                             {Kind: SCA, Tool: "Snyk", Commercial: true},
	"sonarsource/sonarcloud-github-action":     {Kind: SAST, Tool: "SonarCloud", Commercial: true},
	"sonarsource/sonarqube-scan-action":        {Kind: SAST, Tool: "SonarQube", Commercial: true},
	"dependency-check/dependency-check_action": {Kind: SCA, Tool: "OWASP Dependency-Check"},
	"google/osv-scanner-action":                {Kind: SCA, Tool: "osv-scanner"},
	"google/osv-scanner-unified-workflow":      {Kind: SCA, Tool: "osv-scanner"},
	"gitleaks/gitleaks-action":                 {Kind: Secrets, Tool: "gitleaks"},
	"trufflesecurity/trufflehog":               {Kind: Secrets, Tool: "TruffleHog"},
	"bridgecrewio/checkov-action":              {Kind: IaC, Tool: "Checkov"},
	"aquasecurity/tfsec-action":                {Kind: IaC, Tool: "tfsec"},
	"aquasecurity/tfsec-pr-commenter-action":   {Kind: IaC, Tool: "tfsec"},
	"sigstore/cosign-installer":                {Kind: Signing, Tool: "cosign"},
	"sigstore/gh-action-sigstore-python":       {Kind: Signing, Tool: "sigstore"},
	"slsa-framework/slsa-github-generator":     {Kind: Signing, Tool: "SLSA generator"},
	"ossf/scorecard-action":                    {Kind: Hardening, Tool: "OpenSSF Scorecard"},
	"step-security/harden-runner":              {Kind: Hardening, Tool: "Harden-Runner", Commercial: true},
	"snyk/container-action":                    {Kind: Container, Tool: "Snyk Container", Commercial: true},
	"veracode/veracode-uploadandscan-action":   {Kind: SAST, Tool: "Veracode", Commercial: true},
	"checkmarx/ast-github-action":              {Kind: SAST, Tool: "Checkmarx", Commercial: true},
	"mend-toolkit/mend-scan-action":            {Kind: SCA, Tool: "Mend", Commercial: true},
	"fossas/fossa-action":                      {Kind: SCA, Tool: "FOSSA", Commercial: true},
}

// commands maps an invoked BINARY to what it does.
//
// Matched on the command word, never as a substring: a step that greps for the
// string "trivy" or writes a file called sbom.json is not running a scanner,
// and counting it would report a control the repository does not have.
var commands = map[string]Control{
	"trivy":               {Kind: Container, Tool: "Trivy"},
	"grype":               {Kind: Container, Tool: "Grype"},
	"dockle":              {Kind: Container, Tool: "dockle"},
	"hadolint":            {Kind: Container, Tool: "hadolint"},
	"syft":                {Kind: SBOM, Tool: "Syft"},
	"cyclonedx":           {Kind: SBOM, Tool: "CycloneDX"},
	"cyclonedx-py":        {Kind: SBOM, Tool: "cyclonedx-py"},
	"cdxgen":              {Kind: SBOM, Tool: "cdxgen"},
	"spdx-sbom-generator": {Kind: SBOM, Tool: "spdx-sbom-generator"},
	"semgrep":             {Kind: SAST, Tool: "Semgrep"},
	"bandit":              {Kind: SAST, Tool: "Bandit"},
	"codeql":              {Kind: SAST, Tool: "CodeQL"},
	"gosec":               {Kind: SAST, Tool: "gosec"},
	"gitleaks":            {Kind: Secrets, Tool: "gitleaks"},
	"trufflehog":          {Kind: Secrets, Tool: "TruffleHog"},
	"detect-secrets":      {Kind: Secrets, Tool: "detect-secrets"},
	"checkov":             {Kind: IaC, Tool: "Checkov"},
	"tfsec":               {Kind: IaC, Tool: "tfsec"},
	"kics":                {Kind: IaC, Tool: "KICS"},
	"terrascan":           {Kind: IaC, Tool: "Terrascan"},
	"osv-scanner":         {Kind: SCA, Tool: "osv-scanner"},
	"pip-audit":           {Kind: SCA, Tool: "pip-audit"},
	"safety":              {Kind: SCA, Tool: "Safety"},
	"govulncheck":         {Kind: SCA, Tool: "govulncheck"},
	"snyk":                {Kind: SCA, Tool: "Snyk", Commercial: true},
	"cosign":              {Kind: Signing, Tool: "cosign"},
	"sigstore":            {Kind: Signing, Tool: "sigstore"},
	"slsa-verifier":       {Kind: Signing, Tool: "slsa-verifier"},
}

// subcommands are tools whose security mode is a SUBcommand: `npm audit` is a
// scanner, plain `npm` is a package manager, and treating them alike would
// credit every repository with dependency scanning.
var subcommands = map[[2]string]Control{
	{"npm", "audit"}:      {Kind: SCA, Tool: "npm audit"},
	{"pnpm", "audit"}:     {Kind: SCA, Tool: "pnpm audit"},
	{"yarn", "audit"}:     {Kind: SCA, Tool: "yarn audit"},
	{"cargo", "audit"}:    {Kind: SCA, Tool: "cargo-audit"},
	{"cargo", "deny"}:     {Kind: SCA, Tool: "cargo-deny"},
	{"bundle", "audit"}:   {Kind: SCA, Tool: "bundler-audit"},
	{"composer", "audit"}: {Kind: SCA, Tool: "composer audit"},
	{"docker", "scout"}:   {Kind: Container, Tool: "Docker Scout", Commercial: true},
	{"gh", "attestation"}: {Kind: Signing, Tool: "gh attestation"},
}

// bots are recognised config files rather than invocations. They arrive as
// coverage frontiers, which is enough: the file's presence IS the control.
var bots = map[string]Control{
	"dependabot": {Kind: Updates, Tool: "Dependabot"},
	"renovate":   {Kind: Updates, Tool: "Renovate"},
}

// Detect finds the controls a repository runs.
func Detect(nodes []graph.Node) []Control {
	found := map[string]*Control{}
	record := func(c Control, ev string) {
		key := string(c.Kind) + "/" + c.Tool
		cur, ok := found[key]
		if !ok {
			copied := c
			found[key] = &copied
			cur = &copied
		}
		if ev != "" && len(cur.Evidence) < 6 && !contains(cur.Evidence, ev) {
			cur.Evidence = append(cur.Evidence, ev)
		}
	}

	for _, n := range nodes {
		id := string(n.ID)
		switch {
		case strings.HasPrefix(id, "pkg:github/"), strings.HasPrefix(id, "pkg:gitlab/"):
			name := id
			if i := strings.Index(name, "@"); i >= 0 {
				name = name[:i]
			}
			name = strings.TrimPrefix(strings.TrimPrefix(name, "pkg:github/"), "pkg:gitlab/")
			if c, ok := actions[strings.ToLower(name)]; ok {
				record(c, orSource(n, name))
			}

		case strings.HasPrefix(id, "pkg:generic/unanalysed/"):
			tool := strings.SplitN(strings.TrimPrefix(id, "pkg:generic/unanalysed/"), "@", 2)[0]
			if c, ok := bots[tool]; ok {
				record(c, n.Source)
			}

		case n.Completeness == graph.Opaque && n.Note != "":
			for _, c := range fromCommand(n.Note) {
				record(c, n.Source)
			}
		}
	}

	out := make([]Control, 0, len(found))
	for _, c := range found {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return kindOrder(out[i].Kind) < kindOrder(out[j].Kind)
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// Assessable reports whether the repository has CI this tool can read.
//
// kubernetes runs Prow and has no .github/workflows at all, so "no controls
// detected" would read as "runs nothing" when the truth is "we cannot see their
// CI". Absence of evidence and evidence of absence are different findings and a
// report that conflates them is worse than one that says nothing.
func Assessable(nodes []graph.Node) bool {
	for _, n := range nodes {
		id := string(n.ID)
		if strings.HasPrefix(id, BuildFileWorkflow) || strings.HasPrefix(id, BuildFileGitLab) {
			return true
		}
	}
	return false
}

// The build-file node prefixes that mean "we read a pipeline definition".
const (
	BuildFileWorkflow = "pkg:generic/buildfile/workflow@"
	BuildFileGitLab   = "pkg:generic/buildfile/gitlab-ci@"
)

// Missing returns the kinds with no detected tool, which is the actionable half.
func Missing(found []Control) []Kind {
	have := map[Kind]bool{}
	for _, c := range found {
		have[c.Kind] = true
	}
	var out []Kind
	for _, k := range Kinds {
		if !have[k] {
			out = append(out, k)
		}
	}
	return out
}

// fromCommand reads a shell line and returns the controls it INVOKES.
func fromCommand(cmd string) []Control {
	var out []Control
	for _, seg := range splitShell(cmd) {
		fields := strings.Fields(seg)
		// Skip leading environment assignments and sudo, which precede the real
		// command: `sudo FOO=1 trivy image ...`.
		for len(fields) > 0 && (fields[0] == "sudo" || strings.Contains(fields[0], "=")) {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		bin := basename(fields[0])
		if c, ok := commands[bin]; ok {
			out = append(out, c)
			continue
		}
		if len(fields) >= 2 {
			if c, ok := subcommands[[2]string{bin, fields[1]}]; ok {
				out = append(out, c)
			}
		}
	}
	return out
}

// splitShell breaks on the operators that begin a new command, so only the
// actual head of each command is tested.
func splitShell(cmd string) []string {
	r := strings.NewReplacer("&&", "\n", "||", "\n", ";", "\n", "|", "\n", "\r", "\n")
	return strings.Split(r.Replace(cmd), "\n")
}

func basename(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return strings.ToLower(s)
}

func orSource(n graph.Node, fallback string) string {
	if n.Source != "" {
		return n.Source
	}
	return fallback
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func kindOrder(k Kind) int {
	for i, x := range Kinds {
		if x == k {
			return i
		}
	}
	return len(Kinds)
}

package extract_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func dockerNodes(t *testing.T, body string) map[graph.NodeID]graph.Node {
	t.Helper()
	_, nodes, err := extract.Dockerfile{}.Extract(context.Background(),
		source.File{Path: "Dockerfile", Data: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	by := map[graph.NodeID]graph.Node{}
	for _, n := range nodes {
		// The Dockerfile's own node is scaffolding for attribution; these tests
		// are about what it pulls IN.
		if strings.HasPrefix(string(n.ID), extract.BuildFilePrefix) {
			continue
		}
		by[n.ID] = n
	}
	return by
}

// TestEveryDockerfileGetsItsOwnBaseImages is the attribution bug. A base image
// shared by several Dockerfiles is one deduplicated node, so hanging everything
// off the repository root left `cli/Dockerfile` reporting no FROM at all in a
// real scan. Attribution is per-occurrence and therefore lives on edges.
func TestEveryDockerfileGetsItsOwnBaseImages(t *testing.T) {
	var files []graph.NodeID
	byFile := map[graph.NodeID][]graph.NodeID{}
	for _, path := range []string{"a/Dockerfile", "b/Dockerfile"} {
		edges, _, err := extract.Dockerfile{}.Extract(context.Background(),
			source.File{Path: path, Data: []byte("FROM python:3.12-slim\n")})
		if err != nil {
			t.Fatal(err)
		}
		var self graph.NodeID
		for _, e := range edges {
			if e.From == "" {
				self = e.To // root -> this file
			}
		}
		if self == "" {
			t.Fatalf("%s: no root edge to the file node", path)
		}
		files = append(files, self)
		for _, e := range edges {
			if e.From == self {
				byFile[self] = append(byFile[self], e.To)
			}
		}
	}
	if files[0] == files[1] {
		t.Fatal("two Dockerfiles collapsed to one node")
	}
	for _, f := range files {
		var sawImage bool
		for _, to := range byFile[f] {
			if to == "pkg:oci/python@3.12-slim" {
				sawImage = true
			}
		}
		if !sawImage {
			t.Errorf("%s has no edge to the shared base image — attribution lost", f)
		}
	}
}

// TestMultiStageReferenceIsNotAnImage is the bug this parser exists to avoid.
// `FROM builder` names an earlier stage in the same file; minting
// pkg:oci/builder invents a registry image that does not exist, and every
// downstream consumer — SBOM, CVE scan, risk report — then carries a phantom.
func TestMultiStageReferenceIsNotAnImage(t *testing.T) {
	by := dockerNodes(t, `
FROM node:24-alpine AS deps
RUN npm ci
FROM deps AS builder
FROM builder
FROM scratch
`)
	for id := range by {
		for _, bad := range []string{"pkg:oci/builder", "pkg:oci/deps", "pkg:oci/scratch"} {
			if string(id) == bad+"@latest" || string(id) == bad {
				t.Errorf("minted %q — a stage alias is not a registry image", id)
			}
		}
	}
	if _, ok := by["pkg:oci/node@24-alpine"]; !ok {
		t.Errorf("the real base image is missing; got %v", nodeKeys(by))
	}
}

// TestDigestPinnedBaseIsResolved: a digest is the only genuinely immutable form
// of a FROM, and it is the difference between "we know what shipped" and "we
// know what the tag pointed at when we looked".
func TestDigestPinnedBaseIsResolved(t *testing.T) {
	by := dockerNodes(t,
		"FROM maven:3.9-eclipse-temurin-17@sha256:4015718012bbf1113ec6cfae2b950be328d90265ceb60f92b26c3ea7c4d14ee8 AS m\n"+
			"FROM python:3.12-slim\n")

	var digest, tagged graph.Node
	for _, n := range by {
		if n.ResolvedRef != "" {
			digest = n
		} else if n.Name == "python" {
			tagged = n
		}
	}
	if digest.Completeness != graph.Resolved {
		t.Errorf("digest-pinned FROM = %q, want resolved (node %+v)", digest.Completeness, digest)
	}
	if digest.ResolvedRef == "" {
		t.Error("the observed digest must be recorded; tag->digest history is not reconstructible")
	}
	if tagged.Completeness != graph.Declared || tagged.Reason != graph.ReasonUnpinnedRef {
		t.Errorf("tag-pinned FROM = %+v, want declared/unpinned-ref", tagged)
	}
}

// TestUnresolvedArgBaseIsDeclaredNotDropped: `FROM ${MLFLOW_BASE}` is decided at
// build time. We know a base image is pulled and we know the expression, so it
// is Declared with a reason — dropping it would report a Dockerfile with no base.
func TestUnresolvedArgBaseIsDeclaredNotDropped(t *testing.T) {
	by := dockerNodes(t, "ARG MLFLOW_BASE\nFROM ${MLFLOW_BASE}\n")
	if len(by) != 1 {
		t.Fatalf("nodes = %v, want exactly one unresolved base", nodeKeys(by))
	}
	for _, n := range by {
		if n.Completeness != graph.Declared || n.Reason != extract.ReasonUnresolvedArg {
			t.Errorf("node = %+v, want declared/unresolved-arg", n)
		}
		if n.Note == "" {
			t.Error("the unevaluated expression must survive for a human to resolve")
		}
	}
}

// TestArgDefaultsAreSubstituted — `ARG CADDY_VERSION=2.8` then
// `FROM caddy:${CADDY_VERSION}-builder` IS statically knowable.
func TestArgDefaultsAreSubstituted(t *testing.T) {
	by := dockerNodes(t, "ARG CADDY_VERSION=2.8\nFROM caddy:${CADDY_VERSION}-builder AS builder\nFROM caddy:${CADDY_VERSION}\n")
	for _, want := range []graph.NodeID{"pkg:oci/caddy@2.8-builder", "pkg:oci/caddy@2.8"} {
		if _, ok := by[want]; !ok {
			t.Errorf("missing %q; got %v", want, nodeKeys(by))
		}
	}
}

// TestDefaultValueSyntax covers ${VAR:-fallback}, which needs no ARG at all.
func TestDefaultValueSyntax(t *testing.T) {
	by := dockerNodes(t, "FROM python:${PY:-3.12}-slim\n")
	if _, ok := by["pkg:oci/python@3.12-slim"]; !ok {
		t.Errorf("got %v, want the ${VAR:-default} fallback applied", nodeKeys(by))
	}
}

// TestLineContinuationAndComments: a multi-line RUN is ONE step, and a comment
// inside it must not terminate the instruction.
func TestLineContinuationAndComments(t *testing.T) {
	_, nodes, err := extract.Dockerfile{}.Extract(context.Background(), source.File{
		Path: "Dockerfile",
		Data: []byte("FROM alpine:3.20\n" +
			"# install the runtime\n" +
			"RUN apk add --no-cache python3 \\\n" +
			"    && apk add curl=8.11.1\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var opaque int
	got := map[graph.NodeID]graph.Node{}
	for _, n := range nodes {
		got[n.ID] = n
		if n.Completeness == graph.Opaque {
			opaque++
		}
	}
	if opaque != 1 {
		t.Errorf("opaque steps = %d, want 1 — the continuation is a single RUN", opaque)
	}
	for _, want := range []graph.NodeID{"pkg:alpine/python3", "pkg:alpine/curl@8.11.1"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q; got %v", want, nodeKeys(got))
		}
	}
}

// TestRunEmitsBothTheCommandAndTheParsedPackages: these are different facts.
// The inference can be wrong; the raw command lets a reader check it.
func TestRunEmitsBothTheCommandAndTheParsedPackages(t *testing.T) {
	by := dockerNodes(t, "FROM debian:12\nRUN apt-get update && apt-get install -y --no-install-recommends python3 curl\n")

	var sawCommand bool
	for _, n := range by {
		if n.Completeness == graph.Opaque && n.Note != "" {
			sawCommand = true
		}
	}
	if !sawCommand {
		t.Error("the raw RUN must survive as an opaque step for formulation")
	}
	for _, want := range []graph.NodeID{"pkg:deb/python3", "pkg:deb/curl"} {
		n, ok := by[want]
		if !ok {
			t.Fatalf("missing %q; got %v", want, nodeKeys(by))
		}
		if n.Completeness != graph.Inferred {
			t.Errorf("%s completeness = %q, want inferred — this is parsed shell, not a manifest", want, n.Completeness)
		}
	}
	// `apt-get update` installs nothing; splitting on && is what keeps its
	// arguments from being read as package names.
	if _, ok := by["pkg:deb/update"]; ok {
		t.Error("`apt-get update` was misread as installing a package named update")
	}
	// Flags must never become packages.
	for id := range by {
		if id == "pkg:deb/-y" || id == "pkg:deb/--no-install-recommends" {
			t.Errorf("flag %q parsed as a package", id)
		}
	}
}

// TestRunDeclinesToGuess: a variable, a subshell or a requirements file means
// the package set is not knowable from the text. The opaque step still records
// it; inventing names would be confident nonsense.
func TestRunDeclinesToGuess(t *testing.T) {
	by := dockerNodes(t, "FROM python:3.12\nRUN pip install -r requirements.txt && pip install ${EXTRA_PKG}\n")
	for id, n := range by {
		if n.Completeness == graph.Inferred {
			t.Errorf("guessed %q from an unresolvable install line", id)
		}
	}
}

func TestDockerfileMatch(t *testing.T) {
	e := extract.Dockerfile{}
	for _, p := range []string{
		"Dockerfile", "backend/Dockerfile", "backend/Dockerfile.dbt",
		"x/Containerfile", "svc/app.Dockerfile",
	} {
		if !e.Match(p) {
			t.Errorf("should match %q", p)
		}
	}
	for _, p := range []string{"docker-compose.yml", "Dockerfilex", "README.md"} {
		if e.Match(p) {
			t.Errorf("must not match %q", p)
		}
	}
}

func nodeKeys(m map[graph.NodeID]graph.Node) []graph.NodeID {
	out := make([]graph.NodeID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestDigestPurlIsWellFormed: `maven:3.9-temurin@sha256:401…` contains two
// colons. Splitting on the last one puts the tag and the literal "sha256" into
// the package name and the bare hex into the version — a nonsense identity for
// the one image form that is actually immutable, and it survived into a real
// scan before this test existed.
func TestDigestPurlIsWellFormed(t *testing.T) {
	by := dockerNodes(t,
		"FROM maven:3.9-eclipse-temurin-17@sha256:4015718012bbf1113ec6cfae2b950be328d90265ceb60f92b26c3ea7c4d14ee8\n")
	if len(by) != 1 {
		t.Fatalf("nodes = %v, want 1", nodeKeys(by))
	}
	// Literal colon in the version, per the PURL spec's own oci example
	// (pkg:oci/debian@sha256:244fd47e...). Not percent-encoded.
	const want = "pkg:oci/maven@sha256:4015718012bbf1113ec6cfae2b950be328d90265ceb60f92b26c3ea7c4d14ee8?tag=3.9-eclipse-temurin-17"
	for id, n := range by {
		if string(id) != want {
			t.Errorf("id  = %q\nwant  %q", id, want)
		}
		if n.Name != "maven" {
			t.Errorf("name = %q, want maven — the tag must not leak into the name", n.Name)
		}
	}
}

// TestLocalProjectInstallIsNotAPackage: `pip install .` installs the project in
// the working directory. "." passes a naive character check and PEP 503
// normalisation then turns it into a package named "-", which reached a real
// SBOM as pkg:pypi/- before this test existed.
func TestLocalProjectInstallIsNotAPackage(t *testing.T) {
	by := dockerNodes(t, "FROM python:3.12-slim\nRUN pip install --no-cache-dir .\nRUN pip install -e ../lib\n")
	for id, n := range by {
		if n.Completeness == graph.Inferred {
			t.Errorf("minted %q from a local-path install", id)
		}
	}
}

// TestScopedNPMPackagesSurviveRunParsing.
//
// A slash normally means a path, so rejecting it dropped every SCOPED npm
// package installed from a RUN line. Scoped packages are precisely what the
// Shai-Hulud worm compromised — @ctrl/tinycolor, @crowdstrike/* — so this
// silently hid the highest-severity finding the tool can make, and only showed
// up when a malicious-package fixture was run end to end.
func TestScopedNPMPackagesSurviveRunParsing(t *testing.T) {
	by := dockerNodes(t, "FROM node:24-alpine\nRUN npm install @ctrl/tinycolor@4.1.1 angulartics2@14.1.2 @types/node\n")

	for id, wantVer := range map[graph.NodeID]string{
		"pkg:npm/%40ctrl/tinycolor@4.1.1": "4.1.1",
		"pkg:npm/angulartics2@14.1.2":     "14.1.2",
		"pkg:npm/%40types/node":           "", // unpinned, still a real package
	} {
		n, ok := by[id]
		if !ok {
			t.Errorf("missing %q; got %v", id, nodeKeys(by))
			continue
		}
		if n.Version != wantVer {
			t.Errorf("%s version = %q, want %q — the scope's @ is part of the NAME", id, n.Version, wantVer)
		}
		if n.Completeness != graph.Inferred {
			t.Errorf("%s completeness = %q, want inferred", id, n.Completeness)
		}
	}
	// A real path argument must still be rejected.
	if _, ok := by["pkg:npm/usr/local/bin"]; ok {
		t.Error("a filesystem path was parsed as a package")
	}
}

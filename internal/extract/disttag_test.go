package extract

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// `npm install -g pkg@latest` pins nothing, and minting `latest` as a version
// is not a cosmetic error. OSV, asked about npm/npm@latest, cannot order that
// token against any fixed range and answers with every npm advisory back to
// 2013 — so an image whose npm is current reported CVE-2013-4116. Six CRITICAL
// and 36 HIGH findings across a 163-repository fleet rested on versions that do
// not exist.
//
// A dist-tag becomes a version-LESS requirement instead, which the walker
// resolves to whatever is newest — the honest reading of what the build does.
func TestDistTagsAreNotVersions(t *testing.T) {
	f := source.File{Path: "Dockerfile", Data: []byte(
		"FROM node:24-alpine\n" +
			"RUN npm install -g npm@latest @google/gemini-cli@nightly pinned@1.2.3\n")}
	_, nodes, err := Dockerfile{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	by := map[graph.NodeID]graph.Node{}
	for _, n := range nodes {
		by[n.ID] = n
	}

	for _, id := range []graph.NodeID{"pkg:npm/npm", "pkg:npm/%40google/gemini-cli"} {
		n, ok := by[id]
		if !ok {
			t.Errorf("missing %s — a dist-tag install must still be reported", id)
			continue
		}
		if n.Version != "" {
			t.Errorf("%s version = %q, want empty: a dist-tag is a moving reference", id, n.Version)
		}
	}
	if _, ok := by["pkg:npm/npm@latest"]; ok {
		t.Error("minted npm@latest as a version; OSV answers that with every npm advisory ever filed")
	}
	// A real pin is untouched.
	if n, ok := by["pkg:npm/pinned@1.2.3"]; !ok || n.Version != "1.2.3" {
		t.Errorf("a genuine pin was lost: %+v", n)
	}
}

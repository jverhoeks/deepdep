package extract

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// A stage alias that only becomes recognisable AFTER argument substitution was
// emitted as a registry image. immich's machine-learning Dockerfile does
// exactly this — `ARG DEVICE=cpu` then `FROM builder-${DEVICE} AS builder`,
// where builder-cpu is a stage declared eleven lines earlier — and deepdep
// minted pkg:oci/builder-cpu@latest.
//
// It is not only a phantom image. A bare stage name carries no tag, so it lands
// in the unpinned bucket and overstates how many base images across a fleet
// float on a movable tag, which is the headline that surface exists to report.
func TestStageAliasesAreNotImagesAfterArgSubstitution(t *testing.T) {
	f := source.File{Path: "Dockerfile", Data: []byte(
		"ARG DEVICE=cpu\n" +
			"FROM python:3.11-bookworm AS builder-cpu\n" +
			"FROM rocm/dev-ubuntu-24.04:7.2 AS builder-rocm\n" +
			"FROM builder-${DEVICE} AS builder\n" +
			"FROM builder AS final\n")}
	_, nodes, err := Dockerfile{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if strings.HasPrefix(string(n.ID), "pkg:oci/builder") {
			t.Errorf("emitted stage alias as an image: %s", n.ID)
		}
	}
	// The two real images survive.
	by := map[graph.NodeID]bool{}
	for _, n := range nodes {
		by[n.ID] = true
	}
	for _, want := range []graph.NodeID{
		"pkg:oci/python@3.11-bookworm",
		"pkg:oci/rocm/dev-ubuntu-24.04@7.2",
	} {
		if !by[want] {
			t.Errorf("lost a real base image: %s", want)
		}
	}
}

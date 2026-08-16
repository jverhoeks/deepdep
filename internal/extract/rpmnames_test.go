package extract

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// rpm pins with a bare hyphen and rpm package names are full of hyphens, so
// splitting on the last one invented packages: `lapack-devel` became
// lapack@devel, `yum-utils` became yum@utils, and `gcc-toolset-13-gcc-c++`
// became a package versioned "c++". OSV answered for those names anyway, so the
// Dockerfile surface reported findings against packages nobody installed.
func TestRPMNamesWithHyphensAreNotSplitIntoVersions(t *testing.T) {
	f := source.File{Path: "Dockerfile", Data: []byte(
		"FROM redhat/ubi9\n" +
			"RUN yum install -y lapack-devel yum-utils gcc-toolset-13-gcc-c++ curl-7.88.1\n")}
	_, nodes, err := Dockerfile{}.Extract(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	by := map[graph.NodeID]graph.Node{}
	for _, n := range nodes {
		by[n.ID] = n
	}

	for _, want := range []graph.NodeID{
		"pkg:rpm/redhat/lapack-devel",
		"pkg:rpm/redhat/yum-utils",
		"pkg:rpm/redhat/gcc-toolset-13-gcc-c%2B%2B",
	} {
		if _, ok := by[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	// A genuine pin still splits.
	if n, ok := by["pkg:rpm/redhat/curl@7.88.1"]; !ok || n.Version != "7.88.1" {
		t.Errorf("a real rpm pin was lost: %+v", n)
	}
	if _, bad := by["pkg:rpm/redhat/lapack@devel"]; bad {
		t.Error("invented lapack@devel — a suffix is not a version")
	}
}

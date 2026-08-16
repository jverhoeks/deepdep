package advisory

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// The single most cited CI supply-chain compromise is in OSV, and every
// PURL-keyed scanner reports the repositories using it as clean, because the
// record carries a null purl. A GitHub Actions node must therefore be asked
// about by ecosystem+name — and WITHOUT a version, since action refs (`v45`, a
// SHA) do not follow the versioning the advisory states its ranges in.
func TestActionsAreQueriedByNameNotPURL(t *testing.T) {
	q := queryFor("pkg:github/tj-actions/changed-files@45.0.7")
	if q.Package.PURL != "" {
		t.Errorf("purl = %q, want empty — OSV's GitHub Actions records have a null purl", q.Package.PURL)
	}
	if q.Package.Name != "tj-actions/changed-files" || q.Package.Ecosystem != ActionsEcosystem {
		t.Errorf("query = %+v, want name+%s", q.Package, ActionsEcosystem)
	}

	// Everything else keeps the PURL, which is right for every registry.
	p := queryFor("pkg:npm/lodash@4.17.21")
	if p.Package.PURL != "pkg:npm/lodash@4.17.21" || p.Package.Name != "" {
		t.Errorf("npm query = %+v, want purl only", p.Package)
	}
}

func TestActionNameDropsRefAndSubpath(t *testing.T) {
	for id, want := range map[graph.NodeID]string{
		"pkg:github/actions/checkout@v4":                           "actions/checkout",
		"pkg:github/myorg/shared@v1#.github/workflows/release.yml": "myorg/shared",
		"pkg:github/actions/setup-node@8c91899e586c":               "actions/setup-node",
	} {
		got, ok := ActionName(id)
		if !ok || got != want {
			t.Errorf("ActionName(%s) = %q,%v want %q", id, got, ok, want)
		}
	}
	if _, ok := ActionName("pkg:npm/lodash@4.17.21"); ok {
		t.Error("an npm package is not a CI action")
	}
}

func TestRefOfRecoversTheRefInUse(t *testing.T) {
	for id, want := range map[graph.NodeID]string{
		"pkg:github/actions/checkout@v4":                           "v4",
		"pkg:github/myorg/shared@v1#.github/workflows/release.yml": "v1",
	} {
		if got := refOf(id); got != want {
			t.Errorf("refOf(%s) = %q, want %q", id, got, want)
		}
	}
}

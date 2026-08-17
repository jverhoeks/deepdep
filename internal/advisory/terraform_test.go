package advisory_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/advisory"
	"github.com/jverhoeks/deepdep/internal/graph"
)

// The mapping that makes provider CVEs reachable at all. A provider is
// distributed as a plugin binary but developed as terraform-provider-<name>
// under its publisher's org, which is the only name OSV files advisories under.
//
// The node keeps its own identity — pkg:terraform is what the configuration
// declares, what the registry serves and what the lockfile pins. Only the QUERY
// is translated.
func TestTerraformProviderMapsToItsGoModulePURL(t *testing.T) {
	cases := map[string]string{
		// Go module tags carry a leading v; Terraform versions never do, and
		// querying without it finds nothing for a version-specific lookup.
		"pkg:terraform/hashicorp/aws@5.31.0":      "pkg:golang/github.com/hashicorp/terraform-provider-aws@v5.31.0",
		"pkg:terraform/hashicorp/vault":           "pkg:golang/github.com/hashicorp/terraform-provider-vault",
		"pkg:terraform/integrations/github@6.2.1": "pkg:golang/github.com/integrations/terraform-provider-github@v6.2.1",
	}
	for id, want := range cases {
		got, ok := advisory.TerraformProviderPURL(graph.NodeID(id))
		if !ok || got != want {
			t.Errorf("TerraformProviderPURL(%s) = %q,%v; want %q", id, got, ok, want)
		}
	}
}

// Everything else must pass through untouched, or an ordinary package is asked
// about under a module name that does not exist.
func TestNonTerraformIdsAreNotRemapped(t *testing.T) {
	for _, id := range []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:golang/github.com/hashicorp/terraform@v1.5.0", // the CLI needs no mapping
		"pkg:pypi/requests@2.32.3",
		"pkg:terraform/onlyonepart",
	} {
		if got, ok := advisory.TerraformProviderPURL(graph.NodeID(id)); ok {
			t.Errorf("TerraformProviderPURL(%s) remapped to %q", id, got)
		}
	}
}

// The Terraform binary is a LEAF. It carries its own ecosystem so the walker
// never expands it as a Go module — doing that pulled in Terraform's own 2,000
// module build tree, dependencies the scanned repository neither chose nor can
// change — while the advisory query still reaches the module OSV files against.
func TestTerraformCLIMapsToItsGoModulePURL(t *testing.T) {
	cases := map[string]string{
		"pkg:terraform-cli/hashicorp/terraform@1.5.7": "pkg:golang/github.com/hashicorp/terraform@v1.5.7",
		"pkg:terraform-cli/hashicorp/terraform":       "pkg:golang/github.com/hashicorp/terraform",
	}
	for id, want := range cases {
		got, ok := advisory.TerraformCLIPURL(graph.NodeID(id))
		if !ok || got != want {
			t.Errorf("TerraformCLIPURL(%s) = %q,%v; want %q", id, got, ok, want)
		}
	}
	if _, ok := advisory.TerraformCLIPURL("pkg:terraform/hashicorp/aws@5.31.0"); ok {
		t.Error("a provider was mapped as though it were the CLI")
	}
}

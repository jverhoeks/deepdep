package extract_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

func tfExtract(t *testing.T, body string) ([]graph.Edge, map[graph.NodeID]graph.Node) {
	t.Helper()
	edges, nodes, err := extract.Terraform{}.Extract(context.Background(), source.File{
		Path: "main.tf", Data: []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	by := map[graph.NodeID]graph.Node{}
	for _, n := range nodes {
		by[n.ID] = n
	}
	return edges, by
}

func tfSpec(edges []graph.Edge, id string) (string, bool) {
	for _, e := range edges {
		if string(e.To) == id {
			return e.Spec, true
		}
	}
	return "", false
}

// The three things a Terraform configuration pulls in, all of which run with
// the credentials of whoever applies it.
func TestTerraformReadsProvidersVersionAndModules(t *testing.T) {
	edges, _ := tfExtract(t, `
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.31"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0, < 4.0"
    }
  }
}

module "network" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
}
`)
	if got, ok := tfSpec(edges, "pkg:terraform/hashicorp/aws"); !ok || got != "~> 5.31" {
		t.Errorf("aws spec = %q (found=%v), want the pessimistic constraint", got, ok)
	}
	if got, ok := tfSpec(edges, "pkg:terraform/hashicorp/azurerm"); !ok || got != ">= 3.0, < 4.0" {
		t.Errorf("azurerm spec = %q (found=%v)", got, ok)
	}
	// The CLI gets its OWN ecosystem, not pkg:golang. Identifying it as a Go
	// module made the walker expand Terraform's entire internal build tree —
	// 2,082 modules on a repository whose real supply chain is two providers.
	if got, ok := tfSpec(edges, "pkg:terraform-cli/hashicorp/terraform"); !ok || got != ">= 1.5.0" {
		t.Errorf("terraform CLI spec = %q (found=%v)", got, ok)
	}
	for _, e := range edges {
		if strings.HasPrefix(string(e.To), "pkg:golang/") {
			t.Errorf("edge to %s: the CLI must not be a Go module, or its 2,000-module build tree is walked", e.To)
		}
	}
	found := false
	for _, e := range edges {
		if string(e.To) == "pkg:terraform-module/terraform-aws-modules/vpc-aws@5.1.2" {
			found = true
		}
	}
	if !found {
		t.Errorf("registry module missing from %v", edges)
	}
}

// A bare local name means the hashicorp namespace, exactly as Terraform
// resolves it — and the source attribute may be omitted entirely.
func TestTerraformDefaultsToHashicorpNamespace(t *testing.T) {
	edges, _ := tfExtract(t, `
terraform {
  required_providers {
    random = {
      version = "3.6.0"
    }
  }
}
`)
	if _, ok := tfSpec(edges, "pkg:terraform/hashicorp/random"); !ok {
		t.Errorf("a source-less provider did not default to hashicorp: %v", edges)
	}
}

// A registry host prefix must not become part of the identity, or one provider
// mints two nodes.
func TestTerraformStripsRegistryHost(t *testing.T) {
	edges, _ := tfExtract(t, `
terraform {
  required_providers {
    aws = {
      source  = "registry.terraform.io/hashicorp/aws"
      version = "5.31.0"
    }
  }
}
`)
	if _, ok := tfSpec(edges, "pkg:terraform/hashicorp/aws"); !ok {
		t.Errorf("a host-qualified source minted a different node: %v", edges)
	}
}

// A local module is a directory in this repository: not fetched, no version, no
// advisory record. Its contents are read from its own files by this same
// extractor.
func TestTerraformLocalModuleIsNotADependency(t *testing.T) {
	edges, _ := tfExtract(t, `
module "local" {
  source = "./modules/thing"
}
`)
	if len(edges) != 0 {
		t.Errorf("a local module became a dependency: %v", edges)
	}
}

// A git-sourced module has no registry to ask and no version list to expand, so
// it is an honest frontier rather than a resolvable package.
func TestTerraformGitModuleIsAFrontier(t *testing.T) {
	_, nodes := tfExtract(t, `
module "forked" {
  source = "git::https://example.com/mod.git?ref=v1.2.3"
}
`)
	found := false
	for _, n := range nodes {
		if n.Reason == "vcs-module" {
			found = true
		}
	}
	if !found {
		t.Errorf("a git module produced no frontier node: %v", nodes)
	}
}

func TestTerraformMatch(t *testing.T) {
	m := extract.Terraform{}
	for _, p := range []string{"main.tf", "examples/basic/terraform.tf"} {
		if !m.Match(p) {
			t.Errorf("Match(%q) = false", p)
		}
	}
	for _, p := range []string{"main.tfvars", ".terraform/modules/x/main.tf", "README.md"} {
		if m.Match(p) {
			t.Errorf("Match(%q) = true; that is not this repository's declaration", p)
		}
	}
}

// required_version is a CONSTRAINT and names no version, so it can never be
// matched against an advisory. These files pin the actual binary, which is what
// makes Terraform's own CVEs checkable.
func TestTerraformVersionFilePinsTheBinary(t *testing.T) {
	for _, c := range []struct{ path, body, want string }{
		{".terraform-version", "1.5.7\n", "1.5.7"},
		{".tool-versions", "nodejs 20.11.0\nterraform 1.9.2\npython 3.12.1\n", "1.9.2"},
	} {
		_, nodes, err := extract.TerraformVersionFile{}.Extract(context.Background(),
			source.File{Path: c.path, Data: []byte(c.body)})
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if len(nodes) != 1 {
			t.Fatalf("%s produced %d nodes, want 1", c.path, len(nodes))
		}
		n := nodes[0]
		if n.Version != c.want {
			t.Errorf("%s version = %q, want %q", c.path, n.Version, c.want)
		}
		if n.Completeness != graph.Resolved {
			t.Errorf("%s completeness = %q, want resolved — a pin is a fact", c.path, n.Completeness)
		}
		if string(n.ID) != "pkg:terraform-cli/hashicorp/terraform@"+c.want {
			t.Errorf("%s id = %q", c.path, n.ID)
		}
	}
}

// "latest" names no single version, so there is nothing an advisory could match.
func TestTerraformVersionFileIgnoresUnpinnedValues(t *testing.T) {
	for _, body := range []string{"latest\n", "latest:^1.5\n", "\n", "not-a-version\n"} {
		_, nodes, err := extract.TerraformVersionFile{}.Extract(context.Background(),
			source.File{Path: ".terraform-version", Data: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 0 {
			t.Errorf("%q produced %d nodes; it names no single version", body, len(nodes))
		}
	}
}

// .tool-versions names many tools; only the terraform line is ours.
func TestToolVersionsIgnoresOtherTools(t *testing.T) {
	_, nodes, err := extract.TerraformVersionFile{}.Extract(context.Background(),
		source.File{Path: ".tool-versions", Data: []byte("nodejs 20.11.0\npython 3.12.1\n")})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Errorf("got %d nodes from a file with no terraform line", len(nodes))
	}
}

package effective_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/source"
)

// The lock is what makes a Terraform repository auditable: the configuration
// says "~> 5.31", the lock says exactly which 5.31.x will be downloaded and run
// on the next apply.
func TestTerraformLockPinsProviders(t *testing.T) {
	inst, err := effective.TerraformLock{}.Resolve(context.Background(), source.Static([]source.File{{
		Path: ".terraform.lock.hcl",
		Data: []byte(`
provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.31"
  hashes = [
    "h1:abc=",
  ]
}

provider "registry.terraform.io/integrations/github" {
  version     = "6.2.1"
  constraints = ">= 6.0.0"
}
`),
	}}))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, i := range inst {
		got[string(i.NodeID)] = true
		if i.DerivedFrom != "lockfile" {
			t.Errorf("%s DerivedFrom = %q, want lockfile", i.NodeID, i.DerivedFrom)
		}
	}
	for _, want := range []string{
		"pkg:terraform/hashicorp/aws@5.31.0",
		"pkg:terraform/integrations/github@6.2.1",
	} {
		if !got[want] {
			t.Errorf("missing %s from %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("got %d providers, want 2", len(got))
	}
}

// Several configuration directories can legitimately lock different versions of
// one provider; collapsing them would hide one.
func TestTerraformLockScopesByDirectory(t *testing.T) {
	inst, err := effective.TerraformLock{}.Resolve(context.Background(), source.Static([]source.File{
		{Path: ".terraform.lock.hcl", Data: []byte("provider \"registry.terraform.io/hashicorp/aws\" {\n  version = \"5.31.0\"\n}\n")},
		{Path: "examples/basic/.terraform.lock.hcl", Data: []byte("provider \"registry.terraform.io/hashicorp/aws\" {\n  version = \"4.9.0\"\n}\n")},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(inst) != 2 {
		t.Fatalf("got %d instances, want 2 — both directories lock a version", len(inst))
	}
	if inst[0].Locator == inst[1].Locator {
		t.Error("both locks share a locator; one selection is hiding the other")
	}
}

package effective_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/source"
)

func TestUVLockYieldsFlatInstances(t *testing.T) {
	lock := []byte(`
version = 1

[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "Typing_Extensions"
version = "4.12.2"

[[package]]
name = "workspace-member"
`)
	got, err := effective.UVLock{}.Resolve(context.Background(),
		source.Static([]source.File{{Path: "uv.lock", Data: lock}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("instances = %d, want 2 (the versionless workspace member is skipped)", len(got))
	}
	by := map[string]effective.Instance{}
	for _, i := range got {
		by[i.Locator] = i
	}
	if by["requests"].NodeID != "pkg:pypi/requests@2.32.3" {
		t.Errorf("requests = %q", by["requests"].NodeID)
	}
	// PEP 503 normalisation must apply here too, or the lockfile entry will not
	// join against the node the manifest produced.
	if by["Typing_Extensions"].NodeID != "pkg:pypi/typing-extensions@4.12.2" {
		t.Errorf("scoped/underscored name = %q, want normalised", by["Typing_Extensions"].NodeID)
	}
	// Python environments are flat: one version per distribution, never nested.
	for _, i := range got {
		if i.ParentLocator != "" {
			t.Errorf("%s has a parent; Python installs a flat environment", i.Locator)
		}
	}
}

func TestUVLockAbsentYieldsNothing(t *testing.T) {
	got, err := effective.UVLock{}.Resolve(context.Background(),
		source.Static([]source.File{{Path: "pyproject.toml", Data: []byte("[project]")}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d instances, want 0", len(got))
	}
}

func TestUVLockMalformedSurfaces(t *testing.T) {
	_, err := effective.UVLock{}.Resolve(context.Background(),
		source.Static([]source.File{{Path: "uv.lock", Data: []byte("[[package\nbroken")}}))
	if err == nil {
		t.Error("malformed lockfile must surface")
	}
}

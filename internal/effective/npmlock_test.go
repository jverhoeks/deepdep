package effective_test

import (
	"context"
	"testing"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/source"
)

func resolve(t *testing.T, files ...source.File) []effective.Instance {
	t.Helper()
	got, err := effective.NPMLock{}.Resolve(context.Background(), source.Static(files))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// The distinction the whole "what would actually be installed" question turns
// on: npm hoists a package to one shared copy where ranges are compatible, and
// NESTS a second copy where they are not.
func TestHoistedAndNestedInstances(t *testing.T) {
	lock := []byte(`{
      "lockfileVersion": 3,
      "packages": {
        "": {"name":"root"},
        "node_modules/a": {"version":"1.0.0"},
        "node_modules/b": {"version":"1.0.0"},
        "node_modules/lodash": {"version":"4.17.21"},
        "node_modules/b/node_modules/lodash": {"version":"3.10.1"}
      }
    }`)
	by := map[string]effective.Instance{}
	for _, i := range resolve(t, source.File{Path: "package-lock.json", Data: lock}) {
		by[i.Locator] = i
	}

	if got := by["node_modules/lodash"].NodeID; got != "pkg:npm/lodash@4.17.21" {
		t.Errorf("hoisted lodash = %q", got)
	}
	if got := by["node_modules/b/node_modules/lodash"].NodeID; got != "pkg:npm/lodash@3.10.1" {
		t.Errorf("nested lodash = %q, want the SECOND copy at an incompatible version", got)
	}
	if got := by["node_modules/b/node_modules/lodash"].ParentLocator; got != "node_modules/b" {
		t.Errorf("nested parent = %q, want node_modules/b", got)
	}
	if got := by["node_modules/lodash"].ParentLocator; got != "" {
		t.Errorf("hoisted parent = %q, want empty (top level)", got)
	}
	for _, i := range by {
		if i.DerivedFrom != "lockfile" {
			t.Errorf("%s derived_from = %q, want lockfile — never recompute what npm wrote down", i.Locator, i.DerivedFrom)
		}
	}
}

func TestScopedPackagePaths(t *testing.T) {
	lock := []byte(`{"lockfileVersion":3,"packages":{
      "":{},
      "node_modules/@types/node":{"version":"20.1.0"},
      "node_modules/a/node_modules/@scope/deep":{"version":"2.0.0"}
    }}`)
	by := map[string]effective.Instance{}
	for _, i := range resolve(t, source.File{Path: "package-lock.json", Data: lock}) {
		by[i.Locator] = i
	}
	if got := by["node_modules/@types/node"].NodeID; got != "pkg:npm/%40types/node@20.1.0" {
		t.Errorf("scoped instance = %q", got)
	}
	if got := by["node_modules/a/node_modules/@scope/deep"].NodeID; got != "pkg:npm/%40scope/deep@2.0.0" {
		t.Errorf("nested scoped instance = %q", got)
	}
	if got := by["node_modules/a/node_modules/@scope/deep"].ParentLocator; got != "node_modules/a" {
		t.Errorf("nested scoped parent = %q, want node_modules/a", got)
	}
}

// With no lockfile there is no effective resolution. v1 reports `unknown` rather
// than guessing — guessing in either direction misleads.
func TestNoLockfileYieldsNoInstances(t *testing.T) {
	got := resolve(t, source.File{Path: "package.json", Data: []byte(`{"name":"x"}`)})
	if len(got) != 0 {
		t.Errorf("got %d instances, want 0", len(got))
	}
}

func TestLinkAndMissingVersionEntriesAreSkipped(t *testing.T) {
	lock := []byte(`{"lockfileVersion":3,"packages":{
      "":{},
      "node_modules/real":{"version":"1.0.0"},
      "node_modules/linked":{"link":true,"resolved":"packages/linked"},
      "node_modules/noversion":{}
    }}`)
	got := resolve(t, source.File{Path: "package-lock.json", Data: lock})
	if len(got) != 1 || got[0].Locator != "node_modules/real" {
		t.Errorf("got %+v, want only the one real package", got)
	}
}

func TestMalformedLockfileSurfacesError(t *testing.T) {
	_, err := effective.NPMLock{}.Resolve(context.Background(),
		source.Static([]source.File{{Path: "package-lock.json", Data: []byte(`{bad`)}}))
	if err == nil {
		t.Error("a malformed lockfile must surface, not silently yield zero instances")
	}
}

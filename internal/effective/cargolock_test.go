package effective_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/source"
)

func cargoResolve(t *testing.T, files ...source.File) []effective.Instance {
	t.Helper()
	inst, err := effective.CargoLock{}.Resolve(context.Background(), source.Static(files))
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

// A workspace member has no source: it is this repository's own crate, not
// something fetched. Counting it would make the project its own dependency and
// send it to crates.io for a package that was never published.
func TestCargoLockSkipsWorkspaceMembers(t *testing.T) {
	inst := cargoResolve(t, source.File{Path: "Cargo.lock", Data: []byte(`
[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)})
	if len(inst) != 1 {
		t.Fatalf("got %d instances, want 1 (serde only): %+v", len(inst), inst)
	}
	if string(inst[0].NodeID) != "pkg:cargo/serde@1.0.197" {
		t.Errorf("got %s, want pkg:cargo/serde@1.0.197", inst[0].NodeID)
	}
	if inst[0].DerivedFrom != "lockfile" {
		t.Errorf("DerivedFrom = %q, want lockfile", inst[0].DerivedFrom)
	}
}

// Semver-incompatible requirements coexist, so one crate is genuinely built at
// two versions. Both are real; keying the locator by name alone would hide one
// and understate the closure.
func TestCargoLockKeepsBothVersionsOfOneCrate(t *testing.T) {
	inst := cargoResolve(t, source.File{Path: "Cargo.lock", Data: []byte(`
[[package]]
name = "rand"
version = "0.7.3"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)})
	if len(inst) != 2 {
		t.Fatalf("got %d instances, want 2 — both versions are really built", len(inst))
	}
	if inst[0].Locator == inst[1].Locator {
		t.Error("both versions share a locator; one is hiding the other")
	}
}

func TestCargoLockIgnoresVendoredTrees(t *testing.T) {
	inst := cargoResolve(t,
		source.File{Path: "Cargo.lock", Data: []byte("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\n")},
		source.File{Path: "vendor/other/Cargo.lock", Data: []byte("[[package]]\nname = \"leaked\"\nversion = \"9.9.9\"\nsource = \"registry+x\"\n")},
	)
	for _, i := range inst {
		if strings.Contains(string(i.NodeID), "leaked") {
			t.Error("a vendored lockfile was read as this build's")
		}
	}
	if len(inst) != 1 {
		t.Fatalf("got %d instances, want 1", len(inst))
	}
}

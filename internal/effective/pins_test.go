package effective_test

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/graph"
)

// A pin is compared against the version string a resolver reports, so it has to
// come back out of the PURL decoded. splitID hand-decoded only %40, and only in
// the NAME — so any version carrying a character the PURL escapes produced a pin
// that could never match.
//
// Cargo exposed it: wasi 0.11.1+wasi-snapshot-preview1 encodes the + as %2B, and
// a full-fleet run turned 10 crates into error:pin-not-found. PEP 440 local
// versions (1.0+local) have the same shape.
func TestPinsDecodeVersionsOutOfThePURL(t *testing.T) {
	id, err := graph.NodeIDFor("cargo", "wasi", "0.11.1+wasi-snapshot-preview1")
	if err != nil {
		t.Fatal(err)
	}
	pins := effective.Pins([]effective.Instance{{Locator: "#wasi", NodeID: id, DerivedFrom: "lockfile"}})
	got, ok := pins["cargo/wasi"]
	if !ok {
		t.Fatalf("no pin recorded; got %v", pins)
	}
	if got != "0.11.1+wasi-snapshot-preview1" {
		t.Errorf("pin = %q, want the decoded version — an encoded one never matches a resolver", got)
	}
}

// The npm scope case must keep working: it is why the hand-rolled %40 decode
// existed in the first place.
func TestPinsDecodeScopedNPMNames(t *testing.T) {
	id, err := graph.NPMNodeID("@babel/core", "7.24.7")
	if err != nil {
		t.Fatal(err)
	}
	pins := effective.Pins([]effective.Instance{{Locator: "#b", NodeID: id, DerivedFrom: "lockfile"}})
	if got, ok := pins["npm/@babel/core"]; !ok || got != "7.24.7" {
		t.Errorf("pins = %v, want npm/@babel/core -> 7.24.7", pins)
	}
}

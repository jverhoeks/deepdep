package walk

import (
	"testing"

	"github.com/jverhoeks/deepdep/internal/graph"
)

// The closure takes the WIDEST reading: everything reachable counts, including
// a dependency's own optional extras.
//
// This was previously skipped for PyPI, which under-reported — on one Poetry
// repository, 125 packages sat behind `extra-not-requested` while 55 were
// resolved. An extra is code a downstream consumer can switch on without this
// repository changing a line, so it is genuinely reachable.
//
// The old rationale (pyobjc declares 300+ framework subpackages, fsspec 50
// cloud backends) is real, but it is a SIZE argument, and size is what
// MaxNodes and MaxDepth are for. Correctness of the answer is not their job.
func TestOptionalDependenciesAreWalkedEverywhere(t *testing.T) {
	for _, eco := range []string{"pypi", "npm", "cargo", "golang"} {
		if why, skip := skipScope(eco, graph.Optional); skip {
			t.Errorf("%s optional dependencies skipped as %q; everything reachable counts", eco, why)
		}
	}
}

// Dev is a different question and must NOT change. A dev dependency of the
// scanned repository arrives through the seed, which skipScope never sees; a dev
// edge reached THROUGH a package is installed by nobody.
func TestTransitiveDevDependenciesAreStillSkipped(t *testing.T) {
	for _, eco := range []string{"pypi", "npm", "cargo", "golang"} {
		why, skip := skipScope(eco, graph.Dev)
		if !skip {
			t.Errorf("%s transitive dev dependency was walked; nobody installs it", eco)
		}
		if why != ReasonDevNotInstalled {
			t.Errorf("%s dev reason = %q, want %q", eco, why, ReasonDevNotInstalled)
		}
	}
}

func TestProdIsNeverSkipped(t *testing.T) {
	for _, eco := range []string{"pypi", "npm", "cargo", "golang"} {
		if _, skip := skipScope(eco, graph.Prod); skip {
			t.Errorf("%s production dependency was skipped", eco)
		}
	}
}

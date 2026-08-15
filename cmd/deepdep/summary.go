package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/rollup"
)

// scanSummary is what a person wants to see when a scan finishes.
//
// It reports only what the scan itself knows: the surface it found, how much of
// it resolved, what it could not read, and what holds the versions in place.
// Advisories, reputation and the risk grade need OSV and deps.dev, so they
// belong to `report` — and the last line says so rather than leaving the reader
// to wonder whether this was the whole answer.
func scanSummary(g *graph.Graph, res rollup.Result, inst []effective.Instance,
	m emit.Meta, dbPath string, noDB bool) []byte {

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s @ %s   mode %s   as-of %s\n\n",
		orDash(m.Repo), short(m.Ref), m.Mode, m.AsOf.Format("2006-01-02"))

	var (
		pkgs, resolved int
		kinds          = map[string]int{}
		reasons        = map[string]int{}
		steps          int
		files          int
	)
	for _, n := range g.Nodes() {
		id := string(n.ID)
		switch {
		case graph.IsPackage(n.ID):
			pkgs++
			if n.Completeness == graph.Resolved {
				resolved++
			}
			kinds[ecoOf(id)]++
		case strings.HasPrefix(id, "pkg:oci/"):
			kinds["container images"]++
		case strings.HasPrefix(id, "pkg:github/"), strings.HasPrefix(id, "pkg:gitlab/"):
			kinds["CI actions"]++
		case strings.HasPrefix(id, "pkg:generic/buildfile/"):
			files++
		case n.Completeness == graph.Opaque:
			steps++
		}
		// Inferred is a SUCCESS: we named the package from a shell line. Only
		// Declared and Opaque nodes are frontiers, and listing an inference
		// under "could not expand" reads as a failure to do the thing we did.
		if n.Reason != "" && (n.Completeness == graph.Declared || n.Completeness == graph.Opaque) {
			reasons[n.Reason]++
		}
	}

	fmt.Fprintf(&b, "SURFACE\n")
	for _, k := range sortedIntKeys(kinds) {
		fmt.Fprintf(&b, "  %-22s %d\n", k, kinds[k])
	}
	fmt.Fprintf(&b, "  %-22s %d\n", "build/CI files", files)
	fmt.Fprintf(&b, "  %-22s %d\n", "shell build steps", steps)

	fmt.Fprintf(&b, "\nRESOLUTION\n")
	pct := 0
	if pkgs > 0 {
		pct = resolved * 100 / pkgs
	}
	fmt.Fprintf(&b, "  %d of %d package nodes resolved to a version (%d%%)\n", resolved, pkgs, pct)
	fmt.Fprintf(&b, "  %d on-disk instances from lockfiles\n", len(inst))
	if len(inst) == 0 {
		// The single most common reason a report later says "not graded".
		fmt.Fprintf(&b, "  no supported lockfile found — nothing could be confirmed as installed\n")
	}

	pin := map[rollup.Pinning]int{}
	for _, v := range res.Versions {
		pin[v.Pinning]++
	}
	if n := pin[rollup.Pinned] + pin[rollup.Locked] + pin[rollup.Floating]; n > 0 {
		fmt.Fprintf(&b, "  pinned %d   locked %d   floating %d\n",
			pin[rollup.Pinned], pin[rollup.Locked], pin[rollup.Floating])
	}

	if len(reasons) > 0 {
		fmt.Fprintf(&b, "\nCOULD NOT EXPAND\n")
		for _, k := range sortedIntKeys(reasons) {
			fmt.Fprintf(&b, "  %-22s %d\n", k, reasons[k])
		}
	}

	fmt.Fprintf(&b, "\nnext: deepdep report")
	if !noDB && dbPath != defaultDBPath() {
		fmt.Fprintf(&b, " --db %s", dbPath)
	}
	fmt.Fprintf(&b, "\n  adds advisories, malicious packages, upstream posture and the risk grade\n")
	if noDB {
		fmt.Fprintf(&b, "  (this run was not stored: drop --no-db to make it reportable)\n")
	}
	return b.Bytes()
}

func ecoOf(id string) string {
	s := strings.TrimPrefix(id, "pkg:")
	typ, _, _ := strings.Cut(s, "/")
	switch typ {
	case "deb", "apk", "rpm":
		return "OS packages"
	}
	return typ + " packages"
}

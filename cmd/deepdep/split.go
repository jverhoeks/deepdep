package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/graph"
)

// writeSplitSBOMs emits one CycloneDX document per deliverable and returns a
// manifest of what it wrote.
//
// The manifest ends with the exact `cyclonedx merge --hierarchical` invocation,
// because a directory of documents is only half an answer: the handbook's
// prescription for a multi-layer product is per-layer SBOMs merged
// hierarchically, and a flat merge would throw away the layering that makes
// "which container brought this in?" answerable.
func writeSplitSBOMs(dir string, g *graph.Graph, inst []effective.Instance,
	root graph.NodeID, m emit.Meta, opts emit.CycloneDXOptions) ([]byte, error) {

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	units := emit.Split(g, inst, root)

	var (
		manifest bytes.Buffer
		files    []string
	)
	fmt.Fprintf(&manifest, "%d documents in %s\n\n", len(units), dir)
	for _, u := range units {
		name := strings.NewReplacer("/", "_", " ", "-").Replace(u.Name) + ".cdx.json"
		p := filepath.Join(dir, name)

		um := m
		// Each document describes its OWN subject, so the unit's synthetic root
		// has to be the ref the emitter recognises as the metadata component.
		um.Repo = u.Name
		um.Ref = unitRefOf(u.Root)

		var buf bytes.Buffer
		if err := emit.CycloneDX(&buf, u.Graph, um, opts); err != nil {
			return nil, fmt.Errorf("%s: %w", u.Name, err)
		}
		if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
			return nil, err
		}
		files = append(files, p)
		n, err := countComponents(buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u.Name, err)
		}
		fmt.Fprintf(&manifest, "  %-12s %-46s %d components\n", u.Kind, name, n)
	}

	fmt.Fprintf(&manifest, "\nmerge into one deliverable:\n  cyclonedx merge --hierarchical \\\n")
	fmt.Fprintf(&manifest, "    --name %s --version <release> \\\n", orDash(m.Repo))
	fmt.Fprintf(&manifest, "    --output-file product.cdx.json \\\n    --input-files")
	for _, f := range files {
		fmt.Fprintf(&manifest, " \\\n      %s", f)
	}
	fmt.Fprintln(&manifest)
	fmt.Fprintln(&manifest, "\nthese cover the SOURCE layer only. Per the handbook, add one")
	fmt.Fprintln(&manifest, "`syft <image> -o cyclonedx-json` per built image for the BUILD layer:")
	fmt.Fprintln(&manifest, "deepdep reads Dockerfiles, it never builds them, so it cannot know")
	fmt.Fprintln(&manifest, "which transitive OS packages apt actually pulled.")
	return manifest.Bytes(), nil
}

// unitRefOf recovers the version half of a unit's synthetic root PURL, which is
// what emit.CycloneDX matches on to pick the metadata component.
func unitRefOf(id graph.NodeID) string {
	if i := strings.LastIndex(string(id), "@"); i >= 0 {
		return string(id)[i+1:]
	}
	return ""
}

// countComponents reads the array rather than counting bom-ref substrings: the
// metadata component carries one too, so a string count reports every unit as
// one component larger than it is.
func countComponents(b []byte) (int, error) {
	var doc struct {
		Components []struct{} `json:"components"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return 0, err
	}
	return len(doc.Components), nil
}

// Mermaid renders a repository's supply-chain surfaces as a diagram, bounded so
// it stays readable.
//
// A scan produces between a thousand and fifty thousand nodes and Mermaid stops
// being legible somewhere around a hundred, so drawing the graph is not an
// option and "draw the first hundred nodes" would be a picture of the alphabet.
// This draws the SHAPE instead: the repository, each build file that names
// something, and — under each — only the artifacts that carry a finding.
//
// That makes it a risk map rather than a dependency dump. A clean repository
// renders as a handful of boxes with counts, which is the correct picture of a
// clean repository, and every box that appears is a box someone has to act on.
package emit

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// MermaidHit is one artifact worth drawing: it carries a finding, or it moves.
type MermaidHit struct {
	Label    string // display name, already shortened
	Severity string // MALICIOUS | CRITICAL | HIGH | MODERATE | LOW | UNKNOWN | ""
	Count    int    // advisories against it
	Moving   bool   // reference can be repointed
	Note     string // optional, e.g. "advisory not version-matched"
}

// MermaidFile is a build-definition file and what it pulls in.
type MermaidFile struct {
	Kind   string // dockerfile | ci | manifest
	Path   string
	Names  int // everything it names, findings or not
	Moving int // of those, on a reference that can be repointed
	Hits   []MermaidHit
}

// MermaidInput is everything the diagram draws. Deliberately a flat,
// purpose-built struct: the emitter does no querying and no severity ranking of
// its own, so what it draws can never disagree with what the report printed.
type MermaidInput struct {
	Repo, Ref string
	Grade     string
	Files     []MermaidFile

	// MaxFiles bounds how many build files are drawn, worst first; the rest are
	// summarised in one node. MaxPerFile does the same for artifacts under each.
	MaxFiles, MaxPerFile int
}

const (
	defaultMaxFiles   = 12
	defaultMaxPerFile = 6
)

// Mermaid writes a fenced ```mermaid block, ready to paste into a README, a PR
// comment or an issue.
func Mermaid(w io.Writer, in MermaidInput) error {
	maxFiles, maxPer := in.MaxFiles, in.MaxPerFile
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}
	if maxPer <= 0 {
		maxPer = defaultMaxPerFile
	}

	files := append([]MermaidFile(nil), in.Files...)
	// Worst first, so a bound drops the least interesting files rather than an
	// arbitrary set. A file with a malicious package must never be the one cut.
	sort.SliceStable(files, func(i, j int) bool {
		a, b := weight(files[i]), weight(files[j])
		if a != b {
			return a > b
		}
		return files[i].Path < files[j].Path
	})

	var b strings.Builder
	b.WriteString("```mermaid\ngraph LR\n")

	root := fmt.Sprintf("%s<br/><small>%s</small>", esc(in.Repo), esc(short(in.Ref)))
	if in.Grade != "" {
		root = fmt.Sprintf("%s<br/><small>risk %s</small>", esc(in.Repo), esc(in.Grade))
	}
	fmt.Fprintf(&b, "  root[%q]\n", root)

	drawn := files
	hidden := 0
	if len(files) > maxFiles {
		drawn, hidden = files[:maxFiles], len(files)-maxFiles
	}

	for i, f := range drawn {
		fid := fmt.Sprintf("F%d", i)
		sub := fmt.Sprintf("%d named", f.Names)
		if f.Moving > 0 {
			sub += fmt.Sprintf(" · %d moving", f.Moving)
		}
		fmt.Fprintf(&b, "  root --> %s[%q]\n", fid,
			fmt.Sprintf("%s<br/><small>%s</small>", esc(trimPath(f.Path)), sub))
		fmt.Fprintf(&b, "  class %s %s\n", fid, kindClass(f.Kind))

		hits := f.Hits
		more := 0
		if len(hits) > maxPer {
			hits, more = hits[:maxPer], len(hits)-maxPer
		}
		for j, h := range hits {
			hid := fmt.Sprintf("%s_%d", fid, j)
			label := esc(h.Label)
			var tags []string
			if h.Count > 0 {
				// An OSV record with no severity field is not a zero-severity
				// record — the malicious-packages feed has none at all — so the
				// label says "unrated" rather than rendering an empty word.
				sev := strings.ToLower(h.Severity)
				if sev == "" || sev == "unknown" {
					sev = "unrated"
				}
				noun := "advisories"
				if h.Count == 1 {
					noun = "advisory"
				}
				tags = append(tags, fmt.Sprintf("%d %s %s", h.Count, sev, noun))
			}
			if h.Moving {
				tags = append(tags, "moving ref")
			}
			if h.Note != "" {
				tags = append(tags, esc(h.Note))
			}
			if len(tags) > 0 {
				label += "<br/><small>" + strings.Join(tags, " · ") + "</small>"
			}
			fmt.Fprintf(&b, "  %s --> %s[%q]\n", fid, hid, label)
			fmt.Fprintf(&b, "  class %s %s\n", hid, sevClass(h.Severity, h.Moving))
		}
		if more > 0 {
			fmt.Fprintf(&b, "  %s --> %s_more[%q]\n", fid, fid,
				fmt.Sprintf("… %d more", more))
			fmt.Fprintf(&b, "  class %s_more muted\n", fid)
		}
	}
	if hidden > 0 {
		// A bound that fired is stated, never silent — the same rule the walker
		// follows. A diagram that quietly drops half a repository's Dockerfiles
		// reads as a repository with half as many Dockerfiles.
		fmt.Fprintf(&b, "  root --> Fmore[%q]\n",
			fmt.Sprintf("… %d more build files<br/><small>no findings, or below the cap</small>", hidden))
		b.WriteString("  class Fmore muted\n")
	}

	b.WriteString(classDefs)
	b.WriteString("```\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// weight ranks a file by the worst thing under it. Malicious code outranks
// everything, for the same reason it clamps the grade.
func weight(f MermaidFile) int {
	w := 0
	for _, h := range f.Hits {
		switch h.Severity {
		case "MALICIOUS":
			w += 100000
		case "CRITICAL":
			w += 1000
		case "HIGH":
			w += 100
		default:
			w += 10
		}
	}
	return w + f.Moving
}

func kindClass(kind string) string {
	switch kind {
	case "dockerfile":
		return "docker"
	case "ci":
		return "ci"
	default:
		return "manifest"
	}
}

func sevClass(sev string, moving bool) string {
	switch sev {
	case "MALICIOUS":
		return "mal"
	case "CRITICAL":
		return "crit"
	case "HIGH":
		return "high"
	case "":
		if moving {
			return "moving"
		}
		return "muted"
	default:
		return "low"
	}
}

// classDefs keep the diagram legible on both light and dark backgrounds, which
// a README is read on both of. Colour carries severity; it never carries the
// only copy of the information, because the same text is in every label.
const classDefs = `
  classDef mal      fill:#450a0a,stroke:#f87171,color:#fecaca,stroke-width:2px
  classDef crit     fill:#7f1d1d,stroke:#ef4444,color:#fee2e2
  classDef high     fill:#9a3412,stroke:#f97316,color:#ffedd5
  classDef low      fill:#78350f,stroke:#f59e0b,color:#fef3c7
  classDef moving   fill:#1e3a5f,stroke:#60a5fa,color:#dbeafe
  classDef muted    fill:#334155,stroke:#94a3b8,color:#e2e8f0
  classDef docker   fill:#164e63,stroke:#22d3ee,color:#cffafe
  classDef ci       fill:#312e81,stroke:#818cf8,color:#e0e7ff
  classDef manifest fill:#14532d,stroke:#4ade80,color:#dcfce7
`

// esc keeps a label from breaking the diagram. Mermaid takes the quoted form
// literally apart from these, and a package name legitimately contains both.
func esc(s string) string {
	r := strings.NewReplacer(`"`, "&quot;", "[", "&#91;", "]", "&#93;",
		"{", "&#123;", "}", "&#125;", "\n", " ")
	return r.Replace(s)
}

// trimPath keeps the tail of a long path: `.github/workflows/ci.yml` reads,
// `a/b/c/d/e/f/.github/workflows/ci.yml` does not.
func trimPath(p string) string {
	if len(p) <= 44 {
		return p
	}
	parts := strings.Split(p, "/")
	if len(parts) <= 2 {
		return "…" + p[len(p)-43:]
	}
	return "…/" + strings.Join(parts[len(parts)-2:], "/")
}

func short(ref string) string {
	if len(ref) > 8 {
		return ref[:8]
	}
	return ref
}

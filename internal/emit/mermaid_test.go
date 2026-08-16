package emit_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/emit"
)

func render(t *testing.T, in emit.MermaidInput) string {
	t.Helper()
	var b bytes.Buffer
	if err := emit.Mermaid(&b, in); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A bound that fires is stated, never silent. A diagram that quietly drops half
// a repository's Dockerfiles is a picture of a repository with half as many
// Dockerfiles, which is the same silent-omission failure the walker exists to
// avoid.
func TestMermaidStatesWhatItDropped(t *testing.T) {
	in := emit.MermaidInput{Repo: "example/repo", MaxFiles: 2, MaxPerFile: 1}
	for i := 0; i < 5; i++ {
		in.Files = append(in.Files, emit.MermaidFile{
			Kind: "ci", Path: "wf.yml", Names: 3,
			Hits: []emit.MermaidHit{
				{Label: "a", Severity: "HIGH", Count: 1},
				{Label: "b", Severity: "HIGH", Count: 1},
			},
		})
	}
	out := render(t, in)
	if !strings.Contains(out, "3 more build files") {
		t.Errorf("dropped files silently:\n%s", out)
	}
	if !strings.Contains(out, "… 1 more") {
		t.Errorf("dropped artifacts silently:\n%s", out)
	}
}

// Malicious code outranks everything, for the same reason it clamps the grade.
// If a bound has to drop a file, it must never be the one holding a worm.
func TestMermaidDrawsTheWorstFileFirst(t *testing.T) {
	in := emit.MermaidInput{Repo: "r", MaxFiles: 1}
	in.Files = []emit.MermaidFile{
		{Kind: "ci", Path: "quiet.yml", Hits: []emit.MermaidHit{{Label: "x", Severity: "LOW", Count: 1}}},
		{Kind: "manifest", Path: "loud", Hits: []emit.MermaidHit{{Label: "worm", Severity: "MALICIOUS", Count: 1}}},
	}
	out := render(t, in)
	if !strings.Contains(out, "worm") {
		t.Errorf("the malicious file was cut by the bound:\n%s", out)
	}
	if strings.Contains(out, "quiet.yml") {
		t.Errorf("kept the quiet file over the malicious one:\n%s", out)
	}
}

// A package name containing a quote or a bracket must not break the diagram —
// scoped npm names and rpm names carry both.
func TestMermaidEscapesLabels(t *testing.T) {
	out := render(t, emit.MermaidInput{
		Repo: `we"ird`,
		Files: []emit.MermaidFile{{Kind: "manifest", Path: "m", Names: 1,
			Hits: []emit.MermaidHit{{Label: `pkg[1]{x}"y`, Severity: "HIGH", Count: 1}}}},
	})
	for _, bad := range []string{`we"ird`, `pkg[1]`} {
		if strings.Contains(out, bad) {
			t.Errorf("unescaped %q in output:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "&quot;") || !strings.Contains(out, "&#91;") {
		t.Errorf("expected escapes missing:\n%s", out)
	}
}

// An OSV record with no severity is not a zero-severity record — the
// malicious-packages feed has none at all — so an empty word must never reach
// the label.
func TestMermaidNamesUnratedSeverity(t *testing.T) {
	out := render(t, emit.MermaidInput{
		Repo: "r",
		Files: []emit.MermaidFile{{Kind: "dockerfile", Path: "Dockerfile", Names: 1,
			Hits: []emit.MermaidHit{{Label: "p", Severity: "", Count: 2}}}},
	})
	if !strings.Contains(out, "2 unrated advisories") {
		t.Errorf("severity-less finding rendered badly:\n%s", out)
	}
}

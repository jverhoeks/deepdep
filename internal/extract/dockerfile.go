package extract

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// Dockerfile extracts the image layer: base images and what the build installs
// into them.
//
// This is a SOURCE view of the container, not a Build one. It reports what the
// Dockerfile declares; it never builds the image, so it cannot know which
// transitive OS packages apt actually pulled. `syft` against the built image
// answers that, and the two are complementary — this one works from a git
// checkout with no daemon, no registry pull and no code execution.
type Dockerfile struct{}

func (Dockerfile) Name() string { return "dockerfile" }

// Match covers the spellings that occur in the wild. Podman's Containerfile is
// the same format under a different name.
func (Dockerfile) Match(p string) bool {
	b := path.Base(p)
	switch {
	case b == "Dockerfile" || b == "Containerfile":
		return true
	case strings.HasPrefix(b, "Dockerfile."), strings.HasPrefix(b, "Containerfile."):
		return true // Dockerfile.dbt, Dockerfile.kernel
	case strings.HasSuffix(b, ".Dockerfile"):
		return true
	}
	return false
}

// digestRe marks the only genuinely pinned form. A tag can be re-pointed at any
// time by whoever owns the repository; a digest cannot.
var digestRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// varRe matches ${NAME}, ${NAME:-default} and $NAME.
var varRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:?[-+][^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

const (
	// ReasonUnresolvedArg marks a base image whose tag comes from a build ARG
	// with no default. `FROM ${MLFLOW_BASE}` is genuinely undecidable from the
	// repository alone — the value arrives at build time.
	ReasonUnresolvedArg = "unresolved-arg"
	// ReasonInferredRun marks a package parsed out of a shell line rather than
	// read from a manifest.
	ReasonInferredRun = "inferred:run"
)

func (Dockerfile) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	// The Dockerfile itself is a node, and everything it pulls in hangs off it
	// rather than off the repository root.
	//
	// Without this, a base image shared by four Dockerfiles is ONE deduplicated
	// node whose Source is whichever file reached it first — and the other three
	// report no base image at all. `cli/Dockerfile` rendered with zero images in
	// a real scan for exactly that reason. Attribution is per-occurrence data, so
	// it has to live on edges; the interface already allows an explicit From, and
	// only From == "" is rewritten to the root.
	file := BuildFileNode("dockerfile", f.Path)

	var (
		edges = []graph.Edge{{From: "", To: file.ID, Kind: graph.Invokes}}
		nodes = []graph.Node{file}
		seen  = map[graph.NodeID]bool{}
	)
	emit := func(n graph.Node, kind graph.EdgeKind) {
		if n.ID == "" {
			return
		}
		// The EDGE is always recorded — that is the attribution — while the node
		// is added once.
		edges = append(edges, graph.Edge{From: file.ID, To: n.ID, Kind: kind})
		if seen[n.ID] {
			return
		}
		seen[n.ID] = true
		nodes = append(nodes, n)
	}

	args := map[string]string{}
	stages := map[string]bool{}

	for _, ins := range parseDockerfile(f.Data) {
		verb, rest := ins.verb, ins.args
		switch verb {
		case "ARG":
			// Only ARGs with a default are usable statically. One without a
			// value is supplied at build time and stays unknown on purpose.
			if k, v, ok := strings.Cut(rest, "="); ok {
				args[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
			}

		case "FROM":
			base, stage := parseFrom(rest)
			if stage != "" {
				stages[strings.ToLower(stage)] = true
			}
			// A reference to an earlier stage is internal to this file. Minting
			// pkg:oci/builder for `FROM builder` would invent a registry image
			// that does not exist — the single most likely multi-stage bug.
			if stages[strings.ToLower(base)] {
				continue
			}
			if strings.EqualFold(base, "scratch") {
				continue // the empty image; there is nothing to pull
			}
			expanded, complete := expandVars(base, args)
			if !complete {
				emit(unresolvedBase(expanded), graph.BuildsOn)
				continue
			}
			emit(baseImageNode(expanded), graph.BuildsOn)

		case "RUN":
			cmd := strings.TrimSpace(rest)
			if cmd == "" {
				continue
			}
			// Two different facts from one line, so both are emitted: the raw
			// command (which formulation renders as a build step, and which is
			// the honest record when parsing fails) and any packages we can
			// actually name.
			emit(opaqueNode(cmd), graph.Installs)
			for _, n := range runPackages(cmd) {
				emit(n, graph.Installs)
			}
		}
	}

	for i := range nodes {
		nodes[i].Source = f.Path
	}
	return edges, nodes, nil
}

// ---- parsing -------------------------------------------------------------

type instruction struct{ verb, args string }

// parseDockerfile joins continuations and strips comments.
//
// The escape character is configurable by a parser directive — Windows builds
// use a backtick because backslash is a path separator — and getting it wrong
// merges unrelated lines into one instruction.
func parseDockerfile(b []byte) []instruction {
	escape := byte('\\')
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")

	// Parser directives are only honoured before the first non-comment line.
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if !strings.HasPrefix(t, "#") {
			break
		}
		if d := strings.TrimSpace(strings.TrimPrefix(t, "#")); strings.HasPrefix(strings.ToLower(d), "escape=") {
			if v := strings.TrimSpace(d[len("escape="):]); len(v) == 1 {
				escape = v[0]
			}
		}
	}

	var out []instruction
	var buf strings.Builder
	for _, l := range lines {
		t := strings.TrimRight(l, " \t")
		if strings.HasPrefix(strings.TrimSpace(t), "#") {
			continue // a comment line is removed even mid-continuation
		}
		if buf.Len() == 0 && strings.TrimSpace(t) == "" {
			continue
		}
		if len(t) > 0 && t[len(t)-1] == escape {
			buf.WriteString(strings.TrimSuffix(t, string(escape)))
			buf.WriteString(" ")
			continue
		}
		buf.WriteString(t)
		if s := strings.TrimSpace(buf.String()); s != "" {
			verb, rest, _ := strings.Cut(s, " ")
			out = append(out, instruction{strings.ToUpper(verb), strings.TrimSpace(rest)})
		}
		buf.Reset()
	}
	return out
}

// parseFrom strips flags and splits off the stage alias.
func parseFrom(rest string) (base, stage string) {
	fields := strings.Fields(rest)
	for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
		fields = fields[1:] // --platform=$BUILDPLATFORM
	}
	if len(fields) == 0 {
		return "", ""
	}
	base = fields[0]
	if len(fields) >= 3 && strings.EqualFold(fields[1], "AS") {
		stage = fields[2]
	}
	return base, stage
}

// expandVars substitutes ARGs with defaults. complete is false when anything is
// left unsubstituted, which is the difference between a known image and a
// build-time decision we cannot see.
func expandVars(s string, args map[string]string) (string, bool) {
	complete := true
	out := varRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := varRe.FindStringSubmatch(m)
		name := sub[1]
		if name == "" {
			name = sub[3]
		}
		if v, ok := args[name]; ok && v != "" {
			return v
		}
		// ${VAR:-default} carries its own fallback.
		if mod := sub[2]; strings.HasPrefix(mod, ":-") || strings.HasPrefix(mod, "-") {
			if d := strings.TrimLeft(mod, ":-"); d != "" {
				return d
			}
		}
		complete = false
		return m
	})
	return out, complete
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// baseImageNode mints the OCI node, and is the one place a Dockerfile can yield
// a genuinely Resolved artifact: a digest-pinned FROM is immutable.
func baseImageNode(ref string) graph.Node {
	n, err := imageNode(strings.TrimPrefix(ref, "docker.io/library/"))
	if err != nil {
		return unresolvedBase(ref)
	}
	if digestRe.MatchString(ref) {
		n.Completeness = graph.Resolved
		n.Reason = ""
		// Recorded even though it is already in the id: ref_obs is how a tag's
		// past digests stay answerable, and a digest-pinned FROM is the ground
		// truth other observations are compared against.
		n.ResolvedRef = ref[strings.Index(ref, "@sha256:")+1:]
	}
	return n
}

// unresolvedBase records a base image whose identity depends on a build-time
// argument. Declared, not Opaque: we know a base image is pulled here and we
// know the expression — we just cannot evaluate it without the build's inputs.
func unresolvedBase(expr string) graph.Node {
	n := hashedNode("unresolved-image", expr)
	n.Ecosystem = "oci"
	n.Name = expr
	n.Completeness = graph.Declared
	n.Reason = ReasonUnresolvedArg
	n.Note = "FROM " + expr
	return n
}

// ---- RUN package parsing -------------------------------------------------

// installer maps a shell installer to the PURL type its packages carry.
var installers = []struct {
	prefix []string
	typ    string
	// pinSep is how that ecosystem pins a version on the command line.
	pinSep string
}{
	{[]string{"apt-get", "install"}, "deb", "="},
	{[]string{"apt", "install"}, "deb", "="},
	{[]string{"apk", "add"}, "alpine", "="},
	{[]string{"pip", "install"}, "pypi", "=="},
	{[]string{"pip3", "install"}, "pypi", "=="},
	{[]string{"uv", "pip", "install"}, "pypi", "=="},
	{[]string{"npm", "install"}, "npm", "@"},
	{[]string{"npm", "i"}, "npm", "@"},
}

// runPackages names what a RUN line installs.
//
// Inferred, never Resolved: this is shell text, and a heuristic that reads
// `apt-get install python3` correctly will also mis-read something. The raw
// command is always emitted alongside as an opaque step, so a reader can check
// the inference against the source rather than having to trust it.
//
// Deliberately conservative. Anything with a shell variable, a subshell, or a
// requirements file is left to the opaque node — guessing there produces
// confident nonsense, which is worse than a named unknown.
func runPackages(cmd string) []graph.Node {
	var out []graph.Node
	for _, part := range splitShell(cmd) {
		fields := strings.Fields(part)
		for _, ins := range installers {
			rest, ok := matchPrefix(fields, ins.prefix)
			if !ok {
				continue
			}
			skipNext := false
			for _, tok := range rest {
				if skipNext {
					skipNext = false
					continue
				}
				if strings.HasPrefix(tok, "-") {
					// A flag that takes a SEPARATE value swallows the next
					// token, or its argument is read as a package: `pip install
					// -r requirements.txt` otherwise yields a package named
					// requirements.txt, which PEP 503 then normalises into the
					// entirely plausible-looking pkg:pypi/requirements-txt.
					if valueFlags[tok] {
						skipNext = true
					}
					continue
				}
				if strings.ContainsAny(tok, "$`(){}*/") {
					continue // variable, subshell, glob or a path: not a name
				}
				if isFilename(tok) {
					continue // a file argument that slipped past the flag list
				}
				name, ver := tok, ""
				if i := strings.LastIndex(tok, ins.pinSep); i > 0 {
					name, ver = tok[:i], tok[i+len(ins.pinSep):]
				}
				if name == "" || !plainName(name) {
					continue
				}
				id, err := graph.NodeIDFor(ins.typ, name, ver)
				if err != nil {
					continue
				}
				out = append(out, graph.Node{
					ID: id, Ecosystem: ins.typ, Name: name, Version: ver,
					Completeness: graph.Inferred, Reason: ReasonInferredRun,
					Note: strings.TrimSpace(part),
				})
			}
			break
		}
	}
	return out
}

// splitShell breaks a RUN line on the operators that start a new command, so
// `apt-get update && apt-get install -y curl` yields two commands and only the
// second is read as an install.
func splitShell(cmd string) []string {
	r := strings.NewReplacer("&&", "\n", "||", "\n", ";", "\n", "|", "\n")
	return strings.Split(r.Replace(cmd), "\n")
}

func matchPrefix(fields, prefix []string) ([]string, bool) {
	if len(fields) < len(prefix) {
		return nil, false
	}
	for i, p := range prefix {
		if fields[i] != p {
			return nil, false
		}
	}
	return fields[len(prefix):], true
}

// valueFlags are the options whose value is a SEPARATE argument. Only the
// separate form matters: --index-url=X is one token and needs no lookahead.
var valueFlags = map[string]bool{
	// pip / uv
	"-r": true, "--requirement": true, "-c": true, "--constraint": true,
	"-e": true, "--editable": true, "-t": true, "--target": true,
	"-i": true, "--index-url": true, "--extra-index-url": true,
	"-f": true, "--find-links": true, "--trusted-host": true,
	"--python": true, "--prefix": true, "--root": true, "--src": true,
	// apt / apk
	"-o": true, "--target-release": true, "--repository": true,
	"-X": true, "--virtual": true,
	// npm
	"--registry": true, "-w": true, "--workspace": true, "--tag": true,
}

// fileExts are argument shapes that are never package names.
var fileExts = []string{".txt", ".in", ".toml", ".cfg", ".lock", ".json", ".yaml", ".yml", ".sh", ".whl", ".tar", ".gz"}

func isFilename(s string) bool {
	l := strings.ToLower(s)
	for _, e := range fileExts {
		if strings.HasSuffix(l, e) {
			return true
		}
	}
	return false
}

// plainName rejects anything that is not shaped like a package name.
//
// The leading-alphanumeric rule matters more than it looks: `pip install .`
// installs the local project, and "." passes a naive character check, then PEP
// 503 normalisation turns it into a package literally named "-". That reached a
// real SBOM as pkg:pypi/-.
func plainName(s string) bool {
	if s == "" {
		return false
	}
	first := rune(s[0])
	if !isAlnum(first) {
		return false
	}
	for _, r := range s {
		switch {
		case isAlnum(r):
		case r == '-', r == '_', r == '.', r == '+', r == '@':
		default:
			return false
		}
	}
	return true
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

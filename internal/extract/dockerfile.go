package extract

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"

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
	// ReasonAssumedDistro marks an OS package whose distribution namespace was
	// defaulted because the base image did not identify it. deb/debian and
	// deb/ubuntu carry DIFFERENT advisories, so the assumption is load-bearing.
	ReasonAssumedDistro = "inferred:run,distro-assumed"
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
	// A multi-stage Dockerfile can switch distributions between stages, so the
	// base image in force is tracked per stage rather than per file.
	stageBase := ""

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
				stageBase = ""
				emit(unresolvedBase(expanded), graph.BuildsOn)
				continue
			}
			// The stage check has to happen AGAIN here. `FROM builder-${DEVICE}`
			// with `ARG DEVICE=cpu` names an earlier stage, but only after
			// substitution — checked before, the literal matches nothing and the
			// stage alias is emitted as `pkg:oci/builder-cpu@latest`. That
			// invents a registry image, and because a bare stage name carries no
			// tag it lands in the unpinned bucket, overstating how many base
			// images across a fleet float on a movable tag.
			if stages[strings.ToLower(expanded)] {
				continue
			}
			stageBase = expanded
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
			for _, n := range runPackages(cmd, stageBase) {
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
//
// The OS types need a NAMESPACE — the distribution — and getting it wrong is
// not cosmetic. Verified against OSV: pkg:deb/debian/curl returns 71
// advisories, pkg:deb/curl returns 0, and `alpine` is not a PURL type at all
// (the spec says apk with an `alpine` namespace). Every OS package this
// extractor emitted before this was unmatchable by any advisory database.
//
// family is what the COMMAND proves: you cannot run apt-get on Alpine. The
// distro namespace is refined from the stage's base image where it is knowable.
var installers = []struct {
	prefix []string
	typ    string
	family string // "" for language ecosystems, which need no distro
	// pinSep is how that ecosystem pins a version on the command line.
	pinSep string
}{
	{[]string{"apt-get", "install"}, "deb", "deb", "="},
	{[]string{"apt", "install"}, "deb", "deb", "="},
	{[]string{"apk", "add"}, "apk", "apk", "="},
	{[]string{"yum", "install"}, "rpm", "rpm", "-"},
	{[]string{"dnf", "install"}, "rpm", "rpm", "-"},
	{[]string{"microdnf", "install"}, "rpm", "rpm", "-"},
	{[]string{"zypper", "install"}, "rpm", "rpm", "-"},
	{[]string{"pip", "install"}, "pypi", "", "=="},
	{[]string{"pip3", "install"}, "pypi", "", "=="},
	{[]string{"uv", "pip", "install"}, "pypi", "", "=="},
	{[]string{"npm", "install"}, "npm", "", "@"},
	{[]string{"npm", "i"}, "npm", "", "@"},
}

// distroDefaults is the namespace to use when the command names a family but
// the base image does not identify the distribution.
var distroDefaults = map[string]string{"deb": "debian", "apk": "alpine", "rpm": "redhat"}

// distroOf infers the distribution from a base image reference.
//
// Two signals: the image NAME (alpine, debian, ubuntu, rockylinux) and the TAG,
// because the overwhelming majority of language images are distro variants —
// python:3.12-slim is Debian, node:24-alpine is Alpine — and the tag is the only
// place that says so.
func distroOf(image string) (family, distro string) {
	l := strings.ToLower(image)
	switch {
	case strings.Contains(l, "alpine"):
		return "apk", "alpine"
	case strings.Contains(l, "ubuntu"),
		containsAny(l, "jammy", "noble", "focal", "bionic", "plucky"):
		return "deb", "ubuntu"
	case strings.Contains(l, "debian"),
		containsAny(l, "bookworm", "bullseye", "trixie", "buster", "slim"):
		return "deb", "debian"
	case containsAny(l, "rockylinux", "rocky"):
		return "rpm", "rocky"
	case strings.Contains(l, "almalinux"):
		return "rpm", "almalinux"
	case containsAny(l, "redhat", "ubi8", "ubi9", "rhel"):
		return "rpm", "redhat"
	case strings.Contains(l, "fedora"):
		return "rpm", "fedora"
	case strings.Contains(l, "opensuse"), strings.Contains(l, "suse"):
		return "rpm", "opensuse"
	}
	return "", ""
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
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
func runPackages(cmd, baseImage string) []graph.Node {
	imgFamily, imgDistro := distroOf(baseImage)
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
				if strings.ContainsAny(tok, "$`(){}*") {
					continue // variable, subshell or glob: not a name
				}
				// A slash normally means a path, EXCEPT in an npm scope. Rejecting
				// it outright dropped every scoped package installed from a RUN
				// line — and scoped packages are precisely what the Shai-Hulud
				// worm compromised (@ctrl/tinycolor, @crowdstrike/*), so this
				// silently hid the highest-severity findings the tool can make.
				if strings.Contains(tok, "/") && !isNPMScope(tok) {
					continue
				}
				if isFilename(tok) {
					continue // a file argument that slipped past the flag list
				}
				name, ver := tok, ""
				// LastIndex, and strictly > 0: a scoped name's leading @ is at
				// index 0 and is part of the NAME, not a version separator.
				if i := strings.LastIndex(tok, ins.pinSep); i > 0 {
					cand := tok[i+len(ins.pinSep):]
					// rpm pins with a bare hyphen — `curl-7.88.1` — and rpm
					// package names are full of hyphens too. Splitting on the
					// last one turned `lapack-devel` into lapack@devel,
					// `yum-utils` into yum@utils and `gcc-toolset-13-gcc-c++`
					// into a package versioned "c++": wrong PURLs that OSV then
					// answered anyway, so the Dockerfile surface reported
					// findings against packages that were never installed.
					//
					// A version starts with a digit. Requiring that costs an
					// unpinned `curl` nothing — it was version-less already —
					// and a genuine `curl-7.88.1` still splits.
					if ins.pinSep != "-" || startsWithDigit(cand) {
						name, ver = tok[:i], cand
					}
				}
				// `npm install -g pkg@latest` pins nothing. A dist-tag is a
				// MOVING reference — the same vocabulary as an unpinned image
				// tag or a branch ref — and minting it as a version is not a
				// cosmetic error: OSV was asked about `npm/npm@latest`, could
				// not order it against any fixed range, and answered with every
				// npm advisory back to 2013. Six CRITICAL and 36 HIGH findings
				// across the fleet rested on a version that does not exist.
				if isDistTag(ver) {
					ver = ""
				}
				if name == "" || !plainName(name) {
					continue
				}
				// The COMMAND is authoritative about the family; the base image
				// only refines which distribution inside it. If they disagree,
				// trust the command — you cannot run apt-get on Alpine.
				namespace, reason := "", ReasonInferredRun
				if ins.family != "" {
					if imgFamily == ins.family && imgDistro != "" {
						namespace = imgDistro
					} else {
						// Guessing ubuntu when it is debian yields the WRONG
						// advisories, which is worse than none, so the
						// assumption is recorded rather than hidden.
						namespace = distroDefaults[ins.family]
						reason = ReasonAssumedDistro
					}
				}
				id, err := osNodeID(ins.typ, namespace, name, ver)
				if err != nil {
					continue
				}
				// Completeness stays Inferred whether or not a version was
				// given: it records HOW we know the name — parsed out of a
				// shell line — and pinning is a separate axis carried by the
				// edge. A version-less node is a requirement the walker
				// resolves, which for a dist-tag is exactly right, since
				// `@latest` does mean "whatever is newest at build time".
				out = append(out, graph.Node{
					ID: id, Ecosystem: ins.typ, Name: name, Version: ver,
					Completeness: graph.Inferred, Reason: reason,
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
// isNPMScope matches @scope/name: a leading @ and exactly one slash.
func isNPMScope(tok string) bool {
	return strings.HasPrefix(tok, "@") && strings.Count(tok, "/") == 1
}

func plainName(s string) bool {
	if s == "" {
		return false
	}
	// A scoped npm name legitimately starts with @ and contains one slash.
	body := s
	if isNPMScope(s) {
		body = strings.ReplaceAll(strings.TrimPrefix(s, "@"), "/", "")
	}
	if body == "" || !isAlnum(rune(body[0])) {
		return false
	}
	for _, r := range body {
		switch {
		case isAlnum(r):
		case r == '-', r == '_', r == '.', r == '+':
		default:
			return false
		}
	}
	return true
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

// osNodeID mints an OS package id with its distribution namespace.
func osNodeID(typ, namespace, name, ver string) (graph.NodeID, error) {
	if namespace == "" {
		return graph.NodeIDFor(typ, name, ver)
	}
	return graph.NodeID(packageurl.NewPackageURL(typ, namespace, name, ver, nil, "").ToString()), nil
}

// Command deepdep computes the transitive closure of everything a repository
// pulls in — packages, container images, CI actions, toolchains — over both the
// resolution that installs today and the space of resolutions its version ranges
// permit.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/history"
	"github.com/jverhoeks/deepdep/internal/resolve"
	"github.com/jverhoeks/deepdep/internal/rollup"
	"github.com/jverhoeks/deepdep/internal/source"
	"github.com/jverhoeks/deepdep/internal/store"
	"github.com/jverhoeks/deepdep/internal/version"
	"github.com/jverhoeks/deepdep/internal/walk"
)

const toolVersion = "0.1.0"

func main() {
	out, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "deepdep:", err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}

const usage = `deepdep scan    [flags] <git-url|directory>
deepdep history [flags] <directory>   when each dependency changed, and to what
deepdep tools                         supply-chain surfaces this build recognises

  --mode will|can        will: what installs today (lockfile pins, else max-satisfying)
                         can:  every version the declared ranges permit
  --at REV               git tag, SHA or date; forces a full clone
  --as-of TIME           resolution time (RFC3339); errors if publish times are unavailable
  --known-at TIME        knowledge time; recorded now, consumed by advisory enrichment
  --format json|cyclonedx
  --max-depth N          closure depth bound (default 32)
  --max-versions N       per-range expansion bound in can mode (default 25)
  --concurrency N        registry fetch workers (default 16)
  --max-metadata-age D   re-fetch a packument observation older than this (default 24h)
  --cache-dir PATH       immutable blob store
  --db PATH              run store
  --no-db                do not persist this run
  --offline              extractors only; nothing is resolved
  --timeout D            give up expanding after this long; the partial closure
                         is still emitted, with the frontier marked bound:timeout
`

func run(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New(usage)
	}
	switch args[0] {
	case "scan":
		return scan(args[1:])
	case "history":
		return historyCmd(args[1:])
	case "tools":
		return toolsCmd()
	case "-h", "--help", "help":
		return []byte(usage), nil
	default:
		return nil, fmt.Errorf("unknown subcommand %q\n\n%s", args[0], usage)
	}
}

// historyCmd reports the repository time axis: when we changed what we depend
// on. It reads only commits that touched a manifest or lockfile, and reads them
// offline, so a whole history costs local git reads and nothing else.
func historyCmd(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	var (
		cacheDir = fs.String("cache-dir", defaultCacheDir(), "")
		name     = fs.String("package", "", "")
		format   = fs.String("format", "text", "")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 1 {
		return nil, errors.New(usage)
	}

	changes, err := history.Changes(context.Background(), fs.Arg(0), *cacheDir)
	if err != nil {
		return nil, err
	}
	if *name != "" {
		var keep []history.Change
		for _, c := range changes {
			if c.Name == *name {
				keep = append(keep, c)
			}
		}
		changes = keep
	}

	var buf bytes.Buffer
	if *format == "json" {
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", " ")
		// Encode BEFORE reading the buffer: Go evaluates return arguments left to
		// right, so returning buf.Bytes() alongside the Encode call would capture
		// the buffer while it was still empty.
		if err := enc.Encode(changes); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	for _, c := range changes {
		fmt.Fprintf(&buf, "%s  %s  %-14s %-16s %s\n",
			c.Commit[:8], c.When.Format("2006-01-02"), c.Kind, c.Name, movement(c))
	}
	return buf.Bytes(), nil
}

// movement renders both axes, because they move independently: a lockfile bump
// changes the installed version while the declared range stands still.
func movement(c history.Change) string {
	var parts []string
	if c.FromDeclared != c.ToDeclared {
		parts = append(parts, fmt.Sprintf("range %s -> %s", orDash(c.FromDeclared), orDash(c.ToDeclared)))
	}
	if c.FromInstalled != c.ToInstalled {
		parts = append(parts, fmt.Sprintf("installed %s -> %s", orDash(c.FromInstalled), orDash(c.ToInstalled)))
	}
	if len(parts) == 0 {
		return c.ToDeclared
	}
	return strings.Join(parts, ", ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// toolsCmd prints the recognition catalogue, grouped by what the surface DOES.
//
// The hook group is worth reading first: those files execute code on an ordinary
// commit or install, with your credentials, before anyone reviews anything.
func toolsCmd() ([]byte, error) {
	order := []extract.Category{
		extract.Hook, extract.Manifest, extract.Lockfile,
		extract.RegistryConfig, extract.Toolchain, extract.Orchestrator, extract.Bot,
	}
	byCat := map[extract.Category][]string{}
	seen := map[string]bool{}
	for _, t := range extract.Tools() {
		k := string(t.Category) + "\x00" + t.Name
		if seen[k] {
			continue
		}
		seen[k] = true
		byCat[t.Category] = append(byCat[t.Category], t.Name)
	}

	var buf bytes.Buffer
	total := 0
	for _, c := range order {
		names := byCat[c]
		total += len(names)
		fmt.Fprintf(&buf, "%-13s (%2d)  %s\n", c, len(names), strings.Join(names, ", "))
	}
	fmt.Fprintf(&buf, "\n%d tool/category pairs recognised.\n", total)
	fmt.Fprintf(&buf, "Files matching these appear as declared/no-extractor frontiers rather than being dropped.\n")
	return buf.Bytes(), nil
}

func scan(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer)) // errors are returned, not printed twice

	var (
		mode        = fs.String("mode", "will", "")
		at          = fs.String("at", "", "")
		asOfStr     = fs.String("as-of", "", "")
		knownAtStr  = fs.String("known-at", "", "")
		format      = fs.String("format", "json", "")
		maxDepth    = fs.Int("max-depth", 32, "")
		maxVersions = fs.Int("max-versions", 25, "")
		concurrency = fs.Int("concurrency", 16, "")
		metadataAge = fs.Duration("max-metadata-age", 24*time.Hour, "")
		cacheDir    = fs.String("cache-dir", defaultCacheDir(), "")
		dbPath      = fs.String("db", defaultDBPath(), "")
		noDB        = fs.Bool("no-db", false, "")
		offline     = fs.Bool("offline", false, "")
		timeout     = fs.Duration("timeout", 5*time.Minute, "")
		registry    = fs.String("registry", "https://registry.npmjs.org", "")
		pypiIndex   = fs.String("pypi-index", "https://pypi.org", "")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 1 {
		return nil, errors.New(usage)
	}
	target := fs.Arg(0)

	asOf, err := parseTime(*asOfStr)
	if err != nil {
		return nil, fmt.Errorf("--as-of: %w", err)
	}
	knownAt, err := parseTime(*knownAtStr)
	if err != nil {
		return nil, fmt.Errorf("--known-at: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	src, err := source.Open(ctx, target, *cacheDir, *at)
	if err != nil {
		return nil, err
	}

	// An explicitly-typed --as-of is a promise we must keep or refuse; one
	// derived from --at is a convenience we may decline.
	explicitAsOf := *asOfStr != ""

	// --at pins resolution time to the commit: resolving a 2023 source tree
	// against today's registry silently mixes two instants. Offline there is no
	// resolution to pin, so deriving a filter we cannot apply would be theatre.
	if *at != "" && asOf.IsZero() && !*offline {
		if t, ok := commitTime(src); ok {
			asOf = t
		}
	}

	reg := extract.NewRegistry()
	reg.Register(extract.NPMManifest{})
	reg.Register(extract.GHActions{})
	reg.Register(extract.GitLabCI{})
	reg.Register(extract.PyProject{})
	reg.Register(extract.Requirements{})
	// Reports supply-chain files we saw but cannot expand yet. Without this a
	// Dockerfile or ansible playbook is silently absent, which reads as "this
	// repo has none" — a wrong answer rather than a partial one.
	reg.Register(extract.Coverage{})

	// Open the store up front, not just at persist time: the resolver consults it
	// for prior observations, which is what makes a repeat scan incremental.
	var db *store.Store
	if !*noDB {
		if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
			return nil, err
		}
		if db, err = store.Open(*dbPath); err != nil {
			return nil, err
		}
		defer db.Close()
	}

	resolvers := map[string]resolve.Resolver{}
	if !*offline {
		blobs := cache.NewFS(*cacheDir)
		npm := resolve.NewNPMResolver(*registry, blobs, http.DefaultClient, *metadataAge, time.Now)
		pypi := resolve.NewPyPIResolver(*pypiIndex, blobs, http.DefaultClient, *metadataAge, time.Now)
		if db != nil {
			npm = npm.WithObservations(db)
			pypi = pypi.WithObservations(db)
		}
		resolvers["npm"] = npm
		resolvers["pypi"] = pypi
	}

	// Read the lockfiles first: in will-mode their pins decide what installs.
	// A repository can carry several ecosystems at once, so every effective
	// resolver runs and their instances are merged.
	var inst []effective.Instance
	for _, er := range []effective.EffectiveResolver{effective.NPMLock{}, effective.UVLock{}} {
		got, err := er.Resolve(ctx, src)
		if err != nil {
			return nil, err
		}
		inst = append(inst, got...)
	}

	bounds := walk.Bounds{
		MaxDepth: *maxDepth, MaxNodes: 50000, Concurrency: *concurrency,
		Version: version.BoundPolicy{Mode: modeOf(*mode), MaxVersionsPerRange: *maxVersions},
		AsOf:    asOf,
		Pins:    effective.Pins(inst),
	}

	// An audit flag the user typed must never be recorded and then ignored.
	if explicitAsOf && *offline {
		return nil, errors.New("--as-of requires registry access: publish times are unavailable offline")
	}

	rootID, err := graph.NewNodeID(fmt.Sprintf("pkg:generic/%s@%s", sanitise(src.Repo()), src.Ref()))
	if err != nil {
		return nil, err
	}

	schemes := map[string]version.VersionScheme{
		"npm":  version.NPM,
		"pypi": version.PEP440,
	}
	g, err := walk.New(bounds, resolvers, reg, schemes).Walk(ctx, src, rootID)
	if err != nil {
		return nil, err
	}

	// A lockfile is a decision npm already made, so its exact versions belong in
	// the graph even when the registry was never consulted.
	effective.Merge(g, inst, rootID)
	res := rollup.ComputeWith(g, inst, rootID, schemes)

	m := emit.Meta{
		AsOf: orNow(asOf), KnownAt: orNow(knownAt),
		Ref: src.Ref(), Repo: src.Repo(), Mode: modeName(*mode),
		ToolVersion: toolVersion, Bounds: bounds,
	}

	if db != nil {
		if _, err := db.WriteRun(ctx, m, g, inst, res); err != nil {
			return nil, err
		}
		// Mutable refs are the one observation that can never be recovered later.
		recordRefs(ctx, db, g)
	}

	var buf bytes.Buffer
	switch *format {
	case "cyclonedx":
		err = emit.CycloneDX(&buf, g, m)
	case "json":
		err = emit.JSON(&buf, g, m)
	default:
		return nil, fmt.Errorf("unknown --format %q", *format)
	}
	return buf.Bytes(), err
}

// recordRefs writes down what each mutable reference pointed at right now.
//
// No API reports what a git tag or container tag pointed at in the past, so a
// scan that does not record this loses that instant permanently. Failures here
// are not fatal to the scan itself.
func recordRefs(ctx context.Context, db *store.Store, g *graph.Graph) {
	now := time.Now().UTC()
	for _, n := range g.Nodes() {
		if n.ResolvedRef == "" {
			continue
		}
		_ = db.RecordRef(ctx, string(n.ID), n.ResolvedRef, now)
	}
}

func commitTime(s source.Source) (time.Time, bool) {
	type timed interface{ CommitTime() (time.Time, bool) }
	if t, ok := s.(timed); ok {
		return t.CommitTime()
	}
	return time.Time{}, false
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD, got %q", s)
	}
	return t, nil
}

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

func modeOf(m string) version.VersionMode {
	if m == "can" {
		return version.ModeAll
	}
	return version.ModeLatest
}

func modeName(m string) string {
	if m == "can" {
		return "can"
	}
	return "will"
}

// sanitise keeps a repo identifier usable as a PURL name.
func sanitise(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "repo"
	}
	return string(out)
}

func defaultCacheDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "deepdep")
	}
	return ".deepdep-cache"
}

func defaultDBPath() string {
	if d, err := os.UserHomeDir(); err == nil {
		return filepath.Join(d, ".local", "share", "deepdep", "deepdep.db")
	}
	return "deepdep.db"
}

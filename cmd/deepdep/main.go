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
	"sort"
	"strings"
	"time"

	"github.com/jverhoeks/deepdep/internal/advisory"
	"github.com/jverhoeks/deepdep/internal/cache"
	"github.com/jverhoeks/deepdep/internal/effective"
	"github.com/jverhoeks/deepdep/internal/emit"
	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/forge"
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
deepdep audit   [flags] [run-id]      check stored packages against OSV advisories
deepdep risk    [flags] [run-id]      supply-chain posture from deps.dev + OpenSSF Scorecard
deepdep report  [flags] [run-id]      malicious + advisories + posture, layered
deepdep org     [flags] <org|user>    scan every repository an org owns, and rank them
deepdep tools                         supply-chain surfaces this build recognises

  --mode will|can        will: what installs today (lockfile pins, else max-satisfying)
                         can:  every version the declared ranges permit
  --at REV               git branch, tag, SHA or date. A branch or tag name
                         clones shallowly; a SHA or date needs full history
  --as-of TIME           resolution time (RFC3339); errors if publish times are unavailable
  --known-at TIME        knowledge time; recorded now, consumed by advisory enrichment
  --format text|json|cyclonedx     scan
  --format text|json|mermaid       report; mermaid draws the surfaces
                         and where risk enters, bounded to stay readable
  --max-depth N          closure depth bound (default 32)
  --max-versions N       per-range expansion bound in can mode (default 25)
  --concurrency N        registry fetch workers (default 32)
  --max-metadata-age D   re-fetch a packument observation older than this (default 24h)
  --cache-dir PATH       immutable blob store
  --db PATH              run store
  --no-db                do not persist this run
  --author NAME          SBOM author (NTIA field 6); defaults to the tool
  --formulation          include the MBOM view in CycloneDX: pipelines, base
                         images, build steps (default true)
  --sbom-dir DIR         with --format cyclonedx: one document per application
                         and per Dockerfile, plus a _repo document for the
                         pipeline, ready for cyclonedx merge --hierarchical
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
	case "audit":
		return auditCmd(args[1:])
	case "risk":
		return riskCmd(args[1:])
	case "report":
		return reportCmd(args[1:])
	case "org":
		return orgCmd(args[1:])
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
// auditCmd checks what a stored run actually installs against OSV.
//
// It audits the INSTALLED set by default — what is really there — rather than
// the can-closure, because those are different questions and mixing them
// equates a hypothetical exposure with a real one.
func auditCmd(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	var (
		dbPath     = fs.String("db", defaultDBPath(), "")
		knownAtStr = fs.String("known-at", "", "")
		state      = fs.String("state", "installed", "installed|possible|unknown|all")
		format     = fs.String("format", "text", "")
		osvBase    = fs.String("osv", "https://api.osv.dev", "")
		timeout    = fs.Duration("timeout", 10*time.Minute, "")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	knownAt, err := parseTime(*knownAtStr)
	if err != nil {
		return nil, fmt.Errorf("--known-at: %w", err)
	}
	if knownAt.IsZero() {
		knownAt = time.Now().UTC()
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	db, err := store.Open(*dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	runID := ""
	if fs.NArg() == 1 {
		runID = fs.Arg(0)
	}
	// "all" is an empty filter. Without it a Dockerfile-only repo is
	// unauditable: with no lockfile there is no effective resolution, so every
	// package lands in `unknown` and neither `installed` nor `possible` sees it.
	want := rollup.State(*state)
	if *state == "all" {
		want = ""
	}
	targets, meta, err := db.AuditTargets(ctx, runID, want)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("run %s resolved no package versions in state %q.\n"+
			"With no lockfile an offline scan resolves nothing; re-scan online, or\n"+
			"use `deepdep report` which describes the coverage gap instead of failing",
			meta.RunID, *state)
	}

	findings, err := advisory.New(*osvBase, nil).Check(ctx, targets, knownAt)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if *format == "json" {
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", " ")
		if err := enc.Encode(map[string]any{
			"run_id": meta.RunID, "ref": meta.Ref, "mode": meta.Mode,
			"as_of": meta.AsOf, "known_at": knownAt,
			"state": *state, "checked": len(targets), "findings": findings,
		}); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	fmt.Fprintf(&buf, "run %s  ref %s  mode %s\n", meta.RunID, short(meta.Ref), meta.Mode)
	fmt.Fprintf(&buf, "as-of %s   known-at %s\n",
		meta.AsOf.Format("2006-01-02"), knownAt.Format("2006-01-02"))
	fmt.Fprintf(&buf, "checked %d %s package versions against OSV\n\n", len(targets), *state)

	if len(findings) == 0 {
		fmt.Fprintf(&buf, "no known advisories\n")
		return buf.Bytes(), nil
	}

	// Worst first: a report read top-down should start with what matters.
	sort.Slice(findings, func(i, j int) bool {
		if severityRank(findings[i].Advisory.SeverityLabel()) != severityRank(findings[j].Advisory.SeverityLabel()) {
			return severityRank(findings[i].Advisory.SeverityLabel()) > severityRank(findings[j].Advisory.SeverityLabel())
		}
		return findings[i].NodeID < findings[j].NodeID
	})
	bySev := map[string]int{}
	affected := map[graph.NodeID]bool{}
	for _, f := range findings {
		bySev[f.Advisory.SeverityLabel()]++
		affected[f.NodeID] = true
	}
	fmt.Fprintf(&buf, "%d advisories across %d package versions\n", len(findings), len(affected))
	for _, s := range []string{"MALICIOUS", "CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"} {
		if bySev[s] > 0 {
			fmt.Fprintf(&buf, "  %-9s %d\n", s, bySev[s])
		}
	}
	fmt.Fprintln(&buf)
	for _, f := range findings {
		cve := f.Advisory.CVE()
		if cve == "" {
			cve = "-"
		}
		fmt.Fprintf(&buf, "%-9s %-16s %-18s %-42s %s\n",
			f.Advisory.SeverityLabel(), f.Advisory.ID, cve,
			label(f.NodeID), // percent-encoded scopes are correct identity, unreadable in a report
			truncate(f.Advisory.Summary, 60))
	}
	return buf.Bytes(), nil
}

func severityRank(s string) int {
	switch {
	// Above CRITICAL on purpose. A malicious package is not a severe flaw, it is
	// hostile code that already ran with your credentials; ranking it by CVSS
	// puts the Shai-Hulud worm below a ReDoS.
	case s == "MALICIOUS":
		return 5
	case strings.HasPrefix(s, "CRITICAL"):
		return 4
	case strings.HasPrefix(s, "HIGH"):
		return 3
	case strings.HasPrefix(s, "MODERATE"):
		return 2
	case strings.HasPrefix(s, "LOW"):
		return 1
	}
	return 0
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n-1] + "\u2026"
	}
	return s
}

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
		concurrency = fs.Int("concurrency", 32, "")
		metadataAge = fs.Duration("max-metadata-age", 24*time.Hour, "")
		cacheDir    = fs.String("cache-dir", defaultCacheDir(), "")
		dbPath      = fs.String("db", defaultDBPath(), "")
		noDB        = fs.Bool("no-db", false, "")
		author      = fs.String("author", "", "SBOM author (NTIA field 6); defaults to the tool")
		formulation = fs.Bool("formulation", true, "include the CycloneDX MBOM view: pipelines, base images, build steps")
		sbomDir     = fs.String("sbom-dir", "", "write one CycloneDX document per application/image into this directory")
		offline     = fs.Bool("offline", false, "")
		timeout     = fs.Duration("timeout", 5*time.Minute, "")
		registry    = fs.String("registry", "https://registry.npmjs.org", "")
		pypiIndex   = fs.String("pypi-index", "https://pypi.org", "")
		goProxy     = fs.String("goproxy", "https://proxy.golang.org", "")
		cratesIndex = fs.String("crates-index", "https://crates.io", "")
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

	// --timeout bounds EXPANSION. The usage text promises that when it fires the
	// partial closure is still emitted with its frontier marked bound:timeout,
	// and a single context spanning the whole run broke that promise in the
	// worst possible place: the walker correctly stopped and marked its
	// frontier, then WriteRun inherited the expired deadline and threw the
	// entire result away. freeCodeCamp, angular and deno reported as total
	// failures while holding a perfectly good partial answer.
	//
	// Each phase therefore gets its own budget. Acquiring the source is not
	// expanding — cloning a large monorepo can legitimately take longer than the
	// expansion budget — and persisting a result that already exists must not be
	// bounded by a clock that has already run out.
	cloneCtx, cancelClone := context.WithTimeout(context.Background(), *timeout)
	defer cancelClone()
	// The same credential that lists an organisation's private repositories is
	// what clones them; without it `org` fails every private repo at clone time.
	src, err := source.Open(cloneCtx, target, *cacheDir, *at, source.Token(forge.Token()))
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// An explicitly-typed --as-of is a promise we must keep or refuse; one
	// derived from --at is a convenience we may decline.
	explicitAsOf := *asOfStr != ""

	// --at pins resolution time to the commit: resolving a 2023 source tree
	// against today's registry silently mixes two instants.
	//
	// This applies offline too. An earlier version skipped it there, reasoning
	// that a filter we cannot apply is theatre — true of the FILTER, false of
	// the DOCUMENT. AsOf is now metadata.timestamp in every CycloneDX we emit,
	// so an offline scan of a year-old tag shipped an SBOM stamped today: the
	// same two-instants confusion the flag exists to prevent, inverted.
	if *at != "" && asOf.IsZero() {
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
	reg.Register(extract.Dockerfile{})
	reg.Register(extract.GoMod{})
	reg.Register(extract.Cargo{})
	reg.Register(extract.Poetry{})
	// Reports supply-chain files we saw but cannot expand yet. Without this a
	// Dockerfile or ansible playbook is silently absent, which reads as "this
	// repo has none" — a wrong answer rather than a partial one.
	reg.Register(extract.Coverage{})

	// Open the store up front, not just at persist time: the resolver consults it
	// for prior observations, which is what makes a repeat scan incremental.
	var db *store.Store
	if !*noDB {
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
		goprox := resolve.NewGoProxyResolver(*goProxy, blobs, http.DefaultClient, *metadataAge, time.Now)
		crates := resolve.NewCratesResolver(*cratesIndex, blobs, http.DefaultClient, *metadataAge, time.Now)
		if db != nil {
			npm = npm.WithObservations(db)
			pypi = pypi.WithObservations(db)
			goprox = goprox.WithObservations(db)
			crates = crates.WithObservations(db)
		}
		resolvers["npm"] = npm
		resolvers["pypi"] = pypi
		resolvers["golang"] = goprox
		resolvers["cargo"] = crates
	}

	// Read the lockfiles first: in will-mode their pins decide what installs.
	// A repository can carry several ecosystems at once, so every effective
	// resolver runs and their instances are merged.
	var inst []effective.Instance
	for _, er := range []effective.EffectiveResolver{effective.NPMLock{}, effective.UVLock{}, effective.PnpmLock{}, effective.GoMod{}, effective.CargoLock{}, effective.PoetryLock{}, effective.YarnLock{}, effective.BunLock{}} {
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
		"npm":    version.NPM,
		"pypi":   version.PEP440,
		"golang": version.Go,
		"cargo":  version.Cargo,
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
		// Deliberately not ctx: see the note on the phase budgets above. A
		// timed-out expansion still produced a graph, and the whole point of
		// naming a bound instead of failing is that the partial answer survives
		// to be written down.
		persistCtx, cancelPersist := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancelPersist()
		if _, err := db.WriteRun(persistCtx, m, g, inst, res); err != nil {
			return nil, err
		}
		// Mutable refs are the one observation that can never be recovered later.
		recordRefs(ctx, db, g)
	}

	var buf bytes.Buffer
	switch *format {
	case "cyclonedx":
		// Licences and suppliers come from deps.dev observations, which exist
		// only if `deepdep risk` has run. Absent is a NAMED gap in the document,
		// never silently licence-free components.
		var facts map[graph.NodeID]emit.Facts
		if db != nil {
			facts, err = db.SupplyFacts(ctx, g.Nodes())
			if err != nil {
				return nil, err
			}
		}
		opts := emit.CycloneDXOptions{Author: *author, Enrichment: facts, Formulation: *formulation}
		if *sbomDir != "" {
			// One document per deliverable. A monorepo's single 1384-component
			// BOM answers nobody's question; "what does the backend ship?" and
			// "what goes into cli/Dockerfile?" are different documents, and a
			// hierarchical merge needs them to exist separately first.
			return writeSplitSBOMs(*sbomDir, g, inst, rootID, m, opts)
		}
		err = emit.CycloneDX(&buf, g, m, opts)
	case "text":
		// A SUMMARY, deliberately not a second report. scan has no OSV or
		// deps.dev data, so it can only describe what it found on disk; two
		// commands each printing a partly-overlapping "report" is worse than
		// one that hands off.
		buf.Write(scanSummary(g, res, inst, m, *dbPath, *noDB))
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

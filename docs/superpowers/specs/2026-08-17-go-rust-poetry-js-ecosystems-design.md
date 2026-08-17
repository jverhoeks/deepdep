# Four more ecosystems: Go, Rust, Poetry, and the rest of the JS family

Status: approved 2026-08-17. Implement in the order given.

## Why

A scan of the 186 repositories `schubergphilis` owns graded 76 and left 108
UNASSESSED — not clean, unassessed. A repository is graded only when at least
half of its packages are auditable (`score.go:37`, `MinCoverage = 0.5`), and a
Go or Poetry repository currently has no auditable packages at all.

The `Coverage` extractor exists to turn "which ecosystem next?" into an
evidence-backed question rather than a guess. Its answer, counted across that
fleet by number of repositories affected:

    go 15    poetry 10    pnpm 4*    cargo 3    bun 2    yarn 0

\* `pnpm` is miscounted; see "Defect found while scoping".

For calibration, the largest gaps NOT in scope here are `pipenv` (27),
`setuptools` (26) and `tox` (20) — all Python packaging. They are the biggest
remaining lever on the ungraded count and are deliberately left for later.

## What is already built

Four ecosystems are asked for that are wholly or partly present. Knowing which
is which is most of the work of scoping this.

| Ecosystem | Version scheme | Registry resolver | Lockfile → exact |
|---|---|---|---|
| npm    | `version/npm.go`    | `resolve/npmregistry.go` | `effective.NPMLock`  |
| pnpm   | npm's               | npm's                    | `effective.PnpmLock` |
| uv     | `version/pep440.go` | `resolve/pypi.go`        | `effective.UVLock`   |
| yarn   | npm's               | npm's                    | MISSING              |
| bun    | npm's               | npm's                    | MISSING              |
| poetry | versions yes, constraint dialect no | `resolve/pypi.go` | MISSING |
| go     | MISSING             | MISSING                  | MISSING              |
| rust   | MISSING             | MISSING                  | MISSING              |

Two seams are already prepared for this work and need no change:

- `graph.packageTypes` (`identity.go:84`) already admits `golang` and `cargo`.
- OSV is queried **by PURL** for every registry ecosystem (`osv.go:274`), so
  advisories for `pkg:golang/...` and `pkg:cargo/...` work the moment such nodes
  exist. No advisory-layer change at all.

Posture (deps.dev/Scorecard) covers Go, Cargo, npm and PyPI, so it is wired the
same way as the existing ecosystems rather than specially.

## Decisions taken

**Depth: full parity.** Each ecosystem gets manifest constraints, registry
resolution and lockfile-derived exact versions — not a lockfile-only shortcut.
This is what makes `can` mode meaningful for them.

**Go models Minimal Version Selection as its own scheme.** `require x v1.2.3`
is a LOWER BOUND, not a range: the build gets the maximum requirement across the
module graph. So `will` is the MVS-selected version and `can` is any published
version at or above the bound, because another module raising its requirement is
precisely what moves you. Reusing npm's range model here would produce
confidently wrong answers, which is the failure this codebase most cares about
(see the reasoning already recorded at `python.go:96-99`).

**Everything reachable counts.** All Cargo features including optional
dependencies behind them, all Python extras and dependency-groups, npm `dev`,
`peer` and `optional` dependencies, and Go's test-only requirements are part of
the closure. This is the widest reading and it inflates package counts relative
to what a default install produces; that is the intended trade, and edge kinds
must record which category each dependency came from so a reader can tell.

**Advisories via the existing OSV client. Posture via the existing deps.dev
path.** Go's own `vuln.go.dev` is more precise but is a second advisory source
to maintain; OSV carries the `Go` and `crates.io` ecosystems already.

## Defect found while scoping

`main.go:492` registers `effective.PnpmLock`, so `pnpm-lock.yaml` IS read — but
`catalogue.go:69` still lists it, so `Coverage` ALSO reports it as
`no-extractor`. `uv.lock` was excluded from the catalogue when its reader landed
(`catalogue.go:89` says so) and pnpm was not.

The document therefore contradicts itself for pnpm: the same file is both
expanded and reported as unexpanded. This is exactly the condition the `Fallback`
interface exists to prevent, and it inflates the measured gap. Fixed as part of
sub-project 4.

## The shared spine

Adding an ecosystem touches five places. Naming them once keeps the four
sub-projects from each inventing their own shape.

1. **Identity** — `graph.NodeIDFor` mints the PURL, and its default branch is
   already correct for both new ecosystems. Verified against the real function:
   `golang`+`github.com/gorilla/mux` yields `pkg:golang/github.com/gorilla/mux@v1.8.0`
   with the slashes preserved as the PURL spec requires, and `cargo`+`serde`
   yields `pkg:cargo/serde@1.0.0`. No `GoNodeID` or `CargoNodeID` is needed.
2. **Version semantics** — a `version.VersionScheme` implementation. This is
   where the ecosystem's real semantics live and where nothing may be
   approximated.
3. **Extraction** — an `extract.Extractor` reading the manifest into Declared
   nodes plus edges, with the dependency kind recorded on the edge.
4. **Effective resolution** — an `effective.EffectiveResolver` reading the
   lockfile into exact `Instance`s with `DerivedFrom: "lockfile"`.
5. **Registry resolution** — a `resolve.Resolver` for `Versions` and
   `Requirements`, using `cache.Cache` for immutable bodies and `Observations`
   for mutable documents.

Registration is in `main.go`: `reg.Register` for extractors, the
`[]effective.EffectiveResolver` slice at `main.go:492`, and the `schemes` map at
`main.go:517`. Every new ecosystem also REMOVES its entries from
`extract/catalogue.go`, or `Coverage` will contradict the new extractor exactly
as it does for pnpm today.

### The one structural change

`schemes` is `map[string]VersionScheme` keyed by ecosystem (`walker.go:31`,
consumed at `walker.go:194`). Poetry breaks that assumption: `^2.32.3` in
`pyproject.toml` and `>=2.0,<3` in the same package's PyPI metadata are
different constraint dialects for the SAME `pkg:pypi` ecosystem.

So the constraint dialect must travel with the requirement that declared it, not
with the package it points at. The requirement carries a dialect tag; the walker
selects the scheme by that tag, falling back to the ecosystem's default when it
is empty. Versions and their ordering stay per-ecosystem — only constraint
PARSING varies. `walker.go:199` already handles a missing scheme by marking the
node Declared with reason `no-scheme`, so an unknown dialect degrades safely
instead of guessing.

This lands in sub-project 3 and affects nothing in 1, 2 or 4.

## Sub-projects, in build order

### 1. Go

- `version/gomod.go`: `GoScheme`. Canonical semver with the `v` prefix,
  pseudo-versions (`v0.0.0-20191109021931-daa7c04131f5`), `+incompatible`, and
  `IsExact` true for a bare version because a `require` is a point, not a range.
  `Satisfies` is `>=` against the bound. `Enumerate` returns versions at or above
  the bound, newest first, bounded by `MaxVersionsPerRange`.
- `extract/gomod.go`: `go.mod` — `require` (both block and single-line), and
  `replace`, `exclude` and `toolchain`. A `replace` to a LOCAL path is not a
  registry package: it becomes a frontier node marked as locally replaced rather
  than being resolved or silently dropped.
- `effective/gosum.go`: the build list. A Go 1.17+ `go.mod` carries the full
  selected list including indirect requirements, which IS the effective answer;
  `go.sum` is a superset of everything ever considered and must NOT be read as
  the install set.
- `resolve/goproxy.go`: `proxy.golang.org` — `@v/list` for versions, `@v/<v>.mod`
  for requirements, `@v/<v>.info` for publish timestamps. Module paths are
  case-encoded (`!e!x!a!m!p!l!e`); get this wrong and every capitalised module
  404s.
- OSV and posture: no change.

### 2. Rust

Follows the spine Go establishes.

- `version/cargo.go`: `CargoScheme`. Semver where a bare `1.2.3` means caret —
  `>=1.2.3, <2.0.0` — and where pre-1.0 caret is narrower (`^0.2.3` allows
  `<0.3.0`). Getting the pre-1.0 rule wrong silently widens half of crates.io.
- `extract/cargo.go`: `Cargo.toml` — `[dependencies]`, `[dev-dependencies]`,
  `[build-dependencies]`, `[target.*.dependencies]` and `[features]`. Per the
  widest reading, optional dependencies behind features are included, tagged
  with the feature that gates them.
- `effective/cargolock.go`: `Cargo.lock`, which is exact and flat.
- `resolve/cratesio.go`: `crates.io` — `/api/v1/crates/<name>` lists versions
  with `created_at`; dependencies come from `/dependencies` per version.
- Workspaces: a virtual manifest has no `[package]` and must not become a node.

### 3. Poetry

- The scheme-dispatch change described above.
- `version/poetry.go`: `PoetryScheme`. PEP 440 VERSIONS (reuse `pep440.go`
  wholesale) under Poetry's CONSTRAINT dialect: `^`, `~`, `*`, comma-separated
  conjunctions, `||` alternatives, and the table form
  `{version = "^1.0", optional = true}`.
- `extract/poetry.go`: `[tool.poetry.dependencies]`,
  `[tool.poetry.dev-dependencies]` (legacy) and `[tool.poetry.group.*.dependencies]`
  (current). The `python` constraint is an interpreter requirement, not a
  package, and must not become a node. Extras and optional dependencies are
  included per the widest reading.
- `effective/poetrylock.go`: `poetry.lock`, exact and flat, same shape as
  `UVLock`.
- `PyProject.Match` must yield the Poetry tables to the new extractor without
  either of them claiming the whole file exclusively — both read
  `pyproject.toml`, and `Registry.For` already runs every extractor that claims a
  path, so this works provided neither errors on the other's tables.

### 4. JS family completion

- `effective/yarnlock.go`: both Yarn v1 (custom format) and Berry v2+ (YAML).
  The two are different parsers, not one with a flag.
- `effective/bunlock.go`: `bun.lock` (JSONC, text). `bun.lockb` is a BINARY
  format — do not guess at it; if it cannot be read faithfully, leave it in the
  catalogue as an honest `no-extractor` frontier and say so.
- Remove `pnpm-lock.yaml` from `catalogue.go` (the defect above), and `yarn.lock`
  and `bun.lock` as their readers land.
- npm needs no work; it is listed here only because it was asked about.

## Testing

Every sub-project follows the existing pattern: table tests per parser against
real fixture files, and an oracle test for each new version scheme in the style
of `version/pep440_oracle_test.go`, which is what keeps a scheme honest about the
ecosystem's real semantics rather than a plausible reading of them.

Each scheme test must include the cases that are easy to get wrong and silent
when wrong: Go pseudo-versions and `+incompatible`; Cargo's pre-1.0 caret;
Poetry's `~` against PEP 440's `~=`, which are NOT the same operator.

Verification for each sub-project is a real scan of a repository from the fleet
that currently reports `not graded`, showing packages resolved and a grade
issued — not only a green unit suite.

## Deviations found during implementation

Two, both recorded rather than taken silently.

### Poetry constraints are TRANSLATED, not given their own dialect

The "one structural change" above — a dialect tag travelling with each
requirement through `graph.Edge`, the walker, the store and the rollup — was not
built. Reading the code, translating Poetry's constraints into PEP 440 RANGE
syntax at extraction time is exactly as correct, keeps the rollup's pinning
analysis working unchanged, and touches four files instead of a dozen.

The objection recorded at `python.go:96` was against MISPARSING `^1.2.3` with
PEP 440 semantics. Translating is a different operation: every Poetry form has an
exact PEP 440 equivalent, so the result means what the author wrote.

Except alternation. `^1.0 || ^2.0` has no PEP 440 equivalent at any level, so it
is refused and recorded as a frontier carrying the original text. The cost of the
approach is display fidelity — a report shows `>=1.2.3,<2.0.0` where the author
wrote `^1.2.3`.

### "Everything reachable" does not yet hold for TRANSITIVE PyPI extras

The decision above was to count everything reachable. It holds for every
dependency a scanned repository DECLARES: `skipScope` is called from exactly one
place (`walker.go:306`), the transitive expansion, so seed edges at depth 1 are
never filtered and a repository's own optional dependencies are walked.

It does NOT hold one level down. `walker.go:352` skips `graph.Optional` for
`pypi`, so a dependency's own extras are not expanded. On `grawsp` that is 125
nodes marked `extra-not-requested` against 55 resolved package versions.

This is a PRE-EXISTING global rule with a stated rationale — pyobjc alone
declares 300+ framework subpackages and fsspec 50 cloud backends — and it governs
npm and PyPI generally, not just the ecosystems added here. Cargo optionals are
NOT affected: `cargo` falls past that branch and is walked.

Honouring the decision fully is a one-line change to `skipScope`, but it widens
every existing PyPI closure in the tool, not only the new ones. That is a
different blast radius from this spec's, so it is surfaced for a decision rather
than folded in.

## Out of scope

`pipenv`, `setuptools`, `tox`, `terraform`, `bundler`, `maven`, `nuget` and the
rest of the catalogue. Recorded here because the fleet data ranks several of them
ABOVE the ecosystems in this spec, and that should be a deliberate choice later
rather than an oversight.

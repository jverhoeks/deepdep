# deepdep

Compute the transitive closure of everything a repository pulls in — packages,
container images, CI actions, toolchains — over both the resolution that
installs today and the space of resolutions its version ranges permit.

```
deepdep scan --mode will .    # what installs today
deepdep scan --mode can  .    # what a future install could pull
```

On a manifest declaring one dependency (`is-string: ^1.0.0`), against the live
npm registry:

| mode | nodes | edges |
|---|---|---|
| `will` | 19 | 28 |
| `can` | **66** | **280** |

## Why

Existing tools (syft, trivy, osv-scanner, cyclonedx-gomod) answer one question:
*what is installed right now, given the lockfiles present.* They stop in three
places that matter.

**They stop at package managers.** A `.pre-commit-config.yaml` pins git repos
that execute on every commit. A `Dockerfile` pulls a base image *and* runs
`apt-get install` / `curl | sh`. A CI workflow pulls third-party actions,
container images, and reusable workflows that call further workflows. None of it
appears in an SBOM.

**They stop at the resolved graph.** Manifests declare *ranges*. Every version
satisfying a range has its own dependency set, so what a future install **can**
pull is strictly larger than what it **will** pull today.

**They silently omit what they cannot see.** `RUN make install` is statically
undecidable. Reporting a clean SBOM that quietly dropped it is a wrong answer,
not a partial one.

## Three orthogonal axes

Conflating any two of these produces confident nonsense, so they are separate
fields on every node.

**Completeness** — how well do we know this?
`resolved` · `declared` · `inferred` · `opaque`

**State** — will it land on disk?
`installed` · `possible` · `unknown`

**Pinning** — what is holding it there?
`pinned` · `locked` · `floating`

The third is the one people miss. These two packages install the same version
and carry completely different exposure:

```
pyproject: ">4.5.0"  + lock 4.6.1   ->  locked   regenerate the lock and it moves
pyproject: "==4.6.1"                ->  pinned   regenerating changes nothing
```

## Time travel

Supply-chain questions have two independent time axes, because a CVE published
today applies to a version published years ago.

| `--as-of` | `--known-at` | question |
|---|---|---|
| now | now | what are we exposed to today? |
| release T | T | was this a known problem when we shipped? |
| release T | now | what do we now know was wrong with what we shipped? |

Rows 2 and 3 together separate negligence from bad luck. A third axis, `--at`,
recomputes the closure at any point in the repository's own history:

```
deepdep scan --at v1.2.0 .     # the closure as it stood at that tag
deepdep history .              # when each dependency changed, and to what
```

`history` distinguishes a range change from a lockfile-only bump — the latter
moves what installs while the manifest stands still, and a range diff misses it
entirely.

### What cannot be reconstructed later

| axis | retroactive? | why |
|---|---|---|
| repo state at T | yes | git history |
| version existence at T | yes | registry publish times |
| advisory existence at T | yes | OSV `published` / `withdrawn` |
| advisory *content* at T | **no** | `modified` is destructive |
| **tag → SHA at T** | **no** | no API exposes it; record it or lose it |
| **OpenSSF Scorecard at T** | **no** | deps.dev serves only the newest; no history endpoint |

The last two rows are why every scan writes observed SHAs and digests to
`ref_obs`, and every `risk` run appends to `depsdev_obs` / `scorecard_obs`, from
the first run. `deepdep risk --known-at` therefore **errors** rather than
returning today's posture under a historical flag.

## Coverage, not silence

`deepdep` reports supply-chain files it saw and could **not** expand, as
`declared` / `no-extractor` frontiers. A scanner that silently omits a Dockerfile
reads as "this repo has none".

```
deepdep tools     # 95 tool/category pairs recognised
```

Categories are ordered by leverage: `hook` first, because those execute on an
ordinary commit or install, with your credentials, before any review.

## Supported today

| | extract | resolve | effective |
|---|---|---|---|
| npm | `package.json` | registry | `package-lock.json` |
| PyPI | `pyproject.toml`, `requirements*.txt` | PyPI JSON | `uv.lock` |
| GitHub Actions | workflows | — | — |
| GitLab CI | `.gitlab-ci.yml`, includes, components | — | — |
| pnpm | — | — | `pnpm-lock.yaml` |
| Dockerfile | `FROM`, `RUN` | — | — |

Enrichment: OSV (advisories, bitemporal) and deps.dev + OpenSSF Scorecard
(posture, current-records only).

Everything else in the catalogue — pre-commit, mise, ansible, Cargo, Maven,
Helm, Terraform — is detected and reported as a frontier.

## CVE checking

```
deepdep scan  --mode will --offline .   # index what is installed
deepdep audit                           # check it against OSV
```

`audit` checks the **installed** set by default — what is really there — not the
can-closure, because equating a hypothetical exposure with a real one is the
mistake this tool exists to avoid. It is bitemporal: `--known-at` replays the
advisories that existed at an instant, so a stored run can be re-audited against
any point in time without rescanning.

Two-stage against OSV, which is what the API offers: `querybatch` returns ids
1000 at a time, then each distinct advisory is fetched once. Packages share
advisories, so the second stage is far smaller than the first.

## Supply-chain posture

```
deepdep risk                            # deps.dev + OpenSSF Scorecard
deepdep risk --signal deprecated --limit 0
```

A different question from `audit`. An advisory says *this version has a known
flaw*. A posture signal says *this is how the code got here, and what a future
compromise would cost*: the package is deprecated and nobody will patch it, its
releases carry no provenance, its repo merges without review, its CI hands out
write-all tokens.

Reported as **named signals with counts, never a 0-100 score** — averaging a
deprecated package against a missing fuzzing harness destroys the only
distinction that makes the output actionable.

Counts are given as **versions / distinct source projects**, both. A Scorecard
finding is a property of a *project*: rollup ships 25 per-platform binary
packages from one repo, so a version-only count turns three upstream problems
into twenty-eight.

Three things about the deps.dev API that silently corrupt a naive client, all
verified and all pinned by tests:

| behaviour | consequence |
|---|---|
| `purlbatch` echoes a **normalised** purl (`annotated_types` → `annotated-types`, `5.0` → `5.0.0`) | correlate by **index**, never by the echo, or facts cross between packages |
| `purlbatch` caps at 100 and returns a `nextPageToken` instead of an error | chunk at 100; a short response is treated as a hard error |
| Scorecard `score: -1` means **the check did not run** ("no releases found") | never a finding; only `>= 0` scores are evaluated |

A package deps.dev has never seen is `unlisted` — **unexamined, not clean**.
Internal packages, private-index packages and typo'd names all land there.

`risk` also cross-checks its own advisory ids against `audit`'s OSV results over
identical inputs. A delta is a lead, not a verdict — the common benign case is an
OSS-Fuzz record attached to an upstream project by a GIT commit range, which says
nothing about which published artifact shipped it.

## SBOM output

```
deepdep scan --format cyclonedx .                      # one document
deepdep scan --format cyclonedx --sbom-dir out/ .      # one per deliverable
```

CycloneDX 1.6, validated against the official JSON schema. **NTIA minimum
elements: 6 of 7** — supplier, name, version, unique identifier, dependency
relationships, author, timestamp. The seventh, component hash, needs registry
digests and is not implemented; the document says so rather than omitting it
quietly.

Three things distinguish it from a `syft` BOM:

**Frontiers are components.** A `Dockerfile` we could not expand, a bound that
fired, a shell step we could not analyse — each is emitted with
`deepdep:completeness` and `deepdep:reason` properties. That is NTIA practice #3,
"known unknowns". A BOM that silently omits them reads as "this repo has none".

**`dependencies[]` presence carries meaning.** CycloneDX distinguishes *known to
have no dependencies* (present, empty `dependsOn`) from *dependencies unknown*
(absent). That maps exactly onto completeness, so a frontier is never claimed
to be a leaf.

**`formulation` carries the build.** Pipelines, base images and shell steps —
the MBOM view. A base image and a third-party CI action execute with the
build's credentials and appear in no `components[]` list anywhere else.

### Per-deliverable documents

`--sbom-dir` writes one document per application (from lockfile locators), one
per Dockerfile, and one `_repo` for the pipeline, then prints the
`cyclonedx merge --hierarchical` line that assembles them. A monorepo's single
1384-component BOM answers nobody's question; "what does the backend ship?" and
"what goes into `cli/Dockerfile`?" are different documents.

Repo-level artifacts — the pipeline, its base images, the coverage frontiers —
go in `_repo` rather than being copied into every application. Duplicating them
would inflate each document and double-count the union; dropping them would make
every document look cleaner than the repository is.

### Known limitations

The GitHub Actions and GitLab CI extractors do not yet emit file nodes, so a
repo with several `.github/workflows/*.yml` attributes a shared action or base
image to whichever workflow reached it first — the bug the Dockerfile extractor
fixes by hanging its findings off a file node. One `.gitlab-ci.yml` is
unambiguous; several workflows are not.

The build layer lands as `possible`, not `installed`: `deepdep audit` checks
lockfile-backed packages by default, so base images and packages parsed out of
`RUN` lines need `--state possible`.

### What this is not

A **Source** SBOM, in CISA's taxonomy — recorded in the document as
`deepdep:cisa-sbom-type`. deepdep reads manifests, lockfiles, pipelines and
Dockerfiles; it never observes a build, so it cannot know which transitive OS
packages `apt` actually pulled into an image. That is a **Build** SBOM, and
`syft <image>` is the tool for it. The two merge.

## Design notes

- **Never executes analysed code.** No `npm install`, no `pip install`, no
  `docker build`. Resolution is registry-API-only. An analyser that runs
  untrusted postinstall scripts to learn a dependency graph is a liability.
- **Version semantics are per-ecosystem.** npm ranges and PEP 440 specifiers
  disagree about ordering, about `~`, and about pre-releases. The npm scheme is
  validated against node-semver's own fixture corpus; PEP 440 is validated
  differentially against Python's `packaging` library (644 cases).
- **Identity is deduplicated, provenance is not.** One node per package version;
  every edge kept. `PathsTo` answers "why is this here?" with every chain.
- **Advisory counts are never materialised.** They are a function of
  `known_at`, a query parameter. Storing them would un-bitemporalise the design
  at the last step.
- **Bounds are named, never silent.** Depth, node count and timeout all mark
  their frontier with a machine-readable reason.

## Storage

Runs persist to SQLite (`modernc.org/sqlite`, pure Go, no cgo). Indexed adjacency
answers "why is this here?" in milliseconds; the flat package list sorts and
paginates. Packument observations make a re-scan incremental — 2.78s to 0.12s on
a repeat run.

```sql
SELECT name, versions_installed, path_count, worst_completeness
  FROM package_rollup ORDER BY path_count DESC LIMIT 10;
```

## Status

Working, tested, and honest about its limits. Not yet built: a graph UI,
`deepdep diff`, hoisting simulation for lockfile-less repos, and the remaining
ecosystem extractors. The schema for the UI is already in place, because
knowledge-time, tag→SHA and scorecard history cannot be reconstructed after the
fact.

Known limitation: `can` mode expands each declared range independently, so a
package with a hard pin from one parent and a wider range from another still
lists the wider range's versions as `possible`. A real resolver would intersect
them away. It over-approximates, which is the safe direction for a security
report, but it is imprecise.

## Licence

MIT

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

That last row is why every scan writes observed SHAs and digests to `ref_obs`
from the first run.

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

Everything else in the catalogue — Dockerfile, pre-commit, mise, ansible, Cargo,
Maven, Helm, Terraform — is detected and reported as a frontier.

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

Working, tested, and honest about its limits. Not yet built: a graph UI, OSV
advisory enrichment, and the remaining ecosystem extractors. The schema for the
first two is already in place, because knowledge-time and tag→SHA history cannot
be reconstructed after the fact.

Known limitation: `can` mode expands each declared range independently, so a
package with a hard pin from one parent and a wider range from another still
lists the wider range's versions as `possible`. A real resolver would intersect
them away. It over-approximates, which is the safe direction for a security
report, but it is imprecise.

## Licence

MIT

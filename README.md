# deepdep

Compute the transitive closure of everything a repository pulls in — packages,
container images, OS packages, CI actions, build steps — and report what it
costs you.

```
deepdep scan   .                     # build the closure
deepdep report                       # risk grade, CVEs, posture, controls
deepdep report --format json         # the same, for a pipeline
```

Offline, from a git checkout. No daemon, no image pull, and it **never executes
the code it analyses**.

📄 **[Who can actually fix it](docs/2026-08-16-who-can-fix-it.md)** — 163 of
GitHub's most-used repositories, with risk sorted by whose job it is, and what
to do about it. Declared packages are **4.1× likelier** to carry an advisory
than inherited ones; **90% of container base images** float on a movable tag;
and the `tj-actions/changed-files` advisory sits in OSV where **no PURL query
can reach it**.

---

## Why

Ask an SBOM tool what your repository depends on and it answers with your package
manager's lockfile. That is a real answer to a smaller question. Three things it
leaves out, all of which run with your build's credentials:

**The pipeline.** `grafana` runs **104 third-party GitHub Actions across 94
workflow files** — more third-party code in CI than in the application itself. A
re-pointed tag on any of them executes on your runner. That is the tj-actions
attack, and it appears in no SBOM.

**The image.** `FROM python:3.12-slim` plus `RUN apt-get install curl` are two
supply-chain decisions your `package.json` knows nothing about. `kubernetes` has
**36 Dockerfiles and 2 npm/PyPI packages**.

**What the tool could not read.** A scanner that silently skips a
`docker-compose.yml` reports the same clean result as one that read it and found
nothing. Those are different answers and a report has to distinguish them.

And one thing every SBOM gets structurally wrong: it describes **one
resolution**. Manifests declare *ranges*. What a future `npm install` **can**
pull is strictly larger than what it **will** pull today.

```
one dependency — "is-string": "^1.0.0"

  will    19 packages,     311 edges     ← what an SBOM shows you
  can     81 packages,    1553 edges     ← what the range actually permits

facebook/react, whole repository

  will  4505 packages,  41497 edges     4m
  can  45446 packages,   1.4M edges     7m
```

---

## How

One heterogeneous graph. Nodes are PURL-identified artifacts of any kind —
`pkg:npm/lodash@4.17.21`, `pkg:oci/python@3.12-slim`, `pkg:deb/debian/curl`,
`pkg:github/actions/checkout@v4`. Edges are "pulls in", typed `depends_on`,
`builds_on`, `invokes`, `installs`.

Two plugin seams do the work. **Extractors** turn files into edges; **Resolvers**
expand a node through registry APIs. A bounded concurrent BFS drives both to
closure. Everything else — the SBOM, the CVE audit, the risk report — is a
projection of that one graph.

### Three axes that are not the same thing

Conflating any two produces confident nonsense, so each is a separate field.

| | |
|---|---|
| **Completeness** | how well we know it — `resolved` `declared` `inferred` `opaque` |
| **State** | will it land on disk — `installed` `possible` `unknown` |
| **Pinning** | what holds it there — `pinned` `locked` `floating` |

The third is the one people miss:

```
pyproject: ">4.5.0"  + lock 4.6.1   →  locked    regenerate the lock and it moves
pyproject: "==4.6.1"                →  pinned    regenerating changes nothing
```

Same installed version. Completely different exposure.

### Blind spots are named, never silent

Every node that could not be expanded carries a machine-readable reason:
`bound:depth`, `offline`, `unpinned-ref`, `no-extractor`, `error:parse`,
`unresolved-arg`. `deepdep tools` lists the **95 tool/category pairs** it
recognises; anything recognised but not expandable is reported as a frontier
rather than dropped.

That is NTIA practice #3, "known unknowns" — the thing an ordinary SBOM omits.

### Time travel

Supply-chain questions have two independent clocks, because a CVE published today
applies to a version published years ago.

| `--as-of` | `--known-at` | question |
|---|---|---|
| now | now | what are we exposed to today? |
| release T | T | was this a known problem when we shipped? |
| release T | now | what do we *now* know was wrong with what we shipped? |

Rows 2 and 3 together separate negligence from bad luck.

```
deepdep scan --at 4.18.0 https://github.com/expressjs/express   # tag
deepdep scan --at 5.x    https://github.com/expressjs/express   # branch
deepdep history .                                               # when each dep changed
```

A branch or tag *name* clones shallowly — express at tag `4.18.0` is 7 MB in
2.5 s. Only a SHA or a date needs full history.

**What cannot be reconstructed later**, and is therefore recorded on every run:

| axis | retroactive? | why |
|---|---|---|
| repo state at T | yes | git history |
| version existence at T | yes | registry publish times |
| advisory existence at T | yes | OSV `published` / `withdrawn` |
| advisory *content* at T | **no** | `modified` is destructive |
| tag → SHA at T | **no** | no API exposes it |
| OpenSSF Scorecard at T | **no** | deps.dev serves only the newest |

---

## Results

Ten widely-used applications and libraries, scanned offline from a git checkout.

### What actually executes

| repo | packages | images | OS pkgs | CI actions | Dockerfiles | workflows | build steps |
|---|---|---|---|---|---|---|---|
| next.js | 7099 | 8 | 13 | 35 | 13 | 38 | 150 |
| n8n | 4626 | 16 | 42 | 83 | 10 | 94 | 275 |
| airflow | 3842 | 17 | 7 | 59 | 30 | 52 | 334 |
| home-assistant | 1232 | 3 | 0 | 40 | 4 | 13 | 114 |
| react | 1070 | 0 | 0 | 16 | 0 | 22 | 105 |
| langchain | 728 | 1 | 6 | 25 | 1 | 27 | 68 |
| grafana | 434 | 28 | 27 | **104** | 25 | **94** | 366 |
| vscode | 421 | 2 | 3 | 19 | 4 | 15 | 143 |
| django | 119 | 0 | 0 | 13 | 0 | 17 | 51 |
| kubernetes | 2 | 11 | 19 | 0 | 36 | 0 | 39 |

Seconds per repo, on trees up to 865 MB. Byte-identical across runs under a fixed
`--as-of`.

### Hygiene

| repo | manifests | with lockfile | exact | caret | **open / any** |
|---|---|---|---|---|---|
| langchain | 21 | 21 | 0% | 0% | **97%** |
| airflow | 155 | 14 | 2% | 17% | **78%** |
| django | 4 | **0** | 9% | 36% | 45% |
| react | 129 | 47 | 11% | 86% | 1% |
| next.js | 694 | 14 | 45% | 50% | 3% |

langchain and airflow declare nearly everything as `>=X` with no upper bound.
Every rebuild can cross a major version.

### Reputation — and *why* it fired

Not a score. Named signals carrying the upstream scanner's own evidence, with the
file and line:

```
dangerous-workflow                     73 versions / 8 projects
  github.com/jcrist/msgspec: untrusted code checkout '${{ ... }}'
    .github/workflows/ci-capability-policy.yml:26
  github.com/microsoft/rushstack: script injection with untrusted input
    ' toJson(github.event) ': .github/workflows/file-doc-tickets.yml:30

unmaintained                          862 versions / 764 projects
  github.com/aio-libs/async-timeout: Repository is archived.
```

Across `next.js`, **half of all dependencies come from repos with under 100
stars** (median 106). Contributor count is *not* exposed by deps.dev, so "single
maintainer" is a proxy — stars, `Maintained`, `Code-Review` — and the report says
so rather than implying a headcount.

### Usage × severity, not a score

There is no composite number here and there will not be one: any single figure
averages *"this package was hostile and ran with your credentials"* against
*"this project has no fuzzing harness"*. Two independently-sourced axes instead —
dependent count from deps.dev, severity band from OSV:

| usage (dependents) | MALICIOUS | CRITICAL | HIGH |
|---|---|---|---|
| very-high >100k | 0 | **1** | **12** |
| high 10k–100k | 0 | 9 | 72 |
| med 1k–10k | 0 | 9 | 103 |
| low <1k | 0 | 51 | 337 |

```
615522 dependents  HIGH  npm/brace-expansion@1.1.11   (react)
214508 dependents  HIGH  npm/postcss@8.4.31           (next.js)
191685 dependents  HIGH  npm/form-data@2.3.3          (next.js)
```

13 findings in the top-left cell against 388 in the bottom-right — a 30× cut in
what to read first, while staying two honest axes.

### Malicious packages

**There is an index, and it is the same query as the CVEs.** OSV ingests the
OpenSSF `malicious-packages` feed as `MAL-YYYY-NNNNN`, with an explicit affected
*version list* rather than a range. The Shai-Hulud npm worm is in it.

Those records carry **no severity field**, so a naive report sorts a live worm
below a moderate ReDoS and labels it `UNKNOWN`. `MALICIOUS` is its own class
above `CRITICAL` — a category, not a CVSS band:

```
MALICIOUS  MAL-2025-47141  npm/@ctrl/tinycolor@4.1.1  Malicious code in @ctrl/tinycolor
```

Found through a `RUN npm install` line in a Dockerfile, with no lockfile
involved — which is why `report` queries every state by default.

### Controls already in place

The closure already holds the evidence — a CI action is a node, a shell step is
a node carrying its command — so detecting what a repo already runs is a query,
not another scan. `report` checks nine categories and, more usefully, says which
are **missing**:

```
5. CONTROLS IN USE
   container-scanning   Trivy            .github/workflows/security-trivy-scan-callable.yml
   static-analysis      CodeQL           .github/workflows/sec-poutine-reusable.yml
   signing              cosign           .github/workflows/docker-build-push.yml
   signing              SLSA generator   .github/workflows/docker-build-push.yml
   not detected: dependency-scanning, sbom, secret-scanning, iac-scanning,
                 dependency-updates, ci-hardening
```

Across the ten repositories above:

| repo | controls detected |
|---|---|
| n8n | Trivy, CodeQL, cosign, SLSA generator |
| home-assistant | CodeQL, cosign, Dependabot, Renovate |
| grafana | CodeQL, TruffleHog, Dependabot, Renovate |
| airflow | govulncheck, CodeQL, Dependabot |
| react / langchain / vscode | Dependabot only |
| **next.js / django** | **none** |
| kubernetes | *not assessable* |

Detection matches the **invoked command**, never a mention: a step that greps for
`trivy` or writes `sbom.json` is not running a scanner, and `npm audit` counts
while `npm ci` does not. Commercial products (Snyk, SonarQube, Veracode,
Checkmarx, Mend, FOSSA, Docker Scout, Harden-Runner) are detected and marked.

`kubernetes` is reported as **not assessable** rather than "none": it runs Prow
and has no `.github/workflows` at all. Absence of evidence and evidence of
absence are different findings, and a report that conflates them is worse than
one that says nothing.

### The risk grade

One number, printed with the arithmetic that produced it. A score you cannot
take apart is a score you have to either trust or ignore:

```
RISK  C  (37/100, higher is worse)
  malicious         0 packages                                        none
  vulnerabilities   0 critical, 36 high, 11 moderate in 3124 packages  +15 / 45
  hygiene           0% floating (2 of 3124 unheld by any constraint)    +0 / 20
  controls          6 of 9 categories absent from CI                   +13 / 20
  upstream posture  862 unmaintained, 73 dangerous-workflow            +10 / 15
  81% of package nodes were auditable
```

Two rules keep it honest:

**A malicious package clamps the grade to F**, whatever the other terms say.
Averaging hostile code that already ran with your build's credentials into a
mid-range number is the exact failure a composite score is accused of, so it is
made impossible rather than merely unlikely.

**Below 50% auditable coverage there is no grade at all.** home-assistant has
zero findings and 15% of its packages readable; that is an unanswered question,
not an A. Coverage gates the grade and never adds points — charging for the
tool's own blind spots would invert the meaning.

The vulnerability term is severity-weighted *density* on a square-root curve: a
raw count punishes size rather than risk, and a linear term either gives
airflow's 36 HIGH across 3124 packages one point out of 45 or saturates react
and next.js alike. Weights are exported constants; recompute it if you disagree.

| repo | grade | | repo | grade |
|---|---|---|---|---|
| next.js | **F** (76) | | airflow | C (37) |
| react | D (69) | | langchain | B (31) |
| n8n | C (40) | | vscode, grafana, django, kubernetes, home-assistant | *not graded* |

Five of ten are ungraded offline, which is the point: without a supported
lockfile there is nothing to grade, and saying so beats inventing an A.

---

## Commands

```
deepdep scan    [flags] <git-url|directory>   build and store the closure
deepdep report  [flags] [run-id]              malicious + CVEs + posture, layered
deepdep audit   [flags] [run-id]              OSV advisories, bitemporal
deepdep risk    [flags] [run-id]              deps.dev + OpenSSF Scorecard
deepdep history [flags] <directory>           when each dependency changed
deepdep tools                                 the recognition catalogue
```

### SBOM

```
deepdep scan --format cyclonedx .                  # one document
deepdep scan --format cyclonedx --sbom-dir out/ .  # one per deliverable
```

CycloneDX 1.6, validated against the official JSON schema — **339 documents
across the ten repos above, 0 errors**. **NTIA minimum elements: 6 of 7**; the
seventh, component hash, needs registry digests, and the document says so rather
than omitting it quietly.

`--sbom-dir` writes one document per application, one per Dockerfile and one
`_repo` for the pipeline, then prints the `cyclonedx merge --hierarchical` line
that assembles them.

`formulation` carries the build itself — pipelines, base images, shell steps —
the CycloneDX MBOM view. A base image and a third-party action appear in no
`components[]` list anywhere else.

---

## Supported

| | extract | resolve | effective |
|---|---|---|---|
| npm | `package.json` | registry | `package-lock.json`, `pnpm-lock.yaml` |
| PyPI | `pyproject.toml`, `requirements*.txt` | PyPI JSON | `uv.lock` |
| Dockerfile | `FROM`, `RUN` | — | — |
| GitHub Actions | workflows | — | — |
| GitLab CI | `.gitlab-ci.yml`, includes, components | — | — |

OS packages parsed from `RUN` lines carry their distribution namespace, which is
load-bearing rather than cosmetic — verified against OSV, `pkg:deb/debian/curl`
returns 71 advisories and `pkg:deb/curl` returns 0:

```
FROM debian:12       + apt-get install curl=7.88.1-10  →  pkg:deb/debian/curl@7.88.1-10
FROM node:24-alpine  + apk add curl=8.11.1-r0          →  pkg:apk/alpine/curl@8.11.1-r0
FROM rockylinux:9    + dnf install curl                →  pkg:rpm/rocky/curl
```

The command decides the family — you cannot run `apt-get` on Alpine — and the
stage's base image refines the distribution. Where it cannot, the node is marked
`distro-assumed`: `deb/debian` and `deb/ubuntu` carry different advisories, so a
wrong guess is worse than none.

Everything else in the catalogue — pre-commit, mise, ansible, Cargo, Maven, Helm,
Terraform — is detected and reported as a frontier.

---

## Design notes

- **Never executes analysed code.** No `npm install`, no `docker build`.
  Resolution is registry-API-only. An analyser that runs untrusted postinstall
  scripts to learn a dependency graph is a liability.
- **Multiplicity lives on edges, never on nodes.** Nodes deduplicate by identity;
  a base image used by four Dockerfiles is one node. Any per-occurrence fact —
  which file pulled it in, which range was declared — must live on the edge, or
  the last writer wins and the answer is both wrong and nondeterministic.
- **Version semantics are per-ecosystem.** npm ranges and PEP 440 specifiers
  disagree about ordering, about `~`, and about pre-releases. npm is validated
  against node-semver's own fixture corpus; PEP 440 differentially against
  Python's `packaging` (644 cases).
- **Advisory counts are never materialised.** They are a function of `known_at`,
  a query parameter. Storing them would un-bitemporalise the design.
- **Bounds are named, never silent.** Depth, node count and timeout each mark
  their frontier with a reason, and the partial closure is still emitted.

## Storage

SQLite (`modernc.org/sqlite`, pure Go, no cgo — one static binary). Indexed
adjacency answers "why is this here?" in milliseconds; observation tables record
what cannot be reconstructed later.

```sql
SELECT name, versions_installed, path_count, worst_completeness
  FROM package_rollup ORDER BY path_count DESC LIMIT 10;
```

## Install

```
go install github.com/jverhoeks/deepdep/cmd/deepdep@latest
```

Go 1.26+. 15 packages, ~11k lines with ~5.5k lines of tests, green under `-race`.

## Limits

- **`can` mode is expensive.** react's full can-closure takes ~7 minutes and
  stops at the 50,000-node cap (`--max-nodes`), not at the clock. It is a
  deliberate bound, not a scaling failure, but it is not a thing to put in a
  pre-commit hook.
- **Yarn and Go have no effective resolver**, so `yarn.lock` / `go.sum`-only repos
  resolve far less. grafana and kubernetes report 0 installed packages for this
  reason and their findings come from Dockerfiles alone. A low coverage ratio
  makes "0 CVEs" meaningless, so the report states the ratio.
- **Base image contents are invisible.** `FROM python:3.12-slim` ships hundreds of
  Debian packages no Dockerfile mentions. That is a *Build*-layer fact and
  `syft <image>` answers it; deepdep reads Dockerfiles and never builds them.
- **`can` over-approximates.** Ranges expand independently, so a package
  hard-pinned by one parent still lists the wider range's versions as `possible`.
  The safe direction for a security report, but imprecise.

## Licence

MIT

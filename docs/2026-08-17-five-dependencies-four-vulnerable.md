# Five dependencies. Four of them vulnerable.

### The most-starred repository on GitHub, and what 163 others taught me about where supply-chain risk actually lives

*17 August 2026. Every figure is from `deepdep`, one binary, one run, over three
frozen repository lists. Scripts and aggregates: [`analysis/`](../analysis). The
methodology piece is [Who can actually fix it](2026-08-16-who-can-fix-it.md);
this one is the findings.*

---

`public-apis/public-apis` has **460,755 stars**. More than React. More than
Linux. It is, by that measure, the most popular repository on GitHub.

It declares **five Python packages**.

**Four of them carry a published advisory.**

```
pypi/urllib3@1.26.8   HIGH  CVE-2026-21441  decompression-bomb safeguards bypassed
pypi/urllib3@1.26.8   HIGH  CVE-2025-66471  streaming API mishandles compressed data
pypi/certifi@2021.10.8 HIGH CVE-2023-37920  removal of e-Tugra root certificate
```

Five dependencies is a list you can read in under a minute. Nobody read it. The
repository runs **no detected security control at all** — no dependency
scanning, no Dependabot, nothing — and grades **F**.

This is not a story about a hard problem. It is a story about a five-line file.

---

## The pattern: the smaller the surface, the worse it gets

I scanned 163 of GitHub's most-used repositories. The result that surprised me
was not that big projects have big problems. It was this:

> **The projects with the fewest dependencies had the worst hit rates.**

```
repo                            stars    declared  vulnerable   rate   grade
public-apis/public-apis       460,755           5           4    80%      F
deepfakes/faceswap             57,461          24           7    29%      D
jackfrued/Python-100-Days     185,218          37          10    27%      D
TheAlgorithms/Python          223,773          25           4    16%      F
microsoft/markitdown          174,002          11           1     9%      F
—
langchain-ai/langchain        144,323          98           1     1%      B
```

A 5-package project at 80%. A 98-package project at 1%.

The difference is not scale. It is whether *anybody is watching*. `langchain`
has more than nineteen times the dependencies and a twentieth of the hit rate,
because something tells them when one goes bad.

**Small dependency lists don't get automated. Nobody thinks five packages needs
a bot.** Then the file sits untouched for four years.

`jackfrued/Python-100-Days` — 185,000 stars, a repository people learn Python
from — pins `certifi@2020.4.5.1`. That pin is from **April 2020**.

---

## Tier 1: the code people copy

These repositories exist to be read and reused. Their dependency lists are
templates that get pasted into other people's projects.

### `TheAlgorithms/Python` — 223,773 stars, grade F

```
HIGH  CVE-2025-9906  pypi/keras@3.9.2  Deserialization of Untrusted Data
HIGH  CVE-2025-9905  pypi/keras@3.9.2  Model.load_model silently ignores safe_mode
HIGH  CVE-2026-1669  pypi/keras@3.9.2  local file disclosure via HDF5 external storage
```

A deserialization flaw, in a repository whose entire purpose is teaching people
how to write Python. 4 of 25 declared packages are affected.

### `Shubhamsaboo/awesome-llm-apps` — 132,816 stars, grade F

188 separate demo applications. **618 declared packages, 76 affected, 15
CRITICAL, 232 HIGH** — the worst direct exposure in the fleet.

```
CRITICAL CVE-2026-67337  npm/better-auth@1.2.8  two-factor authentication bypass
CRITICAL CVE-2026-53512  npm/better-auth@1.2.8  OAuth refresh-token replay
CRITICAL GHSA-9qr9-h5gf npm/next@15.3.2         RCE in React flight protocol
```

A **2FA bypass** in an authentication library, in a repository of starter apps
that 132,000 people have bookmarked to copy from. The reference implementation
is the vulnerability.

---

## Tier 2: software people actually run

### `ollama/ollama` — 178,648 stars, grade D

Three criticals in its build tooling, **20 references that can move under it**,
and **zero detected security controls** in CI.

### `open-webui/open-webui` — 148,908 stars, grade D

```
CRITICAL CVE-2026-45829  pypi/chromadb@1.5.9  pre-authentication code injection
CRITICAL CVE-2026-47429  npm/vitest@1.6.1     arbitrary file read via UI server
HIGH     CVE-2026-13697  npm/undici@7.28.0    cross-user information disclosure
```

**Pre-authentication code injection** in the vector store, named directly in its
own manifest. 21 of 261 declared packages affected.

### `browser-use/browser-use` — 109,377 stars, grade F

One manifest. 48 declared packages. And this:

```
HIGH CVE-2026-54653  datamodel-code-generator@0.53.0  code injection
HIGH CVE-2026-55415  datamodel-code-generator@0.53.0  code injection via input
HIGH CVE-2026-55389  datamodel-code-generator@0.53.0  arbitrary local file read
HIGH CVE-2026-54656  datamodel-code-generator@0.53.0  code execution on load
```

**Four separate HIGH advisories against one pin.** One line. One version bump.
This is the single cheapest fix in the entire study, sitting in a project with
over a hundred thousand stars.

---

## Tier 3: the thing nobody scans at all

Here is where it stops being about CVEs.

```
container base images referenced                420
  of those, on a MOVING tag                     375   89%
third-party CI actions invoked                 2593
  of those, on a MOVING tag                    1514   58%
repositories with >=1 moving first-party ref    132   81%
```

**89% of container base images across the top of GitHub are pinned to a tag, not
a digest.** `python:3.12-slim`, `ubuntu:24.04`, `node:20-alpine`. Twelve
repositories build on `ubuntu:24.04`; nine on `python:3.12-slim`. Rebuild
tomorrow, get different bytes, no commit anywhere in your history.

Some don't even pin a major version: `krahets/hello-algo` builds on
`ubuntu:latest`. `firecrawl/firecrawl` and `anomalyco/opencode` build on
`alpine:latest`.

### And `tj-actions/changed-files` is still running

The most-cited CI supply-chain compromise in existence. Its advisory is *in
OSV* — and **no PURL query reaches it**, because the records carry a null purl.
Every scanner built on Package URL reports these repositories as clean.

Ask the question the way OSV will actually answer, and:

| repository | stars | ref | |
|---|---|---|---|
| `EbookFoundation/free-programming-books` | 394,513 | `@v46` | **moving tag** |
| `godotengine/godot` | 115,728 | `@v47` | **moving tag** |
| `milvus-io/milvus` | 45,651 | `@v46` | **moving tag** |
| `langgenius/dify` | 152,581 | `@9426d409…` | SHA-pinned ✅ |
| `immich-app/immich` | 110,696 | `@a1c6acee…` | SHA-pinned ✅ |

**Be precise about this**: `v46` today resolves to a patched release, so these
projects are very likely running safe code *right now*. That is not the point.
The point is that a tag is a pointer someone else controls, and repointing it is
*exactly* what happened in the original attack. `dify` and `immich` are immune
to a repeat. The other three are trusting that it doesn't happen twice.

**60% of the entire fleet invokes at least one CI action carrying a published
advisory.** These run with your build credentials.

---

## The upcoming projects are worse, and it's structural

The fast-growing list — repositories ranked by stars *per day* since creation:

```
                     no security control    >=1 moving ref
top 100 active            44%                    78%
top 50 fast-growing       53%                    74%
top 50 AI, in use         29%                    94%
```

**More than half of the fastest-growing projects on GitHub run no detected
security control whatsoever.** Not one scanner, not one bot.

```
repo                        stars/day   age   declared  moving refs  controls
stablyai/orca                     305   152d       176           21         0
JustVugg/colibri                  558    45d        24           13         0
garrytan/gstack                   817   157d        18           12         2
DietrichGebert/ponytail         1,595    65d         2            3         0
```

`stablyai/orca`: 176 declared dependencies, 21 references that can move under
it, zero controls, 152 days old.

And the AI projects have the *worst* moving-ref exposure of any group — **94%**
carry at least one. They're the most container-heavy and the most CI-heavy, and
almost nobody pins a digest.

---

## What good looks like

It is achievable, and the same data shows it:

| repo | grade | why |
|---|---|---|
| `ohmyzsh/ohmyzsh` | **A** | 4 controls, **zero moving refs**, everything pinned |
| `xai-org/grok-build` | **A** | 32 days old, zero moving refs |
| `langchain-ai/langchain` | **B** | 98 declared, 1 affected — automation catches them |
| `yt-dlp/yt-dlp` | **B** | 29 declared, 0 affected |
| `odysseus-dev/odysseus` | **B** | 76 days old, **5 controls already running** |

`odysseus` is the one to notice. It is 76 days old and already runs five
security controls. `stablyai/orca` is 152 days old and runs none. Nothing about
age or size forced either outcome — it was a decision, made once, early.

---

## Fix it: four things, in order of value per hour

### 1. Digest-pin your base images — 89% exposed, 2% scan for it

```dockerfile
- FROM python:3.12-slim
+ FROM python:3.12-slim@sha256:7c4d2e5f...
```

Renovate and Dependabot both update digest pins automatically, so you keep
patching *and* get reproducible builds. One afternoon, permanently fixed.

### 2. SHA-pin your CI actions — they hold your credentials

```yaml
- uses: actions/checkout@v4
+ uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8  # v5.0.1
```

`dify` and `immich` did this and are structurally immune to a tj-actions repeat.
Add `zizmor` or `step-security/harden-runner` to keep it that way — of the 20
repositories in the fleet running harden-runner, **all 20 pin correctly**.

### 3. Automate the small list *especially*

The 80%-hit-rate repository had five dependencies. The 1% repository had 98.
The difference was a bot.

```yaml
# .github/dependabot.yml — the whole file
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule: { interval: "weekly" }
```

**Dependabot is at 57% adoption across the fleet. Dependency scanning is at
12%.** That gap isn't knowledge — both are trivially available. It's that one is
a single file and the other needs a workflow. Make yours a single file.

### 4. Sort your findings by who can fix them

Across the repositories where a declaration is unambiguous, **5.5% of declared
packages carry an advisory against 1.3% of inherited ones — a 4.1× gap**. Your
declared surface is a median of 53 packages holding about a third of your known
criticals. It is small, it is yours, and it is where the fixable problems are.

```bash
deepdep scan . && deepdep report | sed -n '/2b. REACH/,/^3\./p'
```

Look for the `browser-use` shape: **one stale pin, four advisories.** Sort by
advisories-per-package and the cheapest fixes surface immediately.

---

## The honest caveats

**The rate measures advisory coverage, not safety.** Direct dependencies skew
toward the frameworks researchers actually audit. The ~219,000 inherited
packages are mostly leaves nobody has filed against. A low rate down there means
less attention, not less risk.

**Named repositories are only ones where attribution is unambiguous.** Monorepos
carrying example apps and test fixtures are excluded from every leaderboard here
— a fixture pinning an old version for a regression test is not the project
shipping a vulnerability, and the tool cannot yet tell you which manifest
declared what.

**CI-action findings are not version-matched.** OSV answers for actions only
without a version, so those rows say *this action has an advisory*, not *your
ref is inside it*.

**And 27 of the 163 resolved no packages at all.** A scanner that reports those
as clean isn't wrong about any package — it's wrong about what it looked at.

---

*Reproduce everything: [`analysis/`](../analysis). deepdep never executes the
code it analyses — resolution is registry-API only.*

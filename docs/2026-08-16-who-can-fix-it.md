# Who can actually fix it

### 163 of GitHub's most-used repositories, with supply-chain risk sorted by whose job it is — and what to do about it

*16 August 2026. Every number below comes from `deepdep`, one binary, one run,
against three frozen repository lists. The lists, the scripts and the aggregated
output are in [`analysis/`](../analysis); every table is in
[`analysis/tables.frozen.txt`](../analysis/tables.frozen.txt). You can re-run the
arithmetic without re-running the scans.*

---

Severity tells you how bad a vulnerability is. It does not tell you what to do
on Monday.

A CRITICAL in a package you named in your own manifest is a version bump you
own. A CRITICAL four levels down, pulled in by something pulled in by something
you chose, is different work: you wait, you fork, or you accept it. Both arrive
as "CRITICAL" in the same list, in the same red.

So I built that split into the tool and pointed it at the top of GitHub.

## The lists

| List | Definition | n |
|---|---|---|
| **Top 100 active** | Most-starred repositories pushed to in the last 30 days | 100 |
| **Top 50 fast-growing** | Highest stars-per-day since creation, over a 300-repository pool created in the last 24 months | 50 |
| **Top 50 AI, in use** | AI-topic repositories that are *software*, not reading material: >8,000 stars, ≥365 days old, a declared language, name and description not matching a content-repository pattern list | 50 |

167 unique targets after overlap; **163 produced a result**. Four failed on clone
or expansion bounds — `torvalds/linux`, `denoland/deno`, `n8n-io/n8n`,
`OpenBB-finance/OpenBB` — counted as failures, not dropped.

---

## 1. Most of the top of GitHub cannot be scanned at all

```
                                                 all  active  growing
repositories scanned                             163      97       50
  had a build file or manifest we could read     155      91       46
  resolved at least one package version          136      77       41
  >=50% of package nodes auditable               134      75       41
```

**27 of 163 resolved no package versions whatsoever.** Eight recognised nothing
at all — `awesome-selfhosted`, `free-for-dev`,
`system-prompts-and-models-of-ai-tools` and similar. These are among the
most-starred repositories on the platform and they are documents.

Any "we scanned the top 100 repos" claim that does not say this out loud is
averaging Markdown into its denominator.

The AI list is the contrast: **96% scannable** against 79% for top-100-active.
Filtering for software rather than stars changes what you are measuring more
than any scanner setting does.

Of the 134 gradeable repositories: **2 A, 15 B, 39 C, 58 D, 20 F.**

---

## 2. What you declare yourself is 4× likelier to be flawed

Here I have to be careful, and the care is the interesting part.

The tool's split asks "do this repository's own files name this package?" That
is true, and it is **not** the same as "does this repository ship it".
`vercel/next.js` has 693 `package.json` files and 389 of them are under
`examples/` or `tests/` — a fixture pinning an old Next for a regression test
reads as the project declaring a vulnerable Next. It isn't shipping one.

So the honest cut is to drop every repository that carries an example or fixture
manifest, leaving 70 where *declared* and *shipped* are the same thing:

```
                                      n         direct              inherited        ratio  d.crit  i.crit
all with resolved packages          136    682/15420     4.4%   2771/214442   1.3%    3.4x     103     240
no example/fixture manifests         70    240/4236      5.7%   1009/73901    1.4%    4.1x      28      57
carries example/fixture manifests    66    442/11184     4.0%   1762/140541   1.3%    3.2x      75     183
```

The effect gets **stronger** when the ambiguity is removed. On repositories where
declared means shipped, **5.7% of declared packages carry an advisory against
1.4% of inherited ones — a 4.1× gap.**

**One caveat that must not be trimmed: this measures advisory *coverage*, not
safety.** Direct dependencies skew toward the frameworks and tooling security
researchers actually audit. The 214,442 inherited packages are mostly small leaf
libraries nobody has ever filed against. A low rate down there means less
attention, not less risk.

What survives the caveat is the shape of the work:

```
median declared packages per repository       53
median inherited packages per repository    1132
declared share of all packages              6.7%
share of all criticals that are declared     30%
```

**The surface you control is 7% of your packages and holds 30% of your known
criticals.** It is also the only part you can act on this week.

And the leverage is brutal. `Snailclimb/JavaGuide` declares 14 packages and
inherits 2,818 — **201×**. `tauri-apps/tauri`: 30 declared, 2,327 inherited.
Fourteen times at the median.

### Directly at risk — repositories where declared means shipped

```
repo                              mfsts  declared  affected    rate  crit  high  grade
ollama/ollama                         2        68        10   14.7%     3     5      D
open-webui/open-webui                 4       261        21    8.0%     2    30      D
deepfakes/faceswap                   15        24         7   29.2%     1     2      D
browser-use/browser-use               1        48         6   12.5%     0    23      F
jackfrued/Python-100-Days             1        37        10   27.0%     0    14      D
TheAlgorithms/Python                  1        25         4   16.0%     0    25      F
Mintplex-Labs/anything-llm            7       177        16    9.0%     0    15      F
microsoft/markitdown                  4        11         1    9.1%     0     5      F
langchain-ai/langchain               21        98         1    1.0%     1     0      B
```

Real, checkable examples:

- **`ollama/ollama`** — two manifests, 68 declared packages, three criticals:
  `CVE-2026-47429` and two more in `vitest`/`@vitest/browser@3.2.4`.
- **`open-webui/open-webui`** — `CVE-2026-45829` in `chromadb@1.5.9`,
  a *pre-authentication code injection*, named directly.
- **`browser-use/browser-use`** — one manifest, and four separate HIGH code-injection
  advisories against a single pinned `datamodel-code-generator@0.53.0`.
- **`microsoft/markitdown`** — four HIGHs, all in one pin: `mcp@1.8.1`.

Notice the pattern in the last two: **one stale pin, several advisories.** That
is the cheapest fix in this entire article.

And `langchain-ai/langchain` shows it is achievable — 98 declared packages, one
affected, **grade B**, the best result of any large AI project in the fleet.

---

## 3. Your CI and your Dockerfile are dependencies

This is where ordinary tooling has nothing to say at all.

```
repositories with CI workflows read             146   90%
repositories with a Dockerfile read              81   50%
third-party CI actions invoked                 2593
  of those, on a MOVING tag                    1514   58%
container base images referenced                432
  of those, on a MOVING tag                     387   90%
repositories with >=1 moving first-party ref    132   81%
statically undecidable build steps            11694
```

**90% of container base images across the top of GitHub are pinned to a tag that
can be repointed at any image.** Not a digest — a tag. `python:3.11-slim`,
`node:20-slim`, `debian:bookworm-slim`. Rebuild tomorrow, get different bytes,
with no commit anywhere in your history.

58% of third-party CI actions are on a moving ref too, and **81% of repositories
carry at least one.** These run with your build credentials.

These counts are exact. Actions and images hang off a *file node*, so the tool
knows which workflow and which Dockerfile — none of the attribution ambiguity
that forced the careful cut in section 2.

### The advisory that exists and no scanner will match

`tj-actions/changed-files` — the most-cited CI supply-chain compromise there is —
**has an advisory in OSV**, and every PURL-keyed scanner reports repositories
using it as clean. Verified against the live API:

```
{"purl":"pkg:github/tj-actions/changed-files@45.0.7"}          -> {}
{"purl":"pkg:githubactions/tj-actions/changed-files@45.0.7"}   -> {}
{"name":"...","ecosystem":"GitHub Actions","version":"45.0.7"} -> {}
{"name":"...","ecosystem":"GitHub Actions"}
                        -> GHSA-mcph-m25j-8j63, GHSA-mrrh-fwg8-r2c3
```

The records carry a **null purl**, and state ranges in a versioning that refs
(`v45`, a SHA) do not follow. Only the version-less ecosystem+name query returns
anything. Package URL is the identifier the modern scanning ecosystem is built
on, and for GitHub Actions it reaches nothing.

Ask the question correctly and:

```
action nodes queried across the fleet     2616
repositories invoking a flagged action      98   60%

action                                    repos  on a moving ref
actions/download-artifact                    87               43
github/codeql-action                         87               34
pypa/gh-action-pypi-publish                  22               10
step-security/harden-runner                  20                0
anthropics/claude-code-action                10                7
ultralytics/actions                           9                9
tj-actions/changed-files                      8                6
```

**60% of the fleet invokes a CI action carrying a published advisory.**
`tj-actions/changed-files` is still in use in 8 of them, **6 on a moving ref**,
well over a year after the compromise.

One limit, stated in the tool's own output: because OSV only answers without a
version, this says *the action has an advisory*, not *your ref is in its range*.
`deepdep` keeps these in a separate type and excludes them from the grade — an
unverified ref must not move a number. It is still the difference between a
scanner that said nothing about tj-actions and one that says go and look.

---

## 4. Hygiene, and what CI actually runs

```
floating   93,953  42%     no exact constraint holds this version
locked     66,676  30%
pinned     61,546  28%
```

**42% of all resolved versions across the fleet are floating** — a rebuild can
move them with no line changing in the repository. 26 repositories are over 75%
floating; exactly one is fully held.

```
control                   repos running it   share
dependency-updates                      84     57%
static-analysis                         45     31%
ci-hardening                            18     12%
dependency-scanning                     17     12%
signing                                  7      5%
sbom                                     6      4%
secret-scanning                          6      4%
container-scanning                       3      2%
iac-scanning                             0      0%

running NO detected control at all: 64  (44%)
```

Of 147 repositories whose CI is readable, **44% run no detected security control
at all** and **only 12% run dependency scanning**. Six produce an SBOM. Three
scan containers — while half the fleet ships a Dockerfile and 90% of base images
float.

Dependabot is the exception at 57%. The most-adopted control by a wide margin is
the one that turns on with a single file. That is not a coincidence, and it is
the single most useful lesson in this data.

---

## What teams should actually do

Ordered by value per hour, using this fleet's numbers as the argument.

### 1. Pin your base images to digests — highest value, lowest effort

**90% of the fleet is exposed here and 2% scan for it.** A tag is a mutable
pointer; a digest is content.

```dockerfile
# before — whatever that tag points at today
FROM python:3.12-slim

# after — these exact bytes, forever
FROM python:3.12-slim@sha256:7c4d2e5f...
```

Renovate and Dependabot both update digest pins automatically, so you keep
patching without giving up reproducibility. One afternoon, permanently fixed.

### 2. Pin CI actions to SHAs — they run with your credentials

58% of actions across the fleet are on a moving tag. `uses: some/action@v4` means
"whatever the maintainer points `v4` at", which is exactly the tj-actions
mechanism.

```yaml
# before
- uses: actions/checkout@v4

# after
- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8  # v5.0.1
```

Add `zizmor` or `step-security/harden-runner` to enforce it. Only 20 repositories
in the entire fleet run harden-runner — and all 20 pin it correctly, which tells
you something about who adopts it.

### 3. Audit your declared dependencies first — it is a one-afternoon list

The median repository declares **53 packages**. That is a list you can read in a
sitting, and it holds 30% of your criticals.

```bash
deepdep scan . && deepdep report | sed -n '/2b. REACH/,/^3\./p'
```

Look for the `browser-use` pattern: **one stale pin producing four advisories**.
Sorting by "number of advisories per package" finds those instantly, and each is
one line.

### 4. Commit a lockfile, then let a bot move it

42% floating across the fleet. Floating is not "staying current" — it is "your
build is different on Tuesday and nobody wrote it down". A lockfile plus
Dependabot or Renovate gives you both: reproducible builds *and* patching, with
the change visible as a reviewable diff.

57% of the fleet already runs the bot. Fewer than that commit lockfiles.

### 5. Turn on the three controls almost nobody runs

- **dependency scanning** (12%) — `osv-scanner`, `trivy fs`, `grype`
- **container scanning** (2%) — `trivy image`, and mean it: half the fleet ships a Dockerfile
- **secret scanning** (4%) — `gitleaks`, `trufflehog`

Each is roughly ten lines of workflow. The gap between 57% adoption for
Dependabot and 12% for dependency scanning is not a knowledge gap, it is a
friction gap.

### 6. For inherited risk, change the question

You cannot bump what you did not declare. What you *can* do:

- **Measure leverage before adding a dependency.** 14× at the median, 201× at the
  worst. "It's only one package" is almost never true — check what it drags in
  before you merge it.
- **Prefer fewer, larger, better-maintained dependencies.** `langchain` declares
  98 and grades B; `llama_index` declares 719. Same problem space.
- **Use `deepdep report`'s reach split to route work.** Direct findings go to a
  sprint. Inherited findings go to a risk register with an owner and a date —
  they are real, but they are not this week's pull request.

### 7. Know what your scanner cannot see

Ask any tool what it *could not* read before believing what it found. 27 of these
163 repositories resolved zero packages; a scanner reporting them clean is not
wrong about any package, it is wrong about what it looked at.

```bash
deepdep report | sed -n '/4b. COVERAGE FRONTIER/,/^5\./p'
```

---

## Four bugs this run found in the tool

I would not publish the numbers above without this section, because three of
these produced *confident wrong answers* rather than crashes — the class that
matters most in a security tool.

1. **npm hoisting made every transitive package look declared.** npm hoists
   nearly everything to the top of `node_modules` and the lockfile merge attaches
   those to the root — `axios` read as 122 direct dependencies against ~60. A
   hoisted sub-sub-dependency's CVE was being reported as the maintainer's own
   line to fix. Placements carry no version range and declarations always do, so
   that absence now decides.

2. **A coverage-denominator bug suppressed every grade.** Frontiers the walk
   stopped at *on purpose* — a dependency's devDependencies, an unrequested
   Python extra — were counted as unread. `axios` read 44% auditable, below the
   grading threshold. **All 163 repositories came back ungraded.** Corrected, it
   reads 99% and 134 grade.

3. **A fired `--timeout` discarded the partial closure it promised to keep.** The
   walker stopped correctly, then the database write inherited the expired
   deadline and threw everything away. Size-correlated, so the largest
   repositories reported as total failures while holding good partial answers.

4. **`RUN npm install -g pkg@latest` minted `latest` as a version.** OSV cannot
   order that token against any range and answered with every npm advisory ever
   filed — an image whose npm is current reported CVE-2013-4116, from 2013. 52
   findings across the fleet rested on versions that do not exist, and they
   landed on the Dockerfile surface, inflating the exact number it exists to
   report. That row read 6 critical before the fix; it reads 0 now.

### And one still open

Manifest edges go straight to the repository root, so the graph cannot say
**which** manifest declared a package. Dockerfiles and workflows can, because
they hang findings off a file node. Until manifests do the same, a monorepo's
example apps are indistinguishable from its product — which is why section 2 is
restricted to the 70 repositories that have no example or fixture manifests at
all, rather than asserting anything about `next.js`.

---

## What I'd take away

**Sort by who can fix it before you sort by severity.** The declared surface is
7% of your packages and 30% of your criticals, and it is the only part you can
act on this week. Every scanner I know buries it in one list with the 214,442
packages you inherited.

**Your build is a dependency.** 90% of base images and 58% of CI actions across
the top of GitHub float on a movable tag; 60% of repositories invoke an action
with a published advisory; and Package URL — the identifier the whole ecosystem
is built on — does not reach GitHub Actions advisories at all.

**Adoption follows friction, not risk.** Dependabot is at 57% because it is one
file. Container scanning is at 2% while half the fleet ships a Dockerfile. If you
want a control adopted, make it a single file.

---

*Reproduce: `analysis/lists.sh && analysis/lists-ai.sh` to refetch the lists (they
drift; the frozen copies used here are committed alongside), then
`analysis/run.sh <repo>` per repository, `analysis/manifests.py`, and
`analysis/finish.sh`. deepdep never executes analysed code — resolution is
registry-API only.*

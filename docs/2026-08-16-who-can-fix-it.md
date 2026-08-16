# Who can actually fix it

### What 163 of GitHub's most-used repositories look like when you sort supply-chain risk by *whose job it is*

*16 August 2026. Every number below comes from `deepdep`, one binary, one run,
against three frozen repository lists. The lists, the aggregation scripts and
the raw output are in [`analysis/`](../analysis) — you can re-run the arithmetic
without re-running the scans.*

---

Severity tells you how bad a vulnerability is. It does not tell you what to do
on Monday.

A CRITICAL in a package you named in your own `package.json` is a version bump
you own. A CRITICAL four levels down a dependency chain, pulled in by something
pulled in by something you chose, is a different piece of work entirely: you
wait, or you fork, or you live with it. Both show up as "CRITICAL" in every
scanner I know of, sorted into the same list, in the same red.

So I built the split into the tool and pointed it at the top of GitHub.

## The three lists

| List | Definition | n |
|---|---|---|
| **Top 100 active** | Most-starred repositories pushed to in the last 30 days | 100 |
| **Top 50 fast-growing** | Highest stars-per-day since creation, ranked over a 300-repository pool created in the last 24 months | 50 |
| **Top 50 AI, in use** | AI-topic repositories that are *software*, not reading material: >8,000 stars, ≥365 days old, a declared language, and neither name nor description matching a content-repository pattern list | 50 |

167 unique targets after overlap; 163 produced a result. The AI list needed the
extra filters because star rank on GitHub's AI topics is dominated by two things
that are not software — curated lists and courses, and the current wave of
three-week-old agent harnesses riding a spike. The age floor removes the second
without anyone deciding by taste which spike deserves it.

Four repositories failed outright — `torvalds/linux`, `denoland/deno`,
`n8n-io/n8n`, `OpenBB-finance/OpenBB` — on clone or expansion bounds. They are
counted as failures, not dropped.

## First: most of the top of GitHub is not scannable at all

```
                                                 all  active  growing
repositories scanned                             163      97       50
  had a build file or manifest we could read     155      91       46
  resolved at least one package version          136      77       41
  >=50% of package nodes auditable               134      75       41
```

**27 of 163 resolved no package versions whatsoever.** Eight recognised nothing
at all: `awesome-selfhosted`, `free-for-dev`,
`system-prompts-and-models-of-ai-tools`, `free-programming-books-zh_CN` and
similar. These are among the most-starred repositories on the platform and they
are documents. Any "we scanned the top 100 repos" claim that does not say this
out loud is quietly averaging Markdown into its denominator.

The AI list is the interesting contrast: **96% scannable**, against 79% for the
top-100-active. Filtering for software rather than stars changes what you are
measuring more than any scanner setting does.

Of the 134 gradeable repositories: **2 A, 15 B, 39 C, 58 D, 20 F.**

## The finding: what you named yourself is 3.4× likelier to be flawed

```
surface                   packages  affected  crit  high  other    rate
direct — manifest            15086       617   103  1305   2517    4.1%
direct — dockerfile            334        65     0    32   2734   19.5%
inherited (transitive)      214442      2771   240  3733   4496    1.3%
ALL DIRECT                   15420       682   103  1337   5251    4.4%
```

There is no `direct — ci` row, and that is not because CI is clean. No
repository in the fleet installed an *auditable package* from a workflow `run:`
step, and the things CI does pull in — actions, images — are not in OSV under
any PURL. That surface is covered further down, where the metric is not a CVE
count.

Across the fleet, **4.4% of directly-declared packages carry at least one
advisory, against 1.3% of inherited ones.**

That is the opposite of the usual story, and it needs an honest caveat
immediately: **this is a statement about advisory coverage, not about safety.**
Direct dependencies skew toward the top-level frameworks and tooling that
security researchers actually audit — React, Next.js, LangChain, `cryptography`,
`pillow`. The 214,442 inherited packages are mostly tiny leaf libraries nobody
has ever filed a CVE against. A low rate down there means less attention, not
less risk.

What the rate *does* establish is that the directly-declared surface is not the
safe part. It is small, it is yours, and proportionally it is where the known
problems are.

And it is small:

```
median declared packages per repository       53
median inherited packages per repository    1132
total declared / total inherited      15,424 / 214,442
```

**14× leverage at the median.** `Snailclimb/JavaGuide` declares 14 packages and
inherits 2,818 — 201×. `tauri-apps/tauri`: 30 declared, 2,327 inherited.

So the two populations are genuinely different work:

- **15,424 packages you can fix by editing a line.** 103 criticals live here.
- **214,442 packages you cannot.** 240 criticals live here.

Twice the criticals, fourteen times the packages, none of them yours to bump.

### Directly at risk

The repositories whose *own files* name a flawed package, worst first:

```
repo                              declared affected    rate  crit  high  mal  grade
janhq/jan                              212        9    4.2%     3    18    1      F
vercel/next.js                        1247       90    7.2%    28   207    0      F
Shubhamsaboo/awesome-llm-apps          617       76   12.3%    15   232    0      F
microsoft/qlib                          60       16   26.7%    10   124    0      F
supabase/supabase                      572       13    2.3%     6    63    0      D
run-llama/llama_index                  719       57    7.9%     4    93    0      D
shadcn-ui/ui                           301       11    3.7%     4    45    0      D
ollama/ollama                           68       10   14.7%     3     5    0      D
google-gemini/gemini-cli               188       12    6.4%     3    24    0      D
```

**83 of 163 repositories have at least one directly-named flawed package.**

`microsoft/qlib` is the sharpest case: 60 declared dependencies, 16 of them
carrying an advisory — **a 26.7% hit rate on a surface small enough to audit in
an afternoon.**

### Indirectly at risk

```
repo                             inherited affected    rate  crit  high  grade
vercel/next.js                        6669      310    4.6%    48   456      F
run-llama/llama_index                 2351      166    7.1%    31   371      D
react/react                           4077      147    3.6%    21   126      F
Shubhamsaboo/awesome-llm-apps         4880      198    4.1%    10   257      F
freeCodeCamp/freeCodeCamp             3282       71    2.2%    10    88      D
Mintplex-Labs/anything-llm            3391       51    1.5%     9    79      F
excalidraw/excalidraw                 3499       42    1.2%     9    46      F
```

Same repositories, mostly — but a different intervention. `next.js` has 28
criticals it can fix and 48 it can only wait on. Reported as one number, "76
criticals" tells a maintainer nothing about how to spend the morning.

## Malicious packages: two, and the reach split is the whole point

```
janhq/jan     MAL-2025-21003  npm/fs@0.0.1-security      DIRECT (manifest)
react/react   MAL-2023-462    npm/fsevents@1.0.17        inherited
react/react   MAL-2023-462    npm/fsevents@1.1.2         inherited
```

`jan` names `fs` in its own manifest — the npm placeholder squatting a core
module name. That is a line in a file, fixable today. React's two are old
`fsevents` versions arriving transitively. Identical severity class, completely
different response. This is exactly the distinction that gets lost when
everything is sorted by CVSS.

## The surfaces no package scanner looks at

Here is where the ordinary tooling simply has nothing to say.

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
`node:20-slim`, `debian:bookworm-slim`. Rebuild tomorrow and you may get
different bytes with no commit anywhere in your history.

58% of third-party CI actions are on a moving ref too. **81% of repositories
carry at least one moving first-party reference.** These actions run with your
build credentials.

For these surfaces the risk metric is not a CVE count — it is *can this move
under you*. Which brings us to the thing I did not expect to find.

### The advisory that exists and no scanner will match

`tj-actions/changed-files` — the single most-cited CI supply-chain compromise —
**has an advisory in OSV**, and every PURL-keyed scanner reports repositories
using it as clean. Verified against the live API:

```
{"purl":"pkg:github/tj-actions/changed-files@45.0.7"}          -> {}
{"purl":"pkg:githubactions/tj-actions/changed-files@45.0.7"}   -> {}
{"name":"...","ecosystem":"GitHub Actions","version":"45.0.7"} -> {}
{"name":"...","ecosystem":"GitHub Actions"}
                        -> GHSA-mcph-m25j-8j63, GHSA-mrrh-fwg8-r2c3
```

The records carry a **null purl**, and state their ranges in a versioning that
refs (`v45`, a SHA) do not follow. Only the version-less ecosystem+name query
returns anything. Package URL is the identifier every modern scanner is built
on, and for this entire ecosystem it reaches nothing.

Once `deepdep` asks the question the right way:

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

**60% of the fleet invokes a CI action with a published advisory.**
`tj-actions/changed-files` is still in use in 8 of these repositories, **6 of
them on a moving ref**, well over a year after the compromise.

One honest limit, stated in the tool's own output: because OSV only answers
without a version, this says *the action has an advisory*, not *your ref is
inside its range*. `deepdep` keeps these in a separate type from version-matched
findings and excludes them from the grade, because an unverified ref must not
move a number. It is still the difference between a scanner that said nothing
about tj-actions and one that says go and look.

### Dockerfiles: the highest hit rate in the fleet

334 OS and language packages installed from `RUN` lines, **19.5% of them
carrying an advisory** — the worst rate of any surface. Mostly low-severity
Debian and Alpine noise, and zero criticals once a bug of mine was fixed (below).
But these packages appear in no lockfile, no manifest, and no SBOM produced by a
package-manager scanner. `rust-lang/rust` installs 17 of them; `vllm` 46;
`pytorch` 19.

## Hygiene, and what CI actually runs

```
floating   93,953  42%     no exact constraint holds this version
locked     66,676  30%
pinned     61,546  28%
```

**42% of all resolved versions across the fleet are floating** — a rebuild can
move them with no line changing in the repository. 26 repositories are over 75%
floating; exactly one is fully held.

And the controls:

```
control                   repos running it   share
dependency-updates                      84     57%
static-analysis                          45     31%
ci-hardening                             18     12%
dependency-scanning                      17     12%
signing                                   7      5%
sbom                                      6      4%
secret-scanning                           6      4%
container-scanning                        3      2%
iac-scanning                              0      0%

running NO detected control at all: 64  (44%)
```

Of 147 repositories whose CI is readable, **44% run no detected security control
at all**, and **only 12% run dependency scanning**. Six produce an SBOM. Three
scan containers — while 50% of the fleet ships a Dockerfile and 90% of base
images float on a tag.

Dependabot is the exception, at 57%. The most-adopted control by a wide margin
is the one GitHub turns on with a single file.

## The three populations

```
                        repos  scannable  graded  lockfile  any ctl  dep scan  med decl  med inh
top 100 active             97        79%      75       54%      56%        6%        48      605
top 50 fast-growing        50        82%      41       62%      47%       19%        25      912
top 50 AI, in use          49        96%      47       59%      71%      10%        134     1745
```

```
                        dir aff  dir rate  ind aff  ind rate  dir crit  ind crit  action adv
top 100 active              415      4.6%     1685      1.5%        74       153         140
top 50 fast-growing          59      2.4%      407      0.7%         4        25          61
top 50 AI, in use           310      4.3%     1020      1.3%        36        88         129
```

**AI projects carry roughly three times the dependency surface of the general
population** — median 134 declared and 1,745 inherited, against 48 and 605.
They also run more CI controls (71% have at least one). Both make sense: these
are large, well-funded, fast-moving Python and TypeScript systems.

The AI list, ranked by what it inherits:

```
repo                            declared  inherited  dir aff  ind aff  crit  high  grade
janhq/jan                            212       4177        9       37     8    48      F
langflow-ai/langflow                 444       4114        5       24     3    25      C
mem0ai/mem0                          260       3950        3       36     5    48      D
Significant-Gravitas/AutoGPT         157       3573        2       55     6    64      D
Mintplex-Labs/anything-llm           177       3391       16       51     9    94      F
infiniflow/ragflow                   348       3370       14       67     2    94      D
apache/airflow                       708       3323        3       27     0    44      C
run-llama/llama_index                719       2351       57      166    35   464      D
langchain-ai/langchain                98        605        1        2     1     0      B
```

`llama_index` is the outlier that matters: **719 declared dependencies, 57 of
them flawed, 35 criticals in the closure.** `langchain` — the comparable project
— declares 98 and grades B. Same problem space, an order of magnitude apart in
declared surface, and the grades follow.

The fast-growing list is the quiet good news: lowest direct rate (2.4%), fewest
criticals, highest dependency-scanning adoption (19%). New code has had less
time to rot, and new projects are being started with Dependabot on.

## Four bugs this run found in the tool

I would not publish the numbers above without this section, because three of
these bugs would have made the article wrong.

**1. npm hoisting made every transitive package look declared.** npm hoists
nearly everything to the top of `node_modules`, and the lockfile merge attaches
top-level entries to the repository root. `axios` read as 122 direct
dependencies against the ~60 its manifests declare — and a hoisted
sub-sub-dependency's CVE was being reported as the maintainer's own line to fix.
That is precisely the confusion the split exists to remove. Placements carry no
version range and declarations always do, so that absence now decides.

**2. Every grade was suppressed by a coverage bug.** Coverage is meant to
measure what could not be *read*. It was also counting frontiers the walk
stopped at on purpose — a dependency's own devDependencies, an unrequested
Python extra, things nothing installs. `axios` read as 44% auditable, below the
grading threshold, when its closure is complete for everything that installs.
**All 163 repositories came back ungraded.** With the denominator corrected,
axios reads 99% and 134 repositories grade.

**3. A fired timeout threw away the answer it promised to keep.** The tool
documents that `--timeout` emits the partial closure with its frontier marked.
One context spanning the whole run broke that in the worst place: the walker
stopped correctly, then the database write inherited the expired deadline and
discarded everything. The failure was size-correlated — `freeCodeCamp`,
`angular`, `deno` reported as total failures while holding good partial answers.

**4. `RUN npm install -g pkg@latest` minted `latest` as a version.** OSV cannot
order that token against any range, so it answered with every npm advisory ever
filed: an image whose npm is current was reported as carrying CVE-2013-4116,
from 2013. **52 findings across the fleet rested on versions that do not
exist**, six of them CRITICAL, and they landed almost entirely on the Dockerfile
surface — inflating the exact number that surface exists to report. Before the
fix that row read 6 critical and 67 high; it now reads 0 and 32.

A fleet is a very good bug detector. Three of these four are the kind that
produce *confident wrong answers* rather than crashes, which is the class that
matters most in a security tool.

## What I'd take from this

**Sort by who can fix it before you sort by severity.** The directly-declared
surface is 7% of the packages and holds 30% of the criticals. It is also the
only part anyone can act on this week. Every scanner I know of buries it in the
same list as the 214,442 packages you inherited.

**Your CI and your Dockerfile are dependencies.** 90% of base images and 58% of
CI actions across the top of GitHub float on a movable tag, 60% of repositories
invoke an action with a published advisory, and almost nothing in the standard
tooling looks at either. Package URL — the identifier the whole ecosystem is
built on — does not reach GitHub Actions advisories at all.

**Coverage claims deserve as much scepticism as findings.** 27 of the top 163
repositories on GitHub resolved zero packages. A scanner that reports those as
clean is not wrong about any individual package; it is wrong about what it
looked at. Ask any tool what it *could not* read before you believe what it
found.

---

*Reproduce: `analysis/lists.sh && analysis/lists-ai.sh` to refetch the lists
(they will drift — the frozen copies used here are in `analysis/`), then
`analysis/run.sh <repo>` per repository and `analysis/finish.sh`. Aggregation is
`analysis/aggregate.py` and `analysis/tables.py`; every table above is in
[`analysis/tables.frozen.txt`](../analysis/tables.frozen.txt). deepdep never
executes analysed code — resolution is registry-API only.*

# Grading the ref surface

## The question

> `terraform-azure-mcaf-virtualmachine  not graded  (0 packages, 6 actions)` —
> since all actions are pinned, should that not be graded A?

## What was actually happening

Coverage counted only package nodes. CI actions were in neither the numerator
nor the denominator, so a repository whose entire supply chain is six actions
had a coverage of `0/0` and was told it was too sparse to grade — having in fact
been read completely.

The Terraform repositories hit a sharper version of the same wall. They are not
`0/0` but `0/N`:

    checked         0
    package_nodes   3     azurerm (declared), random (declared), terraform-cli (declared)
    actions_checked 6
    auditable       0.0

There is no Terraform provider resolver, so a declared provider could enter the
auditable DENOMINATOR and never the numerator. Every Terraform repository was
structurally ungradable.

**36 of 208 stored runs (17%) have actions and no packages at all.** For those,
the ref surface is not a side-channel; it is the whole supply chain.

## Why "all pinned" is not by itself an A

A fixture with six SHA-pinned actions surfaced this:

    2c. CI ACTIONS WITH PUBLISHED ADVISORIES  (1 of 6 invoked)
       HIGH  CVE-2025-24362  github/codeql-action  ref 4dd16135b6…

Pinned to a SHA, and pinned to a vulnerable one. Pinning buys reproducibility,
not safety — it is what makes the version knowable, and therefore what made the
advisory findable at all.

Two consequences shaped the design:

1. **Fixing coverage alone would have been worse than the bug.** Actions never
   reach `version_rollup`, so `pins` has no action entries and hygiene scored
   `0 of 1 versions` whether the refs were `@sha` or `@main`. Made gradable
   without that, an all-`@main` repository and an all-`@sha` one would receive
   the same letter — blind to the exact property the question was about.

2. **Action advisories had to become scoreable.** They were excluded on the
   stated rule that "an unverified ref must not move a grade". That rule was
   right about the strength of the claim and wrong about the consequence: for a
   repository with no packages, excluding refs leaves nothing to grade, so one
   carrying a HIGH scored identically to one carrying none.

## The design

### Coverage spans the whole gradable surface

    Auditable = (package targets + action nodes) / (package nodes + action nodes)

`ActionTargets` returns every `pkg:github/%` node and OSV answers for an action
by name, so naming one is all that auditing one requires. The ref surface is
therefore always 100% covered, which means this change can only ever RAISE
coverage — **no repository can lose its grade to the coverage gate.**

That claim is about the gate, not about letters. The vulnerability and hygiene
changes move scores in both directions, and a previously-graded repository can
move between letters. (Verified across all 208 stored runs: `pkg:github/%` and
`graph.IsAction` select the same set, so the two halves of the ratio cannot
drift apart.)

### Action advisories score at a discount

`score.ActionClaimWeight = 0.5` — the share of the vulnerability budget the ref
surface may ever reach. OSV answers an action query by name — "this action has a
published advisory" — never "the ref you pinned is affected". Discounted and
visible beats absent; full weight would silently upgrade a claim the report is
careful to keep weak.

**It scales points, not the finding count.** The first implementation weighted
the count, which put the factor inside the density's square root — where a
weight delivers its own square root. A stated half arrived as 0.845, and the
first fixture run printed `+38 / 45` and a D. The ordering-only test passed
against that: it confirmed *some* discount and could not tell the intended one
from a nullified one, which is why the test now asserts the ratio.

The two surfaces are also scored on separate curves rather than pooled into one
density. Pooling diluted package findings — 3 findings in 100 packages became 3
in 117 the moment a workflow file appeared.

The irony is worth stating: an action pinned to a TAG could be version-matched,
and one pinned to a SHA — the better practice — cannot.

### Refs count for hygiene

`uses: actions/checkout@main` is the purest form of what that term measures: the
next run can execute different code with nothing in the repository having
changed.

### `Checked` stays packages-only

It is also the denominator of the POSTURE term, which comes from Scorecard
records that exist only for packages. Folding 17 actions into it would dilute
that term for every repository that has both surfaces. The ref counts are
separate fields; only the vulnerability term reads both.

### An exact constraint needs no resolver

`version.ExactVersion` is an optional scheme capability: `IsExact` already says a
constraint admits one version, and `Exact` says which. The walker's no-resolver
branch uses it to record a resolved LEAF rather than a frontier — the version is
known, its dependencies are not, and those are different claims.

The version is read back out of the SCHEME, never parsed in the walker. `= 3.5.1`,
`==3.5.1` and `3.5.1` are three ecosystems' ways of writing one pin; the walker
learning which is which is the same mistake as synthesising a constraint string
to apply a lockfile pin.

### Two suppressions, two sentences

Nothing-to-grade and too-little-read had printed the same reason. A repository
with no dependencies was told 0% of its packages were auditable, which reads as
our failure to read it rather than as an accurate description of an empty supply
chain.

## Measured effect

| | before | after |
|---|---|---|
| `terraform-aws-mcaf-transfer` | not graded, 25% of 4 | **C (36)**, 91% of 22 |
| six-pinned-action fixture | not graded, 0% of 3 | **C (40)**, 67% of 9 |

The transfer repository's C is 18 hygiene points for 18 of 20 refs moving — the
discrimination the question asked for, and previously unreachable. The fixture's
is 18 for controls plus 22 for the discounted HIGH: exactly half of the 45 that
same finding would score version-matched.

## Known limitation: the density curve is steep on small surfaces

The vulnerability term is a severity-weighted density saturating at 0.35, tuned
when only large repositories were gradable. A single HIGH among six dependencies
saturates the curve; the same finding among 100 packages scores 13.

This is the existing model behaving as designed — proportional exposure — now
visible because small surfaces are gradable for the first time. Flagged rather
than tuned: changing `SaturationDensity` would move every grade in the fleet,
which is a different decision from this one.

## Out of scope

- **A Terraform provider resolver.** The exact-constraint path covers pins only;
  `~> 6.0` remains an unresolvable frontier in the denominator, so a repository
  with seven or more ranged providers and six actions would still suppress.
- **Renaming the "actions" surface.** Pre-commit hooks share the
  `pkg:github/owner/repo@ref` identity and are counted with actions throughout —
  correctly, since they are the same kind of thing — but the report calls the
  section "CI ACTIONS", which now under-describes a grade-bearing surface.

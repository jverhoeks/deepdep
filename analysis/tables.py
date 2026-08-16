#!/usr/bin/env python3
"""Every table the write-up cites, printed with its denominator.

Nothing here re-derives a finding. It counts what the tool already reported, so
any row can be checked by opening one out/reports/<slug>.json.
"""
import json, os
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
AGG = json.load(open(f"{ROOT}/out/aggregate.json"))
R = AGG["repos"]
SURFACES = ["manifest", "ci", "dockerfile"]


def pct(a, b):
    return f"{100*a/b:.0f}%" if b else "-"


def rate(a, b):
    return f"{100*a/b:.1f}%" if b else "-"


def h(t):
    print(f"\n{'='*78}\n{t}\n{'='*78}")


def sub(lst):
    return [r for r in R if lst in r["lists"]]


def med(v):
    v = sorted(v)
    return v[len(v) // 2] if v else 0


def direct(r, field):
    return sum(r["exposure"].get(s, {}).get(field, 0) for s in SURFACES)


# ------------------------------------------------------------------ funnel
h("T1  FUNNEL — how far a scanner gets on the top of GitHub")


def recognised(r):
    db = r.get("db") or {}
    return bool(db.get("build_files")) or r["checked"] > 0 or bool(r["controls"])


print(f"{'':46} {'all':>5} {'active':>7} {'growing':>8}")
for label, pred in [
    ("repositories scanned", lambda r: True),
    ("  had a build file or manifest we could read", recognised),
    ("  resolved at least one package version", lambda r: r["checked"] > 0),
    ("  >=50% of package nodes auditable", lambda r: not r["suppressed"]),
    ("  gradeable AND graded", lambda r: bool(r["grade"])),
]:
    print(f"{label:46} {sum(1 for r in R if pred(r)):>5} "
          f"{sum(1 for r in sub('active') if pred(r)):>7} "
          f"{sum(1 for r in sub('growing') if pred(r)):>8}")

print(f"\nscan or report failed: {len(AGG['failed'])}")
for f in AGG["failed"]:
    print(f"    {f['repo']} ({f['stage']})")
nothing = [r["repo"] for r in R if not recognised(r)]
print(f"\nrecognised nothing at all ({len(nothing)}) — curated lists, books, prompt")
print("collections, and projects whose build system we do not read:")
for n in nothing:
    print(f"    {n}")

# ------------------------------------------------------------------ grades
h("T2  GRADE — of the repositories with enough coverage to grade")
g = Counter(r["grade"] for r in R if r["grade"])
for k in "ABCDF":
    if g[k]:
        names = [r["repo"] for r in R if r["grade"] == k]
        print(f"  {k}  {g[k]:>3}   {', '.join(names[:6])}{' ...' if len(names) > 6 else ''}")
print(f"  total graded: {sum(g.values())} of {len(R)}")
sup = Counter("no packages resolved at all" if r["checked"] == 0 else "coverage below 50%"
              for r in R if r["suppressed"])
for k, v in sup.items():
    print(f"  not graded — {k}: {v}")

# ------------------------------------------------------------------- reach
h("T3  REACH — every advisory in the fleet, by who can fix it")
tot, hit = defaultdict(Counter), defaultdict(set)
for r in R:
    for key, e in r["exposure"].items():
        for f in ("checked", "affected", "malicious", "critical", "high", "other"):
            tot[key][f] += e[f]
        if e["affected"]:
            hit[key].add(r["repo"])
print(f"{'surface':24} {'packages':>9} {'affected':>9} {'crit':>5} {'high':>5} "
      f"{'other':>6} {'rate':>7} {'repos hit':>10}")
for key in SURFACES + ["indirect"]:
    t = tot[key]
    if not t["checked"] and not t["affected"]:
        continue
    label = "inherited (transitive)" if key == "indirect" else f"direct — {key}"
    print(f"{label:24} {t['checked']:>9} {t['affected']:>9} {t['critical']:>5} "
          f"{t['high']:>5} {t['other']:>6} {rate(t['affected'], t['checked']):>7} {len(hit[key]):>10}")
d = {f: sum(tot[k][f] for k in SURFACES) for f in
     ("checked", "affected", "critical", "high", "other", "malicious")}
print(f"{'ALL DIRECT':24} {d['checked']:>9} {d['affected']:>9} {d['critical']:>5} "
      f"{d['high']:>5} {d['other']:>6} {rate(d['affected'], d['checked']):>7}")

# ---------------------------------------------------------------- leverage
h("T3b LEVERAGE — how many packages one declared line brings with it")
pairs = [(direct(r, "checked"), r["exposure"].get("indirect", {}).get("checked", 0), r)
         for r in R]
pairs = [p for p in pairs if p[0] + p[1] > 0]
pairs.sort(key=lambda p: -(p[1] / p[0] if p[0] else 0))
print(f"  repositories with any resolved package  {len(pairs):>7}")
print(f"  median declared packages per repo       {med([d for d, _, _ in pairs]):>7}")
print(f"  median inherited packages per repo      {med([i for _, i, _ in pairs]):>7}")
print(f"  total declared / total inherited        {sum(d for d,_,_ in pairs)} / {sum(i for _,i,_ in pairs)}")
print(f"\n  highest multiplier — inherited per declared package:")
print(f"{'repo':40} {'declared':>9} {'inherited':>10} {'x':>7}")
for dd, i, r in pairs[:12]:
    print(f"{r['repo']:40} {dd:>9} {i:>10} {(i/dd if dd else 0):>6.0f}x")

# ------------------------------------------------------- direct risk ranked
h("T4  DIRECTLY AT RISK — the repository's own files name a flawed package")
rows = [(direct(r, "affected"), direct(r, "checked"), direct(r, "critical"),
         direct(r, "high"), direct(r, "malicious"), r) for r in R]
rows = [x for x in rows if x[0]]
rows.sort(key=lambda x: (-x[4], -x[2], -(x[0] / x[1] if x[1] else 0)))
print(f"{'repo':40} {'declared':>9} {'affected':>8} {'rate':>7} {'crit':>5} "
      f"{'high':>5} {'mal':>4} {'grade':>6}")
for da, dc, dcrit, dhigh, dmal, r in rows[:30]:
    print(f"{r['repo']:40} {dc:>9} {da:>8} {rate(da,dc):>7} {dcrit:>5} {dhigh:>5} "
          f"{dmal:>4} {(r['grade'] or '-'):>6}")
print(f"\nrepositories with >=1 directly-named flawed package: {len(rows)} of {len(R)}")

# ----------------------------------------------------- indirect risk ranked
h("T5  INDIRECTLY AT RISK — inherited, and nobody here can fix it directly")
rows = [(e["critical"], e["high"], e, r) for r in R
        if (e := r["exposure"].get("indirect")) and e["affected"]]
rows.sort(key=lambda x: (-x[0], -x[1]))
print(f"{'repo':40} {'inherited':>10} {'affected':>8} {'rate':>7} {'crit':>5} {'high':>5} {'grade':>6}")
for c, hi, e, r in rows[:25]:
    print(f"{r['repo']:40} {e['checked']:>10} {e['affected']:>8} "
          f"{rate(e['affected'],e['checked']):>7} {c:>5} {hi:>5} {(r['grade'] or '-'):>6}")

# ------------------------------------------- surfaces a manifest scan misses
h("T6  BEYOND THE MANIFEST — supply chain a package-manager scanner never sees")
a_t = a_u = i_t = i_u = 0
r_unp = r_dock = r_ci = opaque = 0
for r in R:
    db = r.get("db") or {}
    a, i = db.get("actions", {}), db.get("images", {})
    a_t += a.get("total", 0); a_u += a.get("unpinned", 0)
    i_t += i.get("total", 0); i_u += i.get("unpinned", 0)
    if a.get("unpinned") or i.get("unpinned"):
        r_unp += 1
    bf = db.get("build_files", {})
    if bf.get("dockerfile"):
        r_dock += 1
    if bf.get("workflow") or bf.get("gitlab-ci"):
        r_ci += 1
    opaque += db.get("opaque", 0)
print(f"  repositories with CI workflows read          {r_ci:>6}   {pct(r_ci, len(R))}")
print(f"  repositories with a Dockerfile read          {r_dock:>6}   {pct(r_dock, len(R))}")
print(f"  third-party CI actions invoked               {a_t:>6}")
print(f"    of those, on a MOVING tag                  {a_u:>6}   {pct(a_u, a_t)}")
print(f"  container base images referenced             {i_t:>6}")
print(f"    of those, on a MOVING tag                  {i_u:>6}   {pct(i_u, i_t)}")
print(f"  repositories with >=1 moving first-party ref {r_unp:>6}   {pct(r_unp, len(R))}")
print(f"  statically undecidable build steps           {opaque:>6}")
print("\n  A moving ref is the risk metric here, not a CVE count: OSV answers")
print("  nothing at all for pkg:oci/*, and answers for CI actions only through a")
print("  version-less ecosystem+name query — see T6b.")

h("T6b CI ACTIONS WITH PUBLISHED ADVISORIES  (the query no PURL reaches)")
tot_actions = sum(r.get("actions_checked", 0) for r in R)
hits = [(r, r.get("action_advisories") or []) for r in R]
hits = [(r, a) for r, a in hits if a]
print(f"  action nodes queried across the fleet   {tot_actions:>6}")
print(f"  repositories invoking a flagged action  {len(hits):>6}   {pct(len(hits), len(R))}")
byact, moving = Counter(), Counter()
for r, adv in hits:
    for a in adv:
        byact[a["action"]] += 1
        ref = a.get("ref") or ""
        if not (len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)):
            moving[a["action"]] += 1
print(f"\n{'action':40} {'repos':>6} {'on a moving ref':>16}")
for name, n in byact.most_common(15):
    print(f"{name:40} {n:>6} {moving[name]:>16}")
print("\n  NOT version-matched: OSV answers for actions only without a version, so")
print("  these say the action has an advisory, not that the ref is inside it.")

# ----------------------------------------------------------------- hygiene
h("T7  HYGIENE — what a rebuild can change without a line changing here")
tot = Counter()
for r in R:
    for k, v in ((r.get("db") or {}).get("pinning") or {}).items():
        tot[k] += v
allv = sum(tot.values())
for k in ("floating", "locked", "pinned"):
    print(f"  {k:10} {tot[k]:>8}  {pct(tot[k], allv)}")
band = Counter()
for r in R:
    p = (r.get("db") or {}).get("pinning") or {}
    n = sum(p.values())
    if n < 10:
        continue
    f = p.get("floating", 0) / n
    band["100% floating" if f == 1 else ">75% floating" if f > .75 else
         ">25% floating" if f > .25 else "mostly held" if f > 0 else "fully held"] += 1
print("\n  repositories (>=10 versions) by floating share:")
for k in ("100% floating", ">75% floating", ">25% floating", "mostly held", "fully held"):
    if band[k]:
        print(f"    {k:16} {band[k]:>4}")

# ---------------------------------------------------------------- controls
h("T8  CONTROLS — what the top of GitHub actually runs in CI")
assessable = [r for r in R if r["controls_assessable"]]
have = Counter(c for r in assessable for c in r["controls"])
kinds = sorted(set(list(have) + [k for r in assessable for k in r["controls_missing"]]))
print(f"  assessable repositories (CI we can read): {len(assessable)} of {len(R)}")
print(f"\n{'control':24} {'repos running it':>17} {'share':>7}")
for k in sorted(kinds, key=lambda k: -have[k]):
    print(f"{k:24} {have[k]:>17} {pct(have[k], len(assessable)):>7}")
none = sum(1 for r in assessable if not r["controls"])
print(f"\n  running NO detected control at all: {none}  ({pct(none, len(assessable))})")

# ----------------------------------------------------------------- posture
h("T9  UPSTREAM POSTURE — repo-specific signals across the fleet")
sig, sigrepos = Counter(), Counter()
for r in R:
    for k, v in r["repo_signals"].items():
        sig[k] += v
        sigrepos[k] += 1
print(f"{'signal':28} {'package versions':>17} {'repos':>7}")
for k, v in sig.most_common():
    print(f"{k:28} {v:>17} {sigrepos[k]:>7}")

# --------------------------------------------------------------- malicious
h("T10 MALICIOUS PACKAGES")
mal = [(r["repo"], r["malicious_ids"]) for r in R if r["malicious"]]
if not mal:
    print("  none. Source: OSV MAL- feed (OpenSSF malicious-packages).")
for repo, ids in mal:
    print(f"  {repo}: {ids}")

# ------------------------------------------------------- active vs growing
h("T11 THE THREE POPULATIONS")
print(f"{'':22} {'repos':>6} {'scannable':>10} {'graded':>7} {'lockfile':>9} {'any ctl':>8} "
      f"{'dep scan':>9} {'med decl':>9} {'med inh':>8}")
for rows, label in ((sub("active"), "top 100 active"),
                    (sub("growing"), "top 50 fast-growing"),
                    (sub("ai"), "top 50 AI, in use")):
    n = len(rows)
    scannable = [r for r in rows if r["checked"] > 0]
    lock = [r for r in rows if ((r.get("db") or {}).get("pinning") or {}).get("locked", 0) > 0]
    ci = [r for r in rows if r["controls_assessable"]]
    print(f"{label:22} {n:>6} {pct(len(scannable), n):>10} {sum(1 for r in rows if r['grade']):>7} "
          f"{pct(len(lock), n):>9} {pct(sum(1 for r in ci if r['controls']), len(ci)):>8} "
          f"{pct(sum(1 for r in ci if 'dependency-scanning' in r['controls']), len(ci)):>9} "
          f"{med([direct(r,'checked') for r in scannable]):>9} "
          f"{med([r['exposure'].get('indirect',{}).get('checked',0) for r in scannable]):>8}")

print(f"\n{'':22} {'dir aff':>8} {'dir rate':>9} {'ind aff':>8} {'ind rate':>9} "
      f"{'dir crit':>9} {'ind crit':>9} {'action adv':>11}")
for rows, label in ((sub("active"), "top 100 active"),
                    (sub("growing"), "top 50 fast-growing"),
                    (sub("ai"), "top 50 AI, in use")):
    dc = sum(direct(r, "checked") for r in rows)
    da = sum(direct(r, "affected") for r in rows)
    ic = sum(r["exposure"].get("indirect", {}).get("checked", 0) for r in rows)
    ia = sum(r["exposure"].get("indirect", {}).get("affected", 0) for r in rows)
    print(f"{label:22} {da:>8} {rate(da,dc):>9} {ia:>8} {rate(ia,ic):>9} "
          f"{sum(direct(r,'critical') for r in rows):>9} "
          f"{sum(r['exposure'].get('indirect',{}).get('critical',0) for r in rows):>9} "
          f"{sum(len(r.get('action_advisories') or []) for r in rows):>11}")

h("T11b THE AI LIST, RANKED BY WHAT IT DECLARES AND INHERITS")
ai = [r for r in sub("ai") if r["checked"] > 0]
ai.sort(key=lambda r: -(r["exposure"].get("indirect", {}).get("checked", 0)))
print(f"{'repo':34} {'declared':>9} {'inherited':>10} {'dir aff':>8} {'ind aff':>8} "
      f"{'crit':>5} {'high':>5} {'grade':>6}")
for r in ai[:30]:
    ind = r["exposure"].get("indirect", {})
    print(f"{r['repo']:34} {direct(r,'checked'):>9} {ind.get('checked',0):>10} "
          f"{direct(r,'affected'):>8} {ind.get('affected',0):>8} "
          f"{r['sev'].get('CRITICAL',0):>5} {r['sev'].get('HIGH',0):>5} {(r['grade'] or '-'):>6}")

# ----------------------------------------------------------------- coverage
h("T12 COVERAGE FRONTIER — where the walk stopped")
cov, covrepos = Counter(), Counter()
for r in R:
    for k, v in r["coverage"].items():
        cov[k] += v
        covrepos[k] += 1
print(f"{'reason':24} {'nodes':>8} {'repos':>7}")
for k, v in cov.most_common():
    print(f"{k:24} {v:>8} {covrepos[k]:>7}")
bh = Counter(b for r in R for b in r["bounds_hit"])
print("\n  bounds that fired, by repository count:")
for k, v in bh.most_common():
    print(f"    {k:22} {v:>4}")

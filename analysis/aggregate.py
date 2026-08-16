#!/usr/bin/env python3
"""Fold the per-repository reports into one record per repository.

Reads three sources and keeps them separate on purpose:
  out/reports/<slug>.json  the tool's own layered report (findings, reach, score)
  out/scans/<slug>.json    the closure summary and which bounds fired
  out/db/<slug>.db         structural facts the report summarises but does not
                           list (pinning, ecosystem mix, moving refs)
"""
import glob, json, os, sqlite3, sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = f"{ROOT}/.out"


def load_lists():
    meta, member = {}, defaultdict(set)
    for name in ("active", "growing", "ai"):
        p = f"{OUT}/lists/{name}.json"
        if not os.path.exists(p):
            continue
        doc = json.load(open(p))
        for r in doc["repos"]:
            meta[r["full_name"]] = r
            member[r["full_name"]].add(name)
    return meta, member


def db_facts(path):
    """Structural facts straight out of the run store."""
    if not os.path.exists(path):
        return {}
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    q = lambda s, *a: con.execute(s, a).fetchall()
    try:
        run = q("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1")
        if not run:
            return {}
        rid = run[0][0]
        pins = dict(q("SELECT pinning, COUNT(*) FROM version_rollup WHERE run_id=? GROUP BY pinning", rid))
        ecos = dict(q("SELECT ecosystem, COUNT(*) FROM nodes WHERE run_id=? GROUP BY ecosystem", rid))

        # A build file's id carries its kind before the '@'.
        kinds = Counter()
        for (nid,) in q("SELECT id FROM nodes WHERE run_id=? AND id LIKE 'pkg:generic/buildfile/%'", rid):
            kinds[nid[len("pkg:generic/buildfile/"):].split("@")[0]] += 1

        # Refs whose risk is not a CVE count but whether they can move under you.
        # That is the tj-actions vector, and it is invisible to any scanner that
        # only reads manifests.
        def refs(prefix):
            total = q("SELECT COUNT(*) FROM nodes WHERE run_id=? AND id LIKE ?", rid, prefix + "%")[0][0]
            moving = q("SELECT COUNT(*) FROM nodes WHERE run_id=? AND id LIKE ? AND reason='unpinned-ref'",
                       rid, prefix + "%")[0][0]
            return {"total": total, "unpinned": moving}

        return {
            "pinning": pins, "ecosystems": ecos, "build_files": dict(kinds),
            "actions": refs("pkg:github/"), "images": refs("pkg:oci/"),
            "opaque": q("SELECT COUNT(*) FROM nodes WHERE run_id=? AND completeness='opaque'", rid)[0][0],
        }
    finally:
        con.close()


def main():
    meta, member = load_lists()
    # Sample-vs-product manifest counts, if measured. They decide whether
    # "declared" and "shipped" mean the same thing for a repository.
    mf = {}
    if os.path.exists(f"{OUT}/manifests.json"):
        mf = json.load(open(f"{OUT}/manifests.json"))
    rows, missing = [], []
    for repo in sorted(meta):
        s = repo.replace("/", "__")
        rp, sc = f"{OUT}/reports/{s}.json", f"{OUT}/scans/{s}.json"
        if not os.path.exists(rp):
            missing.append(repo)
            continue
        try:
            rep = json.load(open(rp))
            scan = json.load(open(sc)) if os.path.exists(sc) else {}
        except json.JSONDecodeError:
            # A report caught mid-write while the fleet is still running. Not a
            # result yet, so it counts as missing rather than as a zero.
            missing.append(repo)
            continue
        m = meta[repo]

        exposure = {}
        for e in rep.get("exposure", []):
            exposure[e["surface"] if e["reach"] == "direct" else "indirect"] = e
        terms = {t["name"]: t for t in rep.get("score", {}).get("terms", [])}

        rows.append({
            "repo": repo,
            "lists": sorted(member[repo]),
            "stars": m["stars"],
            "language": m["language"],
            "created_at": m["created_at"],
            "age_days": m.get("age_days"),
            "stars_per_day": m.get("stars_per_day"),
            "summary": scan.get("summary", {}),
            "bounds_hit": scan.get("bounds_hit", []),
            "checked": rep["checked"],
            "package_nodes": rep.get("package_nodes", 0),
            "auditable": rep.get("auditable_share", 0.0),
            "grade": rep["score"].get("grade", ""),
            "score": rep["score"].get("score", 0),
            "suppressed": rep["score"].get("suppressed", False),
            "terms": {k: {"points": v["points"], "detail": v["detail"]} for k, v in terms.items()},
            "malicious": len(rep.get("malicious") or []),
            "malicious_ids": [f["id"] + " " + f["package"] for f in (rep.get("malicious") or [])],
            "advisories": len(rep.get("advisories") or []),
            "sev": {c["name"]: c["versions"] for c in rep.get("advisories_by_severity", [])},
            "exposure": exposure,
            "direct_findings": [f for f in (rep.get("advisories") or []) + (rep.get("malicious") or [])
                                if f.get("surfaces")],
            "actions_checked": rep.get("actions_checked", 0),
            "action_advisories": [
                {"action": a["action"], "ref": a.get("ref", ""), "id": a["advisory"]["id"],
                 "severity": a["advisory"].get("severity") or "UNKNOWN"}
                for a in (rep.get("action_advisories") or [])],
            "controls": [c["kind"] for c in (rep.get("controls") or [])],
            "controls_missing": rep.get("controls_missing") or [],
            "controls_assessable": rep.get("controls_assessable", False),
            "repo_signals": {c["name"]: c["versions"] for c in (rep.get("repo_signals") or [])},
            "coverage": rep.get("coverage_frontier") or {},
            "manifests": mf.get(repo, {}).get("manifests", 0),
            "sample_manifests": mf.get(repo, {}).get("sample_manifests", 0),
            "db": db_facts(f"{OUT}/db/{s}.db"),
        })

    failed = []
    for f in glob.glob(f"{OUT}/logs/*.failed"):
        failed.append(json.load(open(f)))
    out = {"repos": rows, "missing": missing, "failed": failed}
    json.dump(out, open(f"{OUT}/aggregate.json", "w"), indent=1)
    print(f"aggregated {len(rows)} repos, {len(missing)} missing, {len(failed)} failed", file=sys.stderr)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Count each repository's manifests, and how many are samples rather than product.

The reach split says "this repository's own files name it", which is true and is
not the same as "this repository ships it". A monorepo carries example apps and
test fixtures that pin deliberately-old versions — vercel/next.js has 623
package.json files and 376 of them are under examples/ or tests/ — so a fixture
pinning next@13.4.2 for a regression test reads as the project declaring a
vulnerable Next.

Manifest edges are emitted straight to the repository root, so the graph cannot
say WHICH manifest declared a package (Dockerfiles and workflows can, because
they hang their findings off a file node). Until that is fixed, this counts the
manifests on disk so a claim about declared dependencies can be restricted to
the repositories where "declared" and "shipped" are the same thing.
"""
import glob, json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = f"{ROOT}/.out"

MANIFESTS = ("package.json", "pyproject.toml", "Cargo.toml", "go.mod", "pom.xml",
             "composer.json", "Gemfile", "build.gradle", "build.gradle.kts")
REQ = re.compile(r"^requirements.*\.txt$")
# Paths whose manifests describe a demo, a fixture or a benchmark rather than
# the artifact the project publishes.
SAMPLE = re.compile(r"(^|/)(examples?|samples?|demos?|tests?|__tests__|fixtures?|"
                    r"testdata|bench|benchmarks?|docs?|website|e2e|integration[-_]tests?|"
                    r"templates?|starters?|cookbook|tutorials?)(/|$)")


def is_manifest(name):
    return name in MANIFESTS or REQ.match(name)


def scan(clone):
    total = sample = 0
    for dirpath, dirnames, filenames in os.walk(clone):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "node_modules", "vendor", "target", "dist")]
        rel = os.path.relpath(dirpath, clone)
        for f in filenames:
            if not is_manifest(f):
                continue
            total += 1
            if SAMPLE.search(rel.replace(os.sep, "/")):
                sample += 1
    return total, sample


def main():
    origin = {}
    for clone in glob.glob(f"{OUT}/cache/repos/*/"):
        try:
            url = subprocess.run(["git", "-C", clone, "remote", "get-url", "origin"],
                                 capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:
            continue
        m = re.search(r"github\.com[/:]([^/]+/.+?)(?:\.git)?$", url)
        if m:
            origin[m.group(1)] = clone

    out = {}
    for repo, clone in sorted(origin.items()):
        total, sample = scan(clone)
        out[repo] = {"manifests": total, "sample_manifests": sample}
        print(f"{repo:44} {total:>5} manifests, {sample:>5} sample", file=sys.stderr)

    json.dump(out, open(f"{OUT}/manifests.json", "w"), indent=1)
    print(f"\n{len(out)} repositories measured", file=sys.stderr)


if __name__ == "__main__":
    main()

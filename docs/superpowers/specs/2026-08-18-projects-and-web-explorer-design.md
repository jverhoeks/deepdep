# Projects, and an explorer for them

## The question

> I can deepdep on a dir now I want to run the risk, but I can't find the run id?

They could not, and the tool was right not to help. `deepdep risk` defaults to
the newest run, so the immediate answer was "drop the argument". But the question
exposed something the store cannot currently answer at all.

## What was actually happening

A local scan records the basename of the directory and nothing else:

```go
// internal/source/local.go:54
repoName := filepath.Base(dir)
if abs, err := filepath.Abs(dir); err == nil {
    repoName = filepath.Base(abs)
}
```

`~/src/a/data-platform` and `~/work/b/data-platform` therefore land in the same
`runs.target`. The absolute path is computed and discarded; the git remote is
never read, even though `openLocal` already has the `*git.Repository` open.

This is not cosmetic. `alreadyScanned` and `latestRunFor`
(`cmd/deepdep/org_store.go`) both key on exact `r.Target`, so two identically
named local directories already collide in resume logic — the second is reported
as already scanned.

The store as it stands:

```
runs                    211
distinct targets        210
  remote (clone URL)    208 targets, 208 runs
  local  (basename)       2 targets,   3 runs
targets with >1 run       1     ← data-platform, which is what was asked about
```

Two runs, two minutes apart, same name, no way to tell them apart and no way to
get back to what was scanned. That is the actual complaint.

## Why a project is not a run

A run is an event: this tree, at this ref, resolved at this instant. It is
correct that there are 211 of them and that `newRunID` mixes in
`time.Now().UnixNano()` so re-scanning the same thing appends rather than
collides.

What is missing is the durable thing the runs are *about*. You do not want to
name an event; you want to name a repository and ask for its latest. So projects
are a new layer over runs, and — this matters — **not a redefinition of them.**

### Identity is the remote, paths are locations

A repository cloned to two directories is one project with two locations. The
canonical key strips the transport and the suffix:

```
git@github.com:o/r.git      ┐
https://github.com/o/r.git  ├─→  github.com/o/r
https://github.com/o/r      ┘
```

A directory with no remote has no such identity — `openLocal` returns early when
`git.PlainOpen` fails, and a non-git tree is still perfectly scannable. Those get
`kind='local'` and their absolute path as the key. Neither column can be the sole
identity, because either can be absent: a remote scan has no local path, and a
non-git directory has no remote.

### `runs.target` does not change

Setting `target` to the canonical remote would be the tidier schema and the wrong
change. `alreadyScanned` keys on it, so a local scan of a repository would
silently suppress the remote scan of that same repository during an org run — the
org summary would show a repository as scanned when what was actually read was
somebody's working copy at whatever ref it happened to be on. Runs keep their
existing target; they gain a nullable `project_num` beside it.

### The 2 local runs can never be adopted

For the 208 remote runs, `target` *is* the clone URL, so the migration can create
a project per distinct target and link them. For the 3 local runs the path was
never stored and is not recoverable. They keep working by run id and list as
`unclaimed`. Guessing a path from the basename would produce a registry that
points at directories nobody chose, which is worse than an honest gap.

## The design

### Schema v5

```sql
CREATE TABLE projects (
  num        INTEGER PRIMARY KEY AUTOINCREMENT,  -- the friendly id; never reused
  key        TEXT NOT NULL UNIQUE,   -- canonical remote, or abs path when kind='local'
  kind       TEXT NOT NULL CHECK (kind IN ('remote','local')),
  name       TEXT NOT NULL,          -- owner/repo, or directory basename
  created_at TEXT NOT NULL
);

CREATE TABLE project_paths (
  num        INTEGER NOT NULL REFERENCES projects(num) ON DELETE CASCADE,
  path       TEXT NOT NULL,          -- absolute
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (num, path)
);

ALTER TABLE runs ADD COLUMN project_num INTEGER REFERENCES projects(num) ON DELETE CASCADE;
```

`num` is an autoincrement integer rather than a hash because the complaint was
about human friendliness and `deepdep risk 3` is the friendliest thing that can
still be unambiguous. `AUTOINCREMENT` (not bare `INTEGER PRIMARY KEY`) so a
deleted project's number is never handed to a different project later.

Deleting a project cascades to its runs and on to `nodes`/`edges`/`instances`/
`package_rollup`/`version_rollup`. That chain works: `foreign_keys(1)` rides in
the DSN (`internal/store/store.go:59-64`), so it applies to every pooled
connection. Unclaimed runs have `project_num = NULL` and are unaffected by any
project deletion.

### `internal/project`

One new package, one job: `Canonical(remote string) (key, name string, ok bool)`,
table-driven over the SCP-like, HTTPS, and bare forms. It does not resolve
anything over the network and does not know what a forge is.

### The source layer stops discarding what it knows

`Source` gains one method:

```go
// Origin identifies the durable thing a run is about, as distinct from the
// tree that was read. Either field may be empty: a remote scan has no local
// path, a non-git directory has no remote.
type Origin struct {
    Kind   string // "remote" | "local"
    Remote string // raw remote URL, uncanonicalised
    Path   string // absolute path of the scanned directory
}

Origin() Origin
```

`localSource` fills both from facts it already has — `filepath.Abs(dir)` and the
`origin` remote from the already-open `*git.Repository`. `cloneSource` reports
the URL it was given and no path; the cache clone directory is deepdep's, not the
user's, and recording it as a location would invite someone to go edit it.
`staticSource` reports neither.

`WriteRun` upserts the project and the path before inserting the run, in the same
transaction, so a project never exists without the run that created it.

### Migration v4 → v5

Create the tables, add the column, then adopt: one project per distinct
remote-looking `target`, `kind='remote'`, `project_num` backfilled on every run
with that target. Local-looking targets are left alone. On this database that is
208 projects adopted and 3 runs unclaimed, and the migration must assert exactly
that shape in a test rather than merely not erroring.

## The commands

Flat verbs, matching `scan`/`history`/`audit`/`risk`/`report`/`org`/`tools`.

```
deepdep projects  [flags]            list every project
deepdep projects  <ref>              one project: its locations and its run history
deepdep clean     [flags]            prune runs, and optionally the projects themselves
deepdep report | risk | audit  [flags] [ref|run-id]
deepdep serve     [flags]            the explorer
```

```
$ deepdep projects
 NUM  NAME                                      RUNS  LAST SCAN     LOCATIONS
   1  github.com/schubergphilis-ep/…-mcaf-role      1  2026-08-17    —
   2  github.com/expressjs/express                  1  2026-08-16    —
 209  data-platform                                 2  2026-08-18    ~/src/data-platform
   —  (unclaimed)                                   3  2026-08-18    path not recorded
```

On this database that list is 209 rows long, because 208 of the projects come
from `org` scans — `WriteRun`'s upsert means `org` populates the registry as a
side effect, and it is by far the highest-volume producer of projects. Dumping
209 rows would recreate the friction this work exists to remove, so: sort by last
scan descending, `--limit 25` by default (matching `risk`'s existing default),
`--all` to override, and `--org <host/owner>` to filter by key prefix, which is
the cut that actually matters when one org scan supplied most of the table.

The list deliberately carries **no risk grade**. A grade is a function of
`known_at` and is not materialised anywhere — printing one here would mean
running a full report per project, and caching one would un-bitemporalise the
design the same way a stored advisory count would. `deepdep report <ref>` is one
keystroke away and is where a grade belongs.

### Resolving a `ref`

In order: a 16-hex string that matches a run id; an integer that matches
`projects.num`; an exact `projects.name`; a unique substring of a name or of a
recorded path. Ambiguity is an error that prints the candidates — never a guess,
because guessing which of two repositories to report on is the failure this whole
change exists to remove.

Existing invocations keep working: `deepdep report <run-id>` hits the first rule,
and `deepdep report` with no argument still means the newest run.

### `clean`

```
--project <ref>     limit to one project
--keep N            keep the newest N runs per project
--older-than D      delete runs created before now-D
--unclaimed         delete runs with no project
--purge             delete the project rows too, not just their runs
--vacuum            reclaim file space afterwards
--dry-run           print what would go, delete nothing
--yes               skip the confirmation prompt
```

`--keep N` is the form that matters. Every re-scan appends a run row forever, so
the useful question is "keep the newest few per project", not "delete this one".

Three safety properties, each of which gets a test:

**No flags is an error.** `deepdep clean` alone selects nothing and says so. A
cleanup command whose bare form deletes everything is a footgun with a countdown.

**The observation tables are never touched.** `advisories`, `advisory_affects`,
`finding_obs`, `packument_obs`, `depsdev_obs`, `scorecard_obs`, `ref_obs`,
`version_facts` are not run-scoped, and they are what make an old run
re-auditable — `scorecard_obs` in particular holds 47,557 rows that deps.dev
cannot serve again, because it serves only the current scorecard. `clean` prints
what it preserved, so the guarantee is visible rather than merely documented.

**It says what it will do first.** On a TTY, print the counts and confirm.
`--dry-run` prints and exits; `--yes` skips the prompt for CI.

`--vacuum` is opt-in and warned about: this database is 849MB, and VACUUM
rewrites the whole file.

## Advisories have to be persisted, and there is a cheap honest way

The explorer needs to colour a node by severity, offline, per view. The store
cannot answer that today:

```
advisories          0     ← declared in schema.sql; nothing in the codebase writes it
advisory_affects    0     ← same
version_facts       0
depsdev_obs    165,472
scorecard_obs   47,557
packument_obs   15,440
```

`report` and `audit` construct `advisory.New(*osvBase, nil)` and query OSV live
on every invocation (`cmd/deepdep/report.go:92`). The bitemporal substrate the
schema header describes was declared and never wired.

The obvious fix is the expensive one. Populating `advisory_affects` and deriving
findings from it means reimplementing OSV's version-range matching against
`events_json`, per ecosystem, with each ecosystem's own ordering rules. There is
a home for that — `internal/version` grew a `Dialect` seam in 877cda2 — but it is
a project in its own right and getting it subtly wrong produces confident wrong
answers.

So persist the **finding**, which is the match OSV already computed:

```sql
CREATE TABLE finding_obs (
  node_id     TEXT NOT NULL,
  osv_id      TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  source      TEXT NOT NULL,   -- 'osv-purl' | 'osv-action' | 'depsdev'
  PRIMARY KEY (node_id, osv_id, observed_at)
);
```

A row asserts: *at `observed_at`, OSV said this exact version is affected by this
advisory.* `audit`, `risk` and `report` write it, along with the advisory bodies
into `advisories` and the content-addressed blob store.

This keeps `known_at` a query parameter, which is the property `schema.sql` says
must not be given up:

```
findings observed at or before T
  where the advisory was published <= T
  and (withdrawn is null or withdrawn > T)
```

No count is materialised anywhere. `source` is recorded because a deps.dev
advisory id and an OSV version-matched hit are different strengths of claim, the
same distinction `report` already draws between `Advisory` and `ActionAdvisory`.

### The 165,472 rows already in the store

`depsdev_obs.advisory_ids` holds advisory ids for 165,472 purl observations. The
v5 migration harvests them into `finding_obs` with `source='depsdev'`, so the
explorer has data for the existing 208 projects on day one rather than only after
re-auditing all of them.

The caveat has to be stated where the UI will feel it: `advisories` is empty, so a
harvested row carries **no severity and no summary**. Such a node renders as
"carries a finding, severity unknown" — a third state alongside clean and
unaudited, not silently sorted into low. Severity arrives for that node the first
time an `audit` or `report` covers it and writes the advisory body.

**Deviation, recorded deliberately:** deepdep still cannot evaluate an advisory
range locally. It can only recall matches it was told about. A version never
audited has no findings, and the explorer must show that as *unknown*, not as
*clean* — the same distinction the README makes about files a scanner could not
read.

## The explorer

`deepdep serve [--addr 127.0.0.1:7777] [--db PATH] [--open] [--listen-any]`

### 17,996 nodes is the constraint

The newest run has 17,996 nodes. This repository has already answered this
question once, for the mermaid emitter: it "draws the SHAPE rather than the
graph" because "Mermaid stops being legible around a hundred". A select-and-
highlight force layout over 18k nodes is not a harder version of a good idea; it
is a different, worse idea.

**The default view is the risk subgraph:** every node carrying a finding, plus
the shortest path from each back to the root. For a clean repository that is a
root and its surfaces, which is the correct picture of a clean repository. From
there, clicking a node fetches its neighbourhood from SQLite. `idx_edges_in`
exists for the inbound direction already, which is the expensive one.

"Findings plus paths to root" is not self-bounding: *N* finding nodes in a deep
transitive graph can drag in many more intermediate nodes than *N*. So
`risk-graph` carries explicit caps, the way `emit.MermaidInput` already carries
`MaxFiles`/`MaxPerFile`:

```
MaxFindings  200   findings included, worst severity first
MaxNodes     600   total nodes after path expansion
MaxHops       12   path length before a path is elided to root --> node
```

When a cap bites, the response says so — `{"truncated": {"findings": 47,
"reason": "max_findings"}}` — and the UI renders the same kind of overflow marker
mermaid uses. A view that silently dropped findings would read as a cleaner
repository than the one that exists, which is the failure mode the README's
"what the tool could not read" section is entirely about. The caps are defaults,
overridable by query parameter.

The full graph is never shipped to the browser. There is no endpoint that would
let it be.

### API

Read-only JSON. There is no mutating route, so the browser cannot delete a
project or trigger a scan — `serve` is a viewer over a database that may hold an
entire organisation.

```
GET /api/projects
GET /api/projects/{num}                              locations + run history
GET /api/runs/{run}/overview                         the existing reportDoc, as-is
GET /api/runs/{run}/risk-graph?known_at=             findings + paths to root
GET /api/runs/{run}/nodes/{id}
GET /api/runs/{run}/nodes/{id}/neighbours?dir=in|out
```

`overview` reuses `reportDoc` (`cmd/deepdep/report.go:291`) rather than growing a
parallel shape. `report --format json` and the explorer must not be able to
disagree about a grade.

That reuse is not currently possible. `reportDoc`, `computeReach` and the
document assembly around them are in `package main`, and `internal/web` cannot
import `cmd/deepdep`. So this needs an extraction first: the assembly moves to
`internal/report`, and `cmd/deepdep/report.go` becomes a flag-parsing shell that
calls it and formats the result. The grading math is already out — that is
`internal/score` — so this is moving document construction, not logic. The same
question applies to `risk.go`'s posture assembly, which
`/api/runs/{run}/nodes/{id}` needs for its deps.dev panel; extract only what the
API actually consumes.

The extraction is a refactor with no behaviour change, so it is verifiable
independently: `report --format json` must produce byte-identical output before
and after, on a stored run.

Binds loopback. A non-loopback `--addr` is refused unless `--listen-any` is also
given, because the default database is one file containing 208 organisations'
worth of dependency and posture data.

### Front end

`internal/web` with `go:embed assets/*`. Vanilla JS and one vendored renderer,
committed to the repository, with a `assets/vendor/PROVENANCE` file recording
version, origin URL and sha256.

The renderer is **cytoscape.js** (MIT, single UMD file): selection,
neighbourhood traversal and style-by-data are primitives there, which is exactly
the interaction being asked for, where d3-force would mean hand-writing all
three.

No npm, no bundler, no build step. deepdep stays one static no-cgo binary — and a
tool whose central claim is that undeclared JS dependencies are where risk enters
should not acquire a `node_modules` to render its own report. The vendored file is
auditable by deepdep itself, which is the point of the PROVENANCE file.

Severity colour follows the `dataviz` skill's palette at implementation time
rather than being invented here, including the requirement that it read in both
light and dark and that severity not be encoded by hue alone.

### `serve` contradicts the README, so the README changes

The README's third line is "Offline, from a git checkout. No daemon, no image
pull". `serve` is a daemon. It is local-only, read-only, and starts nothing
without being asked — but the sentence needs amending rather than quietly
becoming false.

## Testing

**Store.** Project upsert is idempotent; the same path recorded twice updates
`last_seen` and does not duplicate; `Canonical` is a table test over the SCP,
HTTPS, bare, and trailing-`.git` forms plus the non-git case; deleting a project
removes exactly its runs' derived rows and leaves unclaimed runs intact.

**The preservation guarantee.** Count every observation table before and after a
`clean --purge --vacuum`, and assert equality. This is the test that stops a
future refactor from making `clean` destroy irreplaceable scorecard history.

**Migration.** A v4 fixture holding both remote and local runs migrates to
exactly *N* projects and *M* unclaimed runs — asserted numerically, not just
"no error".

**Resolution.** Each ref form resolves; an ambiguous substring errors and names
every candidate.

**Advisory persistence.** A finding written and read back at three `known_at`
instants — before publication, after publication, after withdrawal — returns
present/absent correctly. A node with no `finding_obs` row reads as unknown, not
clean.

**Web.** Golden JSON per handler from a seeded store; `risk-graph` on an 18k-node
fixture returns at most `MaxNodes` and reports `truncated` when it clips — the
assertion is on the marker, not just the count, because silent clipping is the
failure being guarded against; a non-loopback bind is refused without
`--listen-any`; a table test asserts every registered route is GET.

**The extraction.** `report --format json` output is captured from a stored run
before the move to `internal/report` and compared byte-for-byte after.

No test reaches the network, following the existing `httptest` pattern.

## Order of work

Five things ship in one design because they are one user-facing story, but they
have a dependency order and each step is independently useful:

1. **`internal/project` + `Origin()`** — canonicalisation and the two facts the
   source layer currently throws away. Nothing user-visible yet.
2. **Schema v5 and the migration** — projects exist and 208 are adopted.
3. **`deepdep projects` and `clean`** — the original complaint is answered here.
   Everything after this point is additive.
4. **`finding_obs` and the write side of `advisories`** — wired into `audit`,
   `risk` and `report`, plus the `depsdev_obs` harvest. Still no UI; `report`
   gains the ability to answer from the store.
5. **Extract `internal/report`** — a behaviour-preserving refactor, verified by
   byte-identical `--format json`. Nothing user-visible; it is what makes step 6
   able to reuse the report rather than reimplement it.
6. **`serve`** — API first with golden-JSON tests, then the embedded front end.

Steps 1–3 are the fix and answer the original complaint on their own. Steps 4–6
are the explorer: 6 cannot be built honestly before 4, because a graph that
coloured unaudited nodes green would be lying, and it cannot be built *correctly*
before 5, because `reportDoc` is unreachable from `internal/` until then.

This wants a plan per stage rather than one plan for six, with 1–3 planned and
executed first.

## Deviations, all deliberate

1. `runs.target` keeps its current meaning, so org-scan resume semantics do not
   change.
2. The 3 pre-v5 local runs stay unclaimed permanently. Their paths were never
   recorded.
3. No local OSV range evaluation. Findings are recalled observations, and an
   unaudited version reads as unknown.
4. `serve` introduces a daemon the README currently disclaims.

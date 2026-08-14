-- deepdep run store.
--
-- Three tiers with different lifetimes:
--   * derived per-run tables (nodes, edges, instances, rollups) — regenerable,
--     ON DELETE CASCADE so dropping a run is one statement;
--   * observation tables (packument_obs, ref_obs, advisories) — append-only
--     records of mutable things, each stamped with when we saw it;
--   * fact tables (version_facts) — immutable truths, safe forever.
--
-- Raw bodies live on the filesystem in the content-addressed blob store; this
-- database holds facts and body_sha256 pointers.

CREATE TABLE runs (
  run_id       TEXT PRIMARY KEY,
  target       TEXT NOT NULL,
  ref          TEXT NOT NULL,
  mode         TEXT NOT NULL CHECK (mode IN ('will','can')),
  as_of        TEXT NOT NULL,   -- resolution time
  known_at     TEXT NOT NULL,   -- knowledge time; independent of as_of
  tool_version TEXT NOT NULL,
  bounds_json  TEXT NOT NULL,
  created_at   TEXT NOT NULL
);

CREATE TABLE nodes (
  run_id       TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  id           TEXT NOT NULL,
  ecosystem    TEXT NOT NULL,
  name         TEXT NOT NULL,
  version      TEXT,
  completeness TEXT NOT NULL,
  reason       TEXT,            -- bound:depth|bound:nodes|offline|error:*|unpinned-ref
  resolved_ref TEXT,            -- observed SHA/digest behind a mutable ref
  published_at TEXT,
  source_file  TEXT,
  note         TEXT,
  PRIMARY KEY (run_id, id)
) WITHOUT ROWID;

CREATE INDEX idx_nodes_name ON nodes(run_id, ecosystem, name);

CREATE TABLE edges (
  run_id  TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  from_id TEXT NOT NULL,
  to_id   TEXT NOT NULL,
  kind    TEXT NOT NULL,
  spec    TEXT NOT NULL DEFAULT '',      -- raw range; "constraint" is reserved
  scope   TEXT NOT NULL DEFAULT 'prod',
  PRIMARY KEY (run_id, from_id, to_id, kind, spec)
);

-- "why is this here?" walks inbound edges, so that direction needs its own index;
-- outbound expansion is served by the primary key prefix.
CREATE INDEX idx_edges_in ON edges(run_id, to_id);

CREATE TABLE instances (
  run_id         TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  locator        TEXT NOT NULL,          -- npm: node_modules/a/node_modules/b
  node_id        TEXT NOT NULL,
  parent_locator TEXT,
  derived_from   TEXT NOT NULL CHECK (derived_from IN ('lockfile','simulated')),
  PRIMARY KEY (run_id, locator)
);

CREATE INDEX idx_instances_node ON instances(run_id, node_id);

-- Structural columns only. Advisory counts are deliberately NOT materialised:
-- they are a function of known_at, which is a query parameter, and baking one in
-- would un-bitemporalise the whole design.
CREATE TABLE package_rollup (
  run_id             TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  ecosystem          TEXT NOT NULL,
  name               TEXT NOT NULL,
  direct             INTEGER NOT NULL,
  instance_count     INTEGER NOT NULL,
  path_count         INTEGER NOT NULL,   -- saturating, capped
  worst_completeness TEXT NOT NULL,
  PRIMARY KEY (run_id, ecosystem, name)
);

CREATE TABLE version_rollup (
  run_id         TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  node_id        TEXT NOT NULL,
  ecosystem      TEXT NOT NULL,
  name           TEXT NOT NULL,
  version        TEXT NOT NULL,
  installedness  TEXT NOT NULL CHECK (installedness IN ('installed','possible','unknown')),
  -- How firmly the version is held. Independent of installedness: a wide range
  -- held by a lockfile and an exact manifest constraint install the same version
  -- today, but only the first moves when the lock is regenerated.
  pinning        TEXT NOT NULL DEFAULT '' CHECK (pinning IN ('','pinned','locked','floating')),
  declared_spec  TEXT NOT NULL DEFAULT '',
  instance_count INTEGER NOT NULL,
  path_count     INTEGER NOT NULL,
  PRIMARY KEY (run_id, node_id)
);

CREATE INDEX idx_version_rollup_pkg ON version_rollup(run_id, ecosystem, name);

-- Bitemporal substrate. Populated from v1 so later runs can be re-audited;
-- tag->SHA and tag->digest history cannot be reconstructed after the fact.
CREATE TABLE packument_obs (
  ecosystem         TEXT NOT NULL,
  name              TEXT NOT NULL,
  observed_at       TEXT NOT NULL,
  body_sha256       TEXT NOT NULL,
  registry_modified TEXT,
  -- whether the observed body was the FULL packument (carries publish times) or
  -- the abbreviated one. A cached abbreviated body cannot satisfy an --as-of run.
  full              INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ecosystem, name, observed_at)
);

CREATE TABLE version_facts (
  ecosystem    TEXT NOT NULL,
  name         TEXT NOT NULL,
  version      TEXT NOT NULL,
  published_at TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, version)
);

CREATE TABLE ref_obs (
  ref_purl    TEXT NOT NULL,
  resolved    TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (ref_purl, observed_at)
);

-- (osv_id, modified) is an immutable pair, so an advisory body is safe to
-- content-address like any other fact.
CREATE TABLE advisories (
  osv_id      TEXT NOT NULL,
  modified    TEXT NOT NULL,
  published   TEXT NOT NULL,
  withdrawn   TEXT,
  body_sha256 TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (osv_id, modified)
);

CREATE TABLE advisory_affects (
  osv_id      TEXT NOT NULL,
  ecosystem   TEXT NOT NULL,
  name        TEXT NOT NULL,
  events_json TEXT NOT NULL,
  PRIMARY KEY (osv_id, ecosystem, name)
);

CREATE INDEX idx_affects_pkg ON advisory_affects(ecosystem, name);

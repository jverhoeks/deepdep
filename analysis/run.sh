#!/bin/bash
# Scan one repository end to end: clone + closure, then advisories + posture.
#
# One DB per repo. WriteRun is a single large transaction and concurrent bulk
# writers under WAL serialise or return SQLITE_BUSY — which would fail a scan
# AFTER it did all the network work. Per-repo databases also make `report` with
# no run-id unambiguous, and make re-running a single repository trivial.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/analysis/.out"
BIN="$ROOT/deepdep"

repo="$1"
slug="${repo//\//__}"
url="https://github.com/${repo}.git"

report="$OUT/reports/${slug}.json"
scan="$OUT/scans/${slug}.json"
log="$OUT/logs/${slug}.log"
db="$OUT/db/${slug}.db"

# Resumability. At 131 repositories a transient clone or OSV failure is certain;
# a valid report already on disk is never redone.
if [ -s "$report" ] && jq -e . "$report" >/dev/null 2>&1; then
  echo "SKIP  $repo"
  exit 0
fi

mkdir -p "$OUT"/{reports,scans,logs,db}
rm -f "$db"

start=$(date +%s)
printf '=== %s ===\n--- scan ---\n' "$repo" > "$log"

# The outer bound covers the clone; --timeout bounds closure expansion. Both are
# recorded rather than raised per repository — a bound that fired and was
# reported is consistent with the tool's own thesis.
timeout 900 "$BIN" scan --mode will --format json \
  --timeout 5m --cache-dir "$OUT/cache" --db "$db" "$url" \
  > "$scan" 2>> "$log"
scan_rc=$?

if [ $scan_rc -ne 0 ] || [ ! -s "$scan" ]; then
  echo "FAIL($scan_rc) $repo  scan"
  echo "{\"repo\":\"$repo\",\"stage\":\"scan\",\"rc\":$scan_rc}" > "$OUT/logs/${slug}.failed"
  exit 1
fi

echo "--- report ---" >> "$log"
timeout 1200 "$BIN" report --format json --db "$db" --timeout 15m \
  > "$report" 2>> "$log"
rep_rc=$?

if [ $rep_rc -ne 0 ] || ! jq -e . "$report" >/dev/null 2>&1; then
  echo "FAIL($rep_rc) $repo  report"
  echo "{\"repo\":\"$repo\",\"stage\":\"report\",\"rc\":$rep_rc}" > "$OUT/logs/${slug}.failed"
  rm -f "$report"
  exit 1
fi

rm -f "$OUT/logs/${slug}.failed"
echo "OK    $repo  $(( $(date +%s) - start ))s"

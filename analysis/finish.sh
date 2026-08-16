#!/bin/bash
# Bring the whole fleet onto one binary, then build the write-up's inputs.
#
# Reports written mid-run come from whichever build was on disk at the time.
# Every number cited has to come from ONE binary, or the tables average
# incompatible definitions of "direct".
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/analysis/.out"
cd "$ROOT"

echo "== 1. retry the repositories whose scan failed =========================="
for f in "$OUT"/logs/*.failed; do
  [ -e "$f" ] || continue
  repo=$(jq -r .repo "$f")
  rm -f "$f"
  ./analysis/run.sh "$repo"
done

echo
echo "== 2. re-run every report on the current binary ========================="
regen() {
  db="$1"; slug="$(basename "$db" .db)"; out="$OUT/reports/${slug}.json"
  if timeout 1200 "$ROOT/deepdep" report --format json --db "$db" --timeout 15m \
       > "${out}.tmp" 2>> "$OUT/logs/${slug}.log" && jq -e . "${out}.tmp" >/dev/null 2>&1; then
    mv "${out}.tmp" "$out"; echo "OK"
  else
    rm -f "${out}.tmp"; echo "FAIL $slug"
  fi
}
export -f regen; export ROOT OUT
ls "$OUT"/db/*.db | xargs -P 6 -I{} bash -c 'regen "$@"' _ {} | sort | uniq -c

echo
echo "== 3. aggregate ========================================================"
python3 analysis/aggregate.py

echo
echo "== 4. tables ==========================================================="
python3 analysis/tables.py > "$OUT/tables.txt" 2>&1
echo "wrote out/tables.txt ($(wc -l < "$OUT/tables.txt") lines)"

# Freeze the inputs alongside the lists. If anything is re-run later the numbers
# must not shift under a half-written write-up.
cp "$OUT/aggregate.json" analysis/aggregate.frozen.json
cp "$OUT/tables.txt" analysis/tables.frozen.txt
cp "$OUT"/lists/{active,growing,ai}.json analysis/
echo "frozen into analysis/"

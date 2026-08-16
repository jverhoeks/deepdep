#!/bin/bash
# Freeze the two repository lists, with the literal query and the fetch time.
#
# GitHub search is live. Without freezing, nobody — including the author a week
# later — can reproduce a number in the write-up, and reproducibility is this
# tool's whole argument.
set -euo pipefail
OUT="$(cd "$(dirname "$0")/.." && pwd)/analysis/.out/lists"
mkdir -p "$OUT"
cd "$OUT"

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CUTOFF=$(date -u -v-30d +%Y-%m-%d)   # "active" = pushed to within 30 days
BORN=$(date -u -v-24m +%Y-%m-%d)     # "new" = created within 24 months

# ---- top 100 active -------------------------------------------------------
QA="stars:>10000 pushed:>$CUTOFF"
: > active.raw.jsonl
for p in 1 2; do
  gh api -X GET search/repositories --field q="$QA" --field sort=stars \
    --field order=desc --field per_page=50 --field page=$p \
  | jq -c '.items[] | {full_name, stars:.stargazers_count, language,
                       created_at, pushed_at, size, archived, fork}' >> active.raw.jsonl
done
jq -s --arg q "$QA" --arg at "$NOW" '{
  definition: "top 100 by stars among repositories pushed to in the last 30 days",
  query: $q, fetched_at: $at, repos: .}' active.raw.jsonl > active.json

# ---- top 50 fast-growing --------------------------------------------------
# Stars alone rank old projects; stars-per-day-since-creation ranks momentum.
# Ranked over a 300-repository pool rather than taken off the top of one page,
# so a repository that is merely large does not crowd out one that is growing.
QG="created:>$BORN stars:>2000 pushed:>$CUTOFF"
: > growing.pool.jsonl
for p in 1 2 3 4 5 6; do
  gh api -X GET search/repositories --field q="$QG" --field sort=stars \
    --field order=desc --field per_page=50 --field page=$p \
  | jq -c '.items[] | {full_name, stars:.stargazers_count, language,
                       created_at, pushed_at, size, archived, fork}' >> growing.pool.jsonl
done
POOL=$(wc -l < growing.pool.jsonl | tr -d ' ')
jq -s --arg q "$QG" --arg at "$NOW" --argjson pool "$POOL" '
  [ .[] | . + {age_days: (((($at|fromdate) - (.created_at|fromdate))/86400)|floor)} ]
  | [ .[] | . + {stars_per_day: (.stars / (if .age_days < 1 then 1 else .age_days end))} ]
  | sort_by(-.stars_per_day) | .[0:50]
  | {definition: "top 50 by stars-per-day since creation, ranked over a pool of
repositories created in the last 24 months with >2000 stars and pushed to in the
last 30 days",
     query: $q, fetched_at: $at, pool_size: $pool, repos: .}' growing.pool.jsonl > growing.json

jq -r '.repos[].full_name' active.json growing.json ai.json 2>/dev/null | sort -u > targets.txt
echo "active $(jq '.repos|length' active.json)  growing $(jq '.repos|length' growing.json)  unique targets $(wc -l < targets.txt)"

#!/bin/bash
# Freeze a third list: AI projects that are software people run, not reading
# material about AI.
#
# The star ranking on GitHub's AI topics is dominated by two things that are not
# software: curated lists / courses / prompt collections, and the current wave of
# weeks-old agent-harness repositories riding a spike. Both would be scanned
# honestly and both would say nothing about how real AI systems are assembled.
#
# Two objective filters, stated rather than hand-picked:
#   1. a content-repository name/description pattern list (awesome, lessons,
#      roadmap, from-scratch, prompts, ...)
#   2. created at least 365 days ago — a project cannot yet be "actually used"
#      if it is three weeks old, and this removes the spike wave without anyone
#      exercising taste about which spike deserves it
#
# Whether the result really is *used* is then tested by the scan itself: a
# project with no dependency manifest we can read gets reported as such in the
# funnel rather than quietly dropped.
set -euo pipefail
OUT="$(cd "$(dirname "$0")/.." && pwd)/analysis/.out/lists"
mkdir -p "$OUT"; cd "$OUT"

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CUTOFF=$(date -u -v-30d +%Y-%m-%d)
ESTABLISHED=$(date -u -v-365d +%Y-%m-%d)
TOPICS="llm machine-learning deep-learning generative-ai ai-agents rag nlp computer-vision llmops"

: > ai.pool.jsonl
for t in $TOPICS; do
  gh api -X GET search/repositories \
    --field q="topic:$t stars:>8000 pushed:>$CUTOFF created:<$ESTABLISHED" \
    --field sort=stars --field order=desc --field per_page=50 \
  | jq -c '.items[] | {full_name, stars:.stargazers_count, language, description,
                       created_at, pushed_at, size, archived, fork}' >> ai.pool.jsonl
done

# Reading material, not software. Matched case-insensitively on name and
# description; every pattern is listed here so the exclusion is auditable.
REJECT='awesome|for-beginners|-beginners|from-scratch|tutorial|lessons|course|roadmap|checklist|cheat.?sheet|interview|handbook|curated|prompt|100-days|learn-|-guide$|guides?$|examples?$|cookbook|paper.?list|reading.?list|resources$'

jq -s --arg q "topic:{$TOPICS} stars:>8000 pushed:>$CUTOFF created:<$ESTABLISHED" \
      --arg at "$NOW" --arg reject "$REJECT" '
  unique_by(.full_name)
  | map(select(.language != null and .archived == false and .fork == false))
  | map(select((.full_name | ascii_downcase | test($reject)) | not))
  | map(select(((.description // "") | ascii_downcase | test($reject)) | not))
  | sort_by(-.stars) | .[0:50]
  | {definition: "top 50 AI/ML repositories by stars that are software rather than
reading material: an AI topic, >8000 stars, pushed in the last 30 days, created
at least 365 days ago, a declared language, not a fork or archived, and neither
name nor description matching the content-repository pattern list",
     query: $q, fetched_at: $at, excluded_pattern: $reject, repos: .}' \
  ai.pool.jsonl > ai.json

jq -r '.repos[] | "\(.stars)\t\(.full_name)\t\(.language)"' ai.json
echo "---"
echo "pool $(wc -l < ai.pool.jsonl)  selected $(jq '.repos|length' ai.json)"

#!/usr/bin/env bash
# Fetch the latest baseline from the benchmark-baseline branch and run
# scripts/bench-compare.py against the PR results. Writes compare.json and
# appends the results table to the GitHub step summary.
#
# Env: COMPARE_JSON (path to write), HEAD_SHA (PR head sha).
set -euo pipefail

mkdir -p target/bench/workdir
if git ls-remote --exit-code --heads origin benchmark-baseline >/dev/null 2>&1; then
  git fetch -q origin benchmark-baseline:refs/remotes/origin/benchmark-baseline
else
  status=$?
  if [ "$status" -ne 2 ]; then
    echo 'ERROR: could not determine benchmark baseline status' >&2
    exit "$status"
  fi
  echo 'No benchmark baseline found yet; skipping comparison'
  exit 0
fi

git show origin/benchmark-baseline:baseline.json > target/bench/baseline.json
BASE_SHA=$(git rev-parse --short origin/benchmark-baseline)

echo '## Benchmark results' >> "$GITHUB_STEP_SUMMARY"
if ! python3 scripts/bench-compare.py \
  --results target/bench/results.json \
  --baseline target/bench/baseline.json \
  --sha "$HEAD_SHA" \
  --base-sha "$BASE_SHA" \
  --compare-json "$COMPARE_JSON" \
  | tee -a "$GITHUB_STEP_SUMMARY"; then
  if ! jq -e . "$COMPARE_JSON" >/dev/null 2>&1; then
    echo 'ERROR: comparison failed without writing compare.json' >&2
    exit 1
  fi
fi

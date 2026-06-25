#!/usr/bin/env bash
# Fails if the Infracost monthly total exceeds the threshold. The federation
# trust plane is free; a non-zero total means a billable resource crept in.
set -euo pipefail

THRESHOLD="${COST_THRESHOLD:-0.01}"
BREAKDOWN_JSON="${1:?usage: cost_guardrail.test.sh <infracost-breakdown.json>}"

TOTAL=$(jq -r '.totalMonthlyCost // "0"' "$BREAKDOWN_JSON")

awk -v t="$TOTAL" -v thr="$THRESHOLD" 'BEGIN {
  if (t + 0 > thr + 0) {
    printf("FAIL: monthly cost %s exceeds threshold %s\n", t, thr); exit 1
  }
  printf("OK: monthly cost %s within threshold %s\n", t, thr);
}'

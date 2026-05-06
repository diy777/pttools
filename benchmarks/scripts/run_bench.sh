#!/usr/bin/env bash
# Run a single benchmark and write a JSON result.
#
# Usage:
#   benchmarks/scripts/run_bench.sh <challenge-name>
#
# Reads:
#   benchmarks/challenges/<name>/SPEC.md
#   benchmarks/challenges/<name>/setup.sh
#   benchmarks/challenges/<name>/target.txt
#   benchmarks/challenges/<name>/teardown.sh
#
# Writes:
#   benchmarks/results/<YYYYMMDD-HHMMSS>-<commit>-<name>.json

set -euo pipefail

NAME="${1:-}"
if [[ -z "$NAME" ]]; then
    echo "usage: $0 <challenge-name>" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHAL_DIR="$REPO_ROOT/benchmarks/challenges/$NAME"
RESULTS_DIR="$REPO_ROOT/benchmarks/results"

if [[ ! -d "$CHAL_DIR" ]]; then
    echo "challenge not found: $CHAL_DIR" >&2
    exit 1
fi

mkdir -p "$RESULTS_DIR"

TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "no-git")"
OUT="$RESULTS_DIR/$TIMESTAMP-$COMMIT-$NAME.json"

START=$(date -u +%s)

# 1) Setup
if [[ -f "$CHAL_DIR/setup.sh" ]]; then
    bash "$CHAL_DIR/setup.sh" || { echo "setup failed for $NAME" >&2; exit 1; }
fi

TARGET=""
if [[ -f "$CHAL_DIR/target.txt" ]]; then
    TARGET="$(cat "$CHAL_DIR/target.txt")"
fi

# 2) Run pentest-tools against the target.
# This is the real measurement. Currently a stub that records placeholders;
# fill in with `pttools start --json --target ...` when the per-challenge
# integration lands.
SOLVED="false"
DURATION=0
TOKENS=0

if command -v pttools >/dev/null 2>&1 && [[ -n "$TARGET" ]]; then
    # Real run path (commented out until the JSON output mode is stable):
    #   pttools start "$TARGET" --intensity light --json --output "$RESULTS_DIR/raw-$NAME.json"
    echo "(stub) would invoke: pttools start $TARGET --intensity light --json"
    DURATION=1
fi

END=$(date -u +%s)
DURATION=$((END - START))

# 3) Teardown
if [[ -f "$CHAL_DIR/teardown.sh" ]]; then
    bash "$CHAL_DIR/teardown.sh" || true
fi

# 4) Emit JSON result
cat > "$OUT" <<EOF
{
  "name": "$NAME",
  "commit": "$COMMIT",
  "timestamp": "$TIMESTAMP",
  "target": "$TARGET",
  "duration_seconds": $DURATION,
  "solved": $SOLVED,
  "tokens_used": $TOKENS,
  "harness_version": "1",
  "stub": true
}
EOF

echo "wrote $OUT"

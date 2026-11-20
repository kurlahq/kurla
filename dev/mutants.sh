#!/usr/bin/env bash
set -euo pipefail

mode="${1:?mode}"
value="${2:?value}"

case "$mode" in
diff) selection=(--in-diff "$value") ;;
full)
    [[ "$value" =~ ^[0-9]+/[0-9]+$ ]] || { echo "mutants.sh: shard must look like 0/8, got: $value" >&2; exit 2; }
    selection=(--shard "$value")
    ;;
*) echo "mutants.sh: mode must be diff or full, got: $mode" >&2; exit 2 ;;
esac

status=0
cargo mutants -j 2 "${selection[@]}" || status=$?
case "$status" in
0 | 2 | 3) echo "mutants.sh: cargo-mutants exit code $status" ;;
*) echo "mutants.sh: cargo-mutants failed with exit code $status" >&2; exit "$status" ;;
esac

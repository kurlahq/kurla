#!/usr/bin/env bash
set -euo pipefail

mode="${1:?mode}"
value="${2:?value}"

case "$mode" in
diff) selection=(--in-diff "$value") ;;
full)
    [[ "$value" =~ ^[0-9]+/[0-9]+$ ]] || { echo "mutants.sh: shard must look like 0/8, got: $value" >&2; exit 2; }
    selection=(--shard "$value" --cargo-test-arg=--no-fail-fast)
    ;;
*) echo "mutants.sh: mode must be diff or full, got: $mode" >&2; exit 2 ;;
esac

status=0
cargo mutants -j 2 "${selection[@]}" || status=$?
case "$status" in
0 | 2 | 3) echo "mutants.sh: cargo-mutants exit code $status" ;;
*) echo "mutants.sh: cargo-mutants failed with exit code $status" >&2; exit "$status" ;;
esac

if [ ! -f mutants.out/outcomes.json ]; then
    if [ "$mode" = diff ] && [ "$status" = 0 ]; then
        echo "mutants.sh: no mutants were generated from this diff"
        : > mutants.none
    else
        echo "mutants.sh: cargo-mutants wrote no mutants.out/outcomes.json" >&2
        exit 1
    fi
fi

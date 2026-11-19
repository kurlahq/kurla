#!/usr/bin/env bash
set -euo pipefail

image="${KURLA_DEV_IMAGE:-kurla-dev}"
expected="network=blocked token=absent ssh=absent"

probe="$(docker run --rm --network none \
    -v "$PWD/dev/evil-build":/src:ro -w /src \
    "$image" \
    sh -c 'CARGO_TARGET_DIR=/tmp/evil-target cargo build --locked --offline >&2 && cat /tmp/evil-target/debug/build/evil-build-*/out/probe.txt')"

printf '%s\n' "$probe"

if [ "$probe" != "$expected" ]; then
    echo "evil-build probe mismatch, expected: $expected" >&2
    exit 1
fi

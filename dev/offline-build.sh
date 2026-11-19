#!/usr/bin/env bash
set -euo pipefail

image="${KURLA_DEV_IMAGE:-kurla-dev}"

for target in x86_64-unknown-linux-musl x86_64-pc-windows-gnu; do
    docker run --rm --network none -v "$PWD":/src -w /src "$image" \
        cargo build --release --locked --offline --target "$target"
done

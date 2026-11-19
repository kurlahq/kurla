FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates cmake curl git mingw-w64 pkg-config libssl-dev \
    && update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy \
    && rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu \
    && rustup toolchain install nightly-2026-11-04 --profile minimal

RUN cargo install --locked cargo-deny@0.20.2 \
    && cargo install --locked cargo-audit@0.22.2 \
    && cargo install --locked cargo-vet@0.10.3 \
    && cargo install --locked cargo-mutants@27.1.0 \
    && cargo install --locked cargo-fuzz@0.13.2 \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc

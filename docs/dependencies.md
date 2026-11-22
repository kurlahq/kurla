# Dependencies

| Name | Version | Source | Published | Reason |
| --- | --- | --- | --- | --- |
| Rust toolchain | 1.98.1 | rustup, pinned in `rust-toolchain.toml` | before 2026-11-05 | Compiler, rustfmt and clippy for every crate in the workspace. |
| actions/checkout | v7.0.1 (`3d3c42e5aac5ba805825da76410c181273ba90b1`) | GitHub Actions | 2026-07-20 | Checks out the repository in CI, with `persist-credentials: false`. GitHub's own action, pinned by full commit SHA. |
| actions/upload-artifact | v7.0.2 (`cf430e030ddbb5b0abf93d22962f4752f3646cd9`) | GitHub Actions | 2026-10-07 | Carries each mutation-test shard's `mutants.out` to the merge job in `.github/workflows/mutants.yml`. GitHub's own action, pinned by full commit SHA. |
| actions/download-artifact | v8.0.2 (`9000827ccba6bdab643e8b6fd33ac0654aef8333`) | GitHub Actions | 2026-10-07 | Fetches every shard's `mutants.out` in the merge job of `.github/workflows/mutants.yml`. GitHub's own action, pinned by full commit SHA. |
| adler2 | 2.0.1 | crates.io | 2025-06-09 | Pulled in by miniz_oxide (checksums). |
| arbitrary | 1.5.0 | crates.io | 2026-10-06 | Fuzz workspace only. Pulled in by libfuzzer-sys. Licence MIT OR Apache-2.0. |
| block-buffer | 0.12.1 | crates.io | 2026-06-11 | Pulled in by digest. |
| cc | 1.11.1 | crates.io | 2026-11-06 | Fuzz workspace only. Pulled in by libfuzzer-sys, which compiles libFuzzer with it. Licence MIT OR Apache-2.0. Pinned below 1.11.2 and 1.11.3 with `cargo update --precise`, because those are younger than the cutoff. |
| cfg-if | 1.0.5 | crates.io | 2026-09-16 | Pulled in by sha2. |
| const-oid | 0.10.2 | crates.io | 2026-01-07 | Pulled in by digest. |
| cpufeatures | 0.3.1 | crates.io | 2026-08-26 | Pulled in by sha2 (CPU feature detection). |
| crypto-common | 0.2.2 | crates.io | 2026-05-19 | Pulled in by digest. |
| digest | 0.11.3 | crates.io | 2026-05-03 | Pulled in by sha2. |
| find-msvc-tools | 0.1.15 | crates.io | 2026-10-19 | Fuzz workspace only. Pulled in by cc. Licence MIT OR Apache-2.0. |
| getrandom | 0.4.3 | crates.io | 2026-06-17 | Fuzz workspace only. Pulled in by jobserver. Licence MIT OR Apache-2.0. |
| hybrid-array | 0.4.15 | crates.io | 2026-09-08 | Pulled in by block-buffer and crypto-common. |
| itoa | 1.0.18 | crates.io | 2026-03-20 | Pulled in by serde_json. |
| jobserver | 0.1.35 | crates.io | 2026-07-06 | Fuzz workspace only. Pulled in by cc. Licence MIT OR Apache-2.0. |
| libfuzzer-sys | 0.4.13 | crates.io | 2026-06-04 | Fuzz workspace only, direct. Rust bindings to LLVM's libFuzzer, used by every target in `fuzz/fuzz_targets`. Licence (MIT OR Apache-2.0) AND NCSA, see the NCSA exception below. |
| libc | 0.2.191 | crates.io | 2026-10-16 | Pulled in by cpufeatures. |
| memchr | 2.8.3 | crates.io | 2026-07-08 | Pulled in by quick-xml and serde_json. |
| miniz_oxide | 0.9.1 | crates.io | 2026-03-13 | Direct. Inflate and deflate for compressed archive members, with no C code. |
| proc-macro2 | 1.0.107 | crates.io | 2026-07-19 | Listed in Cargo.lock through serde_derive, syn and quote. Not compiled: serde's derive feature is off. |
| quick-xml | 0.42.0 | crates.io | 2026-08-22 | Direct. Streaming XML parsing for OOXML and similar formats. |
| quote | 1.0.47 | crates.io | 2026-07-19 | Listed in Cargo.lock through serde_derive. Not compiled: serde's derive feature is off. |
| r-efi | 6.0.0 | crates.io | 2026-02-03 | Fuzz workspace only. Pulled in by getrandom (UEFI targets). Licence MIT OR Apache-2.0 OR LGPL-2.1-or-later, used under MIT OR Apache-2.0. |
| same-file | 1.0.6 | crates.io | 2020-01-11 | Pulled in by walkdir. |
| serde | 1.0.229 | crates.io | 2026-07-18 | Direct, default features off and `std` on, no derive macros. Serialisation traits for the JSON report. |
| serde_core | 1.0.229 | crates.io | 2026-07-18 | Pulled in by serde and serde_json. |
| serde_derive | 1.0.229 | crates.io | 2026-07-18 | Listed in Cargo.lock as an optional dependency of serde_core. Not compiled: serde's derive feature is off. |
| serde_json | 1.0.154 | crates.io | 2026-10-11 | Direct (also used by `xtask` to read the crates.io API response). JSON report output. |
| sha2 | 0.11.1 | crates.io | 2026-10-12 | Direct. SHA-256 digests for finding fingerprints. |
| shlex | 2.0.1 | crates.io | 2026-05-17 | Fuzz workspace only. Pulled in by cc. Licence MIT OR Apache-2.0. |
| syn | 3.0.9 | crates.io | 2026-10-12 | Listed in Cargo.lock through serde_derive. Not compiled: serde's derive feature is off. |
| typenum | 1.20.1 | crates.io | 2026-05-29 | Pulled in by hybrid-array. |
| unicode-ident | 1.0.27 | crates.io | 2026-10-12 | Listed in Cargo.lock through proc-macro2 and syn. Not compiled: serde's derive feature is off. |
| walkdir | 2.5.0 | crates.io | 2024-03-01 | Direct. Recursive repository traversal. |
| winapi-util | 0.1.11 | crates.io | 2025-09-07 | Pulled in by walkdir and same-file (Windows only). |
| windows-link | 0.2.1 | crates.io | 2025-10-06 | Pulled in by windows-sys (Windows only). |
| windows-sys | 0.61.2 | crates.io | 2025-10-06 | Pulled in by winapi-util (Windows only). |
| zmij | 1.0.23 | crates.io | 2026-07-13 | Pulled in by serde_json (float formatting). |
| rust:1.98.1-slim-bookworm | `sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730` | Docker Hub, image index digest | 2026-09-19 | Base of the dev container in `dev/Dockerfile`, pinned by digest. The tag exists, so the trixie fallback is not used. |
| nightly-2026-11-04 | rustc 1.101.0-nightly (708c94ef0 2026-11-03) | rustup, installed in `dev/Dockerfile` | 2026-11-04 | Dated nightly toolchain used for fuzzing only. |
| cargo-deny | 0.20.2 | crates.io, `cargo install --locked` | 2026-07-09 | Licence, ban, source and advisory policy checks (`deny.toml`). Newest release on or before 2026-11-05 whose `rust-version` (1.88.0) is at most 1.98.1. |
| cargo-audit | 0.22.2 | crates.io, `cargo install --locked` | 2026-06-05 | RustSec advisory audit of `Cargo.lock`, in its own CI job. `rust-version` 1.88. |
| cargo-vet | 0.10.3 | crates.io, `cargo install --locked` | 2026-10-22 | Supply-chain audit tracking. `rust-version` 1.85. |
| cargo-mutants | 27.1.0 | crates.io, `cargo install --locked` | 2026-06-02 | Mutation testing, run in CI only. `rust-version` 1.88. |
| cargo-fuzz | 0.13.2 | crates.io, `cargo install --locked` | 2026-06-09 | Fuzz target runner, used with the dated nightly. No declared `rust-version`. |
| actions/cache | v6.1.0 (`55cc8345863c7cc4c66a329aec7e433d2d1c52a9`) | GitHub Actions | 2026-06-26 | Caches the dev container image between CI runs, keyed on `dev/Dockerfile`. GitHub's own action, pinned by full commit SHA. |
| actions/attest-build-provenance | v4.2.2 (`4d101475d8b20a2381f78447822ac1eab6504dd8`) | GitHub Actions | 2026-08-06 | Writes the build provenance attestation for the four release binaries in the `attest` job of `.github/workflows/release.yml`. GitHub's own action, pinned by full commit SHA. A composite action whose only step calls `actions/attest`, listed next. |
| actions/attest | v4.2.1 (`508db95dd578ae2727ebd6217d5ba78e4fbda05d`) | GitHub Actions | 2026-07-29 | Called by `actions/attest-build-provenance` v4.2.2, pinned there by full commit SHA. A Node 24 action. Not referenced from our workflows. |
| macOS runner `macos-15` | arm64 image 20261118.0550.1 | GitHub-hosted runner, label from the runner-images README | image current on 2026-11-22 | Runs the `build-macos` job of `.github/workflows/release.yml`. The label is fixed to a macOS version rather than `macos-latest`. The image ships rustup 1.29.3 and Rust 1.100.0, which the job does not use. |
| Rust 1.98.1 on macOS | 1.98.1 with `aarch64-apple-darwin` and `x86_64-apple-darwin` | `rustup toolchain install` in the `build-macos` job | same as the Rust toolchain row | The toolchain pinned in `rust-toolchain.toml`, installed explicitly so that no later download is implicit. The macOS build runs with `--locked --offline` and the vendored sources, but the runner keeps network access, so it is offline by flag only. |

## Notes

- Every crates.io package in `Cargo.lock` was published on or before 2026-11-05, the cooldown cutoff for this baseline. `cargo xtask cooldown-check` enforces the 14 day rule on every run.
- `const-oid`, `itoa` and `syn` were pinned below their newest resolved versions with `cargo update --precise`, because the newest releases (0.10.3, 1.0.19, 3.0.10) were younger than the cutoff.
- Sources are vendored in `vendor/` and replaced in `.cargo/config.toml`, so builds run with `--offline`.
- The dev container installs Debian packages (`build-essential`, `cmake`, `mingw-w64`, `pkg-config`, `libssl-dev`, `curl`, `git`) from the base image's Debian bookworm archive. They are not version-pinned.
- Exceptions to the cooldown go in `supply-chain/cooldown-exceptions.toml`. The file is absent while there are none.
- The fuzz workspace (`fuzz/`) has its own `fuzz/Cargo.lock`, vendored into the same `vendor/` directory with `cargo vendor --sync fuzz/Cargo.toml vendor`. `cargo xtask cooldown-check` checks both lock files, and a missing `fuzz/Cargo.lock` is an error. The fuzz crate is never part of the shipped binary.
- `cc` was pinned at 1.11.1 with `cargo update --precise`, because 1.11.2 and 1.11.3 were younger than the cutoff.
- cargo-deny, cargo-vet and cargo-audit run against the fuzz workspace as well. The cargo-vet store is shared: `[package.metadata.vet]` in `fuzz/Cargo.toml` points `store` at `../supply-chain`. cargo-vet 0.10.3 uses that path as written, relative to the working directory, so CI runs `cargo vet` from `fuzz/`. It refuses a manifest that sets both `[package.metadata.vet]` and `[workspace.metadata.vet]`.

## cargo-vet

- Imports: every audit set in cargo-vet's built-in registry, namely `actix`, `ariel-os`, `bytecode-alliance`, `embark-studios`, `fermyon`, `google`, `isrg`, `mozilla` and `zcash`.
- Verification 1 (2026-11-19, cargo-vet 0.10.3): 4 of the 29 crates.io packages in `Cargo.lock` are fully audited through imports: `adler2`, `cpufeatures`, `quote` and `windows-link`. The other 25 are listed as exemptions in `supply-chain/config.toml`.
- The 8 crates that only the fuzz workspace uses (`arbitrary`, `cc`, `find-msvc-tools`, `getrandom`, `jobserver`, `libfuzzer-sys`, `r-efi`, `shlex`) are exemptions at `safe-to-deploy`, the same criteria as every other exemption.
- Verification 2 (2026-11-22, cargo-vet 0.10.3, CI): the fuzz workspace's 37 crates.io packages are 4 fully audited and 33 exempted; the main workspace's 29 are 4 and 25. Every exemption is used by at least one workspace.

## Crate-policy reviews pending

Each exempted crate needs a summary from an agent with no tools, no network and no credentials, approved by the code owner's merge. Pending:
`arbitrary`, `block-buffer`, `cc`, `cfg-if`, `const-oid`, `crypto-common`, `digest`, `find-msvc-tools`, `getrandom`, `hybrid-array`, `itoa`, `jobserver`, `libc`, `libfuzzer-sys`, `memchr`, `miniz_oxide`, `proc-macro2`, `quick-xml`, `r-efi`, `same-file`, `serde`, `serde_core`, `serde_derive`, `serde_json`, `sha2`, `shlex`, `syn`, `typenum`, `unicode-ident`, `walkdir`, `winapi-util`, `windows-sys` and `zmij`.

## Licence exceptions

- `libfuzzer-sys` 0.4.13 is licensed (MIT OR Apache-2.0) AND NCSA. `fuzz/deny.toml` allows `NCSA` for that crate only, through `[licenses] exceptions`. Reason: it bundles LLVM's libFuzzer; the fuzz crate is never part of the shipped binary.
- `fuzz/deny.toml` is used only for the fuzz workspace's cargo-deny check. It is the root `deny.toml` plus that one exception line, and an xtask test fails if the two files differ in any other way. The root config therefore holds no exception that its own dependency graph never uses.
- The licence allow list is `Apache-2.0`, `MIT` and `Zlib`. `Unicode-3.0` and `BSD-3-Clause` were removed (2026-11-22) because no compiled crate needs them, so cargo-deny reported them as not encountered. `unicode-ident` (MIT OR Apache-2.0 AND Unicode-3.0) is listed in `Cargo.lock` only through `serde_derive`, which is not compiled.

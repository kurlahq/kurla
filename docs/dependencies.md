# Dependencies

| Name | Version | Source | Published | Reason |
| --- | --- | --- | --- | --- |
| Rust toolchain | 1.98.1 | rustup, pinned in `rust-toolchain.toml` | before 2026-11-05 | Compiler, rustfmt and clippy for every crate in the workspace. |
| actions/checkout | v7.0.1 (`3d3c42e5aac5ba805825da76410c181273ba90b1`) | GitHub Actions | 2026-07-20 | Checks out the repository in CI, with `persist-credentials: false`. GitHub's own action, pinned by full commit SHA. |
| adler2 | 2.0.1 | crates.io | 2025-06-09 | Pulled in by miniz_oxide (checksums). |
| block-buffer | 0.12.1 | crates.io | 2026-06-11 | Pulled in by digest. |
| cfg-if | 1.0.5 | crates.io | 2026-09-16 | Pulled in by sha2. |
| const-oid | 0.10.2 | crates.io | 2026-01-07 | Pulled in by digest. |
| cpufeatures | 0.3.1 | crates.io | 2026-08-26 | Pulled in by sha2 (CPU feature detection). |
| crypto-common | 0.2.2 | crates.io | 2026-05-19 | Pulled in by digest. |
| digest | 0.11.3 | crates.io | 2026-05-03 | Pulled in by sha2. |
| hybrid-array | 0.4.15 | crates.io | 2026-09-08 | Pulled in by block-buffer and crypto-common. |
| itoa | 1.0.18 | crates.io | 2026-03-20 | Pulled in by serde_json. |
| libc | 0.2.191 | crates.io | 2026-10-16 | Pulled in by cpufeatures. |
| memchr | 2.8.3 | crates.io | 2026-07-08 | Pulled in by quick-xml and serde_json. |
| miniz_oxide | 0.9.1 | crates.io | 2026-03-13 | Direct. Inflate and deflate for compressed archive members, with no C code. |
| proc-macro2 | 1.0.107 | crates.io | 2026-07-19 | Listed in Cargo.lock through serde_derive, syn and quote. Not compiled: serde's derive feature is off. |
| quick-xml | 0.42.0 | crates.io | 2026-08-22 | Direct. Streaming XML parsing for OOXML and similar formats. |
| quote | 1.0.47 | crates.io | 2026-07-19 | Listed in Cargo.lock through serde_derive. Not compiled: serde's derive feature is off. |
| same-file | 1.0.6 | crates.io | 2020-01-11 | Pulled in by walkdir. |
| serde | 1.0.229 | crates.io | 2026-07-18 | Direct, default features off and `std` on, no derive macros. Serialisation traits for the JSON report. |
| serde_core | 1.0.229 | crates.io | 2026-07-18 | Pulled in by serde and serde_json. |
| serde_derive | 1.0.229 | crates.io | 2026-07-18 | Listed in Cargo.lock as an optional dependency of serde_core. Not compiled: serde's derive feature is off. |
| serde_json | 1.0.154 | crates.io | 2026-10-11 | Direct (also used by `xtask` to read the crates.io API response). JSON report output. |
| sha2 | 0.11.1 | crates.io | 2026-10-12 | Direct. SHA-256 digests for finding fingerprints. |
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

## Notes

- Every crates.io package in `Cargo.lock` was published on or before 2026-11-05, the cooldown cutoff for this baseline. `cargo xtask cooldown-check` enforces the 14 day rule on every run.
- `const-oid`, `itoa` and `syn` were pinned below their newest resolved versions with `cargo update --precise`, because the newest releases (0.10.3, 1.0.19, 3.0.10) were younger than the cutoff.
- Sources are vendored in `vendor/` and replaced in `.cargo/config.toml`, so builds run with `--offline`.
- The dev container installs Debian packages (`build-essential`, `cmake`, `mingw-w64`, `pkg-config`, `libssl-dev`, `curl`, `git`) from the base image's Debian bookworm archive. They are not version-pinned.
- Exceptions to the cooldown go in `supply-chain/cooldown-exceptions.toml`. The file is absent while there are none.

## cargo-vet

- Imports: every audit set in cargo-vet's built-in registry, namely `actix`, `ariel-os`, `bytecode-alliance`, `embark-studios`, `fermyon`, `google`, `isrg`, `mozilla` and `zcash`.
- Verification 1 (2026-11-19, cargo-vet 0.10.3): 4 of the 29 crates.io packages in `Cargo.lock` are fully audited through imports: `adler2`, `cpufeatures`, `quote` and `windows-link`. The other 25 are listed as exemptions in `supply-chain/config.toml`.

## Crate-policy reviews pending

Each exempted crate needs a summary from an agent with no tools, no network and no credentials, approved by the code owner's merge. Pending:
`block-buffer`, `cfg-if`, `const-oid`, `crypto-common`, `digest`, `hybrid-array`, `itoa`, `libc`, `memchr`, `miniz_oxide`, `proc-macro2`, `quick-xml`, `same-file`, `serde`, `serde_core`, `serde_derive`, `serde_json`, `sha2`, `syn`, `typenum`, `unicode-ident`, `walkdir`, `winapi-util`, `windows-sys` and `zmij`.

# Dependencies

| Name | Version | Source | Published | Reason |
| --- | --- | --- | --- | --- |
| Rust toolchain | 1.98.1 | rustup, pinned in `rust-toolchain.toml` | before 2026-11-05 | Compiler, rustfmt and clippy for every crate in the workspace. |
| actions/checkout | v7.0.1 (`3d3c42e5aac5ba805825da76410c181273ba90b1`) | GitHub Actions | 2026-07-20 | Checks out the repository in CI, with `persist-credentials: false`. GitHub's own action, pinned by full commit SHA. |

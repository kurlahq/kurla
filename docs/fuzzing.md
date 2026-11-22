# Fuzzing

Kurla parses untrusted bytes, so every parser has a libFuzzer target. The fuzz crate lives in `fuzz/`, has its own workspace and lock file, and is never part of the shipped binary.

## Targets

| Target | Entry points exercised |
| --- | --- |
| `png` | `binary::scan_png` |
| `jpeg` | `binary::scan_jpeg` |
| `exif` | `binary::exif_text_fields`, and the same bytes wrapped as a JPEG APP1 segment, a PNG `eXIf` chunk and a WebP `EXIF` chunk |
| `gif` | `binary::scan_gif` |
| `bmff` | `binary::scan_webp` and `binary::scan_avif` |
| `svg` | `svg::scan_svg` |
| `markup` | `markup::scan_markup`, as HTML and as Markdown |
| `encoded` | `encoded::scan_encoded` at every decode depth |
| `text_unicode` | `unicode::scan_text` for every location kind, `aimed::classify`, `unicode::confusable_skeleton` |
| `scan_file` | `engine::scan_file` on the input named `fuzz.bin`, `x.md`, `x.svg`, `x.png` and `.claude/settings.json` |

Each target in `fuzz/fuzz_targets/` is a thin wrapper. It includes the matching module of `tests/fuzz_props/` with `#[path = ...]` and calls `check(data)`.

## Properties

- No panic. The fuzz build keeps debug assertions and overflow checks on.
- Every finding span and carrier span satisfies `byte_start <= byte_end <= data.len()`. `encoded` also checks the spans of embedded blobs, and `scan_file` also checks the spans of embedded files that were not scanned. The check is `check_spans` in `tests/fuzz_props/spans.rs`, and a self-test proves that it panics on a span that is out of range.
- Decompression stays within `max_decompressed_bytes`, checked as a differential on PNG, the only parser that inflates data (zlib in `zTXt`, `iTXt` and `iCCP` chunks). `check` in `tests/fuzz_props/png.rs` scans the input twice, each time with its own `Budget`: once with `max_decompressed_bytes` of 4096 and once with 65536. The bytes a run consumed are its limit minus `Budget::remaining_decompressed()`. The small run must consume at most 4096 bytes. If the large run consumed more than 4096 bytes, the small run must carry the decompression-limit signal: a `B002` finding with the resource-limit carrier and the `DecompressionLimit` skip reason (or the `SizeLimit` skip when an earlier `L001` or `B003` finding set it first). The one exception is an input whose small run ended with the `Timeout` skip, where the comparison is not decided. The seed `fuzz/corpus/png/ztxt_over_4k.png` inflates to 5000 bytes, so it exercises the second rule on every test run, and self-tests in `tests/fuzz_corpus.rs` prove that the checker panics on each violation and accepts the exact limit.
- On an input that starts with the PNG signature, `scan_file` checks that `x.png` carries the same skip reason as the small `scan_png` run when that run reports `DecompressionLimit`.
- The other parsers do not inflate. They run with the same small limit so that fuzz inputs can reach their size caps, and they are checked for panics and spans only.

## Running locally

Fuzzing needs Linux and the dated nightly toolchain, and it compiles libFuzzer's C++ code. Use the dev container (`dev/Dockerfile`), which has the toolchain and `cargo-fuzz`:

```
cargo +nightly-2026-11-04 fuzz run png fuzz/corpus/png -- -max_total_time=60
```

Run it from the repository root. New inputs that libFuzzer finds are written to the corpus directory you pass first, and crashes are written to `fuzz/artifacts/<target>/`. Neither is committed unless you add it on purpose.

The stable tests do not need any of that. `cargo test --test fuzz_corpus` runs every target's `check` over every file in `fuzz/corpus/<target>/`, on any platform.

## Corpus

`fuzz/corpus/<target>/` is seeded from `tests/fixtures` (SVG and text files) and from small hand-built files made from the published PNG, JPEG, GIF, TIFF/EXIF, RIFF/WebP and ISO base media file format layouts. Every seed is at most 4 KiB.

The text seeds of the `markup`, `encoded` and `text_unicode` targets must decode as text, because those targets return early on input that does not; a test checks every one. The corpus directories hold regular files only, and the corpus test fails on any other entry (a subdirectory, a symbolic link) instead of skipping it.

The `exif` target wraps the input in a JPEG APP1 segment, whose length is a 16-bit field, so the JPEG wrapper carries at most 60000 bytes of the input and truncates the rest. The PNG and WebP wrappers fuzz the input whole.

`fuzz/Cargo.toml` pins the root crate as `kurla = { path = "..", version = "=<version>" }`, which `cargo-deny` needs to accept a path dependency. A release bump of the root crate must change that line too, and the test `fuzz_manifest_pins_the_root_crate_version` fails until it does.

## CI

`.github/workflows/fuzz.yml` runs one job per target in the dev container, with the network off.

| Trigger | Seconds per target |
| --- | --- |
| Pull request touching `src/binary/`, `src/svg.rs`, `src/markup.rs`, `src/encoded.rs`, `src/unicode/`, `src/engine.rs`, `fuzz/` or `tests/fuzz_props/` | 60 |
| Manual dispatch | 60 |
| Weekly schedule | 300 while the repository is private, 1800 once it is public |

The two durations are the `PULL_REQUEST_SECONDS` and `SCHEDULE_SECONDS` variables at the top of the workflow. Going public changes `SCHEDULE_SECONDS` to `1800`. The jobs have a read-only token, no secrets, and a time limit. A failed job uploads `fuzz/artifacts/<target>` as a workflow artifact.

## From crash to regression test

1. Download the `fuzz-artifacts-<target>` artifact of the failed job.
2. Reproduce it in the dev container: `cargo +nightly-2026-11-04 fuzz run <target> fuzz/artifacts/<target>/<file>`.
3. Write the smallest failing test in the module that owns the bug, and watch it fail.
4. Fix the bug.
5. Copy the crashing input into `fuzz/corpus/<target>/` under a descriptive name. `cargo test --test fuzz_corpus` now replays it on every platform, in every test run.

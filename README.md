# Kurla

Kurla is a local command-line scanner for repositories. It looks for content that is hidden from human readers and for text that is aimed at AI agents, and reports where it found each thing and why it matters.

Kurla runs on your machine and never contacts the network. It reads the files under the paths you give it. It does not execute, render or follow anything it finds in them.

## What it detects

| Family | What it looks for |
| --- | --- |
| U: invisible and deceptive Unicode | Zero-width and other invisible characters, Unicode tag characters (including the payload they spell out), variation selectors used as data, bidirectional controls, private-use characters, and identifiers or URLs that mix look-alike scripts. |
| M: hidden in markup | HTML comments in Markdown, elements hidden with `hidden`, `display:none`, `visibility:hidden`, zero opacity or zero font size, and text whose colour matches its background, in Markdown and HTML files. |
| A: text aimed at AI | Phrases and structures addressed to a model, such as instructions to ignore earlier instructions, mentions of a system prompt, messages addressed to AI reviewers, role and turn markers and fake tool-call syntax. |
| S: SVG | Text that is invisible in the drawing, and active content such as scripts, event-handler attributes and external references. Kurla reads SVG as plain XML and never loads a DTD or expands an entity. |
| B: metadata in binary files | Text in PNG, JPEG, GIF, WebP and AVIF metadata: text chunks, comments, EXIF text fields and XMP packets. The readers are Kurla's own. |
| E: encoded payloads | Long Base64 or hexadecimal runs in text that decode to readable, instruction-like text. Decoding is bounded in depth. |
| I: agent instruction files | Files that configure or instruct agents, such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.claude/`, `.cursor/rules/`, `.cursorrules`, `.github/copilot-instructions.md`, MCP configuration files and similar. Findings in them rank higher than the same finding elsewhere, and they are always checked for text aimed at AI. Commands configured in them are listed, and a configuration that cannot be parsed is reported. |
| L: limits | A file that was too large, took too long or hit a decompression or nesting limit is reported, never dropped silently. |

Every finding has a rule identifier, a severity (`info`, `low`, `medium`, `high` or `critical`), the file and position, and a fingerprint. Severity depends on the rule and on where the file sits: for example, hidden content in an agent instruction file ranks above the same content in a data asset.

## Usage

```
kurla scan [PATH]... [--format human|json|sarif] [--output FILE]
           [--fail-on info|low|medium|high|critical] [--require-complete]
           [--exclude GLOB]... [--follow-symlinks] [--decisions-base FILE]
           [--cache-dir DIR] [--no-cache] [--jobs N] [--max-file-size BYTES]
kurla --version
kurla --help
```

With no path, Kurla scans the current directory.

- The scan set is everything on disk under the given paths, except `.git` directories. `.gitignore` and `.ignore` files are not obeyed, and `node_modules/` and `vendor/` are included. Every `--exclude` is listed in the coverage.
- `--fail-on` sets the severity at which a run fails. The default is `high`.
- `--require-complete` also makes unknown binary files and embedded formats that were not scanned (other than PDF) count as incomplete.
- `--follow-symlinks` follows links; by default they are not followed and are listed in the coverage.
- `--output FILE` writes the report to a file through a temporary file and a rename. Standard output then stays empty.
- `--max-file-size BYTES` sets the per-file size limit (the default is 32 MiB). A larger file is partly read and reported.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean and complete. |
| `1` | At least one finding at or above the `--fail-on` threshold that is not a counted review. This wins over every other condition, even when the scan is also incomplete. |
| `2` | No such finding, but the run is incomplete or a decisions file was rejected. Also used for usage errors and for errors that stop the run, such as a path that does not exist or a report that cannot be written. |

A run is incomplete when:

- any file could not be read. An unreadable file always makes the run incomplete, whatever its type, because what it holds is unknown;
- a text, SVG or image-metadata file hit the size, decompression or time limit, or was malformed;
- `--require-complete` is given and a file is an unknown binary, or something embedded in a scanned file was not scanned (embedded PDFs excepted).

PDF files, text drawn inside images, files excluded by `--exclude` and links that were not followed never change the exit code. They stay listed in the coverage.

## Review decisions

A reviewed finding can be recorded in `.kurla/decisions.json`. Kurla reads that file from the working directory when it exists. Each entry names a finding by its fingerprint and rule, with a reviewer label, a reason, a start date and an expiry date. An entry is valid for at most 365 days. The file is read strictly: any error, including a repeated key, rejects the whole file. The rejection is reported and makes the run exit `2`, unless findings already make it `1`.

Reviewing never hides a finding. Every reviewed finding is still shown, with its reviewer and reason.

A review counts towards the gate only when a second file, given with `--decisions-base FILE`, holds a valid entry for the same fingerprint and rule. In CI that file should come from the base branch, so a change cannot excuse its own findings: an entry added in the same change is shown but does not count. Without `--decisions-base`, no review counts.

The format and the matching rules are in [docs/output-schema.md](docs/output-schema.md).

### Example: a GitHub Actions step

This pull-request step takes the decisions file from `main` with git and passes it as the base. It fails if `main` cannot be found. If `main` has no decisions file yet, it supplies an empty one, so nothing counts as reviewed. A base file that does not exist is itself a rejection, so the step never passes a missing path.

```yaml
- uses: actions/checkout@<full commit SHA>
  with:
    persist-credentials: false
    fetch-depth: 0
- name: Scan
  run: |
    base="$RUNNER_TEMP/decisions-base.json"
    if ! git rev-parse --verify --quiet "origin/main^{commit}" > /dev/null; then
      echo "origin/main is not available"
      exit 1
    fi
    if git cat-file -e "origin/main:.kurla/decisions.json" 2> /dev/null; then
      git show "origin/main:.kurla/decisions.json" > "$base"
    else
      printf '%s\n' '{"version":1,"entries":[]}' > "$base"
    fi
    kurla scan --no-cache --decisions-base "$base"
```

## The cache

Kurla keeps a local cache of per-file results so that unchanged files are not scanned again. The cache is trusted local state: anyone who can write to the cache directory can change what a scan reports. Use `--no-cache` in CI, and never restore a cache directory that an untrusted run produced. The cache directory comes from `--cache-dir`, then `KURLA_CACHE_DIR`, then the platform default. A cache directory inside a scanned path is not used, and the run says so.

## Output formats

- `human` (the default): plain text, one line per finding, then a coverage section and a final `complete` or `incomplete` line with the exit code.
- `json`: the `kurla.report/1` schema.
- `sarif`: SARIF 2.1.0, with reviewed findings carried as suppressions.

Every payload, path and message in every format escapes control, bidirectional and default-ignorable characters as `\u{XXXX}`, so a hostile file cannot disguise the report. The fields are described in [docs/output-schema.md](docs/output-schema.md).

## Limits

- Review names are not verified. The reviewer in a decisions file is a free-text label, so anyone who can change the file can write any name. The base-branch rule stops a change from excusing itself; it does not check who reviewed.
- Text drawn inside images is not scanned, and PDFs are not scanned. Both are listed in the coverage, and neither affects the exit code. Embedded formats that Kurla does not read are listed as not scanned.
- Family A is experimental. Its findings, and those of the look-alike script rule `U006`, are capped at `medium`, so they never fail the default gate on their own. Expect both false positives and misses.
- Kurla is not a guarantee that a repository is free of hidden or hostile content.
- The macOS build is offline by flag only: it uses `--locked --offline` and the vendored sources, but the runner that builds it keeps network access. The Linux and Windows builds run in a container with no network.
- The release binaries are not signed. Windows SmartScreen and macOS Gatekeeper may warn when you run them.

## Supply chain

- Every dependency is pinned to an exact version and recorded in [docs/dependencies.md](docs/dependencies.md). A version must have been published at least 14 days before it is adopted, and `cargo xtask cooldown-check` enforces that rule.
- Sources are vendored in `vendor/`, and builds use `--locked --offline`.
- The Linux and Windows release binaries are built in a container with `--network none`.
- `cargo-deny`, `cargo-audit` and `cargo-vet` run in CI.
- The parsers have fuzz targets, and mutation testing runs in CI.
- GitHub Actions are pinned by full commit SHA, and the release workflow gives its build jobs a read-only token.
- Each release is created as a draft by the release workflow, with a `SHA256SUMS` file and a build provenance attestation for every binary.

To check a download, run these in the directory that holds the files:

```
sha256sum -c SHA256SUMS
gh attestation verify kurla-x86_64-unknown-linux-musl --repo OWNER/REPO
```

Replace `OWNER/REPO` with the repository the release came from, and the file name with the binary you downloaded. To build from source, `cargo build --release --locked --offline` uses the vendored sources.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

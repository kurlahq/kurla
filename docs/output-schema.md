# Output schema

## Decisions file

A decisions file records review decisions for findings. It is JSON and is read strictly: any problem makes the whole file an error, and nothing is loaded partially or skipped silently.

```json
{"version":1,"entries":[{"fingerprint":"<64 hex>","rule":"S002","path":"docs/example.md","reviewer":"label","reason":"why this is acceptable","date":"2026-05-01","expires":"2026-09-01"}]}
```

### Format

- The top level has exactly `version` (the number `1`) and `entries` (an array).
- Each entry has exactly the seven fields shown above. Every field is a string. Unknown fields, missing fields, wrong types and any other version are errors. The error message names the entry index and the field.
- `fingerprint` is 64 lowercase hexadecimal characters.
- `rule`, `reviewer` and `reason` are non-empty. `path` is informational and is not used for matching.
- `date` and `expires` are `YYYY-MM-DD` and must be real calendar dates, leap years included.
- The file is UTF-8. A leading UTF-8 byte order mark is accepted. UTF-16 and invalid JSON are errors.

### Matching

An entry matches a finding when both `fingerprint` and `rule` are equal. When several valid entries match, the earliest in the file is used.

### Validity

An entry is valid when `date <= today < expires` and `expires` is at most 365 days after `date`. An entry that matched a finding but is not valid is not an error. It does not apply, and it is reported with its reason: `expired`, `not yet valid` or `longer than 365 days`.

`today` is the current date in UTC. The `KURLA_TODAY` environment variable (`YYYY-MM-DD`) overrides it; a value that does not parse is an error.

### Base-branch counting rule

A finding with a valid matching entry in the current decisions file always carries its review: the reviewer and the reason are shown in every output. The review only counts towards the gate when a base decisions file is supplied with `--decisions-base <file>` and that base file also holds a valid entry for the same fingerprint and rule. An entry added in the same change that it excuses is shown but does not count.

### Reviewed findings are always shown

Reviewing a finding never removes it from the output. Counted and uncounted reviews are both listed with their reviewer label, so a forged or self-approved entry is visible to a reader.

### Duplicate keys and rejected files

A repeated key in any JSON object of the file, at any depth, rejects the whole file, even when both values are identical. Keys are compared after JSON unescaping, so a key spelled with a JSON unicode escape collides with the same key spelled plainly. The message contains `duplicate key` and the key name.

A decisions file that cannot be loaded for any reason (unreadable, not UTF-8, invalid JSON, a duplicate key, a schema violation) is reported as rejected, with its path and the message, and is then treated as absent:

- a rejected current file reviews nothing, so every finding stays active;
- a rejected base file counts nothing, so reviews from the current file are shown but not counted.

### Invalid entries

When an entry matches a finding but is not valid, the reason is chosen in this order: `longer than 365 days`, then `not yet valid`, then `expired`.

Invalid entries from the current file that match a finding are reported with source `current`. An invalid entry in the base file is reported with source `base` when its finding was reviewed through the current file, since it could otherwise have counted. Each entry is reported once.

## Cache

Kurla keeps a local cache of per-file scan results so that unchanged files are not scanned again. The cache directory comes from `--cache-dir`, then `KURLA_CACHE_DIR`, then the platform default. `--no-cache` turns the cache off.

### The cache is trusted local state

Anyone who can write to the cache directory can change scan results, because a stored entry is used in place of a scan. Use `--no-cache` wherever that is not acceptable, for example on a shared or untrusted machine or in a directory other users can write to.

### What the key covers

An entry is looked up by a SHA-256 key over these length-prefixed fields:

- the SHA-256 of the file content;
- the path used to classify the file;
- the Kurla version;
- the rules version, which changes whenever any rule changes;
- every resource limit, including the per-file time limit.
- the SHA-256 of the running Kurla executable, which changes with every change to the rules, the bundled libraries or the compiler, so a stale rules version label cannot serve old results.

A change to any of them is a miss, and the file is scanned again. The executable is hashed once per run, and only when the cache is on. Cached entries hold findings from before review decisions are applied, so a changed decisions file always takes effect; an entry that carries a review is a miss. Each entry also records its own key, and an entry that is corrupt, has an unknown name or field, or does not match its key is treated as a miss.

### What is never cached

- A result that hit the per-file time limit, because time limits depend on machine load.
- Files that were only partly read (over the size limit), unreadable files, and files that were excluded or not followed.

### Problems are reported

- A cache directory inside a scanned path is not used, and the run reports `cache disabled: cache directory is inside a scanned path`, so a scanned tree cannot supply its own results.
- When entries cannot be written the scan result is unaffected and the run reports `cache writes failed: N`.
- When no cache directory can be determined, the cache is disabled and the reason is reported.
- When the running executable cannot be hashed, the cache is disabled and the run reports `cache disabled: cannot hash the running executable: <reason>`.

## Reports

`kurla scan` writes one report to standard output, or to the file named by `--output`. The file is written to a temporary name next to it and renamed, so a reader never sees half a report. With `--output`, standard output stays empty.

Warnings, rejected decisions files and usage errors go to standard error. Everything on standard error is escaped like the report.

### Escaping

Every string that came from a scanned repository or from a decisions file is escaped in all three formats: payloads, paths, messages, rule identifiers, `declared_type`, reviewer and reason, decisions-file error messages and the patterns and arguments echoed back in errors. Each control, bidirectional-control, default-ignorable, tag and variation-selector character, and the line and paragraph separators, becomes `\u{XXXX}` with at least four uppercase hexadecimal digits. Other text is unchanged. A backslash is not escaped.

### Exit code

- `1`: a finding at or above the `--fail-on` threshold (default `high`) that is not reviewed and counted. This wins over every other condition.
- `2`: otherwise, when the run is incomplete or a decisions file was rejected, and also for every usage error and every error that stops the run (a missing path, an invalid `--exclude` glob, an unusable `KURLA_TODAY` when a decisions file is given, a report that cannot be written).
- `0`: otherwise.

The run is incomplete when any of these holds:

- any file, in any category, has the skip reason `unreadable`: the category of content that could not be read is unknown, so an unreadable file always fails closed (this covers read errors, unreadable directories and special files that were not opened);
- a file in the text, SVG or image metadata category has the skip reason `size_limit`, `decompression_limit`, `timeout` or `malformed`;
- `--require-complete` is given and any file is in the unknown binary category (other images and unread special files included, but not files excluded by `--exclude` and not links that were not followed), or any `embedded_not_scanned` entry has a kind other than `pdf`.

PDF files, embedded PDFs, files with unscanned drawn text, files whose metadata is not scanned, excluded files and links that were not followed never make a run incomplete. They stay listed in the coverage.

A rejected decisions file never makes `complete` false, because `complete` describes coverage only.

### JSON (`kurla.report/1`)

The top-level object has exactly these fields.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `kurla.report/1`. |
| `kurla_version` | string | The version of Kurla that wrote the report. |
| `rules_version` | string | The rules version, which changes whenever any rule changes. |
| `complete` | boolean | True when the incomplete conditions above, evaluated as if `--require-complete` were given, are all false. It does not depend on the flag. |
| `exit_code` | number | The exit code of the run: `0`, `1` or `2`. |
| `threshold` | string | The `--fail-on` level: `info`, `low`, `medium`, `high` or `critical`. |
| `findings` | array | Findings, ordered by path, byte offset and rule. |
| `coverage` | object | What was and was not scanned. |
| `carrier_counts` | object | Number of carriers that gave no finding of their own, keyed by carrier name: visible text that family A did not flag, and hidden bytes in an image that do not read as text. Names with no carriers are absent. |
| `invalid_decisions` | array | Decisions entries that matched a finding but are not valid. |
| `decisions_errors` | array | Decisions files that were rejected. |
| `warnings` | array of strings | Problems that did not stop the run, for example the cache problems listed above. Each is also printed on standard error. `--no-cache` gives no warning. |

Each finding has exactly these fields.

| Field | Type | Meaning |
| --- | --- | --- |
| `rule` | string | Rule identifier, for example `U002`. |
| `family` | string | Rule family letter: `U`, `M`, `A`, `S`, `B`, `E`, `I` or `L`. |
| `severity` | string | Final severity, after every adjustment: `info`, `low`, `medium`, `high` or `critical`. |
| `status` | string | `stable` or `experimental`. |
| `path` | string | The file, relative to the working directory when it is inside it. |
| `location` | string | `agent_file`, `docs_template`, `code`, `data_asset` or `dependency`. |
| `line`, `column` | number or null | One-based, counted in Unicode code points. Null for binary files. |
| `byte_start`, `byte_end` | number | The byte range in the file. A finding inside a compressed SVG (`.svgz`) covers the whole file, because positions in the decompressed text do not exist in the file; its `line` and `column` are null. |
| `carrier` | string | `hidden_text`, `decoded_payload`, `html_comment`, `svg_text`, `metadata_field`, `agent_file_text`, `active_content` or `resource_limit`. |
| `message` | string | A short description. |
| `payload` | string or null | The text that was hidden or decoded, when there is one. |
| `fingerprint` | string | A stable identifier used by decisions files. |
| `review` | object or null | `reviewer`, `reason` and `counted` when a valid decisions entry matched. |

`coverage` has these fields.

| Field | Type | Meaning |
| --- | --- | --- |
| `scanned_by_category` | object | Files scanned with no skip, for each of `text`, `svg`, `image_metadata`, `pdf` and `unknown_binary`. All five keys are always present. |
| `skipped` | array | Every file with a skip reason, each `{path, kind, category, reason}`. `kind` is one of `text`, `svg`, `png`, `jpeg`, `gif`, `webp`, `avif`, `pdf`, `other_image`, `unknown_binary`. `reason` is one of `size_limit`, `decompression_limit`, `timeout`, `unreadable`, `excluded_by_user`, `symlink_not_followed`, `pdf_not_scanned`, `malformed`. Malformed files are listed here and nowhere else. |
| `not_scanned_for_drawn_text` | array of strings | Paths of files whose drawn text, such as text inside pixels, is not scanned. |
| `not_scanned_for_metadata` | array of strings | Paths of TIFF, PSD, JPEG XL, JPEG 2000, BMP and ICO files. Kurla does not read their metadata yet, so text stored in it is not scanned. See [known-limits.md](known-limits.md). |
| `excluded_by_user` | array of strings | Paths excluded by `--exclude`. These are also in `skipped`. |
| `embedded_not_scanned` | array | Content found inside a scanned file that was not scanned, each `{path, byte_start, byte_end, declared_type, kind, reason}`. `declared_type` is a string or null. |
| `encoded_runs_not_payloads` | number | The total, over all files, of encoded runs that did not decode to a payload. |

An `invalid_decisions` entry is `{fingerprint, rule, path, reason, source}`. `reason` is `expired`, `not yet valid` or `longer than 365 days`, and `source` is `current` or `base`.

A `decisions_errors` entry is `{file, message}`. The file contributes no entries, so every finding stays active.

### SARIF 2.1.0

- The tool driver is named `Kurla`. It has one rule for each rule identifier that appears in the results, ordered by identifier. A rule's properties are `family`, `status` and `security-severity`, a string: `9.5` for critical, `8.0` for high, `5.5` for medium, `3.0` for low and `0.0` for info. A rule takes the highest severity among its results.
- `level` is `error` for high and critical, `warning` for medium and `note` otherwise.
- The run sets `columnKind` to `unicodeCodePoints`.
- A finding in a text file has a region with `startLine` and `startColumn`, and `endLine` and `endColumn` when the end can be derived. The end is found by mapping `byte_end` through the decoded file, and it is left out when the file cannot be read again, the offsets do not fall on character boundaries or the start does not agree with the reported line and column. An end position is never invented. A finding in a binary file has `byteOffset` and `byteLength`.
- `partialFingerprints` is `{"kurla/v1": <fingerprint>}`.
- A reviewed finding is still emitted. It carries `suppressions` with one `external` entry whose `justification` is the review reason; its `properties` hold `reviewer` and `counted`.
- `invocations[0]` has `executionSuccessful` set from `complete`, the `exitCode`, and `toolExecutionNotifications`: one `error` notification for each rejected decisions file and one `warning` notification for each warning.
- `runs[0].properties` holds `complete`, `exit_code`, `coverage` (the same object as the JSON `coverage`), `invalid_decisions`, `decisions_errors` and `warnings`.

### Human format

Plain text with no colour. There is one line for each finding:

`<severity> <rule> <path>:<line>:<column> <message> [<payload>]`

A finding in a binary file has `<path>@<byte_start>-<byte_end>` in place of the position. A reviewed finding ends with `reviewed (counted|not counted) by <reviewer>: <reason>`.

A `coverage:` section follows. It lists the scanned counts, every skipped file, every embedded entry that was not scanned, every file not scanned for drawn text, every file whose metadata is not scanned, the number of excluded files and the encoded-run total. After it come the invalid decisions, the rejected decisions files and the warnings, one line each. The last line is `complete, exit code N` or `incomplete, exit code N`.

### Command line

`kurla scan [PATH]... [--format human|json|sarif] [--output FILE] [--fail-on LEVEL] [--require-complete] [--exclude GLOB]... [--follow-symlinks] [--decisions-base FILE] [--cache-dir DIR] [--no-cache] [--jobs N] [--max-file-size BYTES]` and `kurla --version`.

- With no path, `.` is scanned. A path that does not exist is a usage error.
- A value may be given as `--flag value` or `--flag=value`. A value that starts with `--` is not taken as a value, and `--` ends the flags.
- An unknown flag, a missing value, a number that does not parse, `--jobs 0`, or an unknown `--format` or `--fail-on` value prints the usage text on standard error and exits `2`.
- The current decisions file is `./.kurla/decisions.json` when anything exists at that path. The base file is the one named by `--decisions-base`. A file that is rejected is reported in all three formats and on standard error, and the run goes on with no entries from it.
- `--output` writes through an exclusively created temporary file next to the target, which is renamed into place; a name that already exists is never reused or followed. It fails the run with exit `2` when the report cannot be written.

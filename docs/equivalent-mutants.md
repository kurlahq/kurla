# Equivalent mutants

A mutant is equivalent when no test can tell it from the original code. Each entry below needs the maintainer's approval through the merge, and each needs a reason showing why no test can distinguish the mutant from the original. `cargo xtask mutants-check` fails the mutation job on any missed mutant that is not listed here.

Each row covers one missed occurrence. Two identical equivalent mutants need two identical rows. A row listed more often than the mutant is missed is reported as stale in full runs.

The `mutation` column is the description cargo-mutants prints, with the `:line:col` removed from the location, for example `replace == with != in matches_segment`. When a description contains the pipe character, escape each pipe with a backslash inside the table, because an unescaped pipe ends the cell.

| file | mutation | reason |
| --- | --- | --- |
| src/cache.rs | replace * with + | The constant sets the size of the read buffer in `hash_file`, which only decides how many `read` calls feed the same byte sequence to SHA-256. The digest of a byte sequence does not depend on how it is chunked, so no test can observe the buffer size. |
| src/cache.rs | replace match guard error.kind() == std::io::ErrorKind::Interrupted with false in hash_file | The guard differs from the original only when `read` returns `ErrorKind::Interrupted`. A regular file or a directory cannot be made to produce that error without injecting a signal, so no test can reach the difference. |
| src/decisions.rs | replace <impl Visitor<'de> for StrictVisitor>::expecting -> fmt::Result with Ok(Default::default()) | serde calls `expecting` only from the default `visit_*` methods of a Visitor, to build an invalid-type error. StrictVisitor overrides every method that serde_json 1.0.154 `deserialize_any` calls (`vendor/serde_json/src/de.rs` lines 1393 to 1458), so `expecting` is unreachable. |

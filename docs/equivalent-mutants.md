# Equivalent mutants

A mutant is equivalent when no test can tell it from the original code. Each entry below needs the maintainer's approval through the merge, and each needs a reason showing why no test can distinguish the mutant from the original. `cargo xtask mutants-check` fails the mutation job on any missed mutant that is not listed here, and warns about listed entries that no longer occur.

The `mutation` column is the description cargo-mutants prints, with the `:line:col` removed from the location, for example `replace == with != in matches_segment`.

| file | mutation | reason |
| --- | --- | --- |

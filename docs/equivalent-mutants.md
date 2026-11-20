# Equivalent mutants

A mutant is equivalent when no test can tell it from the original code. Each entry below needs the maintainer's approval through the merge, and each needs a reason showing why no test can distinguish the mutant from the original. `cargo xtask mutants-check` fails the mutation job on any missed mutant that is not listed here.

Each row covers one missed occurrence. Two identical equivalent mutants need two identical rows. A row listed more often than the mutant is missed is reported as stale in full runs.

The `mutation` column is the description cargo-mutants prints, with the `:line:col` removed from the location, for example `replace == with != in matches_segment`. When a description contains the pipe character, escape each pipe with a backslash inside the table, because an unescaped pipe ends the cell.

| file | mutation | reason |
| --- | --- | --- |

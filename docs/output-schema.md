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

use std::collections::BTreeSet;
use std::fs;
use std::process::ExitCode;

type Key = (String, String);

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub missed: usize,
    pub unlisted: Vec<Key>,
    pub stale: Vec<Key>,
}

pub fn run(args: &[String]) -> ExitCode {
    let [missed_path, table_path] = args else {
        eprintln!("mutants-check: usage: mutants-check <missed.txt> <equivalent-mutants.md>");
        return ExitCode::from(2);
    };
    let read =
        |path: &String| fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"));
    let result = read(missed_path)
        .and_then(|missed| read(table_path).map(|table| (missed, table)))
        .and_then(|(missed, table)| check(&missed, &table));
    match result {
        Ok(report) => print_report(&report),
        Err(message) => {
            eprintln!("mutants-check: {message}");
            ExitCode::from(2)
        }
    }
}

fn print_report(report: &Report) -> ExitCode {
    println!(
        "mutants-check: {} missed, {} unlisted, {} stale",
        report.missed,
        report.unlisted.len(),
        report.stale.len()
    );
    for (file, description) in &report.unlisted {
        println!("UNLISTED {file}: {description}");
    }
    for (file, description) in &report.stale {
        println!("warning: STALE {file}: {description}");
    }
    if report.unlisted.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

pub fn check(missed: &str, table: &str) -> Result<Report, String> {
    let listed = parse_table(table)?;
    let mut seen = BTreeSet::new();
    let mut unlisted = BTreeSet::new();
    let mut count = 0;
    for (index, line) in missed.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        count += 1;
        let key = parse_missed_line(line)
            .ok_or_else(|| format!("missed.txt line {}: malformed: {line:?}", index + 1))?;
        if listed.contains(&key) {
            seen.insert(key);
        } else {
            unlisted.insert(key);
        }
    }
    let stale = listed.difference(&seen).cloned().collect();
    Ok(Report {
        missed: count,
        unlisted: unlisted.into_iter().collect(),
        stale,
    })
}

fn strip_position(text: &str) -> &str {
    let mut rest = text;
    for _ in 0..2 {
        match rest.rsplit_once(':') {
            Some((head, tail)) if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) => {
                rest = head;
            }
            _ => return text,
        }
    }
    rest
}

fn parse_missed_line(line: &str) -> Option<Key> {
    let (location, description) = line.trim().split_once(": ")?;
    let file = strip_position(location);
    if file == location || file.is_empty() || description.trim().is_empty() {
        return None;
    }
    Some((file.to_string(), description.trim().to_string()))
}

fn cells(line: &str) -> Option<Vec<&str>> {
    let inner = line.trim().strip_prefix('|')?.strip_suffix('|')?;
    Some(inner.split('|').map(str::trim).collect())
}

fn unquote(cell: &str) -> &str {
    cell.strip_prefix('`')
        .and_then(|c| c.strip_suffix('`'))
        .unwrap_or(cell)
}

fn parse_table(table: &str) -> Result<BTreeSet<Key>, String> {
    let mut listed = BTreeSet::new();
    let mut header_seen = false;
    for (index, line) in table.lines().enumerate() {
        if !line.trim_start().starts_with('|') {
            continue;
        }
        let number = index + 1;
        let row = cells(line)
            .filter(|c| c.len() == 3)
            .ok_or_else(|| format!("table line {number}: malformed row: {line:?}"))?;
        if !header_seen {
            if row != ["file", "mutation", "reason"] {
                return Err(format!("table line {number}: expected the header row"));
            }
            header_seen = true;
            continue;
        }
        if row
            .iter()
            .all(|c| !c.is_empty() && c.bytes().all(|b| b == b'-' || b == b':'))
        {
            continue;
        }
        if row.iter().any(|c| c.is_empty()) {
            return Err(format!("table line {number}: empty cell: {line:?}"));
        }
        let file = strip_position(unquote(row[0]));
        let mutation = unquote(row[1]);
        listed.insert((file.to_string(), mutation.to_string()));
    }
    Ok(listed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "| file | mutation | reason |\n| --- | --- | --- |\n";

    fn table(rows: &str) -> String {
        format!("Intro text.\n\n{HEADER}{rows}")
    }

    fn key(file: &str, description: &str) -> Key {
        (file.to_string(), description.to_string())
    }

    #[test]
    fn empty_missed_and_empty_table_pass() {
        let report = check("", HEADER).unwrap();
        assert_eq!(
            report,
            Report {
                missed: 0,
                unlisted: vec![],
                stale: vec![]
            }
        );
    }

    #[test]
    fn unlisted_missed_mutant_is_reported() {
        let report = check(
            "src/glob.rs:10:5: replace == with != in matches_segment\n",
            HEADER,
        )
        .unwrap();
        assert_eq!(report.missed, 1);
        assert_eq!(
            report.unlisted,
            vec![key("src/glob.rs", "replace == with != in matches_segment")]
        );
    }

    #[test]
    fn listed_mutant_matches_even_when_line_and_column_differ() {
        let rows =
            "| `src/glob.rs` | `replace == with != in matches_segment` | no test can tell |\n";
        let report = check(
            "src/glob.rs:99:17: replace == with != in matches_segment\n",
            &table(rows),
        )
        .unwrap();
        assert!(report.unlisted.is_empty());
        assert!(report.stale.is_empty());
    }

    #[test]
    fn same_description_in_another_file_is_not_matched() {
        let rows = "| src/glob.rs | replace == with != in f | r |\n";
        let report = check("src/walk.rs:1:1: replace == with != in f\n", &table(rows)).unwrap();
        assert_eq!(
            report.unlisted,
            vec![key("src/walk.rs", "replace == with != in f")]
        );
        assert_eq!(
            report.stale,
            vec![key("src/glob.rs", "replace == with != in f")]
        );
    }

    #[test]
    fn same_file_different_description_is_not_matched() {
        let rows = "| src/glob.rs | replace == with != in f | r |\n";
        let report = check("src/glob.rs:1:1: replace == with != in g\n", &table(rows)).unwrap();
        assert_eq!(report.unlisted.len(), 1);
        assert_eq!(report.stale.len(), 1);
    }

    #[test]
    fn listed_entry_that_no_longer_occurs_is_stale() {
        let rows = "| src/exit.rs | replace code -> u8 with 0 | r |\n";
        let report = check("\n", &table(rows)).unwrap();
        assert_eq!(report.missed, 0);
        assert_eq!(
            report.stale,
            vec![key("src/exit.rs", "replace code -> u8 with 0")]
        );
    }

    #[test]
    fn row_with_too_few_cells_is_an_error() {
        let err = check("", &table("| src/exit.rs | replace x |\n")).unwrap_err();
        assert!(err.contains("malformed row"), "{err}");
    }

    #[test]
    fn row_with_too_many_cells_is_an_error() {
        let err = check("", &table("| a | b | c | d |\n")).unwrap_err();
        assert!(err.contains("malformed row"), "{err}");
    }

    #[test]
    fn row_with_an_empty_cell_is_an_error() {
        let err = check("", &table("| src/exit.rs | replace x | |\n")).unwrap_err();
        assert!(err.contains("empty cell"), "{err}");
    }

    #[test]
    fn row_without_closing_pipe_is_an_error() {
        let err = check("", &table("| src/exit.rs | replace x | why\n")).unwrap_err();
        assert!(err.contains("malformed row"), "{err}");
    }

    #[test]
    fn table_without_the_header_row_is_an_error() {
        let err = check("", "| src/a.rs | m | r |\n").unwrap_err();
        assert!(err.contains("header"), "{err}");
    }

    #[test]
    fn malformed_missed_line_is_an_error() {
        let err = check("src/glob.rs replace == with !=\n", HEADER).unwrap_err();
        assert!(err.contains("line 1"), "{err}");
    }

    #[test]
    fn missed_line_without_position_is_an_error() {
        let err = check("src/glob.rs: replace == with !=\n", HEADER).unwrap_err();
        assert!(err.contains("malformed"), "{err}");
    }

    #[test]
    fn strip_position_only_removes_two_numeric_suffixes() {
        assert_eq!(strip_position("src/a.rs:12:3"), "src/a.rs");
        assert_eq!(strip_position("src/a.rs:12"), "src/a.rs:12");
        assert_eq!(strip_position("src/a.rs"), "src/a.rs");
        assert_eq!(strip_position("a:x:3"), "a:x:3");
    }

    #[test]
    fn duplicate_missed_lines_are_counted_but_reported_once() {
        let line = "src/a.rs:1:1: replace x with y in f\n";
        let report = check(&format!("{line}{line}"), HEADER).unwrap();
        assert_eq!(report.missed, 2);
        assert_eq!(report.unlisted.len(), 1);
    }

    #[test]
    fn run_exit_codes_follow_the_ruling() {
        let dir = std::env::temp_dir().join(format!("xtask-mc-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let md = dir.join("e.md");
        let missed = dir.join("m.txt");
        let args = |a: &std::path::Path, b: &std::path::Path| {
            vec![a.display().to_string(), b.display().to_string()]
        };
        fs::write(&md, HEADER).unwrap();
        fs::write(&missed, "").unwrap();
        assert_eq!(run(&args(&missed, &md)), ExitCode::SUCCESS);
        fs::write(&missed, "src/a.rs:1:1: replace x with y in f\n").unwrap();
        assert_eq!(run(&args(&missed, &md)), ExitCode::from(1));
        fs::write(&md, "| bad |\n").unwrap();
        assert_eq!(run(&args(&missed, &md)), ExitCode::from(2));
        assert_eq!(run(&[]), ExitCode::from(2));
        fs::remove_dir_all(&dir).unwrap();
    }
}

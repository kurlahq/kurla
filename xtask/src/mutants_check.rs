use std::collections::BTreeMap;
use std::fs;
use std::process::ExitCode;

type Key = (String, String);

#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: Key,
    pub missed: usize,
    pub listed: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub missed: usize,
    pub unlisted: Vec<Entry>,
    pub stale: Vec<Entry>,
}

const REPORT_STALE: &str = "--report-stale";
const BACKSLASH: char = 92u8 as char;

pub fn run(args: &[String]) -> ExitCode {
    let report_stale = args.iter().any(|a| a == REPORT_STALE);
    let paths: Vec<&String> = args.iter().filter(|a| *a != REPORT_STALE).collect();
    let [missed_path, table_path] = paths.as_slice() else {
        eprintln!(
            "mutants-check: usage: mutants-check [--report-stale] <missed.txt> <equivalent-mutants.md>"
        );
        return ExitCode::from(2);
    };
    let read =
        |path: &String| fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"));
    let result = read(missed_path)
        .and_then(|missed| read(table_path).map(|table| (missed, table)))
        .and_then(|(missed, table)| check(&missed, &table));
    match result {
        Ok(report) => print_report(&report, report_stale),
        Err(message) => {
            eprintln!("mutants-check: {message}");
            ExitCode::from(2)
        }
    }
}

fn print_report(report: &Report, report_stale: bool) -> ExitCode {
    println!(
        "mutants-check: {} missed, {} unlisted",
        report.missed,
        report.unlisted.len()
    );
    for entry in &report.unlisted {
        println!(
            "UNLISTED {}: {} (missed {}, listed {})",
            entry.key.0, entry.key.1, entry.missed, entry.listed
        );
    }
    if report_stale {
        println!("mutants-check: {} stale", report.stale.len());
        for entry in &report.stale {
            println!(
                "warning: STALE {}: {} (listed {}, missed {})",
                entry.key.0, entry.key.1, entry.listed, entry.missed
            );
        }
    }
    if report.unlisted.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

pub fn check(missed: &str, table: &str) -> Result<Report, String> {
    let listed = parse_table(table)?;
    let mut counts: BTreeMap<Key, usize> = BTreeMap::new();
    let mut total = 0;
    for (index, line) in missed.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        total += 1;
        let key = parse_missed_line(line)
            .ok_or_else(|| format!("missed.txt line {}: malformed: {line:?}", index + 1))?;
        *counts.entry(key).or_insert(0) += 1;
    }
    let mut unlisted = Vec::new();
    for (key, count) in &counts {
        let rows = listed.get(key).copied().unwrap_or(0);
        if *count > rows {
            unlisted.push(Entry {
                key: key.clone(),
                missed: *count,
                listed: rows,
            });
        }
    }
    let mut stale = Vec::new();
    for (key, rows) in &listed {
        let count = counts.get(key).copied().unwrap_or(0);
        if *rows > count {
            stale.push(Entry {
                key: key.clone(),
                missed: count,
                listed: *rows,
            });
        }
    }
    Ok(Report {
        missed: total,
        unlisted,
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
    if file == location || file.is_empty() {
        return None;
    }
    Some((file.to_string(), description.trim().to_string()))
}

fn split_unescaped(line: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            BACKSLASH if chars.peek() == Some(&'|') => {
                chars.next();
                parts.last_mut().expect("one part").push('|');
            }
            '|' => parts.push(String::new()),
            other => parts.last_mut().expect("one part").push(other),
        }
    }
    parts
}

fn cells(line: &str) -> Option<Vec<String>> {
    let mut parts = split_unescaped(line.trim());
    if parts.len() < 2 || !parts[0].trim().is_empty() || !parts[parts.len() - 1].trim().is_empty() {
        return None;
    }
    parts.pop();
    parts.remove(0);
    Some(parts.into_iter().map(|p| p.trim().to_string()).collect())
}

fn unquote(cell: &str) -> &str {
    cell.strip_prefix('`')
        .and_then(|c| c.strip_suffix('`'))
        .unwrap_or(cell)
}

fn parse_table(table: &str) -> Result<BTreeMap<Key, usize>, String> {
    let mut listed: BTreeMap<Key, usize> = BTreeMap::new();
    let mut header_seen = false;
    for (index, line) in table.lines().enumerate() {
        let number = index + 1;
        if !line.trim_start().starts_with('|') {
            if split_unescaped(line).len() > 1 {
                return Err(format!(
                    "table line {number}: looks like a row but does not start with a pipe: {line:?}"
                ));
            }
            continue;
        }
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
        let file = strip_position(unquote(&row[0]));
        let mutation = unquote(&row[1]);
        *listed
            .entry((file.to_string(), mutation.to_string()))
            .or_insert(0) += 1;
    }
    if !header_seen {
        return Err("the table has no header row: file, mutation, reason".to_string());
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

    fn entry(file: &str, description: &str, missed: usize, listed: usize) -> Entry {
        Entry {
            key: (file.to_string(), description.to_string()),
            missed,
            listed,
        }
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
            vec![entry(
                "src/glob.rs",
                "replace == with != in matches_segment",
                1,
                0
            )]
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
            vec![entry("src/walk.rs", "replace == with != in f", 1, 0)]
        );
        assert_eq!(
            report.stale,
            vec![entry("src/glob.rs", "replace == with != in f", 0, 1)]
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
            vec![entry("src/exit.rs", "replace code -> u8 with 0", 0, 1)]
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
    fn duplicate_missed_lines_are_counted_and_each_needs_a_listed_row() {
        let line = "src/a.rs:1:1: replace x with y in f\n";
        let two = format!("{line}{line}");
        let report = check(&two, HEADER).unwrap();
        assert_eq!(report.missed, 2);
        assert_eq!(
            report.unlisted,
            vec![entry("src/a.rs", "replace x with y in f", 2, 0)]
        );
        let one_row = table("| src/a.rs | replace x with y in f | r |\n");
        let report = check(&two, &one_row).unwrap();
        assert_eq!(
            report.unlisted,
            vec![entry("src/a.rs", "replace x with y in f", 2, 1)]
        );
        let two_rows = table(
            "| src/a.rs | replace x with y in f | r |\n| src/a.rs:5:1 | replace x with y in f | r |\n",
        );
        let report = check(&two, &two_rows).unwrap();
        assert!(report.unlisted.is_empty(), "{report:?}");
        assert!(report.stale.is_empty(), "{report:?}");
    }

    #[test]
    fn more_listed_rows_than_missed_occurrences_is_stale_with_both_counts() {
        let rows =
            "| src/a.rs | replace x with y in f | r |\n| src/a.rs | replace x with y in f | r |\n";
        let report = check("src/a.rs:1:1: replace x with y in f\n", &table(rows)).unwrap();
        assert!(report.unlisted.is_empty());
        assert_eq!(
            report.stale,
            vec![entry("src/a.rs", "replace x with y in f", 1, 2)]
        );
    }

    #[test]
    fn a_stale_only_run_exits_0_with_or_without_the_flag() {
        let dir = std::env::temp_dir().join(format!("xtask-mc-stale-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let md = dir.join("e.md");
        let missed = dir.join("m.txt");
        fs::write(&md, table("| src/a.rs | replace x with y in f | r |\n")).unwrap();
        fs::write(&missed, "").unwrap();
        let (m, e) = (missed.display().to_string(), md.display().to_string());
        assert_eq!(run(&[m.clone(), e.clone()]), ExitCode::SUCCESS);
        assert_eq!(
            run(&["--report-stale".to_string(), m, e]),
            ExitCode::SUCCESS
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unknown_flag_is_a_usage_error() {
        assert_eq!(
            run(&["--bogus".to_string(), "a".to_string(), "b".to_string()]),
            ExitCode::from(2)
        );
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

    #[test]
    fn escaped_pipes_in_a_row_are_unescaped_before_matching() {
        let bs = char::from(92u8);
        let rows = format!("| src/a.rs | replace {bs}|{bs}| with && in f | r |\n");
        let report = check("src/a.rs:3:5: replace || with && in f\n", &table(&rows)).unwrap();
        assert!(report.unlisted.is_empty(), "{report:?}");
        assert!(report.stale.is_empty(), "{report:?}");
    }

    #[test]
    fn a_second_missed_occurrence_needs_its_own_listed_row() {
        let rows = "| src/a.rs | replace == with != in f | r |\n";
        let missed =
            "src/a.rs:3:5: replace == with != in f\nsrc/a.rs:9:5: replace == with != in f\n";
        let report = check(missed, &table(rows)).unwrap();
        assert_eq!(report.unlisted.len(), 1, "{report:?}");
    }

    #[test]
    fn a_prose_line_containing_a_pipe_is_an_error() {
        let doc = format!("src/a.rs | m | r |\n{HEADER}");
        let err = check("", &doc).unwrap_err();
        assert!(err.contains("looks like a row"), "{err}");
    }

    #[test]
    fn a_document_without_a_table_is_an_error() {
        let err = check("", "Only prose.\n").unwrap_err();
        assert!(err.contains("header"), "{err}");
    }

    #[test]
    fn a_missed_line_with_an_empty_file_name_is_an_error() {
        let err = check(":1:1: replace x with y in f\n", HEADER).unwrap_err();
        assert!(err.contains("malformed"), "{err}");
    }

    #[test]
    fn unquote_strips_exactly_one_pair_of_backticks() {
        assert_eq!(unquote("`x`"), "x");
        assert_eq!(unquote("``x``"), "`x`");
        assert_eq!(unquote("`x"), "`x");
        assert_eq!(unquote("`"), "`");
    }

    #[test]
    fn the_committed_equivalent_mutants_document_parses_and_starts_without_entries() {
        let document = include_str!("../../docs/equivalent-mutants.md");
        let report = check("", document).unwrap();
        assert_eq!(report.missed, 0);
        assert!(report.stale.is_empty(), "{report:?}");
    }
}

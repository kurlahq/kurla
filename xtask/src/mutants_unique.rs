use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

type ReadLog = dyn Fn(&str) -> Result<String, String>;

pub struct Source {
    pub outcomes: String,
    pub read_log: Box<ReadLog>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Analysis {
    pub directories: usize,
    pub tests_seen: usize,
    pub caught: usize,
    pub missed: usize,
    pub timeout: usize,
    pub unviable: usize,
    pub other: usize,
    pub caught_by_exactly_one: usize,
    pub never_sole: Vec<String>,
    pub no_failing_test: Vec<String>,
    pub timed_out: Vec<String>,
}

pub fn run(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("mutants-unique: usage: mutants-unique <mutants.out dir>...");
        return ExitCode::from(2);
    }
    let sources: Result<Vec<Source>, String> =
        args.iter().map(|d| load_dir(Path::new(d))).collect();
    match sources.and_then(|s| analyze(&s)) {
        Ok(analysis) => {
            print!("{}", render(&analysis));
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("mutants-unique: {message}");
            ExitCode::from(2)
        }
    }
}

fn load_dir(dir: &Path) -> Result<Source, String> {
    let outcomes_path = dir.join("outcomes.json");
    let outcomes = fs::read_to_string(&outcomes_path)
        .map_err(|e| format!("cannot read {}: {e}", outcomes_path.display()))?;
    let base = dir.to_path_buf();
    Ok(Source {
        outcomes,
        read_log: Box::new(move |log_path| {
            let path = base.join(log_path);
            fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
        }),
    })
}

#[derive(Default)]
struct Tally {
    caught: usize,
    missed: usize,
    timeout: usize,
    unviable: usize,
    other: usize,
}

fn top_level(root: &Value, field: &str) -> Result<usize, String> {
    root.get(field)
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .ok_or_else(|| format!("outcomes.json is missing the top-level count {field}"))
}

fn cross_check(root: &Value, tally: &Tally) -> Result<(), String> {
    let total = tally.caught + tally.missed + tally.timeout + tally.unviable + tally.other;
    let expected = [
        ("caught", tally.caught),
        ("missed", tally.missed),
        ("timeout", tally.timeout),
        ("unviable", tally.unviable),
        ("total_mutants", total),
    ];
    for (field, counted) in expected {
        let stated = top_level(root, field)?;
        if stated != counted {
            return Err(format!(
                "outcomes.json says {field} is {stated} but its outcomes list {counted}"
            ));
        }
    }
    top_level(root, "success")?;
    Ok(())
}

pub fn analyze(sources: &[Source]) -> Result<Analysis, String> {
    let mut seen = BTreeSet::new();
    let mut sole: BTreeMap<String, usize> = BTreeMap::new();
    let mut tally = Tally::default();
    let mut by_one = 0;
    let mut no_failing = Vec::new();
    let mut timed_out = Vec::new();
    for source in sources {
        let root: Value = serde_json::from_str(&source.outcomes)
            .map_err(|e| format!("outcomes.json is not JSON: {e}"))?;
        let list = root
            .get("outcomes")
            .and_then(Value::as_array)
            .ok_or("outcomes.json has no outcomes array")?;
        let mut local = Tally::default();
        for (index, outcome) in list.iter().enumerate() {
            let summary = outcome
                .get("summary")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("outcome {index} has no summary"))?;
            let Some(mutant) = outcome.get("scenario").and_then(|s| s.get("Mutant")) else {
                continue;
            };
            let log_path = outcome
                .get("log_path")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("outcome {index} has no log_path"))?;
            let name = mutant
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("outcome {index} has no mutant name"))?;
            let log = (source.read_log)(log_path)?;
            let (names, failed) = parse_log(&log);
            seen.extend(names);
            match summary {
                "MissedMutant" => local.missed += 1,
                "Unviable" => local.unviable += 1,
                "Timeout" => {
                    local.timeout += 1;
                    timed_out.push(name.to_string());
                }
                "CaughtMutant" => {
                    local.caught += 1;
                    match failed.len() {
                        0 => no_failing.push(name.to_string()),
                        1 => {
                            by_one += 1;
                            for test in failed {
                                *sole.entry(test).or_insert(0) += 1;
                            }
                        }
                        _ => {}
                    }
                }
                _ => local.other += 1,
            }
        }
        cross_check(&root, &local)?;
        tally.caught += local.caught;
        tally.missed += local.missed;
        tally.timeout += local.timeout;
        tally.unviable += local.unviable;
        tally.other += local.other;
    }
    let never_sole = seen
        .iter()
        .filter(|test| !sole.contains_key(*test))
        .cloned()
        .collect();
    Ok(Analysis {
        directories: sources.len(),
        tests_seen: seen.len(),
        caught: tally.caught,
        missed: tally.missed,
        timeout: tally.timeout,
        unviable: tally.unviable,
        other: tally.other,
        caught_by_exactly_one: by_one,
        never_sole,
        no_failing_test: no_failing,
        timed_out,
    })
}

fn parse_log(log: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut seen = BTreeSet::new();
    let mut failed = BTreeSet::new();
    for line in log.lines() {
        let Some(rest) = line.strip_prefix("test ") else {
            continue;
        };
        let Some((name, status)) = rest.rsplit_once(" ... ") else {
            continue;
        };
        let word = status.split([' ', ',']).next().unwrap_or("");
        if !matches!(word, "ok" | "FAILED" | "ignored") || name.is_empty() {
            continue;
        }
        seen.insert(name.to_string());
        if word == "FAILED" {
            failed.insert(name.to_string());
        }
    }
    (seen, failed)
}

const HEADER_NOTE: &str = "note: sole-catcher counts are complete only for a run with --no-fail-fast; cargo-mutants does not record its test arguments in mutants.out, so per-binary fail-fast may hide catches";

pub fn render(analysis: &Analysis) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "mutants.out directories merged: {}",
        analysis.directories
    );
    let _ = writeln!(out, "{HEADER_NOTE}");
    for test in &analysis.never_sole {
        let _ = writeln!(out, "never the sole catcher: {test}");
    }
    for mutant in &analysis.no_failing_test {
        let _ = writeln!(out, "caught with no failing test in its log: {mutant}");
    }
    for mutant in &analysis.timed_out {
        let _ = writeln!(out, "timed out: {mutant}");
    }
    let _ = writeln!(out, "tests seen: {}", analysis.tests_seen);
    let _ = writeln!(out, "mutants caught: {}", analysis.caught);
    let _ = writeln!(out, "mutants missed: {}", analysis.missed);
    let _ = writeln!(out, "mutants timed out: {}", analysis.timeout);
    let _ = writeln!(out, "mutants unviable: {}", analysis.unviable);
    let _ = writeln!(out, "mutants with another summary: {}", analysis.other);
    let _ = writeln!(
        out,
        "mutants caught by exactly one test: {}",
        analysis.caught_by_exactly_one
    );
    let _ = writeln!(
        out,
        "tests that are the sole catcher of zero mutants: {}",
        analysis.never_sole.len()
    );
    let _ = writeln!(
        out,
        "mutants caught with no failing test in their log: {}",
        analysis.no_failing_test.len()
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_NOTE: &str = "note: sole-catcher counts are complete only for a run with --no-fail-fast; cargo-mutants does not record its test arguments in mutants.out, so per-binary fail-fast may hide catches\n";

    const OUTCOMES: &str = r#"{"caught":3,"missed":1,"timeout":1,"unviable":1,"success":0,"total_mutants":6,"outcomes":[
      {"scenario":"Baseline","summary":"Success","log_path":"log/baseline.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:1:1: replace f -> bool with true"}},"summary":"CaughtMutant","log_path":"log/m1.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:2:1: replace g -> bool with false"}},"summary":"CaughtMutant","log_path":"log/m2.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:3:1: replace h -> () with ()"}},"summary":"CaughtMutant","log_path":"log/m3.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:4:1: replace i -> bool with true"}},"summary":"MissedMutant","log_path":"log/m4.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:5:1: replace j -> u8 with 1"}},"summary":"Unviable","log_path":"log/m5.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:6:1: replace k -> u8 with 0"}},"summary":"Timeout","log_path":"log/m6.log"}
    ]}"#;

    fn logs(path: &str) -> Result<String, String> {
        let text = match path {
            "log/baseline.log" => "test t1 ... ok\ntest t2 ... ok\n",
            "log/m1.log" => {
                "Running unittests\ntest t1 ... FAILED\ntest t2 ... ok\ntest t3 ... ok\ntest result: FAILED. 2 passed; 1 failed\n"
            }
            "log/m2.log" => "test t1 ... FAILED\ntest t2 ... FAILED\n",
            "log/m3.log" => "error[E0308]: mismatched types\n",
            "log/m4.log" => "test t1 ... ok\ntest t2 ... ok\ntest t3 ... ok\ntest t4 ... ok\n",
            "log/m5.log" => "error: could not compile\n",
            "log/m6.log" => "test t1 ... ok\n",
            other => return Err(format!("no such log {other}")),
        };
        Ok(text.to_string())
    }

    type Reader = fn(&str) -> Result<String, String>;

    fn source(outcomes: &str) -> Source {
        one(outcomes, logs)
    }

    fn one(outcomes: &str, read: Reader) -> Source {
        Source {
            outcomes: outcomes.to_string(),
            read_log: Box::new(read),
        }
    }

    fn counts(
        caught: usize,
        missed: usize,
        timeout: usize,
        unviable: usize,
        other: usize,
    ) -> String {
        let total = caught + missed + timeout + unviable + other;
        format!(
            r#""caught":{caught},"missed":{missed},"timeout":{timeout},"unviable":{unviable},"success":{other},"total_mutants":{total}"#
        )
    }

    fn mutant(name: &str, summary: &str, log: &str) -> String {
        format!(
            r#"{{"scenario":{{"Mutant":{{"name":"{name}"}}}},"summary":"{summary}","log_path":"{log}"}}"#
        )
    }

    fn document(counts: String, mutants: &[String]) -> String {
        format!(r#"{{{counts},"outcomes":[{}]}}"#, mutants.join(","))
    }

    #[test]
    fn sole_catchers_and_summary_counts_match_the_hand_written_fixture() {
        let analysis = analyze(&[source(OUTCOMES)]).unwrap();
        assert_eq!(
            analysis,
            Analysis {
                directories: 1,
                tests_seen: 4,
                caught: 3,
                missed: 1,
                timeout: 1,
                unviable: 1,
                other: 0,
                caught_by_exactly_one: 1,
                never_sole: vec!["t2".into(), "t3".into(), "t4".into()],
                no_failing_test: vec!["src/a.rs:3:1: replace h -> () with ()".into()],
                timed_out: vec!["src/a.rs:6:1: replace k -> u8 with 0".into()],
            }
        );
    }

    #[test]
    fn a_test_that_alone_catches_two_mutants_counts_both() {
        let outcomes = document(
            counts(2, 0, 0, 0, 0),
            &[
                mutant("x", "CaughtMutant", "a"),
                mutant("y", "CaughtMutant", "b"),
            ],
        );
        let read: Reader = |_| Ok("test only ... FAILED\ntest other ... ok\n".to_string());
        let analysis = analyze(&[one(&outcomes, read)]).unwrap();
        assert_eq!(analysis.caught_by_exactly_one, 2);
        assert_eq!(analysis.never_sole, vec!["other".to_string()]);
    }

    #[test]
    fn missed_mutant_failures_do_not_count_as_catches() {
        let outcomes = document(counts(0, 1, 0, 0, 0), &[mutant("x", "MissedMutant", "a")]);
        let read: Reader = |_| Ok("test t ... FAILED\n".to_string());
        let analysis = analyze(&[one(&outcomes, read)]).unwrap();
        assert_eq!(analysis.caught, 0);
        assert_eq!(analysis.missed, 1);
        assert_eq!(analysis.caught_by_exactly_one, 0);
        assert_eq!(analysis.never_sole, vec!["t".to_string()]);
    }

    #[test]
    fn every_summary_category_is_counted_including_other() {
        let outcomes = document(
            counts(1, 1, 1, 1, 1),
            &[
                mutant("a", "CaughtMutant", "l"),
                mutant("b", "MissedMutant", "l"),
                mutant("c", "Timeout", "l"),
                mutant("d", "Unviable", "l"),
                mutant("e", "Success", "l"),
            ],
        );
        let read: Reader = |_| Ok(String::new());
        let analysis = analyze(&[one(&outcomes, read)]).unwrap();
        assert_eq!(
            (
                analysis.caught,
                analysis.missed,
                analysis.timeout,
                analysis.unviable,
                analysis.other
            ),
            (1, 1, 1, 1, 1)
        );
    }

    #[test]
    fn a_top_level_count_that_disagrees_with_the_outcomes_is_an_error() {
        let outcomes = document(counts(2, 0, 0, 0, 0), &[mutant("a", "CaughtMutant", "l")]);
        let read: Reader = |_| Ok(String::new());
        let err = analyze(&[one(&outcomes, read)]).unwrap_err();
        assert!(err.contains("caught"), "{err}");
        assert!(err.contains('2') && err.contains('1'), "{err}");
    }

    #[test]
    fn a_missing_top_level_count_is_an_error() {
        let outcomes = format!(r#"{{"outcomes":[{}]}}"#, mutant("a", "CaughtMutant", "l"));
        let read: Reader = |_| Ok(String::new());
        let err = analyze(&[one(&outcomes, read)]).unwrap_err();
        assert!(err.contains("missing"), "{err}");
    }

    #[test]
    fn the_total_must_equal_the_number_of_mutant_outcomes() {
        let outcomes = format!(
            r#"{{"caught":1,"missed":0,"timeout":0,"unviable":0,"success":0,"total_mutants":5,"outcomes":[{}]}}"#,
            mutant("a", "CaughtMutant", "l")
        );
        let read: Reader = |_| Ok(String::new());
        let err = analyze(&[one(&outcomes, read)]).unwrap_err();
        assert!(err.contains("total_mutants"), "{err}");
    }

    #[test]
    fn unreadable_log_is_an_error_not_a_skip() {
        let outcomes = document(
            counts(1, 0, 0, 0, 0),
            &[mutant("x", "CaughtMutant", "gone")],
        );
        let err = analyze(&[source(&outcomes)]).unwrap_err();
        assert!(err.contains("no such log gone"), "{err}");
    }

    #[test]
    fn outcomes_without_the_array_is_an_error() {
        let err = analyze(&[source("{}")]).unwrap_err();
        assert!(err.contains("no outcomes array"), "{err}");
        let err = analyze(&[source("not json")]).unwrap_err();
        assert!(err.contains("not JSON"), "{err}");
    }

    #[test]
    fn mutant_outcome_without_a_log_path_is_an_error() {
        let outcomes = document(
            counts(1, 0, 0, 0, 0),
            &[r#"{"scenario":{"Mutant":{"name":"x"}},"summary":"CaughtMutant"}"#.to_string()],
        );
        let err = analyze(&[source(&outcomes)]).unwrap_err();
        assert!(err.contains("log_path"), "{err}");
    }

    #[test]
    fn merging_directories_uses_every_directory_for_sole_catches() {
        let out_a = document(counts(1, 0, 0, 0, 0), &[mutant("a", "CaughtMutant", "a")]);
        let out_b = document(counts(1, 0, 0, 0, 0), &[mutant("b", "CaughtMutant", "b")]);
        let read_a: Reader = |_| Ok("test t1 ... FAILED\ntest t2 ... ok\n".to_string());
        let read_b: Reader = |_| Ok("test t1 ... ok\ntest t2 ... FAILED\n".to_string());
        let alone = analyze(&[one(&out_a, read_a)]).unwrap();
        assert_eq!(alone.never_sole, vec!["t2".to_string()]);
        let merged = analyze(&[one(&out_a, read_a), one(&out_b, read_b)]).unwrap();
        assert_eq!(merged.directories, 2);
        assert_eq!(merged.caught, 2);
        assert_eq!(merged.caught_by_exactly_one, 2);
        assert!(merged.never_sole.is_empty(), "{merged:?}");
    }

    #[test]
    fn log_lines_are_parsed_from_every_binary_and_summary_lines_are_ignored() {
        let log = "Running unittests src/lib.rs\ntest a::b ... ok\ntest c ... ignored, slow\ntest result: ok. 1 passed\nRunning tests/e2e.rs\ntest d ... FAILED\ntest e ... bench: 3 ns\nsome test x ... FAILED\n";
        let (seen, failed) = parse_log(log);
        let names: Vec<&str> = seen.iter().map(String::as_str).collect();
        assert_eq!(names, ["a::b", "c", "d"]);
        let failed: Vec<&str> = failed.iter().map(String::as_str).collect();
        assert_eq!(failed, ["d"]);
    }

    #[test]
    fn render_prints_the_header_the_zero_sole_tests_the_unexplained_catches_the_timeouts_and_the_summary()
     {
        let analysis = analyze(&[source(OUTCOMES)]).unwrap();
        let text = render(&analysis);
        let expected = format!(
            "mutants.out directories merged: 1\n{HEADER_NOTE}never the sole catcher: t2\nnever the sole catcher: t3\nnever the sole catcher: t4\ncaught with no failing test in its log: src/a.rs:3:1: replace h -> () with ()\ntimed out: src/a.rs:6:1: replace k -> u8 with 0\ntests seen: 4\nmutants caught: 3\nmutants missed: 1\nmutants timed out: 1\nmutants unviable: 1\nmutants with another summary: 0\nmutants caught by exactly one test: 1\ntests that are the sole catcher of zero mutants: 3\nmutants caught with no failing test in their log: 1\n"
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn run_reads_several_directories_and_rejects_bad_usage() {
        let root = std::env::temp_dir().join(format!("xtask-mu-{}", std::process::id()));
        let dirs: Vec<String> = ["one", "two"]
            .iter()
            .map(|name| {
                let dir = root.join(name);
                fs::create_dir_all(dir.join("log")).unwrap();
                fs::write(dir.join("outcomes.json"), OUTCOMES).unwrap();
                for log in ["baseline", "m1", "m2", "m3", "m4", "m5", "m6"] {
                    let path = format!("log/{log}.log");
                    fs::write(dir.join(&path), logs(&path).unwrap()).unwrap();
                }
                dir.display().to_string()
            })
            .collect();
        assert_eq!(run(&dirs), ExitCode::SUCCESS);
        fs::remove_file(root.join("two/log/m4.log")).unwrap();
        assert_eq!(run(&dirs), ExitCode::from(2));
        assert_eq!(run(&[]), ExitCode::from(2));
        fs::remove_dir_all(&root).unwrap();
    }
}

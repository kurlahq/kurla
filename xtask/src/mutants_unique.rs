use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

#[derive(Debug, PartialEq, Eq)]
pub struct Analysis {
    pub tests_seen: usize,
    pub caught: usize,
    pub caught_by_exactly_one: usize,
    pub never_sole: Vec<String>,
    pub no_failing_test: Vec<String>,
}

pub fn run(args: &[String]) -> ExitCode {
    let [dir] = args else {
        eprintln!("mutants-unique: usage: mutants-unique <mutants.out dir>");
        return ExitCode::from(2);
    };
    match analyze_dir(Path::new(dir)) {
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

fn analyze_dir(dir: &Path) -> Result<Analysis, String> {
    let outcomes_path = dir.join("outcomes.json");
    let outcomes = fs::read_to_string(&outcomes_path)
        .map_err(|e| format!("cannot read {}: {e}", outcomes_path.display()))?;
    analyze(&outcomes, &|log_path| {
        let path = dir.join(log_path);
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    })
}

pub fn analyze(
    outcomes: &str,
    read_log: &dyn Fn(&str) -> Result<String, String>,
) -> Result<Analysis, String> {
    let root: Value =
        serde_json::from_str(outcomes).map_err(|e| format!("outcomes.json is not JSON: {e}"))?;
    let list = root
        .get("outcomes")
        .and_then(Value::as_array)
        .ok_or("outcomes.json has no outcomes array")?;
    let mut seen = BTreeSet::new();
    let mut sole: BTreeMap<String, usize> = BTreeMap::new();
    let mut caught = 0;
    let mut by_one = 0;
    let mut no_failing = Vec::new();
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
        let log = read_log(log_path)?;
        let (names, failed) = parse_log(&log);
        seen.extend(names);
        if summary != "CaughtMutant" {
            continue;
        }
        caught += 1;
        match failed.len() {
            0 => {
                let name = mutant
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("outcome {index} has no mutant name"))?;
                no_failing.push(name.to_string());
            }
            1 => {
                by_one += 1;
                for test in failed {
                    *sole.entry(test).or_insert(0) += 1;
                }
            }
            _ => {}
        }
    }
    let never_sole = seen
        .iter()
        .filter(|test| !sole.contains_key(*test))
        .cloned()
        .collect();
    Ok(Analysis {
        tests_seen: seen.len(),
        caught,
        caught_by_exactly_one: by_one,
        never_sole,
        no_failing_test: no_failing,
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

pub fn render(analysis: &Analysis) -> String {
    let mut out = String::new();
    for test in &analysis.never_sole {
        let _ = writeln!(out, "never the sole catcher: {test}");
    }
    for mutant in &analysis.no_failing_test {
        let _ = writeln!(out, "caught with no failing test in its log: {mutant}");
    }
    let _ = writeln!(out, "tests seen: {}", analysis.tests_seen);
    let _ = writeln!(out, "mutants caught: {}", analysis.caught);
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

    const OUTCOMES: &str = r#"{"outcomes":[
      {"scenario":"Baseline","summary":"Success","log_path":"log/baseline.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:1:1: replace f -> bool with true"}},"summary":"CaughtMutant","log_path":"log/m1.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:2:1: replace g -> bool with false"}},"summary":"CaughtMutant","log_path":"log/m2.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:3:1: replace h -> () with ()"}},"summary":"CaughtMutant","log_path":"log/m3.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:4:1: replace i -> bool with true"}},"summary":"MissedMutant","log_path":"log/m4.log"},
      {"scenario":{"Mutant":{"name":"src/a.rs:5:1: replace j -> u8 with 1"}},"summary":"Unviable","log_path":"log/m5.log"}
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
            other => return Err(format!("no such log {other}")),
        };
        Ok(text.to_string())
    }

    #[test]
    fn sole_catchers_and_summary_counts_match_the_hand_written_fixture() {
        let analysis = analyze(OUTCOMES, &logs).unwrap();
        assert_eq!(
            analysis,
            Analysis {
                tests_seen: 4,
                caught: 3,
                caught_by_exactly_one: 1,
                never_sole: vec!["t2".into(), "t3".into(), "t4".into()],
                no_failing_test: vec!["src/a.rs:3:1: replace h -> () with ()".into()],
            }
        );
    }

    #[test]
    fn a_test_that_alone_catches_two_mutants_counts_both() {
        let outcomes = r#"{"outcomes":[
          {"scenario":{"Mutant":{"name":"x"}},"summary":"CaughtMutant","log_path":"a"},
          {"scenario":{"Mutant":{"name":"y"}},"summary":"CaughtMutant","log_path":"b"}]}"#;
        let read = |_: &str| Ok("test only ... FAILED\ntest other ... ok\n".to_string());
        let analysis = analyze(outcomes, &read).unwrap();
        assert_eq!(analysis.caught_by_exactly_one, 2);
        assert_eq!(analysis.never_sole, vec!["other".to_string()]);
    }

    #[test]
    fn missed_mutant_failures_do_not_count_as_catches() {
        let outcomes = r#"{"outcomes":[
          {"scenario":{"Mutant":{"name":"x"}},"summary":"MissedMutant","log_path":"a"}]}"#;
        let read = |_: &str| Ok("test t ... FAILED\n".to_string());
        let analysis = analyze(outcomes, &read).unwrap();
        assert_eq!(analysis.caught, 0);
        assert_eq!(analysis.caught_by_exactly_one, 0);
        assert_eq!(analysis.never_sole, vec!["t".to_string()]);
    }

    #[test]
    fn unreadable_log_is_an_error_not_a_skip() {
        let outcomes = r#"{"outcomes":[
          {"scenario":{"Mutant":{"name":"x"}},"summary":"CaughtMutant","log_path":"gone"}]}"#;
        let err = analyze(outcomes, &logs).unwrap_err();
        assert!(err.contains("no such log gone"), "{err}");
    }

    #[test]
    fn outcomes_without_the_array_is_an_error() {
        let err = analyze("{}", &logs).unwrap_err();
        assert!(err.contains("no outcomes array"), "{err}");
        let err = analyze("not json", &logs).unwrap_err();
        assert!(err.contains("not JSON"), "{err}");
    }

    #[test]
    fn mutant_outcome_without_a_log_path_is_an_error() {
        let outcomes = r#"{"outcomes":[
          {"scenario":{"Mutant":{"name":"x"}},"summary":"CaughtMutant"}]}"#;
        let err = analyze(outcomes, &logs).unwrap_err();
        assert!(err.contains("log_path"), "{err}");
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
    fn render_prints_every_zero_sole_test_the_unexplained_catches_and_the_summary() {
        let analysis = analyze(OUTCOMES, &logs).unwrap();
        let text = render(&analysis);
        let expected = "never the sole catcher: t2\nnever the sole catcher: t3\nnever the sole catcher: t4\ncaught with no failing test in its log: src/a.rs:3:1: replace h -> () with ()\ntests seen: 4\nmutants caught: 3\nmutants caught by exactly one test: 1\ntests that are the sole catcher of zero mutants: 3\nmutants caught with no failing test in their log: 1\n";
        assert_eq!(text, expected);
    }

    #[test]
    fn run_reads_the_mutants_out_layout_and_rejects_bad_usage() {
        let dir = std::env::temp_dir().join(format!("xtask-mu-{}", std::process::id()));
        fs::create_dir_all(dir.join("log")).unwrap();
        fs::write(dir.join("outcomes.json"), OUTCOMES).unwrap();
        for name in ["baseline", "m1", "m2", "m3", "m4", "m5"] {
            let path = format!("log/{name}.log");
            fs::write(dir.join(&path), logs(&path).unwrap()).unwrap();
        }
        assert_eq!(run(&[dir.display().to_string()]), ExitCode::SUCCESS);
        fs::remove_file(dir.join("log/m4.log")).unwrap();
        assert_eq!(run(&[dir.display().to_string()]), ExitCode::from(2));
        assert_eq!(run(&[]), ExitCode::from(2));
        fs::remove_dir_all(&dir).unwrap();
    }
}

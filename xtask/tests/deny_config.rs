use std::fs;
use std::path::{Path, PathBuf};

const FUZZ_EXCEPTION: &str = r#"exceptions = [{ crate = "libfuzzer-sys", allow = ["NCSA"] }]"#;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn read(relative: &str) -> String {
    fs::read_to_string(repo_root().join(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

fn fuzz_config_problem(root: &str, fuzz: &str) -> Option<String> {
    if root
        .lines()
        .any(|line| line.trim_start().starts_with("exceptions"))
    {
        return Some("the root deny.toml holds a licence exception".to_string());
    }
    let root_lines: Vec<&str> = root.lines().collect();
    let fuzz_lines: Vec<&str> = fuzz.lines().collect();
    let Some(at) = fuzz_lines.iter().position(|line| *line == FUZZ_EXCEPTION) else {
        return Some("fuzz/deny.toml lacks the libfuzzer-sys exception".to_string());
    };
    let mut without: Vec<&str> = fuzz_lines.clone();
    without.remove(at);
    if without != root_lines {
        return Some(
            "fuzz/deny.toml differs from the root deny.toml by more than the exception".to_string(),
        );
    }
    if at == 0 || !fuzz_lines[at - 1].starts_with("allow = ") {
        return Some("the exception does not follow the allow list".to_string());
    }
    None
}

#[test]
fn the_fuzz_deny_config_is_the_root_config_plus_the_one_exception() {
    assert_eq!(
        fuzz_config_problem(&read("deny.toml"), &read("fuzz/deny.toml")),
        None
    );
}

#[test]
fn the_config_check_rejects_an_exception_in_the_root_or_any_other_difference() {
    let root = "[licenses]\nallow = [\"MIT\"]\n";
    let fuzz = format!("[licenses]\nallow = [\"MIT\"]\n{FUZZ_EXCEPTION}\n");
    assert_eq!(fuzz_config_problem(root, &fuzz), None);
    let root_with_exception = format!("[licenses]\nallow = [\"MIT\"]\n{FUZZ_EXCEPTION}\n");
    assert!(fuzz_config_problem(&root_with_exception, &fuzz).is_some());
    assert!(fuzz_config_problem(root, root).is_some());
    let drifted = format!("[licenses]\nallow = [\"MIT\", \"Zlib\"]\n{FUZZ_EXCEPTION}\n");
    assert!(fuzz_config_problem(root, &drifted).is_some());
    let misplaced = format!("{FUZZ_EXCEPTION}\n[licenses]\nallow = [\"MIT\"]\n");
    assert!(fuzz_config_problem(root, &misplaced).is_some());
}

#[test]
fn only_the_fuzz_deny_step_uses_the_fuzz_config() {
    let ci = read(".github/workflows/ci.yml");
    let deny_lines: Vec<&str> = ci.lines().filter(|l| l.contains("cargo deny")).collect();
    assert_eq!(deny_lines.len(), 2, "{deny_lines:?}");
    assert!(
        deny_lines[0].ends_with("cargo deny check"),
        "{}",
        deny_lines[0]
    );
    assert!(
        deny_lines[1]
            .ends_with("cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check"),
        "{}",
        deny_lines[1]
    );
}

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn read(relative: &str) -> String {
    fs::read_to_string(repo_root().join(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

fn workflow_and_action_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(repo_root().join(".github/workflows")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yml") {
            files.push(path);
        }
    }
    for entry in fs::read_dir(repo_root().join(".github/actions")).unwrap() {
        let path = entry.unwrap().path().join("action.yml");
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    files
}

const BACKSLASH: char = 92u8 as char;

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim();
    let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim_start();
    trimmed
        .strip_prefix(key)
        .and_then(|rest| rest.strip_prefix(':'))
        .map(str::trim)
}

fn uses_values(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| key_value(line, "uses"))
        .map(|value| value.trim_matches(|c| c == '"' || c == '\'').to_string())
        .collect()
}

fn is_pinned(value: &str) -> bool {
    if value.starts_with("./") {
        return true;
    }
    let Some((name, reference)) = value.split_once('@') else {
        return false;
    };
    name.contains('/')
        && !name.contains(char::is_whitespace)
        && reference.len() == 40
        && reference
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn run_scripts(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut scripts = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        index += 1;
        let Some(value) = key_value(line, "run") else {
            continue;
        };
        if !value.starts_with('|') && !value.starts_with('>') {
            scripts.push(value.to_string());
            continue;
        }
        let base = indent_of(line);
        let mut body = Vec::new();
        while index < lines.len()
            && (lines[index].trim().is_empty() || indent_of(lines[index]) > base)
        {
            body.push(lines[index].trim());
            index += 1;
        }
        scripts.push(body.join("\n").trim().to_string());
    }
    scripts
}

fn release_invocations(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !lines[index].contains("gh release") {
            index += 1;
            continue;
        }
        let mut joined = lines[index].trim().to_string();
        while joined.ends_with(BACKSLASH) && index + 1 < lines.len() {
            joined.pop();
            index += 1;
            joined.push(' ');
            joined.push_str(lines[index].trim());
        }
        found.push(joined);
        index += 1;
    }
    found
}

fn draft_violation(text: &str) -> Option<String> {
    let invocations = release_invocations(text);
    if invocations.len() != 1 {
        return Some(format!(
            "expected exactly one gh release invocation, found {}",
            invocations.len()
        ));
    }
    let tokens: Vec<&str> = invocations[0].split_whitespace().collect();
    let creates = tokens
        .windows(3)
        .any(|w| w[0] == "gh" && w[1] == "release" && w[2] == "create");
    if !creates {
        return Some("the gh release invocation is not a create".to_string());
    }
    if !tokens.contains(&"--draft") {
        return Some("the gh release create has no --draft".to_string());
    }
    for forbidden in ["--draft=", "gh release edit", "gh api"] {
        if text.contains(forbidden) {
            return Some(format!("found {forbidden}"));
        }
    }
    None
}

fn contents_write_violation(text: &str) -> Option<String> {
    let mut job: Option<String> = None;
    let mut in_jobs = false;
    let mut header_closed = false;
    let mut hits: Vec<Option<String>> = Vec::new();
    for line in text.lines() {
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        if line.trim() == "permissions: {}" && !in_jobs {
            header_closed = true;
        }
        if in_jobs && indent_of(line) == 2 && line.trim_end().ends_with(':') {
            job = Some(line.trim().trim_end_matches(':').to_string());
        }
        let squeezed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        if squeezed.contains("write-all") {
            return Some("write-all permission".to_string());
        }
        if squeezed.contains("contents") && squeezed.contains("write") {
            hits.push(job.clone());
        }
    }
    if !header_closed {
        return Some("no workflow-level `permissions: {}`".to_string());
    }
    if hits.len() != 1 {
        return Some(format!("contents: write appears {} times", hits.len()));
    }
    if hits[0].as_deref() != Some("release") {
        return Some(format!("contents: write is in {:?}", hits[0]));
    }
    None
}

fn unpinned(text: &str) -> Vec<String> {
    uses_values(text)
        .into_iter()
        .filter(|value| !is_pinned(value))
        .collect()
}

const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";

#[test]
fn unpinned_uses_are_detected_in_fixture_text() {
    assert_eq!(
        unpinned("steps:\n  - uses: actions/checkout@v4\n"),
        vec!["actions/checkout@v4"]
    );
    assert_eq!(
        unpinned("steps:\n  - uses: actions/checkout@3d3c42e5\n"),
        vec!["actions/checkout@3d3c42e5"]
    );
    let upper = format!("  - uses: actions/checkout@{}\n", SHA.to_uppercase());
    assert_eq!(unpinned(&upper).len(), 1);
    assert_eq!(unpinned("  - uses: actions/checkout\n").len(), 1);
    assert_eq!(unpinned("      uses: docker://alpine:3\n").len(), 1);
    assert_eq!(
        unpinned("  - uses: ./.github/actions/dev-image@v1\n").len(),
        0
    );
}

#[test]
fn pinned_uses_are_accepted_in_fixture_text() {
    let text = format!(
        "  - uses: actions/checkout@{SHA}\n    with:\n      x: y\n  - uses: ./.github/actions/dev-image\n  - uses: actions/cache/restore@{SHA}\n"
    );
    assert_eq!(uses_values(&text).len(), 3);
    assert!(unpinned(&text).is_empty());
}

#[test]
fn every_workflow_action_is_pinned_by_full_sha() {
    let mut seen = 0;
    for path in workflow_and_action_files() {
        let text = fs::read_to_string(&path).unwrap();
        seen += uses_values(&text).len();
        let bad = unpinned(&text);
        assert!(bad.is_empty(), "{}: {bad:?}", path.display());
    }
    assert!(seen > 10);
}

const DRAFT_ONLY: &str = "jobs:\n  release:\n    steps:\n      - run: |\n          gh release create \"$TAG\" --repo \"$GITHUB_REPOSITORY\" \\\n            --draft --verify-tag --title \"$TAG\" a b\n";

#[test]
fn a_single_draft_create_passes_the_draft_check() {
    assert_eq!(release_invocations(DRAFT_ONLY).len(), 1);
    assert_eq!(draft_violation(DRAFT_ONLY), None);
}

#[test]
fn the_draft_check_rejects_every_way_to_publish() {
    let no_draft = DRAFT_ONLY.replace("--draft ", "");
    assert!(draft_violation(&no_draft).is_some());
    let publish = DRAFT_ONLY.replace("--draft ", "--draft=false ");
    assert!(draft_violation(&publish).is_some());
    let edit = format!("{DRAFT_ONLY}      - run: gh release edit \"$TAG\" --draft=false\n");
    assert!(draft_violation(&edit).is_some());
    let second = format!("{DRAFT_ONLY}      - run: gh release create \"$TAG\" --draft\n");
    assert!(draft_violation(&second).is_some());
    let upload = format!("{DRAFT_ONLY}      - run: gh release upload \"$TAG\" f\n");
    assert!(draft_violation(&upload).is_some());
    let api = format!("{DRAFT_ONLY}      - run: gh api -X PATCH repos/o/r/releases/1\n");
    assert!(draft_violation(&api).is_some());
    assert!(draft_violation("jobs:\n").is_some());
}

#[test]
fn release_workflow_creates_only_drafts() {
    let text = read(".github/workflows/release.yml");
    assert_eq!(draft_violation(&text), None);
    assert_eq!(release_invocations(&text).len(), 1);
}

const WRITE_GOOD: &str = "permissions: {}\n\njobs:\n  plan:\n    permissions:\n      contents: read\n    steps: []\n  release:\n    permissions:\n      contents: write\n    steps: []\n";

#[test]
fn the_write_check_accepts_a_single_write_in_the_release_job() {
    assert_eq!(contents_write_violation(WRITE_GOOD), None);
}

#[test]
fn the_write_check_rejects_a_write_anywhere_else() {
    let in_plan = WRITE_GOOD.replace("contents: read", "contents: write");
    assert!(contents_write_violation(&in_plan).is_some());
    let at_top = WRITE_GOOD.replace("permissions: {}", "permissions:\n  contents: write");
    assert!(contents_write_violation(&at_top).is_some());
    let flow = WRITE_GOOD.replace("contents: read", "{ contents:  write }");
    assert!(contents_write_violation(&flow).is_some());
    let twice = WRITE_GOOD.replace(
        "steps: []\n  release",
        "steps: []\n    permissions:\n      contents: write\n  release",
    );
    assert!(contents_write_violation(&twice).is_some());
    let all = WRITE_GOOD.replace("contents: read", "write-all");
    assert!(contents_write_violation(&all).is_some());
    let none = WRITE_GOOD.replace("contents: write", "contents: read");
    assert!(contents_write_violation(&none).is_some());
    let open = WRITE_GOOD.replace("permissions: {}\n", "");
    assert!(contents_write_violation(&open).is_some());
}

#[test]
fn only_the_release_job_can_write_contents() {
    assert_eq!(
        contents_write_violation(&read(".github/workflows/release.yml")),
        None
    );
}

const RUN_FIXTURE: &str = "steps:\n  - run: echo one\n  - name: two\n    run: |\n      echo a\n      echo b\n    env:\n      X: ${{ github.ref }}\n  - run: >-\n      echo c\n  - uses: x/y@v1\n";

#[test]
fn run_scripts_are_extracted_without_their_neighbours() {
    assert_eq!(
        run_scripts(RUN_FIXTURE),
        vec!["echo one", "echo a\necho b", "echo c"]
    );
}

#[test]
fn no_workflow_expression_appears_inside_a_run_script() {
    let bad = "steps:\n  - run: echo ${{ github.ref_name }}\n";
    assert!(run_scripts(bad).iter().any(|s| s.contains("${{")));
    let mut seen = 0;
    for path in workflow_and_action_files() {
        for script in run_scripts(&fs::read_to_string(&path).unwrap()) {
            seen += 1;
            assert!(!script.contains("${{"), "{}: {script}", path.display());
        }
    }
    assert!(seen > 10);
}

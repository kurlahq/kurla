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

fn run_blocks(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut scripts = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let start = index;
        let line = lines[index];
        index += 1;
        let Some(value) = key_value(line, "run") else {
            continue;
        };
        if !value.starts_with('|') && !value.starts_with('>') {
            scripts.push((index - 1, value.to_string()));
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
        scripts.push((start, body.join("\n").trim().to_string()));
    }
    scripts
}

fn run_scripts(text: &str) -> Vec<String> {
    run_blocks(text)
        .into_iter()
        .map(|(_, script)| script)
        .collect()
}

fn logical_lines(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut joined_lines = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let mut joined = lines[index].trim().to_string();
        while joined.ends_with(BACKSLASH) && index + 1 < lines.len() {
            joined.pop();
            index += 1;
            joined.push(' ');
            joined.push_str(lines[index].trim());
        }
        joined_lines.push(joined);
        index += 1;
    }
    joined_lines
}

fn gh_invocations(text: &str, subcommand: &str) -> Vec<Vec<String>> {
    let mut found = Vec::new();
    for line in logical_lines(text) {
        for segment in line.split([';', '&', '|']) {
            let tokens: Vec<String> = segment
                .split_whitespace()
                .map(|t| {
                    t.trim_matches(|c| c == '"' || c == '\'' || c == '(')
                        .to_string()
                })
                .collect();
            let Some(gh) = tokens.iter().position(|t| t == "gh") else {
                continue;
            };
            if let Some(offset) = tokens[gh + 1..].iter().position(|t| t == subcommand) {
                found.push(tokens[gh + 1 + offset..].to_vec());
            }
        }
    }
    found
}

fn release_invocations(text: &str) -> Vec<Vec<String>> {
    gh_invocations(text, "release")
}

fn api_violation(text: &str) -> Option<String> {
    for tokens in gh_invocations(text, "api") {
        let joined = tokens.join(" ");
        let reads_a_commit = tokens.iter().any(|t| t.contains("/commits/"));
        let writes = tokens.iter().any(|t| {
            [
                "-X",
                "--method",
                "-f",
                "-F",
                "--field",
                "--raw-field",
                "--input",
            ]
            .contains(&t.as_str())
        });
        if !reads_a_commit || writes || joined.contains("release") {
            return Some(format!(
                "found a gh api call that is not a commit read: {joined}"
            ));
        }
    }
    None
}

fn draft_violation(text: &str) -> Option<String> {
    let invocations = release_invocations(text);
    if invocations.len() != 1 {
        return Some(format!(
            "expected exactly one gh release invocation, found {}",
            invocations.len()
        ));
    }
    let tokens = &invocations[0];
    if tokens.get(1).map(String::as_str) != Some("create") {
        return Some("the gh release invocation is not a create".to_string());
    }
    if !tokens.iter().any(|t| t == "--draft") {
        return Some("the gh release create has no --draft".to_string());
    }
    if text.contains("--draft=") {
        return Some("found --draft=".to_string());
    }
    api_violation(text)
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

fn job_ranges(text: &str) -> Vec<(String, usize, usize)> {
    let lines: Vec<&str> = text.lines().collect();
    let Some(start) = lines.iter().position(|l| *l == "jobs:") else {
        return Vec::new();
    };
    let mut ranges: Vec<(String, usize, usize)> = Vec::new();
    for (offset, line) in lines[start + 1..].iter().enumerate() {
        let index = start + 1 + offset;
        if line.trim().is_empty() {
            continue;
        }
        if indent_of(line) == 0 {
            break;
        }
        if indent_of(line) == 2 && line.trim_end().ends_with(':') {
            if let Some(last) = ranges.last_mut() {
                last.2 = index;
            }
            ranges.push((
                line.trim().trim_end_matches(':').to_string(),
                index,
                lines.len(),
            ));
        }
    }
    ranges
}

fn job_at(ranges: &[(String, usize, usize)], index: usize) -> Option<&str> {
    ranges
        .iter()
        .find(|(_, start, end)| index >= *start && index < *end)
        .map(|(name, _, _)| name.as_str())
}

fn job_text(text: &str, name: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    job_ranges(text)
        .into_iter()
        .find(|(job, _, _)| job == name)
        .map(|(_, start, end)| lines[start..end].join("\n"))
        .unwrap_or_default()
}

fn env_block(lines: &[&str], from: usize, to: usize, indent: usize) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut index = from;
    while index < to {
        let line = lines[index];
        index += 1;
        if indent_of(line) != indent || line.trim() != "env:" {
            continue;
        }
        while index < to && (lines[index].trim().is_empty() || indent_of(lines[index]) > indent) {
            if let Some((name, value)) = lines[index].trim().split_once(':') {
                found.push((name.trim().to_string(), value.trim().to_string()));
            }
            index += 1;
        }
    }
    found
}

fn job_env(text: &str, name: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    job_ranges(text)
        .into_iter()
        .find(|(job, _, _)| job == name)
        .map(|(_, start, end)| env_block(&lines, start, end, 4))
        .unwrap_or_default()
}

fn normalized_pair(line: &str) -> String {
    match line.trim().split_once(':') {
        Some((key, value)) => format!("{}: {}", key.trim(), value.trim()),
        None => line.trim().to_string(),
    }
}

fn permission_violation(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let top: Vec<&&str> = lines
        .iter()
        .filter(|l| indent_of(l) == 0 && l.trim_start().starts_with("permissions"))
        .collect();
    if top.len() != 1 || top[0].trim() != "permissions: {}" {
        return Some("no single workflow-level `permissions: {}`".to_string());
    }
    let expected: [(&str, &[&str]); 5] = [
        ("plan", &["contents: read"]),
        ("build-linux-windows", &["contents: read"]),
        ("build-macos", &["contents: read"]),
        (
            "attest",
            &["attestations: write", "contents: read", "id-token: write"],
        ),
        ("release", &["contents: write"]),
    ];
    let ranges = job_ranges(text);
    let mut names: Vec<&str> = ranges.iter().map(|(n, _, _)| n.as_str()).collect();
    names.sort_unstable();
    let mut wanted: Vec<&str> = expected.iter().map(|(n, _)| *n).collect();
    wanted.sort_unstable();
    if names != wanted {
        return Some(format!("jobs are {names:?}, expected {wanted:?}"));
    }
    for (name, start, end) in &ranges {
        let blocks: Vec<usize> = (*start..*end)
            .filter(|i| lines[*i].trim_start().starts_with("permissions"))
            .collect();
        if blocks.len() != 1 {
            return Some(format!(
                "{name}: expected one permissions block, found {}",
                blocks.len()
            ));
        }
        let at = blocks[0];
        if indent_of(lines[at]) != 4 || lines[at].trim() != "permissions:" {
            return Some(format!("{name}: permissions must be a block under the job"));
        }
        let mut granted: Vec<String> = Vec::new();
        let mut index = at + 1;
        while index < *end && (lines[index].trim().is_empty() || indent_of(lines[index]) > 4) {
            if !lines[index].trim().is_empty() {
                granted.push(normalized_pair(lines[index]));
            }
            index += 1;
        }
        granted.sort();
        let want: Vec<String> = expected
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();
        if granted != want {
            return Some(format!("{name}: grants {granted:?}, expected {want:?}"));
        }
    }
    None
}

fn token_violation(text: &str, allowed_job: Option<&str>) -> Option<String> {
    if text.contains("secrets.") {
        return Some("a secrets. expression".to_string());
    }
    let ranges = job_ranges(text);
    for (index, line) in text.lines().enumerate() {
        if (line.contains("github.token") || line.contains("GH_TOKEN"))
            && (allowed_job.is_none() || job_at(&ranges, index) != allowed_job)
        {
            return Some(format!(
                "the token appears in {:?}: {}",
                job_at(&ranges, index),
                line.trim()
            ));
        }
    }
    None
}

fn is_runner_variable(name: &str) -> bool {
    name.starts_with("GITHUB_")
        || name.starts_with("RUNNER_")
        || ["HOME", "PWD", "PATH"].contains(&name)
}

fn variables_read(script: &str) -> Vec<String> {
    let bytes = script.as_bytes();
    let mut names = Vec::new();
    for (i, byte) in bytes.iter().enumerate() {
        if *byte != b'$' {
            continue;
        }
        let mut j = i + 1;
        if bytes.get(j) == Some(&b'{') {
            j += 1;
        }
        let begin = j;
        while j < bytes.len()
            && (bytes[j].is_ascii_uppercase()
                || bytes[j] == b'_'
                || (j > begin && bytes[j].is_ascii_digit()))
        {
            j += 1;
        }
        let lower_follows = bytes.get(j).is_some_and(u8::is_ascii_lowercase);
        if j > begin && !lower_follows {
            names.push(script[begin..j].to_string());
        }
    }
    names
}

fn assigned_in(script: &str, name: &str) -> bool {
    let needle = format!("{name}=");
    script.match_indices(&needle).any(|(at, _)| {
        let before = script[..at].chars().next_back();
        before.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
            && !script[at + needle.len()..].starts_with('=')
    })
}

fn undefined_variables(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let workflow: Vec<String> = env_block(&lines, 0, lines.len(), 0)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    let ranges = job_ranges(text);
    let mut missing = Vec::new();
    for (at, script) in run_blocks(text) {
        let line = lines[at];
        let dash = line.trim_start().starts_with("- ");
        let column = indent_of(line) + if dash { 2 } else { 0 };
        let mut start = at;
        while start > 0
            && !(lines[start].trim_start().starts_with("- ")
                && indent_of(lines[start]) + 2 == column)
        {
            start -= 1;
        }
        let mut end = at + 1;
        while end < lines.len()
            && (lines[end].trim().is_empty() || indent_of(lines[end]) + 2 > column)
        {
            end += 1;
        }
        let mut defined = workflow.clone();
        if let Some((_, job_start, job_end)) = ranges.iter().find(|(_, s, e)| at >= *s && at < *e) {
            defined.extend(
                env_block(&lines, *job_start, *job_end, 4)
                    .into_iter()
                    .map(|(n, _)| n),
            );
        }
        defined.extend(
            env_block(&lines, start, end, column)
                .into_iter()
                .map(|(n, _)| n),
        );
        for name in variables_read(&script) {
            if !defined.contains(&name)
                && !assigned_in(&script, &name)
                && !is_runner_variable(&name)
            {
                missing.push(name);
            }
        }
    }
    missing.sort();
    missing.dedup();
    missing
}

fn ref_violation(text: &str) -> Option<String> {
    let refs: Vec<&str> = text.lines().filter_map(|l| key_value(l, "ref")).collect();
    if refs.is_empty() {
        return Some("no checkout ref".to_string());
    }
    refs.into_iter()
        .find(|r| *r != "${{ needs.plan.outputs.commit }}")
        .map(|r| format!("a checkout ref is {r}"))
}

fn message_exits(text: &str, message: &str) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    let hits: Vec<usize> = (0..lines.len())
        .filter(|i| lines[*i].contains(message))
        .collect();
    !hits.is_empty()
        && hits.iter().all(|i| {
            lines[*i].trim_start().starts_with("echo")
                && lines[i + 1..]
                    .iter()
                    .find(|l| !l.trim().is_empty())
                    .is_some_and(|l| l.trim() == "exit 1")
        })
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
fn the_draft_check_sees_extra_spaces_and_flags_before_the_subcommand() {
    let spaced = format!("{DRAFT_ONLY}      - run: gh  release edit \"$TAG\" --draft=false\n");
    assert!(draft_violation(&spaced).is_some());
    let flagged = format!("{DRAFT_ONLY}      - run: gh -R x release upload \"$TAG\" f\n");
    assert!(draft_violation(&flagged).is_some());
    let piped = format!("{DRAFT_ONLY}      - run: true && gh  -R x  release delete \"$TAG\"\n");
    assert!(draft_violation(&piped).is_some());
    let wide = DRAFT_ONLY.replace("gh release create", "gh   -R x   release   create");
    assert_eq!(release_invocations(&wide).len(), 1);
    assert_eq!(draft_violation(&wide), None);
    let split = DRAFT_ONLY.replace("gh release create", "gh \\\n            release create");
    assert_eq!(release_invocations(&split).len(), 1);
    let api = format!("{DRAFT_ONLY}      - run: gh  api -X PATCH repos/o/r/releases/1\n");
    assert!(draft_violation(&api).is_some());
}

#[test]
fn the_draft_check_allows_only_a_get_of_a_commit_through_the_api() {
    let get =
        "      - run: sha=\"$(gh api \"repos/$GITHUB_REPOSITORY/commits/tags/$TAG\" --jq .sha)\"\n";
    assert_eq!(draft_violation(&format!("{DRAFT_ONLY}{get}")), None);
    for bad in [
        "gh api -X POST repos/o/r/commits/x",
        "gh api --method PATCH repos/o/r/commits/x",
        "gh api repos/o/r/commits/x -f a=b",
        "gh api repos/o/r/commits/x --input f",
        "gh api repos/o/r/releases/1",
        "gh api repos/o/r/commits/x/releases",
        "gh api graphql",
    ] {
        let text = format!("{DRAFT_ONLY}      - run: {bad}\n");
        assert!(draft_violation(&text).is_some(), "{bad}");
    }
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

const RELEASE_WITHOUT_ENV: &str = "permissions: {}\n\njobs:\n  plan:\n    permissions:\n      contents: read\n    steps:\n      - run: echo hi\n  release:\n    needs: [plan]\n    permissions:\n      contents: write\n    steps:\n      - name: Create the draft release\n        run: |\n          gh release create \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --draft --verify-tag\n";

#[test]
fn a_release_job_without_env_reads_variables_that_nothing_defines() {
    assert_eq!(undefined_variables(RELEASE_WITHOUT_ENV), vec!["TAG"]);
}

#[test]
fn variables_defined_at_any_level_or_assigned_or_from_the_runner_are_accepted() {
    let job_env = RELEASE_WITHOUT_ENV.replace(
        "    steps:\n      - name: Create",
        "    env:\n      TAG: ${{ needs.plan.outputs.tag }}\n    steps:\n      - name: Create",
    );
    assert!(undefined_variables(&job_env).is_empty());
    let step_env = RELEASE_WITHOUT_ENV.replace(
        "        run: |\n          gh release",
        "        env:\n          TAG: x\n        run: |\n          gh release",
    );
    assert!(undefined_variables(&step_env).is_empty());
    let workflow_env = RELEASE_WITHOUT_ENV.replace("jobs:", "env:\n  TAG: x\n\njobs:");
    assert!(undefined_variables(&workflow_env).is_empty());
    let assigned = RELEASE_WITHOUT_ENV.replace(
        "          gh release",
        "          TAG=x\n          gh release",
    );
    assert!(undefined_variables(&assigned).is_empty());
    let braced = RELEASE_WITHOUT_ENV.replace("\"$TAG\"", "\"${TAG:-x}\"");
    assert_eq!(undefined_variables(&braced), vec!["TAG"]);
    let runner = "jobs:\n  a:\n    steps:\n      - run: echo \"$GITHUB_OUTPUT ${RUNNER_TEMP} $HOME $PWD $PATH $lower $(id -u) $((2 + 1)) ${#x[@]}\"\n";
    assert!(undefined_variables(runner).is_empty());
}

#[test]
fn a_variable_defined_in_another_step_or_job_is_not_defined_here() {
    let other_step = "jobs:\n  a:\n    steps:\n      - name: one\n        env:\n          X: 1\n        run: echo one\n      - name: two\n        run: echo \"$X\"\n";
    assert_eq!(undefined_variables(other_step), vec!["X"]);
    let other_job = "jobs:\n  a:\n    env:\n      X: 1\n    steps:\n      - run: echo one\n  b:\n    steps:\n      - run: echo \"$X\"\n";
    assert_eq!(undefined_variables(other_job), vec!["X"]);
    let compare = "jobs:\n  a:\n    steps:\n      - run: if [ \"$X\" == y ]; then X==1; fi\n";
    assert_eq!(undefined_variables(compare), vec!["X"]);
}

#[test]
fn every_variable_a_run_script_reads_is_defined() {
    let mut seen = 0;
    for path in workflow_and_action_files() {
        let text = fs::read_to_string(&path).unwrap();
        seen += run_scripts(&text).len();
        let missing = undefined_variables(&text);
        assert!(missing.is_empty(), "{}: {missing:?}", path.display());
    }
    assert!(seen > 10);
}

const PERMS_GOOD: &str = "permissions: {}\n\njobs:\n  plan:\n    permissions:\n      contents: read\n    steps: []\n  build-linux-windows:\n    permissions:\n      contents: read\n    steps: []\n  build-macos:\n    permissions:\n      contents: read\n    steps: []\n  attest:\n    permissions:\n      contents: read\n      id-token: write\n      attestations: write\n    steps: []\n  release:\n    permissions:\n      contents: write\n    steps: []\n";

#[test]
fn the_permission_map_accepts_the_intended_grants() {
    assert_eq!(permission_violation(PERMS_GOOD), None);
}

#[test]
fn the_permission_map_rejects_every_deviation() {
    let macos = "  build-macos:\n    permissions:\n      contents: read\n";
    let moved = PERMS_GOOD.replace(macos, &format!("{macos}      id-token: write\n"));
    assert!(permission_violation(&moved).is_some());
    let plan = "  plan:\n    permissions:\n      contents: read\n";
    let widened = PERMS_GOOD.replace(plan, &format!("{plan}      attestations: write\n"));
    assert!(permission_violation(&widened).is_some());
    let release = "  release:\n    permissions:\n      contents: write\n";
    let missing = PERMS_GOOD.replace(release, "  release:\n");
    assert!(permission_violation(&missing).is_some());
    let extra = PERMS_GOOD.replace(release, &format!("{release}      issues: read\n"));
    assert!(permission_violation(&extra).is_some());
    let attest = "      id-token: write\n";
    assert!(permission_violation(&PERMS_GOOD.replace(attest, "")).is_some());
    let flow = PERMS_GOOD.replace(
        release,
        "  release:\n    permissions: { contents: write }\n",
    );
    assert!(permission_violation(&flow).is_some());
    let all = PERMS_GOOD.replace(release, "  release:\n    permissions: write-all\n");
    assert!(permission_violation(&all).is_some());
    let reading = PERMS_GOOD.replace(
        release,
        "  release:\n    permissions:\n      contents: read\n",
    );
    assert!(permission_violation(&reading).is_some());
    let writing = PERMS_GOOD.replace(
        macos,
        "  build-macos:\n    permissions:\n      contents: write\n",
    );
    assert!(permission_violation(&writing).is_some());
    let twice = PERMS_GOOD.replace(
        plan,
        &format!("{plan}    permissions:\n      contents: read\n"),
    );
    assert!(permission_violation(&twice).is_some());
    let no_header = PERMS_GOOD.replace("permissions: {}\n", "");
    assert!(permission_violation(&no_header).is_some());
    let open_header = PERMS_GOOD.replace("permissions: {}", "permissions:\n  contents: read");
    assert!(permission_violation(&open_header).is_some());
    let renamed = PERMS_GOOD.replace("  release:\n", "  publish:\n");
    assert!(permission_violation(&renamed).is_some());
    let added =
        format!("{PERMS_GOOD}  extra:\n    permissions:\n      contents: read\n    steps: []\n");
    assert!(permission_violation(&added).is_some());
}

#[test]
fn the_release_workflow_grants_exactly_the_intended_permissions() {
    assert_eq!(
        permission_violation(&read(".github/workflows/release.yml")),
        None
    );
}

const TOKEN_FIXTURE: &str = "jobs:\n  build:\n    steps: []\n  release:\n    env:\n      GH_TOKEN: ${{ github.token }}\n    steps: []\n";

#[test]
fn the_token_check_allows_the_release_job_only() {
    assert_eq!(token_violation(TOKEN_FIXTURE, Some("release")), None);
    assert!(token_violation(TOKEN_FIXTURE, None).is_some());
    let in_build = TOKEN_FIXTURE.replace(
        "  build:\n    steps: []",
        "  build:\n    env:\n      T: ${{ github.token }}\n    steps: []",
    );
    assert!(token_violation(&in_build, Some("release")).is_some());
    let named = TOKEN_FIXTURE.replace(
        "  build:\n    steps: []",
        "  build:\n    env:\n      GH_TOKEN: x\n    steps: []",
    );
    assert!(token_violation(&named, Some("release")).is_some());
    let secret = TOKEN_FIXTURE.replace("github.token", "secrets.GITHUB_TOKEN");
    assert!(token_violation(&secret, Some("release")).is_some());
}

#[test]
fn no_job_but_release_sees_the_github_token() {
    let mut seen = 0;
    for path in workflow_and_action_files() {
        let text = fs::read_to_string(&path).unwrap();
        let in_release = path.file_name().is_some_and(|n| n == "release.yml");
        let allowed = if in_release { Some("release") } else { None };
        assert_eq!(token_violation(&text, allowed), None, "{}", path.display());
        seen += 1;
    }
    assert!(seen >= 5);
}

#[test]
fn release_job_env_has_the_token_and_the_tag() {
    let text = read(".github/workflows/release.yml");
    let env = job_env(&text, "release");
    let expected = [
        ("GH_TOKEN", "${{ github.token }}"),
        ("TAG", "${{ needs.plan.outputs.tag }}"),
        ("COMMIT", "${{ needs.plan.outputs.commit }}"),
    ];
    assert_eq!(env.len(), expected.len(), "{env:?}");
    for (name, value) in expected {
        assert!(
            env.iter().any(|(n, v)| n == name && v == value),
            "{name}: {env:?}"
        );
    }
    assert!(job_env(RELEASE_WITHOUT_ENV, "release").is_empty());
}

#[test]
fn the_build_jobs_check_out_the_commit_the_plan_resolved() {
    let good = "steps:\n  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n    with:\n      ref: ${{ needs.plan.outputs.commit }}\n";
    assert_eq!(ref_violation(good), None);
    let by_tag = good.replace("outputs.commit", "outputs.tag");
    assert!(ref_violation(&by_tag).is_some());
    let tag_ref = good.replace(
        "${{ needs.plan.outputs.commit }}",
        "refs/tags/${{ needs.plan.outputs.tag }}",
    );
    assert!(ref_violation(&tag_ref).is_some());
    assert!(ref_violation("steps: []\n").is_some());
    let text = read(".github/workflows/release.yml");
    assert_eq!(ref_violation(&text), None);
    for job in ["build-linux-windows", "build-macos"] {
        assert!(
            job_text(&text, job).contains("ref: ${{ needs.plan.outputs.commit }}"),
            "{job}"
        );
    }
}

#[test]
fn the_plan_job_outputs_the_peeled_commit_and_the_version() {
    let text = read(".github/workflows/release.yml");
    let plan = job_text(&text, "plan");
    assert!(plan.contains("commit: ${{ steps.tag.outputs.commit }}"));
    assert!(plan.contains("version: ${{ steps.tag.outputs.version }}"));
    assert!(plan.contains("git rev-parse \"refs/tags/$TAG^{commit}\""));
    assert!(plan.contains("echo \"commit=$commit\" >> \"$GITHUB_OUTPUT\""));
    assert!(plan.contains("echo \"version=$version\" >> \"$GITHUB_OUTPUT\""));
}

#[test]
fn the_release_job_checks_the_tag_before_it_creates_the_draft() {
    let text = read(".github/workflows/release.yml");
    let release = job_text(&text, "release");
    let check = release
        .find("gh api \"repos/$GITHUB_REPOSITORY/commits/tags/$TAG\" --jq .sha")
        .expect("the tag check");
    let create = release.find("gh release create").expect("the draft");
    assert!(check < create);
    assert!(release.contains("\"$sha\" != \"$COMMIT\""));
}

#[test]
fn every_failure_message_of_the_fix_round_is_followed_by_an_exit() {
    let text = read(".github/workflows/release.yml");
    for message in [
        "plan: version check failed: cannot read Cargo.toml at $TAG",
        "release: tag check failed: $TAG now points at $sha, not the built $COMMIT",
        "release: tag check failed: cannot resolve $TAG to a commit",
        "build-linux-windows: smoke check failed: the musl binary did not run",
        "build-linux-windows: smoke check failed: expected",
        "build-macos: smoke check failed: the aarch64 binary did not run",
        "build-macos: smoke check failed: expected",
    ] {
        assert!(message_exits(&text, message), "{message}");
    }
    assert!(!message_exits(
        "echo \"x: failed\"\nsomething\n",
        "x: failed"
    ));
    assert!(!message_exits("echo \"x: failed\"\n", "x: failed"));
    assert!(!message_exits(
        "run: echo \"x: failed\"\nexit 1\n",
        "x: failed"
    ));
    assert!(message_exits(
        "  echo \"x: failed\"\n\n  exit 1\n",
        "x: failed"
    ));
}

#[test]
fn each_build_job_runs_the_binary_it_can_run_and_compares_the_version() {
    let text = read(".github/workflows/release.yml");
    for job in ["build-linux-windows", "build-macos"] {
        let env = job_env(&text, job);
        assert!(
            env.iter()
                .any(|(n, v)| n == "VERSION" && v == "${{ needs.plan.outputs.version }}"),
            "{job}: {env:?}"
        );
        assert!(job_text(&text, job).contains("\"kurla $VERSION\""), "{job}");
    }
    let linux = job_text(&text, "build-linux-windows");
    assert!(linux.contains("$DEV_RUN ./dist/kurla-x86_64-unknown-linux-musl --version"));
    assert!(!linux.contains("kurla-x86_64-pc-windows-gnu.exe --version"));
    let macos = job_text(&text, "build-macos");
    assert!(macos.contains("./dist/kurla-aarch64-apple-darwin --version"));
    assert!(!macos.contains("kurla-x86_64-apple-darwin --version"));
}

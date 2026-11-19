use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const COOLDOWN_DAYS: i64 = 14;

const LOCK_PATH: &str = "Cargo.lock";
const EXCEPTIONS_PATH: &str = "supply-chain/cooldown-exceptions.toml";
const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Debug, Default)]
pub struct Report {
    pub offenders: Vec<String>,
    pub invalid: Vec<String>,
    pub stale: Vec<String>,
    pub errors: Vec<String>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.offenders.is_empty() && self.invalid.is_empty() && self.errors.is_empty()
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let sections = [
            ("young packages without a valid exception", &self.offenders),
            ("invalid exceptions", &self.invalid),
            ("errors", &self.errors),
            ("stale exception entries, remove them", &self.stale),
        ];
        for (heading, items) in sections {
            if items.is_empty() {
                continue;
            }
            out.push_str(&format!("{heading}:\n"));
            for item in items {
                out.push_str(&format!("  {item}\n"));
            }
        }
        out
    }
}

#[derive(Debug)]
struct Package {
    name: String,
    version: String,
    registry: bool,
}

#[derive(Debug, Default)]
struct Exception {
    fields: [Option<String>; 6],
}

const EXCEPTION_KEYS: [&str; 6] = [
    "crate",
    "version",
    "advisory",
    "replaces",
    "reviewed_by",
    "date",
];

pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let shifted_month = (month + 9) % 12;
    let doy = (153 * shifted_month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    }
}

fn parse_digits(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn parse_date(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = parse_digits(&text[0..4])?;
    let month = parse_digits(&text[5..7])?;
    let day = parse_digits(&text[8..10])?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

fn parse_timestamp_day(text: &str) -> Option<i64> {
    let date = text.get(..10)?;
    let rest = text.get(10..)?;
    if !rest.starts_with('T') {
        return None;
    }
    parse_date(date)
}

fn parse_string_value(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let inner = raw
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .ok_or_else(|| format!("expected a quoted string, found `{raw}`"))?;
    if inner.contains('"') || inner.contains('\\') {
        return Err(format!("unsupported string escape in `{raw}`"));
    }
    Ok(inner.to_string())
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    Some((key, value))
}

fn parse_lock(text: &str) -> Result<Vec<Package>, String> {
    let mut packages: Vec<Package> = Vec::new();
    let mut current: Option<(Option<String>, Option<String>, Option<String>)> = None;
    let mut in_array = false;
    let mut saw_version = false;

    let finish = |current: &mut Option<(Option<String>, Option<String>, Option<String>)>,
                  packages: &mut Vec<Package>|
     -> Result<(), String> {
        if let Some((name, version, source)) = current.take() {
            let name = name.ok_or("package without a name")?;
            let version = version.ok_or_else(|| format!("package {name} without a version"))?;
            let registry = match source.as_deref() {
                None => false,
                Some(REGISTRY_SOURCE) => true,
                Some(other) => return Err(format!("unsupported source `{other}` for {name}")),
            };
            packages.push(Package {
                name,
                version,
                registry,
            });
        }
        Ok(())
    };

    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        let location = |message: String| format!("{LOCK_PATH} line {}: {message}", number + 1);
        if in_array {
            if line == "]" {
                in_array = false;
            } else if !(line.starts_with('"') && (line.ends_with("\",") || line.ends_with('"'))) {
                return Err(location(format!("unexpected array entry `{line}`")));
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[package]]" {
            finish(&mut current, &mut packages).map_err(location)?;
            current = Some((None, None, None));
            continue;
        }
        let (key, value) =
            split_key_value(line).ok_or_else(|| location(format!("unrecognised line `{line}`")))?;
        match (&mut current, key) {
            (None, "version") => {
                if parse_digits(value.trim()) != Some(4) {
                    return Err(location("only lockfile version 4 is supported".to_string()));
                }
                saw_version = true;
            }
            (Some((name, _, _)), "name") => {
                *name = Some(parse_string_value(value).map_err(location)?)
            }
            (Some((_, version, _)), "version") => {
                *version = Some(parse_string_value(value).map_err(location)?)
            }
            (Some((_, _, source)), "source") => {
                *source = Some(parse_string_value(value).map_err(location)?)
            }
            (Some(_), "checksum") => {
                parse_string_value(value).map_err(location)?;
            }
            (Some(_), "dependencies") => {
                if value.trim() != "[" {
                    return Err(location(
                        "dependencies must be a multi-line array".to_string(),
                    ));
                }
                in_array = true;
            }
            _ => return Err(location(format!("unexpected key `{key}`"))),
        }
    }
    finish(&mut current, &mut packages).map_err(|m| format!("{LOCK_PATH}: {m}"))?;
    if !saw_version {
        return Err(format!("{LOCK_PATH}: missing `version = 4`"));
    }
    Ok(packages)
}

fn parse_exceptions(text: &str) -> Result<Vec<Exception>, String> {
    let mut entries: Vec<Exception> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        let location =
            |message: String| format!("{EXCEPTIONS_PATH} line {}: {message}", number + 1);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[exception]]" {
            entries.push(Exception::default());
            continue;
        }
        let entry = entries
            .last_mut()
            .ok_or_else(|| location(format!("`{line}` before the first [[exception]]")))?;
        let (key, value) =
            split_key_value(line).ok_or_else(|| location(format!("unrecognised line `{line}`")))?;
        let index = EXCEPTION_KEYS
            .iter()
            .position(|k| *k == key)
            .ok_or_else(|| location(format!("unexpected key `{key}`")))?;
        if entry.fields[index].is_some() {
            return Err(location(format!("duplicate key `{key}`")));
        }
        entry.fields[index] = Some(parse_string_value(value).map_err(location)?);
    }
    Ok(entries)
}

fn is_valid_advisory(text: &str) -> bool {
    if let Some(rest) = text.strip_prefix("RUSTSEC-") {
        return match rest.split_once('-') {
            Some((year, number)) => {
                year.len() == 4
                    && number.len() == 4
                    && year.bytes().all(|b| b.is_ascii_digit())
                    && number.bytes().all(|b| b.is_ascii_digit())
            }
            None => false,
        };
    }
    if let Some(rest) = text.strip_prefix("GHSA-") {
        let groups: Vec<&str> = rest.split('-').collect();
        return groups.len() == 3
            && groups.iter().all(|g| {
                g.len() == 4
                    && g.bytes()
                        .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
            });
    }
    false
}

fn exception_label(entry: &Exception) -> String {
    let name = entry.fields[0].as_deref().unwrap_or("?");
    let version = entry.fields[1].as_deref().unwrap_or("?");
    format!("{name} {version}")
}

fn exception_problem(entry: &Exception, packages: &[Package]) -> Option<String> {
    for (key, value) in EXCEPTION_KEYS.iter().zip(entry.fields.iter()) {
        match value.as_deref() {
            None => return Some(format!("field `{key}` is missing")),
            Some("") => return Some(format!("field `{key}` is empty")),
            Some(_) => {}
        }
    }
    let field = |i: usize| entry.fields[i].as_deref().unwrap_or("");
    if !is_valid_advisory(field(2)) {
        return Some(format!("malformed advisory id `{}`", field(2)));
    }
    if parse_date(field(5)).is_none() {
        return Some(format!("malformed date `{}`", field(5)));
    }
    let known = packages
        .iter()
        .any(|p| p.registry && p.name == field(0) && p.version == field(1));
    if !known {
        return Some("no such crates.io package in Cargo.lock".to_string());
    }
    None
}

pub fn evaluate(
    lock: &str,
    exceptions: &str,
    today: i64,
    lookup: &dyn Fn(&str, &str) -> Result<String, String>,
) -> Report {
    let mut report = Report::default();
    let packages = match parse_lock(lock) {
        Ok(packages) => packages,
        Err(message) => {
            report.errors.push(message);
            return report;
        }
    };
    let entries = match parse_exceptions(exceptions) {
        Ok(entries) => entries,
        Err(message) => {
            report.errors.push(message);
            return report;
        }
    };

    let mut valid: Vec<&Exception> = Vec::new();
    for entry in &entries {
        match exception_problem(entry, &packages) {
            Some(problem) => report
                .invalid
                .push(format!("{}: {problem}", exception_label(entry))),
            None => valid.push(entry),
        }
    }

    for package in packages.iter().filter(|p| p.registry) {
        let label = format!("{} {}", package.name, package.version);
        let published = match lookup(&package.name, &package.version) {
            Ok(text) => match parse_timestamp_day(&text) {
                Some(day) => day,
                None => {
                    report
                        .errors
                        .push(format!("{label}: unparseable publish date `{text}`"));
                    continue;
                }
            },
            Err(message) => {
                report.errors.push(format!("{label}: {message}"));
                continue;
            }
        };
        let excepted = valid.iter().any(|e| {
            e.fields[0].as_deref() == Some(package.name.as_str())
                && e.fields[1].as_deref() == Some(package.version.as_str())
        });
        let age = today - published;
        if age >= COOLDOWN_DAYS {
            if excepted {
                report.stale.push(format!("{label}: now {age} days old"));
            }
        } else if !excepted {
            report
                .offenders
                .push(format!("{label}: published {age} days ago"));
        }
    }
    report
}

fn curl_lookup(name: &str, version: &str) -> Result<String, String> {
    std::thread::sleep(Duration::from_secs(1));
    let url = format!("https://crates.io/api/v1/crates/{name}/{version}");
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--retry",
            "5",
            "--retry-delay",
            "2",
            "--retry-all-errors",
            "--user-agent",
            "kurla-cooldown-check",
            &url,
        ])
        .output()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid JSON from crates.io: {e}"))?;
    json["version"]["created_at"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "response has no version.created_at".to_string())
}

fn today_utc() -> Result<i64, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock before 1970: {e}"))?
        .as_secs();
    i64::try_from(seconds / 86_400).map_err(|e| e.to_string())
}

pub fn run() -> ExitCode {
    let lock = match std::fs::read_to_string(LOCK_PATH) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("cannot read {LOCK_PATH}: {e}");
            return ExitCode::from(1);
        }
    };
    let exceptions = match std::fs::read_to_string(EXCEPTIONS_PATH) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            eprintln!("cannot read {EXCEPTIONS_PATH}: {e}");
            return ExitCode::from(1);
        }
    };
    let today = match today_utc() {
        Ok(day) => day,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(1);
        }
    };
    let report = evaluate(&lock, &exceptions, today, &curl_lookup);
    print!("{}", report.render());
    if report.passed() {
        println!("cooldown-check: ok");
        ExitCode::SUCCESS
    } else {
        println!("cooldown-check: FAILED");
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn today() -> i64 {
        days_from_civil(2026, 11, 19)
    }

    fn lock(packages: &[(&str, &str, bool)]) -> String {
        let mut out = String::from("version = 4\n");
        for (name, version, registry) in packages {
            out.push_str(&format!(
                "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n"
            ));
            if *registry {
                out.push_str(
                    "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
                );
                out.push_str("checksum = \"00\"\n");
                out.push_str("dependencies = [\n \"other\",\n]\n");
            }
        }
        out
    }

    fn exception(
        name: &str,
        version: &str,
        advisory: &str,
        replaces: &str,
        reviewer: &str,
        date: &str,
    ) -> String {
        format!(
            "[[exception]]\ncrate = \"{name}\"\nversion = \"{version}\"\nadvisory = \"{advisory}\"\nreplaces = \"{replaces}\"\nreviewed_by = \"{reviewer}\"\ndate = \"{date}\"\n"
        )
    }

    fn good_exception() -> String {
        exception(
            "fresh",
            "1.0.0",
            "RUSTSEC-2026-0001",
            "1.0.0-old",
            "kiri1101",
            "2026-11-18",
        )
    }

    fn evaluate_with(lock_text: &str, exceptions: &str, dates: &[(&str, &str, &str)]) -> Report {
        let map: HashMap<(String, String), String> = dates
            .iter()
            .map(|(n, v, d)| ((n.to_string(), v.to_string()), d.to_string()))
            .collect();
        evaluate(lock_text, exceptions, today(), &|name, version| {
            map.get(&(name.to_string(), version.to_string()))
                .cloned()
                .ok_or_else(|| format!("no fixture for {name} {version}"))
        })
    }

    #[test]
    fn young_version_without_exception_fails() {
        let report = evaluate_with(
            &lock(&[("fresh", "1.0.0", true)]),
            "",
            &[("fresh", "1.0.0", "2026-11-18T10:00:00.5Z")],
        );
        assert!(!report.passed());
        assert_eq!(report.offenders.len(), 1);
        assert!(report.offenders[0].contains("fresh"));
        assert!(report.offenders[0].contains("1.0.0"));
        assert!(report.render().contains("fresh 1.0.0"));
    }

    #[test]
    fn young_version_with_valid_exception_passes() {
        let report = evaluate_with(
            &lock(&[("fresh", "1.0.0", true)]),
            &good_exception(),
            &[("fresh", "1.0.0", "2026-11-18T10:00:00.5Z")],
        );
        assert!(report.passed(), "{}", report.render());
        assert!(report.offenders.is_empty());
        assert!(report.invalid.is_empty());
        assert!(report.stale.is_empty());
    }

    #[test]
    fn malformed_advisory_id_rejected() {
        let bad = [
            "RUSTSEC-2026-123",
            "RUSTSEC-2026-12345",
            "RUSTSEC-26-1234",
            "RUSTSEC-2026-12a4",
            "RUSTSEC-2026-1234x",
            "xRUSTSEC-2026-1234",
            "rustsec-2026-1234",
            "GHSA-abcd-efgh-ijk",
            "GHSA-abcd-efgh-ijklm",
            "GHSA-abcd-efgh",
            "GHSA-ABCD-efgh-ijkl",
            "GHSA-abcd-efgh-ijk!",
            "GHSA-abcd-efgh-ijkl-mnop",
            "CVE-2026-1234",
            "",
        ];
        for advisory in bad {
            let report = evaluate_with(
                &lock(&[("fresh", "1.0.0", true)]),
                &exception(
                    "fresh",
                    "1.0.0",
                    advisory,
                    "0.9.0",
                    "kiri1101",
                    "2026-11-18",
                ),
                &[("fresh", "1.0.0", "2026-11-18T10:00:00Z")],
            );
            assert!(!report.passed(), "{advisory:?} must be rejected");
            assert_eq!(report.invalid.len(), 1, "{advisory:?}");
            assert!(report.invalid[0].contains("fresh"));
        }
    }

    #[test]
    fn well_formed_advisory_ids_accepted() {
        for advisory in [
            "RUSTSEC-2026-0001",
            "GHSA-ab12-cd34-ef56",
            "GHSA-0000-zzzz-9a9a",
        ] {
            let report = evaluate_with(
                &lock(&[("fresh", "1.0.0", true)]),
                &exception(
                    "fresh",
                    "1.0.0",
                    advisory,
                    "0.9.0",
                    "kiri1101",
                    "2026-11-18",
                ),
                &[("fresh", "1.0.0", "2026-11-18T10:00:00Z")],
            );
            assert!(report.passed(), "{advisory:?}: {}", report.render());
        }
    }

    #[test]
    fn rejected_exception_does_not_excuse_young_version() {
        let report = evaluate_with(
            &lock(&[("fresh", "1.0.0", true)]),
            &exception("fresh", "1.0.0", "bogus", "0.9.0", "kiri1101", "2026-11-18"),
            &[("fresh", "1.0.0", "2026-11-18T10:00:00Z")],
        );
        assert_eq!(report.offenders.len(), 1);
        assert_eq!(report.invalid.len(), 1);
    }

    #[test]
    fn exception_for_crate_not_in_lockfile_rejected() {
        let lock_text = lock(&[("fresh", "1.0.0", true), ("old", "2.0.0", true)]);
        let dates = [
            ("fresh", "1.0.0", "2026-01-01T00:00:00Z"),
            ("old", "2.0.0", "2026-01-01T00:00:00Z"),
        ];
        for (name, version) in [("ghost", "1.0.0"), ("fresh", "1.0.1"), ("old", "1.0.0")] {
            let report = evaluate_with(
                &lock_text,
                &exception(
                    name,
                    version,
                    "RUSTSEC-2026-0001",
                    "0.9.0",
                    "kiri1101",
                    "2026-11-18",
                ),
                &dates,
            );
            assert!(!report.passed(), "{name} {version}");
            assert_eq!(report.invalid.len(), 1);
            assert!(report.invalid[0].contains(name));
            assert!(report.invalid[0].contains(version));
        }
    }

    #[test]
    fn exception_for_path_package_rejected() {
        let report = evaluate_with(
            &lock(&[("local", "1.0.0", false)]),
            &exception(
                "local",
                "1.0.0",
                "RUSTSEC-2026-0001",
                "0.9.0",
                "kiri1101",
                "2026-11-18",
            ),
            &[],
        );
        assert_eq!(report.invalid.len(), 1);
    }

    #[test]
    fn thirteen_days_old_fails_and_fourteen_days_old_passes() {
        let lock_text = lock(&[("young", "1.0.0", true), ("ripe", "1.0.0", true)]);
        let report = evaluate_with(
            &lock_text,
            "",
            &[
                ("young", "1.0.0", "2026-11-06T00:00:00Z"),
                ("ripe", "1.0.0", "2026-11-05T23:59:59Z"),
            ],
        );
        assert_eq!(report.offenders.len(), 1);
        assert!(report.offenders[0].contains("young"));
    }

    #[test]
    fn published_today_fails() {
        let report = evaluate_with(
            &lock(&[("fresh", "1.0.0", true)]),
            "",
            &[("fresh", "1.0.0", "2026-11-19T00:00:00Z")],
        );
        assert!(!report.passed());
    }

    #[test]
    fn stale_exception_is_reported_but_does_not_fail() {
        let report = evaluate_with(
            &lock(&[("fresh", "1.0.0", true)]),
            &good_exception(),
            &[("fresh", "1.0.0", "2026-11-05T08:00:00Z")],
        );
        assert!(report.passed(), "{}", report.render());
        assert_eq!(report.stale.len(), 1);
        assert!(report.stale[0].contains("fresh"));
        assert!(report.render().contains("stale exception"));
    }

    #[test]
    fn exception_one_day_short_of_stale_is_not_reported() {
        let report = evaluate_with(
            &lock(&[("fresh", "1.0.0", true)]),
            &good_exception(),
            &[("fresh", "1.0.0", "2026-11-06T08:00:00Z")],
        );
        assert!(report.stale.is_empty());
        assert!(report.passed());
    }

    #[test]
    fn exception_with_missing_or_empty_field_rejected() {
        let lock_text = lock(&[("fresh", "1.0.0", true)]);
        let dates = [("fresh", "1.0.0", "2026-11-18T10:00:00Z")];
        let full = good_exception();
        for field in [
            "crate",
            "version",
            "advisory",
            "replaces",
            "reviewed_by",
            "date",
        ] {
            let without: String = full
                .lines()
                .filter(|l| !l.starts_with(&format!("{field} =")))
                .map(|l| format!("{l}\n"))
                .collect();
            let report = evaluate_with(&lock_text, &without, &dates);
            assert!(!report.passed(), "missing {field}");
            assert!(!report.invalid.is_empty(), "missing {field}");

            let empty: String = full
                .lines()
                .map(|l| {
                    if l.starts_with(&format!("{field} =")) {
                        format!("{field} = \"\"\n")
                    } else {
                        format!("{l}\n")
                    }
                })
                .collect();
            let report = evaluate_with(&lock_text, &empty, &dates);
            assert!(!report.passed(), "empty {field}");
            assert!(!report.invalid.is_empty(), "empty {field}");
        }
    }

    #[test]
    fn exception_with_malformed_date_rejected() {
        for date in [
            "2026-13-01",
            "2026-00-10",
            "2026-11-32",
            "2026-02-29",
            "2026-1-01",
            "20261101",
            "2026-11-18T00:00:00Z",
            "yesterday",
        ] {
            let report = evaluate_with(
                &lock(&[("fresh", "1.0.0", true)]),
                &exception(
                    "fresh",
                    "1.0.0",
                    "RUSTSEC-2026-0001",
                    "0.9.0",
                    "kiri1101",
                    date,
                ),
                &[("fresh", "1.0.0", "2026-11-18T10:00:00Z")],
            );
            assert!(!report.passed(), "{date}");
            assert_eq!(report.invalid.len(), 1, "{date}");
        }
    }

    #[test]
    fn exception_with_leap_day_date_accepted() {
        let report = evaluate_with(
            &lock(&[("fresh", "1.0.0", true)]),
            &exception(
                "fresh",
                "1.0.0",
                "RUSTSEC-2026-0001",
                "0.9.0",
                "kiri1101",
                "2024-02-29",
            ),
            &[("fresh", "1.0.0", "2026-11-18T10:00:00Z")],
        );
        assert!(report.passed(), "{}", report.render());
    }

    #[test]
    fn packages_without_a_source_are_not_looked_up() {
        let report = evaluate_with(&lock(&[("local", "0.1.0", false)]), "", &[]);
        assert!(report.passed(), "{}", report.render());
    }

    #[test]
    fn failed_lookup_fails_the_check() {
        let report = evaluate_with(&lock(&[("mystery", "1.0.0", true)]), "", &[]);
        assert!(!report.passed());
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("mystery"));
    }

    #[test]
    fn unparseable_lock_or_exceptions_fail_the_check() {
        let report = evaluate_with("this is not a lockfile\n", "", &[]);
        assert!(!report.passed());
        assert!(!report.errors.is_empty());

        let report = evaluate_with(
            &lock(&[("old", "1.0.0", true)]),
            "[[exception]]\nsurprise = \"x\"\n",
            &[("old", "1.0.0", "2026-01-01T00:00:00Z")],
        );
        assert!(!report.passed());
        assert!(!report.errors.is_empty());
    }

    #[test]
    fn unparseable_publish_date_fails_the_check() {
        let report = evaluate_with(
            &lock(&[("old", "1.0.0", true)]),
            "",
            &[("old", "1.0.0", "not-a-date")],
        );
        assert!(!report.passed());
        assert_eq!(report.errors.len(), 1);
    }

    #[test]
    fn clean_lock_passes() {
        let report = evaluate_with(
            &lock(&[("old", "1.0.0", true)]),
            "",
            &[("old", "1.0.0", "2026-01-01T00:00:00Z")],
        );
        assert!(report.passed());
        assert!(report.offenders.is_empty());
    }

    #[test]
    fn days_from_civil_matches_hand_calculation() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(
            days_from_civil(2024, 3, 1) - days_from_civil(2024, 2, 28),
            2
        );
        assert_eq!(
            days_from_civil(2026, 3, 1) - days_from_civil(2026, 2, 28),
            1
        );
        assert_eq!(days_from_civil(2026, 11, 19), 20776);
    }
}

use crate::cache::{Cache, executable_hash};
use crate::decisions::{self, Applied};
use crate::glob::Glob;
use crate::limits::Limits;
use crate::model::Severity;
use crate::report::{Report, escape, human, json, sarif};
use crate::walk::{ScanOptions, scan_paths};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub paths: Vec<PathBuf>,
    pub format: Format,
    pub output: Option<PathBuf>,
    pub fail_on: Severity,
    pub require_complete: bool,
    pub excludes: Vec<String>,
    pub follow_symlinks: bool,
    pub decisions_base: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub no_cache: bool,
    pub jobs: usize,
    pub max_file_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Version,
    Help,
    Scan(Options),
}

pub const USAGE: &str = "usage:
  kurla scan [PATH]... [--format human|json|sarif] [--output FILE]
             [--fail-on info|low|medium|high|critical] [--require-complete]
             [--exclude GLOB]... [--follow-symlinks] [--decisions-base FILE]
             [--cache-dir DIR] [--no-cache] [--jobs N] [--max-file-size BYTES]
  kurla --version
  kurla --help";

fn shown(text: &std::ffi::OsStr) -> String {
    escape(&text.to_string_lossy())
}

pub fn parse(args: &[OsString]) -> Result<Command, String> {
    let Some(first) = args.first() else {
        return Err("missing command".to_string());
    };
    match first.to_str() {
        Some("--version") if args.len() == 1 => Ok(Command::Version),
        Some("--version") => Err("unexpected argument after --version".to_string()),
        Some("--help" | "-h") => Ok(Command::Help),
        Some("scan") => parse_scan(&args[1..]),
        _ => Err(format!("unknown command `{}`", shown(first))),
    }
}

fn value_of(
    name: &str,
    inline: Option<OsString>,
    rest: &mut std::slice::Iter<OsString>,
) -> Result<OsString, String> {
    if let Some(value) = inline {
        return Ok(value);
    }
    match rest.as_slice().first() {
        Some(next) if !next.to_string_lossy().starts_with("--") => {
            rest.next();
            Ok(next.clone())
        }
        _ => Err(format!("missing value for {name}")),
    }
}

fn text_of(name: &str, value: OsString) -> Result<String, String> {
    value
        .into_string()
        .map_err(|value| format!("invalid value for {name}: `{}`", shown(&value)))
}

fn severity_of(name: &str) -> Option<Severity> {
    Some(match name {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => return None,
    })
}

fn parse_scan(args: &[OsString]) -> Result<Command, String> {
    let mut options = Options {
        paths: Vec::new(),
        format: Format::Human,
        output: None,
        fail_on: Severity::High,
        require_complete: false,
        excludes: Vec::new(),
        follow_symlinks: false,
        decisions_base: None,
        cache_dir: None,
        no_cache: false,
        jobs: 0,
        max_file_size: None,
    };
    let mut rest = args.iter();
    let mut flags_ended = false;
    while let Some(arg) = rest.next() {
        let text = arg.to_string_lossy();
        if flags_ended || !text.starts_with('-') || text.len() == 1 {
            options.paths.push(PathBuf::from(arg));
            continue;
        }
        if text == "--" {
            flags_ended = true;
            continue;
        }
        if text == "--help" {
            return Ok(Command::Help);
        }
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) if text.starts_with("--") => {
                (name.to_string(), Some(OsString::from(value)))
            }
            _ => (text.to_string(), None),
        };
        match name.as_str() {
            "--require-complete" | "--follow-symlinks" | "--no-cache" => {
                if inline.is_some() {
                    return Err(format!("{} takes no value", escape(&name)));
                }
                match name.as_str() {
                    "--require-complete" => options.require_complete = true,
                    "--follow-symlinks" => options.follow_symlinks = true,
                    _ => options.no_cache = true,
                }
            }
            "--format" => {
                let value = text_of("--format", value_of("--format", inline, &mut rest)?)?;
                options.format = match value.as_str() {
                    "human" => Format::Human,
                    "json" => Format::Json,
                    "sarif" => Format::Sarif,
                    _ => {
                        return Err(format!(
                            "invalid value for --format: `{}` (expected human, json or sarif)",
                            escape(&value)
                        ));
                    }
                };
            }
            "--fail-on" => {
                let value = text_of("--fail-on", value_of("--fail-on", inline, &mut rest)?)?;
                options.fail_on = severity_of(&value).ok_or_else(|| {
                    format!(
                        "invalid value for --fail-on: `{}` (expected info, low, medium, high or critical)",
                        escape(&value)
                    )
                })?;
            }
            "--output" => {
                options.output = Some(PathBuf::from(value_of("--output", inline, &mut rest)?));
            }
            "--exclude" => {
                options.excludes.push(text_of(
                    "--exclude",
                    value_of("--exclude", inline, &mut rest)?,
                )?);
            }
            "--decisions-base" => {
                options.decisions_base = Some(PathBuf::from(value_of(
                    "--decisions-base",
                    inline,
                    &mut rest,
                )?));
            }
            "--cache-dir" => {
                options.cache_dir =
                    Some(PathBuf::from(value_of("--cache-dir", inline, &mut rest)?));
            }
            "--jobs" => {
                let value = text_of("--jobs", value_of("--jobs", inline, &mut rest)?)?;
                options.jobs = match value.parse::<usize>() {
                    Ok(jobs) if jobs > 0 => jobs,
                    _ => {
                        return Err(format!(
                            "invalid value for --jobs: `{}` (expected a positive number)",
                            escape(&value)
                        ));
                    }
                };
            }
            "--max-file-size" => {
                let value = text_of(
                    "--max-file-size",
                    value_of("--max-file-size", inline, &mut rest)?,
                )?;
                options.max_file_size = Some(value.parse::<u64>().map_err(|_| {
                    format!(
                        "invalid value for --max-file-size: `{}` (expected a number of bytes)",
                        escape(&value)
                    )
                })?);
            }
            _ => return Err(format!("unknown flag `{}`", escape(&name))),
        }
    }
    if options.paths.is_empty() {
        options.paths.push(PathBuf::from("."));
    }
    Ok(Command::Scan(options))
}

const MAX_TEMP_ATTEMPTS: u32 = 16;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const CURRENT_DECISIONS: &str = ".kurla/decisions.json";

fn open_cache(
    dir: Result<PathBuf, String>,
    binary: Result<[u8; 32], String>,
    warnings: &mut Vec<String>,
) -> Option<Cache> {
    match (dir, binary) {
        (Err(reason), _) => {
            warnings.push(format!("cache disabled: {reason}"));
            None
        }
        (Ok(_), Err(reason)) => {
            warnings.push(format!(
                "cache disabled: cannot hash the running executable: {reason}"
            ));
            None
        }
        (Ok(dir), Ok(binary)) => Some(Cache::open(dir, binary)),
    }
}

pub fn run(args: &[OsString], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match parse(args) {
        Err(message) => {
            let _ = writeln!(err, "error: {message}\n{USAGE}");
            2
        }
        Ok(Command::Version) => {
            let written = writeln!(out, "kurla {}", env!("CARGO_PKG_VERSION"));
            if written.is_ok() { 0 } else { 2 }
        }
        Ok(Command::Help) => {
            let written = writeln!(out, "{USAGE}");
            if written.is_ok() { 0 } else { 2 }
        }
        Ok(Command::Scan(options)) => scan(&options, out, err),
    }
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn read_source(path: &str, cap: u64) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(cap).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

fn write_atomic_with(
    target: &Path,
    bytes: &[u8],
    names: &mut dyn FnMut(u32) -> PathBuf,
) -> std::io::Result<()> {
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let temp = names(attempt);
        let opened = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp);
        let mut file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let result = file
            .write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| fs::rename(&temp, target));
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        return result;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free temporary file name",
    ))
}

fn write_atomic(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with(target, bytes, &mut |_| {
        temp_path(target, TEMP_COUNTER.fetch_add(1, Ordering::SeqCst))
    })
}

fn temp_path(target: &Path, counter: u64) -> PathBuf {
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    target.with_file_name(format!(
        ".{name}.kurla-tmp-{}-{counter}-{nanos}",
        std::process::id()
    ))
}

fn scan(options: &Options, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut excludes = Vec::new();
    for pattern in &options.excludes {
        match Glob::new(pattern) {
            Ok(glob) => excludes.push(glob),
            Err(error) => {
                let _ = writeln!(
                    err,
                    "error: invalid --exclude pattern `{}`: {error}\n{USAGE}",
                    escape(pattern)
                );
                return 2;
            }
        }
    }
    for path in &options.paths {
        let missing = fs::symlink_metadata(path)
            .err()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound);
        if missing {
            let _ = writeln!(
                err,
                "error: path does not exist: {}",
                shown(path.as_os_str())
            );
            return 2;
        }
    }
    let current = Path::new(CURRENT_DECISIONS);
    let current = exists(current).then_some(current);
    let base = options.decisions_base.as_deref();
    let today = if current.is_some() || base.is_some() {
        match decisions::today() {
            Ok(today) => Some(today),
            Err(error) => {
                let _ = writeln!(err, "error: {}", escape(&error.message));
                return 2;
            }
        }
    } else {
        None
    };
    let mut warnings = Vec::new();
    let cache = if options.no_cache {
        None
    } else {
        open_cache(
            Cache::resolve_dir(options.cache_dir.clone()),
            executable_hash(),
            &mut warnings,
        )
    };
    let mut limits = Limits::default();
    if let Some(max) = options.max_file_size {
        limits.max_file_bytes = max;
    }
    let cap = limits.max_file_bytes;
    let scan_options = ScanOptions {
        excludes,
        follow_symlinks: options.follow_symlinks,
        jobs: options.jobs,
        limits,
        cache,
    };
    let mut result = scan_paths(&options.paths, &scan_options);
    warnings.append(&mut result.warnings);
    let applied = match today {
        Some(today) => decisions::load_and_apply(&mut result.findings, current, base, today),
        None => Applied::default(),
    };
    let report = Report {
        findings: &result.findings,
        coverage: &result.coverage,
        carrier_counts: &result.carrier_counts,
        threshold: options.fail_on,
        require_complete: options.require_complete,
        invalid: &applied.invalid,
        rejected: &applied.rejected,
        warnings: &warnings,
    };
    let mut rendered = match options.format {
        Format::Human => human::render(&report),
        Format::Json => json::render(&report),
        Format::Sarif => sarif::render(&report, &|path| read_source(path, cap)),
    };
    if options.format != Format::Human {
        rendered.push('\n');
    }
    for warning in &warnings {
        let _ = writeln!(err, "warning: {}", escape(warning));
    }
    for file in &applied.rejected {
        let _ = writeln!(
            err,
            "error: decisions file {}: {}",
            escape(&file.file),
            escape(&file.message)
        );
    }
    let written = match &options.output {
        Some(target) => write_atomic(target, rendered.as_bytes()).map_err(|error| {
            format!(
                "cannot write {}: {}",
                shown(target.as_os_str()),
                escape(&error.to_string())
            )
        }),
        None => out
            .write_all(rendered.as_bytes())
            .and_then(|()| out.flush())
            .map_err(|error| format!("cannot write the report: {}", escape(&error.to_string()))),
    };
    if let Err(message) = written {
        let _ = writeln!(err, "error: {message}");
        return 2;
    }
    report.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn scan(list: &[&str]) -> Options {
        match parse(&args(list)).unwrap() {
            Command::Scan(options) => options,
            other => panic!("expected a scan, got {other:?}"),
        }
    }

    fn usage_error(list: &[&str]) -> String {
        parse(&args(list)).unwrap_err()
    }

    #[test]
    fn defaults_scan_the_current_directory_and_fail_on_high() {
        let options = scan(&["scan"]);
        assert_eq!(options.paths, vec![PathBuf::from(".")]);
        assert_eq!(options.format, Format::Human);
        assert_eq!(options.fail_on, Severity::High);
        assert_eq!(options.output, None);
        assert!(!options.require_complete);
        assert!(options.excludes.is_empty());
        assert!(!options.follow_symlinks);
        assert_eq!(options.decisions_base, None);
        assert_eq!(options.cache_dir, None);
        assert!(!options.no_cache);
        assert_eq!(options.jobs, 0);
        assert_eq!(options.max_file_size, None);
    }

    #[test]
    fn every_flag_is_parsed() {
        let options = scan(&[
            "scan",
            "a",
            "b",
            "--format",
            "sarif",
            "--output",
            "out.sarif",
            "--fail-on",
            "low",
            "--require-complete",
            "--exclude",
            "*.log",
            "--exclude",
            "build/**",
            "--follow-symlinks",
            "--decisions-base",
            "base.json",
            "--cache-dir",
            "cache",
            "--no-cache",
            "--jobs",
            "3",
            "--max-file-size",
            "1024",
        ]);
        assert_eq!(options.paths, vec![PathBuf::from("a"), PathBuf::from("b")]);
        assert_eq!(options.format, Format::Sarif);
        assert_eq!(options.output, Some(PathBuf::from("out.sarif")));
        assert_eq!(options.fail_on, Severity::Low);
        assert!(options.require_complete);
        assert_eq!(options.excludes, vec!["*.log", "build/**"]);
        assert!(options.follow_symlinks);
        assert_eq!(options.decisions_base, Some(PathBuf::from("base.json")));
        assert_eq!(options.cache_dir, Some(PathBuf::from("cache")));
        assert!(options.no_cache);
        assert_eq!(options.jobs, 3);
        assert_eq!(options.max_file_size, Some(1024));
    }

    #[test]
    fn flags_and_paths_may_be_mixed_and_equals_form_works() {
        let options = scan(&["scan", "--format=json", "a", "--fail-on=critical", "b"]);
        assert_eq!(options.paths, vec![PathBuf::from("a"), PathBuf::from("b")]);
        assert_eq!(options.format, Format::Json);
        assert_eq!(options.fail_on, Severity::Critical);
    }

    #[test]
    fn double_dash_ends_the_flags() {
        let options = scan(&["scan", "--", "--odd-name", "-x"]);
        assert_eq!(
            options.paths,
            vec![PathBuf::from("--odd-name"), PathBuf::from("-x")]
        );
    }

    #[test]
    fn every_severity_is_accepted_by_fail_on() {
        for (name, severity) in [
            ("info", Severity::Info),
            ("low", Severity::Low),
            ("medium", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
        ] {
            assert_eq!(scan(&["scan", "--fail-on", name]).fail_on, severity);
        }
    }

    #[test]
    fn version_and_help_are_commands() {
        assert_eq!(parse(&args(&["--version"])), Ok(Command::Version));
        assert_eq!(parse(&args(&["--help"])), Ok(Command::Help));
        assert_eq!(parse(&args(&["-h"])), Ok(Command::Help));
    }

    #[test]
    fn usage_errors_name_the_problem() {
        assert!(usage_error(&[]).contains("missing command"));
        assert!(usage_error(&["frobnicate"]).contains("unknown command"));
        assert!(usage_error(&["--version", "x"]).contains("unexpected"));
        assert!(usage_error(&["scan", "--bogus"]).contains("unknown flag `--bogus`"));
        assert!(usage_error(&["scan", "--format"]).contains("missing value for --format"));
        assert!(usage_error(&["scan", "--exclude"]).contains("missing value for --exclude"));
        assert!(usage_error(&["scan", "--format", "xml"]).contains("--format"));
        assert!(usage_error(&["scan", "--fail-on", "severe"]).contains("--fail-on"));
        assert!(usage_error(&["scan", "--jobs", "many"]).contains("--jobs"));
        assert!(usage_error(&["scan", "--jobs", "0"]).contains("--jobs"));
        assert!(usage_error(&["scan", "--jobs", "-1"]).contains("--jobs"));
        assert!(usage_error(&["scan", "--max-file-size", "big"]).contains("--max-file-size"));
        assert!(usage_error(&["scan", "--require-complete=yes"]).contains("takes no value"));
    }

    #[test]
    fn usage_error_text_escapes_what_the_user_typed() {
        let message = usage_error(&["scan", "--bog\u{202E}us"]);
        assert!(!message.contains('\u{202E}'));
        assert!(message.contains("\\u{202E}"));
    }

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Scratch {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("kurla-cli-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Scratch { path }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn create_new_retries_past_an_existing_regular_file_at_the_first_name() {
        let scratch = Scratch::new();
        let target = scratch.path.join("report.json");
        let taken = scratch.path.join("first");
        fs::write(&taken, b"planted").unwrap();
        let second = scratch.path.join("second");
        let mut offered = Vec::new();
        let mut names = |attempt: u32| {
            offered.push(attempt);
            if attempt == 0 {
                taken.clone()
            } else {
                second.clone()
            }
        };
        write_atomic_with(&target, b"report", &mut names).unwrap();
        assert_eq!(offered, vec![0, 1]);
        assert_eq!(fs::read(&taken).unwrap(), b"planted");
        assert_eq!(fs::read(&target).unwrap(), b"report");
        assert!(!second.exists());
    }

    #[test]
    fn create_new_gives_up_after_sixteen_taken_names() {
        let scratch = Scratch::new();
        let target = scratch.path.join("report.json");
        let taken = scratch.path.join("taken");
        fs::write(&taken, b"planted").unwrap();
        let mut calls = 0u32;
        let mut names = |_: u32| {
            calls += 1;
            taken.clone()
        };
        let error = write_atomic_with(&target, b"report", &mut names).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(calls, 16);
        assert_eq!(fs::read(&taken).unwrap(), b"planted");
        assert!(!target.exists());
    }

    #[test]
    fn temp_names_differ_by_counter_and_stay_beside_the_target() {
        let target = Path::new("out").join("report.json");
        let first = temp_path(&target, 0);
        let second = temp_path(&target, 1);
        assert_ne!(first, second);
        assert_eq!(first.parent(), target.parent());
    }

    #[cfg(unix)]
    #[test]
    fn output_temp_never_follows_a_planted_symlink() {
        let scratch = Scratch::new();
        let target = scratch.path.join("report.json");
        let victim = scratch.path.join("victim");
        fs::write(&victim, b"precious").unwrap();
        let planted = scratch.path.join("first");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        let second = scratch.path.join("second");
        let mut names = |attempt: u32| {
            if attempt == 0 {
                planted.clone()
            } else {
                second.clone()
            }
        };
        write_atomic_with(&target, b"report", &mut names).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        assert_eq!(fs::read(&target).unwrap(), b"report");
    }

    #[test]
    fn a_failed_rename_removes_only_the_temp_file_it_created() {
        let scratch = Scratch::new();
        let target = scratch.path.join("occupied");
        fs::create_dir(&target).unwrap();
        let temp = scratch.path.join("temp");
        let mut names = |_: u32| temp.clone();
        assert!(write_atomic_with(&target, b"report", &mut names).is_err());
        assert!(!temp.exists());
        assert!(target.is_dir());
    }

    #[test]
    fn unhashable_executable_disables_cache_with_warning() {
        let mut warnings = Vec::new();
        let cache = open_cache(
            Ok(PathBuf::from("somewhere")),
            Err("access denied".to_string()),
            &mut warnings,
        );
        assert!(cache.is_none());
        assert_eq!(
            warnings,
            vec!["cache disabled: cannot hash the running executable: access denied".to_string()]
        );
    }

    #[test]
    fn hashable_executable_and_directory_enable_cache_without_warning() {
        let mut warnings = Vec::new();
        let dir = std::env::temp_dir().join(format!("kurla-cli-open-{}", std::process::id()));
        let cache = open_cache(Ok(dir.clone()), Ok([3; 32]), &mut warnings);
        assert_eq!(cache.as_ref().map(Cache::dir), Some(dir.as_path()));
        assert!(warnings.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unresolvable_directory_disables_cache_with_its_reason() {
        let mut warnings = Vec::new();
        let cache = open_cache(Err("no home".to_string()), Ok([3; 32]), &mut warnings);
        assert!(cache.is_none());
        assert_eq!(warnings, vec!["cache disabled: no home".to_string()]);
    }
}

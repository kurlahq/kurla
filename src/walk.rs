use crate::engine::{scan_file, scan_oversize, unreadable};
use crate::glob::Glob;
use crate::limits::Limits;
use crate::model::{CarrierKind, Category, FileCoverage, FileKind, Finding, SkipReason};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;

const PREFIX_BYTES: u64 = 8192;
const MAX_DEFAULT_JOBS: usize = 4;

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub excludes: Vec<Glob>,
    pub follow_symlinks: bool,
    pub jobs: usize,
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub coverage: Vec<FileCoverage>,
    pub carrier_counts: BTreeMap<CarrierKind, u64>,
}

type Scanned = (Vec<Finding>, FileCoverage, BTreeMap<CarrierKind, u64>);

enum Plan {
    Scan(PathBuf),
    Record(SkipReason),
    Unreadable,
}

struct Work {
    display: String,
    class: String,
    plan: Plan,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}

fn strip_verbatim(text: &str) -> String {
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    text.strip_prefix(r"\\?\").unwrap_or(text).to_string()
}

fn slashed(text: &str) -> String {
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.to_string()
    }
}

fn display_of(path: &Path, cwd: Option<&Path>) -> String {
    let relative = cwd
        .and_then(|cwd| path.strip_prefix(cwd).ok())
        .filter(|rest| !rest.as_os_str().is_empty());
    let shown = relative.unwrap_or(path);
    match shown.to_str() {
        Some(text) if relative.is_some() => slashed(text),
        Some(text) => slashed(&strip_verbatim(text)),
        None => format!("hex:{}", hex(&path_bytes(shown))),
    }
}

fn text_or_hex(path: &Path) -> String {
    match path.to_str() {
        Some(text) => slashed(text),
        None => format!("hex:{}", hex(&path_bytes(path))),
    }
}

fn error_site<'a>(path: Option<&'a Path>, open_dirs: &'a [PathBuf], root: &'a Path) -> &'a Path {
    path.or_else(|| open_dirs.last().map(PathBuf::as_path))
        .unwrap_or(root)
}

fn long_form(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok()
}

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(MAX_DEFAULT_JOBS)
}

fn recorded(path: &str, skip: SkipReason) -> FileCoverage {
    let kind = FileKind::UnknownBinary;
    FileCoverage {
        path: path.to_string(),
        kind,
        category: Category::UnknownBinary,
        skip: Some(skip),
        drawn_text_unscanned: kind.drawn_text_unscanned(),
        embedded_not_scanned: Vec::new(),
        encoded_runs_not_payloads: 0,
    }
}

struct Walker<'a> {
    opts: &'a ScanOptions,
    cwd: Option<PathBuf>,
    roots: Vec<PathBuf>,
    seen: HashSet<PathBuf>,
    recorded: HashSet<String>,
    work: Vec<Work>,
}

impl Walker<'_> {
    fn display(&self, path: &Path) -> String {
        display_of(path, self.cwd.as_deref())
    }

    fn class_of(&self, root: &Path, root_is_dir: bool, path: &Path) -> String {
        if root_is_dir {
            return text_or_hex(path.strip_prefix(root).unwrap_or(path));
        }
        let display = self.display(path);
        let under_cwd = self
            .cwd
            .as_deref()
            .is_some_and(|cwd| path.strip_prefix(cwd).is_ok());
        if under_cwd {
            return display;
        }
        path.file_name()
            .map_or(display, |name| text_or_hex(Path::new(name)))
    }

    fn push_scan(&mut self, path: &Path, class: String) {
        let display = self.display(path);
        self.work.push(Work {
            display,
            class,
            plan: Plan::Scan(path.to_path_buf()),
        });
    }

    fn record(&mut self, path: &Path, class: String, plan: Plan) {
        let display = self.display(path);
        if self.recorded.insert(display.clone()) {
            self.work.push(Work {
                display,
                class,
                plan,
            });
        }
    }

    fn first_scan(&mut self, path: &Path) -> bool {
        let key = if self.opts.follow_symlinks {
            long_form(path).unwrap_or_else(|| path.to_path_buf())
        } else {
            path.to_path_buf()
        };
        self.seen.insert(key)
    }

    fn inside_a_root(&self, target: &Path) -> bool {
        self.roots.iter().any(|root| target.starts_with(root))
    }

    fn excluded(&self, class: &str) -> bool {
        self.opts.excludes.iter().any(|glob| glob.matches(class))
    }

    fn walk_root(&mut self, given: &Path) {
        let Some(root) = long_form(given) else {
            let class = text_or_hex(given);
            self.record(given, class, Plan::Unreadable);
            return;
        };
        let root_is_dir = root.is_dir();
        let mut open_dirs: Vec<PathBuf> = Vec::new();
        let mut walk = WalkDir::new(&root)
            .follow_links(self.opts.follow_symlinks)
            .sort_by_file_name()
            .into_iter();
        while let Some(next) = walk.next() {
            let entry = match next {
                Ok(entry) => entry,
                Err(error) => {
                    self.walk_error(&root, root_is_dir, &open_dirs, &error);
                    continue;
                }
            };
            let path = entry.path().to_path_buf();
            let file_type = entry.file_type();
            let is_dir = file_type.is_dir();
            open_dirs.truncate(entry.depth());
            if is_dir {
                open_dirs.push(path.clone());
            }
            if entry.depth() == 0 && is_dir {
                continue;
            }
            if is_dir && entry.depth() > 0 && entry.file_name() == ".git" {
                walk.skip_current_dir();
                continue;
            }
            let class = self.class_of(&root, root_is_dir, &path);
            if self.excluded(&class) {
                if is_dir {
                    walk.skip_current_dir();
                }
                self.record(&path, class, Plan::Record(SkipReason::ExcludedByUser));
                continue;
            }
            if file_type.is_symlink() {
                self.record(&path, class, Plan::Record(SkipReason::SymlinkNotFollowed));
                continue;
            }
            if self.opts.follow_symlinks && entry.path_is_symlink() {
                let target = long_form(&path);
                if !target.as_deref().is_some_and(|t| self.inside_a_root(t)) {
                    if is_dir {
                        walk.skip_current_dir();
                    }
                    self.record(&path, class, Plan::Record(SkipReason::SymlinkNotFollowed));
                    continue;
                }
            }
            if is_dir {
                continue;
            }
            if file_type.is_file() {
                if self.first_scan(&path) {
                    self.push_scan(&path, class);
                }
            } else {
                self.record(&path, class, Plan::Record(SkipReason::Unreadable));
            }
        }
    }

    fn walk_error(
        &mut self,
        root: &Path,
        root_is_dir: bool,
        open_dirs: &[PathBuf],
        error: &walkdir::Error,
    ) {
        let path = error_site(error.path(), open_dirs, root);
        let class = self.class_of(root, root_is_dir, path);
        let plan = if error.loop_ancestor().is_some() {
            Plan::Record(SkipReason::SymlinkNotFollowed)
        } else {
            Plan::Unreadable
        };
        self.record(path, class, plan);
    }
}

fn read_capped(path: &Path, cap: u64) -> std::io::Result<(Vec<u8>, u64)> {
    let file = fs::File::open(path)?;
    let declared = file.metadata()?.len();
    let mut bytes = Vec::new();
    file.take(cap).read_to_end(&mut bytes)?;
    Ok((bytes, declared))
}

fn scan_regular(path: &Path, class: &str, opts: &ScanOptions) -> Scanned {
    let meta = if opts.follow_symlinks {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    let Ok(meta) = meta else {
        return unreadable(class);
    };
    if meta.file_type().is_symlink() {
        return not_followed(class);
    }
    if !meta.file_type().is_file() {
        return (
            Vec::new(),
            recorded(class, SkipReason::Unreadable),
            BTreeMap::new(),
        );
    }
    let max = opts.limits.max_file_bytes;
    if meta.len() > max {
        return match read_capped(path, PREFIX_BYTES) {
            Ok((prefix, _)) => scan_oversize(class, &prefix, meta.len(), &opts.limits),
            Err(_) => unreadable(class),
        };
    }
    match read_capped(path, max.saturating_add(1)) {
        Ok((bytes, declared)) => {
            let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            if len > max {
                let prefix_end = bytes.len().min(PREFIX_BYTES as usize);
                scan_oversize(class, &bytes[..prefix_end], declared.max(len), &opts.limits)
            } else {
                scan_file(class, &bytes, &opts.limits)
            }
        }
        Err(_) => unreadable(class),
    }
}

fn not_followed(class: &str) -> Scanned {
    (
        Vec::new(),
        recorded(class, SkipReason::SymlinkNotFollowed),
        BTreeMap::new(),
    )
}

fn run_one(item: &Work, opts: &ScanOptions) -> Scanned {
    let (mut findings, mut coverage, counts) = match &item.plan {
        Plan::Scan(path) => scan_regular(path, &item.class, opts),
        Plan::Record(skip) => (Vec::new(), recorded(&item.class, *skip), BTreeMap::new()),
        Plan::Unreadable => unreadable(&item.class),
    };
    for finding in &mut findings {
        finding.path.clone_from(&item.display);
    }
    coverage.path.clone_from(&item.display);
    (findings, coverage, counts)
}

fn run_all(work: &[Work], opts: &ScanOptions) -> Vec<Scanned> {
    let wanted = if opts.jobs == 0 {
        default_jobs()
    } else {
        opts.jobs
    };
    let workers = wanted.clamp(1, work.len().max(1));
    let next = AtomicUsize::new(0);
    let done: Mutex<Vec<(usize, Scanned)>> = Mutex::new(Vec::with_capacity(work.len()));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(item) = work.get(index) else {
                        break;
                    };
                    local.push((index, run_one(item, opts)));
                }
                done.lock().unwrap_or_else(|e| e.into_inner()).extend(local);
            });
        }
    });
    let mut finished = done.into_inner().unwrap_or_else(|e| e.into_inner());
    finished.sort_by_key(|(index, _)| *index);
    finished.into_iter().map(|(_, scanned)| scanned).collect()
}

pub fn scan_paths(paths: &[PathBuf], opts: &ScanOptions) -> ScanResult {
    let cwd = std::env::current_dir().ok().and_then(|cwd| long_form(&cwd));
    let mut roots: Vec<PathBuf> = paths.iter().filter_map(|path| long_form(path)).collect();
    roots.sort();
    roots.dedup();
    let mut walker = Walker {
        opts,
        cwd,
        roots,
        seen: HashSet::new(),
        recorded: HashSet::new(),
        work: Vec::new(),
    };
    for given in paths {
        walker.walk_root(given);
    }
    let mut work = walker.work;
    work.sort_by(|a, b| a.display.cmp(&b.display));
    let scanned = run_all(&work, opts);
    let mut findings = Vec::new();
    let mut coverage = Vec::new();
    let mut carrier_counts: BTreeMap<CarrierKind, u64> = BTreeMap::new();
    for (file_findings, file_coverage, counts) in scanned {
        findings.extend(file_findings);
        coverage.push(file_coverage);
        for (kind, count) in counts {
            *carrier_counts.entry(kind).or_insert(0) += count;
        }
    }
    findings.sort_by(|a, b| {
        (&a.path, a.raw.span.byte_start, a.raw.rule_id).cmp(&(
            &b.path,
            b.raw.span.byte_start,
            b.raw.rule_id,
        ))
    });
    ScanResult {
        findings,
        coverage,
        carrier_counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_site_prefers_the_error_path() {
        let root = PathBuf::from("root");
        let dirs = vec![PathBuf::from("root"), PathBuf::from("root/a")];
        let own = PathBuf::from("root/a/b");
        assert_eq!(error_site(Some(&own), &dirs, &root), own.as_path());
    }

    #[test]
    fn pathless_error_is_attributed_to_the_deepest_open_directory() {
        let root = PathBuf::from("root");
        let dirs = vec![PathBuf::from("root"), PathBuf::from("root/a")];
        assert_eq!(error_site(None, &dirs, &root), Path::new("root/a"));
    }

    #[test]
    fn pathless_error_with_no_open_directory_is_attributed_to_the_root() {
        let root = PathBuf::from("root/file.txt");
        assert_eq!(error_site(None, &[], &root), root.as_path());
    }

    #[test]
    fn text_or_hex_keeps_utf8_and_hex_encodes_the_rest() {
        assert_eq!(text_or_hex(Path::new("a/b.txt")), "a/b.txt");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let odd = Path::new(std::ffi::OsStr::from_bytes(b"a\xff"));
            assert_eq!(text_or_hex(odd), "hex:61ff");
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            let odd = std::ffi::OsString::from_wide(&[0x61, 0xD800]);
            assert_eq!(text_or_hex(Path::new(&odd)), "hex:610000d8");
        }
    }
}

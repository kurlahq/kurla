use kurla::engine::scan_file;
use kurla::limits::Limits;

use crate::spans;

const NAMES: [&str; 5] = [
    "fuzz.bin",
    "x.md",
    "x.svg",
    "x.png",
    ".claude/settings.json",
];

pub fn limits() -> Limits {
    Limits {
        max_decompressed_bytes: 4096,
        max_base64_run_bytes: 1024,
        ..Limits::default()
    }
}

pub fn check(data: &[u8]) {
    let limits = limits();
    for name in NAMES {
        let (findings, coverage, _) = scan_file(name, data, &limits);
        let raws: Vec<_> = findings.iter().map(|f| f.raw.clone()).collect();
        let embedded: Vec<_> = coverage
            .embedded_not_scanned
            .iter()
            .map(|e| e.span)
            .collect();
        spans::check_spans(data.len(), name, &raws, &[], &embedded);
    }
}

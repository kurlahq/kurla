use kurla::binary::scan_png;
use kurla::engine::scan_file;
use kurla::limits::{Budget, Limits};
use kurla::model::{DetectorOutput, SkipReason};

use crate::spans;

const NAMES: [&str; 5] = [
    "fuzz.bin",
    "x.md",
    "x.svg",
    "x.png",
    ".claude/settings.json",
];

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

pub fn limits() -> Limits {
    Limits {
        max_decompressed_bytes: 4096,
        max_base64_run_bytes: 1024,
        ..Limits::default()
    }
}

pub fn check_png_propagation(small: &DetectorOutput, scanned_skip: Option<SkipReason>) {
    if small.skip != Some(SkipReason::DecompressionLimit) {
        return;
    }
    if scanned_skip == Some(SkipReason::Timeout) {
        return;
    }
    assert!(
        scanned_skip == small.skip,
        "scan_file: x.png lost the skip reason {:?}, got {:?}",
        small.skip,
        scanned_skip
    );
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
        if name == "x.png" && data.starts_with(&PNG_SIGNATURE) {
            let small = scan_png(data, &mut Budget::new(&limits));
            check_png_propagation(&small, coverage.skip);
        }
    }
}

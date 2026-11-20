use kurla::binary::{scan_avif, scan_webp};
use kurla::limits::{Budget, Limits};

use crate::spans;

pub fn limits() -> Limits {
    Limits {
        max_decompressed_bytes: 4096,
        ..Limits::default()
    }
}

pub fn check(data: &[u8]) {
    let mut budget = Budget::new(&limits());
    let out = scan_webp(data, &mut budget);
    spans::check_spans(data.len(), "webp", &out.findings, &out.carriers, &[]);
    let mut budget = Budget::new(&limits());
    let out = scan_avif(data, &mut budget);
    spans::check_spans(data.len(), "avif", &out.findings, &out.carriers, &[]);
}

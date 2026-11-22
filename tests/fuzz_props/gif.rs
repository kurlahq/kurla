use kurla::binary::scan_gif;
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
    let out = scan_gif(data, &mut budget);
    spans::check_spans(data.len(), "gif", &out.findings, &out.carriers, &[]);
}

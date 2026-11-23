use kurla::binary::{scan_avif, scan_webp};
use kurla::limits::{Budget, Limits};
use kurla::model::Span;

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
    let embedded: Vec<Span> = out.embedded.iter().map(|blob| blob.span).collect();
    spans::check_spans(data.len(), "webp", &out.findings, &out.carriers, &embedded);
    let mut budget = Budget::new(&limits());
    let out = scan_avif(data, &mut budget);
    let embedded: Vec<Span> = out.embedded.iter().map(|blob| blob.span).collect();
    spans::check_spans(data.len(), "avif", &out.findings, &out.carriers, &embedded);
}

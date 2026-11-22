use kurla::binary::scan_jpeg;
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
    let out = scan_jpeg(data, &mut budget);
    let embedded: Vec<Span> = out.embedded.iter().map(|blob| blob.span).collect();
    spans::check_spans(data.len(), "jpeg", &out.findings, &out.carriers, &embedded);
}

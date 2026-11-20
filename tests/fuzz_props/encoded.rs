use kurla::encoded::scan_encoded;
use kurla::limits::{Budget, Limits};
use kurla::text::TextDoc;

use crate::spans;

pub fn limits() -> Limits {
    Limits {
        max_base64_run_bytes: 1024,
        max_decompressed_bytes: 4096,
        ..Limits::default()
    }
}

pub fn check(data: &[u8]) {
    let Some(doc) = TextDoc::decode(data) else {
        return;
    };
    let limits = limits();
    for depth in 0..=limits.max_decode_depth {
        let mut budget = Budget::new(&limits);
        let encoded = scan_encoded(&doc, depth, &mut budget);
        let blob_spans: Vec<_> = encoded.blobs.iter().map(|b| b.span).collect();
        spans::check_spans(
            data.len(),
            "encoded",
            &encoded.out.findings,
            &encoded.out.carriers,
            &blob_spans,
        );
    }
}

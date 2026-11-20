use kurla::limits::{Budget, Limits};
use kurla::svg::scan_svg;

use crate::spans;

pub fn limits() -> Limits {
    Limits {
        max_xml_depth: 16,
        max_xml_attributes: 32,
        max_decompressed_bytes: 4096,
        ..Limits::default()
    }
}

pub fn check(data: &[u8]) {
    let limits = limits();
    let mut budget = Budget::new(&limits);
    let out = scan_svg(data, &mut budget, &limits);
    spans::check_spans(data.len(), "svg", &out.findings, &out.carriers, &[]);
}

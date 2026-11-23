use kurla::binary::scan_png;
use kurla::limits::{Budget, Limits};
use kurla::model::{CarrierKind, DetectorOutput, SkipReason, Span};

use crate::spans;

const SMALL_LIMIT: u64 = 4096;
const LARGE_LIMIT: u64 = 65536;

pub fn limits() -> Limits {
    Limits {
        max_decompressed_bytes: SMALL_LIMIT,
        ..Limits::default()
    }
}

pub fn large_limits() -> Limits {
    Limits {
        max_decompressed_bytes: LARGE_LIMIT,
        ..Limits::default()
    }
}

fn limit_signalled(out: &DetectorOutput) -> bool {
    let finding = out
        .findings
        .iter()
        .any(|f| f.rule_id == "B002" && f.carrier == CarrierKind::ResourceLimit);
    let earlier_skip = matches!(
        out.skip,
        Some(SkipReason::SizeLimit | SkipReason::Malformed)
    ) && out
        .findings
        .iter()
        .any(|f| f.rule_id == "L001" || f.rule_id == "B003");
    finding && (out.skip == Some(SkipReason::DecompressionLimit) || earlier_skip)
}

pub fn check_decompression(small_consumed: u64, large_consumed: u64, small: &DetectorOutput) {
    assert!(
        small_consumed <= SMALL_LIMIT,
        "png: the small run consumed {small_consumed} bytes, over its limit of {SMALL_LIMIT}"
    );
    if large_consumed > SMALL_LIMIT && small.skip != Some(SkipReason::Timeout) {
        assert!(
            limit_signalled(small),
            "png: the large run consumed {large_consumed} bytes, over {SMALL_LIMIT}, but the small run carries no B002 decompression-limit signal"
        );
    }
}

pub fn check(data: &[u8]) {
    let mut small = Budget::new(&limits());
    let out = scan_png(data, &mut small);
    let embedded: Vec<Span> = out.embedded.iter().map(|blob| blob.span).collect();
    spans::check_spans(data.len(), "png", &out.findings, &out.carriers, &embedded);
    let mut large = Budget::new(&large_limits());
    scan_png(data, &mut large);
    check_decompression(
        SMALL_LIMIT - small.remaining_decompressed(),
        LARGE_LIMIT - large.remaining_decompressed(),
        &out,
    );
}

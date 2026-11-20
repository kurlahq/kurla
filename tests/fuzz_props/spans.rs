use kurla::model::{Carrier, RawFinding, Span};

fn check_one(len: usize, what: &str, kind: &str, span: &Span) {
    let len = len as u64;
    assert!(
        span.byte_start <= span.byte_end && span.byte_end <= len,
        "{what}: {kind} span {}..{} is outside the input of {len} bytes",
        span.byte_start,
        span.byte_end
    );
}

pub fn check_spans(
    len: usize,
    what: &str,
    findings: &[RawFinding],
    carriers: &[Carrier],
    extra: &[Span],
) {
    for finding in findings {
        check_one(len, what, "finding", &finding.span);
    }
    for carrier in carriers {
        check_one(len, what, "carrier", &carrier.span);
    }
    for span in extra {
        check_one(len, what, "extra", span);
    }
}

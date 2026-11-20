use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

#[path = "fuzz_props/bmff.rs"]
mod bmff;
#[path = "fuzz_props/encoded.rs"]
mod encoded;
#[path = "fuzz_props/exif.rs"]
mod exif;
#[path = "fuzz_props/gif.rs"]
mod gif;
#[path = "fuzz_props/jpeg.rs"]
mod jpeg;
#[path = "fuzz_props/markup.rs"]
mod markup;
#[path = "fuzz_props/png.rs"]
mod png;
#[path = "fuzz_props/scan_file.rs"]
mod scan_file;
#[path = "fuzz_props/spans.rs"]
mod spans;
#[path = "fuzz_props/svg.rs"]
mod svg;
#[path = "fuzz_props/text_unicode.rs"]
mod text_unicode;

use kurla::model::{Carrier, CarrierKind, Family, RawFinding, RuleStatus, Severity, Span};

const TARGETS: [&str; 10] = [
    "png",
    "jpeg",
    "exif",
    "gif",
    "bmff",
    "svg",
    "markup",
    "encoded",
    "text_unicode",
    "scan_file",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn seeds(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = root().join("fuzz").join("corpus").join(target);
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("directory entry").path();
        if path.is_file() {
            let bytes = fs::read(&path).expect("seed is readable");
            out.push((path.display().to_string(), bytes));
        }
    }
    assert!(!out.is_empty(), "no seeds for {target}");
    out
}

fn run(target: &str, check: fn(&[u8])) -> usize {
    let all = seeds(target);
    for (name, bytes) in &all {
        if let Err(cause) = catch_unwind(AssertUnwindSafe(|| check(bytes))) {
            let message = cause
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| cause.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            panic!("{target} property failed on {name}: {message}");
        }
    }
    all.len()
}

fn span(start: u64, end: u64) -> Span {
    Span {
        byte_start: start,
        byte_end: end,
        line: None,
        column: None,
    }
}

fn finding(start: u64, end: u64) -> RawFinding {
    RawFinding {
        rule_id: "T000",
        family: Family::B,
        base: Severity::Low,
        status: RuleStatus::Stable,
        span: span(start, end),
        carrier: CarrierKind::MetadataField,
        payload: None,
        message: String::new(),
        evidence: Vec::new(),
    }
}

fn carrier(start: u64, end: u64) -> Carrier {
    Carrier {
        kind: CarrierKind::MetadataField,
        text: String::new(),
        span: span(start, end),
        hidden: false,
        evidence: Vec::new(),
    }
}

fn panic_text(f: impl FnOnce()) -> Option<String> {
    catch_unwind(AssertUnwindSafe(f)).err().map(|cause| {
        cause
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| cause.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_default()
    })
}

#[test]
fn png_seeds_satisfy_the_properties() {
    assert!(run("png", png::check) >= 1);
}

#[test]
fn jpeg_seeds_satisfy_the_properties() {
    assert!(run("jpeg", jpeg::check) >= 1);
}

#[test]
fn exif_seeds_satisfy_the_properties() {
    assert!(run("exif", exif::check) >= 1);
}

#[test]
fn gif_seeds_satisfy_the_properties() {
    assert!(run("gif", gif::check) >= 1);
}

#[test]
fn bmff_seeds_satisfy_the_properties() {
    assert!(run("bmff", bmff::check) >= 2);
}

#[test]
fn svg_seeds_satisfy_the_properties() {
    assert!(run("svg", svg::check) >= 6);
}

#[test]
fn markup_seeds_satisfy_the_properties() {
    assert!(run("markup", markup::check) >= 20);
}

#[test]
fn encoded_seeds_satisfy_the_properties() {
    assert!(run("encoded", encoded::check) >= 3);
}

#[test]
fn text_unicode_seeds_satisfy_the_properties() {
    assert!(run("text_unicode", text_unicode::check) >= 14);
}

#[test]
fn scan_file_seeds_satisfy_the_properties() {
    assert!(run("scan_file", scan_file::check) >= 27);
}

#[test]
fn every_target_has_a_thin_wrapper_that_calls_its_check() {
    let dir = root().join("fuzz").join("fuzz_targets");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .expect("fuzz_targets exists")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut expected: Vec<String> = TARGETS.iter().map(|t| format!("{t}.rs")).collect();
    expected.sort();
    assert_eq!(names, expected);
    for target in TARGETS {
        let source = fs::read_to_string(dir.join(format!("{target}.rs"))).expect("readable");
        let include = format!("#[path = \"../../tests/fuzz_props/{target}.rs\"]");
        assert!(source.contains(&include), "{target}: {include}");
        assert!(
            source.contains("#[path = \"../../tests/fuzz_props/spans.rs\"]"),
            "{target}"
        );
        assert!(source.contains("props::check(data)"), "{target}");
        assert!(source.contains("#![no_main]"), "{target}");
    }
}

#[test]
fn span_checker_rejects_an_end_past_the_input() {
    let message = panic_text(|| {
        spans::check_spans(10, "x", &[finding(2, 11)], &[], &[]);
    });
    assert!(message.expect("must panic").contains("outside the input"));
}

#[test]
fn span_checker_rejects_a_start_past_the_end() {
    let message = panic_text(|| {
        spans::check_spans(10, "x", &[], &[carrier(6, 5)], &[]);
    });
    assert!(message.expect("must panic").contains("outside the input"));
}

#[test]
fn span_checker_rejects_a_bad_extra_span() {
    let message = panic_text(|| {
        spans::check_spans(10, "x", &[], &[], &[span(0, 11)]);
    });
    assert!(message.expect("must panic").contains("outside the input"));
}

#[test]
fn span_checker_rejects_a_span_beyond_usize_range_values() {
    let message = panic_text(|| {
        spans::check_spans(10, "x", &[finding(u64::MAX, u64::MAX)], &[], &[]);
    });
    assert!(message.expect("must panic").contains("outside the input"));
}

#[test]
fn span_checker_accepts_spans_touching_both_edges() {
    spans::check_spans(
        10,
        "x",
        &[finding(0, 0), finding(0, 10), finding(10, 10)],
        &[carrier(3, 3), carrier(0, 10)],
        &[span(10, 10), span(4, 9)],
    );
}

#[test]
fn span_checker_accepts_everything_on_empty_input() {
    spans::check_spans(0, "x", &[finding(0, 0)], &[carrier(0, 0)], &[span(0, 0)]);
    assert!(panic_text(|| spans::check_spans(0, "x", &[finding(0, 1)], &[], &[])).is_some());
}

fn carriers_in(
    target: &str,
    file: &str,
    scan: fn(&[u8], &mut kurla::limits::Budget) -> kurla::model::DetectorOutput,
) -> usize {
    let bytes =
        fs::read(root().join("fuzz").join("corpus").join(target).join(file)).expect("seed exists");
    let mut budget = kurla::limits::Budget::new(&kurla::limits::Limits::default());
    scan(&bytes, &mut budget).carriers.len()
}

#[test]
fn hand_built_seeds_reach_the_metadata_they_were_built_to_carry() {
    assert_eq!(
        carriers_in("png", "minimal_text_xmp_exif.png", kurla::binary::scan_png),
        5
    );
    assert_eq!(
        carriers_in("jpeg", "minimal_exif_xmp_com.jpg", kurla::binary::scan_jpeg),
        4
    );
    assert!(carriers_in("gif", "minimal_comment_xmp.gif", kurla::binary::scan_gif) >= 2);
    assert_eq!(
        carriers_in("bmff", "minimal_exif_xmp.webp", kurla::binary::scan_webp),
        3
    );
    assert_eq!(
        carriers_in("bmff", "minimal_exif_xmp.avif", kurla::binary::scan_avif),
        3
    );
    let tiff = fs::read(root().join("fuzz/corpus/exif/minimal_two_entries.tiff")).expect("seed");
    assert_eq!(
        kurla::binary::exif_text_fields(&tiff).expect("valid").len(),
        2
    );
}

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

use kurla::model::{
    Carrier, CarrierKind, DetectorOutput, Family, RawFinding, RuleStatus, Severity, SkipReason,
    Span,
};

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
    assert!(!seeds_in(&dir).is_empty(), "no seeds for {target}");
    seeds_in(&dir)
}

fn seeds_in(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("directory entry").path();
        let kind = fs::symlink_metadata(&path)
            .expect("entry metadata")
            .file_type();
        assert!(kind.is_file(), "{} is not a regular file", path.display());
        let bytes = fs::read(&path).expect("seed is readable");
        out.push((path.display().to_string(), bytes));
    }
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
fn span_checker_rejects_a_u64_max_end() {
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
        7
    );
    assert!(carriers_in("gif", "minimal_comment_xmp.gif", kurla::binary::scan_gif) >= 2);
    assert_eq!(
        carriers_in("bmff", "minimal_exif_xmp.webp", kurla::binary::scan_webp),
        6
    );
    assert_eq!(
        carriers_in("bmff", "minimal_exif_xmp.avif", kurla::binary::scan_avif),
        8
    );
    let tiff = fs::read(root().join("fuzz/corpus/exif/minimal_two_entries.tiff")).expect("seed");
    assert_eq!(
        kurla::binary::exif_text_fields(&tiff).expect("valid").len(),
        2
    );
}

fn limit_output(skip: Option<SkipReason>, rule: &'static str) -> DetectorOutput {
    let mut raw = finding(0, 1);
    raw.rule_id = rule;
    raw.carrier = CarrierKind::ResourceLimit;
    DetectorOutput {
        findings: vec![raw],
        carriers: Vec::new(),
        skip,
        embedded: Vec::new(),
    }
}

fn quiet_output() -> DetectorOutput {
    DetectorOutput {
        findings: Vec::new(),
        carriers: Vec::new(),
        skip: None,
        embedded: Vec::new(),
    }
}

#[test]
fn png_differential_rejects_a_small_run_over_its_limit() {
    let message = panic_text(|| png::check_decompression(4097, 4097, &quiet_output()));
    assert!(
        message
            .expect("must panic")
            .contains("png: the small run consumed 4097 bytes")
    );
}

#[test]
fn png_differential_rejects_a_large_run_over_the_limit_without_a_signal() {
    let message = panic_text(|| png::check_decompression(4096, 5000, &quiet_output()));
    assert!(
        message
            .expect("must panic")
            .contains("png: the large run consumed 5000 bytes")
    );
}

#[test]
fn png_differential_rejects_a_signal_with_the_wrong_rule_or_skip() {
    let wrong_rule = limit_output(Some(SkipReason::DecompressionLimit), "B003");
    assert!(panic_text(|| png::check_decompression(4096, 5000, &wrong_rule)).is_some());
    let wrong_skip = limit_output(Some(SkipReason::Malformed), "B002");
    assert!(panic_text(|| png::check_decompression(4096, 5000, &wrong_skip)).is_some());
    let no_skip = limit_output(None, "B002");
    assert!(panic_text(|| png::check_decompression(4096, 5000, &no_skip)).is_some());
}

#[test]
fn png_differential_accepts_a_large_run_over_the_limit_with_the_signal() {
    let signal = limit_output(Some(SkipReason::DecompressionLimit), "B002");
    png::check_decompression(4000, 5000, &signal);
}

#[test]
fn png_differential_accepts_the_signal_behind_an_earlier_size_skip() {
    let mut out = limit_output(Some(SkipReason::SizeLimit), "B002");
    let mut earlier = finding(0, 1);
    earlier.rule_id = "L001";
    out.findings.insert(0, earlier);
    png::check_decompression(4000, 5000, &out);
    let mut no_earlier = limit_output(Some(SkipReason::SizeLimit), "B002");
    no_earlier.findings[0].carrier = CarrierKind::ResourceLimit;
    assert!(panic_text(|| png::check_decompression(4000, 5000, &no_earlier)).is_some());
}

#[test]
fn png_differential_accepts_the_signal_behind_an_earlier_malformed_skip() {
    let mut out = limit_output(Some(SkipReason::Malformed), "B002");
    let mut earlier = finding(0, 1);
    earlier.rule_id = "L001";
    out.findings.insert(0, earlier);
    png::check_decompression(4000, 5000, &out);
    let no_earlier = limit_output(Some(SkipReason::Malformed), "B002");
    assert!(panic_text(|| png::check_decompression(4000, 5000, &no_earlier)).is_some());
}

#[test]
fn png_differential_accepts_a_large_run_at_or_under_the_limit_without_a_signal() {
    png::check_decompression(100, 4000, &quiet_output());
    png::check_decompression(0, 0, &quiet_output());
}

#[test]
fn png_differential_accepts_a_large_run_of_exactly_the_limit_without_a_signal() {
    png::check_decompression(4096, 4096, &quiet_output());
}

#[test]
fn png_differential_leaves_a_timeout_undecided() {
    let timed_out = DetectorOutput {
        skip: Some(SkipReason::Timeout),
        ..quiet_output()
    };
    png::check_decompression(0, 5000, &timed_out);
}

#[test]
fn png_differential_seed_exceeds_the_small_limit() {
    let bytes = fs::read(root().join("fuzz/corpus/png/ztxt_over_4k.png")).expect("seed exists");
    assert!(bytes.len() <= 4096);
    let mut small = kurla::limits::Budget::new(&png::limits());
    let small_out = kurla::binary::scan_png(&bytes, &mut small);
    let mut large = kurla::limits::Budget::new(&png::large_limits());
    kurla::binary::scan_png(&bytes, &mut large);
    assert_eq!(
        png::large_limits().max_decompressed_bytes - large.remaining_decompressed(),
        5000
    );
    assert_eq!(small.remaining_decompressed(), 4096);
    assert_eq!(small_out.skip, Some(SkipReason::DecompressionLimit));
    assert!(
        small_out
            .findings
            .iter()
            .any(|f| f.rule_id == "B002" && f.carrier == CarrierKind::ResourceLimit)
    );
}

#[test]
fn scan_file_carries_the_png_limit_skip() {
    let bytes = fs::read(root().join("fuzz/corpus/png/ztxt_over_4k.png")).expect("seed exists");
    let (findings, coverage, _) = kurla::engine::scan_file("x.png", &bytes, &scan_file::limits());
    assert_eq!(coverage.skip, Some(SkipReason::DecompressionLimit));
    assert!(findings.iter().any(|f| f.raw.rule_id == "B002"));
    let small = limit_output(Some(SkipReason::DecompressionLimit), "B002");
    scan_file::check_png_propagation(&small, coverage.skip);
    scan_file::check_png_propagation(&quiet_output(), None);
    scan_file::check_png_propagation(&small, Some(SkipReason::Timeout));
    let message = panic_text(|| scan_file::check_png_propagation(&small, None));
    assert!(
        message
            .expect("must panic")
            .contains("scan_file: x.png lost the skip reason")
    );
}

#[test]
fn text_seeds_of_the_text_targets_decode_except_the_listed_ones() {
    let expected_undecodable: [&str; 0] = [];
    for target in ["markup", "encoded", "text_unicode"] {
        for (name, bytes) in seeds(target) {
            let listed = expected_undecodable.iter().any(|f| name.ends_with(f));
            assert_eq!(
                kurla::text::TextDoc::decode(&bytes).is_some(),
                !listed,
                "{target}: {name}"
            );
        }
    }
}

#[test]
fn seeds_panics_on_a_directory_entry_instead_of_skipping_it() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("seeds_dir_entry");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("nested")).expect("create");
    fs::write(dir.join("a.bin"), b"x").expect("write");
    let message = panic_text(|| {
        seeds_in(&dir);
    });
    let message = message.expect("must panic");
    assert!(message.contains("not a regular file"), "{message}");
    assert!(message.contains("nested"), "{message}");
}

#[test]
fn seeds_accepts_a_directory_of_regular_files() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("seeds_regular_only");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create");
    fs::write(dir.join("a.bin"), b"x").expect("write");
    assert_eq!(seeds_in(&dir).len(), 1);
}

#[test]
fn fuzz_manifest_pins_the_root_crate_version() {
    let manifest = fs::read_to_string(root().join("fuzz/Cargo.toml")).expect("readable");
    let line = format!(
        "kurla = {{ path = \"..\", version = \"={}\" }}",
        env!("CARGO_PKG_VERSION")
    );
    assert!(manifest.lines().any(|l| l == line), "{line}");
}

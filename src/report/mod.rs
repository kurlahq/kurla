pub mod human;
pub mod json;
pub mod sarif;

use crate::decisions::{DecisionsSource, InvalidDecision, RejectedFile};
use crate::exit;
use crate::model::{
    CarrierKind, Category, Family, FileCoverage, FileKind, Finding, LocationKind, RuleStatus,
    Severity, SkipReason,
};
use crate::unicode::{is_bidi_control, is_default_ignorable, is_tag, is_variation_selector};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write;

pub struct Report<'a> {
    pub findings: &'a [Finding],
    pub coverage: &'a [FileCoverage],
    pub carrier_counts: &'a BTreeMap<CarrierKind, u64>,
    pub threshold: Severity,
    pub require_complete: bool,
    pub invalid: &'a [InvalidDecision],
    pub rejected: &'a [RejectedFile],
    pub warnings: &'a [String],
}

impl Report<'_> {
    pub fn complete(&self) -> bool {
        !exit::incomplete(self.coverage, true)
    }

    pub fn exit_code(&self) -> i32 {
        exit::code(
            self.findings,
            self.coverage,
            self.threshold,
            self.require_complete,
            !self.rejected.is_empty(),
        )
    }
}

fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{2028}' | '\u{2029}')
        || is_bidi_control(c)
        || is_default_ignorable(c)
        || is_tag(c)
        || is_variation_selector(c)
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

pub(crate) fn sarif_uri(path: &str) -> String {
    let bytes = path.as_bytes();
    if let Some(rest) = path.strip_prefix("//") {
        return format!("file://{}", percent_encode(rest));
    }
    if path.starts_with('/') {
        return format!("file://{}", percent_encode(path));
    }
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/' {
        return format!(
            "file:///{}:{}",
            char::from(bytes[0]),
            percent_encode(&path[2..])
        );
    }
    percent_encode(path)
}

pub(crate) const SRCROOT: &str = "%SRCROOT%";

pub(crate) fn artifact_location(path: &str) -> Value {
    let uri = sarif_uri(path);
    if uri.starts_with("file:") {
        json!({ "uri": uri })
    } else {
        json!({ "uri": uri, "uriBaseId": SRCROOT })
    }
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' {
            out.push_str(r"\\");
        } else if needs_escape(c) {
            let _ = write!(out, "\\u{{{:04X}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn family_name(family: Family) -> &'static str {
    match family {
        Family::U => "U",
        Family::M => "M",
        Family::A => "A",
        Family::S => "S",
        Family::B => "B",
        Family::E => "E",
        Family::I => "I",
        Family::L => "L",
    }
}

pub(crate) fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

pub(crate) fn status_name(status: RuleStatus) -> &'static str {
    match status {
        RuleStatus::Stable => "stable",
        RuleStatus::Experimental => "experimental",
    }
}

fn location_name(location: LocationKind) -> &'static str {
    match location {
        LocationKind::AgentFile => "agent_file",
        LocationKind::DocsTemplate => "docs_template",
        LocationKind::Code => "code",
        LocationKind::DataAsset => "data_asset",
        LocationKind::Dependency => "dependency",
    }
}

fn carrier_name(carrier: CarrierKind) -> &'static str {
    match carrier {
        CarrierKind::HiddenText => "hidden_text",
        CarrierKind::DecodedPayload => "decoded_payload",
        CarrierKind::HtmlComment => "html_comment",
        CarrierKind::SvgText => "svg_text",
        CarrierKind::MetadataField => "metadata_field",
        CarrierKind::AgentFileText => "agent_file_text",
        CarrierKind::ActiveContent => "active_content",
        CarrierKind::ResourceLimit => "resource_limit",
    }
}

pub(crate) fn kind_name(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Text => "text",
        FileKind::Svg => "svg",
        FileKind::Png => "png",
        FileKind::Jpeg => "jpeg",
        FileKind::Gif => "gif",
        FileKind::Webp => "webp",
        FileKind::Avif => "avif",
        FileKind::Pdf => "pdf",
        FileKind::OtherImage => "other_image",
        FileKind::UnknownBinary => "unknown_binary",
    }
}

pub(crate) fn category_name(category: Category) -> &'static str {
    match category {
        Category::Text => "text",
        Category::Svg => "svg",
        Category::ImageMetadata => "image_metadata",
        Category::Pdf => "pdf",
        Category::UnknownBinary => "unknown_binary",
    }
}

pub(crate) fn skip_name(skip: SkipReason) -> &'static str {
    match skip {
        SkipReason::SizeLimit => "size_limit",
        SkipReason::DecompressionLimit => "decompression_limit",
        SkipReason::Timeout => "timeout",
        SkipReason::Unreadable => "unreadable",
        SkipReason::ExcludedByUser => "excluded_by_user",
        SkipReason::SymlinkNotFollowed => "symlink_not_followed",
        SkipReason::PdfNotScanned => "pdf_not_scanned",
        SkipReason::Malformed => "malformed",
    }
}

pub(crate) fn source_name(source: DecisionsSource) -> &'static str {
    match source {
        DecisionsSource::Current => "current",
        DecisionsSource::Base => "base",
    }
}

const CATEGORIES: [Category; 5] = [
    Category::Text,
    Category::Svg,
    Category::ImageMetadata,
    Category::Pdf,
    Category::UnknownBinary,
];

fn finding_value(finding: &Finding) -> Value {
    let raw = &finding.raw;
    json!({
        "rule": escape(raw.rule_id),
        "family": family_name(raw.family),
        "severity": severity_name(finding.severity),
        "status": status_name(raw.status),
        "path": escape(&finding.path),
        "location": location_name(finding.location),
        "line": raw.span.line,
        "column": raw.span.column,
        "byte_start": raw.span.byte_start,
        "byte_end": raw.span.byte_end,
        "carrier": carrier_name(raw.carrier),
        "message": escape(&raw.message),
        "payload": raw.payload.as_deref().map(escape),
        "fingerprint": escape(&finding.fingerprint),
        "review": finding.review.as_ref().map(|review| json!({
            "reviewer": escape(&review.reviewer),
            "reason": escape(&review.reason),
            "counted": review.counted,
        })),
    })
}

pub(crate) fn findings_value(report: &Report) -> Value {
    Value::Array(report.findings.iter().map(finding_value).collect())
}

pub(crate) fn coverage_value(report: &Report) -> Value {
    let mut scanned = serde_json::Map::new();
    for category in CATEGORIES {
        let count = report
            .coverage
            .iter()
            .filter(|file| file.category == category && file.skip.is_none())
            .count();
        scanned.insert(category_name(category).to_string(), json!(count));
    }
    let skipped: Vec<Value> = report
        .coverage
        .iter()
        .filter_map(|file| {
            file.skip.map(|skip| {
                json!({
                    "path": escape(&file.path),
                    "kind": kind_name(file.kind),
                    "category": category_name(file.category),
                    "reason": skip_name(skip),
                })
            })
        })
        .collect();
    let drawn: Vec<Value> = report
        .coverage
        .iter()
        .filter(|file| file.drawn_text_unscanned)
        .map(|file| json!(escape(&file.path)))
        .collect();
    let metadata: Vec<Value> = report
        .coverage
        .iter()
        .filter(|file| file.metadata_unscanned)
        .map(|file| json!(escape(&file.path)))
        .collect();
    let excluded: Vec<Value> = report
        .coverage
        .iter()
        .filter(|file| file.skip == Some(SkipReason::ExcludedByUser))
        .map(|file| json!(escape(&file.path)))
        .collect();
    let embedded: Vec<Value> = report
        .coverage
        .iter()
        .flat_map(|file| {
            file.embedded_not_scanned.iter().map(|entry| {
                json!({
                    "path": escape(&file.path),
                    "byte_start": entry.span.byte_start,
                    "byte_end": entry.span.byte_end,
                    "declared_type": entry.declared_type.as_deref().map(escape),
                    "kind": kind_name(entry.kind),
                    "reason": escape(&entry.reason),
                })
            })
        })
        .collect();
    let runs: u64 = report
        .coverage
        .iter()
        .map(|file| file.encoded_runs_not_payloads)
        .sum();
    json!({
        "scanned_by_category": scanned,
        "skipped": skipped,
        "not_scanned_for_drawn_text": drawn,
        "not_scanned_for_metadata": metadata,
        "excluded_by_user": excluded,
        "embedded_not_scanned": embedded,
        "encoded_runs_not_payloads": runs,
    })
}

pub(crate) fn carrier_counts_value(report: &Report) -> Value {
    let mut map = serde_json::Map::new();
    for (kind, count) in report.carrier_counts {
        map.insert(carrier_name(*kind).to_string(), json!(count));
    }
    Value::Object(map)
}

pub(crate) fn invalid_value(report: &Report) -> Value {
    Value::Array(
        report
            .invalid
            .iter()
            .map(|entry| {
                json!({
                    "fingerprint": escape(&entry.fingerprint),
                    "rule": escape(&entry.rule),
                    "path": escape(&entry.path),
                    "reason": escape(entry.reason),
                    "source": source_name(entry.source),
                })
            })
            .collect(),
    )
}

pub(crate) fn rejected_value(report: &Report) -> Value {
    Value::Array(
        report
            .rejected
            .iter()
            .map(|file| {
                json!({
                    "file": escape(&file.file),
                    "message": escape(&file.message),
                })
            })
            .collect(),
    )
}

pub(crate) fn warnings_value(report: &Report) -> Value {
    Value::Array(
        report
            .warnings
            .iter()
            .map(|warning| json!(escape(warning)))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decisions::DecisionsSource;
    use crate::model::{
        EmbeddedNotScanned, Family, FileKind, LocationKind, RawFinding, Review, RuleStatus,
        SkipReason, Span,
    };
    use crate::unicode::{is_bidi_control, is_default_ignorable};
    use serde_json::Value;
    use std::collections::BTreeSet;

    const RLO: char = '\u{202E}';
    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn rlo_text(label: &str) -> String {
        let text = format!("{label}{RLO}tail");
        assert!(text.contains('\u{202E}'));
        text
    }

    fn raw(rule: &'static str, family: Family, span: Span, payload: Option<String>) -> RawFinding {
        RawFinding {
            rule_id: rule,
            family,
            base: Severity::High,
            status: RuleStatus::Stable,
            span,
            carrier: CarrierKind::HiddenText,
            payload,
            message: rlo_text("message "),
            evidence: Vec::new(),
        }
    }

    fn finding(
        rule: &'static str,
        severity: Severity,
        path: &str,
        span: Span,
        payload: Option<String>,
    ) -> Finding {
        let mut raw = raw(rule, Family::U, span, payload);
        raw.base = severity;
        Finding {
            raw,
            path: path.to_string(),
            location: LocationKind::Code,
            severity,
            fingerprint: FP.to_string(),
            review: None,
        }
    }

    fn text_span(start: u64, end: u64, line: u32, column: u32) -> Span {
        Span {
            byte_start: start,
            byte_end: end,
            line: Some(line),
            column: Some(column),
        }
    }

    fn binary_span(start: u64, end: u64) -> Span {
        Span {
            byte_start: start,
            byte_end: end,
            line: None,
            column: None,
        }
    }

    fn coverage_entry(path: &str, kind: FileKind, skip: Option<SkipReason>) -> FileCoverage {
        FileCoverage {
            path: path.to_string(),
            kind,
            category: kind.category(),
            skip,
            drawn_text_unscanned: kind.drawn_text_unscanned(),
            metadata_unscanned: false,
            embedded_not_scanned: Vec::new(),
            encoded_runs_not_payloads: 0,
        }
    }

    struct Fixture {
        findings: Vec<Finding>,
        coverage: Vec<FileCoverage>,
        counts: BTreeMap<CarrierKind, u64>,
        invalid: Vec<InvalidDecision>,
        rejected: Vec<RejectedFile>,
        warnings: Vec<String>,
        threshold: Severity,
        require_complete: bool,
    }

    impl Fixture {
        fn report(&self) -> Report<'_> {
            Report {
                findings: &self.findings,
                coverage: &self.coverage,
                carrier_counts: &self.counts,
                threshold: self.threshold,
                require_complete: self.require_complete,
                invalid: &self.invalid,
                rejected: &self.rejected,
                warnings: &self.warnings,
            }
        }
    }

    fn rich() -> Fixture {
        let evil_path = rlo_text("dir/");
        let mut reviewed = finding(
            "S002",
            Severity::Medium,
            "b.md",
            text_span(0, 1, 1, 1),
            Some("plain".to_string()),
        );
        reviewed.review = Some(Review {
            reviewer: rlo_text("rev "),
            reason: rlo_text("because "),
            counted: false,
        });
        let mut skipped = coverage_entry("big.txt", FileKind::Text, Some(SkipReason::SizeLimit));
        skipped.encoded_runs_not_payloads = 3;
        let mut container = coverage_entry("c.md", FileKind::Text, None);
        container.embedded_not_scanned.push(EmbeddedNotScanned {
            span: binary_span(10, 20),
            declared_type: Some(rlo_text("image/")),
            kind: FileKind::Png,
            reason: "png content not scanned".to_string(),
        });
        container.encoded_runs_not_payloads = 4;
        let mut counts = BTreeMap::new();
        counts.insert(CarrierKind::HiddenText, 2);
        counts.insert(CarrierKind::MetadataField, 5);
        Fixture {
            findings: vec![
                finding(
                    "U002",
                    Severity::High,
                    &evil_path,
                    text_span(6, 9, 1, 7),
                    Some(rlo_text("payload ")),
                ),
                reviewed,
                finding("B002", Severity::Low, "pic.png", binary_span(30, 40), None),
            ],
            coverage: vec![
                coverage_entry("b.md", FileKind::Text, None),
                container,
                coverage_entry("pic.png", FileKind::Png, None),
                skipped,
                coverage_entry("doc.pdf", FileKind::Pdf, Some(SkipReason::PdfNotScanned)),
                coverage_entry(
                    "x/skip.bin",
                    FileKind::UnknownBinary,
                    Some(SkipReason::ExcludedByUser),
                ),
            ],
            counts,
            invalid: vec![InvalidDecision {
                source: DecisionsSource::Base,
                fingerprint: FP.to_string(),
                rule: "S002".to_string(),
                path: rlo_text("inv/"),
                reason: "expired",
            }],
            rejected: vec![RejectedFile {
                file: rlo_text(".kurla/"),
                message: rlo_text("unknown field "),
            }],
            warnings: vec![rlo_text("cache disabled: ")],
            threshold: Severity::High,
            require_complete: false,
        }
    }

    fn no_source(_: &str) -> Option<Vec<u8>> {
        None
    }

    fn keys(value: &Value) -> BTreeSet<String> {
        value.as_object().unwrap().keys().cloned().collect()
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    fn assert_safe(out: &str) {
        for c in out.chars() {
            assert!(
                c == '\n' || !(c.is_control() || is_bidi_control(c) || is_default_ignorable(c)),
                "unescaped U+{:04X}",
                c as u32
            );
        }
    }

    #[test]
    fn escape_turns_bidi_control_tag_and_ignorable_characters_into_braced_hex() {
        assert_eq!(escape("a\u{202E}b"), "a\\u{202E}b");
        assert_eq!(
            escape("\u{A}\u{9}\u{7F}\u{85}"),
            "\\u{000A}\\u{0009}\\u{007F}\\u{0085}"
        );
        assert_eq!(escape("\u{E0041}"), "\\u{E0041}");
        assert_eq!(
            escape("\u{FE0F}\u{200D}\u{200B}\u{AD}"),
            "\\u{FE0F}\\u{200D}\\u{200B}\\u{00AD}"
        );
        assert_eq!(
            escape("\u{2028}\u{FEFF}\u{2066}\u{61C}"),
            "\\u{2028}\\u{FEFF}\\u{2066}\\u{061C}"
        );
    }

    #[test]
    fn escape_doubles_a_backslash_so_every_escape_comes_from_kurla() {
        assert_eq!(escape(r"a\u{202E}b"), r"a\\u{202E}b");
        assert_ne!(escape(r"a\u{202E}b"), escape("a\u{202E}b"));
        assert_eq!(escape(r"\"), r"\\");
        assert_eq!(escape("\u{1B}[31m"), r"\u{001B}[31m");
    }

    #[test]
    fn sarif_uris_are_percent_encoded_uri_references() {
        assert_eq!(sarif_uri("dir/a b%#?.txt"), "dir/a%20b%25%23%3F.txt");
        assert_eq!(sarif_uri("a\u{202E}b"), "a%E2%80%AEb");
        assert_eq!(sarif_uri(r"a\b{c}"), "a%5Cb%7Bc%7D");
        assert_eq!(sarif_uri("Az09-._~/x"), "Az09-._~/x");
        assert_eq!(sarif_uri("/tmp/x y"), "file:///tmp/x%20y");
        assert_eq!(sarif_uri("C:/Users/x y"), "file:///C:/Users/x%20y");
        assert_eq!(sarif_uri("//server/share/a"), "file://server/share/a");
        assert_eq!(sarif_uri("c:"), "c%3A");
        assert_eq!(sarif_uri("C:/"), "file:///C:/");
        assert_eq!(sarif_uri("1:/x"), "1%3A/x");
        assert_eq!(sarif_uri("C:x/y"), "C%3Ax/y");
        assert_eq!(sarif_uri("C|/y"), "C%7C/y");
    }

    #[test]
    fn sarif_locations_inside_the_root_are_relative_to_srcroot() {
        let relative = json!({"uri": "dir/a%20b.txt", "uriBaseId": "%SRCROOT%"});
        assert_eq!(artifact_location("dir/a b.txt"), relative);
        let hex = json!({"uri": "hex%3A00ff", "uriBaseId": "%SRCROOT%"});
        assert_eq!(artifact_location("hex:00ff"), hex);
        assert_eq!(artifact_location("/abs/x"), json!({"uri": "file:///abs/x"}));
        assert_eq!(artifact_location("C:/x"), json!({"uri": "file:///C:/x"}));
        let fixture = rich();
        let sarif: Value =
            serde_json::from_str(&sarif::render(&fixture.report(), &no_source)).unwrap();
        let run = &sarif["runs"][0];
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"],
            json!({"uri": "dir/%E2%80%AEtail", "uriBaseId": "%SRCROOT%"})
        );
        assert_eq!(
            run["originalUriBaseIds"],
            json!({"%SRCROOT%": {"description": {"text": "The directory the scan ran from."}}})
        );
    }

    #[test]
    fn escape_leaves_visible_text_alone() {
        assert_eq!(escape("plain é 日本 \u{1F600}"), "plain é 日本 \u{1F600}");
        assert_eq!(escape(""), "");
    }

    #[test]
    fn rlo_in_payload_and_filename_escaped_in_all_formats() {
        let fixture = rich();
        let report = fixture.report();
        let outputs = [
            json::render(&report),
            sarif::render(&report, &no_source),
            human::render(&report),
        ];
        for out in &outputs {
            assert!(!out.is_empty());
            assert!(!out.contains(RLO));
            assert_safe(out);
        }
        let json: Value = serde_json::from_str(&outputs[0]).unwrap();
        let first = &json["findings"][0];
        assert_eq!(first["path"], "dir/\\u{202E}tail");
        assert_eq!(first["payload"], "payload \\u{202E}tail");
        assert_eq!(first["message"], "message \\u{202E}tail");
        assert_eq!(
            json["findings"][1]["review"]["reviewer"],
            "rev \\u{202E}tail"
        );
        assert_eq!(
            json["findings"][1]["review"]["reason"],
            "because \\u{202E}tail"
        );
        assert_eq!(
            json["coverage"]["embedded_not_scanned"][0]["declared_type"],
            "image/\\u{202E}tail"
        );
        assert_eq!(json["decisions_errors"][0]["file"], ".kurla/\\u{202E}tail");
        assert_eq!(
            json["decisions_errors"][0]["message"],
            "unknown field \\u{202E}tail"
        );
        assert_eq!(json["invalid_decisions"][0]["path"], "inv/\\u{202E}tail");
        assert_eq!(json["warnings"][0], "cache disabled: \\u{202E}tail");
        let sarif: Value = serde_json::from_str(&outputs[1]).unwrap();
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "dir/%E2%80%AEtail"
        );
        assert!(
            result["message"]["text"]
                .as_str()
                .unwrap()
                .contains("payload \\u{202E}tail")
        );
        let suppression = &sarif["runs"][0]["results"][1]["suppressions"][0];
        assert_eq!(suppression["justification"], "because \\u{202E}tail");
        for needle in [
            "dir/\\u{202E}tail",
            "payload \\u{202E}tail",
            "rev \\u{202E}tail",
            "because \\u{202E}tail",
            "image/\\u{202E}tail",
            "inv/\\u{202E}tail",
            ".kurla/\\u{202E}tail",
            "unknown field \\u{202E}tail",
            "cache disabled: \\u{202E}tail",
        ] {
            assert!(outputs[2].contains(needle), "human output lacks {needle}");
        }
    }

    #[test]
    fn json_schema_field_set_is_stable() {
        let fixture = rich();
        let json: Value = serde_json::from_str(&json::render(&fixture.report())).unwrap();
        assert_eq!(json["schema"], "kurla.report/1");
        assert_eq!(
            keys(&json),
            set(&[
                "schema",
                "kurla_version",
                "rules_version",
                "complete",
                "exit_code",
                "threshold",
                "findings",
                "coverage",
                "carrier_counts",
                "invalid_decisions",
                "decisions_errors",
                "warnings",
            ])
        );
        assert_eq!(
            keys(&json["findings"][0]),
            set(&[
                "rule",
                "family",
                "severity",
                "status",
                "path",
                "location",
                "line",
                "column",
                "byte_start",
                "byte_end",
                "carrier",
                "message",
                "payload",
                "fingerprint",
                "review",
            ])
        );
        assert_eq!(
            keys(&json["findings"][1]["review"]),
            set(&["reviewer", "reason", "counted"])
        );
        assert_eq!(
            keys(&json["coverage"]),
            set(&[
                "scanned_by_category",
                "skipped",
                "not_scanned_for_drawn_text",
                "not_scanned_for_metadata",
                "excluded_by_user",
                "embedded_not_scanned",
                "encoded_runs_not_payloads",
            ])
        );
        assert_eq!(
            keys(&json["coverage"]["scanned_by_category"]),
            set(&["text", "svg", "image_metadata", "pdf", "unknown_binary"])
        );
        assert_eq!(
            keys(&json["coverage"]["skipped"][0]),
            set(&["path", "kind", "category", "reason"])
        );
        assert_eq!(
            keys(&json["coverage"]["embedded_not_scanned"][0]),
            set(&[
                "path",
                "byte_start",
                "byte_end",
                "declared_type",
                "kind",
                "reason",
            ])
        );
        assert_eq!(
            keys(&json["invalid_decisions"][0]),
            set(&["fingerprint", "rule", "path", "reason", "source"])
        );
        assert_eq!(
            keys(&json["decisions_errors"][0]),
            set(&["file", "message"])
        );
    }

    #[test]
    fn json_values_follow_the_documented_encoding() {
        let fixture = rich();
        let json: Value = serde_json::from_str(&json::render(&fixture.report())).unwrap();
        assert_eq!(json["kurla_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(json["rules_version"], crate::engine::RULES_VERSION);
        assert_eq!(json["threshold"], "high");
        assert_eq!(json["complete"], false);
        assert_eq!(json["exit_code"], 1);
        let first = &json["findings"][0];
        assert_eq!(first["rule"], "U002");
        assert_eq!(first["family"], "U");
        assert_eq!(first["severity"], "high");
        assert_eq!(first["status"], "stable");
        assert_eq!(first["location"], "code");
        assert_eq!(first["line"], 1);
        assert_eq!(first["column"], 7);
        assert_eq!(first["byte_start"], 6);
        assert_eq!(first["byte_end"], 9);
        assert_eq!(first["carrier"], "hidden_text");
        assert_eq!(first["fingerprint"], FP);
        assert!(first["review"].is_null());
        let binary = &json["findings"][2];
        assert!(binary["line"].is_null());
        assert!(binary["column"].is_null());
        assert!(binary["payload"].is_null());
        assert_eq!(json["findings"][1]["review"]["counted"], false);
        let coverage = &json["coverage"];
        assert_eq!(coverage["scanned_by_category"]["text"], 2);
        assert_eq!(coverage["scanned_by_category"]["image_metadata"], 1);
        assert_eq!(coverage["scanned_by_category"]["pdf"], 0);
        assert_eq!(coverage["scanned_by_category"]["unknown_binary"], 0);
        assert_eq!(coverage["encoded_runs_not_payloads"], 7);
        assert_eq!(
            coverage["excluded_by_user"],
            serde_json::json!(["x/skip.bin"])
        );
        assert_eq!(
            coverage["not_scanned_for_drawn_text"],
            serde_json::json!(["pic.png", "doc.pdf"])
        );
        let skipped: Vec<(&str, &str, &str, &str)> = coverage["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["path"].as_str().unwrap(),
                    entry["kind"].as_str().unwrap(),
                    entry["category"].as_str().unwrap(),
                    entry["reason"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            skipped,
            vec![
                ("big.txt", "text", "text", "size_limit"),
                ("doc.pdf", "pdf", "pdf", "pdf_not_scanned"),
                (
                    "x/skip.bin",
                    "unknown_binary",
                    "unknown_binary",
                    "excluded_by_user"
                ),
            ]
        );
        let embedded = &coverage["embedded_not_scanned"][0];
        assert_eq!(embedded["path"], "c.md");
        assert_eq!(embedded["byte_start"], 10);
        assert_eq!(embedded["byte_end"], 20);
        assert_eq!(embedded["kind"], "png");
        assert_eq!(embedded["reason"], "png content not scanned");
        assert_eq!(json["carrier_counts"]["hidden_text"], 2);
        assert_eq!(json["carrier_counts"]["metadata_field"], 5);
        assert_eq!(json["invalid_decisions"][0]["source"], "base");
        assert_eq!(json["invalid_decisions"][0]["reason"], "expired");
    }

    #[test]
    fn invalid_decisions_appear_in_all_formats() {
        let fixture = rich();
        let report = fixture.report();
        let json: Value = serde_json::from_str(&json::render(&report)).unwrap();
        assert_eq!(json["invalid_decisions"][0]["fingerprint"], FP);
        assert_eq!(json["invalid_decisions"][0]["rule"], "S002");
        assert_eq!(json["invalid_decisions"][0]["source"], "base");
        assert_eq!(json["invalid_decisions"][0]["reason"], "expired");
        let sarif: Value = serde_json::from_str(&sarif::render(&report, &no_source)).unwrap();
        let invalid = &sarif["runs"][0]["properties"]["invalid_decisions"][0];
        assert_eq!(invalid["fingerprint"], FP);
        assert_eq!(invalid["source"], "base");
        assert_eq!(invalid["reason"], "expired");
        let human = human::render(&report);
        let line = human
            .lines()
            .find(|line| line.starts_with("invalid decision"))
            .unwrap();
        assert!(line.contains(FP));
        assert!(line.contains("S002"));
        assert!(line.contains("base"));
        assert!(line.contains("expired"));
    }

    #[test]
    fn sarif_has_required_fields_and_columnkind() {
        let fixture = rich();
        let sarif: Value =
            serde_json::from_str(&sarif::render(&fixture.report(), &no_source)).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["$schema"].as_str().unwrap().contains("sarif"));
        let run = &sarif["runs"][0];
        assert_eq!(run["columnKind"], "unicodeCodePoints");
        assert_eq!(run["tool"]["driver"]["name"], "Kurla");
        assert_eq!(run["tool"]["driver"]["version"], env!("CARGO_PKG_VERSION"));
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["B002", "S002", "U002"]);
        let u002 = &rules[2];
        assert_eq!(u002["properties"]["family"], "U");
        assert_eq!(u002["properties"]["status"], "stable");
        assert_eq!(u002["properties"]["security-severity"], "8.0");
        assert_eq!(rules[1]["properties"]["security-severity"], "5.5");
        assert_eq!(rules[0]["properties"]["security-severity"], "3.0");
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        let first = &results[0];
        assert_eq!(first["ruleId"], "U002");
        assert_eq!(first["level"], "error");
        assert_eq!(first["partialFingerprints"]["kurla/v1"], FP);
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "note");
        let region = &first["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 1);
        assert_eq!(region["startColumn"], 7);
        let binary = &results[2]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(binary["byteOffset"], 30);
        assert_eq!(binary["byteLength"], 10);
        assert!(binary.get("startLine").is_none());
        let invocation = &run["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], false);
    }

    #[test]
    fn sarif_execution_successful_follows_complete() {
        let mut fixture = rich();
        fixture
            .coverage
            .retain(|file| file.path != "big.txt" && file.path != "c.md");
        let sarif: Value =
            serde_json::from_str(&sarif::render(&fixture.report(), &no_source)).unwrap();
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            true
        );
        assert_eq!(sarif["runs"][0]["properties"]["complete"], true);
        fixture.coverage.push(coverage_entry(
            "t.txt",
            FileKind::Text,
            Some(SkipReason::Timeout),
        ));
        let sarif: Value =
            serde_json::from_str(&sarif::render(&fixture.report(), &no_source)).unwrap();
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(sarif["runs"][0]["properties"]["complete"], false);
    }

    #[test]
    fn sarif_severity_mapping_covers_every_level() {
        let mut fixture = rich();
        fixture.findings = [
            ("A001", Severity::Critical),
            ("A002", Severity::High),
            ("A003", Severity::Medium),
            ("A004", Severity::Low),
            ("A005", Severity::Info),
        ]
        .iter()
        .map(|(rule, severity)| finding(rule, *severity, "a", binary_span(0, 1), None))
        .collect();
        let sarif: Value =
            serde_json::from_str(&sarif::render(&fixture.report(), &no_source)).unwrap();
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let scores: Vec<&str> = rules
            .iter()
            .map(|r| r["properties"]["security-severity"].as_str().unwrap())
            .collect();
        assert_eq!(scores, vec!["9.5", "8.0", "5.5", "3.0", "0.0"]);
        let levels: Vec<&str> = sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["level"].as_str().unwrap())
            .collect();
        assert_eq!(levels, vec!["error", "error", "warning", "note", "note"]);
    }

    fn region_of(content: &'static [u8], span: Span) -> Value {
        let mut fixture = rich();
        fixture.findings = vec![finding("U002", Severity::High, "f.txt", span, None)];
        let read = move |path: &str| (path == "f.txt").then(|| content.to_vec());
        let sarif: Value = serde_json::from_str(&sarif::render(&fixture.report(), &read)).unwrap();
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"].clone()
    }

    #[test]
    fn sarif_region_end_is_derived_from_byte_end_in_code_points() {
        let region = region_of("ab\ncdef\n".as_bytes(), text_span(4, 6, 2, 2));
        assert_eq!(region["startLine"], 2);
        assert_eq!(region["startColumn"], 2);
        assert_eq!(region["endLine"], 2);
        assert_eq!(region["endColumn"], 4);
        let region = region_of("\u{e9}ab".as_bytes(), text_span(2, 4, 1, 2));
        assert_eq!(region["startColumn"], 2);
        assert_eq!(region["endColumn"], 4);
        let region = region_of("ab\ncd\n".as_bytes(), text_span(1, 4, 1, 2));
        assert_eq!(region["endLine"], 2);
        assert_eq!(region["endColumn"], 2);
    }

    #[test]
    fn sarif_region_without_derivable_end_has_start_only() {
        let mut fixture = rich();
        fixture.findings = vec![finding(
            "U002",
            Severity::High,
            "f.txt",
            text_span(4, 6, 2, 2),
            None,
        )];
        let sarif: Value =
            serde_json::from_str(&sarif::render(&fixture.report(), &no_source)).unwrap();
        let region = &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 2);
        assert_eq!(region["startColumn"], 2);
        assert!(region.get("endLine").is_none());
        assert!(region.get("endColumn").is_none());
        let off_boundary = region_of("\u{e9}ab".as_bytes(), text_span(0, 1, 1, 1));
        assert!(off_boundary.get("endLine").is_none());
        assert_eq!(off_boundary["startColumn"], 1);
        let past_end = region_of(b"ab\n", text_span(1, 99, 1, 2));
        assert!(past_end.get("endLine").is_none());
        let disagrees = region_of(b"ab\ncdef\n", text_span(4, 6, 1, 1));
        assert!(disagrees.get("endLine").is_none());
        assert_eq!(disagrees["startLine"], 1);
    }

    #[test]
    fn sarif_reviewed_findings_are_emitted_with_an_external_suppression() {
        let fixture = rich();
        let sarif: Value =
            serde_json::from_str(&sarif::render(&fixture.report(), &no_source)).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].get("suppressions").is_none());
        let suppression = &results[1]["suppressions"][0];
        assert_eq!(suppression["kind"], "external");
        assert_eq!(suppression["justification"], "because \\u{202E}tail");
        assert_eq!(suppression["properties"]["counted"], false);
        assert_eq!(suppression["properties"]["reviewer"], "rev \\u{202E}tail");
    }

    #[test]
    fn sarif_carries_coverage_and_notifications() {
        let fixture = rich();
        let report = fixture.report();
        let sarif: Value = serde_json::from_str(&sarif::render(&report, &no_source)).unwrap();
        let run = &sarif["runs"][0];
        let json: Value = serde_json::from_str(&json::render(&report)).unwrap();
        assert_eq!(run["properties"]["coverage"], json["coverage"]);
        assert_eq!(run["properties"]["exit_code"], 1);
        assert_eq!(run["properties"]["complete"], false);
        assert_eq!(
            run["properties"]["invalid_decisions"],
            json["invalid_decisions"]
        );
        assert_eq!(
            run["properties"]["decisions_errors"],
            json["decisions_errors"]
        );
        assert_eq!(run["properties"]["warnings"], json["warnings"]);
        let notes = run["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0]["level"], "error");
        assert_eq!(
            notes[0]["message"]["text"],
            ".kurla/\\u{202E}tail: unknown field \\u{202E}tail"
        );
        assert_eq!(notes[1]["level"], "warning");
        assert_eq!(notes[1]["message"]["text"], "cache disabled: \\u{202E}tail");
    }

    #[test]
    fn human_lists_findings_coverage_and_verdict() {
        let fixture = rich();
        let out = human::render(&fixture.report());
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            "high U002 dir/\\u{202E}tail:1:7 message \\u{202E}tail [payload \\u{202E}tail]"
        );
        assert!(lines[1].starts_with("medium S002 b.md:1:1 message "));
        assert!(
            lines[1].contains("reviewed (not counted) by rev \\u{202E}tail: because \\u{202E}tail")
        );
        assert!(lines[2].starts_with("low B002 pic.png@30-40 message "));
        assert!(out.contains("skipped big.txt text size_limit"));
        assert!(out.contains("skipped x/skip.bin unknown_binary excluded_by_user"));
        assert!(out.contains(
            "embedded not scanned c.md 10-20 image/\\u{202E}tail png png content not scanned"
        ));
        assert!(out.contains("not scanned for drawn text pic.png"));
        assert!(out.contains("decisions error .kurla/\\u{202E}tail: unknown field \\u{202E}tail"));
        assert!(out.contains("warning cache disabled: \\u{202E}tail"));
        assert_eq!(*lines.last().unwrap(), "incomplete, exit code 1");
    }

    #[test]
    fn human_verdict_says_incomplete_when_coverage_is_incomplete() {
        let mut fixture = rich();
        fixture.findings.clear();
        fixture.coverage.push(coverage_entry(
            "t.txt",
            FileKind::Text,
            Some(SkipReason::Timeout),
        ));
        let out = human::render(&fixture.report());
        assert_eq!(out.lines().last().unwrap(), "incomplete, exit code 2");
    }

    fn unknown_binary_fixture(require_complete: bool, skip: Option<SkipReason>) -> Fixture {
        let mut fixture = rich();
        fixture.findings.clear();
        fixture.rejected.clear();
        fixture.coverage = vec![
            coverage_entry("a.txt", FileKind::Text, None),
            coverage_entry("blob.bin", FileKind::UnknownBinary, skip),
        ];
        fixture.require_complete = require_complete;
        fixture
    }

    fn all_formats(fixture: &Fixture) -> (Value, Value, String) {
        let report = fixture.report();
        (
            serde_json::from_str(&json::render(&report)).unwrap(),
            serde_json::from_str(&sarif::render(&report, &no_source)).unwrap(),
            human::render(&report),
        )
    }

    #[test]
    fn require_complete_flag_changes_exit_code_but_not_complete() {
        let (json, sarif, human) = all_formats(&unknown_binary_fixture(false, None));
        assert_eq!(json["complete"], false);
        assert_eq!(json["exit_code"], 0);
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(sarif["runs"][0]["properties"]["complete"], false);
        assert_eq!(sarif["runs"][0]["properties"]["exit_code"], 0);
        assert_eq!(human.lines().last().unwrap(), "incomplete, exit code 0");
        let (json, sarif, human) = all_formats(&unknown_binary_fixture(true, None));
        assert_eq!(json["complete"], false);
        assert_eq!(json["exit_code"], 2);
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(sarif["runs"][0]["properties"]["exit_code"], 2);
        assert_eq!(human.lines().last().unwrap(), "incomplete, exit code 2");
    }

    #[test]
    fn unreadable_unknown_binary_is_incomplete_without_the_flag() {
        let fixture = unknown_binary_fixture(false, Some(SkipReason::Unreadable));
        let (json, sarif, human) = all_formats(&fixture);
        assert_eq!(json["complete"], false);
        assert_eq!(json["exit_code"], 2);
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(human.lines().last().unwrap(), "incomplete, exit code 2");
        assert!(!fixture.report().complete());
    }

    #[test]
    fn sarif_regions_correct_across_several_files() {
        let mut fixture = rich();
        fixture.findings = vec![
            finding(
                "U002",
                Severity::High,
                "f2.txt",
                text_span(2, 4, 1, 2),
                None,
            ),
            finding(
                "U002",
                Severity::High,
                "f1.txt",
                text_span(4, 6, 2, 2),
                None,
            ),
            finding(
                "U002",
                Severity::High,
                "f3.txt",
                text_span(1, 4, 1, 2),
                None,
            ),
            finding(
                "U002",
                Severity::High,
                "f1.txt",
                text_span(0, 2, 1, 1),
                None,
            ),
            finding(
                "U002",
                Severity::High,
                "f2.txt",
                text_span(0, 2, 1, 1),
                None,
            ),
            finding(
                "U002",
                Severity::High,
                "f3.txt",
                text_span(3, 5, 2, 1),
                None,
            ),
        ];
        let reads = std::cell::RefCell::new(Vec::new());
        let read = |path: &str| {
            reads.borrow_mut().push(path.to_string());
            let content: &[u8] = match path {
                "f1.txt" => b"ab\ncdef\n",
                "f2.txt" => "\u{e9}ab".as_bytes(),
                "f3.txt" => b"ab\ncd\n",
                _ => return None,
            };
            Some(content.to_vec())
        };
        let sarif: Value = serde_json::from_str(&sarif::render(&fixture.report(), &read)).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let regions: Vec<(String, u64, u64, u64, u64)> = results
            .iter()
            .map(|result| {
                let location = &result["locations"][0]["physicalLocation"];
                let region = &location["region"];
                (
                    location["artifactLocation"]["uri"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    region["startLine"].as_u64().unwrap(),
                    region["startColumn"].as_u64().unwrap(),
                    region["endLine"].as_u64().unwrap(),
                    region["endColumn"].as_u64().unwrap(),
                )
            })
            .collect();
        let expected = vec![
            ("f2.txt", 1, 2, 1, 4),
            ("f1.txt", 2, 2, 2, 4),
            ("f3.txt", 1, 2, 2, 2),
            ("f1.txt", 1, 1, 1, 3),
            ("f2.txt", 1, 1, 1, 2),
            ("f3.txt", 2, 1, 2, 3),
        ];
        let expected: Vec<(String, u64, u64, u64, u64)> = expected
            .into_iter()
            .map(|(path, a, b, c, d)| (path.to_string(), a, b, c, d))
            .collect();
        assert_eq!(regions, expected);
        let mut seen = reads.borrow().clone();
        seen.sort();
        assert_eq!(seen, vec!["f1.txt", "f2.txt", "f3.txt"]);
    }

    #[test]
    fn files_whose_metadata_is_not_scanned_are_listed_in_every_text_format() {
        let mut tiff = coverage_entry("pic.tiff", FileKind::OtherImage, None);
        tiff.metadata_unscanned = true;
        let fixture = Fixture {
            findings: Vec::new(),
            coverage: vec![tiff, coverage_entry("a.md", FileKind::Text, None)],
            counts: BTreeMap::new(),
            invalid: Vec::new(),
            rejected: Vec::new(),
            warnings: Vec::new(),
            threshold: Severity::High,
            require_complete: false,
        };
        let report = fixture.report();
        let json: Value = serde_json::from_str(&json::render(&report)).unwrap();
        assert_eq!(
            json["coverage"]["not_scanned_for_metadata"],
            serde_json::json!(["pic.tiff"])
        );
        assert!(human::render(&report).contains(
            "
metadata not scanned pic.tiff
"
        ));
    }
}

use crate::model::{Category, FileCoverage, FileKind, Finding, Severity, SkipReason};

fn limit_skip(skip: SkipReason) -> bool {
    matches!(
        skip,
        SkipReason::SizeLimit
            | SkipReason::DecompressionLimit
            | SkipReason::Timeout
            | SkipReason::Malformed
    )
}

fn required(category: Category) -> bool {
    matches!(
        category,
        Category::Text | Category::Svg | Category::ImageMetadata
    )
}

fn file_incomplete(file: &FileCoverage, require_complete: bool) -> bool {
    if file.skip == Some(SkipReason::Unreadable)
        || (required(file.category) && file.skip.is_some_and(limit_skip))
    {
        return true;
    }
    if !require_complete {
        return false;
    }
    let unknown_binary = file.category == Category::UnknownBinary
        && !matches!(
            file.skip,
            Some(SkipReason::ExcludedByUser | SkipReason::SymlinkNotFollowed)
        );
    let embedded = file
        .embedded_not_scanned
        .iter()
        .any(|entry| entry.kind != FileKind::Pdf);
    unknown_binary || embedded
}

pub fn incomplete(coverage: &[FileCoverage], require_complete: bool) -> bool {
    coverage
        .iter()
        .any(|file| file_incomplete(file, require_complete))
}

pub fn code(
    findings: &[Finding],
    coverage: &[FileCoverage],
    threshold: Severity,
    require_complete: bool,
    decisions_rejected: bool,
) -> i32 {
    let active = findings.iter().any(|finding| {
        finding.severity >= threshold && !finding.review.as_ref().is_some_and(|r| r.counted)
    });
    if active {
        1
    } else if decisions_rejected || incomplete(coverage, require_complete) {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CarrierKind, EmbeddedNotScanned, Family, LocationKind, RawFinding, Review, RuleStatus, Span,
    };

    fn finding(severity: Severity, review: Option<bool>) -> Finding {
        Finding {
            raw: RawFinding {
                rule_id: "S002",
                family: Family::S,
                base: severity,
                status: RuleStatus::Stable,
                span: Span {
                    byte_start: 0,
                    byte_end: 1,
                    line: Some(1),
                    column: Some(1),
                },
                carrier: CarrierKind::HiddenText,
                payload: None,
                message: String::new(),
                evidence: Vec::new(),
            },
            path: "a.md".to_string(),
            location: LocationKind::Code,
            severity,
            fingerprint: "f".repeat(64),
            review: review.map(|counted| Review {
                reviewer: "r".to_string(),
                reason: "why".to_string(),
                counted,
            }),
        }
    }

    fn file(kind: FileKind, skip: Option<SkipReason>) -> FileCoverage {
        FileCoverage {
            path: "x".to_string(),
            kind,
            category: kind.category(),
            skip,
            drawn_text_unscanned: kind.drawn_text_unscanned(),
            metadata_unscanned: false,
            embedded_not_scanned: Vec::new(),
            encoded_runs_not_payloads: 0,
        }
    }

    fn with_embedded(mut coverage: FileCoverage, kind: FileKind) -> FileCoverage {
        coverage.embedded_not_scanned.push(EmbeddedNotScanned {
            span: Span {
                byte_start: 1,
                byte_end: 2,
                line: None,
                column: None,
            },
            declared_type: None,
            kind,
            reason: "not scanned".to_string(),
        });
        coverage
    }

    struct Row {
        name: &'static str,
        findings: Vec<Finding>,
        coverage: Vec<FileCoverage>,
        threshold: Severity,
        rejected: bool,
        default: i32,
        required: i32,
    }

    fn row(
        name: &'static str,
        findings: Vec<Finding>,
        coverage: Vec<FileCoverage>,
        default: i32,
        required: i32,
    ) -> Row {
        Row {
            name,
            findings,
            coverage,
            threshold: Severity::High,
            rejected: false,
            default,
            required,
        }
    }

    #[test]
    fn exit_table_matches_spec_13_3() {
        let text = FileKind::Text;
        let mut rows = vec![
            row("empty", vec![], vec![], 0, 0),
            row(
                "high finding",
                vec![finding(Severity::High, None)],
                vec![],
                1,
                1,
            ),
            row(
                "critical finding",
                vec![finding(Severity::Critical, None)],
                vec![],
                1,
                1,
            ),
            row(
                "medium finding below the default threshold",
                vec![finding(Severity::Medium, None)],
                vec![],
                0,
                0,
            ),
            row(
                "findings win over incomplete",
                vec![finding(Severity::High, None)],
                vec![file(text, Some(SkipReason::SizeLimit))],
                1,
                1,
            ),
            row(
                "text size limit",
                vec![],
                vec![file(text, Some(SkipReason::SizeLimit))],
                2,
                2,
            ),
            row(
                "svg decompression limit",
                vec![],
                vec![file(FileKind::Svg, Some(SkipReason::DecompressionLimit))],
                2,
                2,
            ),
            row(
                "image metadata timeout",
                vec![],
                vec![file(FileKind::Png, Some(SkipReason::Timeout))],
                2,
                2,
            ),
            row(
                "image metadata decompression limit",
                vec![],
                vec![file(FileKind::Png, Some(SkipReason::DecompressionLimit))],
                2,
                2,
            ),
            row(
                "image metadata malformed",
                vec![],
                vec![file(FileKind::Jpeg, Some(SkipReason::Malformed))],
                2,
                2,
            ),
            row(
                "unknown binary timeout counts only under the flag",
                vec![],
                vec![file(FileKind::UnknownBinary, Some(SkipReason::Timeout))],
                0,
                2,
            ),
            row(
                "unknown binary size limit counts only under the flag",
                vec![],
                vec![file(FileKind::UnknownBinary, Some(SkipReason::SizeLimit))],
                0,
                2,
            ),
            row(
                "text unreadable",
                vec![],
                vec![file(text, Some(SkipReason::Unreadable))],
                2,
                2,
            ),
            row(
                "malformed svg is incomplete by default",
                vec![],
                vec![file(FileKind::Svg, Some(SkipReason::Malformed))],
                2,
                2,
            ),
            row(
                "drawn text only",
                vec![],
                vec![file(FileKind::Png, None), file(FileKind::Jpeg, None)],
                0,
                0,
            ),
            row(
                "pdf not scanned",
                vec![],
                vec![file(FileKind::Pdf, Some(SkipReason::PdfNotScanned))],
                0,
                0,
            ),
            row(
                "pdf over the size limit",
                vec![],
                vec![file(FileKind::Pdf, Some(SkipReason::SizeLimit))],
                0,
                0,
            ),
            row(
                "unknown binary",
                vec![],
                vec![file(FileKind::UnknownBinary, None)],
                0,
                2,
            ),
            row(
                "other image",
                vec![],
                vec![file(FileKind::OtherImage, None)],
                0,
                2,
            ),
            row(
                "unread fifo",
                vec![],
                vec![file(FileKind::UnknownBinary, Some(SkipReason::Unreadable))],
                2,
                2,
            ),
            row(
                "unreadable pdf",
                vec![],
                vec![file(FileKind::Pdf, Some(SkipReason::Unreadable))],
                2,
                2,
            ),
            row(
                "unreadable other image",
                vec![],
                vec![file(FileKind::OtherImage, Some(SkipReason::Unreadable))],
                2,
                2,
            ),
            row(
                "excluded unknown binary",
                vec![],
                vec![file(
                    FileKind::UnknownBinary,
                    Some(SkipReason::ExcludedByUser),
                )],
                0,
                0,
            ),
            row(
                "symlink not followed",
                vec![],
                vec![file(
                    FileKind::UnknownBinary,
                    Some(SkipReason::SymlinkNotFollowed),
                )],
                0,
                0,
            ),
            row(
                "text file excluded by the user",
                vec![],
                vec![file(text, Some(SkipReason::ExcludedByUser))],
                0,
                0,
            ),
            row(
                "embedded png in text",
                vec![],
                vec![with_embedded(file(text, None), FileKind::Png)],
                0,
                2,
            ),
            row(
                "embedded unknown binary in text",
                vec![],
                vec![with_embedded(file(text, None), FileKind::UnknownBinary)],
                0,
                2,
            ),
            row(
                "embedded pdf in text",
                vec![],
                vec![with_embedded(file(text, None), FileKind::Pdf)],
                0,
                0,
            ),
            row(
                "reviewed and counted",
                vec![finding(Severity::High, Some(true))],
                vec![],
                0,
                0,
            ),
            row(
                "reviewed but not counted",
                vec![finding(Severity::High, Some(false))],
                vec![],
                1,
                1,
            ),
            row(
                "counted review does not hide an incomplete scan",
                vec![finding(Severity::High, Some(true))],
                vec![file(text, Some(SkipReason::Timeout))],
                2,
                2,
            ),
        ];
        let mut at_medium = row(
            "medium finding at a medium threshold",
            vec![finding(Severity::Medium, None)],
            vec![],
            1,
            1,
        );
        at_medium.threshold = Severity::Medium;
        rows.push(at_medium);
        let mut at_critical = row(
            "high finding below a critical threshold",
            vec![finding(Severity::High, None)],
            vec![],
            0,
            0,
        );
        at_critical.threshold = Severity::Critical;
        rows.push(at_critical);
        let mut rejected_clean = row("rejected decisions, nothing active", vec![], vec![], 2, 2);
        rejected_clean.rejected = true;
        rows.push(rejected_clean);
        let mut rejected_active = row(
            "rejected decisions, active high finding",
            vec![finding(Severity::High, None)],
            vec![],
            1,
            1,
        );
        rejected_active.rejected = true;
        rows.push(rejected_active);
        let mut rejected_below = row(
            "rejected decisions, finding below the threshold",
            vec![finding(Severity::Low, None)],
            vec![],
            2,
            2,
        );
        rejected_below.rejected = true;
        rows.push(rejected_below);
        for row in rows {
            assert_eq!(
                code(
                    &row.findings,
                    &row.coverage,
                    row.threshold,
                    false,
                    row.rejected
                ),
                row.default,
                "{} without --require-complete",
                row.name
            );
            assert_eq!(
                code(
                    &row.findings,
                    &row.coverage,
                    row.threshold,
                    true,
                    row.rejected
                ),
                row.required,
                "{} with --require-complete",
                row.name
            );
        }
    }

    #[test]
    fn exit_require_complete_counts_embedded_not_scanned_but_not_embedded_pdf() {
        let png = [with_embedded(file(FileKind::Text, None), FileKind::Png)];
        let pdf = [with_embedded(file(FileKind::Text, None), FileKind::Pdf)];
        assert_eq!(code(&[], &png, Severity::High, false, false), 0);
        assert_eq!(code(&[], &png, Severity::High, true, false), 2);
        assert_eq!(code(&[], &pdf, Severity::High, false, false), 0);
        assert_eq!(code(&[], &pdf, Severity::High, true, false), 0);
    }

    #[test]
    fn exit_malformed_svg_is_incomplete_by_default() {
        let coverage = [file(FileKind::Svg, Some(SkipReason::Malformed))];
        assert_eq!(code(&[], &coverage, Severity::High, false, false), 2);
    }

    #[test]
    fn complete_flag_is_independent_of_require_complete() {
        let binary = [file(FileKind::UnknownBinary, None)];
        assert!(!incomplete(&binary, false));
        let unreadable = [file(FileKind::UnknownBinary, Some(SkipReason::Unreadable))];
        assert!(incomplete(&unreadable, false));
        assert!(incomplete(&binary, true));
        let text = [file(FileKind::Text, Some(SkipReason::SizeLimit))];
        assert!(incomplete(&text, false));
        assert!(incomplete(&text, true));
        assert!(!incomplete(&[file(FileKind::Text, None)], true));
        let pdf = [with_embedded(file(FileKind::Text, None), FileKind::Pdf)];
        assert!(!incomplete(&pdf, true));
    }

    #[test]
    fn exit_rejected_decisions_without_findings_is_2_with_findings_is_1() {
        assert_eq!(code(&[], &[], Severity::High, false, true), 2);
        let active = [finding(Severity::High, None)];
        assert_eq!(code(&active, &[], Severity::High, false, true), 1);
    }
}

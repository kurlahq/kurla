use super::{Report, category_name, escape, kind_name, severity_name, skip_name, source_name};
use crate::model::{Finding, SkipReason};
use std::fmt::Write;

fn finding_line(finding: &Finding) -> String {
    let raw = &finding.raw;
    let place = match (raw.span.line, raw.span.column) {
        (Some(line), Some(column)) => format!("{}:{line}:{column}", escape(&finding.path)),
        _ => format!(
            "{}@{}-{}",
            escape(&finding.path),
            raw.span.byte_start,
            raw.span.byte_end
        ),
    };
    let mut line = format!(
        "{} {} {place} {}",
        severity_name(finding.severity),
        escape(raw.rule_id),
        escape(&raw.message)
    );
    if let Some(payload) = &raw.payload {
        let _ = write!(line, " [{}]", escape(payload));
    }
    if let Some(review) = &finding.review {
        let counted = if review.counted {
            "counted"
        } else {
            "not counted"
        };
        let _ = write!(
            line,
            " reviewed ({counted}) by {}: {}",
            escape(&review.reviewer),
            escape(&review.reason)
        );
    }
    line
}

pub fn render(report: &Report) -> String {
    let mut out = String::new();
    for finding in report.findings {
        out.push_str(&finding_line(finding));
        out.push('\n');
    }
    out.push_str("coverage:\n");
    let scanned: Vec<String> = [
        crate::model::Category::Text,
        crate::model::Category::Svg,
        crate::model::Category::ImageMetadata,
        crate::model::Category::Pdf,
        crate::model::Category::UnknownBinary,
    ]
    .iter()
    .map(|category| {
        let count = report
            .coverage
            .iter()
            .filter(|file| file.category == *category && file.skip.is_none())
            .count();
        format!("{}={count}", category_name(*category))
    })
    .collect();
    let _ = writeln!(out, "scanned {}", scanned.join(" "));
    for file in report.coverage {
        if let Some(skip) = file.skip {
            let _ = writeln!(
                out,
                "skipped {} {} {}",
                escape(&file.path),
                kind_name(file.kind),
                skip_name(skip)
            );
        }
    }
    for file in report.coverage {
        for entry in &file.embedded_not_scanned {
            let declared = entry
                .declared_type
                .as_deref()
                .map_or("-".to_string(), escape);
            let _ = writeln!(
                out,
                "embedded not scanned {} {}-{} {declared} {} {}",
                escape(&file.path),
                entry.span.byte_start,
                entry.span.byte_end,
                kind_name(entry.kind),
                escape(&entry.reason)
            );
        }
    }
    for file in report.coverage {
        if file.drawn_text_unscanned {
            let _ = writeln!(out, "not scanned for drawn text {}", escape(&file.path));
        }
    }
    let excluded = report
        .coverage
        .iter()
        .filter(|file| file.skip == Some(SkipReason::ExcludedByUser))
        .count();
    let _ = writeln!(out, "excluded by user {excluded}");
    let runs: u64 = report
        .coverage
        .iter()
        .map(|file| file.encoded_runs_not_payloads)
        .sum();
    let _ = writeln!(out, "encoded runs not payloads {runs}");
    for entry in report.invalid {
        let _ = writeln!(
            out,
            "invalid decision {} {} {} {}: {}",
            source_name(entry.source),
            escape(&entry.rule),
            escape(&entry.fingerprint),
            escape(&entry.path),
            escape(entry.reason)
        );
    }
    for file in report.rejected {
        let _ = writeln!(
            out,
            "decisions error {}: {}",
            escape(&file.file),
            escape(&file.message)
        );
    }
    for warning in report.warnings {
        let _ = writeln!(out, "warning {}", escape(warning));
    }
    let verdict = if report.complete() {
        "complete"
    } else {
        "incomplete"
    };
    let _ = writeln!(out, "{verdict}, exit code {}", report.exit_code());
    out
}

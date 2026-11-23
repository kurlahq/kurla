use super::{
    Report, SRCROOT, artifact_location, coverage_value, escape, family_name, invalid_value,
    rejected_value, severity_name, status_name, warnings_value,
};
use crate::model::{Finding, RuleStatus, Severity};
use crate::text::TextDoc;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

struct Docs<'a> {
    source: &'a dyn Fn(&str) -> Option<Vec<u8>>,
    current: Option<(String, Option<TextDoc>)>,
}

impl Docs<'_> {
    fn doc(&mut self, path: &str) -> Option<&TextDoc> {
        let loaded = self
            .current
            .as_ref()
            .is_some_and(|(current, _)| current == path);
        if !loaded {
            let doc = (self.source)(path).and_then(|bytes| TextDoc::decode(&bytes));
            self.current = Some((path.to_string(), doc));
        }
        self.current.as_ref().and_then(|(_, doc)| doc.as_ref())
    }

    #[cfg(test)]
    fn resident(&self) -> usize {
        usize::from(self.current.is_some())
    }

    fn end_position(&mut self, finding: &Finding, line: u32, column: u32) -> Option<(u32, u32)> {
        let span = finding.raw.span;
        let doc = self.doc(&finding.path)?;
        let start = doc.char_index_of_byte(span.byte_start)?;
        let end = doc.char_index_of_byte(span.byte_end)?;
        if end < start || doc.position(start) != (line, column) {
            return None;
        }
        Some(doc.position(end))
    }
}

fn region(finding: &Finding, docs: &mut Docs) -> Value {
    let span = finding.raw.span;
    let (Some(line), Some(column)) = (span.line, span.column) else {
        return json!({
            "byteOffset": span.byte_start,
            "byteLength": span.byte_end.saturating_sub(span.byte_start),
        });
    };
    let mut region = json!({"startLine": line, "startColumn": column});
    if let Some((end_line, end_column)) = docs.end_position(finding, line, column) {
        region["endLine"] = json!(end_line);
        region["endColumn"] = json!(end_column);
    }
    region
}

fn result(finding: &Finding, docs: &mut Docs) -> Value {
    let raw = &finding.raw;
    let text = match &raw.payload {
        Some(payload) => format!("{}: {}", escape(&raw.message), escape(payload)),
        None => escape(&raw.message),
    };
    let mut result = json!({
        "ruleId": escape(raw.rule_id),
        "level": level(finding.severity),
        "message": {"text": text},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": artifact_location(&finding.path),
                "region": region(finding, docs),
            }
        }],
        "partialFingerprints": {"kurla/v1": escape(&finding.fingerprint)},
        "properties": {"severity": severity_name(finding.severity)},
    });
    if let Some(review) = &finding.review {
        result["suppressions"] = json!([{
            "kind": "external",
            "justification": escape(&review.reason),
            "properties": {
                "reviewer": escape(&review.reviewer),
                "counted": review.counted,
            },
        }]);
    }
    result
}

fn rules(report: &Report) -> Vec<Value> {
    let mut rules: BTreeMap<&str, (crate::model::Family, RuleStatus, Severity)> = BTreeMap::new();
    for finding in report.findings {
        let raw = &finding.raw;
        rules
            .entry(raw.rule_id)
            .and_modify(|entry| entry.2 = entry.2.max(finding.severity))
            .or_insert((raw.family, raw.status, finding.severity));
    }
    rules
        .into_iter()
        .map(|(id, (family, status, severity))| {
            json!({
                "id": escape(id),
                "properties": {
                    "family": family_name(family),
                    "status": status_name(status),
                    "security-severity": security_severity(severity),
                },
            })
        })
        .collect()
}

fn notifications(report: &Report) -> Vec<Value> {
    let errors = report.rejected.iter().map(|file| {
        json!({
            "level": "error",
            "message": {"text": format!("{}: {}", escape(&file.file), escape(&file.message))},
        })
    });
    let warnings = report.warnings.iter().map(|warning| {
        json!({
            "level": "warning",
            "message": {"text": escape(warning)},
        })
    });
    errors.chain(warnings).collect()
}

pub fn render(report: &Report, source: &dyn Fn(&str) -> Option<Vec<u8>>) -> String {
    let mut docs = Docs {
        source,
        current: None,
    };
    let mut order: Vec<usize> = (0..report.findings.len()).collect();
    order.sort_by(|a, b| report.findings[*a].path.cmp(&report.findings[*b].path));
    let mut slots: Vec<Option<Value>> = vec![None; report.findings.len()];
    for index in order {
        slots[index] = Some(result(&report.findings[index], &mut docs));
    }
    let results: Vec<Value> = slots.into_iter().flatten().collect();
    json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Kurla",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules(report),
            }},
            "originalUriBaseIds": {
                SRCROOT: {"description": {"text": "The directory the scan ran from."}},
            },
            "columnKind": "unicodeCodePoints",
            "results": results,
            "invocations": [{
                "executionSuccessful": report.complete(),
                "exitCode": report.exit_code(),
                "toolExecutionNotifications": notifications(report),
            }],
            "properties": {
                "complete": report.complete(),
                "exit_code": report.exit_code(),
                "coverage": coverage_value(report),
                "invalid_decisions": invalid_value(report),
                "decisions_errors": rejected_value(report),
                "warnings": warnings_value(report),
            },
        }],
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn docs_keep_one_decoded_file_at_a_time() {
        let reads = RefCell::new(Vec::new());
        let source = |path: &str| {
            reads.borrow_mut().push(path.to_string());
            Some(b"ab\n".to_vec())
        };
        let mut docs = Docs {
            source: &source,
            current: None,
        };
        assert!(docs.doc("a").is_some());
        assert_eq!(docs.resident(), 1);
        assert!(docs.doc("a").is_some());
        assert_eq!(reads.borrow().len(), 1);
        assert!(docs.doc("b").is_some());
        assert_eq!(docs.resident(), 1);
        assert!(docs.doc("c").is_some());
        assert_eq!(docs.resident(), 1);
        assert_eq!(*reads.borrow(), vec!["a", "b", "c"]);
    }
}

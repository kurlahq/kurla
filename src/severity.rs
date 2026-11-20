use crate::model::{CarrierKind, LocationKind, RawFinding, RuleStatus, Severity};

pub fn finalize(raw: &RawFinding, location: LocationKind, instruction_like: bool) -> Severity {
    let mut severity = raw.base;
    if instruction_like && raw.carrier == CarrierKind::HiddenText {
        severity = severity.bump();
    }
    if location == LocationKind::AgentFile && raw.rule_id != "I002" {
        severity = severity.bump();
    }
    if location == LocationKind::Dependency {
        severity = severity.lower();
    }
    if raw.status == RuleStatus::Experimental {
        severity = severity.min(Severity::Medium);
    }
    severity
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Family;
    use crate::model::Span;

    fn raw(
        rule_id: &'static str,
        base: Severity,
        status: RuleStatus,
        carrier: CarrierKind,
    ) -> RawFinding {
        RawFinding {
            rule_id,
            family: Family::U,
            base,
            status,
            span: Span {
                byte_start: 0,
                byte_end: 0,
                line: None,
                column: None,
            },
            carrier,
            payload: None,
            message: String::new(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn severity_table_matches_spec_13_2() {
        use CarrierKind::*;
        use LocationKind::*;
        use RuleStatus::*;
        use Severity::*;
        let rows: Vec<(&str, RawFinding, LocationKind, bool, Severity)> = vec![
            (
                "hidden by construction, code",
                raw("U002", High, Stable, HiddenText),
                Code,
                false,
                High,
            ),
            (
                "hidden by construction, docs",
                raw("M002", High, Stable, HiddenText),
                DocsTemplate,
                false,
                High,
            ),
            (
                "hidden by construction with instruction-like payload",
                raw("U002", High, Stable, HiddenText),
                Code,
                true,
                Critical,
            ),
            (
                "active content ignores instruction_like",
                raw("S003", High, Stable, ActiveContent),
                Code,
                true,
                High,
            ),
            (
                "active content, data asset",
                raw("S003", High, Stable, ActiveContent),
                DataAsset,
                false,
                High,
            ),
            (
                "encoded instruction-like payload",
                raw("E001", High, Stable, DecodedPayload),
                DocsTemplate,
                false,
                High,
            ),
            (
                "any finding in an agent file is one higher",
                raw("M002", High, Stable, HiddenText),
                AgentFile,
                false,
                Critical,
            ),
            (
                "agent file bump on a low finding",
                raw("L001", Low, Stable, ResourceLimit),
                AgentFile,
                false,
                Medium,
            ),
            (
                "active agent configuration is exempt from the agent file bump",
                raw("I002", Medium, Stable, ActiveContent),
                AgentFile,
                false,
                Medium,
            ),
            (
                "visible instruction-like carrier",
                raw("A001", Medium, Experimental, MetadataField),
                DocsTemplate,
                false,
                Medium,
            ),
            (
                "experimental hit in an agent file is capped at medium",
                raw("A001", Medium, Experimental, AgentFileText),
                AgentFile,
                false,
                Medium,
            ),
            (
                "experimental cap applies after every weight",
                raw("U006", High, Experimental, HiddenText),
                AgentFile,
                true,
                Medium,
            ),
            (
                "experimental cap is applied last, after dependency lowering",
                raw("U006", High, Experimental, HiddenText),
                Dependency,
                false,
                Medium,
            ),
            (
                "experimental below the cap stays",
                raw("U006", Low, Experimental, MetadataField),
                Code,
                false,
                Low,
            ),
            (
                "hidden text in a dependency is lowered",
                raw("U002", High, Stable, HiddenText),
                Dependency,
                false,
                Medium,
            ),
            (
                "instruction-like hidden text in a dependency is bumped then lowered",
                raw("U002", High, Stable, HiddenText),
                Dependency,
                true,
                High,
            ),
            (
                "low finding in a dependency becomes info",
                raw("L001", Low, Stable, ResourceLimit),
                Dependency,
                false,
                Info,
            ),
            (
                "decompression bomb",
                raw("B002", High, Stable, ResourceLimit),
                Code,
                false,
                High,
            ),
            (
                "decompression bomb in an agent file",
                raw("B002", High, Stable, ResourceLimit),
                AgentFile,
                false,
                Critical,
            ),
            (
                "instruction_like bump applies once before the agent bump",
                raw("U003", Medium, Stable, HiddenText),
                AgentFile,
                true,
                Critical,
            ),
        ];
        for (name, finding, location, instruction_like, expected) in rows {
            assert_eq!(
                finalize(&finding, location, instruction_like),
                expected,
                "{name}"
            );
        }
    }
}

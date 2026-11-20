use super::{
    Report, carrier_counts_value, coverage_value, findings_value, invalid_value, rejected_value,
    severity_name, warnings_value,
};
use crate::engine::RULES_VERSION;
use serde_json::json;

pub fn render(report: &Report) -> String {
    json!({
        "schema": "kurla.report/1",
        "kurla_version": env!("CARGO_PKG_VERSION"),
        "rules_version": RULES_VERSION,
        "complete": report.complete(),
        "exit_code": report.exit_code(),
        "threshold": severity_name(report.threshold),
        "findings": findings_value(report),
        "coverage": coverage_value(report),
        "carrier_counts": carrier_counts_value(report),
        "invalid_decisions": invalid_value(report),
        "decisions_errors": rejected_value(report),
        "warnings": warnings_value(report),
    })
    .to_string()
}

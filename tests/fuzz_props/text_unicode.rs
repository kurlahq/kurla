use kurla::aimed::classify;
use kurla::model::LocationKind;
use kurla::text::TextDoc;
use kurla::unicode::{confusable_skeleton, scan_text};

use crate::spans;

pub fn check(data: &[u8]) {
    let Some(doc) = TextDoc::decode(data) else {
        return;
    };
    for location in [
        LocationKind::AgentFile,
        LocationKind::DocsTemplate,
        LocationKind::Code,
        LocationKind::DataAsset,
        LocationKind::Dependency,
    ] {
        let findings = scan_text(&doc, location);
        spans::check_spans(data.len(), "unicode", &findings, &[], &[]);
    }
    let _ = classify(&doc.text);
    let _ = confusable_skeleton(&doc.text);
}

use kurla::limits::{Budget, Limits};
use kurla::markup::{Markup, scan_markup};
use kurla::text::TextDoc;

use crate::spans;

pub fn check(data: &[u8]) {
    let Some(doc) = TextDoc::decode(data) else {
        return;
    };
    for (flavour, name) in [(Markup::Html, "html"), (Markup::Markdown, "markdown")] {
        let mut budget = Budget::new(&Limits::default());
        let out = scan_markup(&doc, &mut budget, flavour);
        spans::check_spans(data.len(), name, &out.findings, &out.carriers, &[]);
    }
}

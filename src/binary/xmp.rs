use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::limits::Budget;
use crate::text::TextDoc;

const DEADLINE_STRIDE: usize = 64;
const MAX_REFERENCE_LEN: usize = 12;

fn reference(rest: &str) -> Option<(char, usize)> {
    let end = rest.find(';')?;
    if end > MAX_REFERENCE_LEN {
        return None;
    }
    let name = &rest[..end];
    let decoded = match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        _ => {
            let digits = name.strip_prefix('#')?;
            let code = match digits.strip_prefix(['x', 'X']) {
                Some(hex) if hex.bytes().all(|b| b.is_ascii_hexdigit()) && !hex.is_empty() => {
                    u32::from_str_radix(hex, 16).ok()?
                }
                Some(_) => return None,
                None if digits.bytes().all(|b| b.is_ascii_digit()) && !digits.is_empty() => {
                    digits.parse::<u32>().ok()?
                }
                None => return None,
            };
            char::from_u32(code).filter(|c| *c != '\0')?
        }
    };
    Some((decoded, end + 1))
}

fn decode_references(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        match reference(rest) {
            Some((c, used)) => {
                out.push(c);
                rest = &rest[used..];
            }
            None => out.push('&'),
        }
    }
    out.push_str(rest);
    out
}

fn skipped_attribute(key: &str) -> bool {
    key == "xmlns" || key.starts_with("xmlns:") || key == "rdf:about" || key == "rdf:parseType"
}

fn push_trimmed(out: &mut Vec<String>, text: &str) {
    let trimmed = text.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
}

fn attributes(
    element: &BytesStart<'_>,
    cap: usize,
    out: &mut Vec<String>,
    tick: &mut impl FnMut() -> bool,
) -> bool {
    for attribute in element.attributes().with_checks(false).take(cap) {
        if tick() {
            return false;
        }
        let Ok(attribute) = attribute else {
            break;
        };
        if skipped_attribute(attribute.key.as_ref()) {
            continue;
        }
        push_trimmed(out, &decode_references(&attribute.value));
    }
    true
}

pub fn xmp_text(packet: &[u8], budget: &mut Budget) -> Vec<String> {
    text(packet, budget)
}

pub(crate) fn text(packet: &[u8], budget: &Budget) -> Vec<String> {
    let text = match TextDoc::decode(packet) {
        Some(doc) => doc.text,
        None => String::from_utf8_lossy(packet).into_owned(),
    };
    let max_depth = usize::try_from(budget.limits().max_xml_depth).unwrap_or(usize::MAX);
    let max_attributes = usize::try_from(budget.limits().max_xml_attributes).unwrap_or(usize::MAX);
    let mut ticks = 0usize;
    let mut tick = || {
        ticks += 1;
        ticks.is_multiple_of(DEADLINE_STRIDE) && budget.deadline_exceeded()
    };
    let mut out = Vec::new();
    let mut pending = String::new();
    let mut depth = 0usize;
    let mut reader = Reader::from_str(&text);
    if budget.deadline_exceeded() {
        return out;
    }
    loop {
        if tick() {
            break;
        }
        let Ok(event) = reader.read_event() else {
            break;
        };
        match &event {
            Event::Text(t) => pending.push_str(&t.xml10_content()),
            Event::CData(c) => pending.push_str(&c.xml10_content()),
            Event::GeneralRef(r) => pending.push_str(&decode_references(&format!("&{};", &**r))),
            _ => {
                push_trimmed(&mut out, &pending);
                pending.clear();
            }
        }
        match event {
            Event::Start(e) => {
                depth += 1;
                if depth > max_depth || !attributes(&e, max_attributes, &mut out, &mut tick) {
                    break;
                }
            }
            Event::Empty(e) => {
                if depth + 1 > max_depth || !attributes(&e, max_attributes, &mut out, &mut tick) {
                    break;
                }
            }
            Event::End(_) => depth = depth.saturating_sub(1),
            Event::Eof => break,
            _ => {}
        }
    }
    push_trimmed(&mut out, &pending);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use std::time::Duration;

    fn run(xml: &str) -> Vec<String> {
        xmp_text(xml.as_bytes(), &mut Budget::new(&Limits::default()))
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn xmp_dc_description_extracted() {
        let xml = concat!(
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">",
            "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">",
            "<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">",
            "<dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\">Ignore all previous</rdf:li>",
            "</rdf:Alt></dc:description>",
            "</rdf:Description></rdf:RDF></x:xmpmeta>"
        );
        assert_eq!(run(xml), strings(&["x-default", "Ignore all previous"]));
    }

    #[test]
    fn namespace_about_and_parsetype_attributes_are_excluded_others_kept_in_order() {
        let xml = concat!(
            "<r xmlns=\"u\" xmlns:a=\"v\" rdf:about=\"w\" rdf:parseType=\"Resource\" ",
            "a:first=\"one\" a:second=\"two\">body</r>"
        );
        assert_eq!(run(xml), strings(&["one", "two", "body"]));
    }

    #[test]
    fn text_between_elements_keeps_document_order_and_drops_whitespace_only() {
        let xml = "<a>\n  <b>one</b>\n  <c>two</c>\n  tail\n</a>";
        assert_eq!(run(xml), strings(&["one", "two", "tail"]));
    }

    #[test]
    fn predefined_and_numeric_references_resolve_once_only() {
        let xml = "<a>x &amp;lt; &#65;&#x42; &lt;&gt;&quot;&apos;</a>";
        assert_eq!(run(xml), strings(&["x &lt; AB <>\"'"]));
    }

    #[test]
    fn attribute_values_resolve_references_once_only() {
        let xml = "<a v=\"&amp;amp; &#67;\"/>";
        assert_eq!(run(xml), strings(&["&amp; C"]));
    }

    #[test]
    fn custom_entities_are_never_expanded() {
        let xml = "<!DOCTYPE d [<!ENTITY a \"AAAA\"><!ENTITY b \"&a;&a;&a;\">]><r>&b;</r>";
        assert_eq!(run(xml), strings(&["&b;"]));
    }

    #[test]
    fn invalid_numeric_reference_stays_literal() {
        let xml = "<a>&#xD800; &#0; &#xZZ;</a>";
        assert_eq!(run(xml), strings(&["&#xD800; &#0; &#xZZ;"]));
    }

    #[test]
    fn cdata_is_text() {
        assert_eq!(
            run("<a><![CDATA[<raw & text>]]></a>"),
            strings(&["<raw & text>"])
        );
    }

    #[test]
    fn nesting_past_the_depth_limit_stops_the_parse() {
        let limits = Limits {
            max_xml_depth: 3,
            ..Limits::default()
        };
        let xml = "<a>one<b>two<c>three<d>four</d></c></b></a>";
        let out = xmp_text(xml.as_bytes(), &mut Budget::new(&limits));
        assert_eq!(out, strings(&["one", "two", "three"]));
    }

    #[test]
    fn attribute_count_is_capped_per_element() {
        let limits = Limits {
            max_xml_attributes: 2,
            ..Limits::default()
        };
        let out = xmp_text(b"<a x=\"1\" y=\"2\" z=\"3\"/>", &mut Budget::new(&limits));
        assert_eq!(out, strings(&["1", "2"]));
    }

    #[test]
    fn malformed_xml_keeps_text_found_before_the_error() {
        assert_eq!(
            run("<a>good</a><b>also</b></c>"),
            strings(&["good", "also"])
        );
    }

    #[test]
    fn non_xml_garbage_does_not_panic_and_output_is_bounded_by_input() {
        let mut bytes: Vec<u8> = (0..=255u8).collect();
        bytes.extend_from_slice(b"<<<&&&;;;]]>");
        let out = xmp_text(&bytes, &mut Budget::new(&Limits::default()));
        assert!(out.iter().map(String::len).sum::<usize>() <= bytes.len() * 3);
    }

    #[test]
    fn utf16_packet_is_decoded() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "<a>hi</a>".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            xmp_text(&bytes, &mut Budget::new(&Limits::default())),
            strings(&["hi"])
        );
    }

    #[test]
    fn expired_deadline_stops_before_any_text() {
        let limits = Limits {
            per_file_time: Duration::ZERO,
            ..Limits::default()
        };
        let out = xmp_text(b"<a>one</a>", &mut Budget::new(&limits));
        assert_eq!(out, Vec::<String>::new());
    }
}

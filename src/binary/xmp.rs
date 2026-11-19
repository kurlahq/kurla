use std::borrow::Cow;

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::limits::Budget;
use crate::text::TextDoc;

const DEADLINE_STRIDE: usize = 64;
const MAX_REFERENCE_LEN: usize = 32;
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

fn reference(rest: &str) -> Option<(char, usize)> {
    let end = rest
        .as_bytes()
        .iter()
        .take(MAX_REFERENCE_LEN + 1)
        .position(|&b| b == b';')?;
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

fn decode_references(raw: &str, tick: &mut dyn FnMut() -> bool) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        if tick() {
            return None;
        }
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
    Some(out)
}

fn skipped_attribute(key: &str) -> bool {
    key == "xmlns" || key.starts_with("xmlns:") || key == "rdf:about" || key == "rdf:parseType"
}

type Emit<'a> = &'a mut dyn FnMut(&str, Option<(usize, usize)>) -> bool;

struct Scan<'a> {
    text: &'a str,
    base: Option<usize>,
    emit: Emit<'a>,
    stopped: bool,
}

impl Scan<'_> {
    fn push(&mut self, raw: &str, range: Option<(usize, usize)>) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        let mapped = match (self.base, range) {
            (Some(base), Some((a, b))) => Some((base + a, base + b)),
            _ => None,
        };
        if !(self.emit)(trimmed, mapped) {
            self.stopped = true;
        }
    }

    fn value_range(&self, value: &str, fallback: (usize, usize)) -> (usize, usize) {
        let origin = self.text.as_ptr() as usize;
        let at = (value.as_ptr() as usize).wrapping_sub(origin);
        match at.checked_add(value.len()) {
            Some(end) if end <= self.text.len() => (at, end),
            _ => fallback,
        }
    }

    fn attributes(
        &mut self,
        element: &BytesStart<'_>,
        span: (usize, usize),
        cap: usize,
        tick: &mut dyn FnMut() -> bool,
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
            let range = self.value_range(&attribute.value, span);
            let Some(decoded) = decode_references(&attribute.value, tick) else {
                return false;
            };
            self.push(&decoded, Some(range));
            if self.stopped {
                return false;
            }
        }
        true
    }
}

pub(crate) fn scan(packet: &[u8], budget: &Budget, emit: Emit<'_>) {
    let has_bom = packet.starts_with(&UTF8_BOM);
    let direct = if packet.contains(&0) {
        None
    } else {
        std::str::from_utf8(packet).ok()
    };
    let (text, base): (Cow<'_, str>, Option<usize>) = match direct {
        Some(s) if has_bom => (Cow::Borrowed(&s[UTF8_BOM.len()..]), Some(UTF8_BOM.len())),
        Some(s) => (Cow::Borrowed(s), Some(0)),
        None => match TextDoc::decode(packet) {
            Some(doc) => (Cow::Owned(doc.text), None),
            None => (
                Cow::Owned(String::from_utf8_lossy(packet).into_owned()),
                None,
            ),
        },
    };
    let max_depth = usize::try_from(budget.limits().max_xml_depth).unwrap_or(usize::MAX);
    let max_attributes = usize::try_from(budget.limits().max_xml_attributes).unwrap_or(usize::MAX);
    let mut ticks = 0usize;
    let mut tick = || {
        ticks += 1;
        ticks.is_multiple_of(DEADLINE_STRIDE) && budget.deadline_exceeded()
    };
    if budget.deadline_exceeded() {
        return;
    }
    let mut scan = Scan {
        text: &text,
        base,
        emit,
        stopped: false,
    };
    let mut pending = String::new();
    let mut pending_range: Option<(usize, usize)> = None;
    let mut depth = 0usize;
    let mut reader = Reader::from_str(&text);
    loop {
        if tick() {
            break;
        }
        let start = usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
        let Ok(event) = reader.read_event() else {
            break;
        };
        let end = usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
        let mut timed_out = false;
        match &event {
            Event::Text(t) => pending.push_str(&t.xml10_content()),
            Event::CData(c) => pending.push_str(&c.xml10_content()),
            Event::GeneralRef(r) => match decode_references(&format!("&{};", &**r), &mut tick) {
                Some(piece) => pending.push_str(&piece),
                None => timed_out = true,
            },
            _ => {
                scan.push(&pending, pending_range);
                pending.clear();
                pending_range = None;
            }
        }
        if matches!(
            event,
            Event::Text(_) | Event::CData(_) | Event::GeneralRef(_)
        ) {
            pending_range = Some(match pending_range {
                Some((first, _)) => (first, end),
                None => (start, end),
            });
        }
        if timed_out || scan.stopped {
            return;
        }
        match event {
            Event::Start(e) => {
                depth += 1;
                if depth > max_depth
                    || !scan.attributes(&e, (start, end), max_attributes, &mut tick)
                {
                    break;
                }
            }
            Event::Empty(e) => {
                if depth + 1 > max_depth
                    || !scan.attributes(&e, (start, end), max_attributes, &mut tick)
                {
                    break;
                }
            }
            Event::End(_) => depth = depth.saturating_sub(1),
            Event::Eof => break,
            _ => {}
        }
    }
    if !scan.stopped {
        scan.push(&pending, pending_range);
    }
}

pub fn xmp_text(packet: &[u8], budget: &mut Budget) -> Vec<String> {
    text(packet, budget)
}

pub(crate) fn text(packet: &[u8], budget: &Budget) -> Vec<String> {
    let mut out = Vec::new();
    scan(packet, budget, &mut |item, _| {
        out.push(item.to_string());
        true
    });
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

    fn collect(packet: &[u8]) -> Vec<(String, Option<(usize, usize)>)> {
        let mut items = Vec::new();
        scan(packet, &Budget::new(&Limits::default()), &mut |t, r| {
            items.push((t.to_string(), r));
            true
        });
        items
    }

    #[test]
    fn items_report_the_byte_range_of_their_own_value() {
        let items = collect(b"<a x=\"1\" y=\"2\">t</a>");
        assert_eq!(
            items,
            vec![
                ("1".to_string(), Some((6, 7))),
                ("2".to_string(), Some((12, 13))),
                ("t".to_string(), Some((15, 16))),
            ]
        );
    }

    #[test]
    fn utf8_bom_shifts_ranges_and_utf16_has_no_range() {
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(b"<a>hi</a>");
        assert_eq!(collect(&bom), vec![("hi".to_string(), Some((6, 8)))]);
        let mut wide = vec![0xFF, 0xFE];
        for unit in "<a>hi</a>".encode_utf16() {
            wide.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(collect(&wide), vec![("hi".to_string(), None)]);
    }

    #[test]
    fn scan_stops_when_the_callback_refuses() {
        let mut seen = 0;
        scan(
            b"<a>one</a><b>two</b>",
            &Budget::new(&Limits::default()),
            &mut |_, _| {
                seen += 1;
                false
            },
        );
        assert_eq!(seen, 1);
    }

    #[test]
    fn reference_decoding_is_one_pass_with_one_tick_per_ampersand() {
        let input = "&".repeat(200_000);
        let mut ticks = 0usize;
        let out = decode_references(&input, &mut || {
            ticks += 1;
            false
        });
        assert_eq!(out.as_deref(), Some(input.as_str()));
        assert_eq!(ticks, 200_000);
    }

    #[test]
    fn reference_decoding_stops_when_the_tick_reports_a_timeout() {
        assert_eq!(decode_references("&amp;&amp;", &mut || true), None);
    }

    #[test]
    fn reference_terminator_must_be_within_thirty_two_bytes() {
        let far = format!("&{};", "a".repeat(40));
        assert_eq!(
            decode_references(&far, &mut || false).as_deref(),
            Some(far.as_str())
        );
        assert_eq!(
            decode_references("&#x41;&amp;", &mut || false).as_deref(),
            Some("A&")
        );
    }
}

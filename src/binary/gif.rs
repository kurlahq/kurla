use super::{Sink, latin1, lossy, sub};
use crate::limits::Budget;
use crate::model::DetectorOutput;

const HEADER_LEN: usize = 13;
const APPLICATION_ID_LEN: usize = 11;
const XMP_ID: &[u8] = b"XMP DataXMP";
const TRAILER_LEN: usize = 258;
const TRUNCATED: &str = "malformed GIF: truncated block";
const UNKNOWN_BLOCK: &str = "malformed GIF: unknown block";
const TRAILER_LABEL: &str = "GIF data after trailer";

enum Stop {
    Truncated,
    Timeout,
}

type Parts<'a> = Vec<(usize, &'a [u8])>;

fn trailer() -> Vec<u8> {
    let mut t = Vec::with_capacity(TRAILER_LEN);
    t.push(0x01);
    t.extend((1..=0xFFu8).rev());
    t.extend_from_slice(&[0x00, 0x00]);
    t
}

fn sub_blocks<'b>(
    bytes: &'b [u8],
    mut at: usize,
    budget: &Budget,
    mut visit: impl FnMut(usize, &'b [u8]),
) -> Result<usize, Stop> {
    loop {
        if budget.deadline_exceeded() {
            return Err(Stop::Timeout);
        }
        let Some(&len) = bytes.get(at) else {
            return Err(Stop::Truncated);
        };
        at += 1;
        if len == 0 {
            return Ok(at);
        }
        let Some(data) = sub(bytes, at, usize::from(len)) else {
            visit(at, &bytes[at..]);
            return Err(Stop::Truncated);
        };
        visit(at, data);
        at += data.len();
    }
}

fn color_table_len(packed: u8) -> usize {
    if packed & 0x80 == 0 {
        0
    } else {
        3usize << (usize::from(packed & 7) + 1)
    }
}

fn joined(parts: &[(usize, &[u8])]) -> Vec<u8> {
    parts
        .iter()
        .flat_map(|(_, data)| data.iter().copied())
        .collect()
}

fn extent(parts: &[(usize, &[u8])]) -> Option<(usize, usize)> {
    let &(first, _) = parts.first()?;
    let &(last, data) = parts.last()?;
    Some((first, last + data.len()))
}

struct Gif<'a> {
    bytes: &'a [u8],
    sink: Sink,
    budget: &'a mut Budget,
}

impl<'a> Gif<'a> {
    fn finish(&mut self, stop: &Stop, from: usize) {
        match stop {
            Stop::Timeout => self.sink.timed_out(),
            Stop::Truncated => self.sink.malformed(TRUNCATED, from, self.bytes.len()),
        }
    }

    fn parts(&mut self, at: usize, from: usize) -> (Parts<'a>, Option<usize>) {
        let mut parts = Vec::new();
        let result = sub_blocks(self.bytes, at, self.budget, |start, data| {
            parts.push((start, data));
        });
        match result {
            Ok(next) => (parts, Some(next)),
            Err(stop) => {
                self.finish(&stop, from);
                (parts, None)
            }
        }
    }

    fn comment(&mut self, from: usize) -> Option<usize> {
        let (parts, next) = self.parts(from + 2, from);
        if let Some((start, end)) = extent(&parts) {
            let text = joined(&parts);
            self.sink
                .carrier("GIF Comment", &lossy(&text), start, end, &text);
        }
        next
    }

    fn plain_text(&mut self, from: usize) -> Option<usize> {
        let (parts, next) = self.parts(from + 2, from);
        let shown = parts.get(1..).unwrap_or_default();
        if let Some((start, end)) = extent(shown) {
            let text = joined(shown);
            self.sink
                .hidden_carrier("GIF plain text", &lossy(&text), start, end, &text);
        }
        next
    }

    fn application(&mut self, from: usize) -> Option<usize> {
        let at = from + 2;
        let is_xmp = self.bytes.get(at) == Some(&(APPLICATION_ID_LEN as u8))
            && sub(self.bytes, at + 1, APPLICATION_ID_LEN) == Some(XMP_ID);
        if is_xmp {
            return self.xmp(at + 1 + APPLICATION_ID_LEN, from);
        }
        let (parts, next) = self.parts(at, from);
        if let (Some(&(_, id)), Some((start, end))) = (parts.first(), extent(&parts)) {
            let data = joined(parts.get(1..).unwrap_or_default());
            let text = if data.is_empty() {
                latin1(id)
            } else {
                format!("{} {}", latin1(id), lossy(&data))
            };
            self.sink
                .carrier("GIF application", &text, start, end, &joined(&parts));
        }
        next
    }

    fn xmp(&mut self, data_at: usize, from: usize) -> Option<usize> {
        match sub_blocks(self.bytes, data_at, self.budget, |_, _| {}) {
            Ok(next) => {
                let trailer_at = next.checked_sub(TRAILER_LEN).filter(|&t| t >= data_at);
                let end = match trailer_at {
                    Some(t) if self.bytes[t..next] == trailer()[..] => t,
                    _ => next - 1,
                };
                self.sink.xmp(
                    "GIF XMP",
                    &self.bytes[data_at..end],
                    data_at,
                    end,
                    true,
                    self.budget,
                );
                Some(next)
            }
            Err(Stop::Truncated) => {
                let end = self.bytes.len();
                self.sink.xmp(
                    "GIF XMP",
                    &self.bytes[data_at..end],
                    data_at,
                    end,
                    true,
                    self.budget,
                );
                self.finish(&Stop::Truncated, from);
                None
            }
            Err(stop) => {
                self.finish(&stop, from);
                None
            }
        }
    }

    fn skip(&mut self, at: usize, from: usize) -> Option<usize> {
        match sub_blocks(self.bytes, at, self.budget, |_, _| {}) {
            Ok(next) => Some(next),
            Err(stop) => {
                self.finish(&stop, from);
                None
            }
        }
    }

    fn image(&mut self, at: usize) -> Option<usize> {
        let data = self.bytes.get(at + 9).and_then(|&packed| {
            at.checked_add(10)?
                .checked_add(color_table_len(packed))?
                .checked_add(1)
        });
        let Some(data) = data else {
            self.finish(&Stop::Truncated, at);
            return None;
        };
        self.skip(data, at)
    }

    fn walk(&mut self, mut at: usize) {
        loop {
            if self.sink.stop {
                return;
            }
            if self.budget.deadline_exceeded() {
                self.sink.timed_out();
                return;
            }
            let Some(&introducer) = self.bytes.get(at) else {
                return;
            };
            let next = match introducer {
                0x21 => match self.bytes.get(at + 1) {
                    Some(0xFE) => self.comment(at),
                    Some(0x01) => self.plain_text(at),
                    Some(0xFF) => self.application(at),
                    Some(_) => self.skip(at + 2, at),
                    None => {
                        self.finish(&Stop::Truncated, at);
                        None
                    }
                },
                0x2C => self.image(at),
                0x3B => {
                    self.sink.trailer(TRAILER_LABEL, self.bytes, at + 1, false);
                    None
                }
                _ => {
                    self.sink.malformed(UNKNOWN_BLOCK, at, self.bytes.len());
                    None
                }
            };
            match next {
                Some(next) => at = next,
                None => return,
            }
        }
    }
}

pub fn scan_gif(bytes: &[u8], budget: &mut Budget) -> DetectorOutput {
    let mut gif = Gif {
        bytes,
        sink: Sink::new(bytes.len()),
        budget,
    };
    if !(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return gif.sink.out;
    }
    let body = bytes
        .get(10)
        .map(|&packed| HEADER_LEN + color_table_len(packed))
        .filter(|&body| body <= bytes.len());
    match body {
        Some(body) => gif.walk(body),
        None => gif.finish(&Stop::Truncated, 0),
    }
    gif.sink.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::model::{CarrierKind, SkipReason};
    use std::time::Duration;

    fn head() -> Vec<u8> {
        let mut v = b"GIF89a".to_vec();
        v.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 255, 255, 255]);
        v
    }

    fn comment(blocks: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![0x21, 0xFE];
        for b in blocks {
            v.push(b.len() as u8);
            v.extend_from_slice(b);
        }
        v.push(0);
        v
    }

    fn trailer() -> Vec<u8> {
        let mut t = vec![0x01];
        t.extend((1..=255u8).rev());
        t.extend_from_slice(&[0, 0]);
        t
    }

    fn xmp_ext(packet: &[u8]) -> Vec<u8> {
        let mut v = vec![0x21, 0xFF, 0x0B];
        v.extend_from_slice(b"XMP DataXMP");
        v.extend_from_slice(packet);
        v.extend_from_slice(&trailer());
        v
    }

    fn budget() -> Budget {
        Budget::new(&Limits::default())
    }

    fn texts(out: &DetectorOutput) -> Vec<&str> {
        out.carriers.iter().map(|c| c.text.as_str()).collect()
    }

    #[test]
    fn gif_comment_extension_extracted() {
        let mut bytes = head();
        bytes.extend_from_slice(&comment(&[b"hello"]));
        bytes.push(0x3B);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["GIF Comment: hello"]);
        let c = &out.carriers[0];
        assert_eq!(c.kind, CarrierKind::MetadataField);
        assert!(!c.hidden);
        assert_eq!(
            (
                c.span.byte_start,
                c.span.byte_end,
                c.span.line,
                c.span.column
            ),
            (22, 27, None, None)
        );
        assert_eq!(c.evidence, b"hello".to_vec());
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn comment_sub_blocks_are_concatenated() {
        let mut bytes = head();
        bytes.extend_from_slice(&comment(&[b"he", b"llo"]));
        bytes.push(0x3B);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["GIF Comment: hello"]);
        assert_eq!(
            (
                out.carriers[0].span.byte_start,
                out.carriers[0].span.byte_end
            ),
            (22, 28)
        );
    }

    #[test]
    fn gif_image_data_is_skipped_by_sub_blocks() {
        let mut bytes = head();
        bytes.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0x00]);
        bytes.extend_from_slice(&[0x02, 0x04, 0x21, 0xFE, 0x01, 0x41, 0x00]);
        bytes.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0x80]);
        bytes.extend_from_slice(&[0x21, 0xFE, 0x01, 0x42, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x02, 0x04, 0x21, 0xFE, 0x01, 0x43, 0x00]);
        bytes.extend_from_slice(&comment(&[b"real"]));
        bytes.push(0x3B);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["GIF Comment: real"]);
    }

    #[test]
    fn graphic_control_is_skipped_and_other_application_extensions_are_carriers() {
        let mut bytes = head();
        bytes.extend_from_slice(&[0x21, 0xF9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x21, 0xFF, 0x0B]);
        bytes.extend_from_slice(b"NETSCAPE2.0");
        bytes.extend_from_slice(&[0x03, 0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x21, 0xFF, 0x0B]);
        bytes.extend_from_slice(b"NOTEPAD 1.0");
        bytes.extend_from_slice(&[0x04, b'n', b'o', b't', b'e', 0x00]);
        bytes.extend_from_slice(&[0x21, 0xFF, 0x0B]);
        bytes.extend_from_slice(b"EMPTYDATA10");
        bytes.push(0x00);
        bytes.extend_from_slice(&comment(&[b"found"]));
        bytes.push(0x3B);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "GIF application: NETSCAPE2.0 \u{1}\0\0",
                "GIF application: NOTEPAD 1.0 note",
                "GIF application: EMPTYDATA10",
                "GIF Comment: found"
            ]
        );
        assert_eq!(
            (
                out.carriers[1].span.byte_start,
                out.carriers[1].span.byte_end
            ),
            (49, 65)
        );
        assert!(out.findings.is_empty());
    }

    #[test]
    fn plain_text_extension_text_is_a_hidden_carrier() {
        let mut bytes = head();
        bytes.extend_from_slice(&[0x21, 0x01, 0x0C]);
        bytes.extend_from_slice(&[0; 12]);
        bytes.extend_from_slice(&[0x03, b'h', b'e', b'l', 0x02, b'l', b'o', 0x00]);
        bytes.push(0x3B);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["GIF plain text: hello"]);
        let c = &out.carriers[0];
        assert!(c.hidden);
        assert_eq!(c.kind, CarrierKind::HiddenText);
        assert_eq!((c.span.byte_start, c.span.byte_end), (35, 41));
        assert!(out.findings.is_empty());
    }

    #[test]
    fn readable_plain_text_is_b005() {
        let mut bytes = head();
        bytes.extend_from_slice(&[0x21, 0x01, 0x0C]);
        bytes.extend_from_slice(&[0; 12]);
        bytes.push(26);
        bytes.extend_from_slice(b"meet me at the usual place");
        bytes.extend_from_slice(&[0x00, 0x3B]);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(
            findings(&out),
            vec![("B005", "readable text hidden in the image", 35, 61)]
        );
    }

    #[test]
    fn xmp_application_extension_stops_at_the_magic_trailer() {
        let xml = "<a><b>gif hidden</b></a>";
        let mut bytes = head();
        bytes.extend_from_slice(&xmp_ext(xml.as_bytes()));
        bytes.extend_from_slice(&comment(&[b"tail"]));
        bytes.push(0x3B);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec!["GIF XMP: gif hidden", "GIF Comment: tail"]
        );
        assert_eq!(
            (
                out.carriers[0].span.byte_start,
                out.carriers[0].span.byte_end
            ),
            (39, 49)
        );
        assert_eq!(out.carriers[0].evidence, b"gif hidden".to_vec());
    }

    #[test]
    fn partial_trailer_inside_the_packet_does_not_end_it_early() {
        let mut packet = b"<a>k</a>".to_vec();
        packet.extend_from_slice(&trailer()[..100]);
        packet.extend_from_slice(b"<b>z</b>");
        let mut bytes = head();
        bytes.extend_from_slice(&xmp_ext(&packet));
        bytes.push(0x3B);
        let out = scan_gif(&bytes, &mut budget());
        let all = texts(&out);
        assert_eq!(all.first(), Some(&"GIF XMP: k"));
        assert_eq!(all.last(), Some(&"GIF XMP: z"));
        assert!(
            out.carriers
                .iter()
                .all(|c| c.span.byte_end == 33 + packet.len() as u64)
        );
    }

    #[test]
    fn xmp_extension_without_trailer_ends_with_its_sub_block_chain() {
        let mut bytes = head();
        bytes.extend_from_slice(&[0x21, 0xFF, 0x0B]);
        bytes.extend_from_slice(b"XMP DataXMP");
        bytes.extend_from_slice(&[0x03, b'a', b'b', b'c', 0x00]);
        bytes.extend_from_slice(&comment(&[b"tail"]));
        bytes.push(0x3B);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(texts(&out).last(), Some(&"GIF Comment: tail"));
    }

    fn findings(out: &DetectorOutput) -> Vec<(&str, &str, u64, u64)> {
        out.findings
            .iter()
            .map(|f| {
                (
                    f.rule_id,
                    f.message.as_str(),
                    f.span.byte_start,
                    f.span.byte_end,
                )
            })
            .collect()
    }

    #[test]
    fn the_trailer_byte_ends_the_parse_and_what_follows_is_b004() {
        let mut bytes = head();
        bytes.extend_from_slice(&comment(&[b"one"]));
        bytes.push(0x3B);
        bytes.extend_from_slice(&comment(&[b"two"]));
        let out = scan_gif(&bytes, &mut budget());
        let visible: Vec<&str> = out
            .carriers
            .iter()
            .filter(|c| !c.hidden)
            .map(|c| c.text.as_str())
            .collect();
        assert_eq!(visible, vec!["GIF Comment: one"]);
        assert_eq!(
            findings(&out),
            vec![("B004", "data after the end of the image", 27, 34)]
        );
    }

    #[test]
    fn data_after_the_trailer_byte_follows_the_trailer_rule() {
        let with = |tail: &[u8]| {
            let mut bytes = head();
            bytes.push(0x3B);
            bytes.extend_from_slice(tail);
            scan_gif(&bytes, &mut budget())
        };
        let out = with(b"note for the reader");
        assert_eq!(
            texts(&out),
            vec!["GIF data after trailer: note for the reader"]
        );
        assert!(out.carriers[0].hidden);
        assert_eq!(
            findings(&out),
            vec![("B004", "data after the end of the image", 20, 39)]
        );
        let out = with(b"PK\x03\x04rest of a zip");
        assert_eq!(findings(&out)[0].0, "B004");
        assert_eq!(out.embedded[0].format, Some("zip"));
        let out = with(b"\0\0 \n");
        assert!(out.carriers.is_empty() && out.findings.is_empty());
    }

    #[test]
    fn an_unknown_block_introducer_stops_the_parse_and_marks_the_gif_malformed() {
        let mut bytes = head();
        bytes.extend_from_slice(&comment(&[b"one"]));
        bytes.push(0x99);
        bytes.extend_from_slice(&comment(&[b"two"]));
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["GIF Comment: one"]);
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed GIF: unknown block", 26, 34)]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
    }

    #[test]
    fn a_truncated_comment_keeps_its_partial_text_and_marks_the_gif_malformed() {
        let mut bytes = head();
        bytes.extend_from_slice(&comment(&[b"one"]));
        bytes.extend_from_slice(&[0x21, 0xFE, 0x02, b'a', b'b', 0x09, b't', b'w']);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["GIF Comment: one", "GIF Comment: abtw"]);
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed GIF: truncated block", 26, 34)]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
    }

    #[test]
    fn truncated_blocks_mark_the_gif_malformed() {
        let mut image = head();
        image.extend_from_slice(&[0x2C, 0, 0, 0, 0]);
        let mut table = head();
        table.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0x80, 0, 0]);
        let mut data = head();
        data.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0x00, 0x02, 0x04, 0x01]);
        let mut label = head();
        label.push(0x21);
        let mut other = head();
        other.extend_from_slice(&[0x21, 0xF9, 0x04, 0x00]);
        for bytes in [image, table, data, label, other] {
            let out = scan_gif(&bytes, &mut budget());
            assert_eq!(
                findings(&out),
                vec![(
                    "L001",
                    "malformed GIF: truncated block",
                    19,
                    bytes.len() as u64
                )],
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn a_truncated_xmp_extension_is_kept_and_marks_the_gif_malformed() {
        let mut bytes = head();
        bytes.extend_from_slice(&[0x21, 0xFF, 0x0B]);
        bytes.extend_from_slice(b"XMP DataXMP");
        bytes.extend_from_slice(b"<a>cut");
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["GIF XMP: cut"]);
        assert_eq!(
            findings(&out),
            vec![(
                "L001",
                "malformed GIF: truncated block",
                19,
                bytes.len() as u64
            )]
        );
    }

    #[test]
    fn a_truncated_header_marks_the_gif_malformed_and_wrong_magic_gives_nothing() {
        for bytes in [
            &b"GIF89a"[..],
            &b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00"[..],
        ] {
            let out = scan_gif(bytes, &mut budget());
            assert!(out.carriers.is_empty());
            assert_eq!(
                findings(&out),
                vec![(
                    "L001",
                    "malformed GIF: truncated block",
                    0,
                    bytes.len() as u64
                )]
            );
        }
        assert!(scan_gif(&head(), &mut budget()).findings.is_empty());
        for bytes in [
            &b""[..],
            &b"GIF88a\x01\x00\x01\x00\x00\x00\x00"[..],
            &b"PNG89a\x01\x00\x01\x00\x00\x00\x00"[..],
        ] {
            let out = scan_gif(bytes, &mut budget());
            assert!(out.carriers.is_empty() && out.findings.is_empty());
        }
    }

    #[test]
    fn gif87a_header_is_accepted() {
        let mut bytes = head();
        bytes[4] = b'7';
        bytes.extend_from_slice(&comment(&[b"old"]));
        assert_eq!(
            texts(&scan_gif(&bytes, &mut budget())),
            vec!["GIF Comment: old"]
        );
    }

    #[test]
    fn expired_deadline_sets_timeout() {
        let limits = Limits {
            per_file_time: Duration::ZERO,
            ..Limits::default()
        };
        let mut bytes = head();
        bytes.extend_from_slice(&comment(&[b"one"]));
        let out = scan_gif(&bytes, &mut Budget::new(&limits));
        assert_eq!(out.skip, Some(SkipReason::Timeout));
        assert!(out.carriers.is_empty());
    }

    #[test]
    fn short_xmp_chain_does_not_swallow_a_later_comment() {
        let mut bytes = head();
        bytes.extend_from_slice(&[0x21, 0xFF, 0x0B]);
        bytes.extend_from_slice(b"XMP DataXMP");
        bytes.extend_from_slice(&[0x03, b'a', b'b', b'c', 0x00]);
        bytes.extend_from_slice(&comment(&[b"payload"]));
        bytes.extend_from_slice(&xmp_ext(b"<a>k</a>"));
        bytes.push(0x3B);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec!["GIF XMP: \u{3}abc", "GIF Comment: payload", "GIF XMP: k"]
        );
    }
}

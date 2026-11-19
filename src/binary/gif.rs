use super::{Sink, lossy, sub};
use crate::limits::Budget;
use crate::model::DetectorOutput;

const HEADER_LEN: usize = 13;
const APPLICATION_ID_LEN: usize = 11;
const XMP_ID: &[u8] = b"XMP DataXMP";
const TRAILER_LEN: usize = 258;
const SEARCH_STRIDE: usize = 1 << 16;

enum Stop {
    Truncated,
    Timeout,
}

enum Search {
    Found(usize),
    Absent,
    Timeout,
}

fn trailer() -> Vec<u8> {
    let mut t = Vec::with_capacity(TRAILER_LEN);
    t.push(0x01);
    t.extend((1..=0xFFu8).rev());
    t.extend_from_slice(&[0x00, 0x00]);
    t
}

fn find_trailer(hay: &[u8], budget: &Budget) -> Search {
    let pattern = trailer();
    let mut fail = vec![0usize; pattern.len()];
    let mut k = 0usize;
    for i in 1..pattern.len() {
        while k > 0 && pattern[i] != pattern[k] {
            k = fail[k - 1];
        }
        if pattern[i] == pattern[k] {
            k += 1;
        }
        fail[i] = k;
    }
    let mut matched = 0usize;
    for (i, &byte) in hay.iter().enumerate() {
        if i % SEARCH_STRIDE == 0 && budget.deadline_exceeded() {
            return Search::Timeout;
        }
        while matched > 0 && byte != pattern[matched] {
            matched = fail[matched - 1];
        }
        if byte == pattern[matched] {
            matched += 1;
        }
        if matched == pattern.len() {
            return Search::Found(i + 1 - pattern.len());
        }
    }
    Search::Absent
}

fn sub_blocks(
    bytes: &[u8],
    mut at: usize,
    budget: &Budget,
    mut visit: impl FnMut(usize, &[u8]),
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

struct Gif<'a> {
    bytes: &'a [u8],
    sink: Sink,
    budget: &'a mut Budget,
}

impl Gif<'_> {
    fn finish(&mut self, stop: &Stop) {
        if matches!(stop, Stop::Timeout) {
            self.sink.timed_out();
        }
    }

    fn comment(&mut self, at: usize) -> Option<usize> {
        let mut text = Vec::new();
        let mut first = None;
        let mut last = 0usize;
        let result = sub_blocks(self.bytes, at, self.budget, |start, data| {
            first.get_or_insert(start);
            last = start + data.len();
            text.extend_from_slice(data);
        });
        match result {
            Ok(next) => {
                if let Some(start) = first {
                    self.sink
                        .carrier("GIF Comment", &lossy(&text), start, last, &text);
                }
                Some(next)
            }
            Err(stop) => {
                self.finish(&stop);
                None
            }
        }
    }

    fn application(&mut self, at: usize) -> Option<usize> {
        let is_xmp = self.bytes.get(at) == Some(&(APPLICATION_ID_LEN as u8))
            && sub(self.bytes, at + 1, APPLICATION_ID_LEN) == Some(XMP_ID);
        if !is_xmp {
            return self.skip(at);
        }
        let from = at + 1 + APPLICATION_ID_LEN;
        let rest = self.bytes.get(from..)?;
        match find_trailer(rest, self.budget) {
            Search::Found(offset) => {
                let end = from + offset;
                self.sink
                    .xmp("GIF XMP", &self.bytes[from..end], from, end, self.budget);
                Some(end + TRAILER_LEN)
            }
            Search::Timeout => {
                self.sink.timed_out();
                None
            }
            Search::Absent => match sub_blocks(self.bytes, from, self.budget, |_, _| {}) {
                Ok(next) => {
                    let end = next - 1;
                    self.sink
                        .xmp("GIF XMP", &self.bytes[from..end], from, end, self.budget);
                    Some(next)
                }
                Err(stop) => {
                    self.finish(&stop);
                    None
                }
            },
        }
    }

    fn skip(&mut self, at: usize) -> Option<usize> {
        match sub_blocks(self.bytes, at, self.budget, |_, _| {}) {
            Ok(next) => Some(next),
            Err(stop) => {
                self.finish(&stop);
                None
            }
        }
    }

    fn image(&mut self, at: usize) -> Option<usize> {
        let packed = *self.bytes.get(at.checked_add(9)?)?;
        let data = at
            .checked_add(10)?
            .checked_add(color_table_len(packed))?
            .checked_add(1)?;
        if data > self.bytes.len() {
            return None;
        }
        self.skip(data)
    }

    fn walk(&mut self, mut at: usize) {
        loop {
            if self.budget.deadline_exceeded() {
                self.sink.timed_out();
                return;
            }
            let Some(&introducer) = self.bytes.get(at) else {
                return;
            };
            let next = match introducer {
                0x21 => {
                    let Some(&label) = self.bytes.get(at + 1) else {
                        return;
                    };
                    match label {
                        0xFE => self.comment(at + 2),
                        0xFF => self.application(at + 2),
                        _ => self.skip(at + 2),
                    }
                }
                0x2C => self.image(at),
                _ => None,
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
        sink: Sink::new(),
        budget,
    };
    if !(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return gif.sink.out;
    }
    let Some(&packed) = bytes.get(10) else {
        return gif.sink.out;
    };
    let body = HEADER_LEN + color_table_len(packed);
    if body <= bytes.len() {
        gif.walk(body);
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
    fn graphic_control_and_other_application_extensions_are_skipped() {
        let mut bytes = head();
        bytes.extend_from_slice(&[0x21, 0xF9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x21, 0xFF, 0x0B]);
        bytes.extend_from_slice(b"NETSCAPE2.0");
        bytes.extend_from_slice(&[0x03, 0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&comment(&[b"found"]));
        bytes.push(0x3B);
        assert_eq!(
            texts(&scan_gif(&bytes, &mut budget())),
            vec!["GIF Comment: found"]
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
            (33, 33 + xml.len() as u64)
        );
        assert_eq!(out.carriers[0].evidence, xml.as_bytes().to_vec());
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

    #[test]
    fn parse_stops_at_the_trailer_byte() {
        let mut bytes = head();
        bytes.extend_from_slice(&comment(&[b"one"]));
        bytes.push(0x3B);
        bytes.extend_from_slice(&comment(&[b"two"]));
        assert_eq!(
            texts(&scan_gif(&bytes, &mut budget())),
            vec!["GIF Comment: one"]
        );
    }

    #[test]
    fn unknown_block_introducer_stops_the_parse() {
        let mut bytes = head();
        bytes.extend_from_slice(&comment(&[b"one"]));
        bytes.push(0x99);
        bytes.extend_from_slice(&comment(&[b"two"]));
        assert_eq!(
            texts(&scan_gif(&bytes, &mut budget())),
            vec!["GIF Comment: one"]
        );
    }

    #[test]
    fn truncated_gif_keeps_earlier_carriers() {
        let mut bytes = head();
        bytes.extend_from_slice(&comment(&[b"one"]));
        bytes.extend_from_slice(&[0x21, 0xFE, 0x09, b't', b'w']);
        let out = scan_gif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["GIF Comment: one"]);
        assert_eq!(out.skip, None);
    }

    #[test]
    fn truncated_header_or_wrong_magic_gives_nothing() {
        for bytes in [
            &b""[..],
            &b"GIF89a"[..],
            &b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00"[..],
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
}

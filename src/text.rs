#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextDoc {
    pub text: String,
    pub encoding: Encoding,
    pub invalid_utf8: bool,
    pub bom_len: usize,
    offsets: Vec<u64>,
    line_starts: Vec<usize>,
}

const SNIFF_LEN: usize = 8192;
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
const UTF32_LE_BOM: [u8; 4] = [0xFF, 0xFE, 0x00, 0x00];
const UTF32_BE_BOM: [u8; 4] = [0x00, 0x00, 0xFE, 0xFF];
const UTF16_LE_BOM: [u8; 2] = [0xFF, 0xFE];
const UTF16_BE_BOM: [u8; 2] = [0xFE, 0xFF];

fn is_printable(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7E | b'\t' | b'\n' | b'\r' | 0x0C)
}

fn mostly_printable(bytes: impl Iterator<Item = u8>) -> bool {
    let (printable, total) = bytes.fold((0usize, 0usize), |(p, t), b| {
        (p + usize::from(is_printable(b)), t + 1)
    });
    printable * 10 >= total * 9
}

fn parity(sample: &[u8], start: usize) -> impl Iterator<Item = u8> + '_ {
    sample.iter().skip(start).step_by(2).copied()
}

fn nul_heavy(sample: &[u8], start: usize) -> bool {
    let total = parity(sample, start).count();
    let nuls = parity(sample, start).filter(|&b| b == 0).count();
    total > 0 && nuls * 10 >= total * 4
}

fn detect_utf16_without_bom(sample: &[u8]) -> Option<Encoding> {
    if nul_heavy(sample, 1) && mostly_printable(parity(sample, 0)) {
        Some(Encoding::Utf16Le)
    } else if nul_heavy(sample, 0) && mostly_printable(parity(sample, 1)) {
        Some(Encoding::Utf16Be)
    } else {
        None
    }
}

fn lossy_utf8_is_text(sample: &[u8]) -> bool {
    !sample.contains(&0) && mostly_printable(sample.iter().copied())
}

fn decode_utf8(body: &[u8], base: usize) -> (String, Vec<u64>, bool) {
    let mut text = String::with_capacity(body.len());
    let mut offsets = Vec::with_capacity(body.len() + 1);
    let mut pos = base as u64;
    let mut invalid = false;
    for chunk in body.utf8_chunks() {
        for c in chunk.valid().chars() {
            offsets.push(pos);
            text.push(c);
            pos += c.len_utf8() as u64;
        }
        if !chunk.invalid().is_empty() {
            offsets.push(pos);
            text.push(char::REPLACEMENT_CHARACTER);
            pos += chunk.invalid().len() as u64;
            invalid = true;
        }
    }
    offsets.push(pos);
    (text, offsets, invalid)
}

fn decode_utf16(body: &[u8], base: usize, big_endian: bool) -> (String, Vec<u64>, bool) {
    let unit = |i: usize| {
        let pair = [body[i], body[i + 1]];
        if big_endian {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        }
    };
    let mut text = String::with_capacity(body.len() / 2);
    let mut offsets = Vec::with_capacity(body.len() / 2 + 1);
    let mut invalid = false;
    let mut i = 0usize;
    while i + 1 < body.len() {
        let u = unit(i);
        offsets.push((base + i) as u64);
        let low_follows = i + 3 < body.len() && (0xDC00..0xE000).contains(&unit(i + 2));
        if (0xD800..0xDC00).contains(&u) && low_follows {
            let cp = 0x10000 + ((u32::from(u) - 0xD800) << 10) + (u32::from(unit(i + 2)) - 0xDC00);
            text.push(char::from_u32(cp).unwrap_or(char::REPLACEMENT_CHARACTER));
            i += 4;
        } else if let Some(c) = char::from_u32(u32::from(u)) {
            text.push(c);
            i += 2;
        } else {
            text.push(char::REPLACEMENT_CHARACTER);
            invalid = true;
            i += 2;
        }
    }
    if i < body.len() {
        offsets.push((base + i) as u64);
        text.push(char::REPLACEMENT_CHARACTER);
        invalid = true;
        i += 1;
    }
    offsets.push((base + i) as u64);
    (text, offsets, invalid)
}

fn utf32_scalar(group: [u8; 4], big_endian: bool) -> Option<char> {
    let value = if big_endian {
        u32::from_be_bytes(group)
    } else {
        u32::from_le_bytes(group)
    };
    char::from_u32(value)
}

fn sniffable_utf32_scalar(c: char) -> bool {
    !(c == '\0' || c.is_ascii_control() && !matches!(c, '\t' | '\n' | '\r' | '\x0C'))
}

fn utf32_sniff_matches(sample: &[u8], big_endian: bool) -> bool {
    let usable = sample.len() / 4 * 4;
    let groups = usable / 4;
    let ok = sample[..usable]
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|&&g| utf32_scalar(g, big_endian).is_some_and(sniffable_utf32_scalar))
        .count();
    groups > 0 && ok * 10 >= groups * 9
}

fn detect_utf32_without_bom(sample: &[u8]) -> Option<Encoding> {
    if utf32_sniff_matches(sample, false) {
        Some(Encoding::Utf32Le)
    } else if utf32_sniff_matches(sample, true) {
        Some(Encoding::Utf32Be)
    } else {
        None
    }
}

fn decode_utf32(body: &[u8], base: usize, big_endian: bool) -> (String, Vec<u64>, bool) {
    let mut text = String::with_capacity(body.len() / 4);
    let mut offsets = Vec::with_capacity(body.len() / 4 + 1);
    let mut invalid = false;
    let (groups, remainder) = body.as_chunks::<4>();
    let mut pos = base;
    for &group in groups {
        offsets.push(pos as u64);
        match utf32_scalar(group, big_endian) {
            Some(c) => text.push(c),
            None => {
                text.push(char::REPLACEMENT_CHARACTER);
                invalid = true;
            }
        }
        pos += 4;
    }
    if !remainder.is_empty() {
        offsets.push(pos as u64);
        text.push(char::REPLACEMENT_CHARACTER);
        invalid = true;
        pos += remainder.len();
    }
    offsets.push(pos as u64);
    (text, offsets, invalid)
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    let mut upcoming = text.chars().skip(1);
    for (i, c) in text.chars().enumerate() {
        let next = upcoming.next();
        if c == '\n' || (c == '\r' && next != Some('\n')) {
            starts.push(i + 1);
        }
    }
    starts
}

impl TextDoc {
    pub fn decode(bytes: &[u8]) -> Option<TextDoc> {
        for (bom, encoding, big_endian) in [
            (UTF32_LE_BOM, Encoding::Utf32Le, false),
            (UTF32_BE_BOM, Encoding::Utf32Be, true),
        ] {
            if let Some(body) = bytes.strip_prefix(&bom) {
                let (text, offsets, invalid_utf8) = decode_utf32(body, bom.len(), big_endian);
                return Some(TextDoc {
                    line_starts: line_starts(&text),
                    text,
                    encoding,
                    invalid_utf8,
                    bom_len: bom.len(),
                    offsets,
                });
            }
        }
        if let Some(body) = bytes.strip_prefix(&UTF8_BOM) {
            let (text, offsets, invalid_utf8) = decode_utf8(body, UTF8_BOM.len());
            return Some(TextDoc {
                line_starts: line_starts(&text),
                text,
                encoding: Encoding::Utf8,
                invalid_utf8,
                bom_len: UTF8_BOM.len(),
                offsets,
            });
        }
        for (bom, encoding, big_endian) in [
            (UTF16_LE_BOM, Encoding::Utf16Le, false),
            (UTF16_BE_BOM, Encoding::Utf16Be, true),
        ] {
            if let Some(body) = bytes.strip_prefix(&bom) {
                let (text, offsets, invalid_utf8) = decode_utf16(body, bom.len(), big_endian);
                return Some(TextDoc {
                    line_starts: line_starts(&text),
                    text,
                    encoding,
                    invalid_utf8,
                    bom_len: bom.len(),
                    offsets,
                });
            }
        }
        let sample = &bytes[..bytes.len().min(SNIFF_LEN)];
        if let Some(encoding) = detect_utf32_without_bom(sample) {
            let (text, offsets, _) = decode_utf32(bytes, 0, encoding == Encoding::Utf32Be);
            return Some(TextDoc {
                line_starts: line_starts(&text),
                text,
                encoding,
                invalid_utf8: true,
                bom_len: 0,
                offsets,
            });
        }
        if let Some(encoding) = detect_utf16_without_bom(sample) {
            let (text, offsets, _) = decode_utf16(bytes, 0, encoding == Encoding::Utf16Be);
            return Some(TextDoc {
                line_starts: line_starts(&text),
                text,
                encoding,
                invalid_utf8: true,
                bom_len: 0,
                offsets,
            });
        }
        if std::str::from_utf8(bytes).is_ok() || lossy_utf8_is_text(sample) {
            let (text, offsets, invalid_utf8) = decode_utf8(bytes, 0);
            return Some(TextDoc {
                line_starts: line_starts(&text),
                text,
                encoding: Encoding::Utf8,
                invalid_utf8,
                bom_len: 0,
                offsets,
            });
        }
        None
    }

    pub fn from_string(text: String) -> TextDoc {
        let (text, offsets, _) = decode_utf8(text.as_bytes(), 0);
        TextDoc {
            line_starts: line_starts(&text),
            text,
            encoding: Encoding::Utf8,
            invalid_utf8: false,
            bom_len: 0,
            offsets,
        }
    }

    pub fn position(&self, char_offset: usize) -> (u32, u32) {
        let line_index = self
            .line_starts
            .partition_point(|&start| start <= char_offset)
            - 1;
        let column = char_offset - self.line_starts[line_index] + 1;
        (
            u32::try_from(line_index + 1).unwrap_or(u32::MAX),
            u32::try_from(column).unwrap_or(u32::MAX),
        )
    }

    pub fn byte_span(&self, char_start: usize, char_end: usize) -> (u64, u64) {
        (self.offsets[char_start], self.offsets[char_end])
    }

    pub fn char_index_of_byte(&self, byte: u64) -> Option<usize> {
        self.offsets.binary_search(&byte).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_bytes(s: &str, big_endian: bool) -> Vec<u8> {
        s.encode_utf16()
            .flat_map(|u| {
                if big_endian {
                    u.to_be_bytes()
                } else {
                    u.to_le_bytes()
                }
            })
            .collect()
    }

    fn pairs_le(with_nul: usize, with_ff: usize) -> Vec<u8> {
        let mut v = Vec::new();
        for _ in 0..with_nul {
            v.extend_from_slice(&[b'a', 0x00]);
        }
        for _ in 0..with_ff {
            v.extend_from_slice(&[b'a', 0xFF]);
        }
        v
    }

    #[test]
    fn crlf_counts_one_line() {
        let doc = TextDoc::decode(b"a\r\nb").unwrap();
        assert_eq!(doc.position(0), (1, 1));
        assert_eq!(doc.position(1), (1, 2));
        assert_eq!(doc.position(2), (1, 3));
        assert_eq!(doc.position(3), (2, 1));
        assert_eq!(doc.position(4), (2, 2));
    }

    #[test]
    fn lone_cr_and_lf_each_break_a_line() {
        let doc = TextDoc::decode(b"a\rb\nc\r\r\nd").unwrap();
        assert_eq!(doc.position(2), (2, 1));
        assert_eq!(doc.position(4), (3, 1));
        assert_eq!(doc.position(6), (4, 1));
        assert_eq!(doc.position(7), (4, 2));
        assert_eq!(doc.position(8), (5, 1));
        assert_eq!(doc.position(9), (5, 2));
    }

    #[test]
    fn positions_across_mixed_line_breaks_at_every_offset() {
        let doc = TextDoc::decode(b"ab\r\ncd\re\nf").unwrap();
        let expected = [
            (1, 1),
            (1, 2),
            (1, 3),
            (1, 4),
            (2, 1),
            (2, 2),
            (2, 3),
            (3, 1),
            (3, 2),
            (4, 1),
            (4, 2),
        ];
        for (offset, want) in expected.iter().enumerate() {
            assert_eq!(doc.position(offset), *want, "offset {offset}");
        }
    }

    #[test]
    fn offset_at_line_break_reports_line_it_ends() {
        let doc = TextDoc::decode(b"ab\ncd\n").unwrap();
        assert_eq!(doc.position(2), (1, 3));
        assert_eq!(doc.position(5), (2, 3));
        assert_eq!(doc.position(6), (3, 1));
    }

    #[test]
    fn column_counts_scalar_values_not_bytes() {
        let doc = TextDoc::decode("é𝄞X".as_bytes()).unwrap();
        assert_eq!(doc.position(2), (1, 3));
        assert_eq!(doc.byte_span(2, 3), (6, 7));
        assert_eq!(doc.byte_span(0, 3), (0, 7));
        assert_eq!(doc.byte_span(1, 2), (2, 6));
    }

    #[test]
    fn bom_is_excluded_from_text_but_counted_in_bytes() {
        let doc = TextDoc::decode(b"\xEF\xBB\xBFhi").unwrap();
        assert_eq!(doc.text, "hi");
        assert_eq!(doc.encoding, Encoding::Utf8);
        assert_eq!(doc.bom_len, 3);
        assert!(!doc.invalid_utf8);
        assert_eq!(doc.position(0), (1, 1));
        assert_eq!(doc.byte_span(0, 2), (3, 5));
        assert_eq!(doc.byte_span(1, 2), (4, 5));
    }

    #[test]
    fn utf8_bom_with_invalid_body_is_still_text() {
        let doc = TextDoc::decode(b"\xEF\xBB\xBF\xFF\x00\x00\x00").unwrap();
        assert_eq!(doc.text, "\u{FFFD}\0\0\0");
        assert!(doc.invalid_utf8);
        assert_eq!(doc.byte_span(0, 1), (3, 4));
    }

    #[test]
    fn empty_file_is_valid_utf8_text() {
        let doc = TextDoc::decode(b"").unwrap();
        assert_eq!(doc.text, "");
        assert_eq!(doc.encoding, Encoding::Utf8);
        assert!(!doc.invalid_utf8);
        assert_eq!(doc.bom_len, 0);
        assert_eq!(doc.position(0), (1, 1));
        assert_eq!(doc.byte_span(0, 0), (0, 0));
    }

    #[test]
    fn one_invalid_byte_still_text_flagged_invalid() {
        let doc = TextDoc::decode(b"abcdefghij\xFFklmnopqrst").unwrap();
        assert_eq!(doc.text, "abcdefghij\u{FFFD}klmnopqrst");
        assert_eq!(doc.encoding, Encoding::Utf8);
        assert!(doc.invalid_utf8);
        assert_eq!(doc.bom_len, 0);
        assert_eq!(doc.byte_span(10, 11), (10, 11));
        assert_eq!(doc.byte_span(11, 13), (11, 13));
    }

    #[test]
    fn valid_utf8_is_not_flagged() {
        let doc = TextDoc::decode("héllo".as_bytes()).unwrap();
        assert!(!doc.invalid_utf8);
    }

    #[test]
    fn lossy_replacement_maps_to_exact_invalid_run() {
        let doc = TextDoc::decode(b"aaaaaaaaaaaaaaaaaaaa\xE2\x82b").unwrap();
        assert_eq!(doc.text, "aaaaaaaaaaaaaaaaaaaa\u{FFFD}b");
        assert_eq!(doc.byte_span(20, 21), (20, 22));
        assert_eq!(doc.byte_span(21, 22), (22, 23));
        let tail = TextDoc::decode(b"aaaaaaaaaaaaaaaaaaaa\xE2\x82").unwrap();
        assert_eq!(tail.text, "aaaaaaaaaaaaaaaaaaaa\u{FFFD}");
        assert_eq!(tail.byte_span(20, 21), (20, 22));
    }

    #[test]
    fn utf16le_without_bom_detected() {
        let text = "héllo wörld again ok";
        let doc = TextDoc::decode(&utf16_bytes(text, false)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf16Le);
        assert_eq!(doc.text, text);
        assert!(doc.invalid_utf8);
        assert_eq!(doc.bom_len, 0);
        assert_eq!(doc.byte_span(1, 2), (2, 4));
        assert_eq!(doc.byte_span(0, 20), (0, 40));
    }

    #[test]
    fn utf16be_without_bom_detected() {
        let text = "héllo wörld again ok";
        let doc = TextDoc::decode(&utf16_bytes(text, true)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf16Be);
        assert_eq!(doc.text, text);
        assert!(doc.invalid_utf8);
        assert_eq!(doc.byte_span(19, 20), (38, 40));
    }

    #[test]
    fn png_signature_is_not_text() {
        let png = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52,
        ];
        assert!(TextDoc::decode(&png).is_none());
    }

    #[test]
    fn utf16be_bom_detected() {
        let mut bytes = vec![0xFE, 0xFF];
        bytes.extend(utf16_bytes("hi", true));
        let doc = TextDoc::decode(&bytes).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf16Be);
        assert_eq!(doc.text, "hi");
        assert_eq!(doc.bom_len, 2);
        assert!(!doc.invalid_utf8);
        assert_eq!(doc.byte_span(0, 2), (2, 6));
        assert_eq!(doc.byte_span(1, 2), (4, 6));
    }

    #[test]
    fn utf16le_bom_detected_and_clean() {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(utf16_bytes("hi", false));
        let doc = TextDoc::decode(&bytes).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf16Le);
        assert_eq!(doc.text, "hi");
        assert_eq!(doc.bom_len, 2);
        assert!(!doc.invalid_utf8);
    }

    #[test]
    fn byte_span_over_surrogate_pair() {
        let doc =
            TextDoc::decode(&[0xFF, 0xFE, 0x61, 0x00, 0x34, 0xD8, 0x1E, 0xDD, 0x62, 0x00]).unwrap();
        assert_eq!(doc.text, "a𝄞b");
        assert!(!doc.invalid_utf8);
        assert_eq!(doc.position(2), (1, 3));
        assert_eq!(doc.byte_span(0, 1), (2, 4));
        assert_eq!(doc.byte_span(1, 2), (4, 8));
        assert_eq!(doc.byte_span(2, 3), (8, 10));
        assert_eq!(doc.byte_span(0, 3), (2, 10));
    }

    #[test]
    fn utf16_unpaired_surrogates_become_replacement_and_flag() {
        let high = TextDoc::decode(&[0xFF, 0xFE, 0x00, 0xD8, 0x61, 0x00]).unwrap();
        assert_eq!(high.text, "\u{FFFD}a");
        assert!(high.invalid_utf8);
        assert_eq!(high.byte_span(0, 1), (2, 4));
        assert_eq!(high.byte_span(1, 2), (4, 6));
        let low = TextDoc::decode(&[0xFE, 0xFF, 0xDC, 0x00, 0x00, 0x61]).unwrap();
        assert_eq!(low.text, "\u{FFFD}a");
        assert!(low.invalid_utf8);
        assert_eq!(low.byte_span(0, 1), (2, 4));
    }

    #[test]
    fn utf16_odd_trailing_byte_becomes_replacement() {
        let doc = TextDoc::decode(&[0xFF, 0xFE, 0x61, 0x00, 0x62]).unwrap();
        assert_eq!(doc.text, "a\u{FFFD}");
        assert!(doc.invalid_utf8);
        assert_eq!(doc.byte_span(1, 2), (4, 5));
    }

    #[test]
    fn lossy_utf8_threshold_at_exactly_ninety_percent() {
        let mut nine = vec![b'a'; 9];
        nine.push(0xFF);
        assert!(TextDoc::decode(&nine).is_some());
        let mut eight = vec![b'a'; 8];
        eight.extend_from_slice(&[0xFF, 0xFF]);
        assert!(TextDoc::decode(&eight).is_none());
    }

    #[test]
    fn printable_set_is_space_to_tilde_and_four_whitespace_bytes() {
        let mut ok = vec![b'a'; 5];
        ok.extend_from_slice(&[b'\t', b'\n', b'\r', 0x0C, 0xFF]);
        assert!(TextDoc::decode(&ok).is_some());
        let mut edges = b" ~ ~ ~ ~a".to_vec();
        edges.push(0xFF);
        assert!(TextDoc::decode(&edges).is_some());
        for bad in [0x0Bu8, 0x7F, 0x1F, 0x80] {
            let mut v = vec![b'a'; 8];
            v.extend_from_slice(&[bad, 0xFF]);
            assert!(TextDoc::decode(&v).is_none(), "byte {bad:#x}");
        }
    }

    #[test]
    fn nul_byte_defeats_lossy_utf8_path() {
        let mut with_nul = vec![b'a'; 18];
        with_nul.extend_from_slice(&[0xFF, 0x00]);
        assert!(TextDoc::decode(&with_nul).is_none());
        let mut without = vec![b'a'; 19];
        without.push(0xFF);
        let doc = TextDoc::decode(&without).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf8);
        assert!(doc.invalid_utf8);
    }

    #[test]
    fn heuristics_look_only_at_first_8_kib() {
        let mut nul_outside = vec![b'a'; 8192];
        nul_outside.extend_from_slice(&[0x00, 0xFF]);
        assert!(TextDoc::decode(&nul_outside).is_some());
        let mut nul_inside = vec![b'a'; 8191];
        nul_inside.extend_from_slice(&[0x00, 0xFF]);
        assert!(TextDoc::decode(&nul_inside).is_none());
        let mut junk_outside = vec![b'a'; 8192];
        junk_outside.extend_from_slice(&[0xFF; 100]);
        assert!(TextDoc::decode(&junk_outside).is_some());
    }

    #[test]
    fn utf16_nul_threshold_at_exactly_forty_percent() {
        let at = TextDoc::decode(&pairs_le(4, 6)).unwrap();
        assert_eq!(at.encoding, Encoding::Utf16Le);
        assert!(at.invalid_utf8);
        assert_eq!(at.text.chars().count(), 10);
        assert!(TextDoc::decode(&pairs_le(3, 7)).is_none());
    }

    #[test]
    fn utf16_other_parity_printable_threshold_at_ninety_percent() {
        let build = |bad: usize| {
            let mut v = Vec::new();
            for i in 0..10 {
                v.push(if i < bad { 0xFF } else { b'a' });
                v.push(0x00);
            }
            v
        };
        let at = TextDoc::decode(&build(1)).unwrap();
        assert_eq!(at.encoding, Encoding::Utf16Le);
        assert!(TextDoc::decode(&build(2)).is_none());
    }

    #[test]
    fn utf16_be_nul_threshold_uses_even_positions() {
        let mut at = Vec::new();
        for i in 0..10 {
            at.push(if i < 4 { 0x00 } else { 0xFF });
            at.push(b'a');
        }
        let doc = TextDoc::decode(&at).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf16Be);
        let mut below = Vec::new();
        for i in 0..10 {
            below.push(if i < 3 { 0x00 } else { 0xFF });
            below.push(b'a');
        }
        assert!(TextDoc::decode(&below).is_none());
    }

    #[test]
    fn ascii_utf16le_without_bom_is_utf16_not_utf8() {
        let text = "fn main() {}";
        let doc = TextDoc::decode(&utf16_bytes(text, false)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf16Le);
        assert_eq!(doc.text, text);
        assert!(doc.invalid_utf8);
        assert_eq!(doc.byte_span(11, 12), (22, 24));
    }

    #[test]
    fn ascii_utf16be_without_bom_is_utf16_not_utf8() {
        let text = "fn main() {}";
        let doc = TextDoc::decode(&utf16_bytes(text, true)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf16Be);
        assert_eq!(doc.text, text);
        assert!(doc.invalid_utf8);
        assert_eq!(doc.byte_span(11, 12), (22, 24));
    }

    #[test]
    fn rlo_in_bomless_utf16le_survives_decoding() {
        let text = "abcdefgh\u{202E}ijkl";
        let doc = TextDoc::decode(&utf16_bytes(text, false)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf16Le);
        assert!(doc.text.contains('\u{202E}'));
        assert_eq!(doc.text, text);
        assert_eq!(doc.byte_span(8, 9), (16, 18));
    }

    #[test]
    fn utf8_with_single_nul_stays_utf8() {
        let doc = TextDoc::decode(b"hello\0world").unwrap();
        assert_eq!(doc.encoding, Encoding::Utf8);
        assert_eq!(doc.text, "hello\0world");
        assert!(!doc.invalid_utf8);
    }

    fn utf32_bytes(s: &str, big_endian: bool) -> Vec<u8> {
        s.chars()
            .flat_map(|c| {
                if big_endian {
                    u32::from(c).to_be_bytes()
                } else {
                    u32::from(c).to_le_bytes()
                }
            })
            .collect()
    }

    fn le_groups(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    #[test]
    fn utf32le_bom_decodes_rlo_and_tag_character() {
        let bytes = [
            0xFF, 0xFE, 0x00, 0x00, 0x2E, 0x20, 0x00, 0x00, 0x41, 0x00, 0x0E, 0x00,
        ];
        let doc = TextDoc::decode(&bytes).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf32Le);
        assert_eq!(doc.text, "\u{202E}\u{E0041}");
        assert!(!doc.invalid_utf8);
        assert_eq!(doc.bom_len, 4);
        assert_eq!(doc.byte_span(0, 1), (4, 8));
        assert_eq!(doc.byte_span(1, 2), (8, 12));
        assert_eq!(doc.position(2), (1, 3));
    }

    #[test]
    fn utf32be_bom_decodes_rlo_and_tag_character() {
        let bytes = [
            0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00, 0x20, 0x2E, 0x00, 0x0E, 0x00, 0x41,
        ];
        let doc = TextDoc::decode(&bytes).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf32Be);
        assert_eq!(doc.text, "\u{202E}\u{E0041}");
        assert!(!doc.invalid_utf8);
        assert_eq!(doc.bom_len, 4);
        assert_eq!(doc.byte_span(1, 2), (8, 12));
    }

    #[test]
    fn bomless_utf32le_keeps_rlo_and_flags_invalid() {
        let text = "ab\u{202E}cd";
        let doc = TextDoc::decode(&utf32_bytes(text, false)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf32Le);
        assert_eq!(doc.text, text);
        assert!(doc.text.contains('\u{202E}'));
        assert!(doc.invalid_utf8);
        assert_eq!(doc.bom_len, 0);
        assert_eq!(doc.byte_span(2, 3), (8, 12));
    }

    #[test]
    fn bomless_utf32be_keeps_rlo_and_flags_invalid() {
        let text = "ab\u{202E}cd";
        let doc = TextDoc::decode(&utf32_bytes(text, true)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf32Be);
        assert_eq!(doc.text, text);
        assert!(doc.invalid_utf8);
        assert_eq!(doc.byte_span(4, 5), (16, 20));
    }

    #[test]
    fn utf32_trailing_partial_group_becomes_replacement() {
        let mut bom = vec![0xFF, 0xFE, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00];
        bom.extend_from_slice(&[0x41, 0x00]);
        let doc = TextDoc::decode(&bom).unwrap();
        assert_eq!(doc.text, "a\u{FFFD}");
        assert!(doc.invalid_utf8);
        assert_eq!(doc.byte_span(1, 2), (8, 10));
        let mut bare = le_groups(&[0x61; 10]);
        bare.extend_from_slice(&[0x41, 0x00]);
        let doc = TextDoc::decode(&bare).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf32Le);
        assert_eq!(doc.text, format!("{}\u{FFFD}", "a".repeat(10)));
        assert!(doc.invalid_utf8);
        assert_eq!(doc.byte_span(10, 11), (40, 42));
    }

    #[test]
    fn utf32_invalid_scalar_becomes_replacement() {
        let mut bytes = vec![0xFF, 0xFE, 0x00, 0x00];
        bytes.extend(le_groups(&[0xD800, 0x61]));
        let doc = TextDoc::decode(&bytes).unwrap();
        assert_eq!(doc.text, "\u{FFFD}a");
        assert!(doc.invalid_utf8);
        assert_eq!(doc.byte_span(0, 1), (4, 8));
    }

    #[test]
    fn utf32_sniff_threshold_at_exactly_ninety_percent() {
        let mut nine = vec![0x61u32; 9];
        nine.push(0x0011_0000);
        let doc = TextDoc::decode(&le_groups(&nine)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf32Le);
        assert_eq!(doc.text.chars().filter(|&c| c == 'a').count(), 9);
        assert!(doc.text.ends_with('\u{FFFD}'));
        let mut eight = vec![0x61u32; 8];
        eight.extend_from_slice(&[0x0011_0000, 0x0011_0000]);
        let doc = TextDoc::decode(&le_groups(&eight)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf8);
    }

    #[test]
    fn utf32_sniff_accepts_four_whitespace_controls_and_rejects_other_c0() {
        let ok = le_groups(&[0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x09, 0x0A, 0x0D, 0x0C]);
        assert_eq!(TextDoc::decode(&ok).unwrap().encoding, Encoding::Utf32Le);
        let bad = le_groups(&[0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x0B, 0x1F]);
        assert_eq!(TextDoc::decode(&bad).unwrap().encoding, Encoding::Utf8);
        let nul = le_groups(&[0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x00, 0x00]);
        assert_eq!(TextDoc::decode(&nul).unwrap().encoding, Encoding::Utf8);
        let nine = le_groups(&[0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x1F]);
        assert_eq!(TextDoc::decode(&nine).unwrap().encoding, Encoding::Utf32Le);
    }

    #[test]
    fn utf32_sniff_needs_one_whole_group() {
        assert_eq!(TextDoc::decode(b"abc").unwrap().encoding, Encoding::Utf8);
    }

    #[test]
    fn ascii_utf16le_without_bom_still_utf16_and_plain_ascii_still_utf8() {
        let doc = TextDoc::decode(&utf16_bytes("ab\u{202E}cd", false)).unwrap();
        assert_eq!(doc.encoding, Encoding::Utf16Le);
        assert_eq!(doc.text, "ab\u{202E}cd");
        let plain = TextDoc::decode(b"abcdefgh").unwrap();
        assert_eq!(plain.encoding, Encoding::Utf8);
        assert!(!plain.invalid_utf8);
    }

    #[test]
    fn from_string_never_sniffs_or_strips_bom() {
        let nuls: String = "a\0".repeat(300);
        let doc = TextDoc::from_string(nuls.clone());
        assert_eq!(doc.text, nuls);
        assert_eq!(doc.encoding, Encoding::Utf8);
        assert!(!doc.invalid_utf8);
        assert_eq!(doc.bom_len, 0);
        let bom = TextDoc::from_string("\u{FEFF}a\nb".to_string());
        assert_eq!(bom.text, "\u{FEFF}a\nb");
        assert_eq!(bom.bom_len, 0);
        assert_eq!(bom.byte_span(0, 1), (0, 3));
        assert_eq!(bom.byte_span(1, 2), (3, 4));
        assert_eq!(bom.byte_span(0, 4), (0, 6));
        assert_eq!(bom.position(3), (2, 1));
    }

    #[test]
    fn char_index_of_byte_maps_only_character_boundaries() {
        let doc = TextDoc::decode("\u{e9}\nab".as_bytes()).unwrap();
        assert_eq!(doc.char_index_of_byte(0), Some(0));
        assert_eq!(doc.char_index_of_byte(1), None);
        assert_eq!(doc.char_index_of_byte(2), Some(1));
        assert_eq!(doc.char_index_of_byte(4), Some(3));
        assert_eq!(doc.char_index_of_byte(5), Some(4));
        assert_eq!(doc.char_index_of_byte(6), None);
        let bom = TextDoc::decode(b"\xEF\xBB\xBFab").unwrap();
        assert_eq!(bom.char_index_of_byte(0), None);
        assert_eq!(bom.char_index_of_byte(3), Some(0));
        assert_eq!(bom.char_index_of_byte(5), Some(2));
    }
}

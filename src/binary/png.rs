use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
use std::ops::BitOr;

use super::{Sink, latin1, lossy, sub};
use crate::limits::Budget;
use crate::model::DetectorOutput;

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const CHUNK_HEADER_LEN: usize = 8;
const CRC_LEN: usize = 4;
const CORRUPT_STREAM: &str = "malformed PNG: compressed text is not a valid zlib stream";
const UNKNOWN_METHOD: &str = "malformed PNG: unknown compression method";
const TRUNCATED_CHUNK: &str = "malformed PNG: truncated chunk";
const INCOMPLETE_HEADER: &str = "malformed PNG: chunk header is incomplete";
const TRAILER_LABEL: &str = "PNG data after IEND";
const IEND_DATA: &str = "malformed PNG: IEND chunk holds data";
const IEND_DATA_LABEL: &str = "PNG data inside IEND";

pub(crate) enum Inflated {
    Text(Vec<u8>),
    Corrupt(Vec<u8>),
    LimitHit,
}

pub(crate) fn inflate(data: &[u8], budget: &mut Budget) -> Inflated {
    inflate_stream(data, budget, inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER).0
}

pub(crate) fn inflate_stream(data: &[u8], budget: &mut Budget, format: u32) -> (Inflated, usize) {
    let allowed = usize::try_from(budget.remaining_decompressed()).unwrap_or(usize::MAX);
    let flags = format.bitor(inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    let mut decompressor = Box::<DecompressorOxide>::default();
    let mut out = vec![0; data.len().saturating_mul(2).min(allowed)];
    let mut input = data;
    let mut produced = 0;
    let mut used = 0;
    loop {
        let (status, consumed, written) =
            decompress(&mut decompressor, input, &mut out, produced, flags);
        produced += written;
        used += consumed;
        input = input.get(consumed..).unwrap_or_default();
        match status {
            TINFLStatus::HasMoreOutput if out.len() < allowed => {
                out.resize(out.len().saturating_mul(2).min(allowed), 0);
            }
            TINFLStatus::HasMoreOutput => return (Inflated::LimitHit, used),
            finished => {
                out.truncate(produced);
                let _ = budget.take_decompressed(produced as u64);
                let inflated = if finished == TINFLStatus::Done {
                    Inflated::Text(out)
                } else {
                    Inflated::Corrupt(out)
                };
                return (inflated, used);
            }
        }
    }
}

struct Chunk<'a> {
    kind: [u8; 4],
    data: &'a [u8],
    data_start: usize,
}

fn read_chunk(bytes: &[u8], at: usize) -> Option<Chunk<'_>> {
    let header = sub(bytes, at, CHUNK_HEADER_LEN)?;
    let length = usize::try_from(u32::from_be_bytes(header[..4].try_into().ok()?)).ok()?;
    let kind = <[u8; 4]>::try_from(&header[4..8]).ok()?;
    let data_start = at.checked_add(CHUNK_HEADER_LEN)?;
    let data = sub(bytes, data_start, length)?;
    Some(Chunk {
        kind,
        data,
        data_start,
    })
}

fn part_span(chunk: &Chunk<'_>, part: &[u8]) -> (usize, usize) {
    let start = chunk.data_start + (part.as_ptr().addr() - chunk.data.as_ptr().addr());
    (start, start + part.len())
}

fn split_nul(data: &[u8]) -> (&[u8], Option<&[u8]>) {
    match data.iter().position(|&b| b == 0) {
        Some(at) => (&data[..at], Some(&data[at + 1..])),
        None => (data, None),
    }
}

struct ItxtHeader<'a> {
    keyword: &'a [u8],
    flag: u8,
    method: u8,
    language: &'a [u8],
    translated: &'a [u8],
    body: &'a [u8],
}

impl<'a> ItxtHeader<'a> {
    fn parse(data: &'a [u8]) -> Option<ItxtHeader<'a>> {
        let (keyword, rest) = split_nul(data);
        let (&flag, rest) = rest?.split_first()?;
        let (&method, rest) = rest.split_first()?;
        let (language, rest) = split_nul(rest);
        let (translated, body) = split_nul(rest?);
        Some(ItxtHeader {
            keyword,
            flag,
            method,
            language,
            translated,
            body: body?,
        })
    }
}

struct Walker<'a> {
    sink: Sink,
    budget: &'a mut Budget,
    limit_hit: bool,
}

impl Walker<'_> {
    fn part_carrier(&mut self, chunk: &Chunk<'_>, label: &str, part: &[u8]) {
        let (start, end) = part_span(chunk, part);
        self.sink
            .carrier(label, &latin1(part), start, end, chunk.data);
    }

    fn name_chunk(&mut self, chunk: &Chunk<'_>, label: &str) {
        match split_nul(chunk.data) {
            (name, Some(_)) => self.part_carrier(chunk, label, name),
            (_, None) => self.incomplete_header(chunk),
        }
    }

    fn pcal_chunk(&mut self, chunk: &Chunk<'_>) {
        let (name, rest) = split_nul(chunk.data);
        let Some(rest) = rest else {
            self.incomplete_header(chunk);
            return;
        };
        self.part_carrier(chunk, "PNG pCAL name", name);
        let (Some(&count), Some(strings)) = (rest.get(9), rest.get(10..)) else {
            self.incomplete_header(chunk);
            return;
        };
        let mut pieces = strings.split(|&b| b == 0);
        if let Some(unit) = pieces.next() {
            self.part_carrier(chunk, "PNG pCAL unit", unit);
        }
        let mut parameters = 0usize;
        for parameter in pieces {
            parameters += 1;
            self.part_carrier(chunk, "PNG pCAL parameter", parameter);
        }
        if parameters != usize::from(count) {
            self.incomplete_header(chunk);
        }
    }

    fn incomplete_header(&mut self, chunk: &Chunk<'_>) {
        self.sink.malformed(
            INCOMPLETE_HEADER,
            chunk.data_start,
            chunk.data_start + chunk.data.len(),
        );
    }

    fn text_carrier(
        &mut self,
        kind: &str,
        chunk: &Chunk<'_>,
        keyword: &[u8],
        text: &str,
        (start, end): (usize, usize),
    ) {
        if text.is_empty() {
            let label = format!("PNG {kind} keyword");
            let keyword_end = chunk.data_start + keyword.len();
            self.sink.carrier(
                &label,
                &latin1(keyword),
                chunk.data_start,
                keyword_end,
                chunk.data,
            );
        } else {
            let label = format!("PNG {kind} {}", latin1(keyword));
            self.sink.carrier(&label, text, start, end, chunk.data);
        }
    }

    fn text_chunk(&mut self, chunk: &Chunk<'_>) {
        let (keyword, rest) = split_nul(chunk.data);
        let Some(text) = rest else {
            let end = chunk.data_start + chunk.data.len();
            self.sink.carrier(
                "PNG tEXt",
                &latin1(chunk.data),
                chunk.data_start,
                end,
                chunk.data,
            );
            self.incomplete_header(chunk);
            return;
        };
        let start = chunk.data_start + keyword.len() + 1;
        let span = (start, start + text.len());
        self.text_carrier("tEXt", chunk, keyword, &latin1(text), span);
    }

    fn inflated(&mut self, compressed: &[u8], start: usize) -> Option<Vec<u8>> {
        if self.limit_hit {
            return None;
        }
        match inflate(compressed, self.budget) {
            Inflated::Text(out) => {
                self.sink.add_inflated(out.len());
                Some(out)
            }
            Inflated::Corrupt(partial) => {
                self.sink.add_inflated(partial.len());
                self.sink
                    .malformed(CORRUPT_STREAM, start, start + compressed.len());
                Some(partial)
            }
            Inflated::LimitHit => {
                self.limit_hit = true;
                self.sink.limit_hit(
                    start,
                    start + compressed.len(),
                    "compressed PNG text inflates past the decompression budget",
                );
                None
            }
        }
    }

    fn ztxt_chunk(&mut self, chunk: &Chunk<'_>) {
        let (keyword, rest) = split_nul(chunk.data);
        let Some((&method, compressed)) = rest.and_then(|r| r.split_first()) else {
            self.incomplete_header(chunk);
            return;
        };
        let start = chunk.data_start + keyword.len() + 2;
        let span = (start, start + compressed.len());
        if method != 0 {
            self.text_carrier("zTXt", chunk, keyword, "", span);
            self.sink.malformed(UNKNOWN_METHOD, span.0, span.1);
            return;
        }
        if let Some(text) = self.inflated(compressed, start) {
            self.text_carrier("zTXt", chunk, keyword, &latin1(&text), span);
        }
    }

    fn itxt_chunk(&mut self, chunk: &Chunk<'_>) {
        let Some(header) = ItxtHeader::parse(chunk.data) else {
            self.incomplete_header(chunk);
            return;
        };
        let keyword = latin1(header.keyword);
        let language_start = chunk.data_start + header.keyword.len() + 3;
        let translated_start = language_start + header.language.len() + 1;
        self.sink.carrier(
            &format!("PNG iTXt {keyword} language"),
            &lossy(header.language),
            language_start,
            language_start + header.language.len(),
            chunk.data,
        );
        self.sink.carrier(
            &format!("PNG iTXt {keyword} translated keyword"),
            &lossy(header.translated),
            translated_start,
            translated_start + header.translated.len(),
            chunk.data,
        );
        let body = header.body;
        let start = chunk.data_start + (chunk.data.len() - body.len());
        let span = (start, start + body.len());
        if header.flag == 0 {
            self.text_carrier("iTXt", chunk, header.keyword, &lossy(body), span);
        } else if header.method != 0 {
            self.text_carrier("iTXt", chunk, header.keyword, "", span);
            self.sink.malformed(UNKNOWN_METHOD, span.0, span.1);
        } else if let Some(text) = self.inflated(body, start) {
            self.text_carrier("iTXt", chunk, header.keyword, &lossy(&text), span);
        }
    }

    fn walk(&mut self, bytes: &[u8]) {
        let mut at = SIGNATURE.len();
        loop {
            if self.budget.deadline_exceeded() {
                self.sink.timed_out();
                return;
            }
            let Some(chunk) = read_chunk(bytes, at) else {
                if at < bytes.len() {
                    self.sink.malformed(TRUNCATED_CHUNK, at, bytes.len());
                }
                return;
            };
            match &chunk.kind {
                b"tEXt" => self.text_chunk(&chunk),
                b"zTXt" => self.ztxt_chunk(&chunk),
                b"iTXt" => self.itxt_chunk(&chunk),
                b"iCCP" => self.name_chunk(&chunk, "PNG iCCP profile name"),
                b"sPLT" => self.name_chunk(&chunk, "PNG sPLT palette name"),
                b"pCAL" => self.pcal_chunk(&chunk),
                b"eXIf" => self.sink.exif(chunk.data, chunk.data_start, &*self.budget),
                b"IEND" => {
                    let data_end = chunk.data_start + chunk.data.len();
                    if !chunk.data.is_empty() {
                        self.sink.malformed(IEND_DATA, chunk.data_start, data_end);
                        let through_data = &bytes[..data_end];
                        self.sink
                            .trailer(IEND_DATA_LABEL, through_data, chunk.data_start, false);
                    }
                    self.sink
                        .trailer(TRAILER_LABEL, bytes, data_end + CRC_LEN, false);
                    return;
                }
                _ => {}
            }
            if self.sink.stop {
                return;
            }
            let Some(next) = chunk
                .data_start
                .checked_add(chunk.data.len())
                .and_then(|n| n.checked_add(CRC_LEN))
            else {
                return;
            };
            at = next;
        }
    }
}

pub fn scan_png(bytes: &[u8], budget: &mut Budget) -> DetectorOutput {
    let mut walker = Walker {
        sink: Sink::new(bytes.len()),
        budget,
        limit_hit: false,
    };
    if bytes.starts_with(&SIGNATURE) {
        walker.walk(bytes);
    }
    walker.sink.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::model::{CarrierKind, Family, FileKind, RuleStatus, Severity, SkipReason};
    use miniz_oxide::deflate::compress_to_vec_zlib;
    use std::time::Duration;

    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    const EXIF_HELLO: [u8; 32] = [
        b'I', b'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0E, 0x01, 0x02, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, b'h', b'e', b'l', b'l',
        b'o', 0x00,
    ];

    fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(kind);
        v.extend_from_slice(data);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    fn png(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut v = SIGNATURE.to_vec();
        for c in chunks {
            v.extend_from_slice(c);
        }
        v
    }

    fn budget() -> Budget {
        Budget::new(&Limits::default())
    }

    fn texts(out: &DetectorOutput) -> Vec<&str> {
        out.carriers.iter().map(|c| c.text.as_str()).collect()
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

    fn stored_zlib_cut_short(declared: u16, present: &[u8]) -> Vec<u8> {
        let mut z = vec![0x78, 0x01, 0x01];
        z.extend_from_slice(&declared.to_le_bytes());
        z.extend_from_slice(&(!declared).to_le_bytes());
        z.extend_from_slice(present);
        z
    }

    #[test]
    fn png_text_chunks_become_carriers() {
        let mut itxt = b"Title\0".to_vec();
        itxt.extend_from_slice(&[0, 0]);
        itxt.extend_from_slice(b"en\0\0");
        itxt.extend_from_slice("héllo".as_bytes());
        let bytes = png(&[
            chunk(b"IHDR", &[0; 13]),
            chunk(b"tEXt", b"Comment\0hello"),
            chunk(b"iTXt", &itxt),
            chunk(b"IEND", &[]),
        ]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "PNG tEXt Comment: hello",
                "PNG iTXt Title language: en",
                "PNG iTXt Title: héllo"
            ]
        );
        let first = &out.carriers[0];
        assert_eq!(first.kind, CarrierKind::MetadataField);
        assert!(!first.hidden);
        assert_eq!(
            (
                first.span.byte_start,
                first.span.byte_end,
                first.span.line,
                first.span.column
            ),
            (49, 54, None, None)
        );
        assert_eq!(first.evidence, b"Comment\0hello".to_vec());
        let second = &out.carriers[2];
        assert_eq!((second.span.byte_start, second.span.byte_end), (78, 84));
        assert_eq!(second.evidence, itxt);
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn text_chunk_keyword_and_text_are_latin_1() {
        let bytes = png(&[chunk(b"tEXt", b"Au\xE9\0\xFF")]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["PNG tEXt Aué: ÿ"]);
    }

    #[test]
    fn ztxt_is_inflated_and_charged_to_the_budget() {
        let z = compress_to_vec_zlib(b"secret", 6);
        let mut data = b"Note\0\0".to_vec();
        data.extend_from_slice(&z);
        let bytes = png(&[chunk(b"zTXt", &data)]);
        let limits = Limits {
            max_decompressed_bytes: 1000,
            ..Limits::default()
        };
        let mut b = Budget::new(&limits);
        let out = scan_png(&bytes, &mut b);
        assert_eq!(texts(&out), vec!["PNG zTXt Note: secret"]);
        assert_eq!(
            (
                out.carriers[0].span.byte_start,
                out.carriers[0].span.byte_end
            ),
            (22, 22 + z.len() as u64)
        );
        assert_eq!(b.remaining_decompressed(), 994);
    }

    #[test]
    fn compressed_itxt_is_inflated() {
        let z = compress_to_vec_zlib(b"zip text", 6);
        let mut data = b"K\0\x01\0\0\0".to_vec();
        data.extend_from_slice(&z);
        let bytes = png(&[chunk(b"iTXt", &data)]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["PNG iTXt K: zip text"]);
        assert_eq!(
            (
                out.carriers[0].span.byte_start,
                out.carriers[0].span.byte_end
            ),
            (22, 22 + z.len() as u64)
        );
    }

    #[test]
    fn exif_chunk_fields_become_carriers() {
        let bytes = png(&[chunk(b"eXIf", &EXIF_HELLO)]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["EXIF ImageDescription: hello"]);
        assert_eq!(
            (
                out.carriers[0].span.byte_start,
                out.carriers[0].span.byte_end
            ),
            (42, 48)
        );
        assert_eq!(out.carriers[0].evidence, b"hello\0".to_vec());
    }

    #[test]
    fn png_ztxt_bomb_is_b002_and_bounded() {
        let z = compress_to_vec_zlib(&vec![b'A'; 1_000_000], 6);
        assert!(z.len() < 5000);
        let mut bomb = b"Bomb\0\0".to_vec();
        bomb.extend_from_slice(&z);
        let small = compress_to_vec_zlib(b"later", 6);
        let mut later = b"Later\0\0".to_vec();
        later.extend_from_slice(&small);
        let bytes = png(&[
            chunk(b"tEXt", b"Before\0kept"),
            chunk(b"zTXt", &bomb),
            chunk(b"zTXt", &later),
            chunk(b"tEXt", b"After\0also kept"),
        ]);
        let limits = Limits {
            max_decompressed_bytes: 1000,
            ..Limits::default()
        };
        let mut b = Budget::new(&limits);
        let out = scan_png(&bytes, &mut b);
        assert_eq!(out.skip, Some(SkipReason::DecompressionLimit));
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.rule_id, "B002");
        assert_eq!(f.family, Family::B);
        assert_eq!(f.base, Severity::High);
        assert_eq!(f.status, RuleStatus::Stable);
        assert_eq!(f.carrier, CarrierKind::ResourceLimit);
        assert_eq!(
            texts(&out),
            vec!["PNG tEXt Before: kept", "PNG tEXt After: also kept"]
        );
        assert_eq!(b.remaining_decompressed(), 1000);
    }

    #[test]
    fn bomb_exactly_at_the_limit_is_allowed_and_one_byte_over_is_not() {
        let z = compress_to_vec_zlib(&[b'B'; 100], 6);
        let mut data = b"K\0\0".to_vec();
        data.extend_from_slice(&z);
        let bytes = png(&[chunk(b"zTXt", &data)]);
        let at = Limits {
            max_decompressed_bytes: 100,
            ..Limits::default()
        };
        let out = scan_png(&bytes, &mut Budget::new(&at));
        assert_eq!(out.skip, None);
        assert_eq!(out.carriers.len(), 1);
        let under = Limits {
            max_decompressed_bytes: 99,
            ..Limits::default()
        };
        let out = scan_png(&bytes, &mut Budget::new(&under));
        assert_eq!(out.skip, Some(SkipReason::DecompressionLimit));
        assert!(out.carriers.is_empty());
    }

    #[test]
    fn a_truncated_chunk_keeps_earlier_carriers_and_marks_the_png_malformed() {
        let complete = png(&[chunk(b"tEXt", b"A\0one")]);
        let mut data_cut = complete.clone();
        data_cut.extend_from_slice(&100u32.to_be_bytes());
        data_cut.extend_from_slice(b"tEXt");
        data_cut.extend_from_slice(b"B\0tw");
        let mut header_cut = complete.clone();
        header_cut.extend_from_slice(&[0, 0, 0]);
        for bytes in [data_cut, header_cut] {
            let out = scan_png(&bytes, &mut budget());
            assert_eq!(texts(&out), vec!["PNG tEXt A: one"]);
            assert_eq!(
                findings(&out),
                vec![(
                    "L001",
                    "malformed PNG: truncated chunk",
                    25,
                    bytes.len() as u64
                )]
            );
            assert_eq!(out.skip, Some(SkipReason::Malformed));
        }
        let out = scan_png(&complete, &mut budget());
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn chunk_with_complete_data_but_missing_crc_is_still_read() {
        let mut bytes = png(&[chunk(b"tEXt", b"A\0one")]);
        bytes.truncate(bytes.len() - 4);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["PNG tEXt A: one"]);
    }

    #[test]
    fn chunk_length_of_four_gigabytes_does_not_panic_or_read() {
        let mut bytes = png(&[chunk(b"tEXt", b"A\0one")]);
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend_from_slice(b"tEXt");
        bytes.extend_from_slice(b"B\0two");
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["PNG tEXt A: one"]);
    }

    #[test]
    fn missing_signature_or_tiny_input_gives_nothing() {
        for bytes in [&b""[..], &b"\x89PNG"[..], &b"not a png at all"[..]] {
            let out = scan_png(bytes, &mut budget());
            assert!(out.carriers.is_empty() && out.findings.is_empty());
        }
    }

    #[test]
    fn corrupt_or_unknown_method_ztxt_is_marked_malformed_and_the_walk_continues() {
        let bytes = png(&[
            chunk(b"zTXt", b"K\0\0this is not zlib"),
            chunk(b"zTXt", b"K\0\x01\x78\x9c"),
            chunk(b"tEXt", b"After\0ok"),
        ]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "PNG zTXt keyword: K",
                "PNG zTXt keyword: K",
                "PNG tEXt After: ok"
            ]
        );
        assert_eq!(
            findings(&out),
            vec![(
                "L001",
                "malformed PNG: compressed text is not a valid zlib stream",
                19,
                35
            )]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
    }

    #[test]
    fn empty_text_keeps_the_keyword_as_a_carrier() {
        let mut ztxt = b"Kz\0\0".to_vec();
        ztxt.extend_from_slice(&compress_to_vec_zlib(b"", 6));
        let bytes = png(&[
            chunk(b"tEXt", b"Key\0"),
            chunk(b"zTXt", &ztxt),
            chunk(b"iTXt", b"Ki\0\0\0\0\0"),
            chunk(b"tEXt", b"K2\0x"),
        ]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "PNG tEXt keyword: Key",
                "PNG zTXt keyword: Kz",
                "PNG iTXt keyword: Ki",
                "PNG tEXt K2: x"
            ]
        );
        assert_eq!(
            (
                out.carriers[0].span.byte_start,
                out.carriers[0].span.byte_end
            ),
            (16, 19)
        );
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn a_text_chunk_without_a_separator_is_a_carrier_and_marks_the_png_malformed() {
        let bytes = png(&[chunk(b"tEXt", b"no separator here")]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["PNG tEXt: no separator here"]);
        assert_eq!(
            (
                out.carriers[0].span.byte_start,
                out.carriers[0].span.byte_end
            ),
            (16, 33)
        );
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed PNG: chunk header is incomplete", 16, 33)]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
    }

    #[test]
    fn a_compressed_text_chunk_with_missing_header_fields_marks_the_png_malformed() {
        let cases: [(&[u8; 4], &[u8]); 7] = [
            (b"zTXt", b"no separator"),
            (b"zTXt", b"K\0"),
            (b"iTXt", b"no separator"),
            (b"iTXt", b"K\0"),
            (b"iTXt", b"K\0\x01"),
            (b"iTXt", b"K\0\0\0en"),
            (b"iTXt", b"K\0\0\0en\0Kt"),
        ];
        for (kind, data) in cases {
            let out = scan_png(&png(&[chunk(kind, data)]), &mut budget());
            assert!(out.carriers.is_empty(), "{data:?}");
            assert_eq!(
                findings(&out),
                vec![(
                    "L001",
                    "malformed PNG: chunk header is incomplete",
                    16,
                    16 + data.len() as u64
                )],
                "{data:?}"
            );
            assert_eq!(out.skip, Some(SkipReason::Malformed), "{data:?}");
        }
    }

    #[test]
    fn itxt_language_tag_and_translated_keyword_are_carriers() {
        let bytes = png(&[chunk(b"iTXt", b"Title\0\0\0en-GB\0Titel\0body")]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "PNG iTXt Title language: en-GB",
                "PNG iTXt Title translated keyword: Titel",
                "PNG iTXt Title: body"
            ]
        );
        let spans: Vec<(u64, u64)> = out
            .carriers
            .iter()
            .map(|c| (c.span.byte_start, c.span.byte_end))
            .collect();
        assert_eq!(spans, vec![(24, 29), (30, 35), (36, 40)]);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn chunks_after_iend_are_not_parsed_and_are_a_trailer() {
        let bytes = png(&[
            chunk(b"tEXt", b"A\0one"),
            chunk(b"IEND", &[]),
            chunk(b"tEXt", b"B\0two"),
        ]);
        let out = scan_png(&bytes, &mut budget());
        let visible: Vec<&str> = out
            .carriers
            .iter()
            .filter(|c| !c.hidden)
            .map(|c| c.text.as_str())
            .collect();
        assert_eq!(visible, vec!["PNG tEXt A: one"]);
        assert_eq!(
            findings(&out),
            vec![(
                "B004",
                "data after the end of the image",
                37,
                bytes.len() as u64
            )]
        );
    }

    #[test]
    fn data_after_iend_is_a_hidden_carrier_with_b004() {
        let mut bytes = png(&[chunk(b"tEXt", b"A\0one"), chunk(b"IEND", &[])]);
        bytes.extend_from_slice(b"note for the reader");
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "PNG tEXt A: one",
                "PNG data after IEND: note for the reader"
            ]
        );
        let trailer = &out.carriers[1];
        assert!(trailer.hidden);
        assert_eq!(trailer.kind, CarrierKind::HiddenText);
        assert_eq!((trailer.span.byte_start, trailer.span.byte_end), (37, 56));
        assert_eq!(trailer.evidence, b"note for the reader".to_vec());
        assert_eq!(
            findings(&out),
            vec![("B004", "data after the end of the image", 37, 56)]
        );
        let b004 = &out.findings[0];
        assert_eq!(
            (b004.family, b004.base, b004.status, b004.carrier),
            (
                Family::B,
                Severity::High,
                RuleStatus::Stable,
                CarrierKind::HiddenText
            )
        );
        assert_eq!(out.skip, None);
        assert!(out.embedded.is_empty());
    }

    fn hidden(out: &DetectorOutput) -> Vec<(&str, u64, u64, &[u8])> {
        out.carriers
            .iter()
            .filter(|c| c.hidden)
            .map(|c| {
                (
                    c.text.as_str(),
                    c.span.byte_start,
                    c.span.byte_end,
                    c.evidence.as_slice(),
                )
            })
            .collect()
    }

    #[test]
    fn data_after_an_iend_chunk_that_holds_data_starts_after_its_crc() {
        let mut bytes = png(&[chunk(b"tEXt", b"A\0one"), chunk(b"IEND", b"abcd")]);
        bytes.extend_from_slice(b"note for the reader");
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(
            hidden(&out),
            vec![
                ("PNG data inside IEND: abcd", 33, 37, &b"abcd"[..]),
                (
                    "PNG data after IEND: note for the reader",
                    41,
                    60,
                    &b"note for the reader"[..]
                )
            ]
        );
        assert_eq!(
            findings(&out),
            vec![
                ("L001", "malformed PNG: IEND chunk holds data", 33, 37),
                ("B004", "data after the end of the image", 33, 37),
                ("B004", "data after the end of the image", 41, 60)
            ]
        );
    }

    #[test]
    fn data_inside_an_iend_chunk_is_malformed_and_b004_unless_it_is_padding() {
        let out = scan_png(
            &png(&[chunk(b"IEND", b"note for the reader")]),
            &mut budget(),
        );
        assert_eq!(
            hidden(&out),
            vec![(
                "PNG data inside IEND: note for the reader",
                16,
                35,
                &b"note for the reader"[..]
            )]
        );
        assert_eq!(
            findings(&out),
            vec![
                ("L001", "malformed PNG: IEND chunk holds data", 16, 35),
                ("B004", "data after the end of the image", 16, 35)
            ]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
        let padded = scan_png(&png(&[chunk(b"IEND", b"\0\0 \r\n\t")]), &mut budget());
        assert!(padded.carriers.is_empty());
        assert_eq!(
            findings(&padded),
            vec![("L001", "malformed PNG: IEND chunk holds data", 16, 22)]
        );
    }

    #[test]
    fn a_trailer_of_only_nul_bytes_or_ascii_whitespace_gives_nothing() {
        let tails: [&[u8]; 3] = [b"\0\0\0\0", b" \t\r\n\x0C", b"\0 \n\0"];
        for tail in tails {
            let mut bytes = png(&[chunk(b"IEND", &[])]);
            bytes.extend_from_slice(tail);
            let out = scan_png(&bytes, &mut budget());
            assert!(out.carriers.is_empty(), "{tail:?}");
            assert!(out.findings.is_empty(), "{tail:?}");
            assert!(out.embedded.is_empty(), "{tail:?}");
        }
    }

    #[test]
    fn a_recognised_file_after_iend_is_embedded_as_well_as_b004() {
        let zip: &[u8] = b"PK\x03\x04rest of a zip";
        let jpeg: &[u8] = &[0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x04, b'h', b'i', 0xFF, 0xD9];
        let cases = [
            (zip, FileKind::UnknownBinary, Some("zip"), Vec::new()),
            (jpeg, FileKind::Jpeg, None, jpeg.to_vec()),
        ];
        for (tail, kind, format, kept) in cases {
            let mut bytes = png(&[chunk(b"IEND", &[])]);
            bytes.extend_from_slice(tail);
            let out = scan_png(&bytes, &mut budget());
            let ids: Vec<&str> = out.findings.iter().map(|f| f.rule_id).collect();
            assert_eq!(ids, vec!["B004"]);
            assert_eq!(out.embedded.len(), 1);
            let blob = &out.embedded[0];
            assert_eq!((blob.kind, blob.format), (kind, format));
            assert_eq!(
                (blob.span.byte_start, blob.span.byte_end),
                (20, bytes.len() as u64)
            );
            assert_eq!(blob.bytes, kept);
        }
    }

    #[test]
    fn expired_deadline_sets_timeout_and_stops() {
        let limits = Limits {
            per_file_time: Duration::ZERO,
            ..Limits::default()
        };
        let bytes = png(&[chunk(b"tEXt", b"A\0one")]);
        let out = scan_png(&bytes, &mut Budget::new(&limits));
        assert_eq!(out.skip, Some(SkipReason::Timeout));
        assert!(out.carriers.is_empty());
    }

    fn overlapping_tiff(entries: usize, blob_len: usize, shrink: bool) -> Vec<u8> {
        let blob_at = 8 + 2 + entries * 12 + 4;
        let mut v = vec![b'I', b'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00];
        v.extend_from_slice(&(entries as u16).to_le_bytes());
        for i in 0..entries {
            let count = if shrink { blob_len - i } else { blob_len };
            v.extend_from_slice(&0x010Eu16.to_le_bytes());
            v.extend_from_slice(&2u16.to_le_bytes());
            v.extend_from_slice(&(count as u32).to_le_bytes());
            v.extend_from_slice(&(blob_at as u32).to_le_bytes());
        }
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&vec![b'A'; blob_len]);
        v
    }

    fn cost(out: &DetectorOutput) -> usize {
        out.carriers
            .iter()
            .map(|c| c.text.split_once(": ").map_or(0, |(_, t)| t.len()) + c.evidence.len())
            .sum()
    }

    #[test]
    fn overlapping_exif_values_beyond_the_output_cap_give_b003() {
        let bytes = png(&[chunk(b"eXIf", &overlapping_tiff(1000, 30000, true))]);
        let out = scan_png(&bytes, &mut budget());
        assert!(cost(&out) <= 3 * bytes.len() + 65536);
        assert!(!out.carriers.is_empty() && out.carriers.len() < 1000);
        assert_eq!(out.skip, Some(SkipReason::SizeLimit));
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.rule_id, "B003");
        assert_eq!(f.family, Family::B);
        assert_eq!(f.base, Severity::High);
        assert_eq!(f.status, RuleStatus::Stable);
        assert_eq!(f.carrier, CarrierKind::ResourceLimit);
        assert_eq!(f.payload, None);
        assert_eq!(f.message, "metadata amplification");
    }

    #[test]
    fn exif_values_with_the_same_offset_and_length_are_emitted_once() {
        let bytes = png(&[chunk(b"eXIf", &overlapping_tiff(5, 30, false))]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(out.carriers.len(), 1);
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    fn many_inline_entries(count: usize) -> Vec<u8> {
        let mut v = vec![b'I', b'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00];
        v.extend_from_slice(&(count as u16).to_le_bytes());
        for _ in 0..count {
            v.extend_from_slice(&0x010Fu16.to_le_bytes());
            v.extend_from_slice(&2u16.to_le_bytes());
            v.extend_from_slice(&3u32.to_le_bytes());
            v.extend_from_slice(&[b'a', 0, 0, 0]);
        }
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    #[test]
    fn exif_entry_limit_is_visible_as_l001_and_size_limit() {
        let bytes = png(&[chunk(b"eXIf", &many_inline_entries(1001))]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(out.carriers.len(), 1000);
        assert_eq!(out.skip, Some(SkipReason::SizeLimit));
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, "L001");
        assert_eq!(out.findings[0].message, "EXIF entry limit");
        let exact = png(&[chunk(b"eXIf", &many_inline_entries(1000))]);
        let out = scan_png(&exact, &mut budget());
        assert_eq!(out.carriers.len(), 1000);
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn the_first_skip_reason_wins() {
        let z = compress_to_vec_zlib(&vec![b'A'; 1_000_000], 6);
        let mut bomb = b"Bomb\0\0".to_vec();
        bomb.extend_from_slice(&z);
        let bytes = png(&[
            chunk(b"zTXt", &bomb),
            chunk(b"eXIf", &many_inline_entries(1001)),
        ]);
        let limits = Limits {
            max_decompressed_bytes: 1000,
            ..Limits::default()
        };
        let out = scan_png(&bytes, &mut Budget::new(&limits));
        assert_eq!(out.skip, Some(SkipReason::DecompressionLimit));
        let ids: Vec<&str> = out.findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, vec!["B002", "L001"]);
    }

    #[test]
    fn two_moderate_ztxt_chunks_sum_against_one_budget() {
        let z = compress_to_vec_zlib(&vec![b'A'; 600], 6);
        let mut data = b"K\0\0".to_vec();
        data.extend_from_slice(&z);
        let bytes = png(&[chunk(b"zTXt", &data), chunk(b"zTXt", &data)]);
        let limits = Limits {
            max_decompressed_bytes: 1000,
            ..Limits::default()
        };
        let mut b = Budget::new(&limits);
        let out = scan_png(&bytes, &mut b);
        assert_eq!(out.carriers.len(), 1);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, "B002");
        assert_eq!(out.skip, Some(SkipReason::DecompressionLimit));
        assert_eq!(b.remaining_decompressed(), 400);
    }

    #[test]
    fn inflate_that_fails_after_producing_output_is_still_charged() {
        let mut z = compress_to_vec_zlib(&vec![b'A'; 600], 6);
        let last = z.len() - 1;
        z[last] ^= 0xFF;
        let mut data = b"K\0\0".to_vec();
        data.extend_from_slice(&z);
        let bytes = png(&[chunk(b"zTXt", &data)]);
        let limits = Limits {
            max_decompressed_bytes: 1000,
            ..Limits::default()
        };
        let mut b = Budget::new(&limits);
        let out = scan_png(&bytes, &mut b);
        assert_eq!(
            texts(&out),
            vec![format!("PNG zTXt K: {}", "A".repeat(600))]
        );
        assert_eq!(b.remaining_decompressed(), 400);
    }

    #[test]
    fn compressible_ztxt_within_the_decompression_budget_is_not_b003() {
        let z = compress_to_vec_zlib(&vec![b'A'; 200_000], 6);
        let mut data = b"K\0\0".to_vec();
        data.extend_from_slice(&z);
        let bytes = png(&[chunk(b"zTXt", &data)]);
        assert!(bytes.len() < 2000);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(out.carriers.len(), 1);
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn latin1_text_chunk_is_not_b003() {
        let mut data = b"K\0".to_vec();
        data.extend(std::iter::repeat_n(0xE9u8, 100_000));
        let bytes = png(&[chunk(b"tEXt", &data)]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(out.carriers.len(), 1);
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn a_ztxt_stream_cut_short_is_charged_only_the_bytes_it_inflated() {
        let mut data = b"K\0\0".to_vec();
        data.extend_from_slice(&stored_zlib_cut_short(4000, &[b'a'; 3000]));
        let bytes = png(&[chunk(b"zTXt", &data)]);
        for limit in [4096, 65536] {
            let limits = Limits {
                max_decompressed_bytes: limit,
                ..Limits::default()
            };
            let mut b = Budget::new(&limits);
            let out = scan_png(&bytes, &mut b);
            assert_eq!(b.remaining_decompressed(), limit - 3000, "limit {limit}");
            assert!(out.findings.iter().all(|f| f.rule_id != "B002"));
        }
    }

    #[test]
    fn reaching_the_limit_is_b002_whatever_follows_the_stream() {
        let mut first_block = vec![0x78, 0x01, 0x00];
        first_block.extend_from_slice(&5000u16.to_le_bytes());
        first_block.extend_from_slice(&(!5000u16).to_le_bytes());
        first_block.extend_from_slice(&[b'a'; 5000]);
        let tails: [&[u8]; 3] = [&[], &[0x07], &[0x01, 0x00, 0x00, 0xFF, 0xFF, 0, 0, 0, 0]];
        for tail in tails {
            let mut data = b"K\0\0".to_vec();
            data.extend_from_slice(&first_block);
            data.extend_from_slice(tail);
            let bytes = png(&[chunk(b"zTXt", &data)]);
            let limits = Limits {
                max_decompressed_bytes: 4096,
                ..Limits::default()
            };
            let out = scan_png(&bytes, &mut Budget::new(&limits));
            let ids: Vec<&str> = out.findings.iter().map(|f| f.rule_id).collect();
            assert_eq!(ids, vec!["B002"]);
            assert_eq!(out.skip, Some(SkipReason::DecompressionLimit));
        }
    }

    #[test]
    fn corrupt_compressed_text_keeps_its_partial_text_and_marks_the_png_malformed() {
        let cut = stored_zlib_cut_short(40, b"partial text");
        let mut ztxt = b"K\0\0".to_vec();
        ztxt.extend_from_slice(&cut);
        let mut itxt = b"T\0\x01\0\0\0".to_vec();
        itxt.extend_from_slice(&cut);
        let bytes = png(&[chunk(b"zTXt", &ztxt), chunk(b"iTXt", &itxt)]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec!["PNG zTXt K: partial text", "PNG iTXt T: partial text"]
        );
        assert_eq!(
            findings(&out),
            vec![(
                "L001",
                "malformed PNG: compressed text is not a valid zlib stream",
                19,
                38
            )]
        );
        assert_eq!(out.findings[0].base, Severity::Low);
        assert_eq!(out.findings[0].carrier, CarrierKind::ResourceLimit);
        assert_eq!(out.skip, Some(SkipReason::Malformed));
    }

    #[test]
    fn an_unknown_compression_method_keeps_the_keyword_and_marks_the_png_malformed() {
        let cases = [
            (
                png(&[chunk(b"zTXt", b"K\0\x01\x78\x01")]),
                19,
                21,
                "PNG zTXt keyword: K",
            ),
            (
                png(&[chunk(b"iTXt", b"T\0\x01\x01\0\0\x78\x01")]),
                22,
                24,
                "PNG iTXt keyword: T",
            ),
        ];
        for (bytes, start, end, keyword) in cases {
            let out = scan_png(&bytes, &mut budget());
            assert_eq!(texts(&out), vec![keyword]);
            assert_eq!(
                findings(&out),
                vec![(
                    "L001",
                    "malformed PNG: unknown compression method",
                    start,
                    end
                )]
            );
            assert_eq!(out.skip, Some(SkipReason::Malformed));
        }
    }

    fn pcal(name: &[u8], count: u8, rest: &[u8]) -> Vec<u8> {
        let mut data = name.to_vec();
        data.push(0);
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1, 0, count]);
        data.extend_from_slice(rest);
        data
    }

    #[test]
    fn iccp_splt_and_pcal_names_are_carriers() {
        let bytes = png(&[
            chunk(b"iCCP", b"sRGB profile\0\0\x78\x01"),
            chunk(b"sPLT", b"Palette one\0\x08\x01\x02\x03\x04\x00\x01"),
            chunk(b"pCAL", &pcal(b"Cal name", 2, b"metres\x001.0\x002.5")),
            chunk(b"pCAL", &pcal(b"Bare", 0, b"")),
        ]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "PNG iCCP profile name: sRGB profile",
                "PNG sPLT palette name: Palette one",
                "PNG pCAL name: Cal name",
                "PNG pCAL unit: metres",
                "PNG pCAL parameter: 1.0",
                "PNG pCAL parameter: 2.5",
                "PNG pCAL name: Bare"
            ]
        );
        let spans: Vec<(u64, u64)> = out
            .carriers
            .iter()
            .map(|c| (c.span.byte_start, c.span.byte_end))
            .collect();
        assert_eq!(spans[0], (16, 28));
        assert_eq!(spans[3], (94, 100));
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn iccp_splt_and_pcal_with_broken_headers_mark_the_png_malformed() {
        let cases: [(&[u8; 4], Vec<u8>); 5] = [
            (b"iCCP", b"no separator".to_vec()),
            (b"sPLT", b"no separator".to_vec()),
            (b"pCAL", b"no separator".to_vec()),
            (b"pCAL", b"Name\0\0\0\0\0\0\0\0\0\0".to_vec()),
            (b"pCAL", pcal(b"Name", 2, b"metres\x001.0")),
        ];
        for (kind, data) in cases {
            let out = scan_png(&png(&[chunk(kind, &data)]), &mut budget());
            assert_eq!(
                findings(&out),
                vec![(
                    "L001",
                    "malformed PNG: chunk header is incomplete",
                    16,
                    16 + data.len() as u64
                )],
                "{data:?}"
            );
            assert_eq!(out.skip, Some(SkipReason::Malformed), "{data:?}");
        }
    }
}

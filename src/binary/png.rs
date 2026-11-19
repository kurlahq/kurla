use miniz_oxide::inflate::decompress_to_vec_zlib_with_limit;

use super::{Sink, latin1, lossy, sub};
use crate::limits::Budget;
use crate::model::DetectorOutput;

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const CHUNK_HEADER_LEN: usize = 8;
const CRC_LEN: usize = 4;

pub(crate) enum Inflated {
    Text(Vec<u8>),
    Unreadable,
    LimitHit,
}

pub(crate) fn inflate(data: &[u8], budget: &mut Budget) -> Inflated {
    let allowed = usize::try_from(budget.remaining_decompressed()).unwrap_or(usize::MAX);
    match decompress_to_vec_zlib_with_limit(data, allowed) {
        Ok(out) => match budget.take_decompressed(out.len() as u64) {
            Ok(()) => Inflated::Text(out),
            Err(_) => Inflated::LimitHit,
        },
        Err(error) if error.status == miniz_oxide::inflate::TINFLStatus::HasMoreOutput => {
            Inflated::LimitHit
        }
        Err(error) => {
            let _ = budget.take_decompressed(error.output.len() as u64);
            Inflated::Unreadable
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

fn split_nul(data: &[u8]) -> (&[u8], Option<&[u8]>) {
    match data.iter().position(|&b| b == 0) {
        Some(at) => (&data[..at], Some(&data[at + 1..])),
        None => (data, None),
    }
}

struct Walker<'a> {
    sink: Sink,
    budget: &'a mut Budget,
    limit_hit: bool,
}

impl Walker<'_> {
    fn text_chunk(&mut self, chunk: &Chunk<'_>) {
        let (keyword, rest) = split_nul(chunk.data);
        let Some(text) = rest else {
            return;
        };
        let start = chunk.data_start + keyword.len() + 1;
        let label = format!("PNG tEXt {}", latin1(keyword));
        self.sink
            .carrier(&label, &latin1(text), start, start + text.len(), chunk.data);
    }

    fn inflated(&mut self, compressed: &[u8], start: usize) -> Option<Vec<u8>> {
        if self.limit_hit {
            return None;
        }
        match inflate(compressed, self.budget) {
            Inflated::Text(out) => Some(out),
            Inflated::Unreadable => None,
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
            return;
        };
        if method != 0 {
            return;
        }
        let start = chunk.data_start + keyword.len() + 2;
        if let Some(text) = self.inflated(compressed, start) {
            let label = format!("PNG zTXt {}", latin1(keyword));
            self.sink.carrier(
                &label,
                &latin1(&text),
                start,
                start + compressed.len(),
                chunk.data,
            );
        }
    }

    fn itxt_chunk(&mut self, chunk: &Chunk<'_>) {
        let (keyword, rest) = split_nul(chunk.data);
        let Some(rest) = rest else {
            return;
        };
        let (Some(&flag), Some(&method), Some(after)) = (rest.first(), rest.get(1), rest.get(2..))
        else {
            return;
        };
        let (_, after_language) = split_nul(after);
        let Some((_, after_translated)) = after_language.map(split_nul) else {
            return;
        };
        let Some(body) = after_translated else {
            return;
        };
        let start = chunk.data_start + (chunk.data.len() - body.len());
        let label = format!("PNG iTXt {}", latin1(keyword));
        if flag == 0 {
            self.sink
                .carrier(&label, &lossy(body), start, start + body.len(), chunk.data);
        } else if method == 0
            && let Some(text) = self.inflated(body, start)
        {
            self.sink
                .carrier(&label, &lossy(&text), start, start + body.len(), chunk.data);
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
                return;
            };
            match &chunk.kind {
                b"tEXt" => self.text_chunk(&chunk),
                b"zTXt" => self.ztxt_chunk(&chunk),
                b"iTXt" => self.itxt_chunk(&chunk),
                b"eXIf" => self.sink.exif(chunk.data, chunk.data_start, &*self.budget),
                b"IEND" => return,
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
    use crate::model::{CarrierKind, Family, RuleStatus, Severity, SkipReason};
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
            vec!["PNG tEXt Comment: hello", "PNG iTXt Title: héllo"]
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
        let second = &out.carriers[1];
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
    fn truncated_png_keeps_earlier_carriers() {
        let mut bytes = png(&[chunk(b"tEXt", b"A\0one")]);
        bytes.extend_from_slice(&100u32.to_be_bytes());
        bytes.extend_from_slice(b"tEXt");
        bytes.extend_from_slice(b"B\0tw");
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["PNG tEXt A: one"]);
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
    fn corrupt_or_unknown_method_ztxt_is_skipped_silently() {
        let bytes = png(&[
            chunk(b"zTXt", b"K\0\0this is not zlib"),
            chunk(b"zTXt", b"K\0\x01\x78\x9c"),
            chunk(b"tEXt", b"After\0ok"),
        ]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["PNG tEXt After: ok"]);
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn empty_text_makes_no_carrier() {
        let bytes = png(&[chunk(b"tEXt", b"Key\0"), chunk(b"tEXt", b"K2\0x")]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["PNG tEXt K2: x"]);
    }

    #[test]
    fn parse_stops_at_iend() {
        let bytes = png(&[
            chunk(b"tEXt", b"A\0one"),
            chunk(b"IEND", &[]),
            chunk(b"tEXt", b"B\0two"),
        ]);
        let out = scan_png(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["PNG tEXt A: one"]);
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
            .map(|c| c.text.len() + c.evidence.len())
            .sum()
    }

    #[test]
    fn exif_values_overlapping_one_blob_stay_under_the_output_cap() {
        let bytes = png(&[chunk(b"eXIf", &overlapping_tiff(1000, 30000, true))]);
        let out = scan_png(&bytes, &mut budget());
        assert!(cost(&out) <= 2 * bytes.len() + 65536);
        assert!(!out.carriers.is_empty() && out.carriers.len() < 1000);
        assert_eq!(out.skip, Some(SkipReason::SizeLimit));
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.rule_id, "L001");
        assert_eq!(f.family, Family::L);
        assert_eq!(f.base, Severity::Low);
        assert_eq!(f.status, RuleStatus::Stable);
        assert_eq!(f.carrier, CarrierKind::ResourceLimit);
        assert_eq!(f.message, "metadata output limit");
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
        assert!(out.carriers.is_empty() && out.findings.is_empty());
        assert!(b.remaining_decompressed() <= 400);
    }
}

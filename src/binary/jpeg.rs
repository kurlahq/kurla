use super::{Sink, is_padding, lossy, sub};
use crate::limits::Budget;
use crate::model::DetectorOutput;

const EXIF_PREFIX: &[u8] = b"Exif\0\0";
const XMP_PREFIX: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
const EXTENDED_PREFIX: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
const GUID_LEN: usize = 32;
const EXTENDED_HEADER_LEN: usize = GUID_LEN + 8;
const MAX_EXTENDED_GUIDS: usize = 16;
const TRAILER_LABEL: &str = "JPEG data after EOI";
const STRAY_LABEL: &str = "JPEG bytes between segments";
const STRAY_BYTES: &str = "malformed JPEG: bytes between segments";
const TRUNCATED_SEGMENT: &str = "malformed JPEG: truncated segment";
const INVALID_LENGTH: &str = "malformed JPEG: invalid segment length";
const BROKEN_EXTENDED_XMP: &str = "malformed JPEG: broken extended XMP";
const GUID_LIMIT: &str = "extended XMP GUID limit";

struct Assembly {
    guid: [u8; GUID_LEN],
    full: usize,
    data: Vec<u8>,
    start: usize,
    end: usize,
    rejected: bool,
}

#[derive(Default)]
struct Extended {
    assemblies: Vec<Assembly>,
    over_limit: bool,
}

fn be32(bytes: &[u8], at: usize) -> Option<usize> {
    let raw = <[u8; 4]>::try_from(sub(bytes, at, 4)?).ok()?;
    usize::try_from(u32::from_be_bytes(raw)).ok()
}

impl Extended {
    fn chunk(&mut self, rest: &[u8], start: usize, sink: &mut Sink, budget: &Budget) {
        let (Some(guid), Some(full), Some(offset), Some(data)) = (
            rest.get(..GUID_LEN)
                .and_then(|g| <[u8; GUID_LEN]>::try_from(g).ok()),
            be32(rest, GUID_LEN),
            be32(rest, GUID_LEN + 4),
            rest.get(EXTENDED_HEADER_LEN..),
        ) else {
            sink.malformed(BROKEN_EXTENDED_XMP, start, start + rest.len());
            return;
        };
        let data_start = start + EXTENDED_HEADER_LEN;
        let data_end = data_start + data.len();
        let index = match self.assemblies.iter().position(|a| a.guid == guid) {
            Some(index) => index,
            None => {
                if self.assemblies.len() >= MAX_EXTENDED_GUIDS {
                    if !self.over_limit {
                        self.over_limit = true;
                        sink.l001(GUID_LIMIT, data_start, data_end);
                    }
                    return;
                }
                let rejected =
                    u64::try_from(full).unwrap_or(u64::MAX) > budget.remaining_decompressed();
                if rejected {
                    sink.limit_hit(
                        data_start,
                        data_end,
                        "extended XMP declares a length past the decompression budget",
                    );
                }
                self.assemblies.push(Assembly {
                    guid,
                    full,
                    data: Vec::new(),
                    start: data_start,
                    end: data_start,
                    rejected,
                });
                self.assemblies.len() - 1
            }
        };
        let assembly = &mut self.assemblies[index];
        if assembly.rejected {
            return;
        }
        let fits = assembly
            .data
            .len()
            .checked_add(data.len())
            .is_some_and(|n| n <= assembly.full);
        if offset != assembly.data.len() || !fits {
            sink.malformed(BROKEN_EXTENDED_XMP, data_start, data_end);
            return;
        }
        assembly.data.extend_from_slice(data);
        assembly.end = data_end;
    }

    fn finish(&self, sink: &mut Sink, budget: &Budget) {
        for assembly in self.assemblies.iter().filter(|a| !a.rejected) {
            if assembly.data.len() < assembly.full {
                sink.malformed(BROKEN_EXTENDED_XMP, assembly.start, assembly.end);
            }
            sink.xmp(
                "JPEG XMP",
                &assembly.data,
                assembly.start,
                assembly.end,
                false,
                budget,
            );
        }
    }
}

fn stray(sink: &mut Sink, bytes: &[u8], start: usize, end: usize) {
    if start < end {
        let skipped = &bytes[start..end];
        sink.malformed(STRAY_BYTES, start, end);
        if !is_padding(skipped) {
            sink.hidden_carrier(STRAY_LABEL, &lossy(skipped), start, end, skipped);
        }
    }
}

fn after_scan(bytes: &[u8], from: usize) -> Option<usize> {
    let rest = bytes.get(from..)?;
    let at = rest
        .windows(2)
        .position(|pair| pair[0] == 0xFF && !matches!(pair[1], 0x00 | 0xD0..=0xD7 | 0xFF))?;
    Some(from + at)
}

fn app1(payload: &[u8], start: usize, extended: &mut Extended, sink: &mut Sink, budget: &Budget) {
    if let Some(tiff) = payload.strip_prefix(EXIF_PREFIX) {
        sink.exif(tiff, start + EXIF_PREFIX.len(), budget);
    } else if let Some(packet) = payload.strip_prefix(XMP_PREFIX) {
        sink.xmp(
            "JPEG XMP",
            packet,
            start + XMP_PREFIX.len(),
            start + payload.len(),
            true,
            budget,
        );
    } else if let Some(rest) = payload.strip_prefix(EXTENDED_PREFIX) {
        extended.chunk(rest, start + EXTENDED_PREFIX.len(), sink, budget);
    }
}

pub fn scan_jpeg(bytes: &[u8], budget: &mut Budget) -> DetectorOutput {
    let mut sink = Sink::new(bytes.len());
    if !bytes.starts_with(&[0xFF, 0xD8]) {
        return sink.out;
    }
    let mut extended = Extended::default();
    let mut at = 2usize;
    loop {
        if budget.deadline_exceeded() {
            sink.timed_out();
            break;
        }
        let Some(skipped) = bytes[at..].iter().position(|&b| b == 0xFF) else {
            stray(&mut sink, bytes, at, bytes.len());
            break;
        };
        stray(&mut sink, bytes, at, at + skipped);
        at += skipped;
        while bytes.get(at + 1) == Some(&0xFF) {
            at += 1;
        }
        let marker_at = at;
        let Some(&marker) = bytes.get(at + 1) else {
            sink.malformed(TRUNCATED_SEGMENT, marker_at, bytes.len());
            break;
        };
        at += 2;
        match marker {
            0xD9 => {
                sink.trailer(TRAILER_LABEL, bytes, at, true);
                break;
            }
            0x00 | 0x01 | 0xD0..=0xD8 => continue,
            _ => {}
        }
        let Some(length) = sub(bytes, at, 2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        else {
            sink.malformed(TRUNCATED_SEGMENT, marker_at, bytes.len());
            break;
        };
        if length < 2 {
            sink.malformed(INVALID_LENGTH, marker_at, at + 2);
            break;
        }
        let start = at + 2;
        let Some(payload) = sub(bytes, start, length - 2) else {
            sink.malformed(TRUNCATED_SEGMENT, marker_at, bytes.len());
            break;
        };
        at += length;
        match marker {
            0xFE => {
                sink.carrier(
                    "JPEG COM",
                    &lossy(payload),
                    start,
                    start + payload.len(),
                    payload,
                );
            }
            0xE1 => app1(payload, start, &mut extended, &mut sink, budget),
            0xDA => match after_scan(bytes, at) {
                Some(next) => at = next,
                None => break,
            },
            _ => {}
        }
        if sink.stop {
            break;
        }
    }
    if !sink.stop {
        extended.finish(&mut sink, budget);
    }
    sink.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::model::{CarrierKind, Family, FileKind, SkipReason};
    use std::time::Duration;

    const EXIF_HELLO: [u8; 32] = [
        b'I', b'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0E, 0x01, 0x02, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, b'h', b'e', b'l', b'l',
        b'o', 0x00,
    ];
    const XMP_NS: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
    const EXT_NS: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
    const GUID: &[u8; 32] = b"0123456789ABCDEF0123456789ABCDEF";

    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn jpeg(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        for p in parts {
            v.extend_from_slice(p);
        }
        v
    }

    fn xmp_doc(word: &str) -> String {
        format!(
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"r\">\
             <rdf:Description rdf:about=\"\" xmlns:dc=\"d\">\
             <dc:description>{word}</dc:description>\
             </rdf:Description></rdf:RDF></x:xmpmeta>"
        )
    }

    fn ext_seg(full: u32, offset: u32, data: &[u8]) -> Vec<u8> {
        let mut p = EXT_NS.to_vec();
        p.extend_from_slice(GUID);
        p.extend_from_slice(&full.to_be_bytes());
        p.extend_from_slice(&offset.to_be_bytes());
        p.extend_from_slice(data);
        seg(0xE1, &p)
    }

    fn budget() -> Budget {
        Budget::new(&Limits::default())
    }

    fn texts(out: &DetectorOutput) -> Vec<&str> {
        out.carriers.iter().map(|c| c.text.as_str()).collect()
    }

    #[test]
    fn jpeg_com_and_exif_description_extracted() {
        let mut exif = b"Exif\0\0".to_vec();
        exif.extend_from_slice(&EXIF_HELLO);
        let bytes = jpeg(&[
            seg(0xFE, b"hello"),
            seg(0xE1, &exif),
            vec![0xFF, 0xDA, 0x00, 0x02],
            seg(0xFE, b"late"),
        ]);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "JPEG COM: hello",
                "EXIF ImageDescription: hello",
                "JPEG COM: late"
            ]
        );
        let com = &out.carriers[0];
        assert_eq!(com.kind, CarrierKind::MetadataField);
        assert!(!com.hidden);
        assert_eq!(
            (
                com.span.byte_start,
                com.span.byte_end,
                com.span.line,
                com.span.column
            ),
            (6, 11, None, None)
        );
        assert_eq!(com.evidence, b"hello".to_vec());
        let ex = &out.carriers[1];
        assert_eq!((ex.span.byte_start, ex.span.byte_end), (47, 53));
        assert_eq!(ex.evidence, b"hello\0".to_vec());
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn app1_xmp_packet_text_extracted_with_packet_span() {
        let xml = xmp_doc("hidden words");
        let mut payload = XMP_NS.to_vec();
        payload.extend_from_slice(xml.as_bytes());
        let bytes = jpeg(&[seg(0xE1, &payload)]);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "JPEG XMP: adobe:ns:meta/",
                "JPEG XMP: r",
                "JPEG XMP: d",
                "JPEG XMP: hidden words"
            ]
        );
        assert_eq!(
            (
                out.carriers[3].span.byte_start,
                out.carriers[3].span.byte_end
            ),
            (153, 165)
        );
        assert_eq!(out.carriers[3].evidence, b"hidden words".to_vec());
    }

    #[test]
    fn extended_xmp_chunks_are_reassembled_by_guid() {
        let xml = xmp_doc("ext words");
        let (a, b) = xml.as_bytes().split_at(40);
        let full = xml.len() as u32;
        let bytes = jpeg(&[ext_seg(full, 0, a), ext_seg(full, 40, b)]);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "JPEG XMP: adobe:ns:meta/",
                "JPEG XMP: r",
                "JPEG XMP: d",
                "JPEG XMP: ext words"
            ]
        );
    }

    #[test]
    fn extended_xmp_chunk_out_of_order_or_past_full_length_is_dropped_and_marks_the_jpeg_malformed()
    {
        let (a, b) = (&b"<a>one</a>"[..], &b"<b>two</b>"[..]);
        let both = jpeg(&[ext_seg(20, 0, a), ext_seg(20, 10, b)]);
        let out = scan_jpeg(&both, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG XMP: one", "JPEG XMP: two"]);
        assert!(out.findings.is_empty());
        let gap = jpeg(&[ext_seg(20, 0, a), ext_seg(20, 11, b)]);
        let out = scan_jpeg(&gap, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG XMP: one"]);
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed JPEG: broken extended XMP", 170, 180)]
        );
        let short = jpeg(&[ext_seg(19, 0, a), ext_seg(19, 10, b)]);
        let out = scan_jpeg(&short, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG XMP: one"]);
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed JPEG: broken extended XMP", 170, 180)]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
    }

    #[test]
    fn extended_xmp_with_a_short_header_or_never_completed_marks_the_jpeg_malformed() {
        let mut header = EXT_NS.to_vec();
        header.extend_from_slice(&GUID[..10]);
        let out = scan_jpeg(&jpeg(&[seg(0xE1, &header)]), &mut budget());
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed JPEG: broken extended XMP", 41, 51)]
        );
        let unfinished = jpeg(&[ext_seg(20, 0, b"<a>one</a>")]);
        let out = scan_jpeg(&unfinished, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG XMP: one"]);
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed JPEG: broken extended XMP", 81, 91)]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
    }

    #[test]
    fn more_than_sixteen_extended_xmp_guids_is_l001_size_limit() {
        let segments: Vec<Vec<u8>> = (0..17)
            .map(|i| {
                let mut p = EXT_NS.to_vec();
                p.extend_from_slice(format!("{i:032}").as_bytes());
                p.extend_from_slice(&10u32.to_be_bytes());
                p.extend_from_slice(&0u32.to_be_bytes());
                p.extend_from_slice(b"<a>one</a>");
                seg(0xE1, &p)
            })
            .collect();
        let out = scan_jpeg(&jpeg(&segments), &mut budget());
        assert_eq!(out.carriers.len(), 16);
        let ids: Vec<(&str, &str)> = out
            .findings
            .iter()
            .map(|f| (f.rule_id, f.message.as_str()))
            .collect();
        assert_eq!(ids, vec![("L001", "extended XMP GUID limit")]);
        assert_eq!(out.skip, Some(SkipReason::SizeLimit));
    }

    #[test]
    fn extended_xmp_claiming_more_than_the_budget_is_b002() {
        let limits = Limits {
            max_decompressed_bytes: 1000,
            ..Limits::default()
        };
        let bytes = jpeg(&[ext_seg(10_000_000, 0, b"<a>x</a>")]);
        let out = scan_jpeg(&bytes, &mut Budget::new(&limits));
        assert_eq!(out.skip, Some(SkipReason::DecompressionLimit));
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, "B002");
        assert_eq!(out.findings[0].family, Family::B);
        assert!(out.carriers.is_empty());
    }

    #[test]
    fn extended_xmp_claiming_exactly_the_budget_is_read_and_one_byte_more_is_b002() {
        let xml = b"<a>budget words</a>";
        let bytes = jpeg(&[ext_seg(xml.len() as u32, 0, xml)]);
        let at_limit = Limits {
            max_decompressed_bytes: xml.len() as u64,
            ..Limits::default()
        };
        let out = scan_jpeg(&bytes, &mut Budget::new(&at_limit));
        assert_eq!(texts(&out), vec!["JPEG XMP: budget words"]);
        assert!(out.findings.is_empty());
        let under = Limits {
            max_decompressed_bytes: xml.len() as u64 - 1,
            ..Limits::default()
        };
        let out = scan_jpeg(&bytes, &mut Budget::new(&under));
        assert_eq!(
            findings(&out),
            vec![(
                "B002",
                "extended XMP declares a length past the decompression budget",
                81,
                100
            )]
        );
        assert!(out.carriers.is_empty());
    }

    #[test]
    fn a_broken_xmp_packet_is_reported_over_the_packet_it_sits_in() {
        let mut payload = XMP_NS.to_vec();
        payload.extend_from_slice(b"<a>good</a></c> ignore this");
        let out = scan_jpeg(&jpeg(&[seg(0xE1, &payload)]), &mut budget());
        assert_eq!(
            findings(&out),
            vec![
                ("B005", "readable text hidden in the image", 46, 62),
                ("L001", "malformed XMP: XML error", 35, 62)
            ]
        );
    }

    #[test]
    fn fill_bytes_and_standalone_markers_are_skipped() {
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xFF, 0xFF, 0x01, 0xFF, 0xD0];
        bytes.extend_from_slice(&seg(0xFE, b"abc"));
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG COM: abc"]);
        assert_eq!(out.carriers[0].span.byte_start, 12);
    }

    #[test]
    fn com_is_decoded_lossily() {
        let bytes = jpeg(&[seg(0xFE, b"caf\xE9")]);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG COM: caf\u{FFFD}"]);
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
    fn reading_stops_at_eoi_and_continues_after_a_scan() {
        let eoi = jpeg(&[seg(0xFE, b"one"), vec![0xFF, 0xD9], seg(0xFE, b"two")]);
        let out = scan_jpeg(&eoi, &mut budget());
        let visible: Vec<&str> = out
            .carriers
            .iter()
            .filter(|c| !c.hidden)
            .map(|c| c.text.as_str())
            .collect();
        assert_eq!(visible, vec!["JPEG COM: one"]);
        assert_eq!(
            findings(&out),
            vec![("B004", "data after the end of the image", 11, 18)]
        );
        let sos = jpeg(&[seg(0xFE, b"one"), seg(0xDA, &[1, 2, 3]), seg(0xFE, b"two")]);
        let out = scan_jpeg(&sos, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG COM: one", "JPEG COM: two"]);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn segments_after_entropy_coded_data_are_read() {
        let bytes = jpeg(&[
            seg(0xFE, b"one"),
            seg(0xDA, &[1, 2, 3]),
            vec![0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD3, 0x56, 0xFF, 0xFF],
            seg(0xFE, b"two"),
            vec![0xFF, 0xD9],
        ]);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG COM: one", "JPEG COM: two"]);
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn data_after_eoi_is_b004_unless_it_is_a_second_jpeg_or_a_motion_photo() {
        let base = jpeg(&[seg(0xFE, b"one"), vec![0xFF, 0xD9]]);
        let with = |tail: &[u8]| {
            let mut bytes = base.clone();
            bytes.extend_from_slice(tail);
            scan_jpeg(&bytes, &mut budget())
        };
        let out = with(b"note for the reader");
        assert_eq!(
            findings(&out),
            vec![("B004", "data after the end of the image", 11, 30)]
        );
        assert_eq!(
            out.carriers[1].text,
            "JPEG data after EOI: note for the reader"
        );
        assert!(out.carriers[1].hidden);
        assert!(out.embedded.is_empty());
        let second: &[u8] = &[0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x04, b'h', b'i', 0xFF, 0xD9];
        let mut mp4 = vec![0, 0, 0, 0x10];
        mp4.extend_from_slice(b"ftypmp42\0\0\0\0");
        let png: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let cases = [
            (second, FileKind::Jpeg, None, false),
            (&mp4[..], FileKind::UnknownBinary, Some("mp4/mov"), false),
            (
                &b"PK\x03\x04rest of a zip"[..],
                FileKind::UnknownBinary,
                Some("zip"),
                true,
            ),
            (&b"%PDF-1.7 rest"[..], FileKind::Pdf, Some("pdf"), true),
            (
                &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4][..],
                FileKind::UnknownBinary,
                Some("7z"),
                true,
            ),
            (png, FileKind::Png, None, true),
        ];
        for (tail, kind, format, flagged) in cases {
            let out = with(tail);
            let expected = if flagged {
                vec![(
                    "B004",
                    "data after the end of the image",
                    11,
                    11 + tail.len() as u64,
                )]
            } else {
                Vec::new()
            };
            assert_eq!(findings(&out), expected, "{format:?}");
            assert_eq!(out.carriers[0].text, "JPEG COM: one");
            assert_eq!(out.carriers.len(), 1 + usize::from(flagged));
            assert!(out.carriers.iter().skip(1).all(|c| c.hidden));
            assert_eq!(out.embedded.len(), 1);
            assert_eq!(
                (out.embedded[0].kind, out.embedded[0].format),
                (kind, format)
            );
            assert_eq!(
                (
                    out.embedded[0].span.byte_start,
                    out.embedded[0].span.byte_end
                ),
                (11, 11 + tail.len() as u64)
            );
        }
        let out = with(b"\0 \n");
        assert!(out.findings.is_empty() && out.embedded.is_empty());
        assert_eq!(texts(&out), vec!["JPEG COM: one"]);
    }

    #[test]
    fn truncated_segment_keeps_earlier_carriers_and_marks_the_jpeg_malformed() {
        let tails: [&[u8]; 3] = [
            &[0xFF, 0xFE, 0x00, 0xFF, b'a', b'b'],
            &[0xFF, 0xFE, 0x00],
            &[0xFF],
        ];
        for tail in tails {
            let mut bytes = jpeg(&[seg(0xFE, b"one")]);
            bytes.extend_from_slice(tail);
            let out = scan_jpeg(&bytes, &mut budget());
            assert_eq!(texts(&out), vec!["JPEG COM: one"]);
            assert_eq!(
                findings(&out),
                vec![(
                    "L001",
                    "malformed JPEG: truncated segment",
                    9,
                    bytes.len() as u64
                )]
            );
            assert_eq!(out.skip, Some(SkipReason::Malformed));
        }
    }

    #[test]
    fn an_invalid_length_stops_the_walk_and_marks_the_jpeg_malformed() {
        let short = jpeg(&[
            seg(0xFE, b"one"),
            vec![0xFF, 0xFE, 0x00, 0x01],
            seg(0xFE, b"two"),
        ]);
        let out = scan_jpeg(&short, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG COM: one"]);
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed JPEG: invalid segment length", 9, 13)]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
    }

    fn after_eoi(tail: &[u8]) -> DetectorOutput {
        let mut bytes = jpeg(&[seg(0xFE, b"one"), vec![0xFF, 0xD9]]);
        bytes.extend_from_slice(tail);
        scan_jpeg(&bytes, &mut budget())
    }

    fn ftyp_box(size: u32, brand: &[u8; 4], extra: usize) -> Vec<u8> {
        let mut v = size.to_be_bytes().to_vec();
        v.extend_from_slice(b"ftyp");
        v.extend_from_slice(brand);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend(std::iter::repeat_n(b'i', extra));
        v
    }

    #[test]
    fn a_samsung_motion_photo_is_listed_without_b004() {
        for (mp4, rest) in [
            (ftyp_box(16, b"mp42", 0), &b"\0\0\0\x08mdat SEFH SEFT"[..]),
            (ftyp_box(24, b"qt  ", 8), &b"\0\0\0\x08mdat SEFH SEFT"[..]),
            (ftyp_box(20, b"isom", 4), &b""[..]),
        ] {
            let mut tail = b"MotionPhoto_Data".to_vec();
            tail.extend_from_slice(&mp4);
            tail.extend_from_slice(rest);
            let out = after_eoi(&tail);
            assert!(out.findings.is_empty(), "{mp4:?}");
            assert_eq!(texts(&out), vec!["JPEG COM: one"]);
            assert_eq!(out.embedded.len(), 1);
            let blob = &out.embedded[0];
            assert_eq!(
                (blob.kind, blob.format),
                (FileKind::UnknownBinary, Some("mp4/mov"))
            );
            let span = (blob.span.byte_start, blob.span.byte_end);
            assert_eq!(span, (11, 11 + tail.len() as u64));
        }
    }

    #[test]
    fn anything_else_after_the_motion_photo_marker_stays_b004() {
        let marker = b"MotionPhoto_Data".to_vec();
        let with = |rest: &[u8]| [marker.as_slice(), rest].concat();
        let mut avif = 20u32.to_be_bytes().to_vec();
        avif.extend_from_slice(b"ftypavif\0\0\0\0mif1");
        let tails = [
            marker.clone(),
            with(b"junk after the marker"),
            with(&ftyp_box(12, b"mp42", 0)),
            with(&ftyp_box(18, b"mp42", 2)),
            with(&ftyp_box(24, b"mp42", 4)),
            with(&ftyp_box(16, b"mp\x004", 0)),
            with(&avif),
            [b"motionphoto_data".as_slice(), &ftyp_box(16, b"mp42", 0)].concat(),
            [b"xMotionPhoto_Data".as_slice(), &ftyp_box(16, b"mp42", 0)].concat(),
        ];
        for tail in tails {
            let out = after_eoi(&tail);
            assert_eq!(
                findings(&out),
                vec![(
                    "B004",
                    "data after the end of the image",
                    11,
                    11 + tail.len() as u64
                )],
                "{tail:?}"
            );
        }
    }

    #[test]
    fn readable_stray_bytes_are_b005() {
        let stray = b"meet me at the usual place".to_vec();
        let bytes = jpeg(&[seg(0xFE, b"one"), stray, seg(0xFE, b"two")]);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(
            findings(&out),
            vec![
                ("L001", "malformed JPEG: bytes between segments", 9, 35),
                ("B005", "readable text hidden in the image", 9, 35)
            ]
        );
    }

    #[test]
    fn stray_bytes_between_segments_are_a_hidden_carrier_and_mark_the_jpeg_malformed() {
        let bytes = jpeg(&[seg(0xFE, b"one"), vec![0x41, 0x42], seg(0xFE, b"two")]);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "JPEG COM: one",
                "JPEG bytes between segments: AB",
                "JPEG COM: two"
            ]
        );
        assert!(out.carriers[1].hidden);
        assert_eq!(
            (
                out.carriers[1].span.byte_start,
                out.carriers[1].span.byte_end
            ),
            (9, 11)
        );
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed JPEG: bytes between segments", 9, 11)]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
        let padded = jpeg(&[seg(0xFE, b"one"), vec![0x00], seg(0xFE, b"two")]);
        let out = scan_jpeg(&padded, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG COM: one", "JPEG COM: two"]);
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed JPEG: bytes between segments", 9, 10)]
        );
        let marker = jpeg(&[seg(0xFE, b"one"), vec![0xFF, 0x00], seg(0xFE, b"two")]);
        let out = scan_jpeg(&marker, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG COM: one", "JPEG COM: two"]);
        assert!(out.findings.is_empty());
        let mut unterminated = jpeg(&[seg(0xFE, b"one")]);
        unterminated.extend_from_slice(b"XYZ");
        let out = scan_jpeg(&unterminated, &mut budget());
        assert_eq!(
            texts(&out),
            vec!["JPEG COM: one", "JPEG bytes between segments: XYZ"]
        );
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed JPEG: bytes between segments", 9, 12)]
        );
    }

    #[test]
    fn corrupt_exif_in_app1_is_malformed_and_the_walk_continues() {
        let bytes = jpeg(&[seg(0xE1, b"Exif\0\0garbage"), seg(0xFE, b"after")]);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG COM: after"]);
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed EXIF: invalid TIFF header", 12, 19)]
        );
    }

    #[test]
    fn non_jpeg_or_tiny_input_gives_nothing() {
        for bytes in [&b""[..], &[0xFF][..], &[0xFF, 0xD8][..], &b"GIF89a"[..]] {
            let out = scan_jpeg(bytes, &mut budget());
            assert!(out.carriers.is_empty() && out.findings.is_empty());
        }
    }

    #[test]
    fn expired_deadline_sets_timeout() {
        let limits = Limits {
            per_file_time: Duration::ZERO,
            ..Limits::default()
        };
        let bytes = jpeg(&[seg(0xFE, b"one")]);
        let out = scan_jpeg(&bytes, &mut Budget::new(&limits));
        assert_eq!(out.skip, Some(SkipReason::Timeout));
        assert!(out.carriers.is_empty());
    }

    #[test]
    fn many_one_character_xmp_attributes_are_not_b003() {
        let element = b"<e a=\"x\" b=\"x\" c=\"x\" d=\"x\" e=\"x\" f=\"x\" g=\"x\" h=\"x\"/>";
        let mut packet = Vec::new();
        while packet.len() + element.len() <= 60_000 {
            packet.extend_from_slice(element);
        }
        let mut payload = XMP_NS.to_vec();
        payload.extend_from_slice(&packet);
        let segments: Vec<Vec<u8>> = (0..16).map(|_| seg(0xE1, &payload)).collect();
        let out = scan_jpeg(&jpeg(&segments), &mut budget());
        assert!(out.carriers.len() > 100_000);
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }
}

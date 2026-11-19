use super::{Sink, lossy, sub};
use crate::limits::Budget;
use crate::model::{DetectorOutput, SkipReason};

const EXIF_PREFIX: &[u8] = b"Exif\0\0";
const XMP_PREFIX: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
const EXTENDED_PREFIX: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
const GUID_LEN: usize = 32;
const EXTENDED_HEADER_LEN: usize = GUID_LEN + 8;
const MAX_EXTENDED_GUIDS: usize = 16;

struct Assembly {
    guid: [u8; GUID_LEN],
    full: usize,
    data: Vec<u8>,
    start: usize,
    end: usize,
    rejected: bool,
}

fn be32(bytes: &[u8], at: usize) -> Option<usize> {
    let raw = <[u8; 4]>::try_from(sub(bytes, at, 4)?).ok()?;
    usize::try_from(u32::from_be_bytes(raw)).ok()
}

fn extended_chunk(
    assemblies: &mut Vec<Assembly>,
    rest: &[u8],
    start: usize,
    sink: &mut Sink,
    budget: &Budget,
) {
    let (Some(guid), Some(full), Some(offset), Some(data)) = (
        rest.get(..GUID_LEN)
            .and_then(|g| <[u8; GUID_LEN]>::try_from(g).ok()),
        be32(rest, GUID_LEN),
        be32(rest, GUID_LEN + 4),
        rest.get(EXTENDED_HEADER_LEN..),
    ) else {
        return;
    };
    let data_start = start + EXTENDED_HEADER_LEN;
    let index = match assemblies.iter().position(|a| a.guid == guid) {
        Some(index) => index,
        None => {
            if assemblies.len() >= MAX_EXTENDED_GUIDS {
                return;
            }
            let rejected =
                u64::try_from(full).unwrap_or(u64::MAX) > budget.remaining_decompressed();
            if rejected {
                sink.limit_hit(
                    data_start,
                    data_start + data.len(),
                    "extended XMP declares a length past the decompression budget",
                );
            }
            assemblies.push(Assembly {
                guid,
                full,
                data: Vec::new(),
                start: data_start,
                end: data_start,
                rejected,
            });
            assemblies.len() - 1
        }
    };
    let assembly = &mut assemblies[index];
    let fits = assembly
        .data
        .len()
        .checked_add(data.len())
        .is_some_and(|n| n <= assembly.full);
    if assembly.rejected || offset != assembly.data.len() || !fits {
        return;
    }
    assembly.data.extend_from_slice(data);
    assembly.end = data_start + data.len();
}

pub fn scan_jpeg(bytes: &[u8], budget: &mut Budget) -> DetectorOutput {
    let mut sink = Sink::new();
    if !bytes.starts_with(&[0xFF, 0xD8]) {
        return sink.out;
    }
    let mut assemblies: Vec<Assembly> = Vec::new();
    let mut at = 2usize;
    loop {
        if budget.deadline_exceeded() {
            sink.timed_out();
            break;
        }
        if bytes.get(at) != Some(&0xFF) {
            break;
        }
        while bytes.get(at + 1) == Some(&0xFF) {
            at += 1;
        }
        let Some(&marker) = bytes.get(at + 1) else {
            break;
        };
        at += 2;
        match marker {
            0x00 | 0xD9 | 0xDA => break,
            0x01 | 0xD0..=0xD8 => continue,
            _ => {}
        }
        let Some(length) = sub(bytes, at, 2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        else {
            break;
        };
        if length < 2 {
            break;
        }
        let start = at + 2;
        let Some(payload) = sub(bytes, start, length - 2) else {
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
            0xE1 => {
                if let Some(tiff) = payload.strip_prefix(EXIF_PREFIX) {
                    sink.exif(tiff, start + EXIF_PREFIX.len(), budget);
                } else if let Some(packet) = payload.strip_prefix(XMP_PREFIX) {
                    sink.xmp(
                        "JPEG XMP",
                        packet,
                        start + XMP_PREFIX.len(),
                        start + payload.len(),
                        budget,
                    );
                } else if let Some(rest) = payload.strip_prefix(EXTENDED_PREFIX) {
                    extended_chunk(
                        &mut assemblies,
                        rest,
                        start + EXTENDED_PREFIX.len(),
                        &mut sink,
                        budget,
                    );
                }
            }
            _ => {}
        }
        if sink.out.skip == Some(SkipReason::Timeout) {
            break;
        }
    }
    if sink.out.skip != Some(SkipReason::Timeout) {
        for assembly in assemblies.iter().filter(|a| !a.rejected) {
            sink.xmp(
                "JPEG XMP",
                &assembly.data,
                assembly.start,
                assembly.end,
                budget,
            );
        }
    }
    sink.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::model::{CarrierKind, Family, SkipReason};
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
            vec!["JPEG COM: hello", "EXIF ImageDescription: hello"]
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
        assert_eq!((ex.span.byte_start, ex.span.byte_end), (21, 53));
        assert_eq!(ex.evidence, EXIF_HELLO.to_vec());
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
        assert_eq!(texts(&out), vec!["JPEG XMP: hidden words"]);
        assert_eq!(
            (
                out.carriers[0].span.byte_start,
                out.carriers[0].span.byte_end
            ),
            (35, 35 + xml.len() as u64)
        );
    }

    #[test]
    fn extended_xmp_chunks_are_reassembled_by_guid() {
        let xml = xmp_doc("ext words");
        let (a, b) = xml.as_bytes().split_at(40);
        let full = xml.len() as u32;
        let bytes = jpeg(&[ext_seg(full, 0, a), ext_seg(full, 40, b)]);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG XMP: ext words"]);
    }

    #[test]
    fn extended_xmp_chunk_out_of_order_or_past_full_length_is_ignored() {
        let (a, b) = (&b"<a>one</a>"[..], &b"<b>two</b>"[..]);
        let both = jpeg(&[ext_seg(20, 0, a), ext_seg(20, 10, b)]);
        assert_eq!(
            texts(&scan_jpeg(&both, &mut budget())),
            vec!["JPEG XMP: one", "JPEG XMP: two"]
        );
        let gap = jpeg(&[ext_seg(20, 0, a), ext_seg(20, 11, b)]);
        assert_eq!(
            texts(&scan_jpeg(&gap, &mut budget())),
            vec!["JPEG XMP: one"]
        );
        let short = jpeg(&[ext_seg(19, 0, a), ext_seg(19, 10, b)]);
        assert_eq!(
            texts(&scan_jpeg(&short, &mut budget())),
            vec!["JPEG XMP: one"]
        );
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

    #[test]
    fn reading_stops_at_eoi_and_at_sos() {
        let eoi = jpeg(&[seg(0xFE, b"one"), vec![0xFF, 0xD9], seg(0xFE, b"two")]);
        assert_eq!(
            texts(&scan_jpeg(&eoi, &mut budget())),
            vec!["JPEG COM: one"]
        );
        let sos = jpeg(&[seg(0xFE, b"one"), seg(0xDA, &[1, 2, 3]), seg(0xFE, b"two")]);
        assert_eq!(
            texts(&scan_jpeg(&sos, &mut budget())),
            vec!["JPEG COM: one"]
        );
    }

    #[test]
    fn truncated_segment_keeps_earlier_carriers() {
        let mut bytes = jpeg(&[seg(0xFE, b"one")]);
        bytes.extend_from_slice(&[0xFF, 0xFE, 0x00, 0xFF, b'a', b'b']);
        let out = scan_jpeg(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["JPEG COM: one"]);
    }

    #[test]
    fn invalid_length_or_missing_marker_prefix_stops_the_walk() {
        let short = jpeg(&[
            seg(0xFE, b"one"),
            vec![0xFF, 0xFE, 0x00, 0x01],
            seg(0xFE, b"two"),
        ]);
        assert_eq!(
            texts(&scan_jpeg(&short, &mut budget())),
            vec!["JPEG COM: one"]
        );
        let stray = jpeg(&[seg(0xFE, b"one"), vec![0x00], seg(0xFE, b"two")]);
        assert_eq!(
            texts(&scan_jpeg(&stray, &mut budget())),
            vec!["JPEG COM: one"]
        );
    }

    #[test]
    fn corrupt_exif_in_app1_is_ignored_and_walk_continues() {
        let bytes = jpeg(&[seg(0xE1, b"Exif\0\0garbage"), seg(0xFE, b"after")]);
        assert_eq!(
            texts(&scan_jpeg(&bytes, &mut budget())),
            vec!["JPEG COM: after"]
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
}

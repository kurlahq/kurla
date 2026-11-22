pub mod bmff;
pub mod exif;
pub mod gif;
pub mod jpeg;
pub mod png;
pub mod xmp;

pub use bmff::{scan_avif, scan_webp};
pub use exif::{ExifError, exif_text_fields};
pub use gif::scan_gif;
pub use jpeg::scan_jpeg;
pub use png::scan_png;
pub use xmp::xmp_text;

use crate::limits::Budget;
use crate::model::{
    Carrier, CarrierKind, DetectorOutput, Family, FileKind, RawFinding, RuleStatus, Severity,
    SkipReason, Span,
};
use crate::text::TextDoc;

pub(crate) const EVIDENCE_CAP: usize = 4096;

const FTYP_BRANDS: [&[u8; 4]; 9] = [
    b"avif", b"avis", b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1",
];
const FTYP_MAX_COMPATIBLE: usize = 64;
const OUTPUT_CAP_SLACK: usize = 64 * 1024;
const OTHER_IMAGE_EXTENSIONS: [&str; 13] = [
    "svgz", "bmp", "tif", "tiff", "ico", "cur", "jxl", "psd", "tga", "jp2", "j2k", "emf", "wmf",
];

fn is_brand(chunk: &[u8]) -> bool {
    FTYP_BRANDS.iter().any(|b| chunk == b.as_slice())
}

fn is_avif(bytes: &[u8]) -> bool {
    if bytes.get(4..8) != Some(b"ftyp".as_slice()) {
        return false;
    }
    let declared = bytes
        .get(0..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_be_bytes);
    let (major_at, end) = match declared {
        0 => (8usize, bytes.len()),
        1 => {
            let large = bytes
                .get(8..16)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map_or(0, u64::from_be_bytes);
            (16, usize::try_from(large).unwrap_or(usize::MAX))
        }
        n => (8, usize::try_from(n).unwrap_or(usize::MAX)),
    };
    if bytes.get(major_at..major_at + 4).is_some_and(is_brand) {
        return true;
    }
    let compatible_at = major_at + 8;
    let limit = compatible_at + 4 * FTYP_MAX_COMPATIBLE;
    let end = end.min(bytes.len()).min(limit);
    bytes
        .get(compatible_at..end)
        .is_some_and(|rest| rest.as_chunks::<4>().0.iter().any(|c| is_brand(c)))
}

pub fn sniff(bytes: &[u8], path: &str) -> FileKind {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return FileKind::Png;
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return FileKind::Jpeg;
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return FileKind::Gif;
    }
    if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP".as_slice()) {
        return FileKind::Webp;
    }
    if is_avif(bytes) {
        return FileKind::Avif;
    }
    if bytes.starts_with(b"%PDF-") {
        return FileKind::Pdf;
    }
    let extension = std::path::Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    match extension.as_deref() {
        Some("svg") if TextDoc::decode(bytes).is_some() => return FileKind::Svg,
        Some(ext) if OTHER_IMAGE_EXTENSIONS.contains(&ext) => return FileKind::OtherImage,
        _ => {}
    }
    if TextDoc::decode(bytes).is_some() {
        FileKind::Text
    } else {
        FileKind::UnknownBinary
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Placement {
    Mapped(usize),
    Whole(usize, usize),
}

pub(crate) struct Sink {
    pub out: DetectorOutput,
    pub stop: bool,
    input_len: usize,
    inflated: usize,
    used: usize,
}

impl Sink {
    pub fn new(input_len: usize) -> Sink {
        Sink {
            out: DetectorOutput {
                findings: Vec::new(),
                carriers: Vec::new(),
                skip: None,
            },
            stop: false,
            input_len,
            inflated: 0,
            used: 0,
        }
    }

    pub(crate) fn add_inflated(&mut self, len: usize) {
        self.inflated = self.inflated.saturating_add(len);
    }

    fn cap(&self) -> usize {
        self.input_len
            .saturating_add(self.inflated)
            .saturating_mul(3)
            .saturating_add(OUTPUT_CAP_SLACK)
    }

    fn set_skip(&mut self, reason: SkipReason) {
        if self.out.skip.is_none() {
            self.out.skip = Some(reason);
        }
    }

    fn l001(&mut self, message: &str, start: usize, end: usize) {
        self.set_skip(SkipReason::SizeLimit);
        self.out.findings.push(RawFinding {
            rule_id: "L001",
            family: Family::L,
            base: Severity::Low,
            status: RuleStatus::Stable,
            span: span(start, end),
            carrier: CarrierKind::ResourceLimit,
            payload: None,
            message: message.to_string(),
            evidence: Vec::new(),
        });
    }

    pub(crate) fn amplification(&mut self, start: usize, end: usize) {
        self.set_skip(SkipReason::SizeLimit);
        self.out.findings.push(RawFinding {
            rule_id: "B003",
            family: Family::B,
            base: Severity::High,
            status: RuleStatus::Stable,
            span: span(start, end),
            carrier: CarrierKind::ResourceLimit,
            payload: None,
            message: "metadata amplification".to_string(),
            evidence: Vec::new(),
        });
    }

    pub fn carrier(
        &mut self,
        label: &str,
        text: &str,
        start: usize,
        end: usize,
        evidence: &[u8],
    ) -> bool {
        if self.stop {
            return false;
        }
        if text.is_empty() {
            return true;
        }
        let evidence = &evidence[..evidence.len().min(EVIDENCE_CAP)];
        let full = format!("{label}: {text}");
        let cost = text.len().saturating_add(evidence.len());
        if self.used.saturating_add(cost) > self.cap() {
            self.stop = true;
            self.amplification(start, end);
            return false;
        }
        self.used += cost;
        self.out.carriers.push(Carrier {
            kind: CarrierKind::MetadataField,
            text: full,
            span: span(start, end),
            hidden: false,
            evidence: evidence.to_vec(),
        });
        true
    }

    pub fn exif(&mut self, tiff: &[u8], base: usize, budget: &Budget) {
        self.exif_at("EXIF", tiff, Placement::Mapped(base), budget);
    }

    pub fn exif_at(&mut self, label: &str, tiff: &[u8], placement: Placement, budget: &Budget) {
        let expired = || budget.deadline_exceeded();
        let (block_start, block_end) = match placement {
            Placement::Mapped(base) => (base, base + tiff.len()),
            Placement::Whole(start, end) => (start, end),
        };
        let mut emit = |value: exif::Value| {
            let evidence = tiff.get(value.start..value.end).unwrap_or_default();
            let (start, end) = match placement {
                Placement::Mapped(base) => (base + value.start, base + value.end),
                Placement::Whole(start, end) => (start, end),
            };
            self.carrier(
                &format!("{label} {}", value.name),
                &value.text,
                start,
                end,
                evidence,
            )
        };
        let Ok(outcome) = exif::parse_values(tiff, &expired, &mut emit) else {
            return;
        };
        if outcome.timed_out {
            self.timed_out();
        }
        if outcome.entry_limit && !self.stop {
            self.l001("EXIF entry limit", block_start, block_end);
        }
    }

    pub fn xmp(
        &mut self,
        label: &str,
        packet: &[u8],
        start: usize,
        end: usize,
        mapped: bool,
        budget: &Budget,
    ) {
        let mut emit = |text: &str, range: Option<(usize, usize)>| match range {
            Some((a, b)) if mapped && a <= b && b <= packet.len() => {
                self.carrier(label, text, start + a, start + b, &packet[a..b])
            }
            _ => self.carrier(label, text, start, end, text.as_bytes()),
        };
        xmp::scan(packet, budget, &mut emit);
        if budget.deadline_exceeded() {
            self.timed_out();
        }
    }

    pub fn limit_hit(&mut self, start: usize, end: usize, message: &str) {
        self.set_skip(SkipReason::DecompressionLimit);
        self.out.findings.push(RawFinding {
            rule_id: "B002",
            family: Family::B,
            base: Severity::High,
            status: RuleStatus::Stable,
            span: span(start, end),
            carrier: CarrierKind::ResourceLimit,
            payload: None,
            message: message.to_string(),
            evidence: Vec::new(),
        });
    }

    pub fn timed_out(&mut self) {
        self.set_skip(SkipReason::Timeout);
        self.stop = true;
    }
}

pub(crate) fn span(start: usize, end: usize) -> Span {
    Span {
        byte_start: start as u64,
        byte_end: end as u64,
        line: None,
        column: None,
    }
}

pub(crate) fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

pub(crate) fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

pub(crate) fn sub(bytes: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    bytes.get(start..start.checked_add(len)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ftyp(major: &[u8; 4], compatible: &[&[u8; 4]]) -> Vec<u8> {
        let size = 16 + 4 * compatible.len();
        let mut v = Vec::new();
        v.extend_from_slice(&(size as u32).to_be_bytes());
        v.extend_from_slice(b"ftyp");
        v.extend_from_slice(major);
        v.extend_from_slice(&[0, 0, 0, 0]);
        for brand in compatible {
            v.extend_from_slice(*brand);
        }
        v
    }

    #[test]
    fn sniff_png_magic() {
        let bytes = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0];
        assert_eq!(sniff(&bytes, "a.bin"), FileKind::Png);
    }

    #[test]
    fn sniff_jpeg_magic() {
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0], "a.bin"), FileKind::Jpeg);
        assert_eq!(sniff(&[0xFF, 0xD8, 0x00], "a.jpg"), FileKind::UnknownBinary);
    }

    #[test]
    fn sniff_gif_both_versions() {
        assert_eq!(sniff(b"GIF87a\x01\x00", "a"), FileKind::Gif);
        assert_eq!(sniff(b"GIF89a\x01\x00", "a"), FileKind::Gif);
        assert_ne!(sniff(b"GIF88a\x01\x00", "a"), FileKind::Gif);
    }

    #[test]
    fn sniff_webp_needs_riff_and_webp_tag() {
        assert_eq!(sniff(b"RIFF\x10\x00\x00\x00WEBPVP8 ", "a"), FileKind::Webp);
        assert_ne!(sniff(b"RIFF\x10\x00\x00\x00WAVEfmt ", "a"), FileKind::Webp);
    }

    #[test]
    fn sniff_avif_by_major_brand() {
        for brand in [
            b"avif", b"avis", b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1",
        ] {
            assert_eq!(sniff(&ftyp(brand, &[]), "a"), FileKind::Avif);
        }
    }

    #[test]
    fn sniff_avif_by_compatible_brand() {
        assert_eq!(
            sniff(&ftyp(b"isom", &[b"iso2", b"mif1"]), "a"),
            FileKind::Avif
        );
    }

    #[test]
    fn sniff_plain_iso_bmff_is_not_avif() {
        assert_ne!(
            sniff(&ftyp(b"isom", &[b"iso2", b"mp41"]), "a.mp4"),
            FileKind::Avif
        );
    }

    #[test]
    fn sniff_ftyp_compatible_brands_stop_at_box_size() {
        let mut v = ftyp(b"isom", &[b"mp41"]);
        v.extend_from_slice(b"avif");
        assert_ne!(sniff(&v, "a"), FileKind::Avif);
    }

    #[test]
    fn sniff_pdf_magic() {
        assert_eq!(sniff(b"%PDF-1.7\n", "a.txt"), FileKind::Pdf);
    }

    #[test]
    fn sniff_svg_extension_needs_decodable_text() {
        assert_eq!(sniff(b"<svg/>", "dir/a.SVG"), FileKind::Svg);
        assert_eq!(
            sniff(&[0x80, 0x81, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05], "a.svg"),
            FileKind::UnknownBinary
        );
    }

    #[test]
    fn sniff_other_image_extensions() {
        for ext in [
            "svgz", "bmp", "tif", "tiff", "ico", "cur", "jxl", "psd", "tga", "jp2", "j2k", "emf",
            "wmf",
        ] {
            assert_eq!(
                sniff(&[0x80, 0x00, 0x01], &format!("x/a.{ext}")),
                FileKind::OtherImage,
                "{ext}"
            );
        }
        assert_eq!(sniff(b"hello", "a.BMP"), FileKind::OtherImage);
    }

    #[test]
    fn sniff_magic_beats_extension() {
        let bytes = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(sniff(&bytes, "a.svg"), FileKind::Png);
        assert_eq!(sniff(b"GIF89a\x01\x00", "a.bmp"), FileKind::Gif);
    }

    #[test]
    fn sniff_text_and_unknown_binary_fallbacks() {
        assert_eq!(sniff(b"just some text\n", "notes.txt"), FileKind::Text);
        assert_eq!(sniff(b"just some text\n", "noext"), FileKind::Text);
        assert_eq!(
            sniff(&[0x80, 0x81, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05], "a.dat"),
            FileKind::UnknownBinary
        );
    }

    #[test]
    fn sniff_ftyp_size_zero_reads_brands_to_end_of_file() {
        let mut v = vec![0, 0, 0, 0];
        v.extend_from_slice(b"ftypisom");
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(b"iso2mif1");
        assert_eq!(sniff(&v, "a"), FileKind::Avif);
    }

    #[test]
    fn sniff_ftyp_size_one_uses_the_64_bit_largesize_layout() {
        let mut compatible = vec![0, 0, 0, 1];
        compatible.extend_from_slice(b"ftyp");
        compatible.extend_from_slice(&28u64.to_be_bytes());
        compatible.extend_from_slice(b"isom");
        compatible.extend_from_slice(&[0, 0, 0, 0]);
        compatible.extend_from_slice(b"mif1");
        assert_eq!(sniff(&compatible, "a"), FileKind::Avif);
        let mut major = vec![0, 0, 0, 1];
        major.extend_from_slice(b"ftyp");
        major.extend_from_slice(&24u64.to_be_bytes());
        major.extend_from_slice(b"avif");
        major.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(sniff(&major, "a"), FileKind::Avif);
    }

    #[test]
    fn sniff_ftyp_reads_at_most_sixty_four_compatible_brands() {
        let build = |fillers: usize| {
            let mut v = vec![0, 0, 0, 0];
            v.extend_from_slice(b"ftypisom");
            v.extend_from_slice(&[0, 0, 0, 0]);
            for _ in 0..fillers {
                v.extend_from_slice(b"mp41");
            }
            v.extend_from_slice(b"avif");
            v
        };
        assert_eq!(sniff(&build(63), "a"), FileKind::Avif);
        assert_ne!(sniff(&build(64), "a"), FileKind::Avif);
    }

    fn plain_budget() -> Budget {
        Budget::new(&crate::limits::Limits::default())
    }

    fn many_inline_entries(count: usize) -> Vec<u8> {
        let mut v = vec![b'I', b'I', 0x2A, 0x00, 0x08, 0, 0, 0];
        v.extend_from_slice(&(count as u16).to_le_bytes());
        for _ in 0..count {
            v.extend_from_slice(&0x010Fu16.to_le_bytes());
            v.extend_from_slice(&2u16.to_le_bytes());
            v.extend_from_slice(&2u32.to_le_bytes());
            v.extend_from_slice(&[b'a', 0, 0, 0]);
        }
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    #[test]
    fn the_output_cap_for_an_empty_input_is_exactly_sixty_four_kib() {
        let mut exact = Sink::new(0);
        assert!(exact.carrier("L", &"a".repeat(65536), 0, 1, &[]));
        assert!(!exact.stop);
        assert_eq!(exact.out.carriers.len(), 1);
        assert!(exact.out.findings.is_empty());
        let mut over = Sink::new(0);
        assert!(!over.carrier("L", &"a".repeat(65537), 0, 1, &[]));
        assert!(over.stop);
        assert!(over.out.carriers.is_empty());
        assert_eq!(over.out.findings.len(), 1);
        assert_eq!(over.out.findings[0].rule_id, "B003");
        assert_eq!(over.out.skip, Some(SkipReason::SizeLimit));
    }

    #[test]
    fn carrier_costs_add_up_to_the_cap_and_the_next_byte_is_refused() {
        let mut sink = Sink::new(0);
        assert!(sink.carrier("L", &"a".repeat(65535), 0, 1, &[]));
        assert!(sink.carrier("L", "a", 0, 1, &[]));
        assert!(!sink.carrier("L", "a", 0, 1, &[]));
        assert!(sink.stop);
        assert_eq!(sink.out.carriers.len(), 2);
    }

    #[test]
    fn exif_entry_limit_finding_spans_the_whole_block_at_its_base_offset() {
        let tiff = many_inline_entries(1001);
        assert_eq!(tiff.len(), 8 + 2 + 1001 * 12 + 4);
        let mut sink = Sink::new(100 + tiff.len());
        sink.exif(&tiff, 100, &plain_budget());
        assert_eq!(sink.out.carriers.len(), 1000);
        assert_eq!(sink.out.findings.len(), 1);
        let finding = &sink.out.findings[0];
        assert_eq!(finding.rule_id, "L001");
        assert_eq!(finding.span.byte_start, 100);
        assert_eq!(finding.span.byte_end, 100 + 12026);
    }

    #[test]
    fn unmapped_xmp_text_is_reported_over_the_whole_packet_span() {
        let packet = b"<a>hello</a>";
        let mut unmapped = Sink::new(packet.len());
        unmapped.xmp("XMP", packet, 100, 112, false, &plain_budget());
        assert_eq!(unmapped.out.carriers.len(), 1);
        let carrier = &unmapped.out.carriers[0];
        assert_eq!(carrier.text, "XMP: hello");
        assert_eq!(carrier.span.byte_start, 100);
        assert_eq!(carrier.span.byte_end, 112);
        assert_eq!(carrier.evidence, b"hello".to_vec());
        let mut mapped = Sink::new(packet.len());
        mapped.xmp("XMP", packet, 100, 112, true, &plain_budget());
        assert_eq!(mapped.out.carriers.len(), 1);
        let carrier = &mapped.out.carriers[0];
        assert_eq!(carrier.span.byte_start, 103);
        assert_eq!(carrier.span.byte_end, 108);
        assert_eq!(carrier.evidence, b"hello".to_vec());
    }
}

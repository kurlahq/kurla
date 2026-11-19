pub mod exif;
pub mod gif;
pub mod jpeg;
pub mod png;
pub mod xmp;

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
const FTYP_SCAN_CAP: usize = 4096;
const OTHER_IMAGE_EXTENSIONS: [&str; 13] = [
    "svgz", "bmp", "tif", "tiff", "ico", "cur", "jxl", "psd", "tga", "jp2", "j2k", "emf", "wmf",
];

fn is_avif(bytes: &[u8]) -> bool {
    if bytes.get(4..8) != Some(b"ftyp".as_slice()) {
        return false;
    }
    let declared = bytes
        .get(0..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_be_bytes);
    let end = usize::try_from(declared)
        .unwrap_or(usize::MAX)
        .clamp(16, FTYP_SCAN_CAP)
        .min(bytes.len());
    let is_brand = |chunk: &[u8]| FTYP_BRANDS.iter().any(|b| chunk == b.as_slice());
    if bytes.get(8..12).is_some_and(is_brand) {
        return true;
    }
    bytes
        .get(16..end)
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

pub(crate) struct Sink {
    pub out: DetectorOutput,
}

impl Sink {
    pub fn new() -> Sink {
        Sink {
            out: DetectorOutput {
                findings: Vec::new(),
                carriers: Vec::new(),
                skip: None,
            },
        }
    }

    pub fn carrier(&mut self, label: &str, text: &str, start: usize, end: usize, evidence: &[u8]) {
        if text.is_empty() {
            return;
        }
        self.out.carriers.push(Carrier {
            kind: CarrierKind::MetadataField,
            text: format!("{label}: {text}"),
            span: span(start, end),
            hidden: false,
            evidence: evidence[..evidence.len().min(EVIDENCE_CAP)].to_vec(),
        });
    }

    pub fn exif(&mut self, tiff: &[u8], start: usize, budget: &Budget) {
        let expired = || budget.deadline_exceeded();
        if let Ok((fields, timed_out)) = exif::parse(tiff, &expired) {
            for (name, text) in fields {
                self.carrier(
                    &format!("EXIF {name}"),
                    &text,
                    start,
                    start + tiff.len(),
                    tiff,
                );
            }
            if timed_out {
                self.out.skip = Some(SkipReason::Timeout);
            }
        }
    }

    pub fn xmp(&mut self, label: &str, packet: &[u8], start: usize, end: usize, budget: &Budget) {
        for text in xmp::text(packet, budget) {
            self.carrier(label, &text, start, end, packet);
        }
        if budget.deadline_exceeded() {
            self.out.skip = Some(SkipReason::Timeout);
        }
    }

    pub fn limit_hit(&mut self, start: usize, end: usize, message: &str) {
        self.out.skip = Some(SkipReason::DecompressionLimit);
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
        self.out.skip = Some(SkipReason::Timeout);
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
}

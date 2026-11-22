use kurla::binary::{exif_text_fields, scan_jpeg, scan_png, scan_webp};
use kurla::limits::{Budget, Limits};

use crate::spans;

const MAX_APP1_TIFF: usize = 60_000;

pub fn limits() -> Limits {
    Limits {
        max_decompressed_bytes: 4096,
        ..Limits::default()
    }
}

fn in_jpeg(tiff: &[u8]) -> Vec<u8> {
    let mut payload = b"Exif\0\0".to_vec();
    payload.extend_from_slice(tiff);
    let mut out = vec![0xFF, 0xD8, 0xFF, 0xE1];
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

fn in_png(tiff: &[u8]) -> Vec<u8> {
    let mut out = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    out.extend_from_slice(&(tiff.len() as u32).to_be_bytes());
    out.extend_from_slice(b"eXIf");
    out.extend_from_slice(tiff);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

fn in_webp(tiff: &[u8]) -> Vec<u8> {
    let mut body = b"WEBPEXIF".to_vec();
    body.extend_from_slice(&(tiff.len() as u32).to_le_bytes());
    body.extend_from_slice(tiff);
    if tiff.len() % 2 == 1 {
        body.push(0);
    }
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

pub fn check(data: &[u8]) {
    let _ = exif_text_fields(data);
    let tiff = &data[..data.len().min(MAX_APP1_TIFF)];
    let jpeg = in_jpeg(tiff);
    let mut budget = Budget::new(&limits());
    let out = scan_jpeg(&jpeg, &mut budget);
    spans::check_spans(
        jpeg.len(),
        "exif in jpeg",
        &out.findings,
        &out.carriers,
        &[],
    );
    let png = in_png(data);
    let mut budget = Budget::new(&limits());
    let out = scan_png(&png, &mut budget);
    spans::check_spans(png.len(), "exif in png", &out.findings, &out.carriers, &[]);
    let webp = in_webp(data);
    let mut budget = Budget::new(&limits());
    let out = scan_webp(&webp, &mut budget);
    spans::check_spans(
        webp.len(),
        "exif in webp",
        &out.findings,
        &out.carriers,
        &[],
    );
}

use std::collections::HashSet;

use super::{lossy, sub};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExifError {
    BadHeader,
}

const MAX_IFD_ENTRIES: usize = 1000;
const ENTRY_LEN: usize = 12;
const TAG_EXIF_IFD: u16 = 0x8769;
const TAG_USER_COMMENT: u16 = 0x9286;
const TAG_XP_FIRST: u16 = 0x9C9B;
const TAG_XP_LAST: u16 = 0x9C9F;
const TYPE_BYTE: u16 = 1;
const TYPE_ASCII: u16 = 2;
const TYPE_UNDEFINED: u16 = 7;

#[derive(Clone, Copy)]
struct Order {
    big: bool,
}

impl Order {
    fn u16(self, bytes: &[u8], at: usize) -> Option<u16> {
        let raw = <[u8; 2]>::try_from(sub(bytes, at, 2)?).ok()?;
        Some(if self.big {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        })
    }

    fn u32(self, bytes: &[u8], at: usize) -> Option<u32> {
        let raw = <[u8; 4]>::try_from(sub(bytes, at, 4)?).ok()?;
        Some(if self.big {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        })
    }
}

fn tag_name(tag: u16) -> String {
    let known = match tag {
        0x010E => "ImageDescription",
        0x010F => "Make",
        0x0110 => "Model",
        0x0131 => "Software",
        0x0132 => "DateTime",
        0x013B => "Artist",
        0x8298 => "Copyright",
        0x9003 => "DateTimeOriginal",
        0x9004 => "DateTimeDigitized",
        0x9286 => "UserComment",
        0x9C9B => "XPTitle",
        0x9C9C => "XPComment",
        0x9C9D => "XPAuthor",
        0x9C9E => "XPKeywords",
        0x9C9F => "XPSubject",
        0xA420 => "ImageUniqueID",
        0xA430 => "CameraOwnerName",
        0xA431 => "BodySerialNumber",
        0xA433 => "LensMake",
        0xA434 => "LensModel",
        0xA435 => "LensSerialNumber",
        _ => return format!("Tag0x{tag:04X}"),
    };
    known.to_string()
}

fn utf16(bytes: &[u8], big: bool) -> String {
    let units = bytes.as_chunks::<2>().0.iter().map(|pair| {
        if big {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        }
    });
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn decode_user_comment(value: &[u8], big: bool) -> Option<String> {
    let (prefix, body) = (value.get(..8)?, value.get(8..)?);
    Some(if prefix == b"UNICODE\0" {
        utf16(body, big)
    } else {
        lossy(body)
    })
}

fn decode_value(tag: u16, typ: u16, value: &[u8], big: bool) -> Option<String> {
    let text = if (TAG_XP_FIRST..=TAG_XP_LAST).contains(&tag) {
        if !matches!(typ, TYPE_BYTE | TYPE_ASCII | TYPE_UNDEFINED) {
            return None;
        }
        utf16(value, false)
    } else if tag == TAG_USER_COMMENT {
        if !matches!(typ, TYPE_BYTE | TYPE_ASCII | TYPE_UNDEFINED) {
            return None;
        }
        decode_user_comment(value, big)?
    } else if typ == TYPE_ASCII {
        lossy(value)
    } else {
        return None;
    };
    let trimmed = text.trim_end_matches('\0');
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

struct IfdWalk {
    exif_pointer: Option<u32>,
    timed_out: bool,
}

fn walk_ifd(
    tiff: &[u8],
    order: Order,
    offset: usize,
    fields: &mut Vec<(String, String)>,
    expired: &dyn Fn() -> bool,
) -> IfdWalk {
    let mut walk = IfdWalk {
        exif_pointer: None,
        timed_out: false,
    };
    let Some(count) = order.u16(tiff, offset) else {
        return walk;
    };
    let count = usize::from(count).min(MAX_IFD_ENTRIES);
    for index in 0..count {
        if expired() {
            walk.timed_out = true;
            break;
        }
        let Some(entry_at) = index
            .checked_mul(ENTRY_LEN)
            .and_then(|n| n.checked_add(offset))
            .and_then(|n| n.checked_add(2))
        else {
            break;
        };
        let Some(entry) = sub(tiff, entry_at, ENTRY_LEN) else {
            break;
        };
        let (Some(tag), Some(typ), Some(n)) = (
            order.u16(entry, 0),
            order.u16(entry, 2),
            order.u32(entry, 4),
        ) else {
            break;
        };
        if tag == TAG_EXIF_IFD {
            walk.exif_pointer = order.u32(entry, 8);
            continue;
        }
        if !matches!(typ, TYPE_BYTE | TYPE_ASCII | TYPE_UNDEFINED) {
            continue;
        }
        let Ok(len) = usize::try_from(n) else {
            continue;
        };
        let value = if len <= 4 {
            sub(entry, 8, len)
        } else {
            order
                .u32(entry, 8)
                .and_then(|o| usize::try_from(o).ok())
                .and_then(|o| sub(tiff, o, len))
        };
        let Some(value) = value else {
            continue;
        };
        if let Some(text) = decode_value(tag, typ, value, order.big) {
            fields.push((tag_name(tag), text));
        }
    }
    walk
}

pub fn exif_text_fields(tiff: &[u8]) -> Result<Vec<(String, String)>, ExifError> {
    parse(tiff, &|| false).map(|(fields, _)| fields)
}

pub(crate) fn parse(
    tiff: &[u8],
    expired: &dyn Fn() -> bool,
) -> Result<(Vec<(String, String)>, bool), ExifError> {
    let big = match tiff.get(..2) {
        Some(b"II") => false,
        Some(b"MM") => true,
        _ => return Err(ExifError::BadHeader),
    };
    let order = Order { big };
    if order.u16(tiff, 2) != Some(42) {
        return Err(ExifError::BadHeader);
    }
    let first = order
        .u32(tiff, 4)
        .and_then(|o| usize::try_from(o).ok())
        .ok_or(ExifError::BadHeader)?;
    let mut fields = Vec::new();
    let mut visited = HashSet::new();
    visited.insert(first);
    let walk = walk_ifd(tiff, order, first, &mut fields, expired);
    if walk.timed_out {
        return Ok((fields, true));
    }
    let Some(exif_at) = walk.exif_pointer.and_then(|o| usize::try_from(o).ok()) else {
        return Ok((fields, false));
    };
    if !visited.insert(exif_at) {
        return Ok((fields, false));
    }
    let second = walk_ifd(tiff, order, exif_at, &mut fields, expired);
    Ok((fields, second.timed_out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LE: bool = false;
    const BE: bool = true;

    fn u16b(big: bool, v: u16) -> [u8; 2] {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    fn u32b(big: bool, v: u32) -> [u8; 4] {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    fn header(big: bool) -> Vec<u8> {
        let mut v = if big { b"MM".to_vec() } else { b"II".to_vec() };
        v.extend_from_slice(&u16b(big, 42));
        v.extend_from_slice(&u32b(big, 8));
        v
    }

    fn entry(big: bool, tag: u16, typ: u16, count: u32, value: [u8; 4]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&u16b(big, tag));
        v.extend_from_slice(&u16b(big, typ));
        v.extend_from_slice(&u32b(big, count));
        v.extend_from_slice(&value);
        v
    }

    fn single_ifd(big: bool, tag: u16, typ: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = header(big);
        v.extend_from_slice(&u16b(big, 1));
        v.extend_from_slice(&entry(big, tag, typ, payload.len() as u32, u32b(big, 26)));
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(payload);
        v
    }

    fn user_comment(big: bool, payload: &[u8]) -> Vec<u8> {
        let mut v = header(big);
        v.extend_from_slice(&u16b(big, 1));
        v.extend_from_slice(&entry(big, 0x8769, 4, 1, u32b(big, 26)));
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&u16b(big, 1));
        v.extend_from_slice(&entry(big, 0x9286, 7, payload.len() as u32, u32b(big, 44)));
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(payload);
        v
    }

    fn pair(name: &str, text: &str) -> (String, String) {
        (name.to_string(), text.to_string())
    }

    #[test]
    fn little_endian_image_description_with_offset_value() {
        let tiff = single_ifd(LE, 0x010E, 2, b"hello\0");
        assert_eq!(tiff.len(), 32);
        assert_eq!(
            exif_text_fields(&tiff),
            Ok(vec![pair("ImageDescription", "hello")])
        );
    }

    #[test]
    fn big_endian_image_description_with_offset_value() {
        let tiff = single_ifd(BE, 0x010E, 2, b"hello\0");
        assert_eq!(
            exif_text_fields(&tiff),
            Ok(vec![pair("ImageDescription", "hello")])
        );
    }

    #[test]
    fn inline_ascii_value_of_four_bytes_or_fewer() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x010F, 2, 3, *b"ab\0\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(exif_text_fields(&tiff), Ok(vec![pair("Make", "ab")]));
    }

    #[test]
    fn unknown_ascii_tag_is_named_by_hex_and_every_ascii_tag_is_taken() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 2));
        tiff.extend_from_slice(&entry(LE, 0x1234, 2, 3, *b"xy\0\0"));
        tiff.extend_from_slice(&entry(LE, 0x0131, 2, 3, *b"sw\0\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            exif_text_fields(&tiff),
            Ok(vec![pair("Tag0x1234", "xy"), pair("Software", "sw")])
        );
    }

    #[test]
    fn non_ascii_typed_tags_are_ignored() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x010E, 3, 1, [1, 0, 0, 0]));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(exif_text_fields(&tiff), Ok(vec![]));
    }

    #[test]
    fn exif_xp_comment_utf16_extracted() {
        let payload = [0x48, 0x00, 0x69, 0x00, 0x21, 0x00, 0x00, 0x00];
        let tiff = single_ifd(LE, 0x9C9C, 1, &payload);
        assert_eq!(exif_text_fields(&tiff), Ok(vec![pair("XPComment", "Hi!")]));
    }

    #[test]
    fn xp_tags_9c9b_to_9c9f_are_all_utf16le_even_in_big_endian_files() {
        for (tag, name) in [
            (0x9C9B, "XPTitle"),
            (0x9C9C, "XPComment"),
            (0x9C9D, "XPAuthor"),
            (0x9C9E, "XPKeywords"),
            (0x9C9F, "XPSubject"),
        ] {
            let mut tiff = header(BE);
            tiff.extend_from_slice(&u16b(BE, 1));
            tiff.extend_from_slice(&entry(BE, tag, 1, 4, [0x41, 0x00, 0x00, 0x00]));
            tiff.extend_from_slice(&[0, 0, 0, 0]);
            assert_eq!(exif_text_fields(&tiff), Ok(vec![pair(name, "A")]));
        }
    }

    #[test]
    fn user_comment_unicode_prefix_uses_tiff_byte_order() {
        let mut little = b"UNICODE\0".to_vec();
        little.extend_from_slice(&[0x48, 0x00, 0x69, 0x00]);
        assert_eq!(
            exif_text_fields(&user_comment(LE, &little)),
            Ok(vec![pair("UserComment", "Hi")])
        );
        let mut big = b"UNICODE\0".to_vec();
        big.extend_from_slice(&[0x00, 0x48, 0x00, 0x69]);
        assert_eq!(
            exif_text_fields(&user_comment(BE, &big)),
            Ok(vec![pair("UserComment", "Hi")])
        );
    }

    #[test]
    fn user_comment_ascii_jis_and_nul_prefixes() {
        let mut ascii = b"ASCII\0\0\0".to_vec();
        ascii.extend_from_slice(b"hey");
        assert_eq!(
            exif_text_fields(&user_comment(LE, &ascii)),
            Ok(vec![pair("UserComment", "hey")])
        );
        let mut jis = b"JIS\0\0\0\0\0".to_vec();
        jis.extend_from_slice(b"jis");
        assert_eq!(
            exif_text_fields(&user_comment(LE, &jis)),
            Ok(vec![pair("UserComment", "jis")])
        );
        let mut nul = vec![0u8; 8];
        nul.extend_from_slice(b"nul");
        assert_eq!(
            exif_text_fields(&user_comment(LE, &nul)),
            Ok(vec![pair("UserComment", "nul")])
        );
    }

    #[test]
    fn user_comment_shorter_than_prefix_or_empty_body_gives_nothing() {
        assert_eq!(exif_text_fields(&user_comment(LE, b"ASCII")), Ok(vec![]));
        assert_eq!(
            exif_text_fields(&user_comment(LE, b"ASCII\0\0\0")),
            Ok(vec![])
        );
    }

    #[test]
    fn exif_ifd_loop_terminates() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 2));
        tiff.extend_from_slice(&entry(LE, 0x010E, 2, 6, u32b(LE, 38)));
        tiff.extend_from_slice(&entry(LE, 0x8769, 4, 1, u32b(LE, 8)));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(b"hello\0");
        assert_eq!(
            exif_text_fields(&tiff),
            Ok(vec![pair("ImageDescription", "hello")])
        );
    }

    #[test]
    fn exif_ifd_pointer_cycle_between_two_ifds_terminates() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x8769, 4, 1, u32b(LE, 26)));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(&u16b(LE, 2));
        tiff.extend_from_slice(&entry(LE, 0x010F, 2, 3, *b"ab\0\0"));
        tiff.extend_from_slice(&entry(LE, 0x8769, 4, 1, u32b(LE, 8)));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(exif_text_fields(&tiff), Ok(vec![pair("Make", "ab")]));
    }

    #[test]
    fn exif_ifd_pointer_is_followed_from_ifd0_only() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x8769, 4, 1, u32b(LE, 26)));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x8769, 4, 1, u32b(LE, 44)));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x010F, 2, 3, *b"zz\0\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(exif_text_fields(&tiff), Ok(vec![]));
    }

    #[test]
    fn bad_headers_are_errors() {
        assert_eq!(exif_text_fields(b""), Err(ExifError::BadHeader));
        assert_eq!(
            exif_text_fields(b"II*\0\x08\0\0"),
            Err(ExifError::BadHeader)
        );
        assert_eq!(
            exif_text_fields(b"XX*\0\x08\0\0\0"),
            Err(ExifError::BadHeader)
        );
        assert_eq!(
            exif_text_fields(b"II+\0\x08\0\0\0"),
            Err(ExifError::BadHeader)
        );
        assert_eq!(
            exif_text_fields(b"MM\x2A\0\0\0\0\x08"),
            Err(ExifError::BadHeader)
        );
    }

    #[test]
    fn ifd_offset_outside_the_buffer_yields_nothing() {
        let mut far = header(LE);
        far[4..8].copy_from_slice(&u32b(LE, 0xFFFF_FFF0));
        assert_eq!(exif_text_fields(&far), Ok(vec![]));
        assert_eq!(exif_text_fields(&header(LE)), Ok(vec![]));
    }

    #[test]
    fn value_offset_outside_the_buffer_is_skipped() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 2));
        tiff.extend_from_slice(&entry(LE, 0x010E, 2, 6, u32b(LE, 0xFFFF_FFF0)));
        tiff.extend_from_slice(&entry(LE, 0x010F, 2, 3, *b"ok\0\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(exif_text_fields(&tiff), Ok(vec![pair("Make", "ok")]));
    }

    #[test]
    fn huge_count_does_not_overflow_or_allocate() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x010E, 2, u32::MAX, u32b(LE, 26)));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(b"hello\0");
        assert_eq!(exif_text_fields(&tiff), Ok(vec![]));
    }

    #[test]
    fn truncated_entry_table_keeps_entries_read_so_far() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 3));
        tiff.extend_from_slice(&entry(LE, 0x010F, 2, 3, *b"ab\0\0"));
        tiff.extend_from_slice(&[0x0E, 0x01, 0x02, 0x00, 0x06]);
        assert_eq!(exif_text_fields(&tiff), Ok(vec![pair("Make", "ab")]));
    }

    #[test]
    fn entry_count_is_capped_at_one_thousand() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1001));
        for i in 0..1001u32 {
            let second = if i == 1000 { b'Z' } else { 0 };
            tiff.extend_from_slice(&entry(LE, 0x010F, 2, 3, [b'a', second, 0, 0]));
        }
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        let fields = exif_text_fields(&tiff).unwrap();
        assert_eq!(fields.len(), 1000);
        assert!(fields.iter().all(|f| f.1 == "a"));
    }

    #[test]
    fn empty_and_all_nul_values_give_no_field() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 2));
        tiff.extend_from_slice(&entry(LE, 0x010F, 2, 1, [0, 0, 0, 0]));
        tiff.extend_from_slice(&entry(LE, 0x0110, 2, 4, [0, 0, 0, 0]));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(exif_text_fields(&tiff), Ok(vec![]));
    }
}

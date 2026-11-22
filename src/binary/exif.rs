use std::collections::HashSet;

use super::{lossy, sub};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExifError {
    BadHeader,
}

const MAX_IFD_ENTRIES: usize = 1000;
const MAX_IFDS: usize = 16;
const ENTRY_LEN: usize = 12;
const TAG_EXIF_IFD: u16 = 0x8769;
const TAG_GPS_IFD: u16 = 0x8825;
const TAG_INTEROP_IFD: u16 = 0xA005;
const TAG_SUB_IFDS: u16 = 0x014A;
const TAG_COPYRIGHT: u16 = 0x8298;
const TAG_USER_COMMENT: u16 = 0x9286;
const TAG_XP_FIRST: u16 = 0x9C9B;
const TAG_XP_LAST: u16 = 0x9C9F;
const TAG_GPS_PROCESSING_METHOD: u16 = 0x001B;
const TAG_GPS_AREA_INFORMATION: u16 = 0x001C;
const TYPE_BYTE: u16 = 1;
const TYPE_ASCII: u16 = 2;
const TYPE_UNDEFINED: u16 = 7;
const TYPE_UTF8: u16 = 129;
const PUBLIC_OUTPUT_SLACK: usize = 64 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub timed_out: bool,
    pub entry_limit: bool,
    pub stopped: bool,
    pub malformed: bool,
    pub ifd_limit: bool,
}

pub(crate) struct Value {
    pub name: String,
    pub text: String,
    pub start: usize,
    pub end: usize,
    pub hidden: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ifd0,
    Ifd1,
    Exif,
    Gps,
    Interop,
}

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

fn gps_tag_name(tag: u16) -> Option<&'static str> {
    Some(match tag {
        0x0001 => "GPSLatitudeRef",
        0x0003 => "GPSLongitudeRef",
        0x0009 => "GPSStatus",
        0x000A => "GPSMeasureMode",
        0x000C => "GPSSpeedRef",
        0x000E => "GPSTrackRef",
        0x0010 => "GPSImgDirectionRef",
        0x0012 => "GPSMapDatum",
        0x0013 => "GPSDestLatitudeRef",
        0x0015 => "GPSDestLongitudeRef",
        0x0017 => "GPSDestBearingRef",
        0x0019 => "GPSDestDistanceRef",
        TAG_GPS_PROCESSING_METHOD => "GPSProcessingMethod",
        TAG_GPS_AREA_INFORMATION => "GPSAreaInformation",
        0x001D => "GPSDateStamp",
        _ => return None,
    })
}

fn tag_name(kind: Kind, tag: u16) -> String {
    let known = match (kind, tag) {
        (Kind::Gps, t) => gps_tag_name(t),
        (Kind::Interop, 0x0001) => Some("InteropIndex"),
        (_, 0x010E) => Some("ImageDescription"),
        (_, 0x010F) => Some("Make"),
        (_, 0x0110) => Some("Model"),
        (_, 0x0131) => Some("Software"),
        (_, 0x0132) => Some("DateTime"),
        (_, 0x013B) => Some("Artist"),
        (_, 0x8298) => Some("Copyright"),
        (_, 0x9003) => Some("DateTimeOriginal"),
        (_, 0x9004) => Some("DateTimeDigitized"),
        (_, 0x9286) => Some("UserComment"),
        (_, 0x9C9B) => Some("XPTitle"),
        (_, 0x9C9C) => Some("XPComment"),
        (_, 0x9C9D) => Some("XPAuthor"),
        (_, 0x9C9E) => Some("XPKeywords"),
        (_, 0x9C9F) => Some("XPSubject"),
        (_, 0xA420) => Some("ImageUniqueID"),
        (_, 0xA430) => Some("CameraOwnerName"),
        (_, 0xA431) => Some("BodySerialNumber"),
        (_, 0xA433) => Some("LensMake"),
        (_, 0xA434) => Some("LensModel"),
        (_, 0xA435) => Some("LensSerialNumber"),
        (_, 0x927C) => Some("MakerNote"),
        _ => None,
    };
    match known {
        Some(name) => name.to_string(),
        None => format!("Tag0x{tag:04X}"),
    }
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

fn decode_prefixed(value: &[u8], big: bool) -> Option<String> {
    let (prefix, body) = (value.get(..8)?, value.get(8..)?);
    Some(if prefix == b"UNICODE\0" {
        utf16(body, big)
    } else {
        lossy(body)
    })
}

fn is_prefixed(kind: Kind, tag: u16) -> bool {
    match kind {
        Kind::Gps => matches!(tag, TAG_GPS_PROCESSING_METHOD | TAG_GPS_AREA_INFORMATION),
        _ => tag == TAG_USER_COMMENT,
    }
}

fn type_size(typ: u16) -> Option<usize> {
    Some(match typ {
        1 | 2 | 6 | 7 | TYPE_UTF8 => 1,
        3 | 8 => 2,
        4 | 9 | 11 | 13 => 4,
        5 | 10 | 12 => 8,
        _ => return None,
    })
}

fn is_xp(kind: Kind, tag: u16) -> bool {
    (TAG_XP_FIRST..=TAG_XP_LAST).contains(&tag) && kind != Kind::Gps
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |at| at + 1);
    &bytes[..end]
}

fn clean_text(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let clean = !text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'));
    clean.then(|| text.to_string())
}

struct Raw<'v> {
    kind: Kind,
    tag: u16,
    typ: u16,
    value: &'v [u8],
    start: usize,
    big: bool,
}

fn decode(raw: &Raw<'_>) -> Vec<Value> {
    let name = tag_name(raw.kind, raw.tag);
    let end = raw.start + raw.value.len();
    let one = |text: String| {
        let text = text.trim_end_matches('\0').to_string();
        if text.is_empty() {
            Vec::new()
        } else {
            vec![Value {
                name: name.clone(),
                text,
                start: raw.start,
                end,
                hidden: false,
            }]
        }
    };
    if is_xp(raw.kind, raw.tag) {
        return one(utf16(raw.value, false));
    }
    if is_prefixed(raw.kind, raw.tag) {
        if !matches!(raw.typ, TYPE_BYTE | TYPE_ASCII | TYPE_UNDEFINED) {
            return Vec::new();
        }
        return one(decode_prefixed(raw.value, raw.big).unwrap_or_else(|| lossy(raw.value)));
    }
    match raw.typ {
        TYPE_ASCII => {
            let trimmed = trim_nul(raw.value);
            let split = trimmed.iter().position(|&b| b == 0);
            match split.filter(|_| raw.tag != TAG_COPYRIGHT) {
                Some(nul) => {
                    let mut values = Vec::new();
                    let shown = lossy(&trimmed[..nul]);
                    if !shown.is_empty() {
                        values.push(Value {
                            name: name.clone(),
                            text: shown,
                            start: raw.start,
                            end: raw.start + nul,
                            hidden: false,
                        });
                    }
                    let after = lossy(&trimmed[nul + 1..]);
                    let after = after.trim_matches('\0');
                    if !after.is_empty() {
                        values.push(Value {
                            name: name.clone(),
                            text: after.to_string(),
                            start: raw.start + nul + 1,
                            end,
                            hidden: true,
                        });
                    }
                    values
                }
                None => one(lossy(trimmed)),
            }
        }
        TYPE_UTF8 => one(lossy(raw.value)),
        _ => clean_text(trim_nul(raw.value)).map_or_else(Vec::new, one),
    }
}

#[derive(Default)]
struct Pointers {
    exif: Option<usize>,
    gps: Option<usize>,
    interop: Option<usize>,
    subs: Vec<usize>,
    next: Option<usize>,
}

struct Walk<'a> {
    tiff: &'a [u8],
    order: Order,
    expired: &'a dyn Fn() -> bool,
    emit: &'a mut dyn FnMut(Value) -> bool,
    seen: HashSet<(usize, usize)>,
    outcome: Outcome,
}

impl Walk<'_> {
    fn sub_ifds(&mut self, entry_at: usize, count: u32, pointer: Option<usize>) -> Vec<usize> {
        let len = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(4));
        let at = len.and_then(|len| {
            if len <= 4 {
                Some(entry_at + 8)
            } else {
                pointer
            }
        });
        let Some(array) = at.zip(len).and_then(|(at, len)| sub(self.tiff, at, len)) else {
            self.outcome.malformed = true;
            return Vec::new();
        };
        array
            .as_chunks::<4>()
            .0
            .iter()
            .filter_map(|raw| self.order.u32(raw, 0))
            .filter_map(|offset| usize::try_from(offset).ok())
            .collect()
    }

    fn ifd(&mut self, offset: usize, kind: Kind) -> Pointers {
        let mut pointers = Pointers::default();
        let order = self.order;
        let Some(declared) = order.u16(self.tiff, offset) else {
            self.outcome.malformed = true;
            return pointers;
        };
        let declared = usize::from(declared);
        if declared > MAX_IFD_ENTRIES {
            self.outcome.entry_limit = true;
        }
        let entries_at = offset.saturating_add(2);
        for index in 0..declared.min(MAX_IFD_ENTRIES) {
            if (self.expired)() {
                self.outcome.timed_out = true;
                return pointers;
            }
            let entry = index
                .checked_mul(ENTRY_LEN)
                .and_then(|n| n.checked_add(entries_at))
                .and_then(|at| Some((at, sub(self.tiff, at, ENTRY_LEN)?)));
            let Some((entry_at, entry)) = entry else {
                self.outcome.malformed = true;
                break;
            };
            let (Some(tag), Some(typ), Some(n)) = (
                order.u16(entry, 0),
                order.u16(entry, 2),
                order.u32(entry, 4),
            ) else {
                self.outcome.malformed = true;
                break;
            };
            let pointer = order.u32(entry, 8).and_then(|o| usize::try_from(o).ok());
            match tag {
                TAG_EXIF_IFD => pointers.exif = pointer,
                TAG_GPS_IFD => pointers.gps = pointer,
                TAG_INTEROP_IFD => pointers.interop = pointer,
                TAG_SUB_IFDS => pointers.subs = self.sub_ifds(entry_at, n, pointer),
                _ => {
                    if !self.value(kind, (tag, typ, n), entry_at, pointer) {
                        return pointers;
                    }
                }
            }
        }
        if matches!(kind, Kind::Ifd0 | Kind::Ifd1) {
            pointers.next = declared
                .checked_mul(ENTRY_LEN)
                .and_then(|n| n.checked_add(entries_at))
                .and_then(|at| order.u32(self.tiff, at))
                .and_then(|o| usize::try_from(o).ok())
                .filter(|&o| o != 0);
        }
        pointers
    }

    fn value(
        &mut self,
        kind: Kind,
        (tag, typ, count): (u16, u16, u32),
        entry_at: usize,
        pointer: Option<usize>,
    ) -> bool {
        let text_type =
            is_xp(kind, tag) || matches!(typ, TYPE_BYTE | TYPE_ASCII | TYPE_UNDEFINED | TYPE_UTF8);
        let len = type_size(typ).and_then(|size| usize::try_from(count).ok()?.checked_mul(size));
        let (true, Some(len)) = (text_type, len) else {
            return true;
        };
        let start = if len <= 4 {
            Some(entry_at + 8)
        } else {
            pointer
        };
        let Some((start, value)) = start.and_then(|s| Some((s, sub(self.tiff, s, len)?))) else {
            self.outcome.malformed = true;
            return true;
        };
        if !self.seen.insert((start, len)) {
            return true;
        }
        let raw = Raw {
            kind,
            tag,
            typ,
            value,
            start,
            big: self.order.big,
        };
        for value in decode(&raw) {
            if !(self.emit)(value) {
                self.outcome.stopped = true;
                return false;
            }
        }
        true
    }
}

pub(crate) fn parse_values(
    tiff: &[u8],
    expired: &dyn Fn() -> bool,
    emit: &mut dyn FnMut(Value) -> bool,
) -> Result<Outcome, ExifError> {
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
    let mut walk = Walk {
        tiff,
        order,
        expired,
        emit,
        seen: HashSet::new(),
        outcome: Outcome::default(),
    };
    let mut visited = HashSet::new();
    let mut queue = vec![(first, Kind::Ifd0)];
    visited.insert(first);
    let mut index = 0;
    while index < queue.len() && !walk.outcome.stopped && !walk.outcome.timed_out {
        let (offset, kind) = queue[index];
        index += 1;
        let pointers = walk.ifd(offset, kind);
        let mut found = vec![
            (pointers.exif, Kind::Exif),
            (pointers.gps, Kind::Gps),
            (pointers.interop, Kind::Interop),
        ];
        found.extend(pointers.subs.iter().map(|&at| (Some(at), Kind::Ifd1)));
        found.push((pointers.next, Kind::Ifd1));
        for (pointer, kind) in found {
            let Some(at) = pointer.filter(|at| !visited.contains(at)) else {
                continue;
            };
            if queue.len() < MAX_IFDS {
                visited.insert(at);
                queue.push((at, kind));
            } else {
                walk.outcome.ifd_limit = true;
            }
        }
    }
    Ok(walk.outcome)
}

pub fn exif_text_fields(tiff: &[u8]) -> Result<Vec<(String, String)>, ExifError> {
    let cap = tiff
        .len()
        .saturating_mul(2)
        .saturating_add(PUBLIC_OUTPUT_SLACK);
    let mut used = 0usize;
    let mut fields = Vec::new();
    parse_values(tiff, &|| false, &mut |value| {
        used = used.saturating_add(value.text.len());
        if used > cap {
            return false;
        }
        fields.push((value.name, value.text));
        true
    })?;
    Ok(fields)
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
    fn user_comment_shorter_than_its_prefix_is_read_and_an_empty_body_gives_nothing() {
        assert_eq!(
            exif_text_fields(&user_comment(LE, b"ASCII")),
            Ok(vec![pair("UserComment", "ASCII")])
        );
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
    fn exif_ifd_pointers_are_followed_from_any_ifd() {
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
        assert_eq!(exif_text_fields(&tiff), Ok(vec![pair("Make", "zz")]));
    }

    fn malformed(tiff: &[u8]) -> bool {
        parse_values(tiff, &|| false, &mut |_| true)
            .unwrap()
            .malformed
    }

    #[test]
    fn blocks_with_out_of_range_parts_are_reported_as_malformed() {
        let mut far = header(LE);
        far[4..8].copy_from_slice(&u32b(LE, 0xFFFF_FFF0));
        let mut outside = header(LE);
        outside.extend_from_slice(&u16b(LE, 1));
        outside.extend_from_slice(&entry(LE, 0x010E, 2, 6, u32b(LE, 0xFFFF_FFF0)));
        outside.extend_from_slice(&[0, 0, 0, 0]);
        let mut cut = header(LE);
        cut.extend_from_slice(&u16b(LE, 2));
        cut.extend_from_slice(&entry(LE, 0x010F, 2, 3, *b"ab\0\0"));
        cut.extend_from_slice(&[0x0E, 0x01, 0x02]);
        for tiff in [far, header(LE), outside, cut] {
            assert!(malformed(&tiff), "{tiff:?}");
        }
        assert!(!malformed(&single_ifd(LE, 0x010E, 2, b"hello\0")));
    }

    fn chain(n: usize) -> Vec<u8> {
        let mut tiff = header(LE);
        for i in 0..n {
            let next = if i + 1 < n { 8 + 18 * (i + 1) } else { 0 };
            tiff.extend_from_slice(&u16b(LE, 1));
            tiff.extend_from_slice(&entry(LE, 0x010F, 2, 2, *b"a\0\0\0"));
            tiff.extend_from_slice(&u32b(LE, next as u32));
        }
        tiff
    }

    #[test]
    fn more_than_sixteen_ifds_are_reported_as_an_ifd_limit() {
        let (seen, outcome) = values(&chain(17));
        assert_eq!(seen.len(), 16);
        assert!(outcome.ifd_limit);
        let (seen, outcome) = values(&chain(16));
        assert_eq!(seen.len(), 16);
        assert!(!outcome.ifd_limit);
    }

    #[test]
    fn later_ifds_sub_ifds_and_pointers_outside_ifd0_are_followed() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x010F, 2, 2, *b"a\0\0\0"));
        tiff.extend_from_slice(&u32b(LE, 26));
        tiff.extend_from_slice(&u16b(LE, 3));
        tiff.extend_from_slice(&entry(LE, 0x0110, 2, 2, *b"b\0\0\0"));
        tiff.extend_from_slice(&entry(LE, 0x014A, 4, 1, u32b(LE, 68)));
        tiff.extend_from_slice(&entry(LE, 0x8825, 4, 1, u32b(LE, 86)));
        tiff.extend_from_slice(&u32b(LE, 104));
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x0131, 2, 2, *b"s\0\0\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x0001, 2, 2, *b"N\0\0\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x013B, 2, 2, *b"c\0\0\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(tiff.len(), 122);
        assert_eq!(
            exif_text_fields(&tiff),
            Ok(vec![
                pair("Make", "a"),
                pair("Model", "b"),
                pair("GPSLatitudeRef", "N"),
                pair("Software", "s"),
                pair("Artist", "c")
            ])
        );
        let mut array = header(LE);
        array.extend_from_slice(&u16b(LE, 1));
        array.extend_from_slice(&entry(LE, 0x014A, 4, 2, u32b(LE, 26)));
        array.extend_from_slice(&[0, 0, 0, 0]);
        array.extend_from_slice(&u32b(LE, 34));
        array.extend_from_slice(&u32b(LE, 52));
        array.extend_from_slice(&u16b(LE, 1));
        array.extend_from_slice(&entry(LE, 0x010F, 2, 2, *b"x\0\0\0"));
        array.extend_from_slice(&[0, 0, 0, 0]);
        array.extend_from_slice(&u16b(LE, 1));
        array.extend_from_slice(&entry(LE, 0x0110, 2, 2, *b"y\0\0\0"));
        array.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            exif_text_fields(&array),
            Ok(vec![pair("Make", "x"), pair("Model", "y")])
        );
    }

    #[test]
    fn utf8_typed_values_are_read() {
        let tiff = single_ifd(LE, 0x010E, 129, "h\u{e9}llo\0".as_bytes());
        assert_eq!(
            exif_text_fields(&tiff),
            Ok(vec![pair("ImageDescription", "h\u{e9}llo")])
        );
    }

    #[test]
    fn clean_utf8_byte_and_undefined_values_are_read() {
        assert_eq!(
            exif_text_fields(&single_ifd(LE, 0x927C, 7, b"Maker text\0\0")),
            Ok(vec![pair("MakerNote", "Maker text")])
        );
        assert_eq!(
            exif_text_fields(&single_ifd(LE, 0x1234, 1, b"plain words")),
            Ok(vec![pair("Tag0x1234", "plain words")])
        );
        for binary in [&[1u8, 2, 0xFF, 0, 9, 9][..], b"a\x01bcde"] {
            assert_eq!(
                exif_text_fields(&single_ifd(LE, 0x927C, 7, binary)),
                Ok(vec![])
            );
        }
    }

    #[test]
    fn xp_tags_of_any_type_are_utf16le() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x9C9B, 3, 2, [0x41, 0x00, 0x42, 0x00]));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(exif_text_fields(&tiff), Ok(vec![pair("XPTitle", "AB")]));
        let mut long = header(LE);
        long.extend_from_slice(&u16b(LE, 1));
        long.extend_from_slice(&entry(LE, 0x9C9C, 4, 1, [0x43, 0x00, 0x44, 0x00]));
        long.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(exif_text_fields(&long), Ok(vec![pair("XPComment", "CD")]));
        let mut rational = header(LE);
        rational.extend_from_slice(&u16b(LE, 1));
        rational.extend_from_slice(&entry(LE, 0x9C9D, 5, 1, u32b(LE, 26)));
        rational.extend_from_slice(&[0, 0, 0, 0]);
        rational.extend_from_slice(b"E F G H ");
        assert_eq!(
            exif_text_fields(&rational),
            Ok(vec![pair("XPAuthor", "EFGH")])
        );
    }

    fn shown(tiff: &[u8]) -> Vec<(String, String, usize, usize, bool)> {
        let mut seen = Vec::new();
        parse_values(tiff, &|| false, &mut |v: Value| {
            seen.push((v.name, v.text, v.start, v.end, v.hidden));
            true
        })
        .unwrap();
        seen
    }

    #[test]
    fn text_after_an_internal_nul_is_a_hidden_value() {
        let tiff = single_ifd(LE, 0x010E, 2, b"shown\0hidden words\0");
        assert_eq!(
            shown(&tiff),
            vec![
                (
                    "ImageDescription".to_string(),
                    "shown".to_string(),
                    26,
                    31,
                    false
                ),
                (
                    "ImageDescription".to_string(),
                    "hidden words".to_string(),
                    32,
                    45,
                    true
                )
            ]
        );
        let copyright = single_ifd(LE, 0x8298, 2, b"photographer\0editor\0");
        assert_eq!(
            shown(&copyright),
            vec![(
                "Copyright".to_string(),
                "photographer\0editor".to_string(),
                26,
                46,
                false
            )]
        );
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

    fn values(tiff: &[u8]) -> (Vec<(String, usize, usize)>, Outcome) {
        let mut seen = Vec::new();
        let outcome = parse_values(tiff, &|| false, &mut |v: Value| {
            seen.push((v.name, v.start, v.end));
            true
        })
        .unwrap();
        (seen, outcome)
    }

    #[test]
    fn values_report_their_own_byte_range() {
        let offset = single_ifd(LE, 0x010E, 2, b"hello\0");
        assert_eq!(
            values(&offset).0,
            vec![("ImageDescription".to_string(), 26, 32)]
        );
        let mut inline = header(LE);
        inline.extend_from_slice(&u16b(LE, 1));
        inline.extend_from_slice(&entry(LE, 0x010F, 2, 3, *b"ab\0\0"));
        inline.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(values(&inline).0, vec![("Make".to_string(), 18, 21)]);
    }

    #[test]
    fn identical_offset_and_length_is_emitted_once() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 3));
        for tag in [0x010E, 0x010F, 0x0110] {
            tiff.extend_from_slice(&entry(LE, tag, 2, 6, u32b(LE, 50)));
        }
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(b"hello\0");
        let (seen, _) = values(&tiff);
        assert_eq!(seen, vec![("ImageDescription".to_string(), 50, 56)]);
    }

    #[test]
    fn entry_limit_is_reported_only_past_one_thousand() {
        let build = |n: u16| {
            let mut tiff = header(LE);
            tiff.extend_from_slice(&u16b(LE, n));
            for _ in 0..n {
                tiff.extend_from_slice(&entry(LE, 0x010F, 2, 3, *b"ab\0\0"));
            }
            tiff.extend_from_slice(&[0, 0, 0, 0]);
            tiff
        };
        let (seen, outcome) = values(&build(1001));
        assert_eq!(seen.len(), 1000);
        assert!(outcome.entry_limit);
        let (seen, outcome) = values(&build(1000));
        assert_eq!(seen.len(), 1000);
        assert!(!outcome.entry_limit);
    }

    #[test]
    fn refusing_callback_stops_the_walk() {
        let tiff = single_ifd(LE, 0x010E, 2, b"hello\0");
        let outcome = parse_values(&tiff, &|| false, &mut |_| false).unwrap();
        assert!(outcome.stopped);
    }

    #[test]
    fn expired_deadline_is_reported() {
        let tiff = single_ifd(LE, 0x010E, 2, b"hello\0");
        let outcome = parse_values(&tiff, &|| true, &mut |_| true).unwrap();
        assert!(outcome.timed_out);
    }

    #[test]
    fn ifd1_is_read_through_the_ifd0_next_pointer() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x010F, 2, 3, *b"a\0\0\0"));
        tiff.extend_from_slice(&u32b(LE, 26));
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x0110, 2, 3, *b"b\0\0\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            exif_text_fields(&tiff),
            Ok(vec![pair("Make", "a"), pair("Model", "b")])
        );
    }

    #[test]
    fn gps_ifd_text_is_read_with_gps_names() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x8825, 4, 1, u32b(LE, 26)));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(&u16b(LE, 2));
        tiff.extend_from_slice(&entry(LE, 0x001C, 7, 11, u32b(LE, 56)));
        tiff.extend_from_slice(&entry(LE, 0x0001, 2, 2, *b"N\0\0\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(b"ASCII\0\0\0xyz");
        assert_eq!(
            exif_text_fields(&tiff),
            Ok(vec![
                pair("GPSAreaInformation", "xyz"),
                pair("GPSLatitudeRef", "N")
            ])
        );
    }

    #[test]
    fn interop_ifd_is_read_from_the_exif_ifd() {
        let mut tiff = header(LE);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x8769, 4, 1, u32b(LE, 26)));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0xA005, 4, 1, u32b(LE, 44)));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        tiff.extend_from_slice(&u16b(LE, 1));
        tiff.extend_from_slice(&entry(LE, 0x0001, 2, 4, *b"R98\0"));
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            exif_text_fields(&tiff),
            Ok(vec![pair("InteropIndex", "R98")])
        );
    }
}

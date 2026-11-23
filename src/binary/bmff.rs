use super::png::{Inflated, inflate};
use super::{Placement, Sink, lossy, span, sub};
use crate::limits::Budget;
use crate::model::{DetectorOutput, EmbeddedBlob, FileKind};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 1000;
const WORK_SLACK: usize = 64 * 1024;
const MAX_RECORDED_RANGES: usize = 1 << 20;
const EXIF_PREFIX: &[u8] = b"Exif\0\0";
const XMP_MIME: &[u8] = b"application/rdf+xml";
const RIFF_HEADER_LEN: usize = 12;
const RIFF_SIZE: &str = "malformed WebP: RIFF size does not fit the file";
const TRUNCATED_CHUNK: &str = "malformed WebP: truncated chunk";
const WEBP_TRAILER: &str = "WebP data after RIFF";
const TRUNCATED_BOX: &str = "malformed AVIF: truncated box";
const INVALID_ITEM: &str = "malformed AVIF: invalid item information";
const AVIF_TRAILER: &str = "AVIF data after the last box";
const REFERENCED_ITEM: &str = "referenced item";
const ENCODED_ITEM: &str = "encoded item";
const INFLATE_LIMIT: &str = "compressed AVIF item inflates past the decompression budget";
const TOP_LEVEL_BOXES: [&[u8; 4]; 11] = [
    b"ftyp", b"styp", b"meta", b"moov", b"moof", b"mfra", b"mdat", b"free", b"skip", b"uuid",
    b"sidx",
];

pub fn scan_webp(bytes: &[u8], budget: &mut Budget) -> DetectorOutput {
    let mut sink = Sink::new(bytes.len());
    if !(bytes.starts_with(b"RIFF") && bytes.get(8..RIFF_HEADER_LEN) == Some(b"WEBP".as_slice())) {
        return sink.out;
    }
    let declared = le_u32(bytes, 4)
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| n.checked_add(8));
    let riff_end = match declared {
        Some(end) if (RIFF_HEADER_LEN..=bytes.len()).contains(&end) => end,
        _ => {
            sink.malformed(RIFF_SIZE, 4, 8);
            bytes.len()
        }
    };
    let body = &bytes[..riff_end];
    let mut at = RIFF_HEADER_LEN;
    while at < body.len() {
        if budget.deadline_exceeded() {
            sink.timed_out();
            break;
        }
        let (Some(kind), Some(size)) = (
            sub(body, at, 4),
            le_u32(body, at + 4).and_then(|n| usize::try_from(n).ok()),
        ) else {
            sink.malformed(TRUNCATED_CHUNK, at, body.len());
            break;
        };
        let start = at + 8;
        let Some(payload) = sub(body, start, size) else {
            sink.malformed(TRUNCATED_CHUNK, at, body.len());
            break;
        };
        let end = start + size;
        match kind {
            b"EXIF" => {
                let skip = if payload.starts_with(EXIF_PREFIX) {
                    EXIF_PREFIX.len()
                } else {
                    0
                };
                sink.exif_at(
                    "WebP Exif",
                    &payload[skip..],
                    Placement::Mapped(start + skip),
                    budget,
                );
            }
            b"XMP " => sink.xmp("WebP XMP", payload, start, end, true, budget),
            _ => {}
        }
        if sink.stop {
            break;
        }
        at = end.saturating_add(size & 1);
    }
    if !sink.stop {
        sink.trailer(WEBP_TRAILER, bytes, riff_end, false);
    }
    sink.out
}

pub fn scan_avif(bytes: &[u8], budget: &mut Budget) -> DetectorOutput {
    let max_work = budget.limits().max_decompressed_bytes;
    let mut scan = Avif {
        bytes,
        sink: Sink::new(bytes.len()),
        budget,
        items: 0,
        work_left: bytes
            .len()
            .saturating_mul(3)
            .saturating_add(WORK_SLACK)
            .min(usize::try_from(max_work).unwrap_or(usize::MAX)),
        anomaly: false,
        charged: Vec::new(),
    };
    if read_box(bytes, 0, bytes.len()).is_some_and(|b| &b.kind == b"ftyp") {
        scan.run();
    }
    scan.sink.out
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        <[u8; 4]>::try_from(sub(bytes, at, 4)?).ok()?,
    ))
}

fn be(bytes: &[u8], at: usize, width: usize) -> Option<u64> {
    if width > 8 {
        return None;
    }
    Some(
        sub(bytes, at, width)?
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)),
    )
}

fn mime_kind(content_type: &[u8]) -> Option<Wanted> {
    let base = content_type
        .split(|&c| c == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii()
        .to_ascii_lowercase();
    if base == XMP_MIME {
        Some(Wanted::Xmp)
    } else if base.ends_with(b"+xml") || base.ends_with(b"/xml") {
        Some(Wanted::Xml)
    } else if base.starts_with(b"text/") {
        Some(Wanted::Text)
    } else {
        None
    }
}

fn coding(encoding: Option<&[u8]>) -> Coding {
    match encoding.map(<[u8]>::trim_ascii) {
        None | Some(b"") => Coding::Plain,
        Some(name) if name.eq_ignore_ascii_case(b"deflate") => Coding::Deflate,
        Some(_) => Coding::Unknown,
    }
}

fn be_usize(bytes: &[u8], at: usize, width: usize) -> Option<usize> {
    usize::try_from(be(bytes, at, width)?).ok()
}

#[derive(Clone, Copy)]
struct BoxHeader {
    kind: [u8; 4],
    start: usize,
    payload: usize,
    end: usize,
}

fn read_box(bytes: &[u8], at: usize, end: usize) -> Option<BoxHeader> {
    let end = end.min(bytes.len());
    if at.checked_add(8)? > end {
        return None;
    }
    let size = be(bytes, at, 4)?;
    let kind = <[u8; 4]>::try_from(sub(bytes, at + 4, 4)?).ok()?;
    let (header_len, total) = match size {
        0 => (8, end - at),
        1 => {
            if at.checked_add(16)? > end {
                return None;
            }
            (16, usize::try_from(be(bytes, at + 8, 8)?).ok()?)
        }
        n => (8, usize::try_from(n).ok()?),
    };
    if total < header_len {
        return None;
    }
    let box_end = at.checked_add(total)?;
    if box_end > end {
        return None;
    }
    Some(BoxHeader {
        kind,
        start: at,
        payload: at + header_len,
        end: box_end,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Wanted {
    Exif,
    Xmp,
    Xml,
    Text,
    Uri,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Coding {
    Plain,
    Deflate,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Item {
    kind: Wanted,
    coding: Coding,
}

#[derive(Clone, Copy)]
struct Frame {
    at: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct Widths {
    index: usize,
    offset: usize,
    length: usize,
}

struct Avif<'a> {
    bytes: &'a [u8],
    sink: Sink,
    budget: &'a mut Budget,
    items: usize,
    work_left: usize,
    anomaly: bool,
    charged: Vec<(usize, usize)>,
}

struct Resolved<'a> {
    data: Cow<'a, [u8]>,
    first: (usize, usize),
    contiguous_from: Option<usize>,
    ranges: Vec<(usize, usize)>,
}

struct Infe<'a> {
    id: u32,
    item: Option<Item>,
    name: &'a [u8],
    name_at: usize,
}

struct Location<'d> {
    id: u64,
    method: u64,
    reference: u64,
    base: u64,
    extents: &'d [u8],
}

fn location<'d>(
    d: &'d [u8],
    at: &mut usize,
    version: u8,
    widths: Widths,
    (base_width, id_width): (usize, usize),
) -> Option<Location<'d>> {
    let id = be(d, *at, id_width)?;
    *at += id_width;
    let mut method = 0;
    if version >= 1 {
        method = be(d, *at, 2)? & 0xF;
        *at += 2;
    }
    let reference = be(d, *at, 2)?;
    *at += 2;
    let base = be(d, *at, base_width)?;
    *at += base_width;
    let count = be_usize(d, *at, 2)?;
    *at += 2;
    let extents_len = count.checked_mul(widths.index + widths.offset + widths.length)?;
    let extents = sub(d, *at, extents_len)?;
    *at += extents_len;
    Some(Location {
        id,
        method,
        reference,
        base,
        extents,
    })
}

impl<'a> Avif<'a> {
    fn expired(&mut self) -> bool {
        if self.budget.deadline_exceeded() {
            self.sink.timed_out();
            true
        } else {
            false
        }
    }

    fn invalid(&mut self, start: usize, end: usize) {
        self.sink.malformed(INVALID_ITEM, start, end);
    }

    fn not_scanned(&mut self, (start, end): (usize, usize), format: &'static str) {
        self.sink.out.embedded.push(EmbeddedBlob {
            kind: FileKind::UnknownBinary,
            declared_type: None,
            format: Some(format),
            span: span(start, end),
            bytes: Vec::new(),
            evidence: Vec::new(),
        });
    }

    fn run(&mut self) {
        let (metas, tail) = self.find_metas();
        for (start, end) in metas {
            if self.sink.stop {
                break;
            }
            self.meta(start, end);
        }
        if let Some(at) = tail
            && !self.sink.stop
        {
            self.leftover(at, self.bytes.len(), true);
        }
    }

    fn leftover(&mut self, at: usize, end: usize, top: bool) {
        let boxed = sub(self.bytes, at + 4, 4)
            .is_some_and(|kind| TOP_LEVEL_BOXES.iter().any(|known| kind == known.as_slice()));
        if top && !boxed {
            self.sink.trailer(AVIF_TRAILER, self.bytes, at, false);
        } else {
            self.sink.malformed(TRUNCATED_BOX, at, end);
        }
    }

    fn find_metas(&mut self) -> (Vec<(usize, usize)>, Option<usize>) {
        let mut metas = Vec::new();
        let mut tail = None;
        let mut stack = vec![Frame {
            at: 0,
            end: self.bytes.len(),
        }];
        let mut depth_reported = false;
        while let Some(&frame) = stack.last() {
            if self.expired() {
                break;
            }
            let Some(b) = read_box(self.bytes, frame.at, frame.end) else {
                if frame.at < frame.end {
                    if stack.len() == 1 {
                        tail = Some(frame.at);
                    } else {
                        self.leftover(frame.at, frame.end, false);
                    }
                }
                stack.pop();
                continue;
            };
            if let Some(top) = stack.last_mut() {
                top.at = b.end;
            }
            match &b.kind {
                b"meta" => match b.payload.checked_add(4).filter(|&p| p <= b.end) {
                    Some(p) => metas.push((p, b.end)),
                    None => self.sink.malformed(TRUNCATED_BOX, b.start, b.end),
                },
                b"moov" | b"trak" => {
                    if stack.len() > MAX_DEPTH {
                        if !depth_reported {
                            depth_reported = true;
                            self.sink.l001("box nesting limit", b.start, b.end);
                        }
                    } else {
                        stack.push(Frame {
                            at: b.payload,
                            end: b.end,
                        });
                    }
                }
                _ => {}
            }
        }
        (metas, tail)
    }

    fn meta(&mut self, start: usize, end: usize) {
        let (mut iinf, mut iloc, mut idat) = (None, None, None);
        let mut at = start;
        loop {
            let Some(b) = read_box(self.bytes, at, end) else {
                if at < end {
                    self.sink.malformed(TRUNCATED_BOX, at, end);
                }
                break;
            };
            if self.expired() {
                return;
            }
            at = b.end;
            match &b.kind {
                b"iinf" => iinf = iinf.or(Some(b)),
                b"iloc" => iloc = iloc.or(Some(b)),
                b"idat" => idat = idat.or(Some(b)),
                _ => {}
            }
        }
        match (iinf, iloc) {
            (Some(iinf), Some(iloc)) => {
                let wanted = self.iinf(iinf);
                if wanted.is_empty() || self.sink.stop {
                    return;
                }
                self.iloc(iloc, idat, &wanted);
            }
            (Some(iinf), None) => {
                if !self.iinf(iinf).is_empty() {
                    self.invalid(iinf.start, iinf.end);
                }
            }
            (None, Some(iloc)) => self.invalid(iloc.start, iloc.end),
            (None, None) => {}
        }
    }

    fn iinf(&mut self, b: BoxHeader) -> HashMap<u32, Vec<Item>> {
        let mut wanted: HashMap<u32, Vec<Item>> = HashMap::new();
        let mut seen: HashSet<u32> = HashSet::new();
        let version = self.bytes.get(b.payload..b.end).and_then(|d| d.first());
        let count_width = if version == Some(&0) { 2 } else { 4 };
        let first = b
            .payload
            .checked_add(4 + count_width)
            .filter(|&at| at <= b.end);
        let (Some(_), Some(mut at)) = (version, first) else {
            self.invalid(b.start, b.end);
            return wanted;
        };
        loop {
            let Some(entry) = read_box(self.bytes, at, b.end) else {
                if at < b.end {
                    self.sink.malformed(TRUNCATED_BOX, at, b.end);
                }
                break;
            };
            if self.expired() {
                break;
            }
            at = entry.end;
            if &entry.kind != b"infe" {
                continue;
            }
            self.items += 1;
            if self.items > MAX_ITEMS {
                self.sink.l001("item limit", entry.start, entry.end);
                break;
            }
            let Some(infe) = self.infe(entry) else {
                self.invalid(entry.start, entry.end);
                continue;
            };
            self.sink.carrier(
                "AVIF item name",
                &lossy(infe.name),
                infe.name_at,
                infe.name_at + infe.name.len(),
                infe.name,
            );
            if !seen.insert(infe.id) {
                self.anomaly = true;
            }
            if let Some(item) = infe.item {
                let kinds = wanted.entry(infe.id).or_default();
                if !kinds.contains(&item) {
                    kinds.push(item);
                }
            }
        }
        wanted
    }

    fn infe(&self, b: BoxHeader) -> Option<Infe<'a>> {
        let d = self.bytes.get(b.payload..b.end)?;
        let version = *d.first()?;
        if version > 3 {
            return None;
        }
        let id_width = if version == 3 { 4 } else { 2 };
        let id = u32::try_from(be(d, 4, id_width)?).ok()?;
        let mut at = 4 + id_width + 2;
        let kind = if version >= 2 {
            let kind = sub(d, at, 4)?;
            at += 4;
            Some(kind)
        } else {
            None
        };
        let rest = d.get(at..)?;
        let name_end = rest.iter().position(|&c| c == 0)?;
        let name = &rest[..name_end];
        let mut fields = rest[name_end + 1..].split(|&c| c == 0);
        let item = match kind {
            Some(b"Exif") => Some(Item {
                kind: Wanted::Exif,
                coding: Coding::Plain,
            }),
            Some(b"mime") | None => {
                let content_type = fields.next().unwrap_or_default();
                let encoding = fields.next();
                mime_kind(content_type).map(|kind| Item {
                    kind,
                    coding: coding(encoding),
                })
            }
            Some(b"uri ") => Some(Item {
                kind: Wanted::Uri,
                coding: Coding::Plain,
            }),
            Some(_) => None,
        };
        Some(Infe {
            id,
            item,
            name,
            name_at: b.payload + at,
        })
    }

    fn overlaps(&mut self) -> bool {
        self.charged.sort_unstable();
        self.charged.windows(2).any(|w| w[1].0 < w[0].1)
    }

    fn charge(&mut self, item: &Resolved<'_>) -> bool {
        let (start, end) = item.first;
        for &range in item.ranges.iter().filter(|r| r.0 < r.1) {
            if self.charged.len() >= MAX_RECORDED_RANGES {
                self.sink.amplification(start, end);
                self.sink.stop = true;
                return false;
            }
            self.charged.push(range);
        }
        match self.work_left.checked_sub(item.data.len()) {
            Some(left) => {
                self.work_left = left;
                true
            }
            None => {
                if self.anomaly || self.overlaps() {
                    self.sink.amplification(start, end);
                } else {
                    self.sink.l001("metadata work limit", start, end);
                }
                self.sink.stop = true;
                false
            }
        }
    }

    fn iloc(&mut self, b: BoxHeader, idat: Option<BoxHeader>, wanted: &HashMap<u32, Vec<Item>>) {
        let bytes = self.bytes;
        let header = bytes
            .get(b.payload..b.end)
            .and_then(|d| Some((d, *d.first()?, *d.get(4)?, *d.get(5)?)));
        let Some((d, version, sizes, bases)) = header else {
            self.invalid(b.start, b.end);
            return;
        };
        let widths = Widths {
            index: if version >= 1 {
                usize::from(bases & 15)
            } else {
                0
            },
            offset: usize::from(sizes >> 4),
            length: usize::from(sizes & 15),
        };
        let base_width = usize::from(bases >> 4);
        let valid = |w: usize| matches!(w, 0 | 4 | 8);
        let id_width = if version < 2 { 2 } else { 4 };
        let count = be(d, 6, id_width);
        let usable = version <= 2
            && valid(widths.index)
            && valid(widths.offset)
            && valid(base_width)
            && valid(widths.length);
        let (true, Some(mut remaining)) = (usable, count) else {
            self.invalid(b.start, b.end);
            return;
        };
        let mut at = 6 + id_width;
        while remaining > 0 {
            remaining -= 1;
            if self.expired() || self.sink.stop {
                return;
            }
            let Some(loc) = location(d, &mut at, version, widths, (base_width, id_width)) else {
                self.invalid(b.start, b.end);
                return;
            };
            let Some(kinds) = u32::try_from(loc.id).ok().and_then(|id| wanted.get(&id)) else {
                continue;
            };
            if loc.reference != 0 || loc.method == 2 {
                self.not_scanned((b.start, b.end), REFERENCED_ITEM);
                continue;
            }
            let (origin, limit) = match (loc.method, idat) {
                (0, _) => (0, bytes.len()),
                (1, Some(i)) => (i.payload, i.end),
                _ => {
                    self.invalid(b.start, b.end);
                    continue;
                }
            };
            let Some(resolved) = self.resolve(loc.extents, widths, loc.base, (origin, limit))
            else {
                if !self.sink.stop {
                    self.invalid(b.start, b.end);
                }
                continue;
            };
            if !self.charge(&resolved) {
                return;
            }
            for item in kinds {
                self.emit(&resolved, *item);
            }
        }
    }

    fn resolve(
        &mut self,
        extents: &[u8],
        widths: Widths,
        base: u64,
        window: (usize, usize),
    ) -> Option<Resolved<'a>> {
        let (origin, limit) = window;
        let bytes = self.bytes;
        let step = widths.index + widths.offset + widths.length;
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut total = 0usize;
        let mut at = 0;
        while at < extents.len() {
            if self.expired() {
                return None;
            }
            let offset = be(extents, at + widths.index, widths.offset)?;
            let length = be(extents, at + widths.index + widths.offset, widths.length)?;
            at += step;
            let from = usize::try_from(base.checked_add(offset)?).ok()?;
            let to = if length == 0 {
                limit.checked_sub(origin)?
            } else {
                from.checked_add(usize::try_from(length).ok()?)?
            };
            let start = origin.checked_add(from)?;
            let end = origin.checked_add(to)?;
            if end > limit || start > end {
                return None;
            }
            total = total.checked_add(end - start)?;
            ranges.push((start, end));
        }
        let first = *ranges.first()?;
        let last = *ranges.last()?;
        if ranges.windows(2).all(|w| w[0].1 == w[1].0) {
            return Some(Resolved {
                data: Cow::Borrowed(bytes.get(first.0..last.1)?),
                first: (first.0, last.1),
                contiguous_from: Some(first.0),
                ranges,
            });
        }
        let mut data = Vec::with_capacity(total);
        for &(start, end) in &ranges {
            data.extend_from_slice(bytes.get(start..end)?);
        }
        Some(Resolved {
            data: Cow::Owned(data),
            first,
            contiguous_from: None,
            ranges,
        })
    }

    fn decoded<'r>(&mut self, item: &'r Resolved<'_>, coding: Coding) -> Option<Cow<'r, [u8]>> {
        let (start, end) = item.first;
        match coding {
            Coding::Plain => Some(Cow::Borrowed(&item.data)),
            Coding::Unknown => {
                self.not_scanned((start, end), ENCODED_ITEM);
                None
            }
            Coding::Deflate => match inflate(&item.data, self.budget) {
                Inflated::Text(out) => {
                    self.sink.add_inflated(out.len());
                    Some(Cow::Owned(out))
                }
                Inflated::Corrupt(partial) => {
                    self.sink.add_inflated(partial.len());
                    self.invalid(start, end);
                    Some(Cow::Owned(partial))
                }
                Inflated::LimitHit => {
                    self.sink.limit_hit(start, end, INFLATE_LIMIT);
                    None
                }
            },
        }
    }

    fn emit(&mut self, item: &Resolved<'_>, wanted: Item) {
        let Some(data) = self.decoded(item, wanted.coding) else {
            return;
        };
        let (start, end) = item.first;
        let contiguous = item
            .contiguous_from
            .filter(|_| wanted.coding == Coding::Plain);
        let budget = &*self.budget;
        match wanted.kind {
            Wanted::Exif => {
                let tiff = be_usize(&data, 0, 4)
                    .and_then(|offset| offset.checked_add(4))
                    .and_then(|skip| Some((skip, data.get(skip..)?)));
                let Some((mut skip, mut tiff)) = tiff else {
                    self.sink.malformed(INVALID_ITEM, start, end);
                    return;
                };
                if tiff.starts_with(EXIF_PREFIX) {
                    skip += EXIF_PREFIX.len();
                    tiff = &tiff[EXIF_PREFIX.len()..];
                }
                let placement = match contiguous {
                    Some(from) => Placement::Mapped(from + skip),
                    None => Placement::Whole(start, end),
                };
                self.sink.exif_at("AVIF Exif", tiff, placement, budget);
            }
            Wanted::Xmp => {
                self.sink
                    .xmp("AVIF XMP", &data, start, end, contiguous.is_some(), budget);
            }
            Wanted::Xml => {
                self.sink
                    .xmp("AVIF XML", &data, start, end, contiguous.is_some(), budget);
            }
            Wanted::Text => {
                self.sink
                    .carrier("AVIF text", &lossy(&data), start, end, &data);
            }
            Wanted::Uri => {
                self.sink
                    .carrier("AVIF uri item", &lossy(&data), start, end, &data);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::model::{CarrierKind, Family, FileKind, RuleStatus, Severity, SkipReason};
    use std::time::Duration;

    const TIFF: [u8; 32] = [
        0x49, 0x49, 0x2A, 0x00, 0x08, 0, 0, 0, 0x01, 0, 0x0E, 0x01, 0x02, 0, 0x06, 0, 0, 0, 0x1A,
        0, 0, 0, 0, 0, 0, 0, b'h', b'e', b'l', b'l', b'o', 0,
    ];
    const XMP_MIME: &[u8] = b"application/rdf+xml";

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

    fn spans(out: &DetectorOutput) -> Vec<(u64, u64)> {
        out.carriers
            .iter()
            .map(|c| (c.span.byte_start, c.span.byte_end))
            .collect()
    }

    fn riff(chunks: &[(&[u8; 4], u32, &[u8])]) -> Vec<u8> {
        let mut body = b"WEBP".to_vec();
        for (kind, size, payload) in chunks {
            body.extend_from_slice(*kind);
            body.extend_from_slice(&size.to_le_bytes());
            body.extend_from_slice(payload);
        }
        let mut v = b"RIFF".to_vec();
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&body);
        v
    }

    fn bx(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut v = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(kind);
        v.extend_from_slice(payload);
        v
    }

    fn full(kind: &[u8; 4], version: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![version, 0, 0, 0];
        payload.extend_from_slice(body);
        bx(kind, &payload)
    }

    fn ftyp() -> Vec<u8> {
        bx(b"ftyp", b"avif\0\0\0\0mif1")
    }

    fn infe(version: u8, id: u32, kind: &[u8; 4], content_type: Option<&[u8]>) -> Vec<u8> {
        let mut body = if version == 2 {
            (id as u16).to_be_bytes().to_vec()
        } else {
            id.to_be_bytes().to_vec()
        };
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(kind);
        body.push(0);
        if let Some(ct) = content_type {
            body.extend_from_slice(ct);
            body.push(0);
        }
        full(b"infe", version, &body)
    }

    fn iinf(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut body = (entries.len() as u16).to_be_bytes().to_vec();
        for e in entries {
            body.extend_from_slice(e);
        }
        full(b"iinf", 0, &body)
    }

    fn iloc0(items: &[(u16, Vec<(u32, u32)>)]) -> Vec<u8> {
        let mut body = vec![0x44, 0x00];
        body.extend_from_slice(&(items.len() as u16).to_be_bytes());
        for (id, extents) in items {
            body.extend_from_slice(&id.to_be_bytes());
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&(extents.len() as u16).to_be_bytes());
            for (offset, length) in extents {
                body.extend_from_slice(&offset.to_be_bytes());
                body.extend_from_slice(&length.to_be_bytes());
            }
        }
        full(b"iloc", 0, &body)
    }

    fn exif_item() -> Vec<u8> {
        let mut v = vec![0, 0, 0, 0];
        v.extend_from_slice(&TIFF);
        v
    }

    fn assemble(wrap: usize, children: &dyn Fn(u32) -> Vec<u8>, mdat: &[u8]) -> Vec<u8> {
        let build = |base: u32| {
            let mut meta = full(b"meta", 0, &children(base));
            for _ in 0..wrap {
                meta = bx(b"moov", &meta);
            }
            let mut v = ftyp();
            v.extend_from_slice(&meta);
            v.extend_from_slice(&bx(b"mdat", mdat));
            v
        };
        let probe = build(0);
        build((probe.len() - mdat.len()) as u32)
    }

    fn exif_children(base: u32) -> Vec<u8> {
        let mut c = iinf(&[infe(2, 1, b"Exif", None)]);
        c.extend_from_slice(&iloc0(&[(1, vec![(base, 36)])]));
        c
    }

    #[test]
    fn webp_exif_and_xmp_chunks_extracted() {
        let xmp = b"<a>secret</a>";
        let bytes = riff(&[(b"EXIF", 32, &TIFF), (b"XMP ", 13, xmp)]);
        let out = scan_webp(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec!["WebP Exif ImageDescription: hello", "WebP XMP: secret"]
        );
        assert_eq!(spans(&out), vec![(46, 52), (63, 69)]);
        assert_eq!(out.carriers[0].evidence, b"hello\0");
        assert_eq!(out.carriers[1].evidence, b"secret");
        assert!(
            out.carriers
                .iter()
                .all(|c| c.kind == CarrierKind::MetadataField && !c.hidden)
        );
        assert_eq!(out.skip, None);
    }

    #[test]
    fn webp_odd_chunk_is_padded_to_even_length() {
        let bytes = riff(&[(b"ABCD", 3, b"xyz\0"), (b"EXIF", 32, &TIFF)]);
        let out = scan_webp(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["WebP Exif ImageDescription: hello"]);
        assert_eq!(spans(&out), vec![(58, 64)]);
    }

    #[test]
    fn webp_exif_with_exif_nul_nul_prefix_is_skipped() {
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&TIFF);
        let bytes = riff(&[(b"EXIF", 38, &payload)]);
        let out = scan_webp(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["WebP Exif ImageDescription: hello"]);
        assert_eq!(spans(&out), vec![(52, 58)]);
    }

    #[test]
    fn webp_truncated_chunk_keeps_earlier_carriers_and_marks_the_webp_malformed() {
        let bytes = riff(&[(b"EXIF", 32, &TIFF), (b"XMP ", 100, b"<a>x</a>")]);
        let out = scan_webp(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["WebP Exif ImageDescription: hello"]);
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed WebP: truncated chunk", 52, 68)]
        );
        assert_eq!(out.skip, Some(SkipReason::Malformed));
        let huge = riff(&[(b"XMP ", u32::MAX, b"<a>x</a>")]);
        let out = scan_webp(&huge, &mut budget());
        assert!(out.carriers.is_empty());
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed WebP: truncated chunk", 12, 28)]
        );
        let mut header = riff(&[(b"EXIF", 32, &TIFF)]);
        header.extend_from_slice(b"XMP");
        let size = (header.len() - 8) as u32;
        header[4..8].copy_from_slice(&size.to_le_bytes());
        let out = scan_webp(&header, &mut budget());
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed WebP: truncated chunk", 52, 55)]
        );
    }

    #[test]
    fn data_after_the_riff_size_follows_the_trailer_rule() {
        let with = |tail: &[u8]| {
            let mut bytes = riff(&[(b"EXIF", 32, &TIFF)]);
            bytes.extend_from_slice(tail);
            scan_webp(&bytes, &mut budget())
        };
        let out = with(b"note for the reader");
        assert_eq!(
            texts(&out),
            vec![
                "WebP Exif ImageDescription: hello",
                "WebP data after RIFF: note for the reader"
            ]
        );
        assert!(out.carriers[1].hidden);
        assert_eq!(
            findings(&out),
            vec![("B004", "data after the end of the image", 52, 71)]
        );
        let out = with(b"PK\x03\x04rest of a zip");
        assert_eq!(findings(&out)[0].0, "B004");
        assert_eq!(out.embedded[0].format, Some("zip"));
        let out = with(b"\0\0\0\0");
        assert!(out.findings.is_empty() && out.embedded.is_empty());
    }

    #[test]
    fn a_riff_size_that_does_not_fit_the_file_marks_the_webp_malformed() {
        for declared in [1000u32, 0] {
            let mut bytes = riff(&[(b"EXIF", 32, &TIFF)]);
            bytes[4..8].copy_from_slice(&declared.to_le_bytes());
            let out = scan_webp(&bytes, &mut budget());
            assert_eq!(texts(&out), vec!["WebP Exif ImageDescription: hello"]);
            assert_eq!(
                findings(&out),
                vec![(
                    "L001",
                    "malformed WebP: RIFF size does not fit the file",
                    4,
                    8
                )]
            );
        }
    }

    #[test]
    fn avif_exif_item_resolved_via_iloc() {
        let bytes = assemble(0, &exif_children, &exif_item());
        assert_eq!(bytes.len(), 20 + 77 + 8 + 36);
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF Exif ImageDescription: hello"]);
        assert_eq!(spans(&out), vec![(135, 141)]);
        assert_eq!(out.carriers[0].evidence, b"hello\0");
        assert_eq!(out.carriers[0].kind, CarrierKind::MetadataField);
        assert!(!out.carriers[0].hidden);
        assert_eq!(out.skip, None);
    }

    #[test]
    fn box_size_overflow_does_not_panic() {
        let mut max32 = ftyp();
        max32.extend_from_slice(&u32::MAX.to_be_bytes());
        max32.extend_from_slice(b"meta");
        max32.extend_from_slice(&[0; 16]);
        let mut max64 = ftyp();
        max64.extend_from_slice(&[0, 0, 0, 1]);
        max64.extend_from_slice(b"meta");
        max64.extend_from_slice(&u64::MAX.to_be_bytes());
        max64.extend_from_slice(&[0; 16]);
        let mut small64 = ftyp();
        small64.extend_from_slice(&[0, 0, 0, 1]);
        small64.extend_from_slice(b"meta");
        small64.extend_from_slice(&8u64.to_be_bytes());
        let mut base_overflow = vec![0x44, 0x80];
        base_overflow.extend_from_slice(&1u16.to_be_bytes());
        base_overflow.extend_from_slice(&1u16.to_be_bytes());
        base_overflow.extend_from_slice(&[0, 0, 0, 0]);
        base_overflow.extend_from_slice(&u64::MAX.to_be_bytes());
        base_overflow.extend_from_slice(&1u16.to_be_bytes());
        base_overflow.extend_from_slice(&8u32.to_be_bytes());
        base_overflow.extend_from_slice(&4u32.to_be_bytes());
        let mut checked = ftyp();
        let mut children = iinf(&[infe(2, 1, b"Exif", None)]);
        children.extend_from_slice(&full(b"iloc", 1, &base_overflow));
        checked.extend_from_slice(&full(b"meta", 0, &children));
        let mut wide = vec![0x88, 0x00];
        wide.extend_from_slice(&1u16.to_be_bytes());
        wide.extend_from_slice(&1u16.to_be_bytes());
        wide.extend_from_slice(&[0, 0]);
        wide.extend_from_slice(&1u16.to_be_bytes());
        wide.extend_from_slice(&u64::MAX.to_be_bytes());
        wide.extend_from_slice(&u64::MAX.to_be_bytes());
        let mut wide_file = ftyp();
        let mut children = iinf(&[infe(2, 1, b"Exif", None)]);
        children.extend_from_slice(&full(b"iloc", 0, &wide));
        wide_file.extend_from_slice(&full(b"meta", 0, &children));
        for input in [max32, max64, small64, checked, wide_file] {
            let out = scan_avif(&input, &mut budget());
            assert!(out.carriers.is_empty());
        }
    }

    #[test]
    fn iloc_v1_construction_method_1_reads_from_idat() {
        let mut iloc = vec![0x44, 0x00];
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&[0, 0]);
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&0u32.to_be_bytes());
        iloc.extend_from_slice(&36u32.to_be_bytes());
        let mut children = iinf(&[infe(2, 1, b"Exif", None)]);
        children.extend_from_slice(&full(b"iloc", 1, &iloc));
        children.extend_from_slice(&bx(b"idat", &exif_item()));
        let mut bytes = ftyp();
        bytes.extend_from_slice(&full(b"meta", 0, &children));
        assert_eq!(bytes.len(), 20 + 123);
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF Exif ImageDescription: hello"]);
        assert_eq!(spans(&out), vec![(137, 143)]);
    }

    #[test]
    fn items_stored_by_reference_are_listed_as_not_scanned() {
        let mut iloc = vec![0x44, 0x00];
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&2u16.to_be_bytes());
        iloc.extend_from_slice(&[0, 0]);
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&0u32.to_be_bytes());
        iloc.extend_from_slice(&36u32.to_be_bytes());
        let mut external = vec![0x44, 0x00];
        external.extend_from_slice(&1u16.to_be_bytes());
        external.extend_from_slice(&1u16.to_be_bytes());
        external.extend_from_slice(&1u16.to_be_bytes());
        external.extend_from_slice(&1u16.to_be_bytes());
        external.extend_from_slice(&0u32.to_be_bytes());
        external.extend_from_slice(&36u32.to_be_bytes());
        for (version, body) in [(1u8, iloc), (0u8, external)] {
            let mut children = iinf(&[infe(2, 1, b"Exif", None)]);
            let iloc_at = 32 + children.len();
            let iloc_box = full(b"iloc", version, &body);
            let iloc_end = iloc_at + iloc_box.len();
            children.extend_from_slice(&iloc_box);
            children.extend_from_slice(&bx(b"idat", &exif_item()));
            let mut bytes = ftyp();
            bytes.extend_from_slice(&full(b"meta", 0, &children));
            let out = scan_avif(&bytes, &mut budget());
            assert!(out.carriers.is_empty());
            assert!(out.findings.is_empty());
            assert_eq!(out.embedded.len(), 1);
            let blob = &out.embedded[0];
            assert_eq!(
                (blob.kind, blob.format),
                (FileKind::UnknownBinary, Some("referenced item"))
            );
            assert_eq!(
                (blob.span.byte_start, blob.span.byte_end),
                (iloc_at as u64, iloc_end as u64)
            );
        }
    }

    fn infe_with(version: u8, id: u16, kind: &[u8; 4], name: &[u8], strings: &[&[u8]]) -> Vec<u8> {
        let mut body = id.to_be_bytes().to_vec();
        body.extend_from_slice(&[0, 0]);
        if version >= 2 {
            body.extend_from_slice(kind);
        }
        body.extend_from_slice(name);
        body.push(0);
        for s in strings {
            body.extend_from_slice(s);
            body.push(0);
        }
        full(b"infe", version, &body)
    }

    fn items_file(entries: &[Vec<u8>], items: &[(u16, usize)], mdat: &[u8]) -> Vec<u8> {
        let children = |base: u32| {
            let mut offset = base;
            let located: Vec<(u16, Vec<(u32, u32)>)> = items
                .iter()
                .map(|&(id, len)| {
                    let extent = (offset, len as u32);
                    offset += len as u32;
                    (id, vec![extent])
                })
                .collect();
            let mut c = iinf(entries);
            c.extend_from_slice(&iloc0(&located));
            c
        };
        assemble(0, &children, mdat)
    }

    #[test]
    fn version_0_and_1_item_info_with_an_xmp_content_type_is_read() {
        for version in [0, 1] {
            let entry = infe_with(version, 1, b"mime", b"", &[XMP_MIME]);
            let bytes = items_file(&[entry], &[(1, 13)], b"<a>secret</a>");
            let out = scan_avif(&bytes, &mut budget());
            assert_eq!(texts(&out), vec!["AVIF XMP: secret"], "{version}");
            assert!(out.findings.is_empty());
        }
    }

    #[test]
    fn item_names_are_carriers() {
        let entry = infe_with(2, 1, b"Exif", b"Kitchen", &[]);
        let bytes = items_file(&[entry], &[(1, 36)], &exif_item());
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "AVIF item name: Kitchen",
                "AVIF Exif ImageDescription: hello"
            ]
        );
        assert_eq!(spans(&out)[0], (66, 73));
        let old = infe_with(0, 1, b"    ", b"Pantry", &[b"image/jpeg"]);
        let out = scan_avif(&items_file(&[old], &[], b""), &mut budget());
        assert_eq!(texts(&out), vec!["AVIF item name: Pantry"]);
    }

    #[test]
    fn deflate_encoded_items_are_inflated_within_the_budget() {
        let z = miniz_oxide::deflate::compress_to_vec_zlib(b"<a>secret</a>", 6);
        let entry = infe_with(2, 1, b"mime", b"", &[XMP_MIME, b"deflate"]);
        let bytes = items_file(&[entry], &[(1, z.len())], &z);
        let mut b = budget();
        let out = scan_avif(&bytes, &mut b);
        assert_eq!(texts(&out), vec!["AVIF XMP: secret"]);
        assert_eq!(
            b.remaining_decompressed(),
            Limits::default().max_decompressed_bytes - 13
        );
        let bomb = miniz_oxide::deflate::compress_to_vec_zlib(&vec![b'A'; 100_000], 6);
        let entry = infe_with(2, 1, b"mime", b"", &[XMP_MIME, b"deflate"]);
        let bytes = items_file(&[entry], &[(1, bomb.len())], &bomb);
        let limits = Limits {
            max_decompressed_bytes: 1000,
            ..Limits::default()
        };
        let out = scan_avif(&bytes, &mut Budget::new(&limits));
        assert_eq!(findings(&out)[0].0, "B002");
        assert_eq!(out.skip, Some(SkipReason::DecompressionLimit));
        let entry = infe_with(2, 1, b"mime", b"", &[XMP_MIME, b"br"]);
        let out = scan_avif(&items_file(&[entry], &[(1, 4)], b"abcd"), &mut budget());
        assert!(out.carriers.is_empty() && out.findings.is_empty());
        assert_eq!(out.embedded[0].format, Some("encoded item"));
        let mut corrupt = miniz_oxide::deflate::compress_to_vec_zlib(b"<a>secret</a>", 6);
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        let entry = infe_with(2, 1, b"mime", b"", &[XMP_MIME, b"deflate"]);
        let out = scan_avif(
            &items_file(&[entry], &[(1, corrupt.len())], &corrupt),
            &mut budget(),
        );
        assert_eq!(texts(&out), vec!["AVIF XMP: secret"]);
        assert_eq!(
            findings(&out)[0].1,
            "malformed AVIF: invalid item information"
        );
    }

    #[test]
    fn text_xml_and_uri_items_are_carriers() {
        let entries = [
            infe_with(2, 1, b"mime", b"", &[b"text/plain"]),
            infe_with(2, 2, b"mime", b"", &[b"application/xml"]),
            infe_with(2, 3, b"uri ", b"", &[b"urn:example:note"]),
        ];
        let mdat = b"hello there<a>words</a>a note";
        let bytes = items_file(&entries, &[(1, 11), (2, 12), (3, 6)], mdat);
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(
            texts(&out),
            vec![
                "AVIF text: hello there",
                "AVIF XML: words",
                "AVIF uri item: a note"
            ]
        );
        assert!(out.findings.is_empty());
    }

    #[test]
    fn broken_item_structures_mark_the_avif_malformed() {
        let exif = || infe(2, 1, b"Exif", None);
        let with_iloc = |entries: Vec<Vec<u8>>, iloc: Vec<u8>| {
            let mut c = iinf(&entries);
            c.extend_from_slice(&iloc);
            let mut bytes = ftyp();
            bytes.extend_from_slice(&full(b"meta", 0, &c));
            bytes.extend_from_slice(&bx(b"mdat", &exif_item()));
            bytes
        };
        let good_iloc = || iloc0(&[(1, vec![(0, 36)])]);
        let mut cut_iloc = vec![0x44, 0x00];
        cut_iloc.extend_from_slice(&1u16.to_be_bytes());
        cut_iloc.push(0);
        let mut method_1 = vec![0x44, 0x00];
        method_1.extend_from_slice(&1u16.to_be_bytes());
        method_1.extend_from_slice(&1u16.to_be_bytes());
        method_1.extend_from_slice(&1u16.to_be_bytes());
        method_1.extend_from_slice(&[0, 0]);
        method_1.extend_from_slice(&1u16.to_be_bytes());
        method_1.extend_from_slice(&0u32.to_be_bytes());
        method_1.extend_from_slice(&36u32.to_be_bytes());
        let cases = [
            with_iloc(vec![full(b"infe", 4, &[0, 1, 0, 0])], good_iloc()),
            with_iloc(vec![full(b"infe", 2, &[0])], good_iloc()),
            with_iloc(vec![exif()], full(b"iloc", 3, &[0x44, 0, 0, 1])),
            with_iloc(vec![exif()], full(b"iloc", 0, &cut_iloc)),
            with_iloc(vec![exif()], iloc0(&[(1, vec![(100_000, 36)])])),
            with_iloc(vec![exif()], full(b"iloc", 1, &method_1)),
        ];
        for bytes in cases {
            let out = scan_avif(&bytes, &mut budget());
            let found: Vec<(&str, &str)> = findings(&out).iter().map(|f| (f.0, f.1)).collect();
            assert_eq!(
                found,
                vec![("L001", "malformed AVIF: invalid item information")]
            );
            assert_eq!(out.skip, Some(SkipReason::Malformed));
        }
        let mut cut_iinf = ftyp();
        cut_iinf.extend_from_slice(&full(b"meta", 0, &full(b"iinf", 0, &[])));
        let out = scan_avif(&cut_iinf, &mut budget());
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed AVIF: invalid item information", 32, 44)]
        );
    }

    #[test]
    fn an_exif_item_with_a_bad_header_offset_marks_the_avif_malformed() {
        let mut item = vec![0, 0, 1, 0];
        item.extend_from_slice(&TIFF);
        let bytes = items_file(&[infe(2, 1, b"Exif", None)], &[(1, 36)], &item);
        let out = scan_avif(&bytes, &mut budget());
        assert!(out.carriers.is_empty());
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed AVIF: invalid item information", 105, 141)]
        );
    }

    #[test]
    fn a_meta_with_only_one_of_iinf_and_iloc_marks_the_avif_malformed() {
        let only_iinf = iinf(&[infe(2, 1, b"Exif", None)]);
        let only_iloc = iloc0(&[(1, vec![(0, 36)])]);
        for children in [only_iinf, only_iloc] {
            let mut bytes = ftyp();
            bytes.extend_from_slice(&full(b"meta", 0, &children));
            let out = scan_avif(&bytes, &mut budget());
            assert_eq!(
                findings(&out),
                vec![(
                    "L001",
                    "malformed AVIF: invalid item information",
                    32,
                    32 + children.len() as u64
                )]
            );
        }
        let mut neither = ftyp();
        neither.extend_from_slice(&full(b"meta", 0, &bx(b"hdlr", &[0; 8])));
        assert!(scan_avif(&neither, &mut budget()).findings.is_empty());
        let mut empty = iinf(&[]);
        empty.extend_from_slice(&iloc0(&[]));
        let mut both_empty = ftyp();
        both_empty.extend_from_slice(&full(b"meta", 0, &empty));
        assert!(scan_avif(&both_empty, &mut budget()).findings.is_empty());
    }

    #[test]
    fn top_level_leftovers_are_a_trailer_or_a_truncated_box() {
        let base = assemble(0, &exif_children, &exif_item());
        let at = base.len() as u64;
        let with = |tail: &[u8]| {
            let mut bytes = base.clone();
            bytes.extend_from_slice(tail);
            scan_avif(&bytes, &mut budget())
        };
        let out = with(b"note for the reader");
        assert_eq!(
            texts(&out),
            vec![
                "AVIF Exif ImageDescription: hello",
                "AVIF data after the last box: note for the reader"
            ]
        );
        assert!(out.carriers[1].hidden);
        assert_eq!(
            findings(&out),
            vec![("B004", "data after the end of the image", at, at + 19)]
        );
        let out = with(b"PK\x03\x04rest of a zip");
        assert_eq!(findings(&out)[0].0, "B004");
        assert_eq!(out.embedded[0].format, Some("zip"));
        let out = with(b"\0\0\0\0");
        assert!(out.findings.is_empty());
        let out = with(b"\0\0\0\x64mdatabc");
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed AVIF: truncated box", at, at + 11)]
        );
        let mut nested = ftyp();
        let mut children = iinf(&[infe(2, 1, b"Exif", None)]);
        children.extend_from_slice(&[0, 0, 0, 50, b'i', b'l', b'o', b'c']);
        nested.extend_from_slice(&full(b"meta", 0, &children));
        let out = scan_avif(&nested, &mut budget());
        let cut = (32 + children.len() - 8) as u64;
        assert_eq!(
            findings(&out),
            vec![("L001", "malformed AVIF: truncated box", cut, cut + 8)]
        );
    }

    #[test]
    fn infe_v3_mime_xmp_item_through_iloc_v2_with_u32_ids() {
        let xmp = b"<a>secret</a>";
        let children = |base: u32| {
            let mut iloc = vec![0x44, 0x00];
            iloc.extend_from_slice(&1u32.to_be_bytes());
            iloc.extend_from_slice(&65536u32.to_be_bytes());
            iloc.extend_from_slice(&[0, 0, 0, 0]);
            iloc.extend_from_slice(&1u16.to_be_bytes());
            iloc.extend_from_slice(&base.to_be_bytes());
            iloc.extend_from_slice(&13u32.to_be_bytes());
            let mut c = iinf(&[infe(3, 65536, b"mime", Some(XMP_MIME))]);
            c.extend_from_slice(&full(b"iloc", 2, &iloc));
            c
        };
        let bytes = assemble(0, &children, xmp);
        assert_eq!(bytes.len(), 20 + 105 + 8 + 13);
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF XMP: secret"]);
        assert_eq!(spans(&out), vec![(136, 142)]);
        assert_eq!(out.carriers[0].evidence, b"secret");
    }

    #[test]
    fn mime_item_with_a_text_or_unknown_content_type() {
        let children = |kind: &'static [u8]| {
            move |base: u32| {
                let mut c = iinf(&[infe(2, 1, b"mime", Some(kind))]);
                c.extend_from_slice(&iloc0(&[(1, vec![(base, 13)])]));
                c
            }
        };
        let text = assemble(0, &children(b"text/plain"), b"<a>secret</a>");
        assert_eq!(
            texts(&scan_avif(&text, &mut budget())),
            vec!["AVIF text: <a>secret</a>"]
        );
        let other = assemble(0, &children(b"image/jpeg"), b"<a>secret</a>");
        assert!(scan_avif(&other, &mut budget()).carriers.is_empty());
    }

    #[test]
    fn largesize_meta_box_is_parsed() {
        let build = |base: u32| {
            let children = {
                let mut c = iinf(&[infe(2, 1, b"Exif", None)]);
                c.extend_from_slice(&iloc0(&[(1, vec![(base, 36)])]));
                c
            };
            let mut payload = vec![0, 0, 0, 0];
            payload.extend_from_slice(&children);
            let mut v = ftyp();
            v.extend_from_slice(&[0, 0, 0, 1]);
            v.extend_from_slice(b"meta");
            v.extend_from_slice(&(16 + payload.len() as u64).to_be_bytes());
            v.extend_from_slice(&payload);
            v.extend_from_slice(&bx(b"mdat", &exif_item()));
            v
        };
        let probe = build(0);
        let bytes = build((probe.len() - 36) as u32);
        assert_eq!(bytes.len(), 20 + 85 + 8 + 36);
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF Exif ImageDescription: hello"]);
        assert_eq!(spans(&out), vec![(143, 149)]);
    }

    #[test]
    fn size_zero_last_box_runs_to_end_of_file() {
        let mut bytes = ftyp();
        bytes.extend_from_slice(&bx(b"mdat", &exif_item()));
        let mut meta = full(b"meta", 0, &exif_children(28));
        meta[0..4].copy_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(&meta);
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF Exif ImageDescription: hello"]);
        assert_eq!(spans(&out), vec![(58, 64)]);
    }

    #[test]
    fn multi_extent_item_spans_the_first_extent() {
        let item = exif_item();
        let mut mdat = item[..10].to_vec();
        mdat.extend_from_slice(b"ZZ");
        mdat.extend_from_slice(&item[10..]);
        let children = |base: u32| {
            let mut c = iinf(&[infe(2, 1, b"Exif", None)]);
            c.extend_from_slice(&iloc0(&[(1, vec![(base, 10), (base + 12, 26)])]));
            c
        };
        let bytes = assemble(0, &children, &mdat);
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF Exif ImageDescription: hello"]);
        assert_eq!(spans(&out), vec![(113, 123)]);
        assert_eq!(out.carriers[0].evidence, b"hello\0");
    }

    #[test]
    fn exif_item_tiff_offset_header_is_honoured() {
        let mut item = vec![0, 0, 0, 2, 9, 9];
        item.extend_from_slice(&TIFF);
        let children = |base: u32| {
            let mut c = iinf(&[infe(2, 1, b"Exif", None)]);
            c.extend_from_slice(&iloc0(&[(1, vec![(base, 38)])]));
            c
        };
        let bytes = assemble(0, &children, &item);
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(spans(&out), vec![(137, 143)]);
        let mut bad = vec![0xFF, 0xFF, 0xFF, 0xFF];
        bad.extend_from_slice(&TIFF);
        let bytes = assemble(0, &exif_children, &bad);
        assert!(scan_avif(&bytes, &mut budget()).carriers.is_empty());
    }

    #[test]
    fn more_than_a_thousand_items_stops_with_a_visible_limit() {
        let build = |count: u32| {
            let children = move |base: u32| {
                let mut entries = vec![infe(2, 1, b"Exif", None)];
                for id in 2..=count {
                    entries.push(infe(2, id, b"hvc1", None));
                }
                let mut c = iinf(&entries);
                c.extend_from_slice(&iloc0(&[(1, vec![(base, 36)])]));
                c
            };
            assemble(0, &children, &exif_item())
        };
        let over = scan_avif(&build(1001), &mut budget());
        assert_eq!(texts(&over), vec!["AVIF Exif ImageDescription: hello"]);
        assert_eq!(over.skip, Some(SkipReason::SizeLimit));
        assert!(over.findings.iter().any(|f| f.rule_id == "L001"));
        let exact = scan_avif(&build(1000), &mut budget());
        assert_eq!(exact.skip, None);
        assert!(exact.findings.is_empty());
    }

    #[test]
    fn box_nesting_is_capped_at_thirty_two() {
        let at_cap = assemble(32, &exif_children, &exif_item());
        let out = scan_avif(&at_cap, &mut budget());
        assert_eq!(out.carriers.len(), 1);
        assert_eq!(out.skip, None);
        let over = assemble(33, &exif_children, &exif_item());
        let out = scan_avif(&over, &mut budget());
        assert!(out.carriers.is_empty());
        assert_eq!(out.skip, Some(SkipReason::SizeLimit));
        assert!(out.findings.iter().any(|f| f.rule_id == "L001"));
        let deep = assemble(5000, &exif_children, &exif_item());
        assert!(scan_avif(&deep, &mut budget()).carriers.is_empty());
    }

    #[test]
    fn overlapping_text_extents_stay_within_the_output_cap() {
        let mut packet = b"<a>".to_vec();
        packet.extend(std::iter::repeat_n(b'x', 100_000));
        packet.extend_from_slice(b"</a>");
        let length = packet.len() as u32;
        let children = move |base: u32| {
            let mut entries = Vec::new();
            let mut items = Vec::new();
            for id in 1..=1000u32 {
                entries.push(infe(2, id, b"mime", Some(XMP_MIME)));
                items.push((id as u16, vec![(base, length)]));
            }
            let mut c = iinf(&entries);
            c.extend_from_slice(&iloc0(&items));
            c
        };
        let bytes = assemble(0, &children, &packet);
        let out = scan_avif(&bytes, &mut budget());
        let used: usize = out
            .carriers
            .iter()
            .map(|c| c.text.split_once(": ").map_or(0, |(_, t)| t.len()) + c.evidence.len())
            .sum();
        assert!(used <= bytes.len() * 3 + 64 * 1024);
        assert!(!out.carriers.is_empty());
        assert!(out.findings.iter().any(|f| f.rule_id == "B003"));
        assert_eq!(out.skip, Some(SkipReason::SizeLimit));
    }

    #[test]
    fn overlapping_extents_cannot_amplify_output() {
        let packet = b"<b/>".repeat(25_000);
        let length = packet.len() as u32;
        let children = move |base: u32| {
            let mut entries = Vec::new();
            let mut items = Vec::new();
            for id in 1..=1000u32 {
                entries.push(infe(2, id, b"mime", Some(XMP_MIME)));
                items.push((id as u16, vec![(base, length)]));
            }
            let mut c = iinf(&entries);
            c.extend_from_slice(&iloc0(&items));
            c
        };
        let bytes = assemble(0, &children, &packet);
        let out = scan_avif(&bytes, &mut budget());
        assert!(out.carriers.is_empty());
        assert_eq!(out.skip, Some(SkipReason::SizeLimit));
        let limits: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.rule_id == "B003")
            .map(|f| {
                (
                    f.family,
                    f.base,
                    f.status,
                    f.carrier,
                    f.payload.clone(),
                    f.message.as_str(),
                )
            })
            .collect();
        assert_eq!(
            limits,
            vec![(
                Family::B,
                Severity::High,
                RuleStatus::Stable,
                CarrierKind::ResourceLimit,
                None,
                "metadata amplification"
            )]
        );
        assert!(out.findings.iter().all(|f| f.rule_id != "L001"));
    }

    #[test]
    fn duplicate_infe_entries_for_one_id_parse_the_item_once() {
        let children = |base: u32| {
            let entries: Vec<_> = (0..3)
                .map(|_| infe(2, 1, b"mime", Some(XMP_MIME)))
                .collect();
            let mut c = iinf(&entries);
            c.extend_from_slice(&iloc0(&[(1, vec![(base, 13)])]));
            c
        };
        let bytes = assemble(0, &children, b"<a>secret</a>");
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF XMP: secret"]);
    }

    #[test]
    fn thousand_duplicate_infe_entries_on_a_large_textless_item_parse_once() {
        let packet = b"<b/>".repeat(25_000);
        let length = packet.len() as u32;
        let children = move |base: u32| {
            let entries: Vec<_> = (0..1000)
                .map(|_| infe(2, 1, b"mime", Some(XMP_MIME)))
                .collect();
            let mut c = iinf(&entries);
            c.extend_from_slice(&iloc0(&[(1, vec![(base, length)])]));
            c
        };
        let bytes = assemble(0, &children, &packet);
        let out = scan_avif(&bytes, &mut budget());
        assert!(out.carriers.is_empty());
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }

    #[test]
    fn extent_length_zero_runs_to_the_end_of_the_file() {
        let children = |base: u32| {
            let mut c = iinf(&[infe(2, 1, b"Exif", None)]);
            c.extend_from_slice(&iloc0(&[(1, vec![(base, 0)])]));
            c
        };
        let bytes = assemble(0, &children, &exif_item());
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF Exif ImageDescription: hello"]);
        assert_eq!(spans(&out), vec![(135, 141)]);
    }

    #[test]
    fn length_size_zero_runs_to_the_end_of_the_file() {
        let children = |base: u32| {
            let mut body = vec![0x40, 0x00];
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&base.to_be_bytes());
            let mut c = iinf(&[infe(2, 1, b"Exif", None)]);
            c.extend_from_slice(&full(b"iloc", 0, &body));
            c
        };
        let bytes = assemble(0, &children, &exif_item());
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF Exif ImageDescription: hello"]);
        assert_eq!(spans(&out), vec![(131, 137)]);
    }

    #[test]
    fn extent_length_zero_in_idat_runs_to_the_end_of_idat() {
        let mut iloc = vec![0x44, 0x00];
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&[0, 0]);
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&0u32.to_be_bytes());
        iloc.extend_from_slice(&0u32.to_be_bytes());
        let mut children = iinf(&[infe(2, 1, b"Exif", None)]);
        children.extend_from_slice(&full(b"iloc", 1, &iloc));
        children.extend_from_slice(&bx(b"idat", &exif_item()));
        let mut bytes = ftyp();
        bytes.extend_from_slice(&full(b"meta", 0, &children));
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(spans(&out), vec![(137, 143)]);
    }

    #[test]
    fn content_type_ignores_case_parameters_and_padding() {
        for content_type in [
            &b"Application/RDF+XML"[..],
            b"application/rdf+xml; charset=utf-8",
            b"  application/rdf+xml ;x=y",
        ] {
            let children = |base: u32| {
                let mut c = iinf(&[infe(2, 1, b"mime", Some(content_type))]);
                c.extend_from_slice(&iloc0(&[(1, vec![(base, 13)])]));
                c
            };
            let bytes = assemble(0, &children, b"<a>secret</a>");
            let out = scan_avif(&bytes, &mut budget());
            assert_eq!(texts(&out), vec!["AVIF XMP: secret"]);
        }
        let children = |base: u32| {
            let mut c = iinf(&[infe(2, 1, b"mime", Some(b"application/rdf+xmlx"))]);
            c.extend_from_slice(&iloc0(&[(1, vec![(base, 13)])]));
            c
        };
        let bytes = assemble(0, &children, b"<a>secret</a>");
        assert!(scan_avif(&bytes, &mut budget()).carriers.is_empty());
    }

    #[test]
    fn iloc_offset_size_nibble_three_stops_safely_and_marks_the_avif_malformed() {
        let mut body = vec![0x34, 0x00];
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 0x80]);
        body.extend_from_slice(&36u32.to_be_bytes());
        let mut c = iinf(&[infe(2, 1, b"Exif", None)]);
        c.extend_from_slice(&full(b"iloc", 0, &body));
        let mut bytes = ftyp();
        bytes.extend_from_slice(&full(b"meta", 0, &c));
        bytes.extend_from_slice(&bx(b"mdat", &exif_item()));
        let out = scan_avif(&bytes, &mut budget());
        assert!(out.carriers.is_empty());
        assert_eq!(out.skip, Some(SkipReason::Malformed));
        assert_eq!(
            findings(&out)[0].1,
            "malformed AVIF: invalid item information"
        );
    }

    #[test]
    fn zero_deadline_times_out_both_carriers() {
        let limits = Limits {
            per_file_time: Duration::ZERO,
            ..Limits::default()
        };
        let avif = assemble(0, &exif_children, &exif_item());
        let out = scan_avif(&avif, &mut Budget::new(&limits));
        assert_eq!(out.skip, Some(SkipReason::Timeout));
        assert!(out.carriers.is_empty());
        let webp = riff(&[(b"EXIF", 32, &TIFF)]);
        let out = scan_webp(&webp, &mut Budget::new(&limits));
        assert_eq!(out.skip, Some(SkipReason::Timeout));
        assert!(out.carriers.is_empty());
    }

    #[test]
    fn non_riff_and_non_ftyp_inputs_give_nothing() {
        assert!(
            scan_webp(b"RIFX\0\0\0\0WEBP", &mut budget())
                .carriers
                .is_empty()
        );
        assert!(scan_webp(b"", &mut budget()).carriers.is_empty());
        assert!(scan_avif(b"", &mut budget()).carriers.is_empty());
        let no_ftyp = bx(b"meta", &[0; 8]);
        assert!(scan_avif(&no_ftyp, &mut budget()).carriers.is_empty());
    }

    fn xmp_packet(fill: u8) -> Vec<u8> {
        let mut v = b"<a>".to_vec();
        v.extend(std::iter::repeat_n(fill, 53));
        v.extend_from_slice(b"</a>");
        v
    }

    fn xmp_scene(iinf_ids: &[u32], extents: &[(u32, u32)]) -> Vec<u8> {
        let mut mdat = Vec::new();
        for i in 0..4u8 {
            mdat.extend_from_slice(&xmp_packet(b'a' + i));
        }
        let entries: Vec<Vec<u8>> = iinf_ids
            .iter()
            .map(|&id| infe(2, id, b"mime", Some(XMP_MIME)))
            .collect();
        let extents = extents.to_vec();
        let children = move |base: u32| {
            let mut c = iinf(&entries);
            let items: Vec<(u16, Vec<(u32, u32)>)> = extents
                .iter()
                .enumerate()
                .map(|(i, &(offset, length))| ((i + 1) as u16, vec![(base + offset, length)]))
                .collect();
            c.extend_from_slice(&iloc0(&items));
            c
        };
        assemble(0, &children, &mdat)
    }

    fn small_budget() -> Budget {
        Budget::new(&Limits {
            max_decompressed_bytes: 100,
            ..Limits::default()
        })
    }

    fn assert_b003(out: &DetectorOutput) {
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.rule_id, "B003");
        assert_eq!(f.family, Family::B);
        assert_eq!(f.base, Severity::High);
        assert_eq!(f.status, RuleStatus::Stable);
        assert_eq!(f.carrier, CarrierKind::ResourceLimit);
        assert_eq!(f.payload, None);
        assert_eq!(f.message, "metadata amplification");
        assert_eq!(out.skip, Some(SkipReason::SizeLimit));
    }

    #[test]
    fn duplicate_item_ids_exhausting_the_budget_give_b003() {
        let bytes = xmp_scene(
            &[1, 1, 2, 2, 3, 3, 4, 4],
            &[(0, 60), (60, 60), (120, 60), (180, 60)],
        );
        let out = scan_avif(&bytes, &mut small_budget());
        assert_b003(&out);
        assert_eq!(out.carriers.len(), 1);
    }

    #[test]
    fn overlapping_extents_exhausting_the_budget_give_b003() {
        let bytes = xmp_scene(&[1, 2, 3, 4], &[(0, 60), (0, 60), (0, 60), (0, 60)]);
        let out = scan_avif(&bytes, &mut small_budget());
        assert_b003(&out);
        assert_eq!(out.carriers.len(), 1);
    }

    #[test]
    fn well_formed_items_exhausting_a_small_budget_give_l001_low_and_incomplete() {
        let bytes = xmp_scene(&[1, 2, 3, 4], &[(0, 60), (60, 60), (120, 60), (180, 60)]);
        let out = scan_avif(&bytes, &mut small_budget());
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.rule_id, "L001");
        assert_eq!(f.family, Family::L);
        assert_eq!(f.base, Severity::Low);
        assert_eq!(f.status, RuleStatus::Stable);
        assert_eq!(f.carrier, CarrierKind::ResourceLimit);
        assert_eq!(f.payload, None);
        assert_eq!(f.message, "metadata work limit");
        assert_eq!(out.skip, Some(SkipReason::SizeLimit));
        assert_eq!(out.carriers.len(), 1);
    }

    fn iref_box(kind: &[u8; 4], from: u16, to: &[u16]) -> Vec<u8> {
        let mut body = from.to_be_bytes().to_vec();
        body.extend_from_slice(&(to.len() as u16).to_be_bytes());
        for t in to {
            body.extend_from_slice(&t.to_be_bytes());
        }
        bx(kind, &body)
    }

    #[test]
    fn phone_photo_shaped_heif_stays_under_the_budget_with_no_finding() {
        let mut mdat = vec![0u8; 8];
        for _ in 0..48 {
            mdat.extend_from_slice(&[0xAB; 100]);
        }
        mdat.extend_from_slice(&[0xCD; 64]);
        mdat.extend_from_slice(&exif_item());
        mdat.extend_from_slice(&[0xEF; 100]);
        assert_eq!(mdat.len(), 5008);
        let children = |base: u32| {
            let mut entries = vec![infe(2, 1, b"grid", None)];
            for id in 2..=49 {
                entries.push(infe(2, id, b"hvc1", None));
            }
            entries.push(infe(2, 50, b"hvc1", None));
            entries.push(infe(2, 51, b"Exif", None));
            entries.push(infe(2, 52, b"hvc1", None));
            let mut items = vec![(1u16, vec![(base, 8u32)])];
            for tile in 0..48u32 {
                items.push(((tile + 2) as u16, vec![(base + 8 + 100 * tile, 100)]));
            }
            items.push((50, vec![(base + 4808, 64)]));
            items.push((51, vec![(base + 4872, 36)]));
            items.push((52, vec![(base + 4908, 100)]));
            let mut c = iinf(&entries);
            c.extend_from_slice(&iloc0(&items));
            let tiles: Vec<u16> = (2..=49).collect();
            let mut refs = iref_box(b"dimg", 1, &tiles);
            refs.extend_from_slice(&iref_box(b"thmb", 50, &[1]));
            refs.extend_from_slice(&iref_box(b"cdsc", 51, &[1]));
            refs.extend_from_slice(&iref_box(b"auxl", 52, &[1]));
            c.extend_from_slice(&full(b"iref", 0, &refs));
            c
        };
        let bytes = assemble(0, &children, &mdat);
        let out = scan_avif(&bytes, &mut budget());
        assert_eq!(texts(&out), vec!["AVIF Exif ImageDescription: hello"]);
        let value_at = (bytes.len() - 5008 + 4872 + 4 + 26) as u64;
        assert_eq!(spans(&out), vec![(value_at, value_at + 6)]);
        assert!(out.findings.is_empty());
        assert_eq!(out.skip, None);
    }
}

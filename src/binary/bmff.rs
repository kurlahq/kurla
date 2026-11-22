use super::{Placement, Sink, sub};
use crate::limits::Budget;
use crate::model::DetectorOutput;
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
        sink.trailer(WEBP_TRAILER, bytes, riff_end, true);
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

fn is_xmp_mime(content_type: &[u8]) -> bool {
    let base = content_type
        .split(|&c| c == b';')
        .next()
        .unwrap_or_default();
    base.trim_ascii().eq_ignore_ascii_case(XMP_MIME)
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

impl<'a> Avif<'a> {
    fn expired(&mut self) -> bool {
        if self.budget.deadline_exceeded() {
            self.sink.timed_out();
            true
        } else {
            false
        }
    }

    fn run(&mut self) {
        let metas = self.find_metas();
        for (start, end) in metas {
            if self.sink.stop {
                break;
            }
            self.meta(start, end);
        }
    }

    fn find_metas(&mut self) -> Vec<(usize, usize)> {
        let mut metas = Vec::new();
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
                stack.pop();
                continue;
            };
            if let Some(top) = stack.last_mut() {
                top.at = b.end;
            }
            match &b.kind {
                b"meta" => {
                    if let Some(p) = b.payload.checked_add(4).filter(|&p| p <= b.end) {
                        metas.push((p, b.end));
                    }
                }
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
        metas
    }

    fn meta(&mut self, start: usize, end: usize) {
        let (mut iinf, mut iloc, mut idat) = (None, None, None);
        let mut at = start;
        while let Some(b) = read_box(self.bytes, at, end) {
            if self.expired() {
                return;
            }
            at = b.end;
            let slot = match &b.kind {
                b"iinf" => &mut iinf,
                b"iloc" => &mut iloc,
                b"idat" => &mut idat,
                _ => continue,
            };
            slot.get_or_insert(b);
        }
        let (Some(iinf), Some(iloc)) = (iinf, iloc) else {
            return;
        };
        let wanted = self.iinf(iinf);
        if wanted.is_empty() || self.sink.stop {
            return;
        }
        self.iloc(iloc, idat, &wanted);
    }

    fn iinf(&mut self, b: BoxHeader) -> HashMap<u32, Vec<Wanted>> {
        let mut wanted: HashMap<u32, Vec<Wanted>> = HashMap::new();
        let mut seen: HashSet<u32> = HashSet::new();
        let Some(&version) = self.bytes.get(b.payload) else {
            return wanted;
        };
        let count_width = if version == 0 { 2 } else { 4 };
        let mut at = match b.payload.checked_add(4 + count_width) {
            Some(at) if at <= b.end => at,
            _ => return wanted,
        };
        while let Some(entry) = read_box(self.bytes, at, b.end) {
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
            if let Some((id, kind)) = self.infe(entry) {
                if !seen.insert(id) {
                    self.anomaly = true;
                }
                if let Some(kind) = kind {
                    let kinds = wanted.entry(id).or_default();
                    if !kinds.contains(&kind) {
                        kinds.push(kind);
                    }
                }
            }
        }
        wanted
    }

    fn infe(&self, b: BoxHeader) -> Option<(u32, Option<Wanted>)> {
        let d = self.bytes.get(b.payload..b.end)?;
        let version = *d.first()?;
        if version > 3 {
            return None;
        }
        if version < 2 {
            return Some((u32::try_from(be(d, 4, 2)?).ok()?, None));
        }
        let id_width = if version == 2 { 2 } else { 4 };
        let id = u32::try_from(be(d, 4, id_width)?).ok()?;
        let type_at = 4 + id_width + 2;
        let kind = sub(d, type_at, 4)?;
        let rest = d.get(type_at + 4..)?;
        let wanted = match kind {
            b"Exif" => Some(Wanted::Exif),
            b"mime" => rest.iter().position(|&c| c == 0).and_then(|name_end| {
                let after = &rest[name_end + 1..];
                let content_type = after.split(|&c| c == 0).next().unwrap_or_default();
                is_xmp_mime(content_type).then_some(Wanted::Xmp)
            }),
            _ => None,
        };
        Some((id, wanted))
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

    fn iloc(&mut self, b: BoxHeader, idat: Option<BoxHeader>, wanted: &HashMap<u32, Vec<Wanted>>) {
        let bytes = self.bytes;
        let Some(d) = bytes.get(b.payload..b.end) else {
            return;
        };
        let Some(&version) = d.first() else {
            return;
        };
        let (Some(&sizes), Some(&bases)) = (d.get(4), d.get(5)) else {
            return;
        };
        if version > 2 {
            return;
        }
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
        if !(valid(widths.index) && valid(widths.offset) && valid(base_width))
            || !valid(widths.length)
        {
            return;
        }
        let id_width = if version < 2 { 2 } else { 4 };
        let Some(mut remaining) = be(d, 6, id_width) else {
            return;
        };
        let mut at = 6 + id_width;
        let extent_width = widths.index + widths.offset + widths.length;
        while remaining > 0 {
            remaining -= 1;
            if self.expired() || self.sink.stop {
                return;
            }
            let Some(id) = be(d, at, id_width) else {
                return;
            };
            at += id_width;
            let mut method = 0;
            if version >= 1 {
                let Some(m) = be(d, at, 2) else {
                    return;
                };
                method = m & 0xF;
                at += 2;
            }
            let Some(reference) = be(d, at, 2) else {
                return;
            };
            at += 2;
            let Some(base) = be(d, at, base_width) else {
                return;
            };
            at += base_width;
            let Some(count) = be_usize(d, at, 2) else {
                return;
            };
            at += 2;
            let Some(extents_len) = count.checked_mul(extent_width) else {
                return;
            };
            let Some(extents) = sub(d, at, extents_len) else {
                return;
            };
            at += extents_len;
            let Some(kinds) = u32::try_from(id).ok().and_then(|id| wanted.get(&id)) else {
                continue;
            };
            if reference != 0 {
                continue;
            }
            let (origin, limit) = match (method, idat) {
                (0, _) => (0, bytes.len()),
                (1, Some(i)) => (i.payload, i.end),
                _ => continue,
            };
            let Some(resolved) = self.resolve(extents, widths, base, (origin, limit)) else {
                continue;
            };
            if !self.charge(&resolved) {
                return;
            }
            for kind in kinds {
                self.emit(&resolved, *kind);
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

    fn emit(&mut self, item: &Resolved<'_>, kind: Wanted) {
        let budget = &*self.budget;
        match kind {
            Wanted::Exif => {
                let Some(offset) = be_usize(&item.data, 0, 4) else {
                    return;
                };
                let Some(mut skip) = offset.checked_add(4) else {
                    return;
                };
                let Some(mut tiff) = item.data.get(skip..) else {
                    return;
                };
                if tiff.starts_with(EXIF_PREFIX) {
                    skip += EXIF_PREFIX.len();
                    tiff = &tiff[EXIF_PREFIX.len()..];
                }
                let placement = match item.contiguous_from {
                    Some(from) => Placement::Mapped(from + skip),
                    None => Placement::Whole(item.first.0, item.first.1),
                };
                self.sink.exif_at("AVIF Exif", tiff, placement, budget);
            }
            Wanted::Xmp => {
                self.sink.xmp(
                    "AVIF XMP",
                    &item.data,
                    item.first.0,
                    item.first.1,
                    item.contiguous_from.is_some(),
                    budget,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::model::{CarrierKind, Family, RuleStatus, Severity, SkipReason};
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
    fn iloc_v1_construction_method_2_is_skipped() {
        let mut iloc = vec![0x44, 0x00];
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&2u16.to_be_bytes());
        iloc.extend_from_slice(&[0, 0]);
        iloc.extend_from_slice(&1u16.to_be_bytes());
        iloc.extend_from_slice(&0u32.to_be_bytes());
        iloc.extend_from_slice(&36u32.to_be_bytes());
        let mut children = iinf(&[infe(2, 1, b"Exif", None)]);
        children.extend_from_slice(&full(b"iloc", 1, &iloc));
        children.extend_from_slice(&bx(b"idat", &exif_item()));
        let mut bytes = ftyp();
        bytes.extend_from_slice(&full(b"meta", 0, &children));
        assert!(scan_avif(&bytes, &mut budget()).carriers.is_empty());
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
    fn mime_item_with_other_content_type_is_ignored() {
        let children = |base: u32| {
            let mut c = iinf(&[infe(2, 1, b"mime", Some(b"text/plain"))]);
            c.extend_from_slice(&iloc0(&[(1, vec![(base, 13)])]));
            c
        };
        let bytes = assemble(0, &children, b"<a>secret</a>");
        assert!(scan_avif(&bytes, &mut budget()).carriers.is_empty());
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
    fn iloc_offset_size_nibble_three_stops_safely() {
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
        assert_eq!(out.skip, None);
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

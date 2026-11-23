use super::png::{Inflated, inflate_stream};
use super::{Sink, latin1, lossy, sub};
use crate::limits::Budget;
use crate::model::DetectorOutput;

pub const MAGIC: [u8; 2] = [0x1F, 0x8B];
const HEADER_LEN: usize = 10;
const TRAILER_LEN: usize = 8;
const DEFLATE: u8 = 8;
const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;
const RESERVED: u8 = 0xE0;
const RAW_DEFLATE: u32 = 0;
const INVALID_HEADER: &str = "malformed gzip: invalid header";
const TRUNCATED_HEADER: &str = "malformed gzip: truncated header";
const CORRUPT_STREAM: &str = "malformed gzip: corrupt stream";
const TRUNCATED_MEMBER: &str = "malformed gzip: truncated member";
const LIMIT_MESSAGE: &str = "compressed SVG inflates past the decompression budget";
const TRAILER_LABEL: &str = "SVGZ data after the gzip stream";
const EXTRA_LABEL: &str = "gzip extra field";
const NAME_LABEL: &str = "gzip file name";
const COMMENT_LABEL: &str = "gzip comment";

pub struct Gunzipped {
    pub out: DetectorOutput,
    pub data: Option<Vec<u8>>,
    pub malformed: bool,
}

enum Member {
    Next(usize),
    Stop,
    LimitHit,
}

fn zero_terminated(bytes: &[u8], at: usize) -> Option<&[u8]> {
    let rest = bytes.get(at..)?;
    let len = rest.iter().position(|&b| b == 0)?;
    Some(&rest[..len])
}

struct Reader<'a> {
    bytes: &'a [u8],
    sink: Sink,
    data: Vec<u8>,
}

impl Reader<'_> {
    fn header(&mut self, at: usize) -> Result<usize, &'static str> {
        let head = sub(self.bytes, at, HEADER_LEN).ok_or(TRUNCATED_HEADER)?;
        let flags = head[3];
        if head[..2] != MAGIC || head[2] != DEFLATE || flags & RESERVED != 0 {
            return Err(INVALID_HEADER);
        }
        let mut pos = at + HEADER_LEN;
        if flags & FEXTRA != 0 {
            let size = sub(self.bytes, pos, 2).ok_or(TRUNCATED_HEADER)?;
            let size = usize::from(u16::from_le_bytes([size[0], size[1]]));
            pos += 2;
            let extra = sub(self.bytes, pos, size).ok_or(TRUNCATED_HEADER)?;
            self.sink
                .hidden_carrier(EXTRA_LABEL, &lossy(extra), pos, pos + size, extra);
            pos += size;
        }
        for (flag, label) in [(FNAME, NAME_LABEL), (FCOMMENT, COMMENT_LABEL)] {
            if flags & flag != 0 {
                let text = zero_terminated(self.bytes, pos).ok_or(TRUNCATED_HEADER)?;
                self.sink
                    .carrier(label, &latin1(text), pos, pos + text.len(), text);
                pos += text.len() + 1;
            }
        }
        if flags & FHCRC != 0 {
            sub(self.bytes, pos, 2).ok_or(TRUNCATED_HEADER)?;
            pos += 2;
        }
        Ok(pos)
    }

    fn broken(&mut self, message: &str, at: usize) -> Member {
        self.sink.malformed(message, at, self.bytes.len());
        Member::Stop
    }

    fn member(&mut self, at: usize, budget: &mut Budget) -> Member {
        let start = match self.header(at) {
            Ok(start) => start,
            Err(message) => return self.broken(message, at),
        };
        let (inflated, used) = inflate_stream(&self.bytes[start..], budget, RAW_DEFLATE);
        match inflated {
            Inflated::Text(out) => {
                self.data.extend_from_slice(&out);
                let end = start + used + TRAILER_LEN;
                if end > self.bytes.len() {
                    return self.broken(TRUNCATED_MEMBER, at);
                }
                Member::Next(end)
            }
            Inflated::Corrupt(partial) => {
                self.data.extend_from_slice(&partial);
                self.broken(CORRUPT_STREAM, at)
            }
            Inflated::LimitHit => {
                self.sink.limit_hit(start, self.bytes.len(), LIMIT_MESSAGE);
                Member::LimitHit
            }
        }
    }
}

pub fn gunzip(bytes: &[u8], budget: &mut Budget) -> Gunzipped {
    let mut reader = Reader {
        bytes,
        sink: Sink::new(bytes.len()),
        data: Vec::new(),
    };
    let mut at = 0;
    let complete = loop {
        if budget.deadline_exceeded() {
            reader.sink.timed_out();
            break true;
        }
        match reader.member(at, budget) {
            Member::Next(next) if bytes[next..].starts_with(&MAGIC) => at = next,
            Member::Next(next) => {
                reader.sink.trailer(TRAILER_LABEL, bytes, next, false);
                break true;
            }
            Member::Stop => break true,
            Member::LimitHit => break false,
        }
    };
    Gunzipped {
        malformed: reader.sink.malformed,
        out: reader.sink.out,
        data: complete.then_some(reader.data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::model::SkipReason;
    use miniz_oxide::deflate::compress_to_vec;

    const READABLE: &[u8] = b"meet me at the usual place";

    fn head(flags: u8, fields: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1F, 0x8B, 0x08, flags, 0, 0, 0, 0, 0, 0xFF];
        v.extend_from_slice(fields);
        v
    }

    fn member(flags: u8, fields: &[u8], deflated: &[u8]) -> Vec<u8> {
        let mut v = head(flags, fields);
        v.extend_from_slice(deflated);
        v.extend_from_slice(&[0; 8]);
        v
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        member(0, &[], &compress_to_vec(data, 6))
    }

    fn budget() -> Budget {
        Budget::new(&Limits::default())
    }

    fn carriers(got: &Gunzipped) -> Vec<(&str, bool, u64, u64)> {
        got.out
            .carriers
            .iter()
            .map(|c| {
                (
                    c.text.as_str(),
                    c.hidden,
                    c.span.byte_start,
                    c.span.byte_end,
                )
            })
            .collect()
    }

    fn findings(got: &Gunzipped) -> Vec<(&str, &str, u64, u64)> {
        got.out
            .findings
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
    fn a_member_is_inflated_and_its_name_and_comment_are_carriers() {
        let bytes = member(0x18, b"pic.svg\0a note\0", &compress_to_vec(b"<svg/>", 6));
        let got = gunzip(&bytes, &mut budget());
        assert_eq!(got.data.as_deref(), Some(&b"<svg/>"[..]));
        assert_eq!(
            carriers(&got),
            vec![
                ("gzip file name: pic.svg", false, 10, 17),
                ("gzip comment: a note", false, 18, 24)
            ]
        );
        assert!(got.out.findings.is_empty());
        assert_eq!(got.out.skip, None);
        assert!(!got.malformed);
    }

    #[test]
    fn the_extra_field_is_hidden_and_the_header_crc_is_skipped() {
        let mut fields = vec![26, 0];
        fields.extend_from_slice(READABLE);
        fields.extend_from_slice(&[0xAB, 0xCD]);
        let bytes = member(0x06, &fields, &compress_to_vec(b"<svg/>", 6));
        let got = gunzip(&bytes, &mut budget());
        assert_eq!(got.data.as_deref(), Some(&b"<svg/>"[..]));
        assert_eq!(
            carriers(&got),
            vec![("gzip extra field: meet me at the usual place", true, 12, 38)]
        );
        assert_eq!(
            findings(&got),
            vec![("B005", "readable text hidden in the image", 12, 38)]
        );
    }

    #[test]
    fn members_are_joined_and_data_after_the_last_is_b004() {
        let mut bytes = gz(b"<svg>");
        bytes.extend_from_slice(&gz(b"</svg>"));
        let end = bytes.len() as u64;
        bytes.extend_from_slice(b"note for the reader");
        let got = gunzip(&bytes, &mut budget());
        assert_eq!(got.data.as_deref(), Some(&b"<svg></svg>"[..]));
        assert_eq!(
            findings(&got),
            vec![("B004", "data after the end of the image", end, end + 19)]
        );
        assert_eq!(
            carriers(&got),
            vec![(
                "SVGZ data after the gzip stream: note for the reader",
                true,
                end,
                end + 19
            )]
        );
        let mut padded = gz(b"<svg/>");
        padded.extend_from_slice(&[0, 0, b'\n']);
        let got = gunzip(&padded, &mut budget());
        assert_eq!(got.data.as_deref(), Some(&b"<svg/>"[..]));
        assert!(got.out.findings.is_empty() && got.out.carriers.is_empty());
    }

    #[test]
    fn inflating_past_the_budget_is_b002_and_gives_no_data() {
        let limits = Limits {
            max_decompressed_bytes: 100,
            ..Limits::default()
        };
        let exact = gz(&[b' '; 100]);
        let got = gunzip(&exact, &mut Budget::new(&limits));
        assert_eq!(got.data, Some(vec![b' '; 100]));
        assert!(got.out.findings.is_empty());
        let over = gz(&[b' '; 101]);
        let got = gunzip(&over, &mut Budget::new(&limits));
        assert_eq!(got.data, None);
        assert_eq!(
            findings(&got),
            vec![(
                "B002",
                "compressed SVG inflates past the decompression budget",
                10,
                over.len() as u64
            )]
        );
        assert_eq!(got.out.skip, Some(SkipReason::DecompressionLimit));
        let mut two = gz(&[b' '; 60]);
        let second = two.len() as u64;
        two.extend_from_slice(&gz(&[b' '; 60]));
        let got = gunzip(&two, &mut Budget::new(&limits));
        assert_eq!(got.data, None);
        assert_eq!(findings(&got)[0].0, "B002");
        assert_eq!(findings(&got)[0].2, second + 10);
    }

    #[test]
    fn a_spent_time_budget_stops_before_the_next_member() {
        let limits = Limits {
            per_file_time: std::time::Duration::ZERO,
            ..Limits::default()
        };
        let got = gunzip(&gz(b"<svg/>"), &mut Budget::new(&limits));
        assert_eq!(got.out.skip, Some(SkipReason::Timeout));
        assert_eq!(got.data.as_deref(), Some(&b""[..]));
        assert!(got.out.findings.is_empty());
    }

    #[test]
    fn broken_members_are_malformed_once_and_keep_what_inflated() {
        let header = "malformed gzip: invalid header";
        let truncated = "malformed gzip: truncated header";
        let corrupt = "malformed gzip: corrupt stream";
        let cut = "malformed gzip: truncated member";
        let stored_cut_short = [0x01, 10, 0, 0xF5, 0xFF, b'a', b'b', b'c'];
        let mut no_trailer = gz(b"<svg/>");
        no_trailer.truncate(no_trailer.len() - 3);
        let mut second_broken = gz(b"<svg/>");
        let at = second_broken.len() as u64;
        second_broken.extend_from_slice(&[0x1F, 0x8B, 0x08]);
        let cases: Vec<(Vec<u8>, &str, u64, &[u8])> = vec![
            (vec![0x1F, 0x8B, 0x08, 0], truncated, 0, b""),
            (member(0x20, &[], &compress_to_vec(b"x", 6)), header, 0, b""),
            (MAGIC.to_vec(), truncated, 0, b""),
            (b"PK\x03\x04 not a gzip".to_vec(), header, 0, b""),
            (
                {
                    let mut v = member(0, &[], &compress_to_vec(b"x", 6));
                    v[2] = 7;
                    v
                },
                header,
                0,
                b"",
            ),
            (head(0x08, b"no end"), truncated, 0, b""),
            (head(0x04, &[200, 0, 1, 2]), truncated, 0, b""),
            (head(0x02, &[0xAB]), truncated, 0, b""),
            (
                {
                    let mut v = vec![0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0xFF];
                    v.extend_from_slice(&stored_cut_short);
                    v
                },
                corrupt,
                0,
                b"abc",
            ),
            (no_trailer, cut, 0, b"<svg/>"),
            (second_broken, truncated, at, b"<svg/>"),
        ];
        for (bytes, message, start, kept) in cases {
            let got = gunzip(&bytes, &mut budget());
            assert_eq!(
                findings(&got),
                vec![("L001", message, start, bytes.len() as u64)],
                "{bytes:?}"
            );
            assert_eq!(got.out.skip, Some(SkipReason::Malformed));
            assert!(got.malformed);
            assert_eq!(got.data.as_deref(), Some(kept), "{bytes:?}");
        }
    }
}

use super::{
    Script, is_bidi_control, is_emoji_modifier, is_extended_pictographic, rgi_tag_sequence_len,
    script,
};
use crate::model::LocationKind;

const ZWNJ: char = '\u{200C}';
const ZWJ: char = '\u{200D}';
const SOFT_HYPHEN: char = '\u{00AD}';
const BOM: char = '\u{FEFF}';
const MONGOLIAN_VOWEL_SEPARATOR: char = '\u{180E}';
pub(super) const BRAILLE_BLANK: char = '\u{2800}';
const BRAILLE_CELLS: std::ops::RangeInclusive<char> = '\u{2801}'..='\u{28FF}';
const VS16: char = '\u{FE0F}';
const BLACK_FLAG: char = '\u{1F3F4}';
const MAX_TAG_SEQUENCE_CHARS: usize = 32;
const RTL_RATIO_DIVISOR: usize = 5;

fn is_joiner_script(s: Script) -> bool {
    matches!(
        s,
        Script::Arabic
            | Script::Syriac
            | Script::Devanagari
            | Script::Bengali
            | Script::Gurmukhi
            | Script::Gujarati
            | Script::Oriya
            | Script::Tamil
            | Script::Telugu
            | Script::Kannada
            | Script::Malayalam
            | Script::Sinhala
            | Script::Myanmar
            | Script::Khmer
            | Script::Mongolian
            | Script::Nko
            | Script::Adlam
    )
}

fn is_rtl_script(s: Script) -> bool {
    matches!(
        s,
        Script::Hebrew | Script::Arabic | Script::Syriac | Script::Thaana | Script::Nko
    )
}

fn is_joiner_neighbour(c: char) -> bool {
    is_joiner_script(script(c)) && !c.is_numeric()
}

pub struct Context<'a> {
    chars: &'a [char],
    location: LocationKind,
    bidi_exempt: bool,
    exempt: Vec<bool>,
}

impl<'a> Context<'a> {
    pub fn new(chars: &'a [char], location: LocationKind) -> Self {
        Context {
            chars,
            location,
            bidi_exempt: location != LocationKind::Code && mostly_rtl(chars),
            exempt: exempt_mask(chars),
        }
    }

    pub fn is_exempt(&self, i: usize) -> bool {
        let c = self.chars[i];
        match c {
            BOM => i == 0,
            ZWJ => self.zwj_between_emoji(i) || self.joiner_between_letters(i),
            ZWNJ => self.joiner_between_letters(i),
            MONGOLIAN_VOWEL_SEPARATOR => self.between_mongolian_letters(i),
            SOFT_HYPHEN => self.location != LocationKind::Code && self.between_letters(i),
            _ if is_bidi_control(c) => self.bidi_exempt,
            _ => self.exempt[i],
        }
    }

    fn between_letters(&self, i: usize) -> bool {
        i > 0
            && self.chars[i - 1].is_alphabetic()
            && self.chars.get(i + 1).is_some_and(|c| c.is_alphabetic())
    }

    fn between_mongolian_letters(&self, i: usize) -> bool {
        let mongolian_letter = |c: &char| script(*c) == Script::Mongolian && c.is_alphabetic();
        i > 0
            && mongolian_letter(&self.chars[i - 1])
            && self.chars.get(i + 1).is_some_and(mongolian_letter)
    }

    fn zwj_between_emoji(&self, i: usize) -> bool {
        let mut j = i;
        while j > 0 && (is_emoji_modifier(self.chars[j - 1]) || self.chars[j - 1] == VS16) {
            j -= 1;
        }
        j > 0
            && is_extended_pictographic(self.chars[j - 1])
            && self
                .chars
                .get(i + 1)
                .is_some_and(|&c| is_extended_pictographic(c))
    }

    fn joiner_between_letters(&self, i: usize) -> bool {
        let mut j = i;
        while j > 0
            && script(self.chars[j - 1]) == Script::Inherited
            && !matches!(self.chars[j - 1], ZWJ | ZWNJ)
        {
            j -= 1;
        }
        j > 0
            && is_joiner_neighbour(self.chars[j - 1])
            && self
                .chars
                .get(i + 1)
                .is_some_and(|&c| is_joiner_neighbour(c) && script(c) == script(self.chars[j - 1]))
    }
}

fn mostly_rtl(chars: &[char]) -> bool {
    let letters = chars.iter().filter(|c| c.is_alphabetic()).count();
    let rtl = chars
        .iter()
        .filter(|&&c| c.is_alphabetic() && is_rtl_script(script(c)))
        .count();
    letters > 0 && rtl * RTL_RATIO_DIVISOR >= letters
}

fn exempt_mask(chars: &[char]) -> Vec<bool> {
    let mut mask = vec![false; chars.len()];
    for (i, &c) in chars.iter().enumerate() {
        if c != BLACK_FLAG {
            continue;
        }
        let window: String = chars[i..]
            .iter()
            .take(MAX_TAG_SEQUENCE_CHARS)
            .copied()
            .collect();
        if let Some(len) = rgi_tag_sequence_len(&window) {
            mask[i..i + len].fill(true);
        }
    }
    let mut start = 0;
    for line in chars.split(|c| matches!(c, '\n' | '\r')) {
        if line.iter().any(|c| BRAILLE_CELLS.contains(c)) {
            for (offset, &c) in line.iter().enumerate() {
                if c == BRAILLE_BLANK {
                    mask[start + offset] = true;
                }
            }
        }
        start += line.len() + 1;
    }
    mask
}

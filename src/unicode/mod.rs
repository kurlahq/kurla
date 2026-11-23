use std::cmp::Ordering;

mod context;
mod scan;
mod tables;

pub use scan::scan_text;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Script {
    Latin,
    Cyrillic,
    Greek,
    Arabic,
    Hebrew,
    Syriac,
    Thaana,
    Nko,
    Devanagari,
    Bengali,
    Gurmukhi,
    Gujarati,
    Oriya,
    Tamil,
    Telugu,
    Kannada,
    Malayalam,
    Sinhala,
    Myanmar,
    Khmer,
    Mongolian,
    Adlam,
    Common,
    Inherited,
    Other,
}

const TAG_FIRST: char = '\u{E0000}';
const TAG_LAST: char = '\u{E007F}';
const TAG_TERMINATOR: char = '\u{E007F}';
const MAX_TAG_SEQUENCE_CHARS: usize = 32;

fn range_order(lo: char, hi: char, c: char) -> Ordering {
    if hi < c {
        Ordering::Less
    } else if lo > c {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

fn in_ranges(table: &[(char, char)], c: char) -> bool {
    table
        .binary_search_by(|&(lo, hi)| range_order(lo, hi, c))
        .is_ok()
}

pub fn is_bidi_control(c: char) -> bool {
    in_ranges(tables::BIDI_CONTROL, c)
}

pub fn is_default_ignorable(c: char) -> bool {
    in_ranges(tables::DEFAULT_IGNORABLE, c)
}

pub fn is_variation_selector(c: char) -> bool {
    in_ranges(tables::VARIATION_SELECTOR, c)
}

pub fn is_tag(c: char) -> bool {
    (TAG_FIRST..=TAG_LAST).contains(&c)
}

pub fn is_private_use(c: char) -> bool {
    in_ranges(tables::PRIVATE_USE, c)
}

pub fn is_extended_pictographic(c: char) -> bool {
    in_ranges(tables::EXTENDED_PICTOGRAPHIC, c)
}

pub fn is_emoji_modifier(c: char) -> bool {
    in_ranges(tables::EMOJI_MODIFIER, c)
}

pub fn script(c: char) -> Script {
    tables::SCRIPTS
        .binary_search_by(|&(lo, hi, _)| range_order(lo, hi, c))
        .map_or(Script::Other, |i| tables::SCRIPTS[i].2)
}

pub fn is_allowed_variation_pair(base: char, vs: char) -> bool {
    tables::VARIATION_PAIRS.binary_search(&(base, vs)).is_ok()
}

pub fn rgi_tag_sequence_len(s: &str) -> Option<usize> {
    let mut sequence: Vec<char> = Vec::new();
    for c in s.chars().take(MAX_TAG_SEQUENCE_CHARS) {
        sequence.push(c);
        if c == TAG_TERMINATOR {
            return tables::RGI_TAG_SEQUENCES
                .binary_search_by(|entry| (*entry).cmp(sequence.as_slice()))
                .ok()
                .map(|_| sequence.len());
        }
    }
    None
}

pub(crate) fn combining_class(c: char) -> u8 {
    tables::COMBINING_CLASS
        .binary_search_by(|&(lo, hi, _)| range_order(lo, hi, c))
        .map_or(0, |i| tables::COMBINING_CLASS[i].2)
}

fn push_decomposed(c: char, out: &mut Vec<char>) {
    const S_BASE: u32 = 0xAC00;
    const L_BASE: u32 = 0x1100;
    const V_BASE: u32 = 0x1161;
    const T_BASE: u32 = 0x11A7;
    const V_COUNT: u32 = 21;
    const T_COUNT: u32 = 28;
    const S_COUNT: u32 = 19 * V_COUNT * T_COUNT;
    let code = c as u32;
    if (S_BASE..S_BASE + S_COUNT).contains(&code) {
        let index = code - S_BASE;
        let parts = [
            L_BASE + index / (V_COUNT * T_COUNT),
            V_BASE + (index % (V_COUNT * T_COUNT)) / T_COUNT,
            T_BASE + index % T_COUNT,
        ];
        let used = if index.is_multiple_of(T_COUNT) { 2 } else { 3 };
        out.extend(parts[..used].iter().filter_map(|&p| char::from_u32(p)));
        return;
    }
    match tables::DECOMPOSITIONS.binary_search_by_key(&c, |&(source, _)| source) {
        Ok(i) => out.extend_from_slice(tables::DECOMPOSITIONS[i].1),
        Err(_) => out.push(c),
    }
}

fn nfd(input: impl Iterator<Item = char>) -> Vec<char> {
    let mut out = Vec::new();
    for c in input {
        push_decomposed(c, &mut out);
    }
    let mut start = 0;
    while start < out.len() {
        if combining_class(out[start]) == 0 {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < out.len() && combining_class(out[end]) != 0 {
            end += 1;
        }
        out[start..end].sort_by_key(|&c| combining_class(c));
        start = end;
    }
    out
}

pub fn confusable_skeleton(s: &str) -> String {
    let decomposed = nfd(s.chars());
    let mapped = decomposed.into_iter().flat_map(|c| {
        match tables::CONFUSABLES.binary_search_by_key(&c, |&(source, _)| source) {
            Ok(i) => tables::CONFUSABLES[i].1.to_vec(),
            Err(_) => vec![c],
        }
    });
    nfd(mapped).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(codes: &[u32]) -> String {
        codes.iter().map(|&c| char::from_u32(c).unwrap()).collect()
    }

    fn ch(code: u32) -> char {
        char::from_u32(code).unwrap()
    }

    #[test]
    fn bidi_control_set_includes_rlo_lrm_alm() {
        assert!(is_bidi_control('\u{202E}'));
        assert!(is_bidi_control('\u{200E}'));
        assert!(is_bidi_control('\u{061C}'));
    }

    #[test]
    fn default_ignorable_includes_hangul_filler_and_soft_hyphen() {
        assert!(is_default_ignorable('\u{3164}'));
        assert!(is_default_ignorable('\u{00AD}'));
    }

    #[test]
    fn tags_and_variation_selectors_classified() {
        assert!(is_tag('\u{E0041}'));
        assert!(is_variation_selector('\u{FE0F}'));
        assert!(is_variation_selector('\u{E0100}'));
    }

    #[test]
    fn heart_with_vs16_is_allowed_pair() {
        assert!(is_allowed_variation_pair('\u{2764}', '\u{FE0F}'));
    }

    #[test]
    fn latin_a_with_vs16_is_not_allowed_pair() {
        assert!(!is_allowed_variation_pair('A', '\u{FE0F}'));
    }

    #[test]
    fn england_flag_is_rgi_tag_sequence() {
        let s = chars(&[
            0x1F3F4, 0xE0067, 0xE0062, 0xE0065, 0xE006E, 0xE0067, 0xE007F,
        ]);
        assert_eq!(rgi_tag_sequence_len(&s), Some(7));
    }

    #[test]
    fn lone_tag_is_not_rgi_sequence() {
        assert_eq!(rgi_tag_sequence_len("\u{E0041}"), None);
    }

    #[test]
    fn cyrillic_a_skeleton_matches_latin_a() {
        assert_eq!(confusable_skeleton("\u{0430}"), confusable_skeleton("a"));
    }

    #[test]
    fn bidi_control_ranges_include_edges_and_exclude_neighbours() {
        for c in [0x061C, 0x200E, 0x200F, 0x202A, 0x202E, 0x2066, 0x2069] {
            assert!(is_bidi_control(ch(c)), "{c:X}");
        }
        for c in [
            0x061B, 0x061D, 0x200D, 0x2010, 0x2029, 0x202F, 0x2065, 0x206A,
        ] {
            assert!(!is_bidi_control(ch(c)), "{c:X}");
        }
    }

    #[test]
    fn default_ignorable_ranges_include_edges_and_exclude_neighbours() {
        for c in [
            0x00AD, 0x034F, 0x115F, 0x1160, 0x180E, 0x200B, 0x2060, 0x2065, 0x206F, 0xFE00, 0xFE0F,
            0xFEFF, 0xFFA0, 0xFFF0, 0xFFF8, 0xE0000, 0xE0001, 0xE0FFF,
        ] {
            assert!(is_default_ignorable(ch(c)), "{c:X}");
        }
        for c in [
            0x00AC, 0x00AE, 0x034E, 0x0350, 0x115E, 0x1161, 0x200A, 0x205F, 0x2070, 0xFDFF, 0xFE10,
            0xFEFE, 0xFF00, 0xFFA1, 0xFFEF, 0xFFF9, 0xDFFFF, 0xE1000,
        ] {
            assert!(!is_default_ignorable(ch(c)), "{c:X}");
        }
    }

    #[test]
    fn variation_selector_ranges_include_edges_and_exclude_neighbours() {
        for c in [0x180B, 0x180D, 0x180F, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF] {
            assert!(is_variation_selector(ch(c)), "{c:X}");
        }
        for c in [0x180A, 0x180E, 0x1810, 0xFDFF, 0xFE10, 0xE00FF, 0xE01F0] {
            assert!(!is_variation_selector(ch(c)), "{c:X}");
        }
    }

    #[test]
    fn tag_range_includes_edges_and_excludes_neighbours() {
        assert!(is_tag('\u{E0000}'));
        assert!(is_tag('\u{E007F}'));
        assert!(!is_tag('\u{DFFFF}'));
        assert!(!is_tag('\u{E0080}'));
    }

    #[test]
    fn private_use_ranges_include_edges_and_exclude_neighbours() {
        for c in [0xE000, 0xF8FF, 0xF0000, 0xFFFFD, 0x100000, 0x10FFFD] {
            assert!(is_private_use(ch(c)), "{c:X}");
        }
        for c in [0xD7FF, 0xF900, 0xEFFFF, 0xFFFFE, 0xFFFFF, 0x10FFFE] {
            assert!(!is_private_use(ch(c)), "{c:X}");
        }
    }

    #[test]
    fn extended_pictographic_ranges_include_edges_and_exclude_neighbours() {
        for c in [
            0x00A9, 0x00AE, 0x203C, 0x2194, 0x2199, 0x21A9, 0x1FAFA, 0x1FAFB, 0x1FC00, 0x1FFFD,
        ] {
            assert!(is_extended_pictographic(ch(c)), "{c:X}");
        }
        for c in [
            0x00A8, 0x00AA, 0x00AD, 0x203B, 0x2193, 0x219A, 0x1FBFF, 0x1FFFE,
        ] {
            assert!(!is_extended_pictographic(ch(c)), "{c:X}");
        }
    }

    #[test]
    fn emoji_modifier_range_includes_edges_and_excludes_neighbours() {
        assert!(is_emoji_modifier('\u{1F3FB}'));
        assert!(is_emoji_modifier('\u{1F3FF}'));
        assert!(!is_emoji_modifier('\u{1F3FA}'));
        assert!(!is_emoji_modifier('\u{1F400}'));
    }

    #[test]
    fn script_ranges_include_edges_and_exclude_neighbours() {
        assert_eq!(script('A'), Script::Latin);
        assert_eq!(script('Z'), Script::Latin);
        assert_eq!(script('a'), Script::Latin);
        assert_eq!(script('z'), Script::Latin);
        assert_eq!(script('@'), Script::Common);
        assert_eq!(script('['), Script::Common);
        assert_eq!(script('`'), Script::Common);
        assert_eq!(script('{'), Script::Common);
        assert_eq!(script('\u{0370}'), Script::Greek);
        assert_eq!(script('\u{0373}'), Script::Greek);
        assert_eq!(script('\u{0400}'), Script::Cyrillic);
        assert_eq!(script('\u{0481}'), Script::Cyrillic);
        assert_eq!(script('\u{0300}'), Script::Inherited);
        assert_eq!(script('\u{036F}'), Script::Inherited);
        assert_eq!(script('\u{0627}'), Script::Arabic);
        assert_eq!(script('\u{05D0}'), Script::Hebrew);
        assert_eq!(script('\u{0915}'), Script::Devanagari);
    }

    #[test]
    fn script_outside_the_enum_is_other() {
        assert_eq!(script('\u{4E00}'), Script::Other);
        assert_eq!(script('\u{0F40}'), Script::Other);
        assert_eq!(script('\u{3042}'), Script::Other);
    }

    #[test]
    fn variation_pairs_from_both_files_are_allowed() {
        assert!(is_allowed_variation_pair('\u{0023}', '\u{FE0E}'));
        assert!(is_allowed_variation_pair('\u{2764}', '\u{FE0E}'));
        assert!(is_allowed_variation_pair('\u{0030}', '\u{FE0F}'));
        assert!(is_allowed_variation_pair('\u{0030}', '\u{FE00}'));
        assert!(is_allowed_variation_pair('\u{FF10}', '\u{FE00}'));
        assert!(is_allowed_variation_pair('\u{2A600}', '\u{FE00}'));
    }

    #[test]
    fn variation_pairs_not_listed_are_rejected() {
        assert!(!is_allowed_variation_pair('\u{2764}', '\u{FE00}'));
        assert!(!is_allowed_variation_pair('\u{0030}', '\u{FE01}'));
        assert!(!is_allowed_variation_pair('\u{2A600}', '\u{FE01}'));
        assert!(!is_allowed_variation_pair('\u{0022}', '\u{FE0E}'));
        assert!(!is_allowed_variation_pair('\u{2764}', '\u{E0100}'));
    }

    #[test]
    fn scotland_and_wales_flags_are_rgi_tag_sequences() {
        let scotland = chars(&[
            0x1F3F4, 0xE0067, 0xE0062, 0xE0073, 0xE0063, 0xE0074, 0xE007F,
        ]);
        let wales = chars(&[
            0x1F3F4, 0xE0067, 0xE0062, 0xE0077, 0xE006C, 0xE0073, 0xE007F,
        ]);
        assert_eq!(rgi_tag_sequence_len(&scotland), Some(7));
        assert_eq!(rgi_tag_sequence_len(&wales), Some(7));
    }

    #[test]
    fn rgi_tag_sequence_length_ignores_trailing_text() {
        let s = chars(&[
            0x1F3F4, 0xE0067, 0xE0062, 0xE0065, 0xE006E, 0xE0067, 0xE007F, 0x41, 0xE0041,
        ]);
        assert_eq!(rgi_tag_sequence_len(&s), Some(7));
    }

    #[test]
    fn non_rgi_tag_sequences_are_rejected() {
        let unknown_region = chars(&[
            0x1F3F4, 0xE0067, 0xE0062, 0xE0065, 0xE006E, 0xE0068, 0xE007F,
        ]);
        let unterminated = chars(&[0x1F3F4, 0xE0067, 0xE0062, 0xE0065, 0xE006E, 0xE0067]);
        let wrong_base = chars(&[
            0x1F3F3, 0xE0067, 0xE0062, 0xE0065, 0xE006E, 0xE0067, 0xE007F,
        ]);
        let prefixed = chars(&[
            0x41, 0x1F3F4, 0xE0067, 0xE0062, 0xE0065, 0xE006E, 0xE0067, 0xE007F,
        ]);
        assert_eq!(rgi_tag_sequence_len(&unknown_region), None);
        assert_eq!(rgi_tag_sequence_len(&unterminated), None);
        assert_eq!(rgi_tag_sequence_len(&wrong_base), None);
        assert_eq!(rgi_tag_sequence_len(&prefixed), None);
        assert_eq!(rgi_tag_sequence_len(""), None);
        assert_eq!(rgi_tag_sequence_len("\u{1F3F4}"), None);
    }

    #[test]
    fn skeleton_maps_digit_and_letter_lookalikes() {
        assert_eq!(confusable_skeleton("0"), "O");
        assert_eq!(confusable_skeleton("1"), "l");
        assert_eq!(confusable_skeleton("I"), "l");
        assert_eq!(confusable_skeleton("\u{0430}"), "a");
        assert_eq!(
            confusable_skeleton("paypal"),
            confusable_skeleton("p\u{0430}yp\u{0430}l")
        );
    }

    #[test]
    fn skeleton_decomposes_canonically() {
        assert_eq!(confusable_skeleton("\u{00E9}"), "e\u{0301}");
        assert_eq!(confusable_skeleton("\u{AC00}"), "\u{1100}\u{1161}");
        assert_eq!(confusable_skeleton("\u{AC01}"), "\u{1100}\u{1161}\u{1100}");
        assert_eq!(confusable_skeleton("\u{212B}"), "A\u{030A}");
    }

    #[test]
    fn skeleton_reorders_combining_marks_by_class() {
        assert_eq!(
            confusable_skeleton("e\u{0301}\u{0323}"),
            "e\u{0323}\u{0301}"
        );
        assert_eq!(
            confusable_skeleton("e\u{0323}\u{0301}"),
            "e\u{0323}\u{0301}"
        );
    }

    #[test]
    fn skeleton_leaves_unmapped_text_unchanged() {
        assert_eq!(confusable_skeleton(""), "");
        assert_eq!(confusable_skeleton("abc"), "abc");
    }

    #[test]
    fn skeleton_ignores_compatibility_decompositions() {
        assert_eq!(confusable_skeleton("\u{00B2}"), "\u{14BE}");
        assert_eq!(confusable_skeleton("\u{2460}"), "\u{2780}");
    }
}

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::process::{Command, ExitCode};

const DATA_DIR: &str = "unicode-data";
const OUTPUT_PATH: &str = "src/unicode/tables.rs";

const SCRIPT_NAMES: [&str; 23] = [
    "Latin",
    "Cyrillic",
    "Greek",
    "Arabic",
    "Hebrew",
    "Syriac",
    "Thaana",
    "Nko",
    "Devanagari",
    "Bengali",
    "Gurmukhi",
    "Gujarati",
    "Oriya",
    "Tamil",
    "Telugu",
    "Kannada",
    "Malayalam",
    "Sinhala",
    "Myanmar",
    "Khmer",
    "Mongolian",
    "Common",
    "Inherited",
];

type Range = (u32, u32);

pub fn run() -> ExitCode {
    match generate() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("gen-unicode: {message}");
            ExitCode::FAILURE
        }
    }
}

fn read(name: &str) -> Result<String, String> {
    let path = format!("{DATA_DIR}/{name}");
    fs::read_to_string(&path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn hex(text: &str) -> Result<u32, String> {
    u32::from_str_radix(text.trim(), 16).map_err(|e| format!("bad code point {text:?}: {e}"))
}

fn fields(line: &str) -> Vec<&str> {
    let body = line.split('#').next().unwrap_or("");
    body.split(';').map(str::trim).collect()
}

fn parse_range(text: &str) -> Result<Range, String> {
    match text.split_once("..") {
        Some((lo, hi)) => Ok((hex(lo)?, hex(hi)?)),
        None => {
            let cp = hex(text)?;
            Ok((cp, cp))
        }
    }
}

fn merge(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_unstable();
    let mut out: Vec<Range> = Vec::new();
    for (lo, hi) in ranges {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

fn property_ranges(text: &str, property: &str) -> Result<Vec<Range>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f = fields(line);
        if f.len() >= 2 && f[1] == property {
            out.push(parse_range(f[0])?);
        }
    }
    if out.is_empty() {
        return Err(format!("no entries for {property}"));
    }
    Ok(merge(out))
}

fn script_ranges(text: &str) -> Result<Vec<(u32, u32, &'static str)>, String> {
    let mut by_script: BTreeMap<&'static str, Vec<Range>> = BTreeMap::new();
    for line in text.lines() {
        let f = fields(line);
        if f.len() < 2 {
            continue;
        }
        if let Some(name) = SCRIPT_NAMES.iter().find(|n| **n == f[1]) {
            by_script.entry(name).or_default().push(parse_range(f[0])?);
        }
    }
    for name in SCRIPT_NAMES {
        if !by_script.contains_key(name) {
            return Err(format!("script {name} missing from Scripts.txt"));
        }
    }
    let mut out = Vec::new();
    for (name, ranges) in by_script {
        for (lo, hi) in merge(ranges) {
            out.push((lo, hi, name));
        }
    }
    out.sort_unstable();
    Ok(out)
}

struct UnicodeData {
    private_use: Vec<Range>,
    combining_class: Vec<(u32, u32, u8)>,
    decompositions: Vec<(u32, Vec<u32>)>,
}

fn parse_unicode_data(text: &str) -> Result<UnicodeData, String> {
    let mut private_use = Vec::new();
    let mut classes: BTreeMap<u32, u8> = BTreeMap::new();
    let mut raw: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut first: Option<u32> = None;
    for line in text.lines().filter(|l| !l.is_empty()) {
        let f: Vec<&str> = line.split(';').collect();
        if f.len() < 6 {
            return Err(format!("short UnicodeData line {line:?}"));
        }
        let cp = hex(f[0])?;
        let name = f[1];
        if name.ends_with(", First>") {
            first = Some(cp);
            continue;
        }
        let lo = if name.ends_with(", Last>") {
            first
                .take()
                .ok_or_else(|| format!("Last without First at {cp:X}"))?
        } else {
            cp
        };
        if f[2] == "Co" {
            private_use.push((lo, cp));
        }
        let class: u8 = f[3]
            .parse()
            .map_err(|e| format!("bad combining class {:?}: {e}", f[3]))?;
        if class != 0 {
            classes.insert(cp, class);
        }
        if !f[5].is_empty() && !f[5].starts_with('<') {
            let mapping = f[5]
                .split_whitespace()
                .map(hex)
                .collect::<Result<Vec<_>, _>>()?;
            raw.insert(cp, mapping);
        }
    }
    let mut decompositions = Vec::new();
    for &cp in raw.keys() {
        decompositions.push((cp, expand(cp, &raw)));
    }
    let mut combining_class: Vec<(u32, u32, u8)> = Vec::new();
    for (cp, class) in classes {
        match combining_class.last_mut() {
            Some(last) if last.1 + 1 == cp && last.2 == class => last.1 = cp,
            _ => combining_class.push((cp, cp, class)),
        }
    }
    Ok(UnicodeData {
        private_use: merge(private_use),
        combining_class,
        decompositions,
    })
}

fn expand(cp: u32, raw: &BTreeMap<u32, Vec<u32>>) -> Vec<u32> {
    match raw.get(&cp) {
        Some(mapping) => mapping.iter().flat_map(|&c| expand(c, raw)).collect(),
        None => vec![cp],
    }
}

fn variation_pairs(variants: &str, emoji: &str) -> Result<Vec<Range>, String> {
    let mut out = Vec::new();
    for text in [variants, emoji] {
        for line in text.lines() {
            let f = fields(line);
            if f.len() < 2 || f[0].is_empty() {
                continue;
            }
            let parts: Vec<&str> = f[0].split_whitespace().collect();
            if parts.len() == 2 {
                out.push((hex(parts[0])?, hex(parts[1])?));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn rgi_tag_sequences(text: &str) -> Result<Vec<Vec<u32>>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f = fields(line);
        if f.len() >= 2 && f[1] == "RGI_Emoji_Tag_Sequence" {
            out.push(
                f[0].split_whitespace()
                    .map(hex)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
    }
    if out.is_empty() {
        return Err("no RGI_Emoji_Tag_Sequence entries".to_string());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn confusables(text: &str) -> Result<Vec<(u32, Vec<u32>)>, String> {
    let mut out: Vec<(u32, Vec<u32>)> = Vec::new();
    for line in text.trim_start_matches('\u{FEFF}').lines() {
        let f = fields(line);
        if f.len() < 3 || f[0].is_empty() {
            continue;
        }
        let target = f[1]
            .split_whitespace()
            .map(hex)
            .collect::<Result<Vec<_>, _>>()?;
        out.push((hex(f[0])?, target));
    }
    out.sort();
    if out.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err("duplicate confusables source".to_string());
    }
    Ok(out)
}

fn chr(cp: u32) -> Result<String, String> {
    char::from_u32(cp)
        .map(|_| format!("'\\u{{{cp:X}}}'"))
        .ok_or_else(|| format!("not a scalar value: {cp:X}"))
}

fn chars(seq: &[u32]) -> Result<String, String> {
    let items = seq.iter().map(|&c| chr(c)).collect::<Result<Vec<_>, _>>()?;
    Ok(format!("&[{}]", items.join(", ")))
}

fn emit_ranges(out: &mut String, name: &str, ranges: &[Range]) -> Result<(), String> {
    let _ = writeln!(out, "pub static {name}: &[(char, char)] = &[");
    for &(lo, hi) in ranges {
        let _ = writeln!(out, "({}, {}),", chr(lo)?, chr(hi)?);
    }
    out.push_str("];\n");
    Ok(())
}

fn generate() -> Result<(), String> {
    let prop_list = read("PropList.txt")?;
    let derived = read("DerivedCoreProperties.txt")?;
    let emoji_data = read("emoji-data.txt")?;
    let unicode_data = parse_unicode_data(&read("UnicodeData.txt")?)?;
    let scripts = script_ranges(&read("Scripts.txt")?)?;
    let pairs = variation_pairs(
        &read("StandardizedVariants.txt")?,
        &read("emoji-variation-sequences.txt")?,
    )?;
    let rgi = rgi_tag_sequences(&read("emoji-sequences.txt")?)?;
    let confusable_map = confusables(&read("confusables.txt")?)?;

    let mut out = String::from("use super::Script;\n");
    emit_ranges(
        &mut out,
        "BIDI_CONTROL",
        &property_ranges(&prop_list, "Bidi_Control")?,
    )?;
    emit_ranges(
        &mut out,
        "VARIATION_SELECTOR",
        &property_ranges(&prop_list, "Variation_Selector")?,
    )?;
    emit_ranges(
        &mut out,
        "DEFAULT_IGNORABLE",
        &property_ranges(&derived, "Default_Ignorable_Code_Point")?,
    )?;
    emit_ranges(
        &mut out,
        "EXTENDED_PICTOGRAPHIC",
        &property_ranges(&emoji_data, "Extended_Pictographic")?,
    )?;
    emit_ranges(
        &mut out,
        "EMOJI_MODIFIER",
        &property_ranges(&emoji_data, "Emoji_Modifier")?,
    )?;
    emit_ranges(&mut out, "PRIVATE_USE", &unicode_data.private_use)?;

    out.push_str("pub static SCRIPTS: &[(char, char, Script)] = &[\n");
    for (lo, hi, name) in &scripts {
        let _ = writeln!(out, "({}, {}, Script::{name}),", chr(*lo)?, chr(*hi)?);
    }
    out.push_str("];\n");

    out.push_str("pub static VARIATION_PAIRS: &[(char, char)] = &[\n");
    for &(base, vs) in &pairs {
        let _ = writeln!(out, "({}, {}),", chr(base)?, chr(vs)?);
    }
    out.push_str("];\n");

    out.push_str("pub static RGI_TAG_SEQUENCES: &[&[char]] = &[\n");
    for seq in &rgi {
        let _ = writeln!(out, "{},", chars(seq)?);
    }
    out.push_str("];\n");

    out.push_str("pub static COMBINING_CLASS: &[(char, char, u8)] = &[\n");
    for &(lo, hi, class) in &unicode_data.combining_class {
        let _ = writeln!(out, "({}, {}, {class}),", chr(lo)?, chr(hi)?);
    }
    out.push_str("];\n");

    out.push_str("pub static DECOMPOSITIONS: &[(char, &[char])] = &[\n");
    for (cp, mapping) in &unicode_data.decompositions {
        let _ = writeln!(out, "({}, {}),", chr(*cp)?, chars(mapping)?);
    }
    out.push_str("];\n");

    out.push_str("pub static CONFUSABLES: &[(char, &[char])] = &[\n");
    for (cp, mapping) in &confusable_map {
        let _ = writeln!(out, "({}, {}),", chr(*cp)?, chars(mapping)?);
    }
    out.push_str("];\n");

    fs::write(OUTPUT_PATH, out).map_err(|e| format!("cannot write {OUTPUT_PATH}: {e}"))?;
    let status = Command::new("rustfmt")
        .args(["--edition", "2024", OUTPUT_PATH])
        .status()
        .map_err(|e| format!("cannot run rustfmt: {e}"))?;
    if !status.success() {
        return Err("rustfmt failed".to_string());
    }
    Ok(())
}

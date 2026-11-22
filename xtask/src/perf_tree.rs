use std::fs;
use std::path::Path;
use std::process::ExitCode;

const SEED: u64 = 0x4B55_524C_4150_4552;
const MIN_SIZE: usize = 200;
const MAX_SIZE: usize = 20 * 1024;
const FILES_PER_DIR: usize = 1000;

pub fn run(args: &[String]) -> ExitCode {
    let [dir, count] = args else {
        eprintln!("perf-tree: usage: perf-tree <dir> <count>");
        return ExitCode::from(2);
    };
    let Ok(count) = count.parse::<usize>() else {
        eprintln!("perf-tree: count must be a non-negative integer: {count:?}");
        return ExitCode::from(2);
    };
    match generate(Path::new(dir), count) {
        Ok(()) => {
            println!("perf-tree: wrote {count} files under {dir}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("perf-tree: {message}");
            ExitCode::from(2)
        }
    }
}

const WORDS: [&str; 40] = [
    "river", "stone", "garden", "window", "paper", "lantern", "market", "bridge", "harbor",
    "meadow", "copper", "winter", "summer", "orchard", "pencil", "ladder", "violin", "button",
    "canvas", "pebble", "ribbon", "anchor", "blanket", "candle", "feather", "mirror", "basket",
    "thunder", "velvet", "whistle", "cobble", "timber", "saddle", "marble", "harvest", "compass",
    "kettle", "lagoon", "puzzle", "sparrow",
];

const PNG_HEAD: [u8; 33] = [
    0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, b'I', b'H', b'D', b'R',
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89,
];
const PNG_TAIL: [u8; 34] = [
    0x00, 0x00, 0x00, 0x0A, b'I', b'D', b'A', b'T', 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05,
    0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xAE, 0x42,
    0x60, 0x82,
];

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn filler(rng: &mut SplitMix64, length: usize) -> String {
    let mut text = String::with_capacity(length + 16);
    while text.len() < length {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(WORDS[rng.below(WORDS.len())]);
    }
    text.truncate(length);
    text
}

fn wrapped(rng: &mut SplitMix64, size: usize, prefix: &str, suffix: &str) -> Vec<u8> {
    let body = filler(rng, size - prefix.len() - suffix.len());
    format!("{prefix}{body}{suffix}").into_bytes()
}

fn png(rng: &mut SplitMix64, size: usize) -> Vec<u8> {
    let data_len = size - PNG_HEAD.len() - PNG_TAIL.len() - 12;
    let mut data = b"Comment\0".to_vec();
    data.extend(filler(rng, data_len - data.len()).into_bytes());
    let mut chunk_body = b"tEXt".to_vec();
    chunk_body.extend(&data);
    let mut out = PNG_HEAD.to_vec();
    out.extend((data.len() as u32).to_be_bytes());
    out.extend(&chunk_body);
    out.extend(crc32(&chunk_body).to_be_bytes());
    out.extend(PNG_TAIL);
    out
}

fn jpeg(rng: &mut SplitMix64, size: usize) -> Vec<u8> {
    let data_len = size - 8;
    let mut out = vec![0xFF, 0xD8, 0xFF, 0xFE];
    out.extend(((data_len + 2) as u16).to_be_bytes());
    out.extend(filler(rng, data_len).into_bytes());
    out.extend([0xFF, 0xD9]);
    out
}

fn render(rng: &mut SplitMix64, kind: usize, size: usize) -> (&'static str, Vec<u8>) {
    match kind {
        0 => ("md", wrapped(rng, size, "# Notes\n\n", "\n")),
        1 => ("txt", wrapped(rng, size, "", "\n")),
        2 => (
            "rs",
            wrapped(rng, size, "pub const NOTE: &str = \"", "\";\n"),
        ),
        3 => ("json", wrapped(rng, size, "{\"note\":\"", "\"}\n")),
        4 => (
            "svg",
            wrapped(
                rng,
                size,
                "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"10\" height=\"10\"><text x=\"1\" y=\"5\">",
                "</text></svg>\n",
            ),
        ),
        5 => ("png", png(rng, size)),
        _ => ("jpg", jpeg(rng, size)),
    }
}

fn ensure_empty_dir(dir: &Path) -> Result<(), String> {
    if dir.exists() {
        let mut entries =
            fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        if entries.next().is_some() {
            return Err(format!("{} is not empty", dir.display()));
        }
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))
}

pub fn generate(dir: &Path, count: usize) -> Result<(), String> {
    ensure_empty_dir(dir)?;
    let mut rng = SplitMix64(SEED);
    for index in 0..count {
        let kind = rng.below(7);
        let size = MIN_SIZE + rng.below(MAX_SIZE - MIN_SIZE + 1);
        let (extension, bytes) = render(&mut rng, kind, size);
        let sub = dir.join(format!("d{:04}", index / FILES_PER_DIR));
        fs::create_dir_all(&sub).map_err(|e| format!("cannot create {}: {e}", sub.display()))?;
        let path = sub.join(format!("f{index:07}.{extension}"));
        fs::write(&path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xtask-pt-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, fs::read(&path).unwrap()));
            }
        }
    }

    fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    #[test]
    fn same_seed_and_count_give_byte_identical_trees() {
        let a = scratch("same-a");
        let b = scratch("same-b");
        generate(&a, 150).unwrap();
        generate(&b, 150).unwrap();
        assert_eq!(tree(&a), tree(&b));
        fs::remove_dir_all(&a).unwrap();
        fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn the_file_count_is_exact_and_no_directory_exceeds_one_thousand_files() {
        let dir = scratch("count");
        generate(&dir, 2500).unwrap();
        let files = tree(&dir);
        assert_eq!(files.len(), 2500);
        let mut per_dir = std::collections::BTreeMap::new();
        for (rel, _) in &files {
            let parent = rel.rsplit_once('/').map_or("", |(p, _)| p);
            *per_dir.entry(parent.to_string()).or_insert(0usize) += 1;
        }
        assert_eq!(per_dir.len(), 3);
        assert!(per_dir.values().all(|n| *n <= 1000), "{per_dir:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn zero_count_writes_nothing_but_succeeds() {
        let dir = scratch("zero");
        generate(&dir, 0).unwrap();
        assert!(tree(&dir).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_size_is_between_200_bytes_and_20_kib_and_every_kind_appears() {
        let dir = scratch("sizes");
        generate(&dir, 400).unwrap();
        let mut kinds = std::collections::BTreeSet::new();
        for (rel, bytes) in tree(&dir) {
            assert!(
                (200..=20480).contains(&bytes.len()),
                "{rel}: {}",
                bytes.len()
            );
            kinds.insert(rel.rsplit_once('.').unwrap().1.to_string());
        }
        let kinds: Vec<&str> = kinds.iter().map(String::as_str).collect();
        assert_eq!(kinds, ["jpg", "json", "md", "png", "rs", "svg", "txt"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn each_kind_has_the_shape_of_its_format() {
        let dir = scratch("shape");
        generate(&dir, 400).unwrap();
        for (rel, bytes) in tree(&dir) {
            let ext = rel.rsplit_once('.').unwrap().1;
            match ext {
                "png" => {
                    assert_eq!(&bytes[..8], &[0x89, b'P', b'N', b'G', 13, 10, 26, 10]);
                    assert_eq!(
                        &bytes[bytes.len() - 8..],
                        &[b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]
                    );
                }
                "jpg" => {
                    assert_eq!(&bytes[..2], &[0xFF, 0xD8]);
                    assert_eq!(&bytes[bytes.len() - 2..], &[0xFF, 0xD9]);
                }
                "json" => {
                    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
                }
                "svg" => assert!(bytes.starts_with(b"<svg ")),
                _ => assert!(String::from_utf8(bytes).unwrap().is_ascii()),
            }
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_non_empty_directory_is_refused_and_left_untouched() {
        let dir = scratch("busy");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("keep.txt"), b"mine").unwrap();
        let err = generate(&dir, 5).unwrap_err();
        assert!(err.contains("not empty"), "{err}");
        assert_eq!(tree(&dir), vec![("keep.txt".to_string(), b"mine".to_vec())]);
        assert_eq!(
            run(&[dir.display().to_string(), "5".to_string()]),
            ExitCode::from(2)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_existing_empty_directory_is_accepted() {
        let dir = scratch("empty");
        fs::create_dir_all(&dir).unwrap();
        generate(&dir, 3).unwrap();
        assert_eq!(tree(&dir).len(), 3);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_in_place_of_the_directory_is_refused() {
        let dir = scratch("isfile");
        fs::write(&dir, b"x").unwrap();
        assert!(generate(&dir, 1).is_err());
        fs::remove_file(&dir).unwrap();
    }

    #[test]
    fn bad_usage_exits_2_and_a_good_run_exits_0() {
        assert_eq!(run(&[]), ExitCode::from(2));
        assert_eq!(run(&["x".into(), "many".into()]), ExitCode::from(2));
        let dir = scratch("run");
        assert_eq!(
            run(&[dir.display().to_string(), "4".into()]),
            ExitCode::SUCCESS
        );
        assert_eq!(tree(&dir).len(), 4);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_first_file_for_count_one_matches_the_golden_kind_size_and_crc() {
        let dir = scratch("golden");
        generate(&dir, 1).unwrap();
        let files = tree(&dir);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "d0000/f0000000.json");
        assert_eq!(files[0].1.len(), 9215);
        assert_eq!(crc32(&files[0].1), 0x3168_B07A);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_png_text_chunk_carries_a_correct_crc() {
        let dir = scratch("pngcrc");
        generate(&dir, 200).unwrap();
        let mut checked = 0;
        for (rel, bytes) in tree(&dir) {
            if !rel.ends_with(".png") {
                continue;
            }
            let length = u32::from_be_bytes(bytes[33..37].try_into().unwrap()) as usize;
            assert_eq!(&bytes[37..41], b"tEXt", "{rel}");
            let body = &bytes[37..41 + length];
            let stored = u32::from_be_bytes(bytes[41 + length..45 + length].try_into().unwrap());
            assert_eq!(stored, crc32(body), "{rel}");
            checked += 1;
        }
        assert!(checked > 10, "{checked}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn splitmix64_from_seed_zero_matches_the_published_first_outputs() {
        let mut rng = SplitMix64(0);
        assert_eq!(rng.next(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next(), 0x6E78_9E6A_A1B9_65F4);
    }

    #[test]
    fn crc32_of_the_check_string_is_the_standard_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}

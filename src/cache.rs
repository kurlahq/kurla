use crate::engine::RULES_VERSION;
use crate::limits::Limits;
use crate::model::{
    CarrierKind, Category, EmbeddedNotScanned, Family, FileCoverage, FileKind, Finding,
    LocationKind, RawFinding, Review, RuleStatus, Severity, SkipReason, Span,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub type Cached = (Vec<Finding>, FileCoverage, BTreeMap<CarrierKind, u64>);

const ENTRY_VERSION: u64 = 1;
const KEY_LEN: usize = 64;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const RULE_IDS: [&str; 27] = [
    "A001", "A002", "A003", "A004", "A005", "A006", "A007", "A008", "A009", "A010", "B002", "B003",
    "E001", "I002", "L001", "L002", "M002", "S002", "S003", "S004", "U001", "U002", "U003", "U004",
    "U005", "U006", "U007",
];

fn rule_id(name: &str) -> Option<&'static str> {
    RULE_IDS.iter().find(|known| **known == name).copied()
}

macro_rules! names {
    ($to:ident, $from:ident, $ty:ty, [$($variant:path => $name:literal),+ $(,)?]) => {
        fn $to(value: $ty) -> &'static str {
            match value {
                $($variant => $name),+
            }
        }

        fn $from(name: &str) -> Option<$ty> {
            match name {
                $($name => Some($variant),)+
                _ => None,
            }
        }
    };
}

names!(severity_name, severity_from, Severity, [
    Severity::Info => "Info",
    Severity::Low => "Low",
    Severity::Medium => "Medium",
    Severity::High => "High",
    Severity::Critical => "Critical",
]);

names!(family_name, family_from, Family, [
    Family::U => "U",
    Family::M => "M",
    Family::A => "A",
    Family::S => "S",
    Family::B => "B",
    Family::E => "E",
    Family::I => "I",
    Family::L => "L",
]);

names!(status_name, status_from, RuleStatus, [
    RuleStatus::Stable => "Stable",
    RuleStatus::Experimental => "Experimental",
]);

names!(location_name, location_from, LocationKind, [
    LocationKind::AgentFile => "AgentFile",
    LocationKind::DocsTemplate => "DocsTemplate",
    LocationKind::Code => "Code",
    LocationKind::DataAsset => "DataAsset",
    LocationKind::Dependency => "Dependency",
]);

names!(carrier_name, carrier_from, CarrierKind, [
    CarrierKind::HiddenText => "HiddenText",
    CarrierKind::DecodedPayload => "DecodedPayload",
    CarrierKind::HtmlComment => "HtmlComment",
    CarrierKind::SvgText => "SvgText",
    CarrierKind::MetadataField => "MetadataField",
    CarrierKind::AgentFileText => "AgentFileText",
    CarrierKind::ActiveContent => "ActiveContent",
    CarrierKind::ResourceLimit => "ResourceLimit",
]);

names!(file_kind_name, file_kind_from, FileKind, [
    FileKind::Text => "Text",
    FileKind::Svg => "Svg",
    FileKind::Png => "Png",
    FileKind::Jpeg => "Jpeg",
    FileKind::Gif => "Gif",
    FileKind::Webp => "Webp",
    FileKind::Avif => "Avif",
    FileKind::Pdf => "Pdf",
    FileKind::OtherImage => "OtherImage",
    FileKind::UnknownBinary => "UnknownBinary",
]);

names!(category_name, category_from, Category, [
    Category::Text => "Text",
    Category::Svg => "Svg",
    Category::ImageMetadata => "ImageMetadata",
    Category::Pdf => "Pdf",
    Category::UnknownBinary => "UnknownBinary",
]);

names!(skip_name, skip_from, SkipReason, [
    SkipReason::SizeLimit => "SizeLimit",
    SkipReason::DecompressionLimit => "DecompressionLimit",
    SkipReason::Timeout => "Timeout",
    SkipReason::Unreadable => "Unreadable",
    SkipReason::ExcludedByUser => "ExcludedByUser",
    SkipReason::SymlinkNotFollowed => "SymlinkNotFollowed",
    SkipReason::PdfNotScanned => "PdfNotScanned",
    SkipReason::Malformed => "Malformed",
]);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.bytes().all(|b| b.is_ascii_hexdigit()) || !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

fn is_key(key: &str) -> bool {
    key.len() == KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn feed(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_le_bytes());
    hasher.update(field);
}

fn key_for(version: &str, rules: &str, rel_path: &str, bytes: &[u8], limits: &Limits) -> String {
    let mut hasher = Sha256::new();
    feed(&mut hasher, &Sha256::digest(bytes));
    feed(&mut hasher, rel_path.as_bytes());
    feed(&mut hasher, version.as_bytes());
    feed(&mut hasher, rules.as_bytes());
    feed(&mut hasher, &limits.max_file_bytes.to_le_bytes());
    feed(&mut hasher, &limits.max_decompressed_bytes.to_le_bytes());
    feed(&mut hasher, &limits.max_xml_depth.to_le_bytes());
    feed(&mut hasher, &limits.max_xml_attributes.to_le_bytes());
    feed(&mut hasher, &limits.max_base64_run_bytes.to_le_bytes());
    feed(&mut hasher, &limits.max_decode_depth.to_le_bytes());
    feed(&mut hasher, &limits.per_file_time.as_nanos().to_le_bytes());
    hex(&hasher.finalize())
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.is_empty())
}

fn resolve_from(
    cli: Option<PathBuf>,
    kurla_env: Option<String>,
    xdg: Option<String>,
    home: Option<String>,
    local_app_data: Option<String>,
) -> Result<PathBuf, String> {
    if let Some(dir) = cli {
        return Ok(dir);
    }
    if let Some(dir) = non_empty(kurla_env) {
        return Ok(PathBuf::from(dir));
    }
    let found = if cfg!(windows) {
        non_empty(local_app_data).map(|base| PathBuf::from(base).join("kurla").join("cache"))
    } else {
        non_empty(xdg)
            .map(|base| PathBuf::from(base).join("kurla"))
            .or_else(|| {
                non_empty(home).map(|base| PathBuf::from(base).join(".cache").join("kurla"))
            })
    };
    found.ok_or_else(|| {
        "cannot determine a cache directory (no --cache-dir, no KURLA_CACHE_DIR and no home directory)"
            .to_string()
    })
}

#[derive(Debug, Clone)]
pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    pub fn open(dir: Option<PathBuf>) -> Cache {
        let dir = dir.unwrap_or_default();
        let _ = fs::create_dir_all(&dir);
        Cache { dir }
    }

    pub fn resolve_dir(cli: Option<PathBuf>) -> Result<PathBuf, String> {
        let env = |name: &str| std::env::var(name).ok();
        resolve_from(
            cli,
            env("KURLA_CACHE_DIR"),
            env("XDG_CACHE_HOME"),
            env("HOME"),
            env("LOCALAPPDATA"),
        )
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn key(rel_path: &str, bytes: &[u8], limits: &Limits) -> String {
        key_for(
            env!("CARGO_PKG_VERSION"),
            RULES_VERSION,
            rel_path,
            bytes,
            limits,
        )
    }

    pub fn get(&self, key: &str) -> Option<Cached> {
        if !is_key(key) {
            return None;
        }
        let text = fs::read_to_string(self.dir.join(format!("{key}.json"))).ok()?;
        decode_entry(&text, key)
    }

    pub fn put(&self, key: &str, value: &Cached) -> bool {
        if !is_key(key) {
            return false;
        }
        let Some(text) = encode_entry(key, value) else {
            return true;
        };
        self.write_atomic(key, text.as_bytes()).is_ok()
    }

    fn write_atomic(&self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let temp = self.dir.join(format!(
            "{key}.{}.{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let written = fs::File::create(&temp).and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        });
        let renamed =
            written.and_then(|()| fs::rename(&temp, self.dir.join(format!("{key}.json"))));
        if renamed.is_err() {
            let _ = fs::remove_file(&temp);
        }
        renamed
    }
}

fn is_cacheable(value: &Cached) -> bool {
    let (findings, coverage, _) = value;
    coverage.skip != Some(SkipReason::Timeout)
        && findings.iter().all(|finding| finding.raw.rule_id != "L002")
        && findings
            .iter()
            .all(|finding| rule_id(finding.raw.rule_id).is_some())
}

fn span_value(span: &Span) -> Value {
    json!({
        "byte_start": span.byte_start,
        "byte_end": span.byte_end,
        "line": span.line,
        "column": span.column,
    })
}

fn finding_value(finding: &Finding) -> Value {
    let raw = &finding.raw;
    let review = finding.review.as_ref().map(|review| {
        json!({
            "reviewer": review.reviewer,
            "reason": review.reason,
            "counted": review.counted,
        })
    });
    json!({
        "rule_id": raw.rule_id,
        "family": family_name(raw.family),
        "base": severity_name(raw.base),
        "status": status_name(raw.status),
        "span": span_value(&raw.span),
        "carrier": carrier_name(raw.carrier),
        "payload": raw.payload,
        "message": raw.message,
        "evidence": hex(&raw.evidence),
        "location": location_name(finding.location),
        "severity": severity_name(finding.severity),
        "fingerprint": finding.fingerprint,
        "review": review,
    })
}

fn coverage_value(coverage: &FileCoverage) -> Value {
    let embedded: Vec<Value> = coverage
        .embedded_not_scanned
        .iter()
        .map(|item| {
            json!({
                "span": span_value(&item.span),
                "declared_type": item.declared_type,
                "kind": file_kind_name(item.kind),
                "reason": item.reason,
            })
        })
        .collect();
    json!({
        "kind": file_kind_name(coverage.kind),
        "category": category_name(coverage.category),
        "skip": coverage.skip.map(skip_name),
        "drawn_text_unscanned": coverage.drawn_text_unscanned,
        "embedded_not_scanned": embedded,
        "encoded_runs_not_payloads": coverage.encoded_runs_not_payloads,
    })
}

fn encode_entry(key: &str, value: &Cached) -> Option<String> {
    if !is_cacheable(value) {
        return None;
    }
    let (findings, coverage, counts) = value;
    let counts: Map<String, Value> = counts
        .iter()
        .map(|(kind, count)| (carrier_name(*kind).to_string(), json!(count)))
        .collect();
    let entry = json!({
        "version": ENTRY_VERSION,
        "key": key,
        "findings": findings.iter().map(finding_value).collect::<Vec<_>>(),
        "coverage": coverage_value(coverage),
        "carrier_counts": counts,
    });
    serde_json::to_string(&entry).ok()
}

fn object(value: Value) -> Option<Map<String, Value>> {
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn finish(map: Map<String, Value>) -> Option<()> {
    map.is_empty().then_some(())
}

fn take(map: &mut Map<String, Value>, name: &str) -> Option<Value> {
    map.remove(name)
}

fn take_string(map: &mut Map<String, Value>, name: &str) -> Option<String> {
    match take(map, name)? {
        Value::String(text) => Some(text),
        _ => None,
    }
}

fn take_option_string(map: &mut Map<String, Value>, name: &str) -> Option<Option<String>> {
    match take(map, name)? {
        Value::Null => Some(None),
        Value::String(text) => Some(Some(text)),
        _ => None,
    }
}

fn take_u64(map: &mut Map<String, Value>, name: &str) -> Option<u64> {
    take(map, name)?.as_u64()
}

fn take_option_u32(map: &mut Map<String, Value>, name: &str) -> Option<Option<u32>> {
    match take(map, name)? {
        Value::Null => Some(None),
        Value::Number(number) => Some(Some(u32::try_from(number.as_u64()?).ok()?)),
        _ => None,
    }
}

fn take_bool(map: &mut Map<String, Value>, name: &str) -> Option<bool> {
    take(map, name)?.as_bool()
}

fn take_object(map: &mut Map<String, Value>, name: &str) -> Option<Map<String, Value>> {
    object(take(map, name)?)
}

fn take_array(map: &mut Map<String, Value>, name: &str) -> Option<Vec<Value>> {
    match take(map, name)? {
        Value::Array(items) => Some(items),
        _ => None,
    }
}

fn read_span(map: &mut Map<String, Value>) -> Option<Span> {
    let mut span = take_object(map, "span")?;
    let parsed = Span {
        byte_start: take_u64(&mut span, "byte_start")?,
        byte_end: take_u64(&mut span, "byte_end")?,
        line: take_option_u32(&mut span, "line")?,
        column: take_option_u32(&mut span, "column")?,
    };
    finish(span)?;
    Some(parsed)
}

fn read_review(map: &mut Map<String, Value>) -> Option<Option<Review>> {
    let value = take(map, "review")?;
    if value.is_null() {
        return Some(None);
    }
    let mut review = object(value)?;
    let parsed = Review {
        reviewer: take_string(&mut review, "reviewer")?,
        reason: take_string(&mut review, "reason")?,
        counted: take_bool(&mut review, "counted")?,
    };
    finish(review)?;
    Some(Some(parsed))
}

fn read_finding(value: Value) -> Option<Finding> {
    let mut map = object(value)?;
    let raw = RawFinding {
        rule_id: rule_id(&take_string(&mut map, "rule_id")?)?,
        family: family_from(&take_string(&mut map, "family")?)?,
        base: severity_from(&take_string(&mut map, "base")?)?,
        status: status_from(&take_string(&mut map, "status")?)?,
        span: read_span(&mut map)?,
        carrier: carrier_from(&take_string(&mut map, "carrier")?)?,
        payload: take_option_string(&mut map, "payload")?,
        message: take_string(&mut map, "message")?,
        evidence: unhex(&take_string(&mut map, "evidence")?)?,
    };
    let finding = Finding {
        raw,
        path: String::new(),
        location: location_from(&take_string(&mut map, "location")?)?,
        severity: severity_from(&take_string(&mut map, "severity")?)?,
        fingerprint: take_string(&mut map, "fingerprint")?,
        review: read_review(&mut map)?,
    };
    finish(map)?;
    Some(finding)
}

fn read_embedded(value: Value) -> Option<EmbeddedNotScanned> {
    let mut map = object(value)?;
    let item = EmbeddedNotScanned {
        span: read_span(&mut map)?,
        declared_type: take_option_string(&mut map, "declared_type")?,
        kind: file_kind_from(&take_string(&mut map, "kind")?)?,
        reason: take_string(&mut map, "reason")?,
    };
    finish(map)?;
    Some(item)
}

fn read_coverage(mut map: Map<String, Value>) -> Option<FileCoverage> {
    let skip = match take_option_string(&mut map, "skip")? {
        Some(name) => Some(skip_from(&name)?),
        None => None,
    };
    let coverage = FileCoverage {
        path: String::new(),
        kind: file_kind_from(&take_string(&mut map, "kind")?)?,
        category: category_from(&take_string(&mut map, "category")?)?,
        skip,
        drawn_text_unscanned: take_bool(&mut map, "drawn_text_unscanned")?,
        embedded_not_scanned: take_array(&mut map, "embedded_not_scanned")?
            .into_iter()
            .map(read_embedded)
            .collect::<Option<Vec<_>>>()?,
        encoded_runs_not_payloads: take_u64(&mut map, "encoded_runs_not_payloads")?,
    };
    finish(map)?;
    Some(coverage)
}

fn read_counts(map: Map<String, Value>) -> Option<BTreeMap<CarrierKind, u64>> {
    map.into_iter()
        .map(|(name, count)| Some((carrier_from(&name)?, count.as_u64()?)))
        .collect()
}

fn decode_entry(text: &str, key: &str) -> Option<Cached> {
    let mut entry = object(serde_json::from_str::<Value>(text).ok()?)?;
    if take_u64(&mut entry, "version")? != ENTRY_VERSION {
        return None;
    }
    if take_string(&mut entry, "key")? != key {
        return None;
    }
    let findings = take_array(&mut entry, "findings")?
        .into_iter()
        .map(read_finding)
        .collect::<Option<Vec<_>>>()?;
    let coverage = read_coverage(take_object(&mut entry, "coverage")?)?;
    let counts = read_counts(take_object(&mut entry, "carrier_counts")?)?;
    finish(entry)?;
    let value = (findings, coverage, counts);
    is_cacheable(&value).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{RULES_VERSION, scan_file};
    use crate::model::{
        Category, EmbeddedNotScanned, Family, FileKind, LocationKind, RawFinding, Review,
        RuleStatus, Severity, SkipReason, Span,
    };
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> TestDir {
            let path = std::env::temp_dir().join(format!(
                "kurla-cache-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&path).unwrap();
            TestDir { path }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn span(start: u64, end: u64) -> Span {
        Span {
            byte_start: start,
            byte_end: end,
            line: Some(3),
            column: Some(4),
        }
    }

    fn finding(severity: Severity, payload: Option<&str>) -> Finding {
        Finding {
            raw: RawFinding {
                rule_id: "U002",
                family: Family::U,
                base: Severity::High,
                status: RuleStatus::Stable,
                span: span(1, 9),
                carrier: CarrierKind::HiddenText,
                payload: payload.map(str::to_string),
                message: "hidden text".to_string(),
                evidence: vec![0, 1, 255],
            },
            path: String::new(),
            location: LocationKind::Code,
            severity,
            fingerprint: "ab".repeat(32),
            review: None,
        }
    }

    fn coverage() -> FileCoverage {
        FileCoverage {
            path: String::new(),
            kind: FileKind::Text,
            category: Category::Text,
            skip: None,
            drawn_text_unscanned: false,
            embedded_not_scanned: Vec::new(),
            encoded_runs_not_payloads: 0,
        }
    }

    fn value() -> Cached {
        (
            vec![finding(Severity::High, Some("payload"))],
            coverage(),
            BTreeMap::from([(CarrierKind::HiddenText, 2)]),
        )
    }

    fn open(dir: &TestDir) -> Cache {
        Cache::open(Some(dir.path.join("c")))
    }

    fn base_key() -> String {
        Cache::key("a.txt", b"hello", &Limits::default())
    }

    fn entry_file(cache: &Cache, key: &str) -> PathBuf {
        cache.dir().join(format!("{key}.json"))
    }

    #[test]
    fn changed_content_misses_cache() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let key = Cache::key("a.txt", b"hello", &Limits::default());
        assert!(cache.put(&key, &value()));
        assert_eq!(cache.get(&key), Some(value()));
        let other = Cache::key("a.txt", b"hellp", &Limits::default());
        assert_ne!(key, other);
        assert_eq!(cache.get(&other), None);
    }

    #[test]
    fn same_content_different_path_misses_cache() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let key = Cache::key("a.txt", b"hello", &Limits::default());
        assert!(cache.put(&key, &value()));
        let other = Cache::key("b.txt", b"hello", &Limits::default());
        assert_ne!(key, other);
        assert_eq!(cache.get(&other), None);
    }

    #[test]
    fn changed_rules_version_misses_cache() {
        let limits = Limits::default();
        let now = key_for("0.1.0", RULES_VERSION, "a.txt", b"hello", &limits);
        let bumped = key_for("0.1.0", "2", "a.txt", b"hello", &limits);
        let newer = key_for("0.1.1", RULES_VERSION, "a.txt", b"hello", &limits);
        assert_ne!(now, bumped);
        assert_ne!(now, newer);
        assert_ne!(bumped, newer);
        assert_eq!(base_key().len(), 64);
        assert!(base_key().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            base_key(),
            key_for(
                env!("CARGO_PKG_VERSION"),
                RULES_VERSION,
                "a.txt",
                b"hello",
                &limits
            )
        );
    }

    #[test]
    fn changed_limits_miss_cache() {
        let d = Limits::default();
        let variants = [
            Limits {
                max_file_bytes: d.max_file_bytes + 1,
                ..d.clone()
            },
            Limits {
                max_decompressed_bytes: d.max_decompressed_bytes + 1,
                ..d.clone()
            },
            Limits {
                max_xml_depth: d.max_xml_depth + 1,
                ..d.clone()
            },
            Limits {
                max_xml_attributes: d.max_xml_attributes + 1,
                ..d.clone()
            },
            Limits {
                max_base64_run_bytes: d.max_base64_run_bytes + 1,
                ..d.clone()
            },
            Limits {
                max_decode_depth: d.max_decode_depth + 1,
                ..d.clone()
            },
            Limits {
                per_file_time: d.per_file_time + Duration::from_nanos(1),
                ..d.clone()
            },
        ];
        let dir = TestDir::new();
        let cache = open(&dir);
        let key = Cache::key("a.txt", b"hello", &d);
        assert!(cache.put(&key, &value()));
        let mut seen = vec![key];
        for limits in &variants {
            let other = Cache::key("a.txt", b"hello", limits);
            assert!(!seen.contains(&other));
            assert_eq!(cache.get(&other), None);
            seen.push(other);
        }
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        let limits = Limits::default();
        let one = Cache::key("ab", b"c", &limits);
        let two = Cache::key("a", b"bc", &limits);
        assert_ne!(one, two);
        let first = key_for("1", "23", "p", b"x", &limits);
        let second = key_for("12", "3", "p", b"x", &limits);
        assert_ne!(first, second);
    }

    #[test]
    fn corrupt_entry_is_ignored() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let key = base_key();
        assert!(cache.put(&key, &value()));
        let file = entry_file(&cache, &key);
        let good = fs::read_to_string(&file).unwrap();
        fs::write(&file, "not json at all").unwrap();
        assert_eq!(cache.get(&key), None);
        fs::write(&file, &good[..good.len() / 2]).unwrap();
        assert_eq!(cache.get(&key), None);
        fs::write(&file, b"").unwrap();
        assert_eq!(cache.get(&key), None);
        fs::write(&file, &good).unwrap();
        assert_eq!(cache.get(&key), Some(value()));
    }

    #[test]
    fn trailing_value_is_a_miss() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let key = base_key();
        assert!(cache.put(&key, &value()));
        let file = entry_file(&cache, &key);
        let good = fs::read_to_string(&file).unwrap();
        fs::write(&file, format!("{good} 1")).unwrap();
        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn missing_extra_and_mistyped_fields_are_misses() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let key = base_key();
        assert!(cache.put(&key, &value()));
        let file = entry_file(&cache, &key);
        let good = fs::read_to_string(&file).unwrap();
        let mutations = [
            good.replace("\"message\":\"hidden text\"", "\"message\":5"),
            good.replace("\"message\":\"hidden text\",", ""),
            good.replacen('{', "{\"extra\":1,", 1),
            good.replace(
                "\"drawn_text_unscanned\":false",
                "\"drawn_text_unscanned\":0",
            ),
        ];
        for mutated in mutations {
            assert_ne!(mutated, good);
            fs::write(&file, &mutated).unwrap();
            assert_eq!(cache.get(&key), None, "{mutated}");
        }
    }

    #[test]
    fn entry_with_wrong_key_inside_is_a_miss() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let key = base_key();
        let other = Cache::key("other.txt", b"hello", &Limits::default());
        assert!(cache.put(&key, &value()));
        fs::copy(entry_file(&cache, &key), entry_file(&cache, &other)).unwrap();
        assert_eq!(cache.get(&other), None);
        assert_eq!(cache.get(&key), Some(value()));
    }

    #[test]
    fn entry_with_unknown_enum_is_a_miss() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let key = base_key();
        assert!(cache.put(&key, &value()));
        let file = entry_file(&cache, &key);
        let good = fs::read_to_string(&file).unwrap();
        for from in [
            "\"High\"",
            "\"HiddenText\"",
            "\"Code\"",
            "\"Text\"",
            "\"U002\"",
            "\"Stable\"",
            "\"U\"",
        ] {
            let mutated = good.replace(from, "\"Bogus\"");
            assert_ne!(mutated, good, "{from}");
            fs::write(&file, &mutated).unwrap();
            assert_eq!(cache.get(&key), None, "{from}");
        }
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let mut findings = Vec::new();
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            findings.push(finding(severity, Some("payload")));
        }
        findings.push(finding(Severity::Low, None));
        let mut bare = finding(Severity::Medium, None);
        bare.raw.rule_id = "A003";
        bare.raw.family = Family::A;
        bare.raw.status = RuleStatus::Experimental;
        bare.raw.carrier = CarrierKind::DecodedPayload;
        bare.location = LocationKind::AgentFile;
        bare.raw.evidence = Vec::new();
        bare.raw.span = Span {
            byte_start: 0,
            byte_end: u64::MAX,
            line: None,
            column: None,
        };
        findings.push(bare);
        let mut reviewed = finding(Severity::High, Some("p"));
        reviewed.review = Some(Review {
            reviewer: "rev".to_string(),
            reason: "why".to_string(),
            counted: true,
        });
        findings.push(reviewed);
        let mut uncounted = finding(Severity::High, Some("q"));
        uncounted.review = Some(Review {
            reviewer: "rev2".to_string(),
            reason: "why2".to_string(),
            counted: false,
        });
        findings.push(uncounted);
        let cov = FileCoverage {
            path: String::new(),
            kind: FileKind::Png,
            category: Category::ImageMetadata,
            skip: Some(SkipReason::DecompressionLimit),
            drawn_text_unscanned: true,
            embedded_not_scanned: vec![
                EmbeddedNotScanned {
                    span: span(5, 6),
                    declared_type: Some("image/png".to_string()),
                    kind: FileKind::Pdf,
                    reason: "pdf content not scanned".to_string(),
                },
                EmbeddedNotScanned {
                    span: span(7, 8),
                    declared_type: None,
                    kind: FileKind::UnknownBinary,
                    reason: "unrecognised binary content".to_string(),
                },
            ],
            encoded_runs_not_payloads: 17,
        };
        let counts = BTreeMap::from([
            (CarrierKind::HiddenText, 1),
            (CarrierKind::SvgText, 2),
            (CarrierKind::ResourceLimit, u64::MAX),
        ]);
        let stored: Cached = (findings, cov, counts);
        let key = base_key();
        assert!(cache.put(&key, &stored));
        assert_eq!(cache.get(&key), Some(stored));
    }

    #[test]
    fn every_enum_name_round_trips() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let kinds = [
            (FileKind::Text, Category::Text),
            (FileKind::Svg, Category::Svg),
            (FileKind::Png, Category::ImageMetadata),
            (FileKind::Jpeg, Category::ImageMetadata),
            (FileKind::Gif, Category::ImageMetadata),
            (FileKind::Webp, Category::ImageMetadata),
            (FileKind::Avif, Category::ImageMetadata),
            (FileKind::Pdf, Category::Pdf),
            (FileKind::OtherImage, Category::UnknownBinary),
            (FileKind::UnknownBinary, Category::UnknownBinary),
        ];
        let skips = [
            SkipReason::SizeLimit,
            SkipReason::DecompressionLimit,
            SkipReason::Unreadable,
            SkipReason::ExcludedByUser,
            SkipReason::SymlinkNotFollowed,
            SkipReason::PdfNotScanned,
            SkipReason::Malformed,
        ];
        for (index, (kind, category)) in kinds.into_iter().enumerate() {
            let mut cov = coverage();
            cov.kind = kind;
            cov.category = category;
            cov.skip = skips.get(index).copied();
            let stored: Cached = (Vec::new(), cov, BTreeMap::new());
            let key = Cache::key("n.txt", &[u8::try_from(index).unwrap()], &Limits::default());
            assert!(cache.put(&key, &stored));
            assert_eq!(cache.get(&key), Some(stored));
        }
        let carriers = [
            CarrierKind::HiddenText,
            CarrierKind::DecodedPayload,
            CarrierKind::HtmlComment,
            CarrierKind::SvgText,
            CarrierKind::MetadataField,
            CarrierKind::AgentFileText,
            CarrierKind::ActiveContent,
            CarrierKind::ResourceLimit,
        ];
        let locations = [
            LocationKind::AgentFile,
            LocationKind::DocsTemplate,
            LocationKind::Code,
            LocationKind::DataAsset,
            LocationKind::Dependency,
        ];
        let families = [
            Family::U,
            Family::M,
            Family::A,
            Family::S,
            Family::B,
            Family::E,
            Family::I,
            Family::L,
        ];
        let rules = [
            "A001", "A002", "A003", "A004", "A005", "A006", "A007", "A008", "A009", "A010", "B002",
            "B003", "E001", "I002", "L001", "M002", "S002", "S003", "S004", "U001", "U002", "U003",
            "U004", "U005", "U006", "U007",
        ];
        let mut findings = Vec::new();
        for (index, rule) in rules.into_iter().enumerate() {
            let mut f = finding(Severity::Low, None);
            f.raw.rule_id = rule;
            f.raw.carrier = carriers[index % carriers.len()];
            f.raw.family = families[index % families.len()];
            f.location = locations[index % locations.len()];
            findings.push(f);
        }
        let counts = carriers.into_iter().map(|c| (c, 1)).collect();
        let stored: Cached = (findings, coverage(), counts);
        let key = base_key();
        assert!(cache.put(&key, &stored));
        assert_eq!(cache.get(&key), Some(stored));
    }

    #[test]
    fn timeout_result_is_not_cached() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let limits = Limits {
            per_file_time: Duration::ZERO,
            ..Limits::default()
        };
        let scanned = scan_file("a.txt", b"some plain words here", &limits);
        assert_eq!(scanned.1.skip, Some(SkipReason::Timeout));
        let key = Cache::key("a.txt", b"some plain words here", &limits);
        assert!(cache.put(&key, &scanned));
        assert_eq!(cache.get(&key), None);
        assert!(!entry_file(&cache, &key).exists());
    }

    #[test]
    fn result_with_l002_is_not_cached() {
        let dir = TestDir::new();
        let cache = open(&dir);
        let mut stored = value();
        stored.0[0].raw.rule_id = "L002";
        let key = base_key();
        assert!(cache.put(&key, &stored));
        assert_eq!(cache.get(&key), None);
        assert!(!entry_file(&cache, &key).exists());
    }

    #[test]
    fn put_leaves_no_temporary_files() {
        let dir = TestDir::new();
        let cache = open(&dir);
        assert!(cache.put(&base_key(), &value()));
        let names: Vec<String> = fs::read_dir(cache.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec![format!("{}.json", base_key())]);
    }

    #[test]
    fn put_reports_failure_when_the_directory_is_a_file() {
        let dir = TestDir::new();
        let blocker = dir.path.join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let cache = Cache::open(Some(blocker));
        assert!(!cache.put(&base_key(), &value()));
        assert_eq!(cache.get(&base_key()), None);
    }

    #[test]
    fn malformed_keys_are_never_used_as_file_names() {
        let dir = TestDir::new();
        let cache = open(&dir);
        assert!(!cache.put("../escape", &value()));
        assert!(!cache.put("short", &value()));
        assert_eq!(cache.get("../escape"), None);
        assert!(!dir.path.join("escape.json").exists());
    }

    fn some(text: &str) -> Option<String> {
        Some(text.to_string())
    }

    #[test]
    fn cache_dir_unresolvable_is_reported() {
        let error = resolve_from(None, None, None, None, None).unwrap_err();
        assert!(error.contains("cache directory"), "{error}");
        assert!(resolve_from(None, some(""), some(""), some(""), some("")).is_err());
    }

    #[test]
    fn cache_dir_order_is_flag_then_environment_then_platform_default() {
        let cli = Some(PathBuf::from("flag"));
        let all = |cli: Option<PathBuf>, env: Option<String>| {
            resolve_from(cli, env, some("xdg"), some("home"), some("local"))
        };
        assert_eq!(
            all(cli.clone(), some("env")).unwrap(),
            PathBuf::from("flag")
        );
        assert_eq!(all(None, some("env")).unwrap(), PathBuf::from("env"));
        let default = all(None, None).unwrap();
        if cfg!(windows) {
            assert_eq!(default, PathBuf::from("local").join("kurla").join("cache"));
        } else {
            assert_eq!(default, PathBuf::from("xdg").join("kurla"));
        }
    }

    #[test]
    fn home_fallback_is_used_without_the_primary_variable() {
        let result = resolve_from(None, None, None, some("home"), None);
        if cfg!(windows) {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap(),
                PathBuf::from("home").join(".cache").join("kurla")
            );
        }
    }
}

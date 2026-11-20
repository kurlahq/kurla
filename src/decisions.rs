use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::model::{Finding, Review};

pub const MAX_VALIDITY_DAYS: i64 = 365;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: i32,
    pub month: u32,
    pub day: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionsError {
    pub message: String,
}

impl fmt::Display for DecisionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DecisionsError {}

fn error(message: String) -> DecisionsError {
    DecisionsError { message }
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    }
}

fn digits(bytes: &[u8]) -> Option<u32> {
    if bytes.iter().all(u8::is_ascii_digit) {
        Some(
            bytes
                .iter()
                .fold(0, |acc, b| acc * 10 + u32::from(b - b'0')),
        )
    } else {
        None
    }
}

impl Date {
    pub fn parse(text: &str) -> Option<Date> {
        let bytes = text.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return None;
        }
        let year = i32::try_from(digits(&bytes[0..4])?).ok()?;
        let month = digits(&bytes[5..7])?;
        let day = digits(&bytes[8..10])?;
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        Some(Date { year, month, day })
    }

    pub fn days_since_epoch(self) -> i64 {
        let month = i64::from(self.month);
        let year = i64::from(self.year) - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let shifted_month = (month + 9) % 12;
        let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    pub fn from_days_since_epoch(days: i64) -> Date {
        let shifted = days + 719_468;
        let era = shifted.div_euclid(146_097);
        let day_of_era = shifted - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        };
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        Date {
            year: year as i32,
            month: month as u32,
            day: day as u32,
        }
    }

    pub fn from_unix_seconds(seconds: u64) -> Date {
        Date::from_days_since_epoch((seconds / 86_400) as i64)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

pub fn today_from(env_value: Option<&str>, now: SystemTime) -> Result<Date, DecisionsError> {
    match env_value {
        Some(text) => Date::parse(text).ok_or_else(|| {
            error(format!(
                "KURLA_TODAY: `{text}` is not a real YYYY-MM-DD date"
            ))
        }),
        None => {
            let seconds = now
                .duration_since(UNIX_EPOCH)
                .map_err(|_| error("system clock is before 1970-01-01".to_string()))?
                .as_secs();
            Ok(Date::from_unix_seconds(seconds))
        }
    }
}

pub fn today() -> Result<Date, DecisionsError> {
    match std::env::var("KURLA_TODAY") {
        Ok(text) => today_from(Some(&text), SystemTime::now()),
        Err(std::env::VarError::NotPresent) => today_from(None, SystemTime::now()),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(error("KURLA_TODAY: value is not valid unicode".to_string()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub fingerprint: String,
    pub rule: String,
    pub path: String,
    pub reviewer: String,
    pub reason: String,
    pub date: Date,
    pub expires: Date,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionsSource {
    Current,
    Base,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidDecision {
    pub source: DecisionsSource,
    pub fingerprint: String,
    pub rule: String,
    pub path: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Decisions {
    pub entries: Vec<Entry>,
}

const ENTRY_FIELDS: [&str; 7] = [
    "fingerprint",
    "rule",
    "path",
    "reviewer",
    "reason",
    "date",
    "expires",
];

impl Entry {
    pub fn invalid_reason(&self, today: Date) -> Option<&'static str> {
        if self.expires.days_since_epoch() - self.date.days_since_epoch() > MAX_VALIDITY_DAYS {
            Some("longer than 365 days")
        } else if today < self.date {
            Some("not yet valid")
        } else if today >= self.expires {
            Some("expired")
        } else {
            None
        }
    }

    fn matches(&self, finding: &Finding) -> bool {
        self.fingerprint == finding.fingerprint && self.rule == finding.raw.rule_id
    }
}

fn string_field(
    object: &Map<String, Value>,
    index: usize,
    field: &str,
) -> Result<String, DecisionsError> {
    match object.get(field) {
        None => Err(error(format!("entry {index}: missing field `{field}`"))),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(error(format!(
            "entry {index}: field `{field}` must be a string"
        ))),
    }
}

fn date_field(
    object: &Map<String, Value>,
    index: usize,
    field: &str,
) -> Result<Date, DecisionsError> {
    let text = string_field(object, index, field)?;
    Date::parse(&text).ok_or_else(|| {
        error(format!(
            "entry {index}: field `{field}` is not a real YYYY-MM-DD date"
        ))
    })
}

fn parse_entry(index: usize, value: &Value) -> Result<Entry, DecisionsError> {
    let object = value
        .as_object()
        .ok_or_else(|| error(format!("entry {index}: must be an object")))?;
    if let Some(unknown) = object.keys().find(|k| !ENTRY_FIELDS.contains(&k.as_str())) {
        return Err(error(format!("entry {index}: unknown field `{unknown}`")));
    }
    let fingerprint = string_field(object, index, "fingerprint")?;
    let rule = string_field(object, index, "rule")?;
    let path = string_field(object, index, "path")?;
    let reviewer = string_field(object, index, "reviewer")?;
    let reason = string_field(object, index, "reason")?;
    let date = date_field(object, index, "date")?;
    let expires = date_field(object, index, "expires")?;
    let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if fingerprint.len() != 64 || !fingerprint.bytes().all(lower_hex) {
        return Err(error(format!(
            "entry {index}: field `fingerprint` must be 64 lowercase hex characters"
        )));
    }
    for (name, text) in [
        ("rule", &rule),
        ("reviewer", &reviewer),
        ("reason", &reason),
    ] {
        if text.is_empty() {
            return Err(error(format!("entry {index}: field `{name}` is empty")));
        }
    }
    Ok(Entry {
        fingerprint,
        rule,
        path,
        reviewer,
        reason,
        date,
        expires,
    })
}

struct StrictValue(Value);

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::Bool(v)))
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::Number(Number::from(v))))
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::Number(Number::from(v))))
    }

    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<StrictValue, E> {
        Number::from_f64(v)
            .map(|n| StrictValue(Value::Number(n)))
            .ok_or_else(|| E::custom("number is not finite"))
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::String(v.to_string())))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::String(v)))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StrictValue, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictValue(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(StrictValue(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StrictValue, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate key \"{key}\"")));
            }
            let StrictValue(value) = map.next_value()?;
            object.insert(key, value);
        }
        Ok(StrictValue(Value::Object(object)))
    }
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<StrictValue, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

impl Decisions {
    pub fn parse(text: &str) -> Result<Decisions, DecisionsError> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let value = serde_json::from_str::<StrictValue>(text)
            .map_err(|e| error(format!("decisions file rejected: {e}")))?
            .0;
        let object = value
            .as_object()
            .ok_or_else(|| error("top level: must be an object".to_string()))?;
        if let Some(unknown) = object
            .keys()
            .find(|k| k.as_str() != "version" && k.as_str() != "entries")
        {
            return Err(error(format!("top level: unknown field `{unknown}`")));
        }
        match object.get("version") {
            None => return Err(error("top level: missing field `version`".to_string())),
            Some(version) if version.as_u64() == Some(1) => {}
            Some(_) => return Err(error("top level: `version` must be 1".to_string())),
        }
        let items = match object.get("entries") {
            None => return Err(error("top level: missing field `entries`".to_string())),
            Some(Value::Array(items)) => items,
            Some(_) => return Err(error("top level: `entries` must be an array".to_string())),
        };
        let entries = items
            .iter()
            .enumerate()
            .map(|(index, value)| parse_entry(index, value))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Decisions { entries })
    }

    pub fn load(path: &Path) -> Result<Decisions, DecisionsError> {
        let bytes =
            std::fs::read(path).map_err(|e| error(format!("cannot read decisions file: {e}")))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| error("decisions file is not valid UTF-8".to_string()))?;
        Decisions::parse(&text)
    }
}

pub fn apply(
    findings: &mut [Finding],
    current: Option<&Decisions>,
    base: Option<&Decisions>,
    today: Date,
) -> Vec<InvalidDecision> {
    let Some(current) = current else {
        return Vec::new();
    };
    let mut current_invalid: Vec<(usize, InvalidDecision)> = Vec::new();
    let mut base_invalid: Vec<(usize, InvalidDecision)> = Vec::new();
    for finding in findings.iter_mut() {
        let mut chosen: Option<&Entry> = None;
        for (index, entry) in current.entries.iter().enumerate() {
            if !entry.matches(finding) {
                continue;
            }
            match entry.invalid_reason(today) {
                None => {
                    chosen = chosen.or(Some(entry));
                }
                Some(reason) => record_invalid(
                    &mut current_invalid,
                    index,
                    entry,
                    DecisionsSource::Current,
                    reason,
                ),
            }
        }
        let Some(entry) = chosen else {
            continue;
        };
        let mut counted = false;
        if let Some(base) = base {
            for (index, base_entry) in base.entries.iter().enumerate() {
                if !base_entry.matches(finding) {
                    continue;
                }
                match base_entry.invalid_reason(today) {
                    None => counted = true,
                    Some(reason) => record_invalid(
                        &mut base_invalid,
                        index,
                        base_entry,
                        DecisionsSource::Base,
                        reason,
                    ),
                }
            }
        }
        finding.review = Some(Review {
            reviewer: entry.reviewer.clone(),
            reason: entry.reason.clone(),
            counted,
        });
    }
    current_invalid.sort_by_key(|(index, _)| *index);
    base_invalid.sort_by_key(|(index, _)| *index);
    current_invalid
        .into_iter()
        .chain(base_invalid)
        .map(|(_, d)| d)
        .collect()
}

fn record_invalid(
    list: &mut Vec<(usize, InvalidDecision)>,
    index: usize,
    entry: &Entry,
    source: DecisionsSource,
    reason: &'static str,
) {
    if list.iter().any(|(i, _)| *i == index) {
        return;
    }
    list.push((
        index,
        InvalidDecision {
            source,
            fingerprint: entry.fingerprint.clone(),
            rule: entry.rule.clone(),
            path: entry.path.clone(),
            reason,
        },
    ));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedFile {
    pub file: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Applied {
    pub invalid: Vec<InvalidDecision>,
    pub rejected: Vec<RejectedFile>,
}

fn load_or_reject(path: Option<&Path>, rejected: &mut Vec<RejectedFile>) -> Option<Decisions> {
    let path = path?;
    match Decisions::load(path) {
        Ok(decisions) => Some(decisions),
        Err(e) => {
            rejected.push(RejectedFile {
                file: path.to_string_lossy().into_owned(),
                message: e.message,
            });
            None
        }
    }
}

pub fn load_and_apply(
    findings: &mut [Finding],
    current: Option<&Path>,
    base: Option<&Path>,
    today: Date,
) -> Applied {
    let mut rejected = Vec::new();
    let current = load_or_reject(current, &mut rejected);
    let base = load_or_reject(base, &mut rejected);
    let invalid = apply(findings, current.as_ref(), base.as_ref(), today);
    Applied { invalid, rejected }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CarrierKind, Family, LocationKind, RawFinding, RuleStatus, Severity, Span};
    use std::time::{Duration, UNIX_EPOCH};

    const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_B: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn d(y: i32, m: u32, day: u32) -> Date {
        Date {
            year: y,
            month: m,
            day,
        }
    }

    fn finding(rule: &'static str, fingerprint: &str) -> Finding {
        Finding {
            raw: RawFinding {
                rule_id: rule,
                family: Family::S,
                base: Severity::High,
                status: RuleStatus::Stable,
                span: Span {
                    byte_start: 0,
                    byte_end: 1,
                    line: None,
                    column: None,
                },
                carrier: CarrierKind::HiddenText,
                payload: None,
                message: String::new(),
                evidence: Vec::new(),
            },
            path: "a.md".to_string(),
            location: LocationKind::Code,
            severity: Severity::High,
            fingerprint: fingerprint.to_string(),
            review: None,
        }
    }

    fn entry_json(fp: &str, rule: &str, reviewer: &str, date: &str, expires: &str) -> String {
        format!(
            r#"{{"fingerprint":"{fp}","rule":"{rule}","path":"a.md","reviewer":"{reviewer}","reason":"ok","date":"{date}","expires":"{expires}"}}"#
        )
    }

    fn file(entries: &[String]) -> Decisions {
        Decisions::parse(&format!(
            r#"{{"version":1,"entries":[{}]}}"#,
            entries.join(",")
        ))
        .unwrap()
    }

    fn today() -> Date {
        d(2026, 6, 1)
    }

    fn valid_entry(fp: &str, rule: &str, reviewer: &str) -> String {
        entry_json(fp, rule, reviewer, "2026-05-01", "2026-09-01")
    }

    #[test]
    fn entry_added_in_pr_without_base_is_shown_not_counted() {
        let current = file(&[valid_entry(FP_A, "S002", "rev")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, today());
        let review = findings[0].review.as_ref().unwrap();
        assert!(!review.counted);
        assert_eq!(review.reviewer, "rev");
        assert_eq!(review.reason, "ok");
        assert!(invalid.is_empty());
    }

    #[test]
    fn entry_present_in_base_is_counted() {
        let current = file(&[valid_entry(FP_A, "S002", "rev")]);
        let base = file(&[valid_entry(FP_A, "S002", "other")]);
        let mut findings = [finding("S002", FP_A)];
        apply(&mut findings, Some(&current), Some(&base), today());
        let review = findings[0].review.as_ref().unwrap();
        assert!(review.counted);
        assert_eq!(review.reviewer, "rev");
    }

    #[test]
    fn base_entry_that_is_expired_does_not_count() {
        let current = file(&[valid_entry(FP_A, "S002", "rev")]);
        let base = file(&[entry_json(FP_A, "S002", "old", "2026-01-01", "2026-06-01")]);
        let mut findings = [finding("S002", FP_A)];
        apply(&mut findings, Some(&current), Some(&base), today());
        assert!(!findings[0].review.as_ref().unwrap().counted);
    }

    #[test]
    fn base_entry_for_other_rule_does_not_count() {
        let current = file(&[valid_entry(FP_A, "S002", "rev")]);
        let base = file(&[valid_entry(FP_A, "S003", "rev")]);
        let mut findings = [finding("S002", FP_A)];
        apply(&mut findings, Some(&current), Some(&base), today());
        assert!(!findings[0].review.as_ref().unwrap().counted);
    }

    #[test]
    fn base_alone_without_current_entry_reviews_nothing() {
        let base = file(&[valid_entry(FP_A, "S002", "rev")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, None, Some(&base), today());
        assert!(findings[0].review.is_none());
        assert!(invalid.is_empty());
    }

    #[test]
    fn expired_entry_not_counted() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2026-01-01", "2026-06-01")]);
        let base = file(&[entry_json(FP_A, "S002", "rev", "2026-01-01", "2026-06-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), Some(&base), today());
        assert!(findings[0].review.is_none());
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0].reason, "expired");
        assert_eq!(invalid[0].fingerprint, FP_A);
        assert_eq!(invalid[0].rule, "S002");
        assert_eq!(invalid[0].path, "a.md");
    }

    #[test]
    fn entry_valid_on_last_day_before_expiry_and_on_start_day() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2026-06-01", "2026-06-02")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, d(2026, 6, 1));
        assert!(findings[0].review.is_some());
        assert!(invalid.is_empty());
    }

    #[test]
    fn expiry_beyond_365_days_invalid() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2026-03-01", "2027-03-02")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, today());
        assert!(findings[0].review.is_none());
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0].reason, "longer than 365 days");
    }

    #[test]
    fn expiry_of_exactly_365_days_is_valid() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2026-03-01", "2027-03-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, today());
        assert!(findings[0].review.is_some());
        assert!(invalid.is_empty());
    }

    #[test]
    fn expiry_across_leap_day_counts_366_days_and_is_invalid() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2027-03-01", "2028-03-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, d(2027, 6, 1));
        assert!(findings[0].review.is_none());
        assert_eq!(invalid[0].reason, "longer than 365 days");
    }

    #[test]
    fn leap_day_2028_is_valid() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2028-02-29", "2028-03-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, d(2028, 2, 29));
        assert!(findings[0].review.is_some());
        assert!(invalid.is_empty());
        assert!(Date::parse("2000-02-29").is_some());
        assert!(Date::parse("2100-02-29").is_none());
        assert_eq!(
            d(2028, 3, 1).days_since_epoch() - d(2028, 2, 29).days_since_epoch(),
            1
        );
    }

    #[test]
    fn not_yet_valid_entry_reported() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2026-06-02", "2026-09-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, today());
        assert!(findings[0].review.is_none());
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0].reason, "not yet valid");
    }

    #[test]
    fn invalid_entry_reported_once_for_several_findings() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2026-01-01", "2026-06-01")]);
        let mut findings = [finding("S002", FP_A), finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, today());
        assert_eq!(invalid.len(), 1);
    }

    #[test]
    fn unmatched_invalid_entry_is_not_reported() {
        let current = file(&[entry_json(FP_B, "S002", "rev", "2026-01-01", "2026-06-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, today());
        assert!(invalid.is_empty());
    }

    #[test]
    fn forged_entry_shows_reviewer_label() {
        let current = file(&[valid_entry(FP_A, "S002", "someone-trusted")]);
        let mut findings = [finding("S002", FP_A)];
        apply(&mut findings, Some(&current), None, today());
        let review = findings[0].review.as_ref().unwrap();
        assert_eq!(review.reviewer, "someone-trusted");
        assert!(!review.counted);
    }

    #[test]
    fn matching_needs_rule_as_well_as_fingerprint() {
        let current = file(&[valid_entry(FP_A, "S003", "rev")]);
        let mut findings = [finding("S002", FP_A), finding("S003", FP_B)];
        apply(&mut findings, Some(&current), None, today());
        assert!(findings[0].review.is_none());
        assert!(findings[1].review.is_none());
    }

    #[test]
    fn earliest_valid_entry_wins() {
        let current = file(&[
            entry_json(FP_A, "S002", "expired-first", "2026-01-01", "2026-06-01"),
            valid_entry(FP_A, "S002", "second"),
            valid_entry(FP_A, "S002", "third"),
        ]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, today());
        assert_eq!(findings[0].review.as_ref().unwrap().reviewer, "second");
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0].reason, "expired");
    }

    #[test]
    fn malformed_decisions_file_is_error_not_silence() {
        assert!(Decisions::parse("{not json").is_err());
        assert!(Decisions::parse("").is_err());
        assert!(Decisions::parse("[]").is_err());
        assert!(Decisions::parse(r#"{"version":1}"#).is_err());
        assert!(Decisions::parse(r#"{"entries":[]}"#).is_err());
        assert!(Decisions::parse(r#"{"version":2,"entries":[]}"#).is_err());
        assert!(Decisions::parse(r#"{"version":"1","entries":[]}"#).is_err());
        assert!(Decisions::parse(r#"{"version":1,"entries":{}}"#).is_err());
        assert!(Decisions::parse(r#"{"version":1,"entries":[1]}"#).is_err());
        assert!(Decisions::parse(r#"{"version":1,"entries":[],"extra":1}"#).is_err());
        assert!(Decisions::parse(r#"{"version":1,"entries":[]}"#).is_ok());
    }

    #[test]
    fn error_names_entry_index_and_field() {
        let good = valid_entry(FP_A, "S002", "rev");
        let bad = good.replace(r#""reviewer":"rev""#, r#""reviewer":5"#);
        let err =
            Decisions::parse(&format!(r#"{{"version":1,"entries":[{good},{bad}]}}"#)).unwrap_err();
        assert!(err.message.contains("entry 1"), "{}", err.message);
        assert!(err.message.contains("reviewer"), "{}", err.message);
    }

    #[test]
    fn missing_field_is_error() {
        let bad = valid_entry(FP_A, "S002", "rev").replace(r#""path":"a.md","#, "");
        let err = Decisions::parse(&format!(r#"{{"version":1,"entries":[{bad}]}}"#)).unwrap_err();
        assert!(err.message.contains("path"), "{}", err.message);
    }

    #[test]
    fn empty_reviewer_reason_and_rule_are_errors() {
        for field in ["reviewer", "reason", "rule"] {
            let good = valid_entry(FP_A, "S002", "rev");
            let needle = match field {
                "reviewer" => r#""reviewer":"rev""#,
                "reason" => r#""reason":"ok""#,
                _ => r#""rule":"S002""#,
            };
            let bad = good.replace(needle, &format!(r#""{field}":"""#));
            let err =
                Decisions::parse(&format!(r#"{{"version":1,"entries":[{bad}]}}"#)).unwrap_err();
            assert!(err.message.contains(field), "{}", err.message);
        }
    }

    #[test]
    fn unknown_field_is_error() {
        let bad = valid_entry(FP_A, "S002", "rev").replace('}', r#","note":"x"}"#);
        let err = Decisions::parse(&format!(r#"{{"version":1,"entries":[{bad}]}}"#)).unwrap_err();
        assert!(err.message.contains("note"), "{}", err.message);
    }

    #[test]
    fn bad_fingerprint_is_error() {
        let uppercase = FP_B.to_uppercase();
        let short = &FP_A[..63];
        let long = format!("{FP_A}a");
        let non_hex = format!("{}g", &FP_A[..63]);
        for fp in [uppercase.as_str(), short, long.as_str(), non_hex.as_str()] {
            let bad = valid_entry(fp, "S002", "rev");
            let err =
                Decisions::parse(&format!(r#"{{"version":1,"entries":[{bad}]}}"#)).unwrap_err();
            assert!(err.message.contains("fingerprint"), "{}", err.message);
        }
    }

    #[test]
    fn impossible_date_is_error() {
        for (date, expires, field) in [
            ("2025-02-29", "2025-06-01", "date"),
            ("2026-01-01", "2026-13-01", "expires"),
            ("2026-01-01", "2026-04-31", "expires"),
            ("2026-1-01", "2026-06-01", "date"),
            ("2026-01-01", "2026-06-00", "expires"),
            ("2026/01/01", "2026-06-01", "date"),
        ] {
            let bad = entry_json(FP_A, "S002", "rev", date, expires);
            let err =
                Decisions::parse(&format!(r#"{{"version":1,"entries":[{bad}]}}"#)).unwrap_err();
            assert!(
                err.message.contains(&format!("field `{field}`")),
                "{date} {expires}: {}",
                err.message
            );
        }
    }

    #[test]
    fn utf8_bom_is_allowed_and_utf16_is_error() {
        let text = format!(
            "\u{feff}{{\"version\":1,\"entries\":[{}]}}",
            valid_entry(FP_A, "S002", "rev")
        );
        assert_eq!(Decisions::parse(&text).unwrap().entries.len(), 1);

        let dir = std::env::temp_dir().join(format!("kurla-decisions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let utf16: Vec<u8> = "{\"version\":1,\"entries\":[]}"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let utf16_path = dir.join("utf16.json");
        std::fs::write(&utf16_path, utf16).unwrap();
        assert!(Decisions::load(&utf16_path).is_err());

        let bom_path = dir.join("bom.json");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"{\"version\":1,\"entries\":[]}");
        std::fs::write(&bom_path, bytes).unwrap();
        assert!(Decisions::load(&bom_path).unwrap().entries.is_empty());

        assert!(Decisions::load(&dir.join("missing.json")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn days_from_civil_matches_hand_calculation() {
        assert_eq!(d(1970, 1, 1).days_since_epoch(), 0);
        assert_eq!(d(2000, 3, 1).days_since_epoch(), 11017);
        assert_eq!(d(2023, 11, 14).days_since_epoch(), 19675);
        assert_eq!(d(1969, 12, 31).days_since_epoch(), -1);
        assert_eq!(Date::from_days_since_epoch(19675), d(2023, 11, 14));
        assert_eq!(Date::from_days_since_epoch(11017), d(2000, 3, 1));
        assert_eq!(Date::from_days_since_epoch(-1), d(1969, 12, 31));
        assert_eq!(Date::from_days_since_epoch(11016), d(2000, 2, 29));
    }

    #[test]
    fn date_displays_zero_padded() {
        assert_eq!(d(2026, 3, 9).to_string(), "2026-03-09");
    }

    #[test]
    fn today_from_clock_is_utc_date() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(today_from(None, now).unwrap(), d(2023, 11, 14));
        let just_before_midnight = UNIX_EPOCH + Duration::from_secs(19675 * 86_400 + 86_399);
        assert_eq!(
            today_from(None, just_before_midnight).unwrap(),
            d(2023, 11, 14)
        );
        let midnight = UNIX_EPOCH + Duration::from_secs(19676 * 86_400);
        assert_eq!(today_from(None, midnight).unwrap(), d(2023, 11, 15));
    }

    #[test]
    fn kurla_today_overrides_clock() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(today_from(Some("2030-01-02"), now).unwrap(), d(2030, 1, 2));
    }

    #[test]
    fn kurla_today_unparseable_is_error() {
        let now = UNIX_EPOCH;
        let err = today_from(Some("tomorrow"), now).unwrap_err();
        assert!(err.message.contains("KURLA_TODAY"), "{}", err.message);
        assert!(today_from(Some("2025-02-29"), now).is_err());
        assert!(today_from(Some(""), now).is_err());
    }

    fn scratch(test: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kurla-decisions-{}-{test}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn duplicate_key_that_would_review_a_finding_leaves_it_active_and_is_reported() {
        let e = valid_entry(FP_A, "S002", "rev");
        let dir = scratch("dup-review");
        for (name, text) in [
            (
                "last-wins.json",
                format!(r#"{{"version":1,"entries":[],"entries":[{e}]}}"#),
            ),
            (
                "first-wins.json",
                format!(r#"{{"version":1,"entries":[{e}],"entries":[]}}"#),
            ),
        ] {
            let path = write(&dir, name, &text);
            let mut findings = [finding("S002", FP_A)];
            let applied = load_and_apply(&mut findings, Some(&path), None, today());
            assert!(findings[0].review.is_none(), "{name}");
            assert_eq!(applied.rejected.len(), 1, "{name}");
            assert_eq!(applied.rejected[0].file, path.to_string_lossy(), "{name}");
            assert!(
                applied.rejected[0].message.contains("duplicate key"),
                "{}",
                applied.rejected[0].message
            );
            assert!(
                applied.rejected[0].message.contains("entries"),
                "{}",
                applied.rejected[0].message
            );
            assert!(applied.invalid.is_empty());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn duplicate_field_inside_entry_is_error() {
        let bad = valid_entry(FP_A, "S002", "rev")
            .replace(r#""rule":"S002""#, r#""rule":"X999","rule":"S002""#);
        let err = Decisions::parse(&format!(r#"{{"version":1,"entries":[{bad}]}}"#)).unwrap_err();
        assert!(err.message.contains("duplicate key"), "{}", err.message);
        assert!(err.message.contains("rule"), "{}", err.message);
    }

    #[test]
    fn duplicate_key_after_unescaping_is_error() {
        for dup in [
            r#""rule":"S002","rule":"S002""#,
            r#""rule":"S002","rule":"S002""#,
        ] {
            let bad = valid_entry(FP_A, "S002", "rev").replace(r#""rule":"S002""#, dup);
            let err =
                Decisions::parse(&format!(r#"{{"version":1,"entries":[{bad}]}}"#)).unwrap_err();
            assert!(err.message.contains("duplicate key"), "{}", err.message);
            assert!(err.message.contains("rule"), "{}", err.message);
        }
    }

    #[test]
    fn duplicate_version_is_error() {
        let err = Decisions::parse(r#"{"version":1,"version":1,"entries":[]}"#).unwrap_err();
        assert!(err.message.contains("duplicate key"), "{}", err.message);
        assert!(err.message.contains("version"), "{}", err.message);
    }

    #[test]
    fn trailing_content_after_object_is_error() {
        assert!(Decisions::parse(r#"{"version":1,"entries":[]} x"#).is_err());
        assert!(
            Decisions::parse(r#"{"version":1,"entries":[]}{"version":1,"entries":[]}"#).is_err()
        );
    }

    #[test]
    fn rejected_base_file_counts_nothing_and_is_reported() {
        let e = valid_entry(FP_A, "S002", "rev");
        let dir = scratch("rej-base");
        let current = write(
            &dir,
            "current.json",
            &format!(r#"{{"version":1,"entries":[{e}]}}"#),
        );
        let base = write(
            &dir,
            "base.json",
            &format!(r#"{{"version":1,"entries":[{e}],"entries":[{e}]}}"#),
        );
        let mut findings = [finding("S002", FP_A)];
        let applied = load_and_apply(&mut findings, Some(&current), Some(&base), today());
        let review = findings[0].review.as_ref().unwrap();
        assert!(!review.counted);
        assert_eq!(applied.rejected.len(), 1);
        assert_eq!(applied.rejected[0].file, base.to_string_lossy());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejected_current_file_reviews_nothing_even_with_valid_base() {
        let e = valid_entry(FP_A, "S002", "rev");
        let dir = scratch("rej-current");
        let current = write(&dir, "current.json", "{not json");
        let base = write(
            &dir,
            "base.json",
            &format!(r#"{{"version":1,"entries":[{e}]}}"#),
        );
        let mut findings = [finding("S002", FP_A)];
        let applied = load_and_apply(&mut findings, Some(&current), Some(&base), today());
        assert!(findings[0].review.is_none());
        assert_eq!(applied.rejected.len(), 1);
        assert_eq!(applied.rejected[0].file, current.to_string_lossy());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unreadable_file_is_rejected_not_fatal() {
        let dir = scratch("unreadable");
        let missing = dir.join("missing.json");
        let mut findings = [finding("S002", FP_A)];
        let applied = load_and_apply(&mut findings, Some(&missing), None, today());
        assert!(findings[0].review.is_none());
        assert_eq!(applied.rejected.len(), 1);
        assert!(applied.rejected[0].message.contains("cannot read"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_and_apply_with_valid_files_reviews_and_counts() {
        let e = valid_entry(FP_A, "S002", "rev");
        let dir = scratch("ok");
        let text = format!(r#"{{"version":1,"entries":[{e}]}}"#);
        let current = write(&dir, "current.json", &text);
        let base = write(&dir, "base.json", &text);
        let mut findings = [finding("S002", FP_A)];
        let applied = load_and_apply(&mut findings, Some(&current), Some(&base), today());
        assert!(findings[0].review.as_ref().unwrap().counted);
        assert!(applied.rejected.is_empty());
        assert!(applied.invalid.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_base_entry_is_reported_with_base_source() {
        let current = file(&[valid_entry(FP_A, "S002", "rev")]);
        let base = file(&[entry_json(FP_A, "S002", "old", "2026-01-01", "2026-06-01")]);
        let mut findings = [finding("S002", FP_A), finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), Some(&base), today());
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0].source, DecisionsSource::Base);
        assert_eq!(invalid[0].reason, "expired");
        assert_eq!(invalid[0].fingerprint, FP_A);
        assert!(!findings[0].review.as_ref().unwrap().counted);
    }

    #[test]
    fn invalid_base_entry_for_unreviewed_finding_is_not_reported() {
        let current = file(&[valid_entry(FP_B, "S002", "rev")]);
        let base = file(&[entry_json(FP_A, "S002", "old", "2026-01-01", "2026-06-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), Some(&base), today());
        assert!(invalid.is_empty());
    }

    #[test]
    fn invalid_current_entry_has_current_source() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2026-01-01", "2026-06-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, today());
        assert_eq!(invalid[0].source, DecisionsSource::Current);
    }

    #[test]
    fn reason_priority_too_long_beats_expired() {
        let current = file(&[entry_json(FP_A, "S002", "rev", "2024-01-01", "2025-06-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&current), None, today());
        assert_eq!(invalid[0].reason, "longer than 365 days");
    }

    #[test]
    fn clock_before_1970_is_error() {
        let err = today_from(None, UNIX_EPOCH - Duration::from_secs(1)).unwrap_err();
        assert!(err.message.contains("1970"), "{}", err.message);
    }

    #[test]
    fn leap_start_span_of_365_days_is_valid() {
        let ok = file(&[entry_json(FP_A, "S002", "rev", "2028-02-29", "2029-02-28")]);
        let long = file(&[entry_json(FP_A, "S002", "rev", "2028-02-29", "2029-03-01")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&ok), None, d(2028, 6, 1));
        assert!(findings[0].review.is_some());
        assert!(invalid.is_empty());
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&long), None, d(2028, 6, 1));
        assert!(findings[0].review.is_none());
        assert_eq!(invalid[0].reason, "longer than 365 days");
    }

    #[test]
    fn year_boundary_span_of_365_days_is_valid() {
        let ok = file(&[entry_json(FP_A, "S002", "rev", "2026-12-31", "2027-12-31")]);
        let mut findings = [finding("S002", FP_A)];
        let invalid = apply(&mut findings, Some(&ok), None, d(2027, 3, 1));
        assert!(findings[0].review.is_some());
        assert!(invalid.is_empty());
    }
}

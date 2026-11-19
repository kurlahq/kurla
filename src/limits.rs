use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub max_decompressed_bytes: u64,
    pub max_xml_depth: u32,
    pub max_xml_attributes: u32,
    pub max_base64_run_bytes: u64,
    pub max_decode_depth: u8,
    pub per_file_time: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_file_bytes: 32 * 1024 * 1024,
            max_decompressed_bytes: 32 * 1024 * 1024,
            max_xml_depth: 256,
            max_xml_attributes: 1000,
            max_base64_run_bytes: 1024 * 1024,
            max_decode_depth: 2,
            per_file_time: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitHit {
    Decompression,
    Time,
}

#[derive(Debug)]
pub struct Budget {
    limits: Limits,
    remaining_decompressed: u64,
    started: Instant,
    per_file_time: Duration,
}

impl Budget {
    pub fn new(limits: &Limits) -> Budget {
        Budget {
            limits: limits.clone(),
            remaining_decompressed: limits.max_decompressed_bytes,
            started: Instant::now(),
            per_file_time: limits.per_file_time,
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn take_decompressed(&mut self, n: u64) -> Result<(), LimitHit> {
        if n > self.remaining_decompressed {
            return Err(LimitHit::Decompression);
        }
        self.remaining_decompressed -= n;
        Ok(())
    }

    pub fn remaining_decompressed(&self) -> u64 {
        self.remaining_decompressed
    }

    pub fn deadline_exceeded(&self) -> bool {
        self.started.elapsed() >= self.per_file_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn budget_exposes_the_limits_it_was_built_from() {
        let limits = Limits {
            max_xml_depth: 7,
            max_xml_attributes: 9,
            ..Limits::default()
        };
        let budget = Budget::new(&limits);
        assert_eq!(budget.limits().max_xml_depth, 7);
        assert_eq!(budget.limits().max_xml_attributes, 9);
    }

    #[test]
    fn remaining_decompressed_tracks_what_was_taken() {
        let limits = Limits {
            max_decompressed_bytes: 10,
            ..Limits::default()
        };
        let mut budget = Budget::new(&limits);
        assert_eq!(budget.remaining_decompressed(), 10);
        assert_eq!(budget.take_decompressed(4), Ok(()));
        assert_eq!(budget.remaining_decompressed(), 6);
        assert_eq!(budget.take_decompressed(7), Err(LimitHit::Decompression));
        assert_eq!(budget.remaining_decompressed(), 6);
    }

    #[test]
    fn budget_refuses_decompression_past_limit() {
        let limits = Limits {
            max_decompressed_bytes: 10,
            ..Limits::default()
        };
        let mut budget = Budget::new(&limits);
        assert_eq!(budget.take_decompressed(6), Ok(()));
        assert_eq!(budget.take_decompressed(5), Err(LimitHit::Decompression));
    }

    #[test]
    fn budget_allows_decompression_exactly_to_limit() {
        let limits = Limits {
            max_decompressed_bytes: 10,
            ..Limits::default()
        };
        let mut budget = Budget::new(&limits);
        assert_eq!(budget.take_decompressed(10), Ok(()));
        assert_eq!(budget.take_decompressed(1), Err(LimitHit::Decompression));
    }

    #[test]
    fn budget_does_not_overflow_on_huge_requests() {
        let mut budget = Budget::new(&Limits::default());
        assert_eq!(
            budget.take_decompressed(u64::MAX),
            Err(LimitHit::Decompression)
        );
    }

    #[test]
    fn deadline_exceeded_after_zero_time_limit() {
        let limits = Limits {
            per_file_time: Duration::ZERO,
            ..Limits::default()
        };
        assert!(Budget::new(&limits).deadline_exceeded());
    }

    #[test]
    fn deadline_not_exceeded_with_very_large_time_limit() {
        let limits = Limits {
            per_file_time: Duration::from_secs(86_400),
            ..Limits::default()
        };
        assert!(!Budget::new(&limits).deadline_exceeded());
    }

    #[test]
    fn default_limits_match_specified_values() {
        let limits = Limits::default();
        assert_eq!(limits.max_file_bytes, 32 * 1024 * 1024);
        assert_eq!(limits.max_decompressed_bytes, 32 * 1024 * 1024);
        assert_eq!(limits.max_xml_depth, 256);
        assert_eq!(limits.max_xml_attributes, 1000);
        assert_eq!(limits.max_base64_run_bytes, 1024 * 1024);
        assert_eq!(limits.max_decode_depth, 2);
        assert_eq!(limits.per_file_time, Duration::from_secs(2));
    }
}

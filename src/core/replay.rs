//! Shared replay-protection and timestamp-parsing helpers used by every
//! timestamped provider. Extracted to avoid duplicating identical logic
//! across provider modules (`spec.md` §5.4).

use crate::core::error::VerifyError;
use crate::core::options::VerifyOptions;

/// Parses a timestamp header value into unix seconds.
///
/// Returns a structured [`VerifyError::MalformedHeader`] for empty, negative,
/// non-numeric, or overflowing values. The `header` parameter identifies
/// which header was malformed so callers (built-in and `Custom`) surface
/// the correct name.
pub(crate) fn parse_timestamp(header: &'static str, value: &str) -> Result<u64, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header,
            reason: "header is empty",
        });
    }

    value.parse::<u64>().map_err(|_| {
        if value.starts_with('-') || !value.bytes().all(|b| b.is_ascii_digit()) {
            VerifyError::MalformedHeader {
                header,
                reason: "timestamp is not a valid unix timestamp",
            }
        } else {
            VerifyError::MalformedHeader {
                header,
                reason: "timestamp overflows unix seconds",
            }
        }
    })
}

/// Enforces `|now - t| <= max_age` when replay protection is enabled.
///
/// Symmetric window: the timestamp is HMAC-covered, and sub-second precision
/// of "now" is truncated. Returns `Ok(())` when `max_age` is `None` (check
/// disabled). A clock before the UNIX epoch yields 0, which fail-closed
/// rejects any realistic delivery timestamp.
pub(crate) fn check_replay(timestamp: u64, options: &VerifyOptions) -> Result<(), VerifyError> {
    let Some(max_age) = options.max_age else {
        return Ok(());
    };

    // A clock before the UNIX epoch yields 0 here, which fail-closed rejects
    // any realistic delivery timestamp rather than accepting it silently.
    let now_unix = options
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // `abs_diff` avoids overflow/panic for absurd attacker-chosen values in
    // either direction.
    let skew_secs = now_unix.abs_diff(timestamp);
    if skew_secs > max_age.as_secs() {
        return Err(VerifyError::TimestampOutOfTolerance {
            skew: std::time::Duration::from_secs(skew_secs),
            max_age,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_replay, parse_timestamp};
    use crate::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::test_helpers::{FixedClock, epoch};
    use std::sync::Arc;
    use std::time::Duration;

    // --- parse_timestamp -----------------------------------------------------

    #[test]
    fn parses_valid_timestamp() {
        assert_eq!(
            parse_timestamp("X-Timestamp", "1700000000"),
            Ok(1_700_000_000)
        );
    }

    #[test]
    fn empty_timestamp_is_malformed() {
        assert_eq!(
            parse_timestamp("X-Timestamp", ""),
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "header is empty",
            })
        );
    }

    #[test]
    fn negative_timestamp_is_malformed() {
        assert_eq!(
            parse_timestamp("X-Timestamp", "-1"),
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "timestamp is not a valid unix timestamp",
            })
        );
    }

    #[test]
    fn non_numeric_timestamp_is_malformed() {
        assert_eq!(
            parse_timestamp("X-Timestamp", "not-a-number"),
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "timestamp is not a valid unix timestamp",
            })
        );
    }

    #[test]
    fn overflowing_timestamp_is_malformed() {
        assert_eq!(
            parse_timestamp("X-Timestamp", "99999999999999999999"),
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "timestamp overflows unix seconds",
            })
        );
    }

    // --- check_replay --------------------------------------------------------

    #[test]
    fn valid_timestamp_within_window() {
        let ts = 1_700_000_000u64;
        let now = epoch(ts + 100);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(check_replay(ts, &opts).is_ok());
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let ts = 1_700_000_000u64;
        let now = epoch(ts + 600);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(matches!(
            check_replay(ts, &opts),
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));
    }

    #[test]
    fn future_timestamp_is_rejected() {
        let ts = 1_700_000_000u64;
        let now = epoch(ts - 600);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(matches!(
            check_replay(ts, &opts),
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));
    }

    #[test]
    fn disabled_max_age_skips_check() {
        let ts = 1_700_000_000u64;
        let opts = VerifyOptions {
            max_age: None,
            ..VerifyOptions::default()
        };
        assert!(check_replay(ts, &opts).is_ok());
    }

    #[test]
    fn boundary_exactly_at_max_age_is_accepted() {
        let ts = 1_700_000_000u64;
        let now = epoch(ts + 300);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(check_replay(ts, &opts).is_ok());
    }
}

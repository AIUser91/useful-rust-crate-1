//! Verification options: timestamp tolerance and clock injection.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Source of "now", injectable so replay-protection tests are deterministic.
///
/// Only providers whose scheme signs a timestamp use a clock; for others
/// (GitHub, Shopify) no `Clock` is consulted.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> SystemTime;
}

/// The default [`Clock`]: real wall-clock time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Tuning knobs for [`crate::verify()`].
#[derive(Clone)]
pub struct VerifyOptions {
    /// Maximum allowed age between a signed timestamp and "now", for providers
    /// whose scheme includes a timestamp. `None` disables the check (not
    /// recommended). Default: 300 seconds, matching Stripe's and Slack's own
    /// SDK defaults.
    ///
    /// Providers that do not sign timestamps document explicitly that this
    /// option has no effect on them (see `spec.md` §3).
    pub max_age: Option<Duration>,
    /// Clock used for "now". `None` means real system time. Injectable for
    /// deterministic tests of timestamp-based providers.
    pub clock: Option<Arc<dyn Clock>>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            max_age: Some(Duration::from_secs(300)),
            clock: None,
        }
    }
}

impl VerifyOptions {
    /// Resolves "now" from the injected clock, falling back to system time.
    #[must_use]
    pub fn now(&self) -> SystemTime {
        match &self.clock {
            Some(clock) => clock.now(),
            None => SystemTime::now(),
        }
    }
}

impl fmt::Debug for VerifyOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("max_age", &self.max_age)
            .field("clock", &self.clock.as_ref().map(|_| "<injected>"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use super::{Clock, VerifyOptions};

    #[derive(Debug)]
    struct FixedClock(SystemTime);

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    #[test]
    fn default_is_five_minutes_without_injected_clock() {
        let opts = VerifyOptions::default();
        assert_eq!(opts.max_age, Some(Duration::from_secs(300)));
        assert!(opts.clock.is_none());
    }

    #[test]
    fn injected_clock_is_used_for_now() {
        let fixed = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(fixed))),
        };
        assert_eq!(opts.now(), fixed);
    }
}

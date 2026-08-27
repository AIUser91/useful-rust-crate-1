//! Shared test helpers: a deterministic clock and options for exercising
//! timestamp-based (replay-protected) providers.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::core::options::{Clock, VerifyOptions};

/// A [`Clock`] pinned to a fixed instant.
#[derive(Debug)]
pub struct FixedClock(pub SystemTime);

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// The [`SystemTime`] `secs` seconds after the Unix epoch.
pub fn epoch(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// Options pinning "now" to [`epoch`]`(secs)` for deterministic tests.
pub fn clocked_at(secs: u64, max_age: Option<Duration>) -> VerifyOptions {
    VerifyOptions {
        max_age,
        clock: Some(Arc::new(FixedClock(epoch(secs)))),
        request_url: None,
        form_params: None,
    }
}

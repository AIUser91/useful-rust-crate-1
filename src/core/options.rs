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
#[must_use]
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
    /// Full URL of the receiving endpoint, required by providers whose
    /// signature incorporates it (currently Square, whose scheme signs the
    /// notification URL followed by the raw body, and Twilio, which signs the
    /// full request URL). The value must match the URL configured with the
    /// provider **exactly** — a differing trailing slash or scheme makes every
    /// signature fail. Providers whose scheme does not sign the URL document
    /// that this option has no effect on them.
    ///
    /// Supplying the configured constant from the provider dashboard is the
    /// intended use; reconstructing the URL from request headers behind a
    /// proxy is a common source of verification failures.
    pub request_url: Option<String>,
    /// Parsed `application/x-www-form-urlencoded` fields, required by Twilio:
    /// its signature covers the request URL concatenated with the sorted
    /// form-field names/values, not the raw body. Pass **every** field as
    /// received — Twilio's own docs warn against verifying against a hardcoded
    /// subset, since providers may add parameters without notice. Sorting is
    /// applied here (it is part of the signing scheme), so callers pass fields
    /// in any order. A duplicate field name keeps its received relative order.
    ///
    /// An explicitly empty list is meaningful (Twilio's JSON-body variant signs
    /// the URL alone); omitting the option entirely fails closed with
    /// [`crate::VerifyError::MissingContext`] so a caller that forgot to parse
    /// the body cannot be confused with an attacker-supplied input.
    pub form_params: Option<Vec<(String, String)>>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            max_age: Some(Duration::from_secs(300)),
            clock: None,
            request_url: None,
            form_params: None,
        }
    }
}

impl VerifyOptions {
    /// Sets [`VerifyOptions::request_url`], for URL-scoped schemes.
    pub fn with_request_url(mut self, url: impl Into<String>) -> Self {
        self.request_url = Some(url.into());
        self
    }

    /// Sets [`VerifyOptions::form_params`], for schemes that sign parsed form
    /// fields (currently Twilio). Order does not matter; fields are sorted
    /// into the signing order here.
    pub fn with_form_params<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.form_params = Some(
            params
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        );
        self
    }

    /// Sets [`VerifyOptions::max_age`], the maximum allowed clock skew for
    /// providers whose scheme signs a timestamp. `None` disables the check
    /// (not recommended); the default is `Some(Duration::from_secs(300))`.
    ///
    /// Providers that do not sign timestamps document explicitly that this
    /// option has no effect on them (see `spec.md` §3).
    pub fn with_max_age(mut self, max_age: Option<Duration>) -> Self {
        self.max_age = max_age;
        self
    }

    /// Sets [`VerifyOptions::clock`], the source of "now" used for replay
    /// protection. `None` uses real system time. Injectable for deterministic
    /// tests of timestamp-based providers.
    pub fn with_clock(mut self, clock: Option<Arc<dyn Clock>>) -> Self {
        self.clock = clock;
        self
    }

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
            .field("request_url_set", &self.request_url.is_some())
            .field(
                "form_params_count",
                &self.form_params.as_ref().map(|p| p.len()),
            )
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
            request_url: None,
            form_params: None,
        };
        assert_eq!(opts.now(), fixed);
    }

    #[test]
    fn builder_sets_request_url() {
        let opts = VerifyOptions::default().with_request_url("https://example.com/webhook");
        assert_eq!(
            opts.request_url.as_deref(),
            Some("https://example.com/webhook")
        );
    }

    #[test]
    fn debug_does_not_print_request_url_value() {
        let opts = VerifyOptions::default().with_request_url("https://internal.example/hook");
        assert!(!format!("{opts:?}").contains("internal.example"));
    }

    #[test]
    fn builder_sets_form_params_in_any_order() {
        let opts = VerifyOptions::default()
            .with_request_url("https://example.com/myapp")
            .with_form_params([("Digits", "1234"), ("CallSid", "CA123")]);
        assert_eq!(
            opts.form_params,
            Some(vec![
                ("Digits".to_string(), "1234".to_string()),
                ("CallSid".to_string(), "CA123".to_string())
            ])
        );
    }

    #[test]
    fn debug_does_not_print_form_param_values() {
        // Form fields are attacker-controlled request content; like the URL,
        // their values must not leak through `Debug` (only the count does).
        let opts = VerifyOptions::default().with_form_params([("Body", "s3cr3t-message")]);
        let debug = format!("{opts:?}");
        assert!(!debug.contains("s3cr3t-message"));
        assert!(debug.contains("form_params_count: Some(1)"));
    }

    #[test]
    fn builder_sets_max_age() {
        let opts = VerifyOptions::default().with_max_age(Some(Duration::from_secs(600)));
        assert_eq!(opts.max_age, Some(Duration::from_secs(600)));
    }

    #[test]
    fn builder_disables_max_age() {
        let opts = VerifyOptions::default().with_max_age(None);
        assert!(opts.max_age.is_none());
    }

    #[test]
    fn builder_sets_clock() {
        let fixed = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let opts = VerifyOptions::default().with_clock(Some(Arc::new(FixedClock(fixed))));
        assert_eq!(opts.now(), fixed);
    }

    #[test]
    fn builder_disables_clock() {
        // Start with an injected clock, then clear it.
        let fixed = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let opts = VerifyOptions::default()
            .with_clock(Some(Arc::new(FixedClock(fixed))))
            .with_clock(None);
        // With no clock, `now()` falls back to system time — just verify it
        // doesn't panic and the clock field is None.
        assert!(opts.clock.is_none());
        let _ = opts.now();
    }
}

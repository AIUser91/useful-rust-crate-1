//! Provider-specific signing schemes and the [`verify`] dispatch.
//!
//! Each provider lives in its own module implementing exactly the scheme
//! documented in `spec.md` §3, backed by that provider's official test
//! vectors. Providers without an implementation yet fail closed with
//! [`VerifyError::UnsupportedProvider`].

mod github;
mod linear;
mod shopify;
mod slack;
mod standard_webhooks;
mod stripe;

use crate::core::VerifyOptions;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// A webhook provider whose signature scheme this crate knows how to verify.
///
/// Variants for providers that do not have an implementation yet are still
/// listed so the API surface matches `spec.md` §2 and stays additive as
/// providers ship; calling [`verify()`] with one returns
/// [`VerifyError::UnsupportedProvider`] (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    /// Stripe (`Stripe-Signature`, HMAC-SHA256 over `t.body`).
    Stripe,
    /// GitHub (`X-Hub-Signature-256`, HMAC-SHA256 over the raw body).
    GitHub,
    /// Shopify (`X-Shopify-Hmac-SHA256`, base64-encoded HMAC-SHA256).
    Shopify,
    /// Slack (`X-Slack-Signature`, `v0=` scheme with timestamp).
    Slack,
    /// Square (HMAC-SHA256 over notification URL + body, hex-decoded key).
    Square,
    /// Twilio (HMAC-SHA1 over full URL + sorted form params).
    Twilio,
    /// Discord (Ed25519 public-key signatures; `Secret` holds a public key).
    Discord,
    /// PayPal (certificate-based; see `spec.md` §7 open questions).
    PayPal,
    /// SendGrid (ECDSA; see `spec.md` §7 open questions).
    SendGrid,
    /// Linear (`linear-signature`, HMAC-SHA256).
    Linear,
    /// Zoom (`X-Zm-Signature`, HMAC-SHA256 with timestamp).
    Zoom,
    /// Dropbox (`X-Dropbox-Signature`, HMAC-SHA256 over URL + body).
    Dropbox,
    /// Standard Webhooks spec (`webhook-*` headers; Svix, Clerk, Resend, ...).
    StandardWebhooks,
}

/// Verifies that a webhook request was sent by `provider` and was not tampered
/// with in transit.
///
/// * `headers` — request headers via [`HeaderMap`] (any framework's map works).
/// * `raw_body` — the **exact bytes** received. Never re-serialize or
///   re-encode the body before calling this.
/// * `secret` — the shared secret configured with the provider. For asymmetric
///   schemes (Discord) it holds the public key instead; each provider's docs
///   state which applies.
/// * `options` — tolerance/clock knobs; see [`VerifyOptions`].
///
/// Errors are structured ([`VerifyError`]) and never contain secret material.
pub fn verify(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: VerifyOptions,
) -> Result<(), VerifyError> {
    match provider {
        Provider::GitHub => github::verify(headers, raw_body, secret, &options),
        Provider::Linear => linear::verify(headers, raw_body, secret, &options),
        Provider::Shopify => shopify::verify(headers, raw_body, secret, &options),
        Provider::Slack => slack::verify(headers, raw_body, secret, &options),
        Provider::Stripe => stripe::verify(headers, raw_body, secret, &options),
        Provider::StandardWebhooks => {
            standard_webhooks::verify(headers, raw_body, secret, &options)
        }
        Provider::Square
        | Provider::Twilio
        | Provider::Discord
        | Provider::PayPal
        | Provider::SendGrid
        | Provider::Zoom
        | Provider::Dropbox => Err(VerifyError::UnsupportedProvider),
    }
}

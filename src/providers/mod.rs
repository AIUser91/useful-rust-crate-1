//! Provider-specific signing schemes and the [`verify`] dispatch.
//!
//! Each provider lives in its own module implementing exactly the scheme
//! documented in `spec.md` §3, backed by that provider's official test
//! vectors. Providers without an implementation yet fail closed with
//! [`VerifyError::UnsupportedProvider`].

mod custom;
mod discord;
mod dropbox;
mod github;
mod linear;
mod shopify;
mod slack;
mod square;
mod standard_webhooks;
mod stripe;
mod twilio;
mod zoom;

pub use custom::{CustomScheme, Encoding, HashAlg};

use std::fmt;

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
#[must_use]
#[non_exhaustive]
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
    /// Square (HMAC-SHA256 over notification URL + body, base64).
    Square,
    /// Twilio (HMAC-SHA1 over full URL + sorted form params; needs
    /// `VerifyOptions::request_url` and `VerifyOptions::form_params`).
    Twilio,
    /// Discord (Ed25519 public-key signatures; `Secret` holds a public key).
    ///
    /// Unlike the shared-secret schemes, verification here proves the payload
    /// was signed with the private key corresponding to the *public* key in
    /// [`crate::Secret`] — see the provider module's security-model notes.
    Discord,
    /// PayPal (certificate-based; see `spec.md` §7 open questions).
    PayPal,
    /// SendGrid (ECDSA; see `spec.md` §7 open questions).
    SendGrid,
    /// Linear (`linear-signature`, HMAC-SHA256).
    Linear,
    /// Zoom (`X-Zm-Signature`, HMAC-SHA256 with timestamp).
    Zoom,
    /// Dropbox (`X-Dropbox-Signature`, HMAC-SHA256 over the raw body).
    Dropbox,
    /// Standard Webhooks spec (`webhook-*` headers; Svix, Clerk, Resend, ...).
    StandardWebhooks,
    /// A caller-configured HMAC scheme (`spec.md` §2.2): covers long-tail
    /// providers and internal senders without waiting on a crate release,
    /// with the same constant-time and fail-closed guarantees as the
    /// built-ins. See [`CustomScheme`].
    Custom(CustomScheme),
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Provider::Stripe => f.write_str("Stripe"),
            Provider::GitHub => f.write_str("GitHub"),
            Provider::Shopify => f.write_str("Shopify"),
            Provider::Slack => f.write_str("Slack"),
            Provider::Square => f.write_str("Square"),
            Provider::Twilio => f.write_str("Twilio"),
            Provider::Discord => f.write_str("Discord"),
            Provider::PayPal => f.write_str("PayPal"),
            Provider::SendGrid => f.write_str("SendGrid"),
            Provider::Linear => f.write_str("Linear"),
            Provider::Zoom => f.write_str("Zoom"),
            Provider::Dropbox => f.write_str("Dropbox"),
            Provider::StandardWebhooks => f.write_str("StandardWebhooks"),
            Provider::Custom(scheme) => {
                write!(f, "Custom({})", scheme.signature_header)
            }
        }
    }
}

/// Header names that carry signing material for `provider`, per its row in
/// `spec.md` §3.
///
/// Used by framework adapters (behind the `tower`/`actix` features) to reject
/// requests whose signature headers arrive duplicated with conflicting values
/// — see the ambiguity contract on [`crate::HeaderMap`] and `spec.md` §4.4,
/// which the first-match-only lookup cannot detect on its own.
///
/// Returns an empty list for providers that are not implemented yet; their
/// verification fails closed with [`VerifyError::UnsupportedProvider`]
/// regardless.
#[cfg(any(feature = "tower", feature = "actix"))]
pub(crate) fn signature_header_names(provider: &Provider) -> Vec<&'static str> {
    match provider {
        Provider::Stripe => vec![stripe::SIGNATURE_HEADER],
        Provider::GitHub => vec![github::SIGNATURE_HEADER],
        Provider::Shopify => vec![shopify::SIGNATURE_HEADER],
        Provider::Slack => vec![slack::SIGNATURE_HEADER, slack::TIMESTAMP_HEADER],
        Provider::Square => vec![square::SIGNATURE_HEADER],
        Provider::Twilio => vec![twilio::SIGNATURE_HEADER],
        Provider::Discord => {
            vec![discord::SIGNATURE_HEADER, discord::TIMESTAMP_HEADER]
        }
        Provider::Linear => vec![linear::SIGNATURE_HEADER],
        Provider::Dropbox => vec![dropbox::SIGNATURE_HEADER],
        Provider::Zoom => vec![zoom::SIGNATURE_HEADER, zoom::TIMESTAMP_HEADER],
        Provider::StandardWebhooks => vec![
            standard_webhooks::ID_HEADER,
            standard_webhooks::TIMESTAMP_HEADER,
            standard_webhooks::SIGNATURE_HEADER,
        ],
        Provider::Custom(scheme) => {
            let mut names = vec![scheme.signature_header];
            if let Some(timestamp) = scheme.timestamp_header {
                names.push(timestamp);
            }
            names
        }
        Provider::PayPal | Provider::SendGrid => Vec::new(),
    }
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
///
/// # Errors
///
/// Returns [`VerifyError::MissingHeader`] when a required signature header is
/// absent, [`VerifyError::MalformedHeader`] when a header is present but
/// unparseable, and [`VerifyError::BadEncoding`] when a hex or base64 value
/// fails to decode. [`VerifyError::SignatureMismatch`] is returned when the
/// decoded signature does not match the expected value. Providers with
/// timestamp-based replay protection return
/// [`VerifyError::TimestampOutOfTolerance`] when the signed timestamp is too
/// old. [`VerifyError::UnsupportedProvider`] is returned for providers that
/// have no implementation yet (PayPal, SendGrid). [`VerifyError::InvalidSecret`]
/// is returned when the secret is not in the format the provider requires.
/// [`VerifyError::MissingContext`] is returned when provider-specific request
/// context (e.g. Square's notification URL) was not supplied via
/// [`VerifyOptions`].
pub fn verify(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: VerifyOptions,
) -> Result<(), VerifyError> {
    match provider {
        Provider::Discord => discord::verify(headers, raw_body, secret, &options),
        Provider::GitHub => github::verify(headers, raw_body, secret, &options),
        Provider::Linear => linear::verify(headers, raw_body, secret, &options),
        Provider::Zoom => zoom::verify(headers, raw_body, secret, &options),
        Provider::Shopify => shopify::verify(headers, raw_body, secret, &options),
        Provider::Slack => slack::verify(headers, raw_body, secret, &options),
        Provider::Square => square::verify(headers, raw_body, secret, &options),
        Provider::Stripe => stripe::verify(headers, raw_body, secret, &options),
        Provider::StandardWebhooks => {
            standard_webhooks::verify(headers, raw_body, secret, &options)
        }
        Provider::Twilio => twilio::verify(headers, raw_body, secret, &options),
        Provider::Dropbox => dropbox::verify(headers, raw_body, secret, &options),
        Provider::Custom(scheme) => custom::verify(&scheme, headers, raw_body, secret, &options),
        Provider::PayPal | Provider::SendGrid => Err(VerifyError::UnsupportedProvider),
    }
}

/// Tries multiple secrets during a zero-downtime rotation window.
///
/// Stripe and Standard Webhooks allow multiple valid signatures during secret
/// rotation (e.g. `v1=...,v1=...`). This function accepts a slice of
/// [`Secret`]s — each representing an active signing key — and returns
/// `Ok(())` if *any* of them verifies. On total failure it returns
/// `Err(VerifyError::SignatureMismatch)` regardless of *which* secrets
/// failed or why (no timing leak about which key was closest).
///
/// For providers whose signing scheme itself embeds multiple signatures
/// (Stripe's `v1=` list, Standard Webhooks' space-delimited `v1,<sig>`
/// list), prefer [`verify()`] with a single secret — the per-provider
/// multi-sig logic already accepts any matching element. `verify_any` is
/// for the *separate* case where the provider's config allows *multiple
/// distinct keys* to be valid simultaneously (e.g. during key rotation).
///
/// # Empty slice
///
/// Passing an empty `secrets` slice returns `SignatureMismatch` immediately
/// — there is nothing to try and no attacker-controlled input to parse.
///
/// # Example
///
/// ```no_run
/// use webhook_verify::{verify_any, HeaderMap, Provider, Secret};
///
/// # let headers: Vec<(String, String)> = vec![];
/// # let raw_body: &[u8] = b"";
/// // During rotation, both the old and new keys are valid.
/// let secrets = [
///     Secret::new("whsec_old_key_being_rotated_out"),
///     Secret::new("whsec_new_key_being_rotated_in"),
/// ];
///
/// let result = verify_any(
///     Provider::Stripe,
///     &headers,
///     raw_body,
///     &secrets,
///     Default::default(),
/// );
/// ```
///
/// # Errors
///
/// Structural errors ([`VerifyError::MissingHeader`],
/// [`VerifyError::MalformedHeader`], [`VerifyError::BadEncoding`],
/// [`VerifyError::UnsupportedProvider`], [`VerifyError::InvalidSecret`],
/// [`VerifyError::MissingContext`]) are returned immediately regardless of
/// how many secrets remain, because they are deterministic across all
/// secrets. [`VerifyError::TimestampOutOfTolerance`] is also returned
/// immediately when encountered, since the timestamp is secret-independent.
/// [`VerifyError::SignatureMismatch`] is returned only after *all* secrets
/// have been tried without a match, to avoid leaking information about
/// which key was closest via timing differences.
pub fn verify_any(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secrets: &[Secret],
    options: VerifyOptions,
) -> Result<(), VerifyError> {
    for secret in secrets {
        match verify(provider, headers, raw_body, secret, options.clone()) {
            // A match on any active key is enough during rotation.
            Ok(()) => return Ok(()),
            // Keep trying the remaining keys when one simply doesn't match.
            Err(VerifyError::SignatureMismatch) => {}
            Err(other) => {
                // Structural errors (MissingHeader, MalformedHeader,
                // BadEncoding, etc.) are deterministic across all secrets —
                // the error occurs before any secret-dependent work. Return
                // it immediately so callers can distinguish a malformed
                // request from a forged signature.
                return Err(other);
            }
        }
    }
    // All secrets exhausted with SignatureMismatch: return the same error
    // regardless of how many were tried, to avoid leaking information
    // about which key was "closest" via timing differences.
    Err(VerifyError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::secret::Secret;

    /// GitHub's documented example vector
    /// (<https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>).
    const GITHUB_SECRET: &str = "It's a Secret to Everybody";
    const GITHUB_BODY: &[u8] = b"Hello, World!";
    const GITHUB_SIGNATURE: &str =
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    fn github_headers() -> Vec<(String, String)> {
        vec![(
            "X-Hub-Signature-256".to_string(),
            GITHUB_SIGNATURE.to_string(),
        )]
    }

    #[test]
    fn verify_any_accepts_first_matching_secret() {
        // First verify that verify() itself works.
        let direct = super::verify(
            Provider::GitHub,
            &github_headers(),
            GITHUB_BODY,
            &Secret::new(GITHUB_SECRET),
            Default::default(),
        );
        assert_eq!(direct, Ok(()), "direct verify: {direct:?}");

        let secrets = [
            Secret::new("wrong-key"),
            Secret::new(GITHUB_SECRET),
            Secret::new("another-wrong-key"),
        ];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &github_headers(),
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn verify_any_accepts_single_secret() {
        let secrets = [Secret::new(GITHUB_SECRET)];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &github_headers(),
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn verify_any_rejects_when_no_secret_matches() {
        let secrets = [Secret::new("wrong-1"), Secret::new("wrong-2")];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &github_headers(),
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_any_rejects_empty_slice() {
        let secrets: [Secret; 0] = [];
        let headers: Vec<(String, String)> = github_headers().to_vec();
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &headers,
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_any_fails_closed_on_malformed_input() {
        // Missing header — error comes from parsing, not the secret check.
        let secrets = [Secret::new(GITHUB_SECRET)];
        let empty_headers: Vec<(String, String)> = vec![];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &empty_headers,
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Err(VerifyError::MissingHeader {
                header: "X-Hub-Signature-256"
            })
        );
    }

    #[test]
    fn verify_any_non_first_secret_matches() {
        // Only the second key is correct; first is wrong.
        let secrets = [Secret::new("bad"), Secret::new(GITHUB_SECRET)];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &github_headers(),
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn provider_display_names() {
        use super::CustomScheme;
        use crate::{Encoding, HashAlg};

        assert_eq!(Provider::Stripe.to_string(), "Stripe");
        assert_eq!(Provider::GitHub.to_string(), "GitHub");
        assert_eq!(Provider::Shopify.to_string(), "Shopify");
        assert_eq!(Provider::Slack.to_string(), "Slack");
        assert_eq!(Provider::Square.to_string(), "Square");
        assert_eq!(Provider::Twilio.to_string(), "Twilio");
        assert_eq!(Provider::Discord.to_string(), "Discord");
        assert_eq!(Provider::PayPal.to_string(), "PayPal");
        assert_eq!(Provider::SendGrid.to_string(), "SendGrid");
        assert_eq!(Provider::Linear.to_string(), "Linear");
        assert_eq!(Provider::Zoom.to_string(), "Zoom");
        assert_eq!(Provider::Dropbox.to_string(), "Dropbox");
        assert_eq!(Provider::StandardWebhooks.to_string(), "StandardWebhooks");

        let custom = Provider::Custom(CustomScheme {
            hash: HashAlg::Sha256,
            signature_header: "X-My-Sig",
            timestamp_header: None,
            encoding: Encoding::Hex,
            prefix: None,
            signed_string: |_h, b| b.to_vec(),
        });
        assert_eq!(custom.to_string(), "Custom(X-My-Sig)");
    }
}

//! Shared utilities for framework adapters (tower, actix).
//!
//! This module is only compiled when an adapter feature is enabled. It holds
//! logic that the adapters share so it cannot drift as new [`VerifyError`]
//! variants are added.

use super::VerifyError;

/// Maps a verification outcome to its rejection HTTP status code.
///
/// Returns the raw numeric status (400/401/500) rather than a framework's
/// `StatusCode` type because the tower adapter uses `http` 1.x while
/// actix-web 4 uses `http` 0.2 — two distinct types. Each adapter converts the
/// number to its own `StatusCode`, so the classification logic (and its
/// exhaustive match over the in-crate enum) lives in exactly one place.
///
/// | Class | Status | Rationale |
/// |---|---|---|
/// | `MissingHeader`, `MalformedHeader`, `BadEncoding` | `400` | Malformed request |
/// | `SignatureMismatch`, `TimestampOutOfTolerance` | `401` | Auth signal |
/// | `UnsupportedProvider`, `InvalidSecret`, `MissingContext` | `500` | Operator misconfiguration |
///
/// Adding a `VerifyError` variant will surface here at compile time so its
/// status class is chosen deliberately.
pub(crate) fn rejection_status(error: &VerifyError) -> u16 {
    match error {
        // Malformed request: missing/unparseable signature headers.
        VerifyError::MissingHeader { .. }
        | VerifyError::MalformedHeader { .. }
        | VerifyError::BadEncoding { .. } => 400,

        // Authentication signals: wrong signature or stale timestamp.
        VerifyError::SignatureMismatch | VerifyError::TimestampOutOfTolerance { .. } => 401,

        // Operator misconfiguration: unsupported/broken configuration, never
        // the requester's fault. Still rejected — fail closed.
        VerifyError::UnsupportedProvider
        | VerifyError::InvalidSecret { .. }
        | VerifyError::MissingContext { .. } => 500,
    }
}

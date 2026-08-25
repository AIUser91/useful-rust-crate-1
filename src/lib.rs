//! # webhook-verify
//!
//! One function to verify inbound webhook signatures from major providers.
//!
//! Every backend that accepts webhooks ends up hand-rolling HMAC verification,
//! and getting subtle details wrong: re-serialized bodies instead of raw bytes,
//! non-constant-time comparison, missing replay protection, provider-specific
//! encoding quirks. This crate does it once, correctly, behind a single API.
//!
//! ## Example: verifying a GitHub delivery
//!
//! ```no_run
//! use webhook_verify::{verify, HeaderMap, Provider, Secret};
//!
//! let headers: Vec<(String, String)> = vec![(
//!     "X-Hub-Signature-256".to_string(),
//!     "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17".to_string(),
//! )];
//! let raw_body = b"Hello, World!";
//!
//! let result = verify(
//!     Provider::GitHub,
//!     &headers,
//!     raw_body,
//!     &Secret::new("It's a Secret to Everybody"),
//!     Default::default(),
//! );
//!
//! assert!(result.is_ok());
//! ```
//!
//! `raw_body` **must** be the exact bytes the provider sent — before any JSON
//! parsing or re-serialization. Verification against anything else will fail.
//!
//! ## Security properties
//!
//! - All signature comparisons are constant-time ([`subtle::ConstantTimeEq`]).
//! - Bodies are hashed exactly as received; never re-encoded.
//! - No secret material ever appears in errors, `Debug`, or `Display` output.
//! - Parsing paths return [`VerifyError`] instead of panicking on
//!   attacker-controlled input.
//!
//! [`subtle::ConstantTimeEq`]: https://docs.rs/subtle/latest/subtle/trait.ConstantTimeEq.html

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

mod core;
mod providers;

#[cfg(feature = "actix")]
pub mod actix;

#[cfg(feature = "tower")]
pub mod tower;

pub use crate::core::{Clock, HeaderMap, Secret, SystemClock, VerifyError, VerifyOptions};
pub use crate::providers::{CustomScheme, Encoding, HashAlg, Provider, verify};

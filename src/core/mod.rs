//! Core verification machinery shared by every provider: the error type, the
//! secret wrapper, the header abstraction, verification options, and the
//! audited crypto helpers.
//!
//! Changes here affect every provider and are treated as high-risk; see
//! `spec.md` §2 for the normative contract.

pub(crate) mod crypto;
pub(crate) mod error;
pub(crate) mod headers;
pub(crate) mod options;
pub(crate) mod secret;

pub use error::VerifyError;
pub use headers::HeaderMap;
pub use options::{Clock, SystemClock, VerifyOptions};
pub use secret::Secret;

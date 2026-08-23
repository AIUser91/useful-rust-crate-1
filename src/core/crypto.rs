//! Audited crypto helpers.
//!
//! All HMAC construction and all constant-time comparison live here so the
//! security guarantees are implemented once (`spec.md` §4). Providers must not
//! call `hmac`/`sha2`/`subtle` directly; they call these helpers.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Verifies `provided_signature` against HMAC-SHA256(`key`, `signed_string`)
/// using a constant-time comparison.
///
/// Fails closed: if key construction fails (cannot happen for HMAC, which
/// accepts arbitrary-length keys, but the API returns `Result`) this returns
/// `false`. Signature length mismatches also simply compare unequal in
/// constant time — length is public information, so branching on it leaks
/// nothing secret.
pub(crate) fn verify_hmac_sha256(
    key: &[u8],
    signed_string: &[u8],
    provided_signature: &[u8],
) -> bool {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(signed_string);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(provided_signature).into()
}

#[cfg(test)]
mod tests {
    use super::verify_hmac_sha256;

    /// Decodes a hardcoded vector; keeps the crate-wide
    /// `clippy::unwrap_used`/`expect_used` denials intact in tests too.
    fn decode(vector: &str) -> Vec<u8> {
        match hex::decode(vector) {
            Ok(bytes) => bytes,
            Err(_) => panic!("hardcoded test vectors must be valid hex"),
        }
    }

    #[test]
    fn matches_known_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let sig = decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert!(verify_hmac_sha256(key, data, &sig));
    }

    #[test]
    fn rejects_tampered_and_wrong_length() {
        let sig = decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        let mut flipped = sig.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_hmac_sha256(
            b"Jefe",
            b"what do ya want for nothing?",
            &flipped
        ));
        assert!(!verify_hmac_sha256(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig[..31]
        ));
        assert!(!verify_hmac_sha256(
            b"wrong key",
            b"what do ya want for nothing?",
            &sig
        ));
    }
}

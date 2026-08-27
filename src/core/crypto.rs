//! Audited crypto helpers.
//!
//! All HMAC construction and all constant-time comparison live here so the
//! security guarantees are implemented once (`spec.md` §4). Providers must not
//! call `hmac`/`sha2`/`sha1`/`subtle` directly; they call these helpers.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;
type HmacSha512 = Hmac<Sha512>;

/// Ed25519 public-key length in bytes (compressed Edwards point).
const ED25519_KEY_LEN: usize = 32;

/// Ed25519 signature length in bytes (`R` || `S`).
const ED25519_SIG_LEN: usize = 64;

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

/// Verifies `provided_signature` against HMAC-SHA1(`key`, `signed_string`)
/// using a constant-time comparison.
///
/// Same guarantees as [`verify_hmac_sha256`]. Used by Twilio's scheme, which
/// mandates HMAC-SHA1 (`spec.md` §3); Twilio's own docs note HMAC is not
/// affected by SHA-1's collision attacks given a secret key.
pub(crate) fn verify_hmac_sha1(
    key: &[u8],
    signed_string: &[u8],
    provided_signature: &[u8],
) -> bool {
    let mut mac = match HmacSha1::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(signed_string);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(provided_signature).into()
}

/// Verifies `provided_signature` against HMAC-SHA512(`key`, `signed_string`)
/// using a constant-time comparison.
///
/// Same guarantees as [`verify_hmac_sha256`]. Used by [`crate::CustomScheme`]
/// (`spec.md` §2.2), whose `HashAlg::Sha512` option covers long-tail senders
/// standardizing on SHA-512 HMACs.
pub(crate) fn verify_hmac_sha512(
    key: &[u8],
    signed_string: &[u8],
    provided_signature: &[u8],
) -> bool {
    let mut mac = match HmacSha512::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(signed_string);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(provided_signature).into()
}

/// Verifies an Ed25519 `signature` over `message` against a 32-byte
/// compressed Edwards public key.
///
/// Used for asymmetric schemes (Discord) where the [`Secret`](crate::Secret)
/// holds a *public* key. Fails closed: malformed keys/signatures (wrong
/// length, undecodable point, non-canonical `S`) verify as `false` rather
/// than erroring; callers that need to distinguish operator misconfiguration
/// (bad configured key) from forged input decode/length-check their inputs
/// before calling this.
///
/// Curve arithmetic inside `ed25519-dalek` is constant-time with respect to
/// secret-dependent data; signature bytes and messages are public inputs by
/// construction of the scheme.
pub(crate) fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key_bytes = match <[u8; ED25519_KEY_LEN]>::try_from(public_key) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        // A public key that fails point decompression is malformed
        // configuration; treat it like any other unusable key.
        Err(_) => return false,
    };
    if signature.len() != ED25519_SIG_LEN {
        // Length is public information; branching on it leaks nothing secret.
        return false;
    }
    match Signature::from_slice(signature) {
        Ok(sig) => verifying_key.verify(message, &sig).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{verify_ed25519, verify_hmac_sha1, verify_hmac_sha256, verify_hmac_sha512};

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
    fn hmac_sha1_matches_rfc2202_vector() {
        // RFC 2202 test case 2: key "Jefe", data "what do ya want for nothing?"
        let sig = decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        assert!(verify_hmac_sha1(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig
        ));
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

    #[test]
    fn hmac_sha1_rejects_tampered_and_wrong_length() {
        let sig = decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        let mut flipped = sig.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_hmac_sha1(
            b"Jefe",
            b"what do ya want for nothing?",
            &flipped
        ));
        assert!(!verify_hmac_sha1(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig[..19]
        ));
    }

    #[test]
    fn hmac_sha512_matches_rfc4231_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let sig = decode(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        );
        assert!(verify_hmac_sha512(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig
        ));
    }

    #[test]
    fn hmac_sha512_rejects_tampered_and_wrong_length() {
        let sig = decode(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        );
        let mut flipped = sig.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_hmac_sha512(
            b"Jefe",
            b"what do ya want for nothing?",
            &flipped
        ));
        assert!(!verify_hmac_sha512(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig[..63]
        ));
    }

    /// Deterministically derives an Ed25519 keypair from `seed` and signs
    /// `message`; used to build local test vectors without pulling in a RNG.
    fn sign_with_seed(seed: [u8; 32], message: &[u8]) -> ([u8; 32], Vec<u8>) {
        use ed25519_dalek::Signer;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(message);
        (*verifying_key.as_bytes(), sig.to_bytes().to_vec())
    }

    #[test]
    fn ed25519_verifies_genuine_signature() {
        let (public_key, signature) = sign_with_seed([7u8; 32], b"hello");
        assert!(verify_ed25519(&public_key, b"hello", &signature));
    }

    #[test]
    fn ed25519_rejects_tampered_malformed_and_wrong_key() {
        let (public_key, signature) = sign_with_seed([7u8; 32], b"hello");

        // Tampered message.
        assert!(!verify_ed25519(&public_key, b"hellO", &signature));

        // Tampered signature byte.
        let mut flipped = signature.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_ed25519(&public_key, b"hello", &flipped));

        // Wrong length signature (63/65 bytes).
        assert!(!verify_ed25519(&public_key, b"hello", &signature[..63]));
        let mut padded = signature.clone();
        padded.push(0);
        assert!(!verify_ed25519(&public_key, b"hello", &padded));

        // Wrong-length public key.
        assert!(!verify_ed25519(&public_key[..31], b"hello", &signature));

        // Non-canonical / non-decodable public key (all-ones is not a valid
        // compressed point encoding).
        let bad_point = [0xffu8; 32];
        assert!(!verify_ed25519(&bad_point, b"hello", &signature));

        // Different key entirely.
        let (other_key, _) = sign_with_seed([8u8; 32], b"hello");
        assert!(!verify_ed25519(&other_key, b"hello", &signature));

        // Empty inputs fail closed instead of panicking.
        assert!(!verify_ed25519(b"", b"hello", &signature));
        assert!(!verify_ed25519(&public_key, b"", &[]));
    }
}

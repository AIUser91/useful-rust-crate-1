# webhook-verify — Technical Specification

Status: draft v0.1
Audience: contributors and implementers (human or AI agent)

This document defines the contract the crate must satisfy: the public API,
the per-provider signing schemes, error semantics, security requirements,
and the testing bar every provider implementation must clear before merge.

---

## 1. Goals and non-goals

**Goals**

- Verify that an inbound HTTP request genuinely originated from a given
  webhook provider and was not tampered with in transit.
- Provide one consistent API across all supported providers.
- Be correct by construction: every provider backed by vendor-sourced test
  vectors, constant-time comparison, and (where applicable) replay
  protection.
- Be embeddable: no required async runtime, no required web framework, no
  network calls, `no_std + alloc` compatible for the core verification path
  where the underlying crypto crates allow it.

**Non-goals**

- Parsing/deserializing the webhook event payload into typed structs.
- Registering, sending, or replaying webhooks.
- Idempotency / deduplication of events (a signature-verified request can
  still be a legitimate retry — that's a separate concern).
- Acting as a proxy, gateway, or hosted service.

---

## 2. Core API

```rust
pub enum Provider {
    Stripe,
    GitHub,
    Shopify,
    Slack,
    Square,
    Twilio,
    Discord,
    PayPal,
    SendGrid,
    Linear,
    Zoom,
    Dropbox,
    StandardWebhooks,
    Custom(CustomScheme),
}

pub struct Secret(/* redacted */);
impl Secret {
    pub fn new(value: impl Into<String>) -> Self;
}
// Debug/Display for Secret print "Secret(**redacted**)" only.

pub struct VerifyOptions {
    /// Maximum allowed age between the signed timestamp and "now",
    /// for providers whose scheme includes a timestamp. `None` disables
    /// the check (not recommended). Default: Some(Duration::from_secs(300)).
    pub max_age: Option<Duration>,
    /// Clock used for "now", injectable for deterministic tests.
    pub clock: Option<Arc<dyn Clock>>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self { max_age: Some(Duration::from_secs(300)), clock: None }
    }
}

pub trait HeaderMap {
    /// Case-insensitive header lookup. Returns the first matching value.
    fn get(&self, name: &str) -> Option<&str>;
}
// Blanket impls provided for http::HeaderMap, Vec<(String,String)>,
// and BTreeMap<String,String> behind feature flags.

pub fn verify(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: VerifyOptions,
) -> Result<(), VerifyError>;
```

### 2.1 `VerifyError`

```rust
#[non_exhaustive]
pub enum VerifyError {
    MissingHeader { header: &'static str },
    MalformedHeader { header: &'static str, reason: &'static str },
    BadEncoding { reason: &'static str },
    SignatureMismatch,
    TimestampOutOfTolerance { skew: Duration, max_age: Duration },
    UnsupportedProvider,
    InvalidSecret { reason: &'static str },
}
```

Design rules for errors:

- `VerifyError` **never** includes the secret, the raw body, or the computed
  signature in its `Display` output. It may include header *names* and
  numeric skew values.
- `SignatureMismatch` must be returned in exactly the same way regardless of
  *how close* the provided signature was to correct (no early-return that
  could leak timing information about which byte differed).
- Distinguish `MissingHeader` / `MalformedHeader` from `SignatureMismatch`
  in the type system (useful for callers who want to log malformed-request
  noise differently from active-attack signals), but treat both as "reject
  the request" outcomes — never treat a malformed header as "skip
  verification."

### 2.2 `CustomScheme`

For providers not yet built in, or self-hosted/internal webhook senders:

```rust
pub struct CustomScheme {
    pub hash: HashAlg,                 // Sha256 | Sha1 | Sha512
    pub signature_header: &'static str,
    pub timestamp_header: Option<&'static str>,
    pub encoding: Encoding,            // Hex | Base64
    pub prefix: Option<&'static str>,  // e.g. "sha256=" or "v0="
    pub signed_string: fn(&dyn HeaderMap, &[u8]) -> Vec<u8>,
}
```

This lets callers cover a long-tail provider today without waiting on a
crate release, and it's how new built-in providers get prototyped before
being promoted into the `Provider` enum.

---

## 3. Per-provider signing schemes

Each entry below is the normative definition an implementation must match.
Every row must ship with at least one test vector taken from the provider's
own published documentation (linked in code comments) plus at least one
locally-constructed vector covering a boundary case (empty body, unicode
body, multi-value headers, etc.).

### Stripe

- Header: `Stripe-Signature: t=<unix_ts>,v1=<hex_hmac>[,v0=<legacy>]`
- Signed string: `"{t}.{raw_body}"` (literal dot join, UTF-8 bytes)
- Algorithm: HMAC-SHA256, hex-encoded
- Replay protection: compare `t` against `max_age` (Stripe's own SDKs
  default to 5 minutes)
- Multiple `v1=` values may be present during secret rotation; a match on
  *any* is accepted.

### GitHub

- Header: `X-Hub-Signature-256: sha256=<hex_hmac>`
- Signed string: raw body bytes, unmodified
- Algorithm: HMAC-SHA256, hex-encoded
- No built-in timestamp; GitHub does not include replay protection at the
  signature layer. `max_age` has no effect for this provider — document
  this explicitly rather than silently ignoring the option.
- Legacy `X-Hub-Signature` (SHA1) supported only via `CustomScheme` — not a
  default path, since GitHub itself deprecated SHA1.

### Shopify

- Header: `X-Shopify-Hmac-SHA256: <base64_hmac>`
- Signed string: raw body bytes, unmodified
- Algorithm: HMAC-SHA256, **base64**-encoded (not hex — a common bug source)
- No timestamp in the signature scheme.

### Slack

- Headers: `X-Slack-Signature: v0=<hex_hmac>`, `X-Slack-Request-Timestamp`
- Signed string: `"v0:{timestamp}:{raw_body}"`
- Algorithm: HMAC-SHA256, hex-encoded
- Replay protection required: Slack explicitly recommends rejecting
  requests where `|now - timestamp| > 300s`.

### Square

- Header: `x-square-hmacsha256-signature: <base64_hmac>`
- Signed string: `"{notification_url}{raw_body}"` (the full webhook
  subscription URL is part of the signed content — this is the one scheme
  where the caller must supply an extra piece of context, so `verify()`
  accepts it via `VerifyOptions` or a provider-specific builder)
- Secret is provided by Square hex-encoded; decode before use as HMAC key.

### Twilio

- Header: `X-Twilio-Signature: <base64_hmac_sha1>`
- Signed string: full request URL concatenated with sorted `POST` param
  key+value pairs (form-encoded requests, not raw JSON)
- Algorithm: HMAC-SHA1, base64-encoded
- Note: this is the one scheme in the default set that is not purely
  raw-body-based; it needs the full URL and parsed form fields. Implement
  as its own code path, not shoehorned into the generic HMAC helper.

### Discord

- Headers: `X-Signature-Ed25519`, `X-Signature-Timestamp`
- Signed message: `"{timestamp}{raw_body}"`
- Algorithm: Ed25519 signature verification against Discord's provided
  **public key** (not a shared secret — `Secret` here holds the hex-encoded
  public key, not an HMAC key; document this distinction prominently since
  it changes the security model).

### PayPal / SendGrid

- Both use asymmetric (certificate/ECDSA-based) verification requiring a
  fetched or configured public key/certificate rather than a bare shared
  secret. v0.1 ships these as documented `CustomScheme` recipes plus tested
  helper functions, promoted to first-class `Provider` variants once the
  certificate-fetch story (sync vs. pluggable async fetcher) is settled —
  see open questions (§7).

### Linear / Zoom / Dropbox

- Standard single-secret HMAC-SHA256 schemes, hex or base64 per provider
  documentation; each gets its own row in the vector table but no special
  logic beyond header name / encoding / prefix differences already modeled
  by `CustomScheme`.

### Standard Webhooks spec

- Headers: `webhook-id`, `webhook-timestamp`, `webhook-signature: v1,<base64_hmac>[ v1,<...>]`
- Signed string: `"{webhook-id}.{webhook-timestamp}.{raw_body}"`
- Algorithm: HMAC-SHA256, base64-encoded, secret is `whsec_`-prefixed base64
- Used by Svix, Clerk, Resend, and a growing list of adopters — implementing
  this once covers all of them.

---

## 4. Security requirements (non-negotiable)

1. **Constant-time comparison.** All signature comparisons use
   `subtle::ConstantTimeEq` (or equivalent) — never `==` on the decoded
   bytes or the encoded strings.
2. **Verify against raw bytes only.** No implementation may re-serialize,
   re-encode, or normalize the body before hashing. The `raw_body: &[u8]`
   passed in is hashed exactly as received.
3. **No secret material in errors, logs, panics, or `Debug` output.**
   Enforced by the `Secret` wrapper type and by a clippy lint / grep check
   in CI (see §6).
4. **Reject on ambiguity, not accept.** If a header is present multiple
   times with different values, or a required header is malformed, return
   an error — never fall back to "treat as valid" behavior.
5. **No panics on attacker-controlled input.** Every parsing path
   (`base64::decode`, `hex::decode`, header splitting, integer parsing of
   timestamps) must return `Result`, not `unwrap()`/`expect()`, and this is
   enforced by `#![deny(clippy::unwrap_used, clippy::expect_used)]` in the
   provider modules.
6. **Timing of the whole function should not vary meaningfully based on
   *why* verification failed.** Structurally this is hard to guarantee
   perfectly (header lookups are not constant-time), but the security-
   relevant step — signature comparison — must be, and is the one that
   matters for known real-world timing attacks.

---

## 5. Testing bar for every provider

A provider implementation is not mergeable until it has:

1. **At least one official test vector**, sourced from the provider's own
   docs/SDK/test suite, with a comment linking to the source.
2. **A negative test**: same inputs, one byte flipped in the signature →
   must return `Err(VerifyError::SignatureMismatch)`.
3. **A tamper test**: valid signature, but `raw_body` modified after
   signing → must fail.
4. **A replay test** (for providers with timestamps): valid signature, but
   timestamp outside `max_age` → must return
   `Err(VerifyError::TimestampOutOfTolerance { .. })`.
5. **A malformed-header test** for each required header: missing, empty,
   and garbage-value cases each return a distinct, documented error variant
   (never a panic, never `SignatureMismatch` masquerading as a parse
   error).
6. **Fuzz coverage**: the header-parsing and encoding-decoding paths for
   each provider are included in the shared `cargo fuzz` target
   (`fuzz/fuzz_targets/parse_and_verify.rs`), which feeds arbitrary bytes as
   headers/body and asserts only "no panic, no timeout" — correctness is
   covered by the vector tests above, fuzzing exists purely to catch
   panics/hangs on adversarial input.
7. **Constant-time assertion** where feasible: a `dudect`-style statistical
   timing test on the comparison step, run in CI as a non-blocking
   (informational) job given the inherent noise of CI runners.

---

## 6. CI requirements

- `cargo test --all-features` on stable, MSRV, and beta.
- `cargo clippy --all-features -- -D warnings`.
- `cargo fuzz build` (build-only in normal CI; timed fuzz runs in a
  scheduled nightly job).
- A grep-based CI check that fails the build if any of `println!`,
  `dbg!`, `log::`, or `tracing::` macros appear inside a `Secret`'s scope in
  a way that could print its inner value (supplemented by the `Secret`
  type's own redacted `Debug`/`Display` impls as the primary defense).
- `cargo semver-checks` against the last published version to catch
  accidental breaking changes to the public API.

---

## 7. Open questions / future work

- **Certificate/public-key providers (PayPal, SendGrid).** Should the crate
  fetch certificates itself (requires an async HTTP client dependency,
  against the "no network calls" goal) or only accept a pre-fetched
  key/cert from the caller? Current lean: caller-supplied only, with a
  separate optional `webhook-verify-fetch` companion crate later if there's
  demand for automated key rotation handling.
- **Secret rotation UX.** Stripe/Standard Webhooks allow multiple valid
  signatures during a rotation window (`v1=...,v1=...`). Should `verify()`
  accept a single `Secret` or `&[Secret]` generically across all providers?
  Current lean: keep `Secret` singular in the core signature for
  ergonomics, and add `verify_any(provider, headers, body, &[Secret], opts)`
  as a thin wrapper.
- **`no_std` scope.** Full `no_std` (no `alloc`) is likely infeasible given
  base64/hex decoding and header string handling; target `no_std + alloc`
  and validate against `wasm32-unknown-unknown` as the primary constrained
  target (webhook verification at the edge, e.g. Cloudflare Workers via
  `wasm-bindgen`, is a plausible real use case).
- **Provider promotion criteria.** A `CustomScheme` recipe gets promoted to
  a first-class `Provider` variant once it has (a) official test vectors,
  (b) at least one external user request or contribution, and (c) no open
  design question from §7 blocking it.

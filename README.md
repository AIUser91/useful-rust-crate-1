# webhook-verify

**One function to verify inbound webhooks from any provider.**

Every backend that accepts webhooks ends up hand-rolling HMAC verification for
Stripe, GitHub, Shopify, Slack, and a dozen other services — and getting subtle
details wrong (raw body vs. re-serialized JSON, non-constant-time comparison,
missing replay protection, provider-specific encoding quirks). `webhook-verify`
is a small, dependency-light, audited-primitive-backed crate that does this
once, correctly, for every major provider, behind a single API.

```rust
use webhook_verify::{verify, Provider, Secret};

let result = verify(
    Provider::Stripe,
    &headers,        // anything implementing HeaderMap
    &raw_body,        // &[u8] — MUST be the untouched request body
    &Secret::new(std::env::var("STRIPE_WEBHOOK_SECRET")?),
    Default::default(),
);

match result {
    Ok(()) => { /* trusted: safe to process the event */ }
    Err(e) => { /* reject with 400/401, log e.kind() */ }
}
```

That's it. No client SDK to pull in, no per-provider crate to learn, no
hand-copied signing-string logic to get wrong.

## Why this exists

- **The pain is universal.** Nearly every SaaS integrates *outbound* webhooks
  from payment processors, source control, chat platforms, and e-commerce
  tools. Verifying them correctly is small in code size but easy to get
  wrong, and wrong verification is a real security hole (forged
  `payment.succeeded` / `order.created` events).
- **Rust has no incumbent.** Go (`trusthook`) and TypeScript
  (`webhook-signature`, `hookinbox-verify`) both grew "one API, many
  providers" webhook verifiers in the last year. Rust still doesn't have one
  — only heavyweight per-vendor SDKs (`async-stripe`, `shopify-sdk`, ...)
  that happen to include verification as a minor feature, plus a handful of
  single-provider crates.
- **This should be a library, not a tutorial.** Search "verify \[provider\]
  webhook signature" for any provider and you'll find blog posts re-teaching
  the same HMAC recipe. That volume of repeated how-to content is the
  classic signal that the logic belongs in a dependency, not a copy-pasted
  snippet.

## Design principles

1. **Correctness over cleverness.** Every provider implementation is backed
   by test vectors taken verbatim from that provider's own documentation.
   No provider ships without them.
2. **No custom cryptography.** All primitives come from
   [RustCrypto](https://github.com/RustCrypto) (`hmac`, `sha2`, `sha1`,
   `ed25519-dalek`, `subtle` for constant-time comparison). This crate only
   owns *parsing and orchestration*, never hashing or signature math.
3. **Headless core, thin adapters.** The value is in `verify()`, a pure,
   synchronous, allocation-light function. Framework integration (Axum,
   Actix Web, Tower) is optional sugar behind feature flags, not the point
   of the crate.
4. **Fail closed, explain why.** Errors are structured
   (`VerifyError::{MissingHeader, BadEncoding, SignatureMismatch,
   TimestampOutOfTolerance, UnsupportedProvider, ...}`) so callers can log
   and alert meaningfully instead of getting a bare `false`.
5. **No unbounded scope creep.** This crate verifies signatures. It does not
   deserialize event payloads, manage retries, store idempotency keys, or
   proxy webhooks. Those are separate, composable concerns (and separate
   crates) on purpose.

## Supported providers (target v0.1 matrix)

| Provider | Scheme | Status |
|---|---|---|
| GitHub | HMAC-SHA256, `X-Hub-Signature-256` | ✅ |
| Stripe | HMAC-SHA256 over `timestamp.body`, tolerance window | ✅ |
| Shopify | HMAC-SHA256, base64, `X-Shopify-Hmac-Sha256` | ✅ |
| Slack | HMAC-SHA256 `v0=` scheme, `X-Slack-Signature` + timestamp | ✅ |
| Linear | HMAC-SHA256, `linear-signature` | ✅ |
| Square | HMAC-SHA256 over notification URL + body, base64, `X-Square-HmacSha256-Signature` (needs `VerifyOptions::request_url`) | ✅ |
| Twilio | HMAC-SHA1 over URL + sorted form params, `X-Twilio-Signature` (needs `VerifyOptions::request_url` + `form_params`) | ✅ |
| Discord | Ed25519 (public-key), no shared secret | ✅ |
| PayPal | Certificate-based / API verification | 🚧 planned (design settled, spec §7) |
| SendGrid | ECDSA (asymmetric) | 🚧 planned (design settled, spec §7) |
| Zoom | HMAC-SHA256, `v0=` scheme | 🚧 planned |
| Dropbox | HMAC-SHA256, `X-Dropbox-Signature` | 🚧 planned |
| Standard Webhooks spec (Svix, Clerk, Resend, ...) | HMAC-SHA256, `webhook-signature` (`v1,` base64, rotation list) + replay window | ✅ |
| Custom | User-supplied HMAC scheme via `Provider::Custom(..)` (SHA-256/SHA-1/SHA-512, hex/base64, optional prefix + timestamp replay window) | ✅ |

Providers marked 🚧 exist as fail-closed variants of the `Provider` enum:
passing one to `verify()` returns `VerifyError::UnsupportedProvider`. See
[`spec.md`](./spec.md) for the exact signed-string construction, header
names, and encoding for each provider, and the process for adding new ones.

## Installation

```toml
[dependencies]
webhook-verify = "0.1"

# verify straight against http::HeaderMap (axum, tower, hyper, ...)
webhook-verify = { version = "0.1", features = ["http"] }

# optional framework adapters
webhook-verify = { version = "0.1", features = ["axum"] }
```

With the `http` feature enabled, any `http::HeaderMap` (from axum, tower, or
hyper requests) implements `HeaderMap` and can be passed to `verify()` directly.

## Framework adapters

### Axum

```rust
use axum::{routing::post, Router};
use webhook_verify::axum::WebhookVerifierLayer;

let app = Router::new()
    .route("/webhooks/stripe", post(handle_stripe))
    .layer(WebhookVerifierLayer::new(Provider::Stripe, secret));
```

### Actix Web

```rust
App::new().route(
    "/webhooks/github",
    web::post()
        .guard(webhook_verify::actix::verified(Provider::GitHub, secret))
        .to(handle_github),
)
```

### Tower

`webhook-verify::tower::VerifyLayer` implements `tower::Layer` directly for
anyone composing their own middleware stack.

> ⚠️ **Raw body required.** All frameworks buffer and re-parse JSON by
> default, which changes byte-for-byte content (key ordering, whitespace).
> Verification must run against the *exact* bytes the provider sent, before
> any JSON deserialization. Each adapter documents how to capture the raw
> body correctly for that framework.

## Security notes

- All signature comparisons use constant-time equality (`subtle::ConstantTimeEq`).
- Timestamp-based replay protection is enabled by default wherever the
  provider supports it (`VerifyOptions::max_age`, default 5 minutes).
- This crate does not log secrets, request bodies, or computed signatures
  under any log level.
- Secrets are wrapped in a `Secret` type that redacts `Debug`/`Display` output.

## Non-goals

- Sending/registering webhooks (that's the provider's own SDK's job).
- Event payload parsing/typing.
- Idempotency / deduplication of already-verified events.
- A hosted or proxying service (this is a plain library).

## Versioning & MSRV

Semantic versioning. New providers are additive (minor version bumps).
Changes to an existing provider's verification logic that could reject
previously-accepted requests are treated as breaking (major version bump),
except where required to fix a genuine security defect, which will be
called out explicitly in the changelog and a security advisory.

MSRV: latest stable minus 2 releases, checked in CI.

## Contributing

New providers, corrected test vectors, and encoding edge cases are the
highest-value contributions. See [`AGENTS.md`](./AGENTS.md) for the
step-by-step process (used by both human and AI contributors) and
[`spec.md`](./spec.md) for the technical contract each provider
implementation must satisfy.

## License

Dual-licensed under MIT or Apache-2.0, at your option.

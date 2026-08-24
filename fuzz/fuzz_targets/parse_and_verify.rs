//! Shared fuzz target: feeds arbitrary bytes as headers + raw body into every
//! implemented provider's verification path (`spec.md` §5.6).
//!
//! Correctness is covered by the per-provider vector tests; this target exists
//! purely to assert **no panic and no timeout** on adversarial input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use webhook_verify::{Provider, Secret, VerifyOptions};

/// Upper bound on parsed header lines so a pathological input cannot spin the
/// loop long enough to trip the fuzzer's timeout.
const MAX_HEADER_LINES: usize = 64;

/// Providers with an implementation in `src/providers/`. When a new provider
/// ships, add it here so its parsing path gets coverage too.
const IMPLEMENTED: &[Provider] = &[
    Provider::Stripe,
    Provider::GitHub,
    Provider::Shopify,
    Provider::Slack,
    Provider::Linear,
    // Square needs VerifyOptions::request_url to get past its context check
    // and into the signature path.
    Provider::Square,
    Provider::StandardWebhooks,
    // Discord's secret is a hex public key; the arbitrary-secret loop below
    // exercises its InvalidSecret decoding paths too.
    Provider::Discord,
];

/// A well-formed secret for each provider's scheme, so the fuzzer reaches the
/// signature-construction/comparison paths and not just early secret errors.
/// (Only Standard Webhooks parses its key format; the rest accept any string.)
const WELL_FORMED_SECRET: &str =
    "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

fn attempt(
    provider: Provider,
    headers: &dyn webhook_verify::HeaderMap,
    body: &[u8],
    secret: &str,
    options: &VerifyOptions,
) {
    let _ = webhook_verify::verify(
        provider,
        headers,
        body,
        &Secret::new(secret),
        options.clone(),
    );
}

fuzz_target!(|data: &[u8]| {
    // Input layout: `Name: value` lines, then a blank line, then the body.
    // Everything malformed stays malformed on purpose — garbage header lines
    // are exactly the input class this target exists to exercise.
    let (header_bytes, body): (&[u8], &[u8]) = match data.windows(2).position(|w| w == b"\n\n") {
        Some(pos) => (&data[..pos], &data[pos + 2..]),
        None => (data, &[]),
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in header_bytes.split(|&b| b == b'\n').take(MAX_HEADER_LINES) {
        let line = String::from_utf8_lossy(line);
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.to_string()));
        }
    }

    // URL-scoped schemes need request context to reach their signature path.
    let url_scoped_options =
        VerifyOptions::default().with_request_url("https://example.com/webhook");

    // Fail-closed dispatch for not-yet-implemented variants must also never
    // panic (Square now has an implementation; it is exercised via
    // IMPLEMENTED below, with and without its required URL context).
    attempt(Provider::Square, &headers, body, WELL_FORMED_SECRET, &url_scoped_options);
    attempt(Provider::Square, &headers, body, WELL_FORMED_SECRET, &VerifyOptions::default());

    for &provider in IMPLEMENTED {
        attempt(provider, &headers, body, WELL_FORMED_SECRET, &url_scoped_options);
        // Arbitrary secret bytes exercise the key-decoding failure paths
        // (e.g. Standard Webhooks' lenient base64) without panicking.
        let arbitrary_secret = String::from_utf8_lossy(body);
        attempt(provider, &headers, body, &arbitrary_secret, &url_scoped_options);
    }
});

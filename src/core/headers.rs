//! The [`HeaderMap`] abstraction: lets `verify()` work against any framework's
//! header representation.

use std::collections::BTreeMap;

/// Case-insensitive, read-only header lookup.
///
/// Returns the value of the *first* header matching `name` (ASCII
/// case-insensitively), or `None` if absent.
///
/// # Ambiguity contract
///
/// Per `spec.md` §4.4, a request whose signature header appears multiple times
/// with *different* values is ambiguous and must be rejected — but detection of
/// duplicates belongs to the caller/adapter layer, since this trait exposes
/// only first-match lookup. Framework adapters are expected to reject
/// duplicated signature headers before calling [`crate::verify()`].
///
/// # `BTreeMap` caveat
///
/// For [`BTreeMap`] the inherent exact-case `get` shadows this trait method in
/// method-call position. Pass the map to `HeaderMap::get(&map, name)` to get
/// the case-insensitive lookup this crate relies on.
pub trait HeaderMap {
    /// Case-insensitive lookup of a single header value.
    fn get(&self, name: &str) -> Option<&str>;
}

impl HeaderMap for Vec<(String, String)> {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl<const N: usize> HeaderMap for [(String, String); N] {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl<const N: usize> HeaderMap for [(&str, &str); N] {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

impl HeaderMap for BTreeMap<String, String> {
    fn get(&self, name: &str) -> Option<&str> {
        // Keys may differ in case from the canonical names providers document,
        // so exact-key lookup is not enough.
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::HeaderMap;

    #[test]
    fn lookup_is_ascii_case_insensitive() {
        let headers = vec![("X-Hub-Signature-256".to_string(), "sha256=ab".to_string())];
        assert_eq!(headers.get("x-hub-signature-256"), Some("sha256=ab"));
        assert_eq!(headers.get("X-HUB-SIGNATURE-256"), Some("sha256=ab"));
        assert_eq!(headers.get("x-hub-signature-1"), None);
    }

    #[test]
    fn first_match_wins() {
        let headers = [
            ("a".to_string(), "first".to_string()),
            ("A".to_string(), "second".to_string()),
        ];
        assert_eq!(headers.get("A"), Some("first"));
    }

    #[test]
    fn btree_map_is_case_insensitive() {
        let mut headers = BTreeMap::new();
        headers.insert("Webhook-Signature".to_string(), "v1,aa".to_string());
        // Note: `headers.get(..)` would resolve to BTreeMap's *inherent* exact-key
        // lookup, which shadows the trait method in method-call position; go
        // through the trait explicitly.
        assert_eq!(HeaderMap::get(&headers, "webhook-signature"), Some("v1,aa"));
    }

    #[test]
    fn str_tuple_arrays_work() {
        let headers = [("X-Slack-Signature", "v0=ff")];
        assert_eq!(headers.get("x-slack-signature"), Some("v0=ff"));
    }
}

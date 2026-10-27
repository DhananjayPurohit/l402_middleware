//! A macaroon is bound to a *protection space* plus an HTTP method, optionally
//! with an expiry:
//!
//!   - `RequestPath = /exact`  — exactly one URL (default; metered per path)
//!   - `Realm = name`          — a named protection space; one payment covers
//!                               every path the server maps to that realm
//!   - `RequestMethod = GET`   — the HTTP method (always bound)
//!   - `ExpiresAt = <unix>`    — optional absolute expiry
//!   - `<Key> = <value>`       — optional consumer-defined bindings (e.g.
//!                               `McpTool = search`), see [`RequestBinding::with_bound`]
//!
//! SECURITY: the scope and method caveats are enforced by EXACT match. The
//! verifier's general callback must REJECT any such predicate rather than let
//! it fall through — otherwise a token minted for one route/realm/method would
//! validate against another (an auth bypass). That guard lives in exactly one
//! place — `RequestBinding::verifier` — and is covered by the bypass tests at
//! the bottom of this file. Bound caveats can't be guarded there (the general
//! callback is a plain `fn` and doesn't know the binding's keys), so
//! `RequestBinding::check_bound` enforces them; `verify_l402_binding` runs both.

use macaroon::{Caveat, Macaroon, Verifier};
use std::time::{SystemTime, UNIX_EPOCH};

/// The protection space a macaroon is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Bind to one exact request path — one payment authorizes one URL.
    Path(String),
    /// Bind to a named realm — one payment authorizes every path the server
    /// maps to this realm.
    Realm(String),
}

impl Scope {
    /// The caveat string that carries this scope in the macaroon.
    fn caveat(&self) -> String {
        match self {
            Scope::Path(p) => format!("RequestPath = {}", p),
            Scope::Realm(r) => format!("Realm = {}", r),
        }
    }
}

/// A macaroon's binding to a request: protection space + HTTP method (+ expiry).
///
/// Build one from request context, then use it for BOTH minting (`to_caveats`)
/// and verification (`verifier` / [`crate::l402::verify_l402_binding`]) so the
/// two can never drift.
#[derive(Clone, Debug)]
pub struct RequestBinding {
    pub scope: Scope,
    pub method: String,
    /// Absolute expiry as a Unix timestamp (seconds). `None` = no expiry.
    /// Consulted only at mint time; at verify, the `ExpiresAt` caveat carried by
    /// the macaroon is what's checked.
    pub expires_at: Option<i64>,
    /// Extra `Key = value` bindings, enforced like scope and method. Set them
    /// with [`RequestBinding::with_bound`].
    pub bound: Vec<(String, String)>,
}

/// Caveat keys this module already owns; `with_bound` cannot take them.
const RESERVED_KEYS: [&str; 4] = ["RequestPath", "Realm", "RequestMethod", "ExpiresAt"];

impl RequestBinding {
    /// Bind to an exact request path + method (the default L402 behaviour).
    pub fn path(path: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            scope: Scope::Path(path.into()),
            method: method.into(),
            expires_at: None,
            bound: Vec::new(),
        }
    }

    /// Bind to a named realm + method — one payment authorizes the whole realm.
    pub fn realm(realm: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            scope: Scope::Realm(realm.into()),
            method: method.into(),
            expires_at: None,
            bound: Vec::new(),
        }
    }

    /// Set the expiry (Unix seconds). `None` leaves the token non-expiring.
    pub fn with_expiry(mut self, expires_at: Option<i64>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Also bind the token to `Key = value` — e.g. `McpTool = search`, so a
    /// token bought for one tool behind a shared endpoint can't call another.
    ///
    /// [`crate::l402::verify_l402_binding`] enforces a bound caveat like scope
    /// and method: exact match, any other value for the same key is rejected,
    /// and so is a token that doesn't carry the key at all. Setting a key twice
    /// keeps the last value.
    ///
    /// Returns `None` if `key` is empty, contains whitespace or `=`, or is one
    /// of the caveats this module already owns (`RequestPath`, `Realm`,
    /// `RequestMethod`, `ExpiresAt`).
    pub fn with_bound(mut self, key: impl Into<String>, value: impl Into<String>) -> Option<Self> {
        let key = key.into();
        if key.is_empty()
            || key.contains(|c: char| c.is_whitespace() || c == '=')
            || RESERVED_KEYS.contains(&key.as_str())
        {
            return None;
        }
        let value = value.into();
        match self.bound.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => self.bound.push((key, value)),
        }
        Some(self)
    }

    fn bound_caveats(&self) -> impl Iterator<Item = String> + '_ {
        self.bound.iter().map(|(k, v)| format!("{} = {}", k, v))
    }

    /// The caveats to bake into the macaroon at mint time.
    pub fn to_caveats(&self) -> Vec<String> {
        let mut caveats = vec![
            self.scope.caveat(),
            format!("RequestMethod = {}", self.method),
        ];
        caveats.extend(self.bound_caveats());
        if let Some(ts) = self.expires_at {
            caveats.push(format!("ExpiresAt = {}", ts));
        }
        caveats
    }

    /// Check `mac` against the bound caveats: every bound key must appear, and
    /// every caveat under a bound key must carry exactly the bound value.
    ///
    /// This runs outside the [`Verifier`] because the macaroon crate's general
    /// callbacks are plain `fn` pointers and cannot know which keys this binding
    /// holds, and because a verifier only judges caveats that are present — a
    /// token minted before the binding existed (no `McpTool` at all) would pass.
    /// [`crate::l402::verify_l402_binding`] runs it on every verification.
    pub fn check_bound(&self, mac: &Macaroon) -> Result<(), String> {
        if self.bound.is_empty() {
            return Ok(());
        }
        let predicates: Vec<Vec<u8>> = mac
            .first_party_caveats()
            .iter()
            .filter_map(|c| match c {
                Caveat::FirstParty(fp) => Some(fp.predicate().0),
                _ => None,
            })
            .collect();
        for (key, value) in &self.bound {
            let prefix = format!("{} = ", key);
            let mut seen = false;
            for p in &predicates {
                if let Some(v) = p.strip_prefix(prefix.as_bytes()) {
                    if v != value.as_bytes() {
                        return Err(format!("macaroon is bound to a different {}", key));
                    }
                    seen = true;
                }
            }
            if !seen {
                return Err(format!("macaroon is missing required caveat {}", key));
            }
        }
        Ok(())
    }

    /// A [`Verifier`] that enforces this binding: the scope and method caveats
    /// by exact match, `ExpiresAt` by a time check, and — critically — REJECTS
    /// any other scope/method predicate instead of letting it pass. Bound
    /// caveats are exact-matched here too, but a wrong or missing bound value is
    /// only caught by [`RequestBinding::check_bound`]; verify through
    /// [`crate::l402::verify_l402_binding`], which runs both.
    pub fn verifier(&self) -> Verifier {
        let mut verifier = Verifier::default();
        verifier.satisfy_exact(self.scope.caveat().into());
        verifier.satisfy_exact(format!("RequestMethod = {}", self.method).into());
        for caveat in self.bound_caveats() {
            verifier.satisfy_exact(caveat.into());
        }
        verifier.satisfy_general(|predicate| {
            let s = match std::str::from_utf8(&predicate.0) {
                Ok(s) => s,
                Err(_) => return false,
            };
            if let Some(secs) = s.strip_prefix("ExpiresAt = ") {
                if let Ok(ts) = secs.parse::<i64>() {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    return now <= ts;
                }
            }
            // SECURITY: scope and method predicates are exact-matched above.
            // Falling through to `true` here would let a token minted for one
            // route/realm/method verify against any other — an auth bypass.
            if s.starts_with("RequestPath = ")
                || s.starts_with("Realm = ")
                || s.starts_with("RequestMethod = ")
            {
                return false;
            }
            true
        });
        verifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l402::verify_l402_binding;
    use crate::macaroon_util::get_macaroon_as_string;
    use crate::utils::parse_l402_header;
    use lightning::types::payment::{PaymentHash, PaymentPreimage};

    const ROOT_KEY: [u8; 4] = [1, 2, 3, 4];

    // Mint a macaroon carrying `caveats`, bound to the payment hash of a fixed
    // preimage, and return the parseable "<macaroon>:<preimage_hex>" auth value.
    fn mint(caveats: Vec<String>) -> (macaroon::Macaroon, PaymentPreimage) {
        let preimage = PaymentPreimage([7u8; 32]);
        let payment_hash = PaymentHash::from(preimage);
        let mac_str = get_macaroon_as_string(payment_hash, caveats, ROOT_KEY.to_vec()).unwrap();
        // Round-trip through the wire format the client would send.
        let hex_preimage = hex::encode(preimage.0);
        let auth = format!("{}:{}", mac_str, hex_preimage);
        parse_l402_header(&auth).unwrap()
    }

    #[test]
    fn path_token_verifies_on_its_path() {
        let (mac, preimage) = mint(RequestBinding::path("/a", "GET").to_caveats());
        let binding = RequestBinding::path("/a", "GET");
        assert!(verify_l402_binding(&mac, &binding, ROOT_KEY.to_vec(), preimage).is_ok());
    }

    #[test]
    fn path_token_rejected_on_other_path() {
        let (mac, preimage) = mint(RequestBinding::path("/a", "GET").to_caveats());
        let binding = RequestBinding::path("/b", "GET");
        assert!(verify_l402_binding(&mac, &binding, ROOT_KEY.to_vec(), preimage).is_err());
    }

    #[test]
    fn realm_token_verifies_across_paths_in_the_realm() {
        // One payment (realm token), two different request paths — both pass,
        // because the binding is the realm, not the path.
        let (mac, preimage) = mint(RequestBinding::realm("blobs", "GET").to_caveats());
        for path in ["/aaaa", "/bbbb", "/whatever"] {
            let _ = path; // path isn't part of a realm binding
            let binding = RequestBinding::realm("blobs", "GET");
            assert!(
                verify_l402_binding(&mac, &binding, ROOT_KEY.to_vec(), preimage).is_ok(),
                "realm token should cover every path in the realm"
            );
        }
    }

    #[test]
    fn realm_token_rejected_on_different_realm() {
        let (mac, preimage) = mint(RequestBinding::realm("read", "GET").to_caveats());
        let binding = RequestBinding::realm("write", "GET");
        assert!(verify_l402_binding(&mac, &binding, ROOT_KEY.to_vec(), preimage).is_err());
    }

    #[test]
    fn token_rejected_cross_method() {
        let (mac, preimage) = mint(RequestBinding::realm("blobs", "GET").to_caveats());
        let binding = RequestBinding::realm("blobs", "PUT");
        assert!(verify_l402_binding(&mac, &binding, ROOT_KEY.to_vec(), preimage).is_err());
    }

    #[test]
    fn path_token_cannot_pose_as_realm_token() {
        // A macaroon minted with a Realm caveat must NOT validate against a
        // path binding, and vice versa — the scope kinds don't cross.
        let (mac, preimage) = mint(RequestBinding::realm("blobs", "GET").to_caveats());
        let path_binding = RequestBinding::path("/aaaa", "GET");
        assert!(verify_l402_binding(&mac, &path_binding, ROOT_KEY.to_vec(), preimage).is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let past = 1_000_000_000i64; // 2001 — safely in the past
        let (mac, preimage) = mint(
            RequestBinding::realm("blobs", "GET")
                .with_expiry(Some(past))
                .to_caveats(),
        );
        let binding = RequestBinding::realm("blobs", "GET");
        assert!(verify_l402_binding(&mac, &binding, ROOT_KEY.to_vec(), preimage).is_err());
    }

    fn tool(name: &str) -> RequestBinding {
        RequestBinding::path("/mcp", "POST")
            .with_bound("McpTool", name)
            .unwrap()
    }

    #[test]
    fn bound_token_verifies_on_its_value() {
        let (mac, preimage) = mint(tool("search").to_caveats());
        assert!(verify_l402_binding(&mac, &tool("search"), ROOT_KEY.to_vec(), preimage).is_ok());
    }

    #[test]
    fn bound_token_rejected_on_other_value() {
        // The bypass this guards: a cheap tool's token calling an expensive one.
        let (mac, preimage) = mint(tool("search").to_caveats());
        assert!(
            verify_l402_binding(&mac, &tool("summarize"), ROOT_KEY.to_vec(), preimage).is_err()
        );
    }

    #[test]
    fn bound_value_is_not_a_prefix_match() {
        let (mac, preimage) = mint(tool("search").to_caveats());
        assert!(
            verify_l402_binding(&mac, &tool("search_all"), ROOT_KEY.to_vec(), preimage).is_err()
        );
    }

    #[test]
    fn token_without_bound_caveat_rejected_where_required() {
        // Minted before the binding existed: same path and method, no McpTool.
        let (mac, preimage) = mint(RequestBinding::path("/mcp", "POST").to_caveats());
        assert!(verify_l402_binding(&mac, &tool("search"), ROOT_KEY.to_vec(), preimage).is_err());
    }

    #[test]
    fn bound_token_still_verifies_without_requirement() {
        // An extra caveat only narrows a token; a binding that doesn't ask for
        // McpTool treats it like any other attenuation.
        let (mac, preimage) = mint(tool("search").to_caveats());
        let plain = RequestBinding::path("/mcp", "POST");
        assert!(verify_l402_binding(&mac, &plain, ROOT_KEY.to_vec(), preimage).is_ok());
    }

    #[test]
    fn bound_token_still_checks_scope_and_method() {
        let (mac, preimage) = mint(tool("search").to_caveats());
        let other_path = RequestBinding::path("/other", "POST")
            .with_bound("McpTool", "search")
            .unwrap();
        let other_method = RequestBinding::path("/mcp", "GET")
            .with_bound("McpTool", "search")
            .unwrap();
        assert!(verify_l402_binding(&mac, &other_path, ROOT_KEY.to_vec(), preimage).is_err());
        assert!(verify_l402_binding(&mac, &other_method, ROOT_KEY.to_vec(), preimage).is_err());
    }

    #[test]
    fn token_with_two_values_for_a_bound_key_rejected() {
        let mut caveats = tool("search").to_caveats();
        caveats.push("McpTool = summarize".to_string());
        let (mac, preimage) = mint(caveats);
        for name in ["search", "summarize"] {
            assert!(
                verify_l402_binding(&mac, &tool(name), ROOT_KEY.to_vec(), preimage).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn with_bound_rejects_reserved_and_malformed_keys() {
        let b = || RequestBinding::path("/a", "GET");
        for key in [
            "RequestPath",
            "Realm",
            "RequestMethod",
            "ExpiresAt",
            "",
            "Mcp Tool",
            "Mcp=Tool",
        ] {
            assert!(b().with_bound(key, "x").is_none(), "{key:?}");
        }
    }

    #[test]
    fn with_bound_same_key_keeps_last_value() {
        let b = RequestBinding::path("/a", "GET")
            .with_bound("McpTool", "a")
            .unwrap()
            .with_bound("McpTool", "b")
            .unwrap();
        assert_eq!(
            b.to_caveats(),
            vec!["RequestPath = /a", "RequestMethod = GET", "McpTool = b"]
        );
    }
}

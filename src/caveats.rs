//! A macaroon is bound to a *protection space* plus an HTTP method, optionally
//! with an expiry:
//!
//!   - `RequestPath = /exact`  — exactly one URL (default; metered per path)
//!   - `Realm = name`          — a named protection space; one payment covers
//!                               every path the server maps to that realm
//!   - `RequestMethod = GET`   — the HTTP method (always bound)
//!   - `ExpiresAt = <unix>`    — optional absolute expiry
//!
//! SECURITY: the scope and method caveats are enforced by EXACT match. The
//! verifier's general callback must REJECT any such predicate rather than let
//! it fall through — otherwise a token minted for one route/realm/method would
//! validate against another (an auth bypass). That guard lives in exactly one
//! place — `RequestBinding::verifier` — and is covered by the bypass tests at
//! the bottom of this file.

use macaroon::Verifier;
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
}

impl RequestBinding {
    /// Bind to an exact request path + method (the default L402 behaviour).
    pub fn path(path: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            scope: Scope::Path(path.into()),
            method: method.into(),
            expires_at: None,
        }
    }

    /// Bind to a named realm + method — one payment authorizes the whole realm.
    pub fn realm(realm: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            scope: Scope::Realm(realm.into()),
            method: method.into(),
            expires_at: None,
        }
    }

    /// Set the expiry (Unix seconds). `None` leaves the token non-expiring.
    pub fn with_expiry(mut self, expires_at: Option<i64>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// The caveats to bake into the macaroon at mint time.
    pub fn to_caveats(&self) -> Vec<String> {
        let mut caveats = vec![
            self.scope.caveat(),
            format!("RequestMethod = {}", self.method),
        ];
        if let Some(ts) = self.expires_at {
            caveats.push(format!("ExpiresAt = {}", ts));
        }
        caveats
    }

    /// A [`Verifier`] that enforces this binding: the scope and method caveats
    /// by exact match, `ExpiresAt` by a time check, and — critically — REJECTS
    /// any other scope/method predicate instead of letting it pass.
    pub fn verifier(&self) -> Verifier {
        let mut verifier = Verifier::default();
        verifier.satisfy_exact(self.scope.caveat().into());
        verifier.satisfy_exact(format!("RequestMethod = {}", self.method).into());
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
}

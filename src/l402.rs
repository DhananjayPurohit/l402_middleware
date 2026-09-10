use lightning::types::payment::{PaymentHash, PaymentPreimage};
use macaroon::{Macaroon, Verifier, MacaroonKey, Caveat};
use rocket::{request, Request};
use hex;

use crate::l402;
use crate::caveats::RequestBinding;

pub const L402_TYPE_FREE: &str = "FREE";
pub const L402_TYPE_PAYMENT_REQUIRED: &str = "PAYMENT REQUIRED";
pub const L402_TYPE_PAID: &str = "PAID";
pub const L402_TYPE_ERROR: &str = "ERROR";
pub const L402_HEADER: &str = "L402";
pub const L402_HEADER_NAME: &str = "Accept-Authenticate";
pub const L402_AUTHENTICATE_HEADER_NAME: &str = "WWW-Authenticate";
pub const L402_AUTHORIZATION_HEADER_NAME: &str = "Authorization";

/// Format the `WWW-Authenticate` challenge value for an L402 `402` response.
///
/// Produces the RFC 7235-style header with **quoted** auth-param values:
/// `L402 macaroon="<macaroon>", invoice="<bolt11>"`. This is the single source
/// of truth for the challenge wire format — consumers must call this rather than
/// hand-rolling the string, so the quoting can't drift between them.
pub fn format_challenge(macaroon: &str, invoice: &str) -> String {
    format!(
        "{} macaroon=\"{}\", invoice=\"{}\"",
        L402_HEADER, macaroon, invoice
    )
}

#[derive(Clone)]
pub struct L402Info {
	pub	l402_type: String,
	pub preimage: Option<PaymentPreimage>,
	pub payment_hash: Option<PaymentHash>,
	pub error: Option<String>,
    pub auth_header: Option<String>,
}

#[rocket::async_trait]
impl<'r> request::FromRequest<'r> for L402Info {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Retrieve L402Info from the local cache
        let l402_info = request.local_cache::<L402Info, _>(|| {
            L402Info {
                l402_type: l402::L402_TYPE_ERROR.to_string(),
                error: Some("No L402 header present".to_string()),
                preimage: None,
                payment_hash: None,
                auth_header: None,
            }
        });

        request::Outcome::Success(l402_info.clone())
    }
}

fn macaroon_id_matches_payment_hash(id_bytes: &[u8], payment_hash: &PaymentHash) -> bool {
    let expected = &payment_hash.0;
    if id_bytes.len() == 33 && id_bytes[0] == 0xff {
        &id_bytes[1..] == expected
    } else if id_bytes.len() == 32 {
        id_bytes == expected
    } else {
        // Identifiers from other issuers may carry extra bytes around the hash.
        // Search the raw bytes, not hex: a hex substring also matches at nibble
        // offsets, where the bytes hold no aligned copy of the hash.
        id_bytes.windows(32).any(|w| w == expected)
    }
}

pub fn verify_l402(
    mac: &Macaroon,
    caveats: Vec<String>,
    root_key: Vec<u8>,
    preimage: PaymentPreimage,
) -> Result<(), Box<dyn std::error::Error>> {
    // verify() checks macaroon ⊆ required; nothing checks the reverse, so a
    // duplicate can pad the count in place of a missing caveat.
    let mac_predicates: Vec<Vec<u8>> = mac
        .first_party_caveats()
        .into_iter()
        .filter_map(|c| match c {
            Caveat::FirstParty(fp) => Some(fp.predicate().0),
            _ => None,
        })
        .collect();

    for required in &caveats {
        if !mac_predicates.iter().any(|p| p.as_slice() == required.as_bytes()) {
            return Err("Error validating macaroon: Caveats don't match".into());
        }
    }

    let mac_key = MacaroonKey::generate(&root_key);
    let mut verifier = Verifier::default();
    
    for caveat in caveats {
        verifier.satisfy_exact(caveat.into());
    }

    match verifier.verify(&mac, &mac_key, Default::default()) {
        Ok(_) => {
            let payment_hash: PaymentHash = PaymentHash::from(preimage);
            let id_bytes = &mac.identifier().clone().0;
            if macaroon_id_matches_payment_hash(id_bytes, &payment_hash) {
                Ok(())
            } else {
                Err(format!(
                    "Invalid PaymentHash {} for macaroon {}",
                    hex::encode(payment_hash.0), hex::encode(id_bytes)
                ).into())
            }
        },
        Err(error) => {
            Err(format!("Error validating macaroon: {:?}", error).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::format_challenge;

    #[test]
    fn challenge_uses_quoted_rfc_style() {
        // Values MUST be quoted (RFC 7235). This locks the format so the two
        // consumers can't drift apart again.
        assert_eq!(
            format_challenge("AGIAJEem", "lnbc10n1p"),
            r#"L402 macaroon="AGIAJEem", invoice="lnbc10n1p""#
        );
    }

    #[test]
    fn payment_binding_matches_bytes_not_hex_nibbles() {
        use lightning::types::payment::PaymentHash;

        let ph = PaymentHash([0xabu8; 32]);

        // Both exact forms.
        assert!(super::macaroon_id_matches_payment_hash(&ph.0, &ph));
        let mut prefixed = vec![0xffu8];
        prefixed.extend_from_slice(&ph.0);
        assert!(super::macaroon_id_matches_payment_hash(&prefixed, &ph));

        // Foreign issuer framing the hash with extra bytes still binds.
        let mut framed = vec![0u8; 8];
        framed.extend_from_slice(&ph.0);
        framed.extend_from_slice(&[1u8; 4]);
        assert!(super::macaroon_id_matches_payment_hash(&framed, &ph));

        // hex("0a" + "ba"*32) contains hex(ph) at an odd index, yet no aligned
        // copy of the hash exists in the bytes. The hex-substring test matched.
        let mut nibble = vec![0x0au8];
        nibble.extend_from_slice(&[0xbau8; 32]);
        assert!(
            !super::macaroon_id_matches_payment_hash(&nibble, &ph),
            "nibble-offset hex match must not bind"
        );
    }

    #[test]
    fn every_required_caveat_must_be_present() {
        use lightning::types::payment::{PaymentHash, PaymentPreimage};
        use macaroon::{ByteString, Macaroon, MacaroonKey};

        let root_key = vec![7u8; 32];
        let key = MacaroonKey::generate(&root_key);
        let preimage = PaymentPreimage([0x11u8; 32]);
        let payment_hash = PaymentHash::from(preimage);

        let mint = |caveats: &[&str]| {
            let mut mac =
                Macaroon::create(Some("L402".into()), &key, payment_hash.0.into()).unwrap();
            for c in caveats {
                mac.add_first_party_caveat(ByteString::from(*c));
            }
            mac
        };
        let required = || vec!["Scope = a".to_string(), "Tier = premium".to_string()];

        // Duplicate pads the count without carrying "Tier = premium".
        assert!(
            super::verify_l402(
                &mint(&["Scope = a", "Scope = a"]),
                required(),
                root_key.clone(),
                preimage
            )
            .is_err(),
            "duplicate caveat must not satisfy a different required caveat"
        );

        // The honest macaroon still verifies.
        assert!(super::verify_l402(
            &mint(&["Scope = a", "Tier = premium"]),
            required(),
            root_key.clone(),
            preimage
        )
        .is_ok());

        // This entry point exact-matches only the required set, so any added
        // caveat is rejected; attenuation belongs on verify_l402_binding.
        assert!(super::verify_l402(
            &mint(&["Scope = a", "Tier = premium", "ExpiresAt = 123"]),
            required(),
            root_key,
            preimage
        )
        .is_err());
    }
}

/// Verify an L402 macaroon against a [`RequestBinding`] — the high-level entry
/// point. Builds the binding's enforcing verifier (exact scope/method match +
/// `ExpiresAt` time check + the reject-unknown-predicate guard) and checks the
/// macaroon signature and payment-hash binding in one call.
///
/// Prefer this over [`verify_l402_with_verifier`] unless you need a bespoke
/// verifier: it keeps the security-critical caveat policy in this crate, so
/// consumers can't accidentally omit the guard.
pub fn verify_l402_binding(
    mac: &Macaroon,
    binding: &RequestBinding,
    root_key: Vec<u8>,
    preimage: PaymentPreimage,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut verifier = binding.verifier();
    verify_l402_with_verifier(mac, &mut verifier, root_key, preimage)
}

/// Verify L402 using a provided Verifier instance
pub fn verify_l402_with_verifier(
    mac: &Macaroon,
    verifier: &mut Verifier,
    root_key: Vec<u8>,
    preimage: PaymentPreimage,
) -> Result<(), Box<dyn std::error::Error>> {
    let mac_key = MacaroonKey::generate(&root_key);
    
    match verifier.verify(&mac, &mac_key, Default::default()) {
        Ok(_) => {
            let payment_hash: PaymentHash = PaymentHash::from(preimage);
            let id_bytes = &mac.identifier().clone().0;
            if macaroon_id_matches_payment_hash(id_bytes, &payment_hash) {
                Ok(())
            } else {
                Err(format!(
                    "Invalid PaymentHash {} for macaroon {}",
                    hex::encode(payment_hash.0), hex::encode(id_bytes)
                ).into())
            }
        },
        Err(error) => {
            Err(format!("Error validating macaroon: {:?}", error).into())
        }
    }
}

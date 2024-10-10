use lightning::ln::{PaymentHash, PaymentPreimage};
use macaroon::{Macaroon, Verifier, MacaroonKey};
use rocket::{request, Request};
use hex;

use crate::l402;

pub const L402_TYPE_FREE: &str = "FREE";
pub const L402_TYPE_PAYMENT_REQUIRED: &str = "PAYMENT REQUIRED";
pub const L402_TYPE_PAID: &str = "PAID";
pub const L402_TYPE_ERROR: &str = "ERROR";
pub const L402_HEADER: &str = "L402";
pub const L402_HEADER_NAME: &str = "Accept-Authenticate";
pub const L402_AUTHENTICATE_HEADER_NAME: &str = "WWW-Authenticate";
pub const L402_AUTHORIZATION_HEADER_NAME: &str = "Authorization";

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

pub fn verify_l402(
    mac: &Macaroon,
    caveats: Vec<String>,
    root_key: Vec<u8>,
    preimage: PaymentPreimage,
) -> Result<(), Box<dyn std::error::Error>> {
    // caveat verification
    let mac_caveats = mac.first_party_caveats();
    if caveats.len() > mac_caveats.len() {
        return Err("Error validating macaroon: Caveats don't match".into());
    }

    let mac_key = MacaroonKey::generate(&root_key);
    let mut verifier = Verifier::default();
    
    for caveat in caveats {
        verifier.satisfy_exact(caveat.into());
    }

    match verifier.verify(&mac, &mac_key, Default::default()) {
        Ok(_) => {
            let macaroon_id = mac.identifier().clone();
            let macaroon_id_hex = hex::encode(macaroon_id.0).replace("ff", "");
            let payment_hash: PaymentHash = PaymentHash::from(preimage);
            let payment_hash_hex = hex::encode(payment_hash.0);

            if macaroon_id_hex.contains(&payment_hash_hex) {
                Ok(())
            } else {
                Err(format!(
                    "Invalid PaymentHash {} for macaroon {}",
                    payment_hash_hex, macaroon_id_hex
                ).into())
            }
        },
        Err(error) => {
            Err(format!("Error validating macaroon: {:?}", error).into())
        }
    }
}

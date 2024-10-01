use lightning::ln::{PaymentHash, PaymentPreimage};
use macaroon::{Macaroon, Caveat, ByteString};
use rocket::{request, Request};
use hex;

use crate::lsat;

pub const LSAT_TYPE_FREE: &str = "FREE";
pub const LSAT_TYPE_PAYMENT_REQUIRED: &str = "PAYMENT REQUIRED";
pub const LSAT_TYPE_PAID: &str = "PAID";
pub const LSAT_TYPE_ERROR: &str = "ERROR";
pub const LSAT_HEADER: &str = "LSAT";
pub const LSAT_HEADER_NAME: &str = "Accept-Authenticate";

pub const FREE_CONTENT_MESSAGE: &str = "Free Content";
pub const PROTECTED_CONTENT_MESSAGE: &str = "Protected Content";
pub const PAYMENT_REQUIRED_MESSAGE: &str = "Payment Required";

#[derive(Clone)]
pub struct LsatInfo {
	pub	lsat_type: String,
	pub preimage: Option<PaymentPreimage>,
	pub payment_hash: Option<PaymentHash>,
	pub error: Option<String>
}

#[rocket::async_trait]
impl<'r> request::FromRequest<'r> for LsatInfo {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Retrieve LsatInfo from the local cache
        let lsat_info = request.local_cache::<LsatInfo, _>(|| {
            LsatInfo {
                lsat_type: lsat::LSAT_TYPE_ERROR.to_string(),
                error: Some("No LSAT header present".to_string()),
                preimage: None,
                payment_hash: None,
            }
        });

        request::Outcome::Success(lsat_info.clone())
    }
}

pub fn verify_lsat(
    mac: &Macaroon,
    root_key: Vec<u8>,
    preimage: PaymentPreimage,
) -> Result<(), Box<dyn std::error::Error>> {
    // caveat verification need to be done

    let macaroon_id = mac.identifier().clone();
    let macaroon_id_hex = hex::encode(macaroon_id.0).replace("ff", "");
    let payment_hash: PaymentHash = PaymentHash::from(preimage);
    let payment_hash_hex = hex::encode(payment_hash.0);

    if macaroon_id_hex.contains(&payment_hash_hex) {
        return Ok(());
    } else {
        return Err(format!(
            "Invalid PaymentHash {} for macaroon {}",
            payment_hash_hex, macaroon_id_hex
        ).into());
    }
}

use lightning::ln::{PaymentHash, PaymentPreimage};
use macaroon::{Macaroon, Caveat, ByteString};

pub const LSAT_TYPE_FREE: &str = "FREE";
pub const LSAT_TYPE_PAID: &str = "PAID";
pub const LSAT_TYPE_ERROR: &str = "ERROR";
pub const LSAT_HEADER: &str = "LSAT";
pub const LSAT_HEADER_NAME: &str = "Accept-Authenticate";

pub const FREE_CONTENT_MESSAGE: &str = "Free Content";
pub const PROTECTED_CONTENT_MESSAGE: &str = "Protected Content";
pub const PAYMENT_REQUIRED_MESSAGE: &str = "Payment Required";

pub struct LsatInfo {
	pub	lsat_type: String,
	pub preimage: PaymentPreimage,
	pub payment_hash: PaymentHash,
	pub amount: u64,
	pub error: String
}

fn verify_lsat(
    mac: &Macaroon,
    conditions: Vec<Caveat>,
    root_key: Vec<u8>,
    preimage: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // caveat verification need to be done

    let macaroon_id = mac.identifier().clone();
    if macaroon_id == ByteString::from(preimage.clone()) {
        return Ok(());
    } else {
        println!("Invalid Preimage {:?} for PaymentHash {:?}", preimage, macaroon_id);
    }

    return Ok(());
}
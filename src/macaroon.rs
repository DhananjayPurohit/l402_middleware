use macaroon::{Macaroon, MacaroonKey, ByteString, Format};
use serde::{Deserialize, Serialize};
use lightning::ln::{PaymentHash};
use rocket::serde::json::from_slice;
use rand;
use hex;

pub fn get_macaroon_as_string(
    payment_hash: PaymentHash,
    caveats: &[String],
    root_key: Vec<u8>,
) -> Result<String, Box<dyn std::error::Error>> {
    let key = MacaroonKey::generate(&root_key);

    let mut mac = Macaroon::create(
        Some("LSAT".into()),
        &key,
        ByteString::from(hex::encode(payment_hash.0)),
    )?;

    for caveat in caveats {
        mac.add_first_party_caveat(ByteString::from(caveat.as_str()));
    }

    let mac_bytes = mac.serialize(Format::V1).unwrap();
    let macaroon_string = base64::encode(mac_bytes);

    Ok(macaroon_string)
}

fn generate_token_id() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut token_id: [u8; 32] = [0; 32];
    for i in 0..32 {
        let random_byte = rand::random::<u8>();
        token_id[i] = random_byte;
    }
    Ok(token_id)
}
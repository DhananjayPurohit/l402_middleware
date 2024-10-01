use macaroon::{Macaroon, MacaroonKey, ByteString, Format};
use serde::{Deserialize, Serialize};
use lightning::ln::{PaymentHash};

pub fn get_macaroon_as_string(
    payment_hash: PaymentHash,
    caveats: &[String],
    root_key: Vec<u8>,
) -> Result<String, Box<dyn std::error::Error>> {
    let key = MacaroonKey::generate(&root_key);

    let mut mac = Macaroon::create(
        Some("LSAT".into()),
        &key,
        payment_hash.0.into(),
    )?;

    for caveat in caveats {
        mac.add_first_party_caveat(ByteString::from(caveat.as_str()));
    }

    let mac_bytes = mac.serialize(Format::V1).unwrap();
    let macaroon_string = base64::encode(mac_bytes);

    Ok(macaroon_string)
}

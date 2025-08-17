use macaroon::{Macaroon, MacaroonKey, ByteString, Format};
use lightning::ln::{PaymentHash};
use crate::l402;

pub fn get_macaroon_as_string(
    payment_hash: PaymentHash,
    caveats: Vec<String>,
    root_key: Vec<u8>,
) -> Result<String, Box<dyn std::error::Error>> {
    let key = MacaroonKey::generate(&root_key);

    let mut mac = Macaroon::create(
        Some(l402::L402_HEADER.into()),
        &key,
        payment_hash.0.into(),
    )?;

    for caveat in caveats {
        mac.add_first_party_caveat(ByteString::from(caveat.as_str()));
    }

    let macaroon_string = mac.serialize(Format::V1).unwrap();

    Ok(macaroon_string)
}

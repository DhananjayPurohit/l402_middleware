use lightning::ln::{PaymentPreimage};
use macaroon::Macaroon;
use base64;
use hex;
use std::env;

pub fn parse_lsat_header(auth_field: &str) -> Result<(Macaroon, PaymentPreimage), String> {
    // Check if the authorization field is empty
    if auth_field.is_empty() {
      return Err(format!("Authorization field not present"));
    }
  
    let auth_field = auth_field.trim();
    if auth_field.is_empty() {
      return Err(format!("LSAT Header is not present"));
    }
  
    let token = auth_field.trim_start_matches("LSAT ");
    let splitted: Vec<&str> = token.split(':').map(|s| s.trim()).collect();
  
    if splitted.len() != 2 {
      return Err(format!("LSAT does not have the right format: {}", auth_field));
    }
  
    let macaroon_string = splitted[0].to_string();
    let preimage_string = splitted[1].to_string();
  
    let mac = get_macaroon_from_string(macaroon_string)?;
    let preimage = get_preimage_from_string(preimage_string)?;
  
    Ok((mac, preimage))
}

pub fn parse_ln_address(address: String) -> Result<(String, String), String> {
  let address = address.trim();
  let address_split = address.split("@").collect::<Vec<&str>>();

  if address_split.len() != 2 {
      return Err(format!("Invalid lightning address"));
  }

  let username = address_split[0].to_string();
  let domain = address_split[1].to_string();

  Ok((username, domain))
}

fn get_macaroon_from_string(macaroon_string: String) -> Result<Macaroon, String> {
    if macaroon_string.is_empty() || !base64::decode(&macaroon_string).is_ok() {
        return Err(format!("Invalid macaroon string"));
    }

    let mac_bytes = base64::decode(&macaroon_string).unwrap();
    let mac = Macaroon::deserialize(&mac_bytes).unwrap();

    Ok(mac)
}

fn get_preimage_from_string(preimage_string: String) -> Result<PaymentPreimage, String> {
  if preimage_string.is_empty() || !hex::decode(&preimage_string).is_ok() {
      return Err(format!("Invalid preimage string"));
  }

  let preimage_bytes = hex::decode(preimage_string).unwrap();
  let mut preimage_array = [0u8; 32];
  preimage_array.copy_from_slice(&preimage_bytes);
  let preimage = PaymentPreimage(preimage_array);
  Ok(preimage)
}

pub fn get_root_key() -> String {
    let root_key = env::var("ROOT_KEY")
        .unwrap();
    root_key
}
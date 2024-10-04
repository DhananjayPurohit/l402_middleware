use lightning::ln::{PaymentPreimage};
use macaroon::Macaroon;
use hex;

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

pub fn get_macaroon_from_string(macaroon_string: String) -> Result<Macaroon, String> {
  if macaroon_string.is_empty() {
    return Err("Macaroon string is empty".to_string());
  }

  let mac = Macaroon::deserialize(&macaroon_string)
    .map_err(|_| "Failed to deserialize macaroon".to_string())?;

  Ok(mac)
}

pub fn get_preimage_from_string(preimage_string: String) -> Result<PaymentPreimage, String> {
  if preimage_string.is_empty() {
    return Err("Preimage string is empty".to_string());
  }

  let preimage_bytes = match hex::decode(&preimage_string) {
    Ok(bytes) => bytes,
    Err(_) => return Err("Invalid hex in preimage string".to_string()),
  };

  if preimage_bytes.len() != 32 {
    return Err("Preimage must be exactly 32 bytes long".to_string());
  }

  let mut preimage_array = [0u8; 32];
  preimage_array.copy_from_slice(&preimage_bytes);

  Ok(PaymentPreimage(preimage_array))
}

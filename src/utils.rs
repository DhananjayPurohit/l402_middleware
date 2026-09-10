use lightning::types::payment::{PaymentPreimage};
use macaroon::Macaroon;
use hex;

pub fn parse_l402_header(auth_field: &str) -> Result<(Macaroon, PaymentPreimage), String> {
    // Check if the authorization field is empty
    if auth_field.is_empty() {
      return Err(format!("Authorization field not present"));
    }
  
    let auth_field = auth_field.trim();
    if auth_field.is_empty() {
      return Err(format!("L402 Header is not present"));
    }
  
    let token = auth_field.trim_start_matches("L402 ");
    let splitted: Vec<&str> = token.split(':').map(|s| s.trim()).collect();
  
    if splitted.len() != 2 {
      return Err(format!("L402 does not have the right format: {}", auth_field));
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

  // Both halves are interpolated into https://{domain}/.well-known/lnurlp/{username}
  // and fetched, so anything that can restructure that URL — '/', '?', '#', ':',
  // '..' — has to be rejected here. LUD-16 limits the username to a-z0-9-_. and
  // the domain is a hostname, so the allowed sets are narrow.
  let username_ok = !username.is_empty()
    && username != ".."
    && username
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
  if !username_ok {
    return Err("Invalid lightning address username".to_string());
  }

  let domain_ok = !domain.is_empty()
    && !domain.contains("..")
    && domain
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'));
  if !domain_ok {
    return Err("Invalid lightning address domain".to_string());
  }

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

#[cfg(test)]
mod tests {
  use super::parse_ln_address;

  #[test]
  fn ln_address_accepts_the_forms_lud16_allows() {
    // LUD-16 limits the username to a-z0-9-_. ; uppercase is accepted too since
    // providers vary. Domains: subdomains, punycode IDN, and v3 onion all pass
    // (the caller hardcodes https://, which is a separate pre-existing limit).
    for good in [
      "hello@getalby.com",
      "HELLO@getalby.com",
      "first.last@getalby.com",
      "a-b_c.d@pay.node.example.co.uk",
      "hello@xn--mnchen-3ya.de",
      "hello@duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    ] {
      assert!(
        parse_ln_address(good.to_string()).is_ok(),
        "must accept {good}"
      );
    }
  }

  #[test]
  fn ln_address_rejects_url_structure_injection() {
    assert_eq!(
      parse_ln_address("hello@getalby.com".to_string()).unwrap(),
      ("hello".to_string(), "getalby.com".to_string())
    );

    // Each of these would otherwise reach a different path or host than the
    // intended /.well-known/lnurlp/{username}.
    for bad in [
      "../../secret@getalby.com",
      "a/b@getalby.com",
      "a?x=1@getalby.com",
      "a#frag@getalby.com",
      "..@getalby.com",
      "@getalby.com",
      "hello@evil.com/path",
      "hello@evil.com:8080",
      "hello@",
    ] {
      assert!(
        parse_ln_address(bad.to_string()).is_err(),
        "must reject {bad}"
      );
    }
  }
}

#[macro_use] extern crate rocket;

use rocket::serde::json::Json;
use rocket::serde::Serialize;
use rocket::http::Status;
use rocket::Request;
use dotenv::dotenv;
use std::env;
use std::sync::Arc;
use reqwest::Client;

mod lsat;
mod middleware;
mod utils;
mod macaroon_util;
mod lnclient;
mod lnurl;
mod lnd;

const SATS_PER_BTC: i64 = 100_000_000;
const MIN_SATS_TO_BE_PAID: i64 = 1;

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]

pub struct FiatRateConfig {
    pub currency: String,
    pub amount: f64,
}

impl FiatRateConfig {
    pub async fn fiat_to_btc_amount_func(&self) -> i64 {
        // If amount is invalid, return the minimum sats.
        if self.amount <= 0.0 {
            return MIN_SATS_TO_BE_PAID;
        }

        // API request to get BTC equivalent of the fiat amount.
        let url = format!(
            "https://blockchain.info/tobtc?currency={}&value={}",
            self.currency, self.amount
        );

        match Client::new().get(&url).send().await {
            Ok(res) => {
                let body = res.text().await.unwrap_or_else(|_| MIN_SATS_TO_BE_PAID.to_string());
                match body.parse::<f64>() {
                    Ok(amount_in_btc) => (SATS_PER_BTC as f64 * amount_in_btc) as i64,
                    Err(_) => MIN_SATS_TO_BE_PAID,
                }
            }
            Err(_) => MIN_SATS_TO_BE_PAID,
        }
    }
}

fn path_caveat(req: &Request<'_>) -> Vec<String> {
    vec![
        format!("RequestPath = {}", req.uri().path()),
    ]
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]

struct Response {
    code: u16,
    message: String
}

#[get("/")]
fn free() -> (Status, Json<Response>) {
    let response = Response {
        code: Status::Ok.code,
        message: String::from("Free content"),
    };

    (Status::Ok, Json(response))
}

#[get("/protected")]
fn protected(lsat_info: lsat::LsatInfo) -> (Status, Json<Response>) {
    let (status, message) = match lsat_info.lsat_type.as_str() {
        lsat::LSAT_TYPE_FREE => (Status::Ok, String::from("Free content")),
        lsat::LSAT_TYPE_PAYMENT_REQUIRED => (Status::PaymentRequired, String::from("Pay the invoice attached in response header")),
        lsat::LSAT_TYPE_PAID => (Status::Ok, String::from("Protected content")),
        lsat::LSAT_TYPE_ERROR => (
            Status::InternalServerError,
            lsat_info.error.clone().unwrap_or_else(|| String::from("An error occurred")),
        ),
        _ => (Status::InternalServerError, String::from("Unknown type")),
    };

    let response = Response {
        code: status.code,
        message,
    };

    (status, Json(response))
}

#[launch]
pub async fn rocket() -> rocket::Rocket<rocket::Build> {
     // Load environment variables from .env file
    dotenv().ok();

    let ln_client_config = lnclient::LNClientConfig {
        ln_client_type: env::var("LN_CLIENT_TYPE").expect("LN_CLIENT_TYPE not found in .env"),
        lnd_config: lnd::LNDOptions {
            address: env::var("LND_ADDRESS").expect("LND_ADDRESS not found in .env"),
            macaroon_hex: Some(env::var("MACAROON_HEX").expect("MACAROON_HEX not found in .env")),
            cert_file: None,
            cert_hex: None,
            macaroon_file: None,
        },
        lnurl_config: lnurl::LNURLOptions {
            address: env::var("LNURL_ADDRESS").expect("LNURL_ADDRESS not found in .env"),
        },
        root_key: env::var("ROOT_KEY")
            .expect("ROOT_KEY not found in .env")
            .as_bytes()
            .to_vec(),
    };

    // Initialize Fiat Rate Config
    let fiat_rate_config = Arc::new(FiatRateConfig {
        currency: "USD".to_string(),
        amount: 0.01,
    });

    let lsat_middleware = middleware::LsatMiddleware::new_lsat_middleware(
        ln_client_config.clone(),
        Arc::new(move |_req: &Request<'_>| {
            let fiat_rate_config = Arc::clone(&fiat_rate_config);
            Box::pin(async move {
                fiat_rate_config.fiat_to_btc_amount_func().await
            })
        }),
        Arc::new(move |req: &Request<'_>| {
            path_caveat(req)
        }),
    ).await.unwrap();

    rocket::build()
        .attach(lsat_middleware)
        .mount("/", routes![free, protected])
}

#[cfg(test)]
mod tests {
    use rocket::http::{Status, Header};
    use rocket::local::asynchronous::Client;
    use rocket::serde::json::Value;
    use super::rocket;
    use lightning::ln::PaymentHash;

    use crate::lsat;
    use crate::utils;

    const TEST_MACAROON_VALID: &str = "MDAxMmxvY2F0aW9uIExTQVQKMDAzMGlkZW50aWZpZXIgjWsDO3viVp1lHXWoaN1CiUFeRdn8Z9Zl1AUIfJHKoCkKMDAyMWNpZCBSZXF1ZXN0UGF0aCA9IC9wcm90ZWN0ZWQKMDAyZnNpZ25hdHVyZSBZJ8RYr2biQ9CRoCxMcmWBObW7L7nS1bvFduQXRIQcJwo=";
	const TEST_PREIMAGE_VALID: &str = "7c9d69d87a1af5d06ecebee2b095e49423400cf4f1d650292e0256ccea8b2ae2";

	const TEST_MACAROON_WITHOUT_CAVEATS: &str = "AgEETFNBVALmAUr/gQMBARJNYWNhcm9vbklkZW50aWZpZXIB/4IAAQMBB1ZlcnNpb24BBgABC1BheW1lbnRIYXNoAf+EAAEHVG9rZW5JZAH/hgAAABT/gwEBAQRIYXNoAf+EAAEGAUAAABn/hQEBAQlbMzJddWludDgB/4YAAQYBQAAAa/+CAiD/pv/jOjY1/9oC/4z/tHb/qf/2Jf+d/4H/u/+YGHj/+/+O/8D/v/+P/8X/qRL/5v/x/4r/tkIBIA1Y/8j/pR3/0P+b/7cwWP+W/87/sD18GP//Hf/f/9Aj//NcBFs2/9VhNEUF/70AAAAGIDlR1jVm5IfEJgvuSQoJLqLg4FcW4Ib1vW8sbkRHdUWX";
	const TEST_MACAROON_WITHOUT_CAVEATS_PREIMAGE: &str = "651505fae9ea341c770c6ebef207d8560d546eb3aee26985e584c15d1c987875";

	const TEST_PREIMAGE_INVALID: &str = "fbe9ac25c04e14b10177514e2d57b0e39224e70277ac1a2cd23c28e58cd4ea35";

    #[rocket::async_test]
    async fn test_free_route() {
        let client = Client::tracked(rocket().await).await.expect("valid rocket instance");
        let response = client.get("/").dispatch().await;
        
        assert_eq!(response.status(), Status::Ok);

        let json: Value = response.into_json().await.expect("valid JSON response");
        assert_eq!(json["code"], 200);
        assert_eq!(json["message"], "Free content");
    }

    #[rocket::async_test]
    async fn test_protected_route_free_content() {
        let client = Client::tracked(rocket().await).await.expect("valid rocket instance");
        let response = client.get("/protected").dispatch().await;
        
        assert_eq!(response.status(), Status::InternalServerError);

        let json: Value = response.into_json().await.expect("valid JSON response");
        assert_eq!(json["code"], 500);
        assert_eq!(json["message"], "No LSAT header present");
    }

    #[rocket::async_test]
    async fn test_protected_route_payment_required() {
        let client = Client::tracked(rocket().await).await.expect("valid rocket instance");
        let response = client.get("/protected")
                        .header(Header::new(lsat::LSAT_HEADER_NAME, lsat::LSAT_HEADER))
                        .dispatch().await;
        
        assert_eq!(response.status(), Status::PaymentRequired);

        let www_authenticate_header = response.headers().get_one(lsat::LSAT_AUTHENTICATE_HEADER_NAME).unwrap();
        assert!(www_authenticate_header.starts_with("LSAT macaroon="));
        assert!(www_authenticate_header.contains("invoice="));

        let json: Value = response.into_json().await.expect("valid JSON response");
        assert_eq!(json["code"], 402);
        assert_eq!(json["message"], "Pay the invoice attached in response header");
    }

    #[tokio::test]
    async fn test_protected_route_with_valid_lsat() {
        let client = Client::tracked(rocket().await).await.expect("valid rocket instance");
        let response = client.get("/protected")
                        .header(Header::new(lsat::LSAT_AUTHORIZATION_HEADER_NAME, format!("LSAT {}:{}", TEST_MACAROON_VALID, TEST_PREIMAGE_VALID)))
                        .dispatch().await;

        assert_eq!(response.status(), Status::Ok);

        let json: Value = response.into_json().await.expect("valid JSON response");
        assert_eq!(json["code"], 200);
        assert_eq!(json["message"], "Protected content");
    }

    #[tokio::test]
    async fn test_protected_route_with_invalid_preimage() {
        let client = Client::tracked(rocket().await).await.expect("valid rocket instance");
        let response = client.get("/protected")
                        .header(Header::new(lsat::LSAT_AUTHORIZATION_HEADER_NAME, format!("LSAT {}:{}", TEST_MACAROON_VALID, TEST_PREIMAGE_INVALID)))
                        .dispatch().await;

        assert_eq!(response.status(), Status::InternalServerError);

        let mac = utils::get_macaroon_from_string(TEST_MACAROON_VALID.to_string()).unwrap();
        let macaroon_id = mac.identifier().clone();
        let macaroon_id_hex = hex::encode(macaroon_id.0).replace("ff", "");
        let preimage = utils::get_preimage_from_string(TEST_PREIMAGE_INVALID.to_string()).unwrap();
        let payment_hash: PaymentHash = PaymentHash::from(preimage);
        let payment_hash_hex = hex::encode(payment_hash.0);

        let json: Value = response.into_json().await.expect("valid JSON response");
        assert_eq!(json["code"], 500);
        assert_eq!(json["message"], format!("Invalid PaymentHash {} for macaroon {}", payment_hash_hex, macaroon_id_hex));
    }

    #[tokio::test]
    async fn test_protected_route_with_macaroon_without_caveats() {
        let client = Client::tracked(rocket().await).await.expect("valid rocket instance");
        let response = client.get("/protected")
                        .header(Header::new(lsat::LSAT_AUTHORIZATION_HEADER_NAME, format!("LSAT {}:{}", TEST_MACAROON_WITHOUT_CAVEATS, TEST_MACAROON_WITHOUT_CAVEATS_PREIMAGE)))
                        .dispatch().await;

        assert_eq!(response.status(), Status::InternalServerError);

        let json: Value = response.into_json().await.expect("valid JSON response");
        assert_eq!(json["code"], 500);
        assert_eq!(json["message"], "Error validating macaroon: Caveats don't match");
    }
}

# lsat-middleware-rs
A middleware library for rust that uses [LSAT](https://github.com/lightninglabs/L402/blob/master/protocol-specification.md) (a protocol standard for authentication and paid APIs) and provides handler functions to accept microtransactions before serving ad-free content or any paid APIs.

Check out the Go version here:
https://github.com/getAlby/lsat-middleware

The middleware:-

1. Checks the preference of the user whether they need paid content or free content.
2. Verify the LSAT before serving paid content.
3. Send macaroon and invoice if the user prefers paid content and fails to present a valid LSAT.

![186736015-f956dfe1-cba0-4dc3-9755-9d22cb1c7e77](https://github.com/user-attachments/assets/afc099e2-d0b8-4344-9665-17a81f6907bc)


## Installation

Add the crate to your `Cargo.toml`:
```toml
[dependencies]
lsat-middleware-rs = { git = "https://github.com/DhananjayPurohit/lsat-middleware-rs" }
```

Ensure that you create a `.env` file based on the provided `.env_example` and configure all the necessary environment variables.

## Example
```rust
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

    // Get LN_CLIENT_TYPE from the environment
    let ln_client_type = env::var("LN_CLIENT_TYPE").expect("LN_CLIENT_TYPE not found in .env");

    // Initialize LNClientConfig based on LN_CLIENT_TYPE
    let ln_client_config = match ln_client_type.as_str() {
        "LNURL" => lnclient::LNClientConfig {
            ln_client_type,
            lnd_config: None,
            lnurl_config: Some(lnurl::LNURLOptions {
                address: env::var("LNURL_ADDRESS").expect("LNURL_ADDRESS not found in .env"),
            }),
            root_key: env::var("ROOT_KEY")
                .expect("ROOT_KEY not found in .env")
                .as_bytes()
                .to_vec(),
        },
        "LND" => lnclient::LNClientConfig {
            ln_client_type,
            lnd_config: Some(lnd::LNDOptions {
                address: env::var("LND_ADDRESS").expect("LND_ADDRESS not found in .env"),
                macaroon_file: env::var("MACAROON_FILE_PATH").expect("MACAROON_FILE_PATH not found in .env"),
                cert_file: env::var("CERT_FILE_PATH").expect("CERT_FILE_PATH not found in .env"),
            }),
            lnurl_config: None,
            root_key: env::var("ROOT_KEY")
                .expect("ROOT_KEY not found in .env")
                .as_bytes()
                .to_vec(),
        },
        _ => panic!("Invalid LN_CLIENT_TYPE. Expected 'LNURL' or 'LND'."),
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
```

## Testing

Run `cargo test` to run tests.

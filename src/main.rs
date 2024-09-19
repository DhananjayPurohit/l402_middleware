#[macro_use] extern crate rocket;

use rocket::serde::json::Json;
use rocket::serde::Serialize;
use rocket::http::Status;
use rocket::Request;
use lightning::ln::{PaymentPreimage, PaymentHash};
use dotenv::dotenv;
use std::env;
use std::sync::Arc;
use reqwest::Client;
use futures::executor::block_on;

mod lsat;
mod middleware;
mod utils;
mod macaroon;
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
    pub fn fiat_to_btc_amount_func(&self) -> i64 {
        // If amount is invalid, return the minimum sats.
        let future = async {
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
        };

        block_on(future)
    }
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]

struct Response {
    code: u16,
    message: String
}

#[get("/")]
fn free() -> Json<Response> {
    let response = Response {
        code: Status::Ok.code,
        message: String::from("Free content"),
    };

    Json(response)
}

#[get("/protected")]
fn protected() -> Json<Response> {
    // let lsatInfo = request.headers().get_one("LSAT").unwrap() as lsat::&LsatInfo;
    let lsat_info = lsat::LsatInfo {
        lsat_type: String::from("PAID"),
        preimage: PaymentPreimage([0; 32]),
        payment_hash: PaymentHash([0; 32]),
        amount: 10000,
        error: String::from("Error")
    };
    let lsat_info_type = lsat_info.lsat_type.to_string();
    let response = match lsat_info_type.as_str() {
        lsat::LSAT_TYPE_FREE => {
            Response {
                code: Status::Ok.code,
                message: String::from("Free content"),
            }
        }
        lsat::LSAT_TYPE_PAID => {
            Response {
                code: Status::Ok.code,
                message: String::from("Protected content"),
            }
        }
        lsat::LSAT_TYPE_ERROR => {
            Response {
                code: Status::InternalServerError.code,
                message: format!("{}", lsat_info.error),
            }
        }
        _ => {
            // Handle other cases
            Response {
                code: Status::InternalServerError.code,
                message: String::from("Unknown type"),
            }
        }
    };

    Json(response)
}

#[launch]
fn rocket() -> rocket::Rocket<rocket::Build> {
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
    let fiat_rate_config = FiatRateConfig {
        currency: "USD".to_string(),
        amount: 0.01,
    };

    let lsat_middleware = middleware::new_lsat_middleware(
        ln_client_config.clone(),
        Arc::new(move |_req: &Request<'_>| fiat_rate_config.fiat_to_btc_amount_func())
    );

    rocket::build()
        .attach(rocket::fairing::AdHoc::on_ignite("LsatMiddleware", |rocket| async {
            rocket.manage(lsat_middleware)
        }))
        .mount("/", routes![free, protected])
}
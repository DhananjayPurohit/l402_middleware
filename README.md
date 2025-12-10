# l402_middleware
A middleware library for rust that uses [L402, formerly known as LSAT](https://github.com/lightninglabs/L402/blob/master/protocol-specification.md) (a protocol standard for authentication and paid APIs) and provides handler functions to accept microtransactions before serving ad-free content or any paid APIs. It supports Lightning Network Daemon (LND), Core Lightning (CLN), Lightning URL (LNURL), and Nostr Wallet Connect (NWC) for generating invoices.

Check out the Go version here:
https://github.com/getAlby/lsat-middleware

The middleware:-

1. Checks the preference of the user whether they need paid content or free content.
2. Verify the L402 before serving paid content.
3. Send macaroon and invoice if the user prefers paid content and fails to present a valid L402.

![186736015-f956dfe1-cba0-4dc3-9755-9d22cb1c7e77](https://github.com/user-attachments/assets/afc099e2-d0b8-4344-9665-17a81f6907bc)


## L402 Header Specifications

| **Header**            | **Description**                                                                                            | **Usage**                                                                                                  | **Example**                                                                                                                                   |
|-----------------------|------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| **Accept-Authenticate** | Sent by the client to show interest in using L402 for authentication. | Used when the client wants to explore authentication options under L402. | `Accept-Authenticate: L402` |
| **WWW-Authenticate**   | Sent by the server to request L402 authentication, providing a macaroon and a payment invoice.             | Used when the client must pay or authenticate to access a resource.                                         | `WWW-Authenticate: L402 macaroon="MDAxM...", invoice="lnbc1..."`                                                                              |
| **Authorization**      | Sent by the client to provide the macaroon and preimage (proof of payment) to access the resource.         | Used by the client after payment or authentication to prove access rights.                                  | `Authorization: L402 <macaroon>:<preimage>`                                                                                                  |


## Installation

Add the crate to your `Cargo.toml`:
```toml
[dependencies]
l402_middleware = "1.9.0"
```

By using the no-accept-authenticate-required feature, the check for the Accept-Authenticate header can be bypassed, allowing L402 to be treated as the default authentication option.
```toml
[dependencies]
l402_middleware = { version = "1.9.0", features = ["no-accept-authenticate-required"] }
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

use l402_middleware::{l402, lnclient, lnd, lnurl, nwc, cln, middleware};

const SATS_PER_BTC: i64 = 100_000_000;
const MIN_SATS_TO_BE_PAID: i64 = 1;
const MSAT_PER_SAT: i64 = 1000;

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]

pub struct FiatRateConfig {
    pub currency: String,
    pub amount: f64,
}

impl FiatRateConfig {
     // Converts fiat amount to BTC equivalent in millisats. Customization possible for different API endpoints.
    pub async fn fiat_to_btc_amount_func(&self) -> i64 {
        // Return the minimum sats if the amount is invalid.
        if self.amount <= 0.0 {
            return MIN_SATS_TO_BE_PAID * MSAT_PER_SAT;
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
                    Ok(amount_in_btc) => ((SATS_PER_BTC as f64 * amount_in_btc) * MSAT_PER_SAT as f64) as i64,
                    Err(_) => MIN_SATS_TO_BE_PAID * MSAT_PER_SAT,
                }
            }
            Err(_) => MIN_SATS_TO_BE_PAID * MSAT_PER_SAT,
        }
    }
}

// Function to add caveats, can customize it based on authentication needs
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
fn protected(l402_info: l402::L402Info) -> (Status, Json<Response>) {
    let (status, message) = match l402_info.l402_type.as_str() {
        l402::L402_TYPE_FREE => (Status::Ok, String::from("Free content")),
        l402::L402_TYPE_PAYMENT_REQUIRED => (Status::PaymentRequired, String::from("Pay the invoice attached in response header")),
        l402::L402_TYPE_PAID => (Status::Ok, String::from("Protected content")),
        l402::L402_TYPE_ERROR => (
            Status::InternalServerError,
            l402_info.error.clone().unwrap_or_else(|| String::from("An error occurred")),
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
            nwc_config: None,
            cln_config: None,
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
                socks5_proxy: env::var("SOCKS5_PROXY").ok(), // Optional: e.g., "127.0.0.1:9050" for Tor
            }),
            lnurl_config: None,
            nwc_config: None,
            cln_config: None,
            root_key: env::var("ROOT_KEY")
                .expect("ROOT_KEY not found in .env")
                .as_bytes()
                .to_vec(),
        },
        "NWC" => lnclient::LNClientConfig {
            ln_client_type,
            lnd_config: None,
            lnurl_config: None,
            cln_config: None,
            nwc_config: Some(nwc::NWCOptions {
                uri: env::var("NWC_URI").expect("NWC_URI not found in .env"),
            }),
            root_key: env::var("ROOT_KEY")
                .expect("ROOT_KEY not found in .env")
                .as_bytes()
                .to_vec(),
        },
        "CLN" => lnclient::LNClientConfig {
            ln_client_type,
            lnd_config: None,
            lnurl_config: None,
            nwc_config: None,
            cln_config: Some(cln::CLNOptions {
                lightning_dir: env::var("CLN_LIGHTNING_RPC_FILE_PATH").expect("CLN_LIGHTNING_RPC_FILE_PATH not found in .env"),
            }),
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

    let l402_middleware = middleware::L402Middleware::new_l402_middleware(
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
        .attach(l402_middleware)
        .mount("/", routes![free, protected])
}
```

## Testing

Run tests with:
- `cargo test --verbose` for standard tests
- `cargo test --verbose --features "no-accept-authenticate-required"` to run tests with accept-authenticate header requirements disabled

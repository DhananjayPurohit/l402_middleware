use rocket::{Request};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::Data;
use std::sync::Arc;
use std::error::Error;

use crate::utils;
use crate::lsat;
use crate::lnclient;

type AmountFunc = Arc<dyn Fn(&Request<'_>) -> i64 + Send + Sync>;

pub struct LsatMiddleware {
    pub amount_func: AmountFunc,
    pub ln_client: Arc<dyn lnclient::LNClient>,
    pub root_key: Vec<u8>,
}

pub async fn new_lsat_middleware(
    ln_client_config: lnclient::LNClientConfig,
    amount_f: AmountFunc,
) -> Result<LsatMiddleware, Box<dyn Error>> {
    // Initialize the LNClient using the configuration
    let ln_client = lnclient::LNClientConn::init(&ln_client_config)?;

    // Create and return the LsatMiddleware instance
    Ok(LsatMiddleware {
        amount_func: amount_f,
        ln_client,
        root_key: ln_client_config.root_key.clone(),
    })
}

#[rocket::async_trait]
impl Fairing for LsatMiddleware {
    fn info(&self) -> Info {
        Info {
            name: "Lsat Middleware",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        if let Some(auth_field) = request.headers().get_one("Authorization") {
            match utils::parse_lsat_header(auth_field) {
                Ok((mac, preimage)) => {
                    if let Some(accept_lsat_field) = request.headers().get_one(lsat::LSAT_HEADER_NAME) {
                        if accept_lsat_field.contains(lsat::LSAT_HEADER) {
                            
                        }
                    }
                },
                Err(error) => {
                    println!("Error parsing LSAT header: {}", error);
                },
            }
        }
    }
}

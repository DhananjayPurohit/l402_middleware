use rocket::{Request, Data};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Header, Status};
use rocket::response::status;
use rocket::serde::json::{json, Json};
use std::sync::{Arc, Mutex};
use std::error::Error;
use lightning::ln::PaymentHash;
use tonic_openssl_lnd::lnrpc;
use std::pin::Pin;
use std::future::Future;

use crate::utils;
use crate::lsat;
use crate::lnclient;
use crate::macaroon::get_macaroon_as_string;

type AmountFunc = Arc<dyn Fn(&Request<'_>) -> Pin<Box<dyn Future<Output = i64> + Send>> + Send + Sync>;

pub struct LsatMiddleware {
    pub amount_func: AmountFunc,
    pub ln_client: Arc<Mutex<dyn lnclient::LNClient>>,
    pub root_key: Vec<u8>,
}

impl LsatMiddleware {
    pub async fn new_lsat_middleware(
        ln_client_config: lnclient::LNClientConfig,
        amount_func: AmountFunc,
    ) -> Result<LsatMiddleware, Box<dyn Error + Send + Sync>> {
        // Initialize the LNClient using the configuration
        let ln_client = lnclient::LNClientConn::init(&ln_client_config).await?;
    
        // Create and return the LsatMiddleware instance
        Ok(LsatMiddleware {
            amount_func: amount_func,
            ln_client,
            root_key: ln_client_config.root_key.clone(),
        })
    }

    pub async fn set_lsat_header(&self, request: &mut Request<'_>) {
        let ln_invoice = lnrpc::Invoice {
            value: (self.amount_func)(request).await,
            memo: "LSAT".to_string(),
            ..Default::default()
        };
        let ln_client_conn = lnclient::LNClientConn{
            ln_client: self.ln_client.clone(),
        };
        match ln_client_conn.generate_invoice(ln_invoice) {
            Ok((invoice, payment_hash)) => {
                match get_macaroon_as_string(payment_hash, &[], self.root_key.clone()) {
                    Ok(macaroon_string) => {
                        request.add_header(Header::new(
                            "WWW-Authenticate",
                            format!("LSAT macaroon={}, invoice={}", macaroon_string, invoice)
                        ));
                    },
                    Err(error) => {
                        request.local_cache(|| lsat::LsatInfo {
                            lsat_type: lsat::LSAT_TYPE_ERROR.to_string(),
                            error: Some(error.to_string()),
                            preimage: None,
                            payment_hash: None,
                        });
                    }
                }
            },
            Err(error) => {
                request.local_cache(|| lsat::LsatInfo {
                    lsat_type: lsat::LSAT_TYPE_ERROR.to_string(),
                    error: Some(error.to_string()),
                    preimage: None,
                    payment_hash: None,
                });
            },
        }
    }
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
                    match lsat::verify_lsat(&mac, self.root_key.clone(), preimage) {
                        Ok(_) => {
                            let payment_hash: PaymentHash = PaymentHash::from(preimage);
                            request.local_cache(|| lsat::LsatInfo {
                                lsat_type: lsat::LSAT_TYPE_PAID.to_string(),
                                preimage: Some(preimage),
                                payment_hash: Some(payment_hash),
                                error: None,
                            });
                        },
                        Err(error) => {
                            request.local_cache(|| lsat::LsatInfo {
                                lsat_type: lsat::LSAT_TYPE_ERROR.to_string(),
                                error: Some(error.to_string()),
                                preimage: None,
                                payment_hash: None,
                            });
                            println!("Error verifying LSAT: {}", error);
                        }
                    }
                },
                Err(error) => {
                    if let Some(accept_lsat_field) = request.headers().get_one(lsat::LSAT_HEADER_NAME) {
                        if accept_lsat_field.contains(lsat::LSAT_HEADER) {
                            LsatMiddleware::set_lsat_header(self, request).await;
                        } else {
                            request.local_cache(|| lsat::LsatInfo {
                                lsat_type: lsat::LSAT_TYPE_FREE.to_string(),
                                preimage: None,
                                payment_hash: None,
                                error: None,
                            });
                        }
                    } else {
                        request.local_cache(|| lsat::LsatInfo {
                            lsat_type: lsat::LSAT_TYPE_ERROR.to_string(),
                            error: Some(error.to_string()),
                            preimage: None,
                            payment_hash: None,
                        });
                        println!("Error parsing LSAT: {}", error);
                    }
                },
            }
        } else {
            if let Some(accept_lsat_field) = request.headers().get_one(lsat::LSAT_HEADER_NAME) {
                if accept_lsat_field.contains(lsat::LSAT_HEADER) {
                    LsatMiddleware::set_lsat_header(self, request).await;
                } else {
                    request.local_cache(|| lsat::LsatInfo {
                        lsat_type: lsat::LSAT_TYPE_FREE.to_string(),
                        preimage: None,
                        payment_hash: None,
                        error: None,
                    });
                }
            }
        }
    }
}

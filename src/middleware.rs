use rocket::{Request, Response, Data};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use std::sync::Arc;
use std::error::Error;
use lightning::ln::PaymentHash;
use tonic_openssl_lnd::lnrpc;
use std::pin::Pin;
use std::future::Future;
use tokio::sync::Mutex;
use macaroon::Caveat;

use crate::utils;
use crate::lsat;
use crate::lnclient;
use crate::macaroon_util::get_macaroon_as_string;

type AmountFunc = Arc<dyn Fn(&Request<'_>) -> Pin<Box<dyn Future<Output = i64> + Send>> + Send + Sync>;

type CaveatFunc = Arc<dyn Fn(&Request<'_>) -> Vec<String> + Send + Sync>;

pub struct LsatMiddleware {
    pub amount_func: AmountFunc,
    pub caveat_func: CaveatFunc,
    pub ln_client: Arc<Mutex<dyn lnclient::LNClient>>,
    pub root_key: Vec<u8>,
}

impl LsatMiddleware {
    pub async fn new_lsat_middleware(
        ln_client_config: lnclient::LNClientConfig,
        amount_func: AmountFunc,
        caveat_func: CaveatFunc,
    ) -> Result<LsatMiddleware, Box<dyn Error + Send + Sync>> {
        // Initialize the LNClient using the configuration
        let ln_client = lnclient::LNClientConn::init(&ln_client_config).await?;
    
        // Create and return the LsatMiddleware instance
        Ok(LsatMiddleware {
            amount_func: amount_func,
            caveat_func: caveat_func,
            ln_client,
            root_key: ln_client_config.root_key.clone(),
        })
    }

    pub async fn set_lsat_header(&self, request: &mut Request<'_>, caveats: Vec<String>) {
        let ln_invoice = lnrpc::Invoice {
            value: (self.amount_func)(request).await,
            memo: "LSAT".to_string(),
            ..Default::default()
        };
        let ln_client_conn = lnclient::LNClientConn{
            ln_client: self.ln_client.clone(),
        };
        match ln_client_conn.generate_invoice(ln_invoice).await {
            Ok((invoice, payment_hash)) => {
                match get_macaroon_as_string(payment_hash, caveats, self.root_key.clone()) {
                    Ok(macaroon_string) => {
                        request.local_cache(|| lsat::LsatInfo {
                            lsat_type: lsat::LSAT_TYPE_PAYMENT_REQUIRED.to_string(),
                            preimage: None,
                            payment_hash: None,
                            error: None,
                            auth_header: format!("LSAT macaroon={}, invoice={}", macaroon_string, invoice).into(),
                        });
                    },
                    Err(error) => {
                        request.local_cache(|| lsat::LsatInfo {
                            lsat_type: lsat::LSAT_TYPE_ERROR.to_string(),
                            error: Some(error.to_string()),
                            preimage: None,
                            payment_hash: None,
                            auth_header: None,
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
                    auth_header: None,
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
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        let mut caveats: Vec<String> = Vec::new();
        let caveat_func = Arc::clone(&self.caveat_func);
        caveats = caveat_func(request);
        if let Some(auth_field) = request.headers().get_one("Authorization") {
            match utils::parse_lsat_header(auth_field) {
                Ok((mac, preimage)) => {
                    match lsat::verify_lsat(&mac, caveats, self.root_key.clone(), preimage) {
                        Ok(_) => {
                            let payment_hash: PaymentHash = PaymentHash::from(preimage);
                            request.local_cache(|| lsat::LsatInfo {
                                lsat_type: lsat::LSAT_TYPE_PAID.to_string(),
                                preimage: Some(preimage),
                                payment_hash: Some(payment_hash),
                                error: None,
                                auth_header: None,
                            });
                        },
                        Err(error) => {
                            request.local_cache(|| lsat::LsatInfo {
                                lsat_type: lsat::LSAT_TYPE_ERROR.to_string(),
                                error: Some(error.to_string()),
                                preimage: None,
                                payment_hash: None,
                                auth_header: None,
                            });
                            println!("Error verifying LSAT: {}", error);
                        }
                    }
                },
                Err(error) => {
                    if let Some(accept_lsat_field) = request.headers().get_one(lsat::LSAT_HEADER_NAME) {
                        if accept_lsat_field.contains(lsat::LSAT_HEADER) {
                            LsatMiddleware::set_lsat_header(self, request, caveats).await;
                        } else {
                            request.local_cache(|| lsat::LsatInfo {
                                lsat_type: lsat::LSAT_TYPE_FREE.to_string(),
                                preimage: None,
                                payment_hash: None,
                                error: None,
                                auth_header: None,
                            });
                        }
                    } else {
                        request.local_cache(|| lsat::LsatInfo {
                            lsat_type: lsat::LSAT_TYPE_ERROR.to_string(),
                            error: Some(error.to_string()),
                            preimage: None,
                            payment_hash: None,
                            auth_header: None,
                        });
                        println!("Error parsing LSAT: {}", error);
                    }
                },
            }
        } else {
            if let Some(accept_lsat_field) = request.headers().get_one(lsat::LSAT_HEADER_NAME) {
                if accept_lsat_field.contains(lsat::LSAT_HEADER) {
                    LsatMiddleware::set_lsat_header(self, request, caveats).await;
                    request.local_cache(|| lsat::LsatInfo {
                        lsat_type: lsat::LSAT_TYPE_PAYMENT_REQUIRED.to_string(),
                        preimage: None,
                        payment_hash: None,
                        error: None,
                        auth_header: None,
                    });
                } else {
                    request.local_cache(|| lsat::LsatInfo {
                        lsat_type: lsat::LSAT_TYPE_FREE.to_string(),
                        preimage: None,
                        payment_hash: None,
                        error: None,
                        auth_header: None,
                    });
                }
            }
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // Retrieve LsatInfo from the local cache
        let lsat_info = request.local_cache::<lsat::LsatInfo, _>(|| {
            lsat::LsatInfo {
                lsat_type: lsat::LSAT_TYPE_ERROR.to_string(),
                error: Some("No LSAT header present".to_string()),
                preimage: None,
                payment_hash: None,
                auth_header: None,
            }
        });

        // Check if the auth header is set and add it to the response
        if let Some(header_value) = &lsat_info.auth_header {
            response.set_header(Header::new("WWW-Authenticate", header_value));
        }
    }
}

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

use crate::utils;
use crate::l402;
use crate::lnclient;
use crate::macaroon_util::get_macaroon_as_string;

type AmountFunc = Arc<dyn Fn(&Request<'_>) -> Pin<Box<dyn Future<Output = i64> + Send>> + Send + Sync>;

type CaveatFunc = Arc<dyn Fn(&Request<'_>) -> Vec<String> + Send + Sync>;

pub struct L402Middleware {
    pub amount_func: AmountFunc,
    pub caveat_func: CaveatFunc,
    pub ln_client: Arc<Mutex<dyn lnclient::LNClient>>,
    pub root_key: Vec<u8>,
}

impl L402Middleware {
    pub async fn new_l402_middleware(
        ln_client_config: lnclient::LNClientConfig,
        amount_func: AmountFunc,
        caveat_func: CaveatFunc,
    ) -> Result<L402Middleware, Box<dyn Error + Send + Sync>> {
        // Initialize the LNClient using the configuration
        let ln_client = lnclient::LNClientConn::init(&ln_client_config).await?;
    
        // Create and return the L402Middleware instance
        Ok(L402Middleware {
            amount_func: amount_func,
            caveat_func: caveat_func,
            ln_client,
            root_key: ln_client_config.root_key.clone(),
        })
    }

    pub async fn set_l402_header(&self, request: &mut Request<'_>, caveats: Vec<String>) {
        let ln_invoice = lnrpc::Invoice {
            value_msat: (self.amount_func)(request).await,
            memo: l402::L402_HEADER.to_string(),
            ..Default::default()
        };
        let ln_client_conn = lnclient::LNClientConn{
            ln_client: self.ln_client.clone(),
        };
        match ln_client_conn.generate_invoice(ln_invoice).await {
            Ok((invoice, payment_hash)) => {
                match get_macaroon_as_string(payment_hash, caveats, self.root_key.clone()) {
                    Ok(macaroon_string) => {
                        request.local_cache(|| l402::L402Info {
                            l402_type: l402::L402_TYPE_PAYMENT_REQUIRED.to_string(),
                            preimage: None,
                            payment_hash: None,
                            error: None,
                            auth_header: format!("L402 macaroon={}, invoice={}", macaroon_string, invoice).into(),
                        });
                    },
                    Err(error) => {
                        request.local_cache(|| l402::L402Info {
                            l402_type: l402::L402_TYPE_ERROR.to_string(),
                            error: Some(error.to_string()),
                            preimage: None,
                            payment_hash: None,
                            auth_header: None,
                        });
                    }
                }
            },
            Err(error) => {
                request.local_cache(|| l402::L402Info {
                    l402_type: l402::L402_TYPE_ERROR.to_string(),
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
impl Fairing for L402Middleware {
    fn info(&self) -> Info {
        Info {
            name: "L402 Middleware",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        let caveat_func = Arc::clone(&self.caveat_func);
        let caveats = caveat_func(request);
        if let Some(auth_field) = request.headers().get_one(l402::L402_AUTHORIZATION_HEADER_NAME) {
            match utils::parse_l402_header(auth_field) {
                Ok((mac, preimage)) => {
                    match l402::verify_l402(&mac, caveats, self.root_key.clone(), preimage) {
                        Ok(_) => {
                            let payment_hash: PaymentHash = PaymentHash::from(preimage);
                            request.local_cache(|| l402::L402Info {
                                l402_type: l402::L402_TYPE_PAID.to_string(),
                                preimage: Some(preimage),
                                payment_hash: Some(payment_hash),
                                error: None,
                                auth_header: None,
                            });
                        },
                        Err(error) => {
                            request.local_cache(|| l402::L402Info {
                                l402_type: l402::L402_TYPE_ERROR.to_string(),
                                error: Some(error.to_string()),
                                preimage: None,
                                payment_hash: None,
                                auth_header: None,
                            });
                            println!("Error verifying L402: {}", error);
                        }
                    }
                },
                Err(error) => {
                    #[cfg(feature = "no-accept-authenticate-required")]
                    L402Middleware::set_l402_header(self, request, caveats).await;

                    #[cfg(not(feature = "no-accept-authenticate-required"))]
                    if let Some(accept_l402_field) = request.headers().get_one(l402::L402_HEADER_NAME) {
                        if accept_l402_field.contains(l402::L402_HEADER) {
                            L402Middleware::set_l402_header(self, request, caveats).await;
                        } else {
                            request.local_cache(|| l402::L402Info {
                                l402_type: l402::L402_TYPE_FREE.to_string(),
                                preimage: None,
                                payment_hash: None,
                                error: None,
                                auth_header: None,
                            });
                        }
                    } else {
                        request.local_cache(|| l402::L402Info {
                            l402_type: l402::L402_TYPE_ERROR.to_string(),
                            error: Some(error.to_string()),
                            preimage: None,
                            payment_hash: None,
                            auth_header: None,
                        });
                        println!("Error parsing L402: {}", error);
                    }
                },
            }
        } else {
            #[cfg(feature = "no-accept-authenticate-required")]
            L402Middleware::set_l402_header(self, request, caveats).await;

            #[cfg(not(feature = "no-accept-authenticate-required"))]
            if let Some(accept_l402_field) = request.headers().get_one(l402::L402_HEADER_NAME) {
                if accept_l402_field.contains(l402::L402_HEADER) {
                    L402Middleware::set_l402_header(self, request, caveats).await;
                    request.local_cache(|| l402::L402Info {
                        l402_type: l402::L402_TYPE_PAYMENT_REQUIRED.to_string(),
                        preimage: None,
                        payment_hash: None,
                        error: None,
                        auth_header: None,
                    });
                } else {
                    request.local_cache(|| l402::L402Info {
                        l402_type: l402::L402_TYPE_FREE.to_string(),
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
        // Retrieve L402Info from the local cache
        let l402_info = request.local_cache::<l402::L402Info, _>(|| {
            l402::L402Info {
                l402_type: l402::L402_TYPE_ERROR.to_string(),
                error: Some("No L402 header present".to_string()),
                preimage: None,
                payment_hash: None,
                auth_header: None,
            }
        });

        // Check if the auth header is set and add it to the response
        if let Some(header_value) = &l402_info.auth_header {
            response.set_header(Header::new(l402::L402_AUTHENTICATE_HEADER_NAME, header_value));
        }
    }
}

use reqwest::{Client, Error};
use serde::Deserialize;
use std::convert::TryInto;
use rocket::serde::json::serde_json;
use lightning::ln::PaymentHash;
use tonic_openssl_lnd::lnrpc;
use lightning_invoice::{Bolt11Invoice, SignedRawBolt11Invoice};
use std::sync::Arc;
use bitcoin::hashes::Hash;
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;

use crate::utils;
use crate::lnclient;

const MSAT_PER_SAT: u64 = 1000;

#[derive(Debug, Clone)]
pub struct LNURLOptions {
    pub address: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct LnAddressUrlResJson {
    callback: String,

    #[serde(rename = "maxSendable")]
    max_sendable: u64,

    #[serde(rename = "minSendable")]
    min_sendable: u64,

    metadata: String,

    #[serde(rename = "commentAllowed")]
    comment_allowed: u32,
    tag: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct CallbackUrlResJson {
    pr: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct DecodedPR {
    currency: String,
    created_at: i32,
    expiry: i32,
    payee: String,
    msatoshi: i64,
    description: Option<String>,
    description_hash: Option<String>,
    payment_hash: String,
    min_final_cltv_expiry: i32,
}

impl LnAddressUrlResJson {
    pub async fn new_client(ln_client_config: &lnclient::LNClientConfig) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn std::error::Error + Send + Sync>> {
        let lnurl_options = ln_client_config.lnurl_config.clone();
        let (username, domain) = utils::parse_ln_address(lnurl_options.address)?;
    
        let ln_address_url = format!("https://{}/.well-known/lnurlp/{}", domain, username);
        let ln_address_url_res_body = do_get_request(&ln_address_url).await;
    
        let ln_address_url_res: LnAddressUrlResJson = serde_json::from_str(&ln_address_url_res_body.unwrap())?;
        Ok(Arc::new(Mutex::new(ln_address_url_res)))
    }
}

impl lnclient::LNClient for LnAddressUrlResJson {
    fn add_invoice(
        &self,
        ln_invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        let callback_url = format!(
            "{}?amount={}",
            self.callback,
            MSAT_PER_SAT * (ln_invoice.value as u64)
        );

        Box::pin(async move {
            let callback_url_res_body = do_get_request(&callback_url).await?;

            let callback_url_res_json: CallbackUrlResJson =
                serde_json::from_str(&callback_url_res_body)?;

            let invoice = callback_url_res_json.pr;
            let decoded_invoice = Bolt11Invoice::from_signed(invoice.parse::<SignedRawBolt11Invoice>().unwrap()).unwrap();
            let payment_hash = decoded_invoice.payment_hash();
            let payment_addr = decoded_invoice.payment_secret();

            Ok(lnrpc::AddInvoiceResponse {
                r_hash: payment_hash.to_byte_array().to_vec(),
                payment_request: invoice,
                add_index: 0,
                payment_addr: payment_addr.0.to_vec(),
            })
        })
    }
}

async fn do_get_request(url: &str) -> Result<String, Error> {
    let client = Client::new();

    let raw_resp = client.get(url).send().await?;
    let resp = raw_resp.error_for_status()?;

    let text = resp.text().await?;
    Ok(text)
}

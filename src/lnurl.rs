use reqwest::{Client, Error};
use futures::executor::block_on;
use serde::Deserialize;
use std::convert::TryInto;

const MSAT_PER_SAT: u64 = 1000;

#[derive(Debug)]
struct LNURLoptions {
    address: String,
}

#[derive(Debug, serde::Deserialize)]
struct LnAddressUrlResJson {
    callback: String,
    max_sendable: u64,
    min_sendable: u64,
    metadata: String,
    comment_allowed: u32,
    tag: String,
}

#[derive(Debug, serde::Deserialize)]
struct CallbackUrlResJson {
    pr: String,
}

#[derive(Debug, serde::Deserialize)]
struct DecodedPR {
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

fn new_lnurl_client(lnurl_options: LNURLoptions) -> Result<LnAddressUrlResJson, Box<dyn Error>> {
    let (username, domain) = utils::parse_ln_address(&lnurl_options.address)?;

    let ln_address_url = format!("https://{}/.well-known/lnurlp/{}", domain, username);
    let ln_address_url_res_body = do_get_request(&ln_address_url)?;

    let ln_address_url_res: LnAddressUrlResJson = serde_json::from_slice(&ln_address_url_res_body)?;
    Ok(ln_address_url_res)
}

impl LnAddressUrlResJson {
    pub fn add_invoice(
        &self,
        ctx: &Context,  // Assuming a Rust Context type
        ln_invoice: &lnrpc::Invoice,
        http_req: &http::Request,
        options: &[grpc::CallOption],
    ) -> Result<lnrpc::AddInvoiceResponse, Box<dyn std::error::Error>> {
        let callback_url = format!(
            "{}?amount={}",
            self.callback,
            MSAT_PER_SAT * ln_invoice.value
        );

        let callback_url_res_body = block_on(do_get_request(&callback_url))?;

        let callback_url_res_json: CallbackUrlResJson =
            serde_json::from_str(&callback_url_res_body)?;

        let invoice = callback_url_res_json.PR;
        let decoded = decodepay::decodepay(&invoice)?;
        let payment_hash = lntypes::Hash::from_str(&decoded.payment_hash)?;

        Ok(lnrpc::AddInvoiceResponse {
            r_hash: payment_hash.as_bytes().to_vec(),
            payment_request: invoice,
        })
    }
}

async fn do_get_request(url: &str) -> Result<String, Error> {
    let client = Client::new();

    let response = client.get(url).send().await?;

    if response.status().is_success() {
        let text = response.text().await?;
        Ok(text)
    } else {
        Err(Error::from(response.status()))
    }
}

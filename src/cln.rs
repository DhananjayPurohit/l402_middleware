use std::{error::Error, sync::Arc, path::Path};
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;
use cln_rpc::{ClnRpc, model::*, Response, TypedRequest};
use cln_rpc::model::requests::GetinfoRequest;
use cln_rpc::model::responses::GetinfoResponse;
use cln_rpc::model::requests::InvoiceRequest;
use cln_rpc::model::responses::InvoiceResponse;
use cln_rpc::primitives::{Amount, AmountOrAny, Sha256};
use tonic_openssl_lnd::lnrpc;
use std::error::Error as StdError;

use crate::lnclient;

#[derive(Debug, Clone)]
pub struct CLNOptions {
    pub lightning_dir: String,
}

pub struct CLNWrapper {
    client: Arc<Mutex<ClnRpc>>,
}

impl CLNWrapper {
    pub async fn new_client(
        ln_client_config: &lnclient::LNClientConfig,
    ) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn Error + Send + Sync>> {
        let cln_options = ln_client_config.cln_config.clone().unwrap();

        println!("CLN client {}", cln_options.lightning_dir);
        
        let mut client = ClnRpc::new(Path::new(&cln_options.lightning_dir)).await
            .map_err(|e| format!("CLN RPC error: {}", e))?;

        // Get node info to verify connection
        let request = GetinfoRequest {};
        let _response: GetinfoResponse = client.call_typed(&request).await
            .map_err(|e| format!("CLN RPC error: {}", e))?;

        Ok(Arc::new(Mutex::new(CLNWrapper { client: Arc::new(Mutex::new(client)) })))
    }
}

impl lnclient::LNClient for CLNWrapper {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>>> + Send>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            let mut client = client.lock().await;
            
            let invoice_request = InvoiceRequest {
                amount_msat: AmountOrAny::Amount(Amount::from_msat(invoice.value_msat as u64)),
                description: invoice.memo,
                label: "l402".to_string(),
                expiry: None,
                fallbacks: None,
                preimage: None,
                cltv: None,
                deschashonly: None,
                exposeprivatechannels: None
            };

            let response: InvoiceResponse = client.call_typed(&invoice_request).await
                .map_err(|e| format!("CLN RPC error: {}", e))?;

            Ok(lnrpc::AddInvoiceResponse {
                r_hash: <Sha256 as AsRef<[u8]>>::as_ref(&response.payment_hash).to_vec(),
                payment_request: response.bolt11,
                add_index: 0, // CLN doesn't have this concept
                payment_addr: vec![], // CLN doesn't have this concept
            })
        })
    }
}

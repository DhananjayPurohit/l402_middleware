use std::{error::Error, sync::Arc, path::Path};
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;
use cln_rpc::ClnRpc;
use cln_rpc::model::requests::FetchinvoiceRequest;
use cln_rpc::model::responses::FetchinvoiceResponse;
use cln_rpc::primitives::Amount;
use tonic_openssl_lnd::lnrpc;

use crate::lnclient;

#[derive(Debug, Clone)]
pub struct Bolt12Options {
    pub lightning_dir: String,
    pub offer: String,
}

pub struct Bolt12Wrapper {
    client: Arc<Mutex<Option<ClnRpc>>>,
    lightning_dir: String,
    offer: String,
}

impl Bolt12Wrapper {
    pub async fn new_client(
        ln_client_config: &lnclient::LNClientConfig,
    ) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn Error + Send + Sync>> {
        let bolt12_options = ln_client_config.bolt12_config.clone().unwrap();

        println!("BOLT12 client {} with offer {}", bolt12_options.lightning_dir, bolt12_options.offer);

        let wrapper = Bolt12Wrapper {
            client: Arc::new(Mutex::new(None)),
            lightning_dir: bolt12_options.lightning_dir,
            offer: bolt12_options.offer,
        };

        Ok(Arc::new(Mutex::new(wrapper)))
    }
}

impl lnclient::LNClient for Bolt12Wrapper {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>>> + Send>> {
        let client = Arc::clone(&self.client);
        let lightning_dir = self.lightning_dir.clone();
        let offer = self.offer.clone();
        
        Box::pin(async move {
            let mut client_guard = client.lock().await;
            
            if client_guard.is_none() {
                let new_client = ClnRpc::new(Path::new(&lightning_dir)).await
                    .map_err(|e| format!("CLN RPC error: {}", e))?;
                *client_guard = Some(new_client);
            }
            
            let client = client_guard.as_mut().unwrap();
            
            let fetch_invoice_request = FetchinvoiceRequest {
                offer: offer,
                amount_msat: Some(Amount::from_msat(invoice.value_msat as u64)),
                quantity: None,
                recurrence_counter: None,
                recurrence_start: None,
                recurrence_label: None,
                timeout: None,
                payer_note: if invoice.memo.is_empty() { None } else { Some(invoice.memo.clone()) },
                bip353: None,
                payer_metadata: None,
            };

            let response: FetchinvoiceResponse = match client.call_typed(&fetch_invoice_request).await {
                Ok(res) => res,
                Err(e) => {
                    *client_guard = None;
                    return Err(format!("CLN RPC error: {}", e).into());
                }
            };

            let invoice_str = response.invoice;
            
            // Decode to extract payment hash
            let decode_request = cln_rpc::model::requests::DecodeRequest {
                string: invoice_str.clone(),
            };
            
            let decode_response: cln_rpc::model::responses::DecodeResponse = match client.call_typed(&decode_request).await {
                 Ok(res) => res,
                 Err(e) => {
                     *client_guard = None;
                     return Err(format!("CLN RPC error during decode: {}", e).into());
                 }
            };
                
            // BOLT12 invoices return `invoice_payment_hash` (hex) instead of `payment_hash` (Sha256)
            let payment_hash_bytes = if let Some(ph) = decode_response.payment_hash {
                <cln_rpc::primitives::Sha256 as AsRef<[u8]>>::as_ref(&ph).to_vec()
            } else if let Some(ph_hex) = decode_response.invoice_payment_hash {
                hex::decode(ph_hex).map_err(|e| format!("Invalid hex in invoice_payment_hash: {}", e))?
            } else {
                return Err("No payment hash in decode response".into());
            };

            let payment_secret = decode_response.payment_secret;
            
            Ok(lnrpc::AddInvoiceResponse {
                r_hash: payment_hash_bytes,
                payment_request: invoice_str,
                add_index: 0,
                payment_addr: if let Some(secret) = payment_secret {
                    // Secret is struct Secret([u8; 32]) - private field access via unsafe
                    unsafe { std::mem::transmute::<_, [u8; 32]>(secret).to_vec() }
                } else {
                    vec![]
                },
            })
        })
    }
}

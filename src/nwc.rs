use nwc::prelude::*;
use std::sync::Arc;
use crate::lndrpc::lnrpc;
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;
use lightning_invoice::{Bolt11Invoice, SignedRawBolt11Invoice};

use crate::lnclient;

#[derive(Debug, Clone)]
pub struct NWCOptions {
    pub uri: String,
}

pub struct NWCWrapper {
    pub client: Arc<Mutex<NWC>>,
}

impl NWCWrapper {
    pub async fn new_client(ln_client_config: &lnclient::LNClientConfig) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn std::error::Error + Send + Sync>> {
        let nwc_options = ln_client_config.nwc_config.clone().unwrap();
        let uri = NostrWalletConnectURI::parse(&nwc_options.uri)?;
        let nwc = NWC::new(uri);
        Ok(Arc::new(Mutex::new(NWCWrapper { client: Arc::new(Mutex::new(nwc)) })))
    }
}

impl lnclient::LNClient for NWCWrapper {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            let client = client.lock().await;

            let params = MakeInvoiceRequest {
                amount: invoice.value_msat as u64,
                description: None,
                description_hash: None,
                expiry: None,
            };
            let response = match client.make_invoice(params).await {
                Ok(res) => {
                    println!("response {:?}", res);

                    // res.invoice comes from the remote wallet — never unwrap it.
                    let signed = res
                        .invoice
                        .parse::<SignedRawBolt11Invoice>()
                        .map_err(|e| format!("NWC returned an unparsable invoice: {:?}", e))?;
                    let decoded_invoice = Bolt11Invoice::from_signed(signed)
                        .map_err(|e| format!("NWC invoice failed validation: {:?}", e))?;
                    let payment_addr = decoded_invoice.payment_secret();
                    // payment_hash is optional in the NIP-47 response.
                    let payment_hash = res
                        .payment_hash
                        .ok_or("NWC make_invoice response has no payment_hash")?;
                    lnrpc::AddInvoiceResponse {
                        r_hash: hex::decode(&payment_hash)
                            .map_err(|e| format!("invalid payment_hash from NWC: {}", e))?,
                        payment_request: res.invoice,
                        add_index: 0,
                        payment_addr: payment_addr.0.to_vec(),
                    }
                }
                Err(e) => {
                    eprintln!("Error adding invoice: {:?}", e);
                    let boxed_error: Box<dyn std::error::Error + Send + Sync> = Box::new(e);
                    return Err(boxed_error);
                }
            };
            Ok(response)
        })
    }

    /// NIP-47 makes `lookup_invoice` optional, so wallets without it return an
    /// error and auto-detect stays off for them.
    fn lookup_invoice(
        &self,
        payment_hash: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            let client = client.lock().await;

            let request = LookupInvoiceRequest {
                payment_hash: Some(hex::encode(&payment_hash)),
                invoice: None,
            };
            let res = client
                .lookup_invoice(request)
                .await
                .map_err(|e| format!("NWC lookup_invoice failed: {:?}", e))?;

            // Settlement comes from the wallet's status, never from the presence
            // of a preimage: the wallet minted this invoice, so it has known the
            // preimage since before anyone paid it.
            if res.state != Some(TransactionState::Settled) && res.settled_at.is_none() {
                return Ok(None);
            }

            match res.preimage.as_deref().filter(|p| !p.is_empty()) {
                Some(preimage) => Ok(Some(
                    hex::decode(preimage)
                        .map_err(|e| format!("invalid preimage from NWC: {}", e))?,
                )),
                None => Err("NWC invoice settled but preimage missing".into()),
            }
        })
    }
}

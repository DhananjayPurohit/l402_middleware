use nwc::prelude::*;
use std::sync::Arc;
use tonic_openssl_lnd::lnrpc;
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

impl NWCOptions {
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

                    let decoded_invoice = Bolt11Invoice::from_signed(res.invoice.parse::<SignedRawBolt11Invoice>().unwrap()).unwrap();
                    let payment_addr = decoded_invoice.payment_secret();
                    lnrpc::AddInvoiceResponse {
                        r_hash: hex::decode(&res.payment_hash).unwrap_or_default(),
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
}

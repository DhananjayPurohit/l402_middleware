use std::{error::Error, sync::Arc, path::Path};
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;
use cln_rpc::ClnRpc;
use cln_rpc::model::requests::InvoiceRequest;
use cln_rpc::model::responses::InvoiceResponse;
use cln_rpc::primitives::{Amount, AmountOrAny, Sha256};
use crate::lndrpc::lnrpc;
use uuid::Uuid;

use crate::lnclient;

#[derive(Debug, Clone)]
pub struct CLNOptions {
    pub lightning_dir: String,
}

pub struct CLNWrapper {
    client: Arc<Mutex<Option<ClnRpc>>>,
    lightning_dir: String,
}

impl CLNWrapper {
    pub async fn new_client(
        ln_client_config: &lnclient::LNClientConfig,
    ) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn Error + Send + Sync>> {
        let cln_options = ln_client_config.cln_config.clone().unwrap();

        println!("CLN client {}", cln_options.lightning_dir);

        let wrapper = CLNWrapper {
            client: Arc::new(Mutex::new(None)),
            lightning_dir: cln_options.lightning_dir,
        };

        Ok(Arc::new(Mutex::new(wrapper)))
    }
}

impl lnclient::LNClient for CLNWrapper {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>>> + Send>> {
        let client = Arc::clone(&self.client);
        let lightning_dir = self.lightning_dir.clone();
        
        Box::pin(async move {
            let mut client_guard = client.lock().await;
            
            if client_guard.is_none() {
                // Create the CLN RPC client only when needed
                let new_client = ClnRpc::new(Path::new(&lightning_dir)).await
                    .map_err(|e| format!("CLN RPC error: {}", e))?;
                *client_guard = Some(new_client);
            }
            
            let client = client_guard.as_mut().unwrap();
            
            let invoice_request = InvoiceRequest {
                amount_msat: AmountOrAny::Amount(Amount::from_msat(
                    u64::try_from(invoice.value_msat)
                        .map_err(|_| format!("invalid value_msat: {}", invoice.value_msat))?,
                )),
                description: invoice.memo,
                label: format!("l402-{}", Uuid::new_v4()),
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

    fn lookup_invoice(
        &self,
        payment_hash: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, Box<dyn Error + Send + Sync>>> + Send>>
    {
        use cln_rpc::model::requests::ListinvoicesRequest;
        use cln_rpc::model::responses::ListinvoicesInvoicesStatus;

        let client = Arc::clone(&self.client);
        let lightning_dir = self.lightning_dir.clone();

        Box::pin(async move {
            let mut client_guard = client.lock().await;
            if client_guard.is_none() {
                let new_client = ClnRpc::new(Path::new(&lightning_dir))
                    .await
                    .map_err(|e| format!("CLN RPC error: {}", e))?;
                *client_guard = Some(new_client);
            }
            let client = client_guard.as_mut().unwrap();

            let request = ListinvoicesRequest {
                payment_hash: Some(hex::encode(&payment_hash)),
                label: None,
                invstring: None,
                offer_id: None,
                index: None,
                start: None,
                limit: None,
            };
            let resp = client
                .call_typed(&request)
                .await
                .map_err(|e| format!("CLN listinvoices error: {}", e))?;

            match resp.invoices.into_iter().next() {
                Some(inv) if inv.status == ListinvoicesInvoicesStatus::PAID => {
                    match inv.payment_preimage {
                        Some(preimage) => Ok(Some(preimage.to_vec())),
                        None => Err("CLN invoice settled but preimage missing".into()),
                    }
                }
                _ => Ok(None),
            }
        })
    }
}

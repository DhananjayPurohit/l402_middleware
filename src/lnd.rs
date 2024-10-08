use std::{error::Error, sync::Arc};
use tonic_openssl_lnd::{LndClient};
use tonic_openssl_lnd::lnrpc;
use base64;
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;

use crate::lnclient;

#[derive(Debug, Clone)]
pub struct LNDOptions {
    pub address: String,
    pub macaroon_file: String,
    pub cert_file: String,
}

pub struct LNDWrapper {
    client: Arc<Mutex<LndClient>>,
}

impl LNDWrapper {
    pub async fn new_client(
        ln_client_config: &lnclient::LNClientConfig,
    ) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn Error + Send + Sync>> {
        let lnd_options = ln_client_config.lnd_config.clone().unwrap();
        // Parse the port from the LNDOptions address, assuming the format is "host:port"
        let address = lnd_options.address.clone();
        let parts: Vec<&str> = address.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid address format. It should be in the form 'host:port'.".into());
        }
        let host = parts[0].to_string();
        let port: u32 = parts[1]
            .parse()
            .map_err(|_| "Port is not a valid u32".to_string())?;

        let cert = lnd_options.cert_file;
        let macaroon = lnd_options.macaroon_file;

        let client = tonic_openssl_lnd::connect(host, port, cert, macaroon).await.unwrap();

        Ok(Arc::new(Mutex::new(LNDWrapper { client: Arc::new(Mutex::new(client)) })))
    }
}

impl lnclient::LNClient for LNDWrapper {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>>> + Send>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            let mut client = client.lock().await;
            match client.lightning().add_invoice(invoice).await {
                Ok(response) => {
                    println!("Response: {:?}", response);
                    Ok(response.into_inner())
                }
                Err(e) => {
                    // Print the error and return it
                    eprintln!("Error adding invoice: {:?}", e);
                    Err(Box::new(e))
                }
            }
        })
    }
}

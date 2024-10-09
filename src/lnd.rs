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

        let client_result = tonic_openssl_lnd::connect(host, port, cert, macaroon).await;

        match client_result {
            Ok(client) => {
                println!("Successfully connected to LND");
                Ok(Arc::new(Mutex::new(LNDWrapper { client: Arc::new(Mutex::new(client)) })))
            }
            Err(ref e) => {
                // Log the error
                eprintln!("Failed to connect to LND: {:?}", e);
                // You can either propagate the error or return a generic error
                Ok(Arc::new(Mutex::new(LNDWrapper { client: Arc::new(Mutex::new(client_result.unwrap())) })))
            }
        }
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
            let response = match client.lightning().add_invoice(invoice).await {
                Ok(res) => {
                    println!("response {:?}", res);
                    res
                }
                Err(e) => {
                    eprintln!("Error adding invoice: {:?}", e);
                    let boxed_error: Box<dyn Error + Send + Sync> = Box::new(e);
                    return Err(boxed_error);
                }
            };
            println!("response {:?}", response);
            Ok(response.into_inner())
        })
    }
}

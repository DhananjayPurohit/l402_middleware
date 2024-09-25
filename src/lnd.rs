use std::{fs, error::Error, sync::Arc, sync::Mutex};
use futures::executor::block_on;
use macaroon::Macaroon;
use tonic_openssl_lnd::{LndClient};
use tonic_openssl_lnd::lnrpc;
use base64;
use std::io::BufReader;

use crate::lnclient;

#[derive(Debug, Clone)]
pub struct LNDOptions {
    pub address: String,
    pub cert_file: Option<String>,
    pub cert_hex: Option<String>,
    pub macaroon_file: Option<String>,
    pub macaroon_hex: Option<String>,
}

pub struct LNDWrapper {
    client: LndClient,
}

impl LNDWrapper {
    pub fn new_client(
        ln_client_config: &lnclient::LNClientConfig,
    ) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn Error + Send + Sync>> {
        let lnd_options = ln_client_config.lnd_config.clone();
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

        // Handle certificate and macaroon fields
        let cert = if let Some(cert_hex) = lnd_options.cert_hex {
            // Convert hex to PEM format
            let decoded_cert = hex::decode(cert_hex)?;
            String::from_utf8(decoded_cert)?
        } else if let Some(cert_file) = lnd_options.cert_file {
            // Read from certificate file
            std::fs::read_to_string(cert_file)?
        } else {
            return Err("Either cert_file or cert_hex must be provided".into());
        };

        let macaroon = if let Some(macaroon_hex) = lnd_options.macaroon_hex {
            // Convert hex to bytes
            let decoded_macaroon = hex::decode(macaroon_hex)?;
            base64::encode(decoded_macaroon)
        } else if let Some(macaroon_file) = lnd_options.macaroon_file {
            // Read macaroon file as bytes
            let mac_bytes = std::fs::read(macaroon_file)?;
            base64::encode(mac_bytes)
        } else {
            return Err("Either macaroon_file or macaroon_hex must be provided".into());
        };

        let client = block_on(tonic_openssl_lnd::connect(host, port, cert, macaroon)).unwrap();

        Ok(Arc::new(Mutex::new(LNDWrapper { client })))
    }
}

impl lnclient::LNClient for LNDWrapper {
    fn add_invoice(
        &mut self,
        invoice: lnrpc::Invoice,
    ) -> Result<lnrpc::AddInvoiceResponse, Box<dyn Error>> {
        let client = &mut self.client;
        let response = block_on(client.lightning().add_invoice(invoice))?;
        Ok(response.into_inner())
    }
}

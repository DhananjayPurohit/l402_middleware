use tonic_openssl_lnd::lnrpc;
use lightning::ln::{PaymentHash};
use std::error::Error;
use std::sync::{Arc, Mutex};

use crate::lnurl;
use crate::lnd;

const LND_CLIENT_TYPE: &str = "LND";
const LNURL_CLIENT_TYPE: &str = "LNURL";

#[derive(Debug, Clone)]
pub struct LNClientConfig {
    pub ln_client_type: String,
    pub lnd_config: lnd::LNDOptions,
    pub lnurl_config: lnurl::LNURLOptions,
    pub root_key: Vec<u8>,
}

pub trait LNClient: Send + Sync + 'static {
    fn add_invoice(
        &mut self,
        invoice: lnrpc::Invoice,
    ) -> Result<lnrpc::AddInvoiceResponse, Box<dyn Error>>;
}

pub struct LNClientConn {
    ln_client: Arc<Mutex<dyn LNClient>>,
}

impl LNClientConn {
    pub fn init(ln_client_config: &LNClientConfig) -> Result<Arc<dyn LNClient>, Box<dyn Error>> {
        let ln_client: Arc<dyn LNClient> = match ln_client_config.ln_client_type.as_str() {
            LND_CLIENT_TYPE => lnd::LNDWrapper::new_client(ln_client_config)?,
            LNURL_CLIENT_TYPE => lnurl::LnAddressUrlResJson::new_client(ln_client_config)?,
            _ => {
                return Err(format!(
                    "LN Client type not recognized: {}",
                    ln_client_config.ln_client_type
                )
                .into());
            }
        };

        Ok(ln_client)
    }

    pub fn generate_invoice(
        &self,
        ln_invoice: lnrpc::Invoice,
    ) -> Result<(String, PaymentHash), Box<dyn Error>> {
        let mut client = self.ln_client.lock().unwrap();
        let ln_client_invoice = client.add_invoice(ln_invoice)?;

        let invoice = ln_client_invoice.payment_request;
        let hash: [u8; 32] = ln_client_invoice.r_hash.try_into().map_err(|_| "Invalid length for r_hash, must be 32 bytes")?;
        let payment_hash = PaymentHash(hash);

        Ok((invoice, payment_hash))
    }
}
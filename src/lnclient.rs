use tonic_openssl_lnd::lnrpc;
use lightning::ln::{PaymentHash};
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;

use crate::lnurl;
use crate::lnd;
use crate::nwc;
use crate::cln;
use crate::bolt12;

const LND_CLIENT_TYPE: &str = "LND";
const LNURL_CLIENT_TYPE: &str = "LNURL";
const NWC_CLIENT_TYPE: &str = "NWC";
const CLN_CLIENT_TYPE: &str = "CLN";
const BOLT12_CLIENT_TYPE: &str = "BOLT12";

#[derive(Debug, Clone)]
pub struct LNClientConfig {
    pub ln_client_type: String,
    pub lnd_config: Option<lnd::LNDOptions>,
    pub lnurl_config: Option<lnurl::LNURLOptions>,
    pub nwc_config: Option<nwc::NWCOptions>,
    pub cln_config: Option<cln::CLNOptions>,
    pub bolt12_config: Option<bolt12::Bolt12Options>,
    pub root_key: Vec<u8>,
}

pub trait LNClient: Send + Sync + 'static {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>>> + Send>>;
}

pub struct LNClientConn {
    pub ln_client: Arc<Mutex<dyn LNClient>>,
}

impl LNClientConn {
    pub async fn init(ln_client_config: &LNClientConfig) -> Result<Arc<Mutex<dyn LNClient>>, Box<dyn Error + Send + Sync>> {
        let ln_client: Arc<Mutex<dyn LNClient>> = match ln_client_config.ln_client_type.as_str() {
            LND_CLIENT_TYPE => lnd::LNDWrapper::new_client(ln_client_config).await?,
            LNURL_CLIENT_TYPE => lnurl::LnAddressUrlResJson::new_client(ln_client_config).await?,
            NWC_CLIENT_TYPE => nwc::NWCWrapper::new_client(ln_client_config).await?,
            CLN_CLIENT_TYPE => cln::CLNWrapper::new_client(ln_client_config).await?,
            BOLT12_CLIENT_TYPE => bolt12::Bolt12Wrapper::new_client(ln_client_config).await?,
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

    pub async fn generate_invoice(
        &self,
        ln_invoice: lnrpc::Invoice,
    ) -> Result<(String, PaymentHash), Box<dyn Error + Send + Sync>> {
        let client = &mut self.ln_client.lock().await;
        let ln_client_invoice = &mut client.add_invoice(ln_invoice).await?;

        let invoice = &ln_client_invoice.payment_request;
        let hash: [u8; 32] = ln_client_invoice.r_hash.clone().try_into().map_err(|_| "Invalid length for r_hash, must be 32 bytes")?;
        let payment_hash = PaymentHash(hash);

        Ok((invoice.to_string(), payment_hash))
    }
}

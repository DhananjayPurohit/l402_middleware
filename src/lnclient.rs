use lnrpc::Invoice;
use lntypes::Hash;
use std::error::Error;

const LND_CLIENT_TYPE: &str = "LND";
const LNURL_CLIENT_TYPE: &str = "LNURL";

// Assuming LNDoptions and LNURLoptions are defined for configuration
struct LNClientConfig {
    ln_client_type: String,
    lnd_config: LNDoptions,
    lnurl_config: LNURLoptions,
    root_key: Vec<u8>,
}

trait LNClient {
    fn add_invoice(
        &self,
        ctx: &Context, // Assuming a Rust Context type
        ln_req: &Invoice,
        http_req: &http::Request,
        options: &[grpc::CallOption],
    ) -> Result<lnrpc::AddInvoiceResponse, Box<dyn Error>>;
}

struct LNClientConn {
    ln_client: Box<dyn LNClient>,
}

impl LNClientConn {
    fn init(ln_client_config: &LNClientConfig) -> Result<Self, Box<dyn Error>> {
        let ln_client = match ln_client_config.ln_client_type.as_str() {
            LND_CLIENT_TYPE => NewLNDClient(&ln_client_config.lnd_config)?,
            LNURL_CLIENT_TYPE => NewLNURLClient(&ln_client_config.lnurl_config)?,
            _ => {
                return Err(format!(
                    "LN Client type not recognized: {}",
                    ln_client_config.ln_client_type
                )
                .into());
            }
        };

        Ok(Self {
            ln_client: Box::new(ln_client),
        })
    }

    fn generate_invoice(
        &self,
        ctx: &Context,
        ln_invoice: Invoice,
        http_req: &http::Request,
    ) -> Result<(String, Hash), Box<dyn Error>> {
        let ln_client_invoice = self.ln_client.add_invoice(ctx, &ln_invoice, http_req, &[])?;

        let invoice = ln_client_invoice.payment_request;
        let payment_hash = Hash::from_bytes(&ln_client_invoice.r_hash)?;

        Ok((invoice, payment_hash))
    }
}
use std::{error::Error, sync::Arc};
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::lndrpc::lnrpc;
use base64::{Engine as _, engine::general_purpose};

use crate::lnclient;

#[derive(Debug, Clone)]
pub struct EclairOptions {
    /// Eclair REST API URL (e.g., "http://localhost:8080")
    pub api_url: String,
    /// Basic auth password for Eclair API
    pub password: String,
}

#[derive(Serialize)]
struct CreateInvoiceRequest {
    #[serde(rename = "amountMsat")]
    amount_msat: i64,
    description: String,
    #[serde(rename = "expireIn", skip_serializing_if = "Option::is_none")]
    expire_in: Option<i64>,
}

#[derive(Deserialize, Debug)]
struct CreateInvoiceResponse {
    #[serde(rename = "serialized")]
    invoice: String,
    #[serde(rename = "paymentHash")]
    payment_hash: String,
}

pub struct EclairWrapper {
    client: Client,
    api_url: String,
    password: String,
}

impl EclairWrapper {
    pub async fn new_client(
        ln_client_config: &lnclient::LNClientConfig,
    ) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn Error + Send + Sync>> {
        let mut eclair_options = ln_client_config
            .eclair_config
            .clone()
            .ok_or("LN_CLIENT_TYPE is ECLAIR but eclair_config is missing")?;

        // Ensure API URL has a scheme
        if !eclair_options.api_url.starts_with("http://") && !eclair_options.api_url.starts_with("https://") {
            eclair_options.api_url = format!("https://{}", eclair_options.api_url);
        }

        println!("Eclair client connecting to {}", eclair_options.api_url);

        // Test connection by making a simple API call
        let client = Client::new();
        let test_url = format!("{}/getinfo", eclair_options.api_url);
        
        let auth_header = format!(":{}", eclair_options.password);
        let encoded = general_purpose::STANDARD.encode(auth_header.as_bytes());
        
        match client
            .post(&test_url)
            .header("Authorization", format!("Basic {}", encoded))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    println!("✓ Successfully connected to Eclair node");
                } else {
                    eprintln!("⚠ Eclair connection test returned status: {}", response.status());
                }
            }
            Err(e) => {
                eprintln!("⚠ Failed to connect to Eclair node: {}", e);
            }
        }

        let wrapper = EclairWrapper {
            client,
            api_url: eclair_options.api_url,
            password: eclair_options.password,
        };

        Ok(Arc::new(Mutex::new(wrapper)))
    }
}

impl lnclient::LNClient for EclairWrapper {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>>> + Send>> {
        let client = self.client.clone();
        let api_url = self.api_url.clone();
        let password = self.password.clone();
        
        Box::pin(async move {
            let url = format!("{}/createinvoice", api_url);
            
            // Prepare the request
            let request_data = CreateInvoiceRequest {
                amount_msat: invoice.value_msat,
                description: invoice.memo,
                expire_in: if invoice.expiry > 0 {
                    Some(invoice.expiry)
                } else {
                    None
                },
            };
            
            // Create basic auth header (username is empty for Eclair, password only)
            let auth_header = format!(":{}", password);
            let encoded = general_purpose::STANDARD.encode(auth_header.as_bytes());
            
            // Make the API call
            let response = client
                .post(&url)
                .header("Authorization", format!("Basic {}", encoded))
                .form(&request_data)
                .send()
                .await
                .map_err(|e| format!("Failed to send request to Eclair: {}", e))?;

            if !response.status().is_success() {
                let status = response.status();
                let error_body = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                return Err(format!(
                    "Eclair API returned error status {}: {}",
                    status, error_body
                ).into());
            }

            let eclair_response: CreateInvoiceResponse = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse Eclair response: {}", e))?;

            // Convert payment hash from hex string to bytes
            let payment_hash_bytes = hex::decode(&eclair_response.payment_hash)
                .map_err(|e| format!("Failed to decode payment hash: {}", e))?;

            Ok(lnrpc::AddInvoiceResponse {
                r_hash: payment_hash_bytes,
                payment_request: eclair_response.invoice,
                add_index: 0, // Eclair doesn't provide this
                payment_addr: vec![], // Eclair doesn't provide this in the invoice response
            })
        })
    }

    fn lookup_invoice(
        &self,
        payment_hash: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, Box<dyn Error + Send + Sync>>> + Send>>
    {
        let client = self.client.clone();
        let api_url = self.api_url.clone();
        let password = self.password.clone();

        Box::pin(async move {
            let payment_hash_hex = hex::encode(&payment_hash);
            let url = format!("{}/getreceivedinfo", api_url.trim_end_matches('/'));

            let response = client
                .post(&url)
                .basic_auth("", Some(&password))
                .form(&[("paymentHash", &payment_hash_hex)])
                .send()
                .await
                .map_err(|e| format!("Eclair getreceivedinfo request failed: {}", e))?;

            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                return Err(
                    format!("Eclair getreceivedinfo returned HTTP {}", response.status()).into(),
                );
            }

            // Eclair returns {"status": {"type": "received", ...}, "paymentPreimage": "hex"}
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| format!("Eclair JSON parse error: {}", e))?;

            let status_type = body
                .get("status")
                .and_then(|s| s.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or("");

            if status_type == "received" {
                let preimage_hex = body
                    .get("paymentPreimage")
                    .and_then(|p| p.as_str())
                    .ok_or("Eclair: paymentPreimage field missing")?;
                hex::decode(preimage_hex)
                    .map(Some)
                    .map_err(|e| format!("Failed to hex-decode Eclair preimage: {}", e).into())
            } else {
                Ok(None)
            }
        })
    }
}

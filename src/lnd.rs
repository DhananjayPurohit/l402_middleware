use std::{error::Error, sync::Arc};
use tonic_openssl_lnd::{LndClient};
use tonic_openssl_lnd::lnrpc;
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;

use crate::lnclient;
use crate::lnc;

#[derive(Debug, Clone)]
pub struct LNDOptions {
    /// LND address (required for traditional, not used for LNC)
    pub address: Option<String>,
    /// Macaroon file path (required for traditional, not needed for LNC)
    pub macaroon_file: Option<String>,
    /// Cert file path (required for traditional, not needed for LNC)
    pub cert_file: Option<String>,
    /// LNC pairing phrase (base64-encoded JSON) - use this for LNC connection
    pub lnc_pairing_phrase: Option<String>,
    /// Override default mailbox server (optional, for LNC only)
    pub lnc_mailbox_server: Option<String>,
}

enum LNDConnectionType {
    Traditional(Arc<Mutex<LndClient>>),
    LNC(Arc<Mutex<lnc::LNCMailbox>>),
}

pub struct LNDWrapper {
    connection: LNDConnectionType,
}

impl LNDWrapper {
    pub async fn new_client(
        ln_client_config: &lnclient::LNClientConfig,
    ) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn Error + Send + Sync>> {
        let lnd_options = ln_client_config.lnd_config.clone().unwrap();
        
        // Check if LNC pairing phrase is provided
        let connection = if let Some(pairing_phrase) = &lnd_options.lnc_pairing_phrase {
            // Use LNC connection
            Self::connect_lnc(pairing_phrase, &lnd_options).await?
        } else {
            // Use traditional connection
            Self::connect_traditional(&lnd_options).await?
        };

        Ok(Arc::new(Mutex::new(LNDWrapper { connection })))
    }
    
    async fn connect_traditional(
        lnd_options: &LNDOptions,
    ) -> Result<LNDConnectionType, Box<dyn Error + Send + Sync>> {
        // Validate required fields for traditional connection
        let address = lnd_options.address.as_ref()
            .ok_or("LND_ADDRESS is required for traditional connection")?;
        let cert = lnd_options.cert_file.as_ref()
            .ok_or("CERT_FILE_PATH is required for traditional connection")?;
        let macaroon = lnd_options.macaroon_file.as_ref()
            .ok_or("MACAROON_FILE_PATH is required for traditional connection")?;
        
        // Parse the port from the LNDOptions address, assuming the format is "host:port"
        let parts: Vec<&str> = address.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid address format. It should be in the form 'host:port'.".into());
        }
        let host = parts[0].to_string();
        let port: u32 = parts[1]
            .parse()
            .map_err(|_| "Port is not a valid u32".to_string())?;

        let client = tonic_openssl_lnd::connect(host, port, cert.clone(), macaroon.clone())
            .await
            .map_err(|e| format!("Failed to connect to LND: {}", e))?;

        Ok(LNDConnectionType::Traditional(Arc::new(Mutex::new(client))))
    }
    
    async fn connect_lnc(
        pairing_phrase: &str,
        lnd_options: &LNDOptions,
    ) -> Result<LNDConnectionType, Box<dyn Error + Send + Sync>> {
        let pairing_phrase = pairing_phrase.trim();
        
        // Check if it's a hex string (pairing_secret) or mnemonic phrase
        // Pairing_secret hex strings are typically 14-32 hex characters (28-64 hex chars)
        // Mnemonics are 10 words separated by spaces
        let trimmed = pairing_phrase.trim();
        let is_hex = trimmed.len() <= 64 
            && !trimmed.contains(' ')
            && trimmed.chars().all(|c| c.is_ascii_hexdigit());
        
        let pairing_data = if is_hex {
            eprintln!("Detected pairing_secret hex format, parsing directly...");
            eprintln!("Pairing_secret hex: {}", trimmed);
            // It's a hex string - use pairing_secret directly (source of truth)
            lnc::parse_pairing_phrase_from_secret(trimmed)?
        } else {
            eprintln!("Detected mnemonic phrase format, parsing...");
            // It's a mnemonic phrase - derive from mnemonic
            lnc::parse_pairing_phrase(trimmed)?
        };
        
        // Use provided mailbox server or default from pairing data
        let mailbox_server = lnd_options.lnc_mailbox_server.clone()
            .or(Some(pairing_data.mailbox_server.clone()));
        
        // Create mailbox (don't connect yet - will connect lazily when needed)
        let mailbox = lnc::LNCMailbox::new(pairing_data, mailbox_server)?;
        
        // Store the mailbox itself, connection will be established when first used
        Ok(LNDConnectionType::LNC(Arc::new(Mutex::new(mailbox))))
    }
}

impl lnclient::LNClient for LNDWrapper {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>>> + Send>> {
        let connection = self.connection.clone();
        
        Box::pin(async move {
            match connection {
                LNDConnectionType::Traditional(client) => {
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
                    Ok(response.into_inner())
                }
                LNDConnectionType::LNC(mailbox) => {
                    Self::add_invoice_via_lnc(mailbox, invoice).await
                }
            }
        })
    }
}

impl LNDWrapper {
    /// Add invoice through LNC mailbox connection
    async fn add_invoice_via_lnc(
        mailbox: Arc<Mutex<lnc::LNCMailbox>>,
        invoice: lnrpc::Invoice,
    ) -> Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>> {
        use prost::Message;
        
        // Get or create the mailbox connection (lazy connection)
        let mut mailbox_guard = mailbox.lock().await;
        let connection = mailbox_guard.get_connection().await?;
        drop(mailbox_guard);
        
        // Serialize the invoice request using protobuf
        let mut buf = Vec::new();
        invoice.encode(&mut buf)
            .map_err(|e| format!("Failed to encode invoice: {}", e))?;
        
        // Create gRPC frame
        // gRPC format: [compressed flag (1 byte)][message length (4 bytes)][message]
        let mut grpc_frame = Vec::new();
        grpc_frame.push(0); // Not compressed
        grpc_frame.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        grpc_frame.extend_from_slice(&buf);
        
        // Create gRPC request with headers
        let request_data = Self::create_grpc_request(
            "POST",
            "/lnrpc.Lightning/AddInvoice",
            grpc_frame,
        )?;
        
        // Send through mailbox connection
        let connection_guard = connection.lock().await;
        connection_guard.send_encrypted(&request_data).await?;
        
        // Receive response
        let response_data = connection_guard.receive_encrypted().await?;
        drop(connection_guard);
        
        // Parse gRPC response
        let response_message = Self::parse_grpc_response(&response_data)?;
        
        // Decode protobuf response
        let add_invoice_response = lnrpc::AddInvoiceResponse::decode(&mut response_message.as_slice())
            .map_err(|e| format!("Failed to decode response: {}", e))?;
        
        println!("LNC response: {:?}", add_invoice_response);
        Ok(add_invoice_response)
    }
    
    /// Create a gRPC request message
    fn create_grpc_request(
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Simple HTTP/2-style request format
        let request = format!(
            "{} {} HTTP/2.0\r\ncontent-type: application/grpc+proto\r\ncontent-length: {}\r\n\r\n",
            method,
            path,
            body.len()
        );
        
        let mut result = request.as_bytes().to_vec();
        result.extend_from_slice(&body);
        
        Ok(result)
    }
    
    /// Parse a gRPC response message
    fn parse_grpc_response(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Find the end of headers (double CRLF)
        let header_end = data.windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or("Invalid gRPC response: no header end found")?;
        
        let body_start = header_end + 4;
        
        if data.len() < body_start + 5 {
            return Err("Response too short".into());
        }
        
        // Parse gRPC frame
        let _compressed = data[body_start];
        let message_len = u32::from_be_bytes([
            data[body_start + 1],
            data[body_start + 2],
            data[body_start + 3],
            data[body_start + 4],
        ]) as usize;
        
        let message_start = body_start + 5;
        let message_end = message_start + message_len;
        
        if data.len() < message_end {
            return Err("Response message incomplete".into());
        }
        
        Ok(data[message_start..message_end].to_vec())
    }
}

// Implement Clone for LNDConnectionType
impl Clone for LNDConnectionType {
    fn clone(&self) -> Self {
        match self {
            LNDConnectionType::Traditional(client) => LNDConnectionType::Traditional(Arc::clone(client)),
            LNDConnectionType::LNC(mailbox) => LNDConnectionType::LNC(Arc::clone(mailbox)),
        }
    }
}

use std::{error::Error, sync::Arc, future::Future, pin::Pin, str::FromStr};
use tokio::sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{timeout, Duration};
use tokio_socks::tcp::Socks5Stream;
use tokio_openssl::SslStream;
use tonic::transport::{Endpoint, Channel};
use tonic::metadata::MetadataValue;
use tonic::Request;
use tonic_openssl_lnd::{LndClient};
use tonic_openssl_lnd::lnrpc;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use http::Uri;
use hex;

use crate::lnclient;
use crate::lnc;

trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

struct TlsStreamWrapper(SslStream<tokio::net::TcpStream>);

impl AsyncRead for TlsStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsStreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
pub struct LNDOptions {
    /// LND address (required for traditional, not used for LNC)
    pub address: Option<String>,
    /// Macaroon file path (required for traditional, not needed for LNC)
    pub macaroon_file: Option<String>,
    /// Cert file path (required for traditional, not needed for LNC)
    pub cert_file: Option<String>,
    /// SOCKS5 proxy (optional, for traditional connection only)
    /// Format: "host:port" (e.g., "127.0.0.1:9050" for Tor)
    /// REQUIRED for Tor .onion addresses (DNS resolution needs Tor)
    /// Optional for regular addresses (useful for privacy, bypassing restrictions, or testing)
    pub socks5_proxy: Option<String>,
    /// LNC pairing phrase (base64-encoded JSON or mnemonic) - use this for LNC connection
    pub lnc_pairing_phrase: Option<String>,
    /// Override default mailbox server (optional, for LNC only)
    pub lnc_mailbox_server: Option<String>,
}

enum LndClientWrapper {
    Standard(LndClient),
    Custom {
        lightning: Box<dyn LightningClientTrait + Send + Sync>,
    },
}

trait LightningClientTrait {
    fn add_invoice(
        &mut self,
        invoice: lnrpc::Invoice,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<tonic::Response<lnrpc::AddInvoiceResponse>, tonic::Status>> + Send + '_>>;
}

// We use a closure-based approach to avoid naming the exact InterceptedService type
struct InterceptedLightningClient {
    add_invoice_fn: Box<dyn FnMut(lnrpc::Invoice) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<tonic::Response<lnrpc::AddInvoiceResponse>, tonic::Status>> + Send>> + Send + Sync>,
}

impl LightningClientTrait for InterceptedLightningClient {
    fn add_invoice(
        &mut self,
        invoice: lnrpc::Invoice,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<tonic::Response<lnrpc::AddInvoiceResponse>, tonic::Status>> + Send + '_>> {
        (self.add_invoice_fn)(invoice)
    }
}

enum LNDConnectionType {
    Traditional(Arc<Mutex<LndClientWrapper>>),
    LNC {
        mailbox: Arc<Mutex<lnc::LNCMailbox>>,
        client: Arc<Mutex<Option<lnrpc::lightning_client::LightningClient<Channel>>>>,
        pairing_phrase: String,
        mailbox_server: String,
    },
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
            return Err(format!(
                "Invalid address format. Expected 'host:port', but got '{}'. \
                For Tor .onion addresses, use format like 'youronionaddress.onion:10009'",
                address
            ).into());
        }
        let host = parts[0].to_string();
        let port: u32 = parts[1]
            .parse()
            .map_err(|_| "Port is not a valid u32".to_string())?;

        let host_clone = host.clone();
        let client_wrapper = if let Some(proxy_addr) = &lnd_options.socks5_proxy {
            println!("Attempting to connect to LND through SOCKS5 proxy: {} -> {}:{}", proxy_addr, host, port);
            let lightning = Self::connect_with_socks5_proxy(host, port, cert.clone(), macaroon.clone(), proxy_addr.clone()).await?;
            LndClientWrapper::Custom {
                lightning,
            }
        } else {
            println!("Connecting to LND directly at {}:{}", host, port);
            let client = tonic_openssl_lnd::connect(host, port, cert.clone(), macaroon.clone()).await
                .map_err(|e| format!("Failed to connect to LND at {}:{}: {}", host_clone, port, e))?;
            LndClientWrapper::Standard(client)
        };

        Ok(LNDConnectionType::Traditional(Arc::new(Mutex::new(client_wrapper))))
    }

    /// Connect to LND through a SOCKS5 proxy (e.g., Tor)
    async fn connect_with_socks5_proxy(
        host: String,
        port: u32,
        cert_file: String,
        macaroon_file: String,
        proxy_addr: String,
    ) -> Result<Box<dyn LightningClientTrait + Send + Sync>, Box<dyn Error + Send + Sync>> {
        let proxy_parts: Vec<&str> = proxy_addr.split(':').collect();
        if proxy_parts.len() != 2 {
            return Err("Invalid proxy address format. It should be in the form 'host:port'.".into());
        }
        let proxy_host = proxy_parts[0];
        let proxy_port: u16 = proxy_parts[1]
            .parse()
            .map_err(|_| "Proxy port is not a valid u16".to_string())?;

        println!("Verifying SOCKS5 proxy accessibility at {}:{}...", proxy_host, proxy_port);
        let test_connection = tokio::net::TcpStream::connect(format!("{}:{}", proxy_host, proxy_port));
        match timeout(Duration::from_secs(5), test_connection).await {
            Ok(Ok(_)) => println!("✓ SOCKS5 proxy is accessible"),
            Ok(Err(e)) => {
                return Err(format!(
                    "Cannot connect to SOCKS5 proxy at {}:{}. Error: {}",
                    proxy_host, proxy_port, e
                ).into());
            }
            Err(_) => {
                return Err(format!(
                    "SOCKS5 proxy at {}:{} is not responding (timeout).",
                    proxy_host, proxy_port
                ).into());
            }
        }

        let cert_data = std::fs::read(&cert_file)
            .map_err(|e| format!("Failed to read cert file: {}", e))?;
        let cert = X509::from_pem(&cert_data)
            .map_err(|e| format!("Failed to parse cert: {}", e))?;

        let mut ctx = SslContext::builder(SslMethod::tls_client())
            .map_err(|e| format!("Failed to create SSL context: {}", e))?;
        ctx.set_verify(SslVerifyMode::PEER);
        
        let mut store = openssl::x509::store::X509StoreBuilder::new()
            .map_err(|e| format!("Failed to create cert store: {}", e))?;
        store.add_cert(cert)
            .map_err(|e| format!("Failed to add cert: {}", e))?;
        ctx.set_verify_cert_store(store.build())
            .map_err(|e| format!("Failed to set cert store: {}", e))?;

        let proxy_host_str = proxy_host.to_string();
        let proxy_host_for_connector = proxy_host.to_string();
        let target_host = host.clone();
        let target_port = port;
        let ssl_context = Arc::new(ctx.build());
        
        // Tonic's connector expects a service that returns a stream implementing AsyncRead + AsyncWrite
        let connector = tower::service_fn(move |_uri: http::Uri| {
            let proxy_host = proxy_host_for_connector.clone();
            let target_host = target_host.clone();
            let ssl_context = Arc::clone(&ssl_context);
            
            async move {
                let target = format!("{}:{}", target_host, target_port);
                println!("Connecting to {} through SOCKS5 proxy {}:{}...", target, proxy_host, proxy_port);
                
                let connect_future = Socks5Stream::connect(
                    (proxy_host.as_str(), proxy_port),
                    target.as_str(),
                );
                
                let socks_stream = timeout(Duration::from_secs(30), connect_future)
                    .await
                    .map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "SOCKS5 connection timed out after 30 seconds. Check if Tor is running and accessible."
                    ))?
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("SOCKS5 connection failed: {}. Make sure Tor is running on {}:{}", e, proxy_host, proxy_port)
                    ))?;
                
                println!("SOCKS5 connection established, proceeding with TLS...");

                let tcp_stream = socks_stream.into_inner();
                
                let mut ssl = Ssl::new(ssl_context.as_ref())
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to create SSL: {}", e)
                    ))?;
                
                // Set the server name for SNI
                ssl.set_hostname(&target_host)
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to set hostname: {}", e)
                    ))?;

                let mut tls_stream = SslStream::new(ssl, tcp_stream)
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to create SSL stream: {}", e)
                    ))?;

                // SslStream::connect requires Pin<&mut Self>
                Pin::new(&mut tls_stream).connect().await
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("TLS handshake failed: {}", e)
                    ))?;

                Ok::<Pin<Box<dyn AsyncReadWrite + Send>>, std::io::Error>(
                    Box::pin(TlsStreamWrapper(tls_stream)) as Pin<Box<dyn AsyncReadWrite + Send>>
                )
            }
        });

        let endpoint = Endpoint::from_str(&format!("https://{}:{}", host, port))
            .map_err(|e| format!("Invalid endpoint: {}", e))?;
        
        let channel = endpoint
            .connect_with_connector(connector)
            .await
            .map_err(|e| format!("Failed to connect through SOCKS5 proxy: {}", e))?;

        let macaroon_data = std::fs::read(&macaroon_file)
            .map_err(|e| format!("Failed to read macaroon file: {}", e))?;
        
        // LND expects macaroons as hex-encoded strings in the metadata
        let macaroon_hex = hex::encode(&macaroon_data);
        let macaroon_value = MetadataValue::from_str(&macaroon_hex)
            .map_err(|e| format!("Failed to create metadata value from macaroon hex: {}", e))?;
        
        // Cloned for the closure
        let macaroon_value_clone = macaroon_value.clone();
        let interceptor: Box<dyn FnMut(Request<()>) -> Result<Request<()>, tonic::Status> + Send + Sync> = Box::new(move |mut req: Request<()>| {
            req.metadata_mut().insert(
                "macaroon",
                macaroon_value_clone.clone(),
            );
            Ok(req)
        });
        
        let lightning_client = lnrpc::lightning_client::LightningClient::with_interceptor(
            channel,
            interceptor,
        );
        
        println!("✓ Successfully connected to LND through SOCKS5 proxy with TLS");
        
        // This allows us to call &mut methods from within the async closure
        let client_mutex = Arc::new(Mutex::new(lightning_client));
        let client_mutex_clone = Arc::clone(&client_mutex);
        
        // This avoids needing to name the exact InterceptedService type or satisfy its trait bounds
        let add_invoice_fn: Box<dyn FnMut(lnrpc::Invoice) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<tonic::Response<lnrpc::AddInvoiceResponse>, tonic::Status>> + Send>> + Send + Sync> = 
            Box::new(move |invoice: lnrpc::Invoice| {
                let client_mutex = Arc::clone(&client_mutex_clone);
                Box::pin(async move {
                    let mut client = client_mutex.lock().await;
                    client.add_invoice(invoice).await
                })
            });
        
        Ok(Box::new(InterceptedLightningClient {
            add_invoice_fn,
        }) as Box<dyn LightningClientTrait + Send + Sync>)
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
            eprintln!("Detected entropy hex format, parsing directly...");
            eprintln!("Entropy hex: {}", trimmed);
            // It's a hex string - use entropy directly
            lnc::parse_pairing_phrase_from_entropy(trimmed)?
        } else {
            eprintln!("Detected mnemonic phrase format, parsing...");
            // It's a mnemonic phrase - derive from mnemonic
            lnc::parse_pairing_phrase(trimmed)?
        };
        
        // Use provided mailbox server or default from pairing data
        let mailbox_server = lnd_options.lnc_mailbox_server.clone()
            .unwrap_or_else(|| pairing_data.mailbox_server.clone());
        
        // Create mailbox (don't connect yet - will connect lazily when needed)
        let mailbox = lnc::LNCMailbox::new(pairing_data, Some(mailbox_server.clone()))?;
        
        // Store the mailbox and prepare for client reuse
        Ok(LNDConnectionType::LNC {
            mailbox: Arc::new(Mutex::new(mailbox)),
            client: Arc::new(Mutex::new(None)),
            pairing_phrase: pairing_phrase.to_string(),
            mailbox_server,
        })
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
                LNDConnectionType::Traditional(client_wrapper) => {
                    let mut client_wrapper = client_wrapper.lock().await;
                    let response = match &mut *client_wrapper {
                        LndClientWrapper::Standard(client) => {
                            client.lightning().add_invoice(invoice).await
                        }
                        LndClientWrapper::Custom { lightning } => {
                            lightning.add_invoice(invoice).await
                        }
                    };
                    
                    match response {
                        Ok(res) => {
                            println!("response {:?}", res);
                            Ok(res.into_inner())
                        }
                        Err(e) => {
                            eprintln!("Error adding invoice: {:?}", e);
                            let boxed_error: Box<dyn Error + Send + Sync> = Box::new(e);
                            Err(boxed_error)
                        }
                    }
                }
                LNDConnectionType::LNC { mailbox, client, pairing_phrase, mailbox_server } => {
                    Self::add_invoice_via_lnc_reusable(
                        &mailbox,
                        &client,
                        &pairing_phrase,
                        &mailbox_server,
                        invoice,
                    ).await
                }
            }
        })
    }
}

impl LNDWrapper {
    /// Add invoice through LNC mailbox connection using proper gRPC client
    /// Connection-reusable version that keeps the gRPC client alive
    async fn add_invoice_via_lnc_reusable(
        mailbox: &Arc<Mutex<lnc::LNCMailbox>>,
        client_cache: &Arc<Mutex<Option<lnrpc::lightning_client::LightningClient<Channel>>>>,
        pairing_phrase: &str,
        mailbox_server: &str,
        invoice: lnrpc::Invoice,
    ) -> Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>> {
        // Try to use cached client first
        let mut client_guard = client_cache.lock().await;
        
        if client_guard.is_none() {
            eprintln!("🔄 No cached gRPC client, creating new connection...");
            drop(client_guard); // Release lock while setting up
            
            // Setup new connection
            let new_client = Self::setup_lnc_client(mailbox, pairing_phrase, mailbox_server).await?;
            
            // Store the client
            let mut client_guard = client_cache.lock().await;
            *client_guard = Some(new_client);
        } else {
            eprintln!("✅ Reusing existing gRPC client");
        }
        
        // Get the client (we know it exists now)
        let mut client_guard = client_cache.lock().await;
        let lightning_client = client_guard.as_mut().unwrap();
        
        // Get auth data for metadata
        let mailbox_guard = mailbox.lock().await;
        let auth_data = mailbox_guard.auth_data.clone();
        drop(mailbox_guard);
        
        eprintln!("📤 Sending AddInvoice request...");
        let mut request = Request::new(invoice);
        
        // Add authentication headers
        if let Some(auth_str) = auth_data {
            let metadata = request.metadata_mut();
            if let Some(macaroon_hex) = auth_str.strip_prefix("Macaroon: ") {
                if let Ok(metadata_value) = tonic::metadata::AsciiMetadataValue::try_from(macaroon_hex) {
                    metadata.insert("macaroon", metadata_value);
                }
            }
        }
        
        match lightning_client.add_invoice(request).await {
            Ok(response) => {
                eprintln!("✅ LNC AddInvoice successful");
                Ok(response.into_inner())
            }
            Err(e) => {
                eprintln!("❌ AddInvoice failed: {}", e);
                // Clear cached client on error so it's recreated next time
                *client_guard = None;
                Err(format!("gRPC call failed: {}", e).into())
            }
        }
    }
    
    /// Setup a new LNC client connection (extracted from add_invoice_via_lnc)
    async fn setup_lnc_client(
        mailbox: &Arc<Mutex<lnc::LNCMailbox>>,
        _pairing_phrase: &str,
        _mailbox_server: &str,
    ) -> Result<lnrpc::lightning_client::LightningClient<Channel>, Box<dyn Error + Send + Sync>> {
        // Get or create the mailbox connection (lazy connection)
        let mut mailbox_guard = mailbox.lock().await;
        let connection_arc = mailbox_guard.get_connection().await?;
        
        // Extract auth_data for gRPC metadata
        let auth_data = mailbox_guard.auth_data.clone();
        drop(mailbox_guard);
        
        // Extract the connection and get the http2_ready Arc for monitoring
        let connection = connection_arc.clone();
        let http2_ready = {
            let conn_guard = connection_arc.lock().await;
            Arc::clone(&conn_guard.http2_ready)
        };
        
        // Create a connector using tower::service_fn
        let connector = tower::service_fn(move |_uri: http::Uri| {
            let conn = Arc::clone(&connection);
            async move {
                eprintln!("🔌 Using mailbox connection for gRPC transport");
                Ok::<MailboxConnectionWrapper, std::io::Error>(
                    MailboxConnectionWrapper { connection: conn }
                )
            }
        });
        
        // Create a tonic channel using the mailbox as transport
        let channel = Endpoint::from_static("http://localhost:10009")
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .connect_with_connector(connector)
            .await
            .map_err(|e| format!("Failed to create gRPC channel: {}", e))?;
        
        // Create a Lightning gRPC client
        let mut lightning_client = lnrpc::lightning_client::LightningClient::new(channel);
        
        // Wait for HTTP/2 SETTINGS exchange to complete
        eprintln!("⏳ Waiting for HTTP/2 SETTINGS exchange...");
        let start = std::time::Instant::now();
        while !*http2_ready.lock().await {
            if start.elapsed() > Duration::from_secs(5) {
                return Err("Timeout waiting for HTTP/2 SETTINGS exchange".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        eprintln!("✅ HTTP/2 SETTINGS exchange complete, proceeding with GetInfo");
        
        // Test connection with GetInfo
        eprintln!("📤 Establishing connection with GetInfo...");
        let mut get_info_request = Request::new(lnrpc::GetInfoRequest{});
        
        // Add authentication metadata
        if let Some(ref auth_str) = auth_data {
            let metadata = get_info_request.metadata_mut();
            if let Some(macaroon_hex) = auth_str.strip_prefix("Macaroon: ") {
                if let Ok(metadata_value) = tonic::metadata::AsciiMetadataValue::try_from(macaroon_hex) {
                    metadata.insert("macaroon", metadata_value);
                }
            }
        }
        
        match lightning_client.get_info(get_info_request).await {
            Ok(info_response) => {
                eprintln!("✅ Connection established! Node: {}", info_response.get_ref().alias);
            }
            Err(e) => {
                eprintln!("❌ GetInfo failed: {}", e);
                return Err(format!("Failed to establish connection: {}", e).into());
            }
        }
        
        Ok(lightning_client)
    }
}
    
/// Wrapper around Arc<Mutex<MailboxConnection>> that implements AsyncRead + AsyncWrite for tonic transport
struct MailboxConnectionWrapper {
    connection: Arc<Mutex<lnc::MailboxConnection>>,
}

impl AsyncRead for MailboxConnectionWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Try to lock and delegate
        match self.connection.try_lock() {
            Ok(mut conn) => Pin::new(&mut *conn).poll_read(cx, buf),
            Err(_) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }
}

impl AsyncWrite for MailboxConnectionWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.connection.try_lock() {
            Ok(mut conn) => Pin::new(&mut *conn).poll_write(cx, buf),
            Err(_) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }
    
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.connection.try_lock() {
            Ok(mut conn) => Pin::new(&mut *conn).poll_flush(cx),
            Err(_) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }
    
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.connection.try_lock() {
            Ok(mut conn) => Pin::new(&mut *conn).poll_shutdown(cx),
            Err(_) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }
}

// Implement Clone for LNDConnectionType
impl Clone for LNDConnectionType {
    fn clone(&self) -> Self {
        match self {
            LNDConnectionType::Traditional(client) => LNDConnectionType::Traditional(Arc::clone(client)),
            LNDConnectionType::LNC { mailbox, client, pairing_phrase, mailbox_server } => {
                LNDConnectionType::LNC {
                    mailbox: Arc::clone(mailbox),
                    client: Arc::clone(client),
                    pairing_phrase: pairing_phrase.clone(),
                    mailbox_server: mailbox_server.clone(),
                }
            }
        }
    }
}

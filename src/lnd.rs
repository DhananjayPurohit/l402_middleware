use std::{error::Error, sync::Arc, future::Future, pin::Pin, str::FromStr};
use tokio::sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{timeout, Duration};
use tokio_socks::tcp::Socks5Stream;
use tokio_openssl::SslStream;
use tonic::transport::{Endpoint, Channel};
use tonic::metadata::MetadataValue;
use tonic::{Request, service::interceptor::InterceptedService};
use hyper_util::rt::TokioIo;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use hex;


use crate::lndrpc::lnrpc;
use crate::lnclient;
use crate::lnc;

// ---- TLS stream wrappers for custom connectors -----------------------------------------

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

// Macaroon interceptor: injects the macaroon header into every request.
#[derive(Clone)]
struct MacaroonInterceptor {
    macaroon: MetadataValue<tonic::metadata::Ascii>,
}

impl tonic::service::Interceptor for MacaroonInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, tonic::Status> {
        req.metadata_mut().insert("macaroon", self.macaroon.clone());
        Ok(req)
    }
}

// ---- Convenience type alias for the intercepted client ---------------------------------

type LndLightningClient =
    lnrpc::lightning_client::LightningClient<InterceptedService<Channel, MacaroonInterceptor>>;

// ---- LND connection types --------------------------------------------------------------

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

enum LNDConnectionType {
    /// Standard direct TLS or SOCKS5 connection — fully initialised LightningClient
    Traditional(Arc<Mutex<LndLightningClient>>),
    /// LNC mailbox connection — lazily initialised client
    LNC {
        mailbox: Arc<Mutex<lnc::LNCMailbox>>,
        client: Arc<Mutex<Option<LndLightningClient>>>,
        pairing_phrase: String,
        mailbox_server: String,
    },
}

pub struct LNDWrapper {
    connection: LNDConnectionType,
}

// ---- Clone for LNDConnectionType -------------------------------------------------------

// Implement Clone for LNDConnectionType
impl Clone for LNDConnectionType {
    fn clone(&self) -> Self {
        match self {
            LNDConnectionType::Traditional(c) => LNDConnectionType::Traditional(Arc::clone(c)),
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

// ---- Helper: build an OpenSSL TLS context from a PEM cert file -------------------------

fn build_ssl_context(cert_file: &str) -> Result<SslContext, Box<dyn Error + Send + Sync>> {
    let cert_data = std::fs::read(cert_file)
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
    Ok(ctx.build())
}

// ---- Helper: build LightningClient from a Channel + macaroon ---------------------------

fn make_lightning_client(
    channel: Channel,
    macaroon_hex: String,
) -> Result<LndLightningClient, Box<dyn Error + Send + Sync>> {
    let macaroon_value = MetadataValue::from_str(&macaroon_hex)
        .map_err(|e| format!("Invalid macaroon metadata: {}", e))?;
    Ok(lnrpc::lightning_client::LightningClient::with_interceptor(
        channel,
        MacaroonInterceptor { macaroon: macaroon_value },
    ))
}

// ---- LNDWrapper implementation ---------------------------------------------------------

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

    // ------ Traditional (direct TLS or SOCKS5) ------------------------------------------

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
        let port: u32 = parts[1].parse()
            .map_err(|_| "Port is not a valid u32")?;

        let channel = if let Some(proxy_addr) = &lnd_options.socks5_proxy {
            println!("Connecting to LND via SOCKS5 proxy {} -> {}:{}", proxy_addr, host, port);
            Self::connect_channel_socks5(host.clone(), port, cert.clone(), proxy_addr.clone()).await?
        } else {
            println!("Connecting to LND directly at {}:{}", host, port);
            Self::connect_channel_direct(host.clone(), port, cert.clone()).await?
        };

        let macaroon_data = std::fs::read(macaroon)
            .map_err(|e| format!("Failed to read macaroon file: {}", e))?;
        let macaroon_hex = hex::encode(&macaroon_data);
        let client = make_lightning_client(channel, macaroon_hex)?;
        println!("\u{2713} LND gRPC channel ready");
        Ok(LNDConnectionType::Traditional(Arc::new(Mutex::new(client))))
    }

    /// Direct TLS connection using OpenSSL (no proxy).
    async fn connect_channel_direct(
        host: String,
        port: u32,
        cert_file: String,
    ) -> Result<Channel, Box<dyn Error + Send + Sync>> {
        let ssl_context = Arc::new(build_ssl_context(&cert_file)?);
        let target_host = host.clone();
        let connector = tower::service_fn(move |_uri: http::Uri| {
            let host = target_host.clone();
            let port = port;
            let ctx = Arc::clone(&ssl_context);
            async move {
                let tcp = tokio::net::TcpStream::connect(format!("{}:{}", host, port))
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let mut ssl = Ssl::new(ctx.as_ref())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                ssl.set_hostname(&host)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let mut tls = SslStream::new(ssl, tcp)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Pin::new(&mut tls).connect().await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Ok::<_, std::io::Error>(TokioIo::new(Box::pin(TlsStreamWrapper(tls)) as Pin<Box<dyn AsyncReadWrite + Send>>))
            }
        });
        let channel = Endpoint::from_str(&format!("https://{}:{}", host, port))
            .map_err(|e| format!("Invalid endpoint: {}", e))?
            .connect_with_connector(connector)
            .await
            .map_err(|e| format!("Failed to connect to LND: {}", e))?;
        Ok(channel)
    }

    /// SOCKS5 proxied TLS connection.
    async fn connect_channel_socks5(
        host: String,
        port: u32,
        cert_file: String,
        proxy_addr: String,
    ) -> Result<Channel, Box<dyn Error + Send + Sync>> {
        let proxy_parts: Vec<&str> = proxy_addr.split(':').collect();
        if proxy_parts.len() != 2 {
            return Err("Invalid proxy address format, expected 'host:port'".into());
        }
        let proxy_host = proxy_parts[0].to_string();
        let proxy_port: u16 = proxy_parts[1].parse()
            .map_err(|_| "Proxy port is not a valid u16")?;

        println!("Verifying SOCKS5 proxy at {}:{}...", proxy_host, proxy_port);
        match timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(format!("{}:{}", proxy_host, proxy_port)),
        ).await {
            Ok(Ok(_)) => println!("\u{2713} SOCKS5 proxy is accessible"),
            Ok(Err(e)) => return Err(format!("Cannot connect to SOCKS5 proxy: {}", e).into()),
            Err(_) => return Err(format!("SOCKS5 proxy at {}:{} not responding", proxy_host, proxy_port).into()),
        }

        let ssl_context = Arc::new(build_ssl_context(&cert_file)?);
        let target_host = host.clone();
        let connector = tower::service_fn(move |_uri: http::Uri| {
            let host = target_host.clone();
            let port = port;
            let ctx = Arc::clone(&ssl_context);
            let proxy_host = proxy_host.clone();
            let proxy_port = proxy_port;
            async move {
                let target = format!("{}:{}", host, port);
                println!("Connecting via SOCKS5 {}:{} -> {}", proxy_host, proxy_port, target);
                let socks_stream = timeout(
                    Duration::from_secs(30),
                    Socks5Stream::connect((proxy_host.as_str(), proxy_port), target.as_str()),
                ).await
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "SOCKS5 timed out"))?
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let tcp = socks_stream.into_inner();
                let mut ssl = Ssl::new(ctx.as_ref())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                ssl.set_hostname(&host)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let mut tls = SslStream::new(ssl, tcp)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Pin::new(&mut tls).connect().await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Ok::<_, std::io::Error>(TokioIo::new(Box::pin(TlsStreamWrapper(tls)) as Pin<Box<dyn AsyncReadWrite + Send>>))
            }
        });
        let channel = Endpoint::from_str(&format!("https://{}:{}", host, port))
            .map_err(|e| format!("Invalid endpoint: {}", e))?
            .connect_with_connector(connector)
            .await
            .map_err(|e| format!("Failed to connect through SOCKS5: {}", e))?;
        Ok(channel)
    }

    // ------ LNC mailbox connection -----------------------------------------------------
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

    /// Add invoice through LNC mailbox connection using proper gRPC client.
    /// Connection-reusable version that keeps the gRPC client alive.
    async fn add_invoice_via_lnc(
        mailbox: &Arc<Mutex<lnc::LNCMailbox>>,
        client_cache: &Arc<Mutex<Option<LndLightningClient>>>,
        _pairing_phrase: &str,
        _mailbox_server: &str,
        invoice: lnrpc::Invoice,
    ) -> Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>> {
        // Check if we need to create a new client
        let client_exists = {
            let guard = client_cache.lock().await;
            guard.is_some()
        }; // Lock automatically dropped here
        
        if !client_exists {
            eprintln!("🔄 No cached gRPC client, creating new connection...");
            // Setup new connection
            let new_client = Self::setup_lnc_client(mailbox).await?;
            // Store the client
            let mut client_guard = client_cache.lock().await;
            *client_guard = Some(new_client);
        } else {
            eprintln!("✅ Reusing cached gRPC client");
        }

        // Take the client out of the cache (we'll put it back after the call)
        let mut lightning_client = client_cache.lock().await.take().unwrap();
        drop(client_cache.lock().await); // CRITICAL: Release lock before making async gRPC call!

        // Get auth data for metadata
        let auth_data = mailbox.lock().await.auth_data.clone();
        
        eprintln!("📤 Sending AddInvoice request...");
        let mut request = Request::new(invoice);
        
        // Add authentication headers
        if let Some(ref auth_str) = auth_data {
            if let Some(macaroon_hex) = auth_str.strip_prefix("Macaroon: ") {
                if let Ok(v) = tonic::metadata::AsciiMetadataValue::try_from(macaroon_hex) {
                    request.metadata_mut().insert("macaroon", v);
                }
            }
        }

        match lightning_client.add_invoice(request).await {
            Ok(response) => {
                eprintln!("✅ LNC AddInvoice successful");
                // Put the client back in the cache
                let mut client_guard = client_cache.lock().await;
                *client_guard = Some(lightning_client);
                Ok(response.into_inner())
            }
            Err(e) => {
                eprintln!("❌ AddInvoice failed: {}", e);
                // DO NOT cache the client on error - the connection is likely broken.
                // Forcing a fresh LNC session (new Noise handshake) on the next request.
                // TODO: Investigate GoBN seq wrap-around causing Noise nonce desync
                Err(format!("gRPC call failed: {}", e).into())
            }
        }
    }

    /// Setup a new LNC client connection.
    async fn setup_lnc_client(
        mailbox: &Arc<Mutex<lnc::LNCMailbox>>,
    ) -> Result<LndLightningClient, Box<dyn Error + Send + Sync>> {
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

        // Create a connector using tower::service_fn that routes gRPC over the LNC mailbox stream.
        let connector = tower::service_fn(move |_uri: http::Uri| {
            let conn = Arc::clone(&connection);
            async move {
                eprintln!("🔌 Using mailbox connection for gRPC transport");
                Ok::<_, std::io::Error>(TokioIo::new(MailboxConnectionWrapper { connection: conn }))
            }
        });

        // Create a tonic channel using the mailbox as transport
        let channel = Endpoint::from_static("http://localhost:10009")
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .connect_with_connector(connector)
            .await
            .map_err(|e| format!("Failed to create gRPC channel: {}", e))?;

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

        // Build LightningClient — macaroon is injected per-request from auth_data.
        let macaroon_hex = auth_data
            .as_deref()
            .and_then(|s| s.strip_prefix("Macaroon: "))
            .unwrap_or("")
            .to_string();
        let client = make_lightning_client(channel, macaroon_hex)?;

        // Test connection with GetInfo
        eprintln!("📤 Establishing connection with GetInfo...");
        let mut get_info_client = client.clone();
        match get_info_client.get_info(Request::new(lnrpc::GetInfoRequest {})).await {
            Ok(info_response) => eprintln!("✅ Connection established! Node: {}", info_response.get_ref().alias),
            Err(e) => {
                eprintln!("❌ GetInfo failed: {}", e);
                return Err(format!("Failed to establish connection: {}", e).into());
            }
        }

        Ok(client)
    }
}

// ---- LNClient trait implementation for LNDWrapper -------------------------------------

impl lnclient::LNClient for LNDWrapper {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>>> + Send>> {
        let connection = self.connection.clone();
        Box::pin(async move {
            match connection {
                LNDConnectionType::Traditional(client_arc) => {
                    let mut client = client_arc.lock().await;
                    client.add_invoice(Request::new(invoice)).await
                        .map(|r| r.into_inner())
                        .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })
                }
                LNDConnectionType::LNC { mailbox, client, pairing_phrase, mailbox_server } => {
                    Self::add_invoice_via_lnc(
                        &mailbox, &client, &pairing_phrase, &mailbox_server, invoice,
                    ).await
                }
            }
        })
    }
}

// ---- MailboxConnectionWrapper ---------------------------------------------------------

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
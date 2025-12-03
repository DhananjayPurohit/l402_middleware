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
    pub address: String,
    pub macaroon_file: String,
    pub cert_file: String,
    pub socks5_proxy: Option<String>, // Format: "host:port" (e.g., "127.0.0.1:9050" for Tor)
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

pub struct LNDWrapper {
    client: Arc<Mutex<LndClientWrapper>>,
}

impl LNDWrapper {
    pub async fn new_client(
        ln_client_config: &lnclient::LNClientConfig,
    ) -> Result<Arc<Mutex<dyn lnclient::LNClient>>, Box<dyn Error + Send + Sync>> {
        let lnd_options = ln_client_config.lnd_config.clone().unwrap();
        let address = lnd_options.address.clone();
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

        let cert = lnd_options.cert_file;
        let macaroon = lnd_options.macaroon_file;

        let host_clone = host.clone();
        let client_wrapper = if let Some(proxy_addr) = lnd_options.socks5_proxy {
            println!("Attempting to connect to LND through SOCKS5 proxy: {} -> {}:{}", proxy_addr, host, port);
            let lightning = Self::connect_with_socks5_proxy(host, port, cert, macaroon, proxy_addr).await?;
            LndClientWrapper::Custom {
                lightning,
            }
        } else {
            println!("Connecting to LND directly at {}:{}", host, port);
            let client = tonic_openssl_lnd::connect(host, port, cert, macaroon).await
                .map_err(|e| format!("Failed to connect to LND at {}:{}: {}", host_clone, port, e))?;
            LndClientWrapper::Standard(client)
        };

        Ok(Arc::new(Mutex::new(LNDWrapper { client: Arc::new(Mutex::new(client_wrapper)) })))
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
}

impl lnclient::LNClient for LNDWrapper {
    fn add_invoice(
        &self,
        invoice: lnrpc::Invoice,
    ) -> Pin<Box<dyn Future<Output = Result<lnrpc::AddInvoiceResponse, Box<dyn Error + Send + Sync>>> + Send>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            let mut client_wrapper = client.lock().await;
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
        })
    }
}

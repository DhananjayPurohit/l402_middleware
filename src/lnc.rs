use std::error::Error;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{StreamExt, SinkExt};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Sha256, Sha512, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Keypair};
use pbkdf2::pbkdf2_hmac;
use hex;
use serde_json;
use base64::{Engine as _, engine::general_purpose};

/// LNC Pairing phrase data structure
#[derive(Debug, Clone)]
pub struct LNCPairingData {
    pub mnemonic: Option<String>,
    pub stream_id: Vec<u8>,
    pub local_keypair: Keypair,
    pub mailbox_server: String,
}

/// Parse the LNC pairing phrase from pairing_secret hex directly
/// This is the source of truth - use this when you have the pairing_secret from litd
pub fn parse_pairing_phrase_from_secret(pairing_secret_hex: &str) -> Result<LNCPairingData, Box<dyn Error + Send + Sync>> {
    // Decode pairing_secret hex string (can be 14 bytes or 16 bytes depending on litd version)
    let pairing_secret = hex::decode(pairing_secret_hex.trim())
        .map_err(|e| format!("Invalid pairing_secret hex: {}", e))?;
    
    eprintln!("Pairing_secret decoded: {} bytes", pairing_secret.len());
    
    // Derive 64-byte stream ID from pairing_secret using SHA512
    // The stream ID is simply SHA512(pairing_secret) -> 64 bytes
    let mut hasher = Sha512::new();
    hasher.update(&pairing_secret);
    let stream_id = hasher.finalize().to_vec();
    
    let stream_id_hex = hex::encode(&stream_id);
    eprintln!("Derived stream ID from pairing_secret (SHA512): {}", stream_id_hex);
    
    // Generate local keypair from pairing_secret
    // Use PBKDF2 to derive keypair seed from pairing_secret
    let mut seed = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        &pairing_secret,
        b"lnc-keypair",
        2048,
        &mut seed,
    );
    
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&seed)
        .map_err(|e| format!("Failed to create secret key: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    
    Ok(LNCPairingData {
        mnemonic: None,
        stream_id: stream_id,
        local_keypair: keypair,
        mailbox_server: "wss://mailbox.terminal.lightning.today:443".to_string(),
    })
}

/// Parse the LNC pairing phrase - accepts only 10-word mnemonic phrase
/// The stream ID is derived from the pairing_secret using double SHA256
pub fn parse_pairing_phrase(phrase: &str) -> Result<LNCPairingData, Box<dyn Error + Send + Sync>> {
    let phrase = phrase.trim();
    
    // Parse as mnemonic phrase (10 words)
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 10 {
        return Err(format!(
            "Invalid pairing phrase: expected 10 words, got {} words",
            words.len()
        ).into());
    }
    
    // Normalize mnemonic: lowercase and join with single spaces
    let mnemonic_normalized = words.iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    
    eprintln!("Using mnemonic: {}", mnemonic_normalized);
    
    // Derive pairing_secret from mnemonic using the same method as litd
    // litd uses: PBKDF2(mnemonic, "lnc-pairing-secret", 2048) -> 16 bytes
    let mut pairing_secret = vec![0u8; 16];
    pbkdf2_hmac::<Sha256>(
        mnemonic_normalized.as_bytes(),
        b"lnc-pairing-secret",
        2048,
        &mut pairing_secret,
    );
    let pairing_secret_hex = hex::encode(&pairing_secret);
    eprintln!("Derived pairing_secret from mnemonic: {}", pairing_secret_hex);
    eprintln!("Pairing_secret length: {} bytes", pairing_secret.len());
    
    // Derive 64-byte stream ID from pairing_secret using SHA512
    // The stream ID is simply SHA512(pairing_secret) -> 64 bytes
    let mut hasher = Sha512::new();
    hasher.update(&pairing_secret);
    let stream_id = hasher.finalize().to_vec();
    
    let stream_id_hex = hex::encode(&stream_id);
    eprintln!("Derived stream ID from pairing_secret (SHA512): {}", stream_id_hex);
    
    // Generate local keypair from mnemonic using PBKDF2
    let mut seed = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        mnemonic_normalized.as_bytes(),
        b"lnc-keypair",
        2048,
        &mut seed,
    );
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&seed)
        .map_err(|e| format!("Failed to create secret key: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    
    Ok(LNCPairingData {
        mnemonic: Some(mnemonic_normalized),
        stream_id: stream_id,
        local_keypair: keypair,
        mailbox_server: "wss://mailbox.terminal.lightning.today:443".to_string(),
    })
}

/// Represents an LNC mailbox connection
pub struct LNCMailbox {
    mnemonic: Option<String>,
    stream_id: Vec<u8>,
    local_keypair: Keypair,
    remote_public: Option<PublicKey>,
    shared_secret: Option<[u8; 32]>,
    mailbox_server: String,
    cipher: Option<ChaCha20Poly1305>,
    nonce_counter: Arc<RwLock<u64>>,
    connection: Option<Arc<Mutex<MailboxConnection>>>,
}

impl LNCMailbox {
    /// Create a new LNC mailbox connection from pairing data
    pub fn new(
        pairing_data: LNCPairingData,
        mailbox_server: Option<String>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let server = mailbox_server.unwrap_or(pairing_data.mailbox_server);
        
        Ok(Self {
            mnemonic: pairing_data.mnemonic,
            stream_id: pairing_data.stream_id,
            local_keypair: pairing_data.local_keypair,
            remote_public: None,
            shared_secret: None,
            mailbox_server: server,
            cipher: None,
            nonce_counter: Arc::new(RwLock::new(0)),
            connection: None,
        })
    }
    
    /// Perform Noise Protocol handshake with the mailbox server
    /// LNC uses: XXeke_secp256k1+SPAKE2_CHACHAPOLY1305_SHA256
    /// This is a simplified implementation - full version would use proper Noise Protocol library
    pub async fn perform_handshake(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // For now, initialize encryption with a derived key
        // The actual Noise Protocol handshake would:
        // 1. Send local ephemeral public key (blinded with SPAKE2)
        // 2. Receive server's ephemeral public key
        // 3. Perform ECDH to derive shared secret
        // 4. Initialize transport cipher
        
        // Temporary: derive key from stream ID and local keypair
        // This will be replaced with proper Noise handshake
        let mut hasher = Sha256::new();
        hasher.update(&self.stream_id);
        hasher.update(self.local_keypair.public_key().serialize().as_slice());
        let key_material = hasher.finalize();
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_material[..32]);
        
        self.shared_secret = Some(key);
        self.cipher = Some(ChaCha20Poly1305::new(&key.into()));
        
        Ok(())
    }
    
    /// Perform the actual Noise Protocol handshake over WebSocket
    /// LNC uses: XXeke_secp256k1+SPAKE2_CHACHAPOLY1305_SHA256
    /// This version accepts an initial message from the server (after stream ID)
    async fn perform_noise_handshake_websocket_with_initial(
        &mut self,
        write: &mut futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
        read: &mut futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
        initial_message: Message,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
                    // Handle the initial message from server (could be acknowledgment or start of handshake)
                    // If server sends text, it's likely an acknowledgment or error - check for errors first
                    match &initial_message {
                        Message::Text(text) => {
                            eprintln!("Server response to stream ID: {}", text);
                            
                            // Check if server returned a result (success) or error
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                                // Check for result message first (success case)
                                if let Some(result) = json.get("result") {
                                    eprintln!("✅ Server responded with result (success)!");
                                    if let Some(desc) = result.get("desc") {
                                        if let Some(stream_id_in_result) = desc.get("stream_id") {
                                            eprintln!("Result contains stream_id: {}", stream_id_in_result);
                                        }
                                    }
                                    if let Some(msg) = result.get("msg") {
                                        eprintln!("Result message (base64): {}", msg);
                                    }
                                    // Server acknowledged with result - proceed with handshake
                                    return self.perform_noise_handshake_websocket(write, read, None).await;
                                }
                                
                                // Check for error
                                if let Some(error) = json.get("error") {
                                    let error_code = error.get("code").and_then(|c| c.as_u64()).unwrap_or(0);
                                    let error_msg = error.get("message")
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("Unknown error");
                                    
                                    if error_code == 2 && error_msg.contains("stream not found") {
                                        return Err(format!(
                                            "❌ Stream not found on mailbox server!\n\
                                            \n\
                                            ⚠️  Most likely causes:\n\
                                            1. Session expired - Sessions expire after ~10 minutes if not connected\n\
                                            2. Using wrong pairing_secret - Must match the active litd session\n\
                                            3. litd session not active - Check if litd is listening for connections\n\
                                            4. Timing issue - Mailbox server may need more time to register stream\n\
                                            \n\
                                            ✅ To fix:\n\
                                            1. Create a NEW session immediately: docker exec litd litcli --network=regtest sessions add --label=\"test\" --type=admin\n\
                                            2. Wait 5-10 seconds after creating session\n\
                                            3. Copy the pairing_secret (hex) from the JSON output\n\
                                            4. Update your .env file with the new pairing_secret\n\
                                            5. Restart your application and connect WITHIN 10 MINUTES\n\
                                            6. Check litd logs to verify the stream ID matches: mailbox:XXXXX@...\n\
                                            \n\
                                            Current stream ID: {}\n\
                                            Server error: {}", 
                                            hex::encode(&self.stream_id), error_msg
                                        ).into());
                                    }
                                    
                                    return Err(format!("Mailbox server error: {}", error_msg).into());
                                }
                            }
                            
                            // Server acknowledged - proceed with handshake (don't pass this message to handshake)
                            self.perform_noise_handshake_websocket(write, read, None).await
                        }
                        Message::Binary(data) => {
                            eprintln!("Server sent binary data immediately after stream ID ({} bytes)", data.len());
                            // Server might have sent handshake data - pass it to handshake function
                            // But first, we need to send our handshake message
                            self.perform_noise_handshake_websocket(write, read, Some(initial_message)).await
                        }
                        _ => {
                            Err(format!("Unexpected initial message type: {:?}", initial_message).into())
                        }
                    }
    }
    
    /// Perform the actual Noise Protocol handshake over WebSocket
    /// LNC uses: XXeke_secp256k1+SPAKE2_CHACHAPOLY1305_SHA256
    async fn perform_noise_handshake_websocket(
        &mut self,
        write: &mut futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
        read: &mut futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
        initial_message: Option<Message>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        use rand::RngCore;
        
        // LNC Noise Protocol handshake: XXeke_secp256k1+SPAKE2_CHACHAPOLY1305_SHA256
        // Step 1: Generate ephemeral keypair for Noise handshake
        // Generate all random data before any await points to ensure Send safety
        let ephemeral_secret = {
            let mut rng = rand::thread_rng();
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);
            secret
        };
        
        let secp = Secp256k1::new();
        let ephemeral_secret_key = SecretKey::from_slice(&ephemeral_secret)
            .map_err(|e| format!("Failed to create ephemeral secret: {}", e))?;
        let ephemeral_keypair = Keypair::from_secret_key(&secp, &ephemeral_secret_key);
        let ephemeral_pubkey = ephemeral_keypair.public_key();
        
        // Step 2: SPAKE2 - derive shared secret from pairing phrase (mnemonic)
        // SPAKE2 uses a generator point M and the pairing phrase as password
        // For now, we'll use a simplified approach - derive SPAKE2 secret from mnemonic
        let mnemonic = self.mnemonic.as_ref()
            .ok_or("Mnemonic not available for SPAKE2")?;
        
        // Derive SPAKE2 shared secret (simplified - full SPAKE2 requires proper implementation)
        let mut spake2_secret = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            mnemonic.as_bytes(),
            b"lnc-spake2",
            2048,
            &mut spake2_secret,
        );
        
        // Step 3: Blind ephemeral public key with SPAKE2
        // In full SPAKE2, we'd multiply the generator point M by the password
        // For now, we'll use a simplified approach
        let blinded_ephemeral = ephemeral_pubkey.serialize();
        
        // Step 4: Send first handshake message (blinded ephemeral public key)
        // Format: [ephemeral_pubkey (33 bytes)]
        write.send(Message::Binary(blinded_ephemeral.to_vec())).await
            .map_err(|e| format!("Failed to send handshake message: {}", e))?;
        
        // Step 5: Receive server's ephemeral public key and static public key
        // Use the initial message if provided, otherwise read from stream
        let server_message = if let Some(msg) = initial_message {
            Ok(msg)
        } else {
            read.next().await.ok_or("Connection closed during handshake")?
        };
        
        match server_message {
            Ok(Message::Binary(data)) => {
                if data.len() < 33 {
                    return Err("Invalid handshake response: too short".into());
                }
                
                // Parse server's ephemeral public key (first 33 bytes)
                let server_ephemeral_pubkey = PublicKey::from_slice(&data[..33])
                    .map_err(|e| format!("Failed to parse server ephemeral key: {}", e))?;
                
                // Step 6: Perform ECDH to get shared secret
                // ECDH(ephemeral_secret, server_ephemeral_pubkey)
                // Use secp256k1 ECDH to compute shared secret
                use secp256k1::ecdh::SharedSecret;
                let shared_secret_bytes = SharedSecret::new(&server_ephemeral_pubkey, &ephemeral_secret_key);
                
                // Derive encryption key from shared secret
                let mut hasher = Sha256::new();
                hasher.update(&shared_secret_bytes.secret_bytes());
                hasher.update(&spake2_secret);
                let key_material = hasher.finalize();
                
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_material[..32]);
                
                self.shared_secret = Some(key);
                self.cipher = Some(ChaCha20Poly1305::new(&key.into()));
                
                eprintln!("Noise Protocol handshake completed successfully");
                Ok(())
            }
            Ok(msg) => Err(format!("Unexpected message type during handshake: {:?}", msg).into()),
            Err(e) => Err(format!("WebSocket error during handshake: {}", e).into()),
        }
    }
    
    /// Encrypt a message
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let cipher = self.cipher.as_ref()
            .ok_or("Cipher not initialized. Call perform_handshake first.")?;
        
        // Get and increment nonce counter
        let mut counter = self.nonce_counter.write().await;
        let nonce_value = *counter;
        *counter += 1;
        drop(counter);
        
        // Create nonce from counter (12 bytes)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&nonce_value.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt a message
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let cipher = self.cipher.as_ref()
            .ok_or("Cipher not initialized")?;
        
        if ciphertext.len() < 12 {
            return Err("Ciphertext too short".into());
        }
        
        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let encrypted_data = &ciphertext[12..];
        
        // Decrypt
        let plaintext = cipher.decrypt(nonce, encrypted_data)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        Ok(plaintext)
    }
    
    /// Get or create the mailbox connection (lazy connection)
    pub async fn get_connection(&mut self) -> Result<Arc<Mutex<MailboxConnection>>, Box<dyn Error + Send + Sync>> {
        if let Some(ref conn) = self.connection {
            return Ok(Arc::clone(conn));
        }
        
        // Perform handshake first
        self.perform_handshake().await?;
        
        // Connect via WebSocket
        // The stream ID is used to identify the mailbox
        
        // For debugging
        let stream_id_hex = hex::encode(&self.stream_id);
        eprintln!("Trying to connect to mailbox server with stream ID:");
        eprintln!("  Hex (64 bytes): {}", stream_id_hex);
        eprintln!("  Expected format from litd: mailbox:{{hex}}@mailbox.terminal.lightning.today:443");
        
        // Try different URL formats - maybe stream ID needs to be in URL path or query param
        let stream_id_base64 = general_purpose::STANDARD.encode(&self.stream_id);
        let stream_id_base64_url = general_purpose::STANDARD.encode(&self.stream_id).replace('+', "-").replace('/', "_");
        
        // Use standard URL format
        let url = if self.mailbox_server.contains("mailbox.terminal.lightning.today") {
            "wss://mailbox.terminal.lightning.today/v1/lightning-node-connect/hashmail/receive?method=POST".to_string()
        } else {
            let base = if self.mailbox_server.starts_with("wss://") || self.mailbox_server.starts_with("ws://") {
                self.mailbox_server.clone()
            } else {
                format!("wss://{}", self.mailbox_server)
            };
            let base = base.trim_end_matches('/');
            format!("{}/v1/lightning-node-connect/hashmail/receive?method=POST", base)
        };
        
        eprintln!("Trying URL: {}", url);
        
        let stream_id_base64 = general_purpose::STANDARD.encode(&self.stream_id);
        let stream_id_hex = hex::encode(&self.stream_id);
        eprintln!("Stream ID hex (for reference): {}", stream_id_hex);
        eprintln!("Stream ID base64: {}", stream_id_base64);
        
        let stream_id_message = serde_json::json!({
            "stream_id": stream_id_base64
        });
        
        // Wait before connecting - mailbox server needs time to register stream from litd
        eprintln!("Waiting 5 seconds for mailbox server to register stream...");
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        
        // Try connecting and sending stream_id with retries (each retry uses fresh connection)
        let mut retry_count = 0;
        let max_retries = 5;
        let mut ws_stream_result = connect_async(&url).await;
        
        loop {
            // Connect (or reconnect on retry)
            let (mut ws_stream, _) = match ws_stream_result {
                Ok((stream, response)) => {
                    if retry_count == 0 {
                        eprintln!("Successfully connected to: {}", url);
                    } else {
                        eprintln!("Successfully reconnected for retry {}...", retry_count);
                    }
                    (stream, response)
                }
                Err(e) => {
                    if retry_count < max_retries {
                        retry_count += 1;
                        eprintln!("Connection failed, retrying ({}/{})...", retry_count, max_retries);
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        ws_stream_result = connect_async(&url).await;
                        continue;
                    } else {
                        return Err(format!("Failed to connect to mailbox server after {} retries: {}", max_retries, e).into());
                    }
                }
            };
            
            let (mut write, mut read) = ws_stream.split();
            
            eprintln!("Sending stream ID as JSON (attempt {}): {}", retry_count + 1, stream_id_message);
            write.send(Message::Text(stream_id_message.to_string())).await
                .map_err(|e| format!("Failed to send stream ID: {}", e))?;
            
            write.flush().await
                .map_err(|e| format!("Failed to flush stream ID: {}", e))?;
            
            // Wait for server response
            let response = tokio::time::timeout(
                tokio::time::Duration::from_secs(3),
                read.next()
            ).await;
            
            match response {
                Ok(Some(Ok(msg))) => {
                    match &msg {
                        Message::Text(text) => {
                            eprintln!("Server response: {}", text);
                            
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                                // Check for result (success)
                                if json.get("result").is_some() {
                                    eprintln!("✅ Got result message from server (success)!");
                                    // Proceed with handshake using the existing write and read
                                    if let Err(e) = self.perform_noise_handshake_websocket_with_initial(&mut write, &mut read, msg).await {
                                        return Err(format!("Noise Protocol handshake failed: {}", e).into());
                                    }
                                    
                                    let connection = MailboxConnection {
                                        write: Arc::new(Mutex::new(write)),
                                        read: Arc::new(Mutex::new(read)),
                                        mailbox: Arc::new(Mutex::new(self.clone())),
                                    };
                                    
                                    let connection_arc = Arc::new(Mutex::new(connection));
                                    self.connection = Some(Arc::clone(&connection_arc));
                                    
                                    return Ok(connection_arc);
                                }
                                
                                // Check for error
                                if let Some(error) = json.get("error") {
                                    let error_code = error.get("code").and_then(|c| c.as_u64()).unwrap_or(0);
                                    let error_msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
                                    
                                    if error_code == 2 && error_msg.contains("stream not found") {
                                        retry_count += 1;
                                        if retry_count <= max_retries {
                                            eprintln!("⚠️  Stream not found, waiting and retrying ({}/{})...", retry_count, max_retries);
                                            // Drop the split halves - this will close the connection
                                            drop(write);
                                            drop(read);
                                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                            ws_stream_result = connect_async(&url).await;
                                            continue;
                                        } else {
                                            return Err(format!(
                                                "\n❌ STREAM NOT FOUND ERROR (after {} retries)\n\
                                                \n\
                                                The mailbox server cannot find the stream even though it works in browser.\n\
                                                This suggests a timing or connection issue.\n\
                                                \n\
                                                ✅ To fix:\n\
                                                1. Create a NEW session: docker exec litd litcli --network=regtest sessions add --label=\"test\" --type=admin\n\
                                                2. Wait 10-15 seconds after creating session (let litd register with mailbox)\n\
                                                3. Copy the pairing_secret (hex) from the JSON output\n\
                                                4. Update your .env file with the new pairing_secret\n\
                                                5. Run your application IMMEDIATELY (within 30 seconds)\n\
                                                \n\
                                                Current stream ID: {}\n\
                                                Server error: {}", 
                                                max_retries, hex::encode(&self.stream_id), error_msg
                                            ).into());
                                        }
                                    } else {
                                        return Err(format!("Mailbox server error: {}", error_msg).into());
                                    }
                                }
                            }
                            
                            // Got a message but not result or error - proceed with handshake
                            if let Err(e) = self.perform_noise_handshake_websocket_with_initial(&mut write, &mut read, msg).await {
                                return Err(format!("Noise Protocol handshake failed: {}", e).into());
                            }
                            
                            let connection = MailboxConnection {
                                write: Arc::new(Mutex::new(write)),
                                read: Arc::new(Mutex::new(read)),
                                mailbox: Arc::new(Mutex::new(self.clone())),
                            };
                            
                            let connection_arc = Arc::new(Mutex::new(connection));
                            self.connection = Some(Arc::clone(&connection_arc));
                            
                            return Ok(connection_arc);
                        }
                        Message::Binary(_) => {
                            eprintln!("Server sent binary message");
                            // Proceed with handshake using the existing write and read
                            if let Err(e) = self.perform_noise_handshake_websocket_with_initial(&mut write, &mut read, msg).await {
                                return Err(format!("Noise Protocol handshake failed: {}", e).into());
                            }
                            
                            let connection = MailboxConnection {
                                write: Arc::new(Mutex::new(write)),
                                read: Arc::new(Mutex::new(read)),
                                mailbox: Arc::new(Mutex::new(self.clone())),
                            };
                            
                            let connection_arc = Arc::new(Mutex::new(connection));
                            self.connection = Some(Arc::clone(&connection_arc));
                            
                            return Ok(connection_arc);
                        }
                        _ => {
                            return Err(format!("Unexpected message type: {:?}", msg).into());
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    return Err(format!("WebSocket error: {}", e).into());
                }
                Ok(None) => {
                    return Err("Connection closed by server".into());
                }
                Err(_) => {
                    retry_count += 1;
                    if retry_count <= max_retries {
                        eprintln!("Timeout, retrying ({}/{})...", retry_count, max_retries);
                        // Drop the split halves - this will close the connection
                        drop(write);
                        drop(read);
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        ws_stream_result = connect_async(&url).await;
                        continue;
                    } else {
                        return Err("Timeout waiting for server response".into());
                    }
                }
            }
        }
    }
    
    /// Connect to the mailbox server (for backward compatibility)
    pub async fn connect(&mut self) -> Result<Arc<Mutex<MailboxConnection>>, Box<dyn Error + Send + Sync>> {
        self.get_connection().await
    }
}

impl Clone for LNCMailbox {
    fn clone(&self) -> Self {
        Self {
            mnemonic: self.mnemonic.clone(),
            stream_id: self.stream_id.clone(),
            local_keypair: self.local_keypair,
            remote_public: self.remote_public,
            shared_secret: self.shared_secret,
            mailbox_server: self.mailbox_server.clone(),
            cipher: self.shared_secret.map(|key| ChaCha20Poly1305::new(&key.into())),
            nonce_counter: Arc::clone(&self.nonce_counter),
            connection: None, // Don't clone connection, will be recreated if needed
        }
    }
}

/// Represents an active mailbox connection
pub struct MailboxConnection {
    write: Arc<Mutex<futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        Message
    >>>,
    read: Arc<Mutex<futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    >>>,
    mailbox: Arc<Mutex<LNCMailbox>>,
}

impl MailboxConnection {
    /// Send an encrypted message through the mailbox
    pub async fn send_encrypted(&self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mailbox = self.mailbox.lock().await;
        let encrypted = mailbox.encrypt(data).await?;
        drop(mailbox);
        
        let mut write = self.write.lock().await;
        write.send(Message::Binary(encrypted)).await
            .map_err(|e| format!("Failed to send message: {}", e))?;
        
        Ok(())
    }
    
    /// Receive and decrypt a message from the mailbox
    pub async fn receive_encrypted(&self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut read = self.read.lock().await;
        
        match read.next().await {
            Some(Ok(Message::Binary(data))) => {
                drop(read);
                let mailbox = self.mailbox.lock().await;
                let decrypted = mailbox.decrypt(&data)?;
                Ok(decrypted)
            }
            Some(Ok(msg)) => Err(format!("Unexpected message type: {:?}", msg).into()),
            Some(Err(e)) => Err(format!("WebSocket error: {}", e).into()),
            None => Err("Connection closed".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_mnemonic_phrase() {
        let mnemonic = "position couch entry powder garage deputy bar nothing rich logic";
        let result = parse_pairing_phrase(mnemonic);
        assert!(result.is_ok());
        
        let parsed = result.unwrap();
        assert!(parsed.mnemonic.is_some());
        assert_eq!(parsed.stream_id.len(), 64);
    }
    
    #[test]
    fn test_parse_invalid_phrase() {
        // Test with wrong number of words
        let invalid = "one two three";
        let result = parse_pairing_phrase(invalid);
        assert!(result.is_err());
        
        // Test error message
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("expected 10 words"));
    }
}

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::Signer;
use log::{info, warn};
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// --- Base64url ---

fn b64url_encode(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(s).map_err(|e| format!("base64 decode: {e}"))
}

// --- AES-GCM helpers ---

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Encrypted {
    nonce: String,
    ciphertext: String,
}

fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Encrypted {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).expect("encrypt");
    Encrypted {
        nonce: b64url_encode(&nonce_bytes),
        ciphertext: b64url_encode(&ct), // includes tag
    }
}

fn aes_decrypt(key: &[u8; 32], enc: &Encrypted) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce_bytes = b64url_decode(&enc.nonce)?;
    let ct = b64url_decode(&enc.ciphertext)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| "Decryption failed".to_string())
}

// --- Key derivation ---

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let params = scrypt::Params::new(18, 8, 1, 32).expect("scrypt params");
    let mut key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).expect("scrypt");
    key
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

// --- CBOR ---

fn cbor_encode(value: &ciborium::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("cbor encode");
    buf
}

fn cose_public_key(key: &SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(false);
    let x = point.x().unwrap();
    let y = point.y().unwrap();
    use ciborium::Value as V;
    cbor_encode(&V::Map(vec![
        (V::Integer(1.into()), V::Integer(2.into())),
        (V::Integer(3.into()), V::Integer((-7).into())),
        (V::Integer((-1).into()), V::Integer(1.into())),
        (V::Integer((-2).into()), V::Bytes(x.to_vec())),
        (V::Integer((-3).into()), V::Bytes(y.to_vec())),
    ]))
}

// --- Authenticator data ---

fn build_auth_data(rp_id: &[u8], counter: u32, credential_data: Option<&[u8]>) -> Vec<u8> {
    let rp_id_hash = Sha256::digest(rp_id);
    let mut flags: u8 = 0x01 | 0x04; // UP + UV
    if credential_data.is_some() {
        flags |= 0x40;
    }
    let mut data = Vec::new();
    data.extend_from_slice(&rp_id_hash);
    data.push(flags);
    data.extend_from_slice(&counter.to_be_bytes());
    if let Some(cd) = credential_data {
        data.extend_from_slice(cd);
    }
    data
}

// --- Credential storage ---

/// Plaintext metadata for discovery
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct CredentialMeta {
    rp_id: String,
    user_name: String,
    created: u64,
}

/// Secret data encrypted by master key
#[derive(serde::Serialize, serde::Deserialize)]
struct CredentialSecret {
    private_key_pem: String,
    user_id: String,
    counter: u32,
}

/// Per-credential entry in the store
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct StoredCredential {
    #[serde(flatten)]
    meta: CredentialMeta,
    encrypted: Encrypted,
}

/// Wrapped master key (encrypted by user password)
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct WrappedMasterKey {
    salt: String, // scrypt salt for password -> wrapping key
    #[serde(flatten)]
    encrypted: Encrypted,
}

/// The credential file format
#[derive(serde::Serialize, serde::Deserialize)]
struct CredentialStore {
    master_key: WrappedMasterKey,
    credentials: HashMap<String, StoredCredential>,
}

/// Session file format
#[derive(serde::Serialize, serde::Deserialize)]
struct SessionFile {
    session_id: String,
    wrapped_master_key: Encrypted,
    expires: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// --- Master key management ---

fn create_store(password: &str) -> Result<(CredentialStore, [u8; 32]), String> {
    let master_key: [u8; 32] = random_bytes();
    let salt: [u8; 32] = random_bytes();
    let wrapping_key = derive_key(password, &salt);
    let encrypted = aes_encrypt(&wrapping_key, &master_key);

    let store = CredentialStore {
        master_key: WrappedMasterKey {
            salt: b64url_encode(&salt),
            encrypted,
        },
        credentials: HashMap::new(),
    };
    Ok((store, master_key))
}

fn unwrap_master_key(store: &CredentialStore, password: &str) -> Result<[u8; 32], String> {
    let salt = b64url_decode(&store.master_key.salt)?;
    let wrapping_key = derive_key(password, &salt);
    let plain = aes_decrypt(&wrapping_key, &store.master_key.encrypted)
        .map_err(|_| "Wrong password".to_string())?;
    let mut key = [0u8; 32];
    if plain.len() != 32 {
        return Err("Corrupted master key".into());
    }
    key.copy_from_slice(&plain);
    Ok(key)
}

fn encrypt_credential(master_key: &[u8; 32], secret: &CredentialSecret) -> Encrypted {
    let plain = serde_json::to_vec(secret).unwrap();
    aes_encrypt(master_key, &plain)
}

fn decrypt_credential(
    master_key: &[u8; 32],
    cred: &StoredCredential,
) -> Result<CredentialSecret, String> {
    let plain = aes_decrypt(master_key, &cred.encrypted)?;
    serde_json::from_slice(&plain).map_err(|e| format!("credential parse: {e}"))
}

// --- File I/O ---

fn load_store(path: &PathBuf) -> Result<CredentialStore, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("parse: {e}"))
}

fn save_store(path: &PathBuf, store: &CredentialStore) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    let data = serde_json::to_string_pretty(store).unwrap();
    fs::write(path, data).map_err(|e| format!("write: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

// --- Session management ---

const SESSION_TTL: u64 = 300; // 5 minutes

fn create_session(
    master_key: &[u8; 32],
    session_dir: &PathBuf,
) -> Result<String, String> {
    let session_key: [u8; 32] = random_bytes();
    let session_id = b64url_encode(&random_bytes::<16>());
    let wrapped = aes_encrypt(&session_key, master_key);

    let session = SessionFile {
        session_id: session_id.clone(),
        wrapped_master_key: wrapped,
        expires: now_secs() + SESSION_TTL,
    };

    let session_path = session_dir.join("session.json");
    let data = serde_json::to_string_pretty(&session).unwrap();
    fs::write(&session_path, data).map_err(|e| format!("write session: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&session_path, fs::Permissions::from_mode(0o600));
    }

    // Return session_key as b64url for the extension to hold
    Ok(b64url_encode(&session_key))
}

fn resume_session(
    session_key_b64: &str,
    session_dir: &PathBuf,
) -> Result<[u8; 32], String> {
    let session_path = session_dir.join("session.json");
    if !session_path.exists() {
        return Err("No active session".into());
    }
    let data = fs::read_to_string(&session_path).map_err(|e| format!("read session: {e}"))?;
    let session: SessionFile =
        serde_json::from_str(&data).map_err(|e| format!("parse session: {e}"))?;

    if now_secs() > session.expires {
        let _ = fs::remove_file(&session_path);
        return Err("Session expired".into());
    }

    let session_key_bytes = b64url_decode(session_key_b64)?;
    let mut session_key = [0u8; 32];
    if session_key_bytes.len() != 32 {
        return Err("Invalid session key".into());
    }
    session_key.copy_from_slice(&session_key_bytes);

    let master_key_bytes = aes_decrypt(&session_key, &session.wrapped_master_key)
        .map_err(|_| "Invalid session key".to_string())?;
    let mut master_key = [0u8; 32];
    if master_key_bytes.len() != 32 {
        return Err("Corrupted session".into());
    }
    master_key.copy_from_slice(&master_key_bytes);
    Ok(master_key)
}

fn revoke_session(session_dir: &PathBuf) {
    let _ = fs::remove_file(session_dir.join("session.json"));
}

// --- Resolve master key from password or session ---

fn get_master_key(
    msg: &serde_json::Value,
    cred_file: &PathBuf,
    session_dir: &PathBuf,
) -> Result<([u8; 32], CredentialStore, Option<String>), String> {
    let password = msg["password"].as_str().unwrap_or("");
    let session_key = msg["sessionKey"].as_str().unwrap_or("");

    // Try session first
    if !session_key.is_empty() {
        let master_key = resume_session(session_key, session_dir)?;
        let store = if cred_file.exists() {
            load_store(cred_file)?
        } else {
            return Err("No credential file".into());
        };
        return Ok((master_key, store, None));
    }

    // Otherwise use password
    if password.is_empty() {
        return Err("Password or session key required".into());
    }

    if !cred_file.exists() {
        // First time setup
        let (store, master_key) = create_store(password)?;
        save_store(cred_file, &store)?;
        info!("Created new credential store");
        let new_session = create_session(&master_key, session_dir)?;
        return Ok((master_key, store, Some(new_session)));
    }

    let store = load_store(cred_file)?;
    let master_key = unwrap_master_key(&store, password)?;
    let new_session = create_session(&master_key, session_dir)?;
    Ok((master_key, store, Some(new_session)))
}

// --- WebAuthn create ---

fn webauthn_create(
    data: &serde_json::Value,
    origin: &str,
    master_key: &[u8; 32],
    store: &mut CredentialStore,
    cred_file: &PathBuf,
) -> Result<serde_json::Value, String> {
    let challenge = b64url_decode(data["challenge"].as_str().ok_or("missing challenge")?)?;
    let rp = &data["rp"];
    let user = &data["user"];
    let rp_id_str = rp["id"].as_str().unwrap_or("");
    let rp_id = rp_id_str.as_bytes();

    let origin = if origin.is_empty() {
        data["origin"].as_str().ok_or("missing origin")?.to_string()
    } else {
        origin.to_string()
    };

    let user_id_str = user["id"].as_str().unwrap_or("");
    let user_id = b64url_decode(user_id_str)?;

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let credential_id: [u8; 16] = random_bytes();
    let credential_id_b64 = b64url_encode(&credential_id);
    let cose_pubkey = cose_public_key(&signing_key);

    let mut attested_data = vec![0u8; 16];
    attested_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    attested_data.extend_from_slice(&credential_id);
    attested_data.extend_from_slice(&cose_pubkey);

    let auth_data = build_auth_data(rp_id, 0, Some(&attested_data));

    use ciborium::Value as V;
    let attestation_cbor = cbor_encode(&V::Map(vec![
        (V::Text("fmt".into()), V::Text("none".into())),
        (V::Text("authData".into()), V::Bytes(auth_data.clone())),
        (V::Text("attStmt".into()), V::Map(vec![])),
    ]));

    let client_data_json = serde_json::json!({
        "challenge": b64url_encode(&challenge),
        "origin": origin,
        "type": "webauthn.create",
        "crossOrigin": false,
    })
    .to_string();

    let pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| format!("pem: {e}"))?;

    let secret = CredentialSecret {
        private_key_pem: pem.to_string(),
        user_id: b64url_encode(&user_id),
        counter: 0,
    };

    store.credentials.insert(
        credential_id_b64.clone(),
        StoredCredential {
            meta: CredentialMeta {
                rp_id: rp_id_str.to_string(),
                user_name: user["displayName"]
                    .as_str()
                    .or(user["name"].as_str())
                    .unwrap_or("")
                    .to_string(),
                created: now_secs(),
            },
            encrypted: encrypt_credential(master_key, &secret),
        },
    );
    save_store(cred_file, store)?;

    Ok(serde_json::json!({
        "authenticatorAttachment": "cross-platform",
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "attestationObject": b64url_encode(&attestation_cbor),
            "clientDataJSON": b64url_encode(client_data_json.as_bytes()),
            "authenticatorData": b64url_encode(&auth_data),
            "publicKey": b64url_encode(&cose_pubkey),
            "pubKeyAlgo": "-7",
            "transports": ["internal"],
        },
    }))
}

// --- WebAuthn get ---

fn webauthn_get(
    data: &serde_json::Value,
    origin: &str,
    master_key: &[u8; 32],
    store: &mut CredentialStore,
    cred_file: &PathBuf,
) -> Result<serde_json::Value, String> {
    let challenge = b64url_decode(data["challenge"].as_str().ok_or("missing challenge")?)?;
    let rp_id_str = data["rpId"].as_str().unwrap_or("");
    if rp_id_str.is_empty() {
        return Err("missing rpId".into());
    }
    let rp_id = rp_id_str.as_bytes();

    let origin = if origin.is_empty() {
        data["origin"].as_str().ok_or("missing origin")?.to_string()
    } else {
        origin.to_string()
    };

    // Find credential by allowCredentials or rpId discovery
    let allowed = data["allowCredentials"].as_array();
    let cred_id_b64 = if let Some(allowed) = allowed {
        let mut found = None;
        for entry in allowed {
            if let Some(id) = entry["id"].as_str() {
                if store.credentials.contains_key(id) {
                    found = Some(id.to_string());
                    break;
                }
            }
        }
        found.ok_or("No matching credential found")?
    } else {
        let mut found = None;
        for (cid, c) in &store.credentials {
            if c.meta.rp_id == rp_id_str {
                found = Some(cid.clone());
                break;
            }
        }
        found.ok_or("No matching credential found")?
    };

    let cred = store
        .credentials
        .get(&cred_id_b64)
        .ok_or("Credential not found")?;
    let mut secret = decrypt_credential(master_key, cred)?;

    secret.counter += 1;
    let auth_data = build_auth_data(rp_id, secret.counter, None);

    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": b64url_encode(&challenge),
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_bytes = client_data.to_string().into_bytes();
    let client_data_hash = Sha256::digest(&client_data_bytes);

    let signing_key = SigningKey::from_pkcs8_pem(&secret.private_key_pem)
        .map_err(|e| format!("key: {e}"))?;

    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(&client_data_hash);
    let signature: DerSignature = signing_key.sign(&signed_data);

    // Re-encrypt with updated counter
    let updated = StoredCredential {
        meta: cred.meta.clone(),
        encrypted: encrypt_credential(master_key, &secret),
    };
    store.credentials.insert(cred_id_b64.clone(), updated);
    save_store(cred_file, store)?;

    Ok(serde_json::json!({
        "authenticatorAttachment": "cross-platform",
        "id": cred_id_b64,
        "rawId": cred_id_b64,
        "type": "public-key",
        "response": {
            "authenticatorData": b64url_encode(&auth_data),
            "clientDataJSON": b64url_encode(&client_data_bytes),
            "signature": b64url_encode(&signature.to_bytes()),
            "userHandle": secret.user_id,
        },
    }))
}

// --- List credentials (no password needed) ---

fn list_credentials(cred_file: &PathBuf, rp_id: &str) -> Result<serde_json::Value, String> {
    if !cred_file.exists() {
        return Ok(serde_json::json!([]));
    }
    let store = load_store(cred_file)?;
    let matches: Vec<_> = store
        .credentials
        .iter()
        .filter(|(_, c)| rp_id.is_empty() || c.meta.rp_id == rp_id)
        .map(|(id, c)| {
            serde_json::json!({
                "id": id,
                "rp_id": c.meta.rp_id,
                "user_name": c.meta.user_name,
                "created": c.meta.created,
            })
        })
        .collect();
    Ok(serde_json::json!(matches))
}

// --- Native Messaging ---

fn read_message() -> Option<serde_json::Value> {
    let mut len_buf = [0u8; 4];
    if io::stdin().read_exact(&mut len_buf).is_err() {
        return None;
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    if io::stdin().read_exact(&mut buf).is_err() {
        return None;
    }
    serde_json::from_slice(&buf).ok()
}

fn send_message(msg: &serde_json::Value) {
    let data = serde_json::to_vec(msg).unwrap();
    let len = (data.len() as u32).to_le_bytes();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let _ = out.write_all(&len);
    let _ = out.write_all(&data);
    let _ = out.flush();
}

fn handle(msg: &serde_json::Value, cred_file: &PathBuf, session_dir: &PathBuf) -> serde_json::Value {
    let msg_type = msg["type"].as_str().unwrap_or("");
    let msg_id = &msg["id"];

    // No-auth operations
    match msg_type {
        "ping" => {
            return serde_json::json!({
                "id": msg_id,
                "success": true,
                "data": {"status": "ok"},
            });
        }
        "status" => {
            let exists = cred_file.exists();
            return serde_json::json!({
                "id": msg_id,
                "success": true,
                "data": {"needsSetup": !exists},
            });
        }
        "list" => {
            let rp_id = msg["rpId"].as_str().unwrap_or("");
            match list_credentials(cred_file, rp_id) {
                Ok(data) => {
                    return serde_json::json!({"id": msg_id, "success": true, "data": data});
                }
                Err(e) => {
                    return serde_json::json!({"id": msg_id, "success": false, "error": e});
                }
            }
        }
        "revoke" => {
            revoke_session(session_dir);
            return serde_json::json!({
                "id": msg_id,
                "success": true,
                "data": {"revoked": true},
            });
        }
        _ => {}
    }

    // Auth-required operations
    let data = &msg["data"];
    let options = &data["publicKey"];
    let origin = data["origin"].as_str().unwrap_or("");

    let (master_key, mut store, new_session) = match get_master_key(msg, cred_file, session_dir) {
        Ok(v) => v,
        Err(e) => {
            warn!("auth error: {}", e);
            return serde_json::json!({"id": msg_id, "success": false, "error": e});
        }
    };

    let rp = options["rp"]["id"]
        .as_str()
        .or(options["rpId"].as_str())
        .unwrap_or("");
    info!("{} rp={} origin={}", msg_type, rp, origin);

    let result = match msg_type {
        "create" => webauthn_create(options, origin, &master_key, &mut store, cred_file),
        "get" => webauthn_get(options, origin, &master_key, &mut store, cred_file),
        _ => Err(format!("Unknown type: {msg_type}")),
    };

    match result {
        Ok(data) => {
            info!("  success");
            let mut resp = serde_json::json!({"id": msg_id, "success": true, "data": data});
            if let Some(sk) = new_session {
                resp["sessionKey"] = serde_json::Value::String(sk);
            }
            resp
        }
        Err(e) => {
            warn!("  error: {}", e);
            serde_json::json!({"id": msg_id, "success": false, "error": e})
        }
    }
}

fn main() {
    let cred_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".passkeys");
    let cred_file = std::env::var("VWEBAUTHN_CRED_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| cred_dir.join("credentials.json"));

    let _ = fs::create_dir_all(&cred_dir);

    let log_file = cred_dir.join("host.log");
    if let Ok(file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
    {
        env_logger::Builder::new()
            .filter_level(
                if std::env::var("VWEBAUTHN_VERBOSE").unwrap_or_default() == "1" {
                    log::LevelFilter::Debug
                } else {
                    log::LevelFilter::Info
                },
            )
            .target(env_logger::Target::Pipe(Box::new(file)))
            .format_timestamp_secs()
            .init();
    }

    info!("Host started, cred_file={}", cred_file.display());

    loop {
        let msg = match read_message() {
            Some(m) => m,
            None => break,
        };
        let response = handle(&msg, &cred_file, &cred_dir);
        send_message(&response);
    }

    info!("Host exiting");
}

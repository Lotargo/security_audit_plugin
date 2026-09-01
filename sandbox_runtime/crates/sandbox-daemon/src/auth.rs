use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_EPOCH_DRIFT_SECS: u64 = 30;

#[allow(dead_code)]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKeyBuffer {
    pub key_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct TransportEnvelope {
    algorithm: String,
    ciphertext: String,
    nonce: String,
    tag: String,
}

#[derive(Clone)]
pub struct RatchetAuthState {
    trusted_host_pubkey: Option<VerifyingKey>,
    session_key: Option<Arc<Zeroizing<Vec<u8>>>>,
    seen_nonces: Arc<Mutex<HashMap<String, u64>>>,
    insecure_dev_mode: bool,
}

impl RatchetAuthState {
    pub fn new(
        host_pubkey_hex: Option<&str>,
        session_key_hex: Option<&str>,
        insecure_dev_mode: bool,
    ) -> Result<Self, String> {
        let trusted_host_pubkey = if let Some(hex_str) = host_pubkey_hex {
            let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex pubkey: {}", e))?;
            if bytes.len() != 32 {
                return Err("Ed25519 public key must be exactly 32 bytes".to_string());
            }
            let array: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "Ed25519 public key must be exactly 32 bytes".to_string())?;
            Some(
                VerifyingKey::from_bytes(&array)
                    .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?,
            )
        } else {
            None
        };

        let session_key = if let Some(hex_str) = session_key_hex {
            let bytes =
                hex::decode(hex_str).map_err(|e| format!("Invalid session key hex: {}", e))?;
            if bytes.len() != 32 {
                return Err("Bridge session key must be exactly 32 bytes".to_string());
            }
            Some(Arc::new(Zeroizing::new(bytes)))
        } else {
            None
        };

        if !insecure_dev_mode && trusted_host_pubkey.is_none() {
            return Err(
                "HOST_PUBKEY_HEX is required unless SANDBOX_INSECURE_DEV is enabled".to_string(),
            );
        }
        if !insecure_dev_mode && session_key.is_none() {
            return Err(
                "BRIDGE_SESSION_KEY_HEX is required unless SANDBOX_INSECURE_DEV is enabled"
                    .to_string(),
            );
        }

        Ok(Self {
            trusted_host_pubkey,
            session_key,
            seen_nonces: Arc::new(Mutex::new(HashMap::new())),
            insecure_dev_mode,
        })
    }

    pub fn verify_signature(
        &self,
        method: &str,
        path_and_query: &str,
        epoch_str: &str,
        nonce: &str,
        body_bytes: &[u8],
        signature_hex: &str,
    ) -> Result<(), (StatusCode, String)> {
        if self.insecure_dev_mode {
            return Ok(());
        }

        let epoch: u64 = epoch_str.parse().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid X-Ratchet-Epoch header".to_string(),
            )
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if epoch > now + 5 || now.saturating_sub(epoch) > MAX_EPOCH_DRIFT_SECS {
            warn!(
                "Rejected request: expired or future epoch. request={}, current={}",
                epoch, now
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("Epoch expired (drift > {}s)", MAX_EPOCH_DRIFT_SECS),
            ));
        }

        let body_hash = hex::encode(ring_sha256(body_bytes));
        let message = format!(
            "{}|{}|{}|{}|{}",
            method, path_and_query, epoch_str, nonce, body_hash
        );

        let pubkey = self.trusted_host_pubkey.as_ref().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "No trusted host public key configured in RatchetGuard".to_string(),
            )
        })?;

        let sig_bytes = hex::decode(signature_hex).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid hex signature in X-Signature-Host".to_string(),
            )
        })?;
        let signature = Signature::from_slice(&sig_bytes).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid signature structure".to_string(),
            )
        })?;

        pubkey
            .verify_strict(message.as_bytes(), &signature)
            .map_err(|e| {
                error!("RatchetGuard: Ed25519 signature verification failed: {}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    "Invalid host signature".to_string(),
                )
            })?;

        let mut msg_vec = message.into_bytes();
        msg_vec.zeroize();

        let mut nonces = self.seen_nonces.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Replay cache lock poisoned".to_string(),
            )
        })?;
        let oldest_allowed = now.saturating_sub(MAX_EPOCH_DRIFT_SECS + 5);
        nonces.retain(|_, seen_epoch| *seen_epoch >= oldest_allowed);
        if nonces.contains_key(nonce) {
            warn!("Rejected request: replayed nonce detected: {}", nonce);
            return Err((
                StatusCode::FORBIDDEN,
                "Replay attack detected: nonce already used".to_string(),
            ));
        }
        nonces.insert(nonce.to_string(), epoch);

        Ok(())
    }

    fn decrypt_body(
        &self,
        encrypted_body: &[u8],
        aad: &str,
    ) -> Result<Vec<u8>, (StatusCode, String)> {
        if encrypted_body.is_empty() {
            return Ok(Vec::new());
        }

        let envelope: TransportEnvelope = serde_json::from_slice(encrypted_body).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Protected request body is not a valid encrypted envelope".to_string(),
            )
        })?;

        if envelope.algorithm != "chacha20-poly1305" {
            return Err((
                StatusCode::BAD_REQUEST,
                "Unsupported transport encryption algorithm".to_string(),
            ));
        }

        let nonce_bytes = hex::decode(&envelope.nonce).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid encrypted envelope nonce".to_string(),
            )
        })?;
        if nonce_bytes.len() != 12 {
            return Err((
                StatusCode::BAD_REQUEST,
                "ChaCha20-Poly1305 nonce must be 12 bytes".to_string(),
            ));
        }

        let mut ciphertext = hex::decode(&envelope.ciphertext).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid encrypted envelope ciphertext".to_string(),
            )
        })?;
        let tag = hex::decode(&envelope.tag).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid encrypted envelope authentication tag".to_string(),
            )
        })?;
        if tag.len() != 16 {
            return Err((
                StatusCode::BAD_REQUEST,
                "ChaCha20-Poly1305 tag must be 16 bytes".to_string(),
            ));
        }
        ciphertext.extend_from_slice(&tag);

        let key = self.session_key.as_ref().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "No bridge session key configured".to_string(),
            )
        })?;
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid bridge session key".to_string(),
            )
        })?;

        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Encrypted payload authentication failed".to_string(),
                )
            })
    }
}

fn ring_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub async fn ratchet_auth_middleware(
    axum::extract::State(state): axum::extract::State<RatchetAuthState>,
    headers: HeaderMap,
    req: Request<Body>,
    next: Next,
) -> Response {
    if state.insecure_dev_mode {
        return next.run(req).await;
    }

    let method = req.method().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| req.uri().path())
        .to_string();

    let signature = match headers
        .get("x-signature-host")
        .and_then(|h| h.to_str().ok())
    {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing X-Signature-Host header"})),
            )
                .into_response();
        }
    };
    let epoch = match headers.get("x-ratchet-epoch").and_then(|h| h.to_str().ok()) {
        Some(e) => e,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing X-Ratchet-Epoch header"})),
            )
                .into_response();
        }
    };
    let nonce = match headers.get("x-nonce").and_then(|h| h.to_str().ok()) {
        Some(n) => n,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing X-Nonce header"})),
            )
                .into_response();
        }
    };
    let aad = match headers.get("x-aad-binding").and_then(|h| h.to_str().ok()) {
        Some(value) => value,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing X-AAD-Binding header"})),
            )
                .into_response();
        }
    };

    let expected_aad = format!("host_mcp:{}:{}:{}", method, path_and_query, epoch);
    if aad != expected_aad {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AAD binding mismatch"})),
        )
            .into_response();
    }

    let (parts, body) = req.into_parts();
    let encrypted_bytes = match axum::body::to_bytes(body, 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Failed to read request body: {}", e)})),
            )
                .into_response();
        }
    };

    if let Err((status, msg)) = state.verify_signature(
        &method,
        &path_and_query,
        epoch,
        nonce,
        &encrypted_bytes,
        signature,
    ) {
        return (status, Json(json!({"error": msg}))).into_response();
    }

    let plain_bytes = match state.decrypt_body(&encrypted_bytes, aad) {
        Ok(bytes) => bytes,
        Err((status, msg)) => return (status, Json(json!({"error": msg}))).into_response(),
    };

    let req = Request::from_parts(parts, Body::from(plain_bytes));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn state_and_key() -> (RatchetAuthState, SigningKey) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.as_bytes());
        let session_key_hex = "11".repeat(32);
        let state =
            RatchetAuthState::new(Some(&pubkey_hex), Some(&session_key_hex), false).unwrap();
        (state, signing_key)
    }

    fn signed_request(
        signing_key: &SigningKey,
        method: &str,
        path: &str,
        nonce: &str,
        body: &[u8],
    ) -> (String, String) {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let body_hash = hex::encode(ring_sha256(body));
        let message = format!("{}|{}|{}|{}|{}", method, path, epoch, nonce, body_hash);
        let signature = signing_key.sign(message.as_bytes());
        (epoch, hex::encode(signature.to_bytes()))
    }

    #[test]
    fn test_valid_signature_and_replay_rejection() {
        let (state, signing_key) = state_and_key();
        let method = "POST";
        let path = "/execute";
        let nonce = "nonce_123456789012";
        let body = b"{\"ciphertext\":\"00\"}";
        let (epoch, sig_hex) = signed_request(&signing_key, method, path, nonce, body);

        assert!(state
            .verify_signature(method, path, &epoch, nonce, body, &sig_hex)
            .is_ok());

        let replay = state.verify_signature(method, path, &epoch, nonce, body, &sig_hex);
        assert!(replay.is_err());
        assert_eq!(replay.unwrap_err().0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn invalid_signature_does_not_poison_nonce_cache() {
        let (state, signing_key) = state_and_key();
        let method = "GET";
        let path = "/poll_logs?session=main";
        let nonce = "same_nonce_after_invalid_signature";
        let body = b"";
        let (epoch, valid_sig) = signed_request(&signing_key, method, path, nonce, body);

        let invalid = state.verify_signature(method, path, &epoch, nonce, body, &"00".repeat(64));
        assert!(invalid.is_err());

        assert!(state
            .verify_signature(method, path, &epoch, nonce, body, &valid_sig)
            .is_ok());
    }
}

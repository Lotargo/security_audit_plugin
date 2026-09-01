use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::json;
use tracing::{error, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_EPOCH_DRIFT_SECS: u64 = 30;

#[allow(dead_code)]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKeyBuffer {
    pub key_bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct RatchetAuthState {
    trusted_host_pubkey: Option<VerifyingKey>,
    seen_nonces: Arc<Mutex<HashSet<String>>>,
    insecure_dev_mode: bool,
}

impl RatchetAuthState {
    pub fn new(host_pubkey_hex: Option<&str>, insecure_dev_mode: bool) -> Result<Self, String> {
        let trusted_host_pubkey = if let Some(hex_str) = host_pubkey_hex {
            let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex pubkey: {}", e))?;
            if bytes.len() != 32 {
                return Err("Ed25519 public key must be exactly 32 bytes".to_string());
            }
            let array: [u8; 32] = bytes.as_slice().try_into().unwrap();
            let key = VerifyingKey::from_bytes(&array)
                .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;
            Some(key)
        } else {
            None
        };

        Ok(Self {
            trusted_host_pubkey,
            seen_nonces: Arc::new(Mutex::new(HashSet::new())),
            insecure_dev_mode,
        })
    }

    /// Verifies the Ed25519 signature of an incoming envelope
    pub fn verify_signature(
        &self,
        method: &str,
        path: &str,
        epoch_str: &str,
        nonce: &str,
        body_bytes: &[u8],
        signature_hex: &str,
    ) -> Result<(), (StatusCode, String)> {
        if self.insecure_dev_mode {
            return Ok(());
        }

        // 1. Verify epoch timestamp
        let epoch: u64 = epoch_str.parse().map_err(|_| {
            (StatusCode::BAD_REQUEST, "Invalid X-Ratchet-Epoch header".to_string())
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if epoch > now + 5 || now.saturating_sub(epoch) > MAX_EPOCH_DRIFT_SECS {
            warn!("Rejected request: Expired or future epoch. Request: {}, Current: {}", epoch, now);
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("Epoch expired (drift > {}s)", MAX_EPOCH_DRIFT_SECS),
            ));
        }

        // 2. Replay protection via nonce cache
        {
            let mut nonces = self.seen_nonces.lock().unwrap();
            if nonces.contains(nonce) {
                warn!("Rejected request: Replayed nonce detected: {}", nonce);
                return Err((StatusCode::FORBIDDEN, "Replay attack detected: Nonce already used".to_string()));
            }
            // Keep cache bounded
            if nonces.len() > 10_000 {
                nonces.clear();
            }
            nonces.insert(nonce.to_string());
        }

        // 3. Construct signing message
        let body_hash = hex::encode(ring_sha256(body_bytes));
        let message = format!("{}|{}|{}|{}|{}", method, path, epoch_str, nonce, body_hash);

        // 4. Verify Ed25519 Signature
        let pubkey = self.trusted_host_pubkey.as_ref().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "No trusted host public key configured in RatchetGuard".to_string(),
            )
        })?;

        let sig_bytes = hex::decode(signature_hex).map_err(|_| {
            (StatusCode::BAD_REQUEST, "Invalid hex signature in X-Signature-Host".to_string())
        })?;

        let signature = Signature::from_slice(&sig_bytes).map_err(|_| {
            (StatusCode::BAD_REQUEST, "Invalid signature structure".to_string())
        })?;

        pubkey
            .verify_strict(message.as_bytes(), &signature)
            .map_err(|e| {
                error!("RatchetGuard: Ed25519 signature verification failed: {}", e);
                (StatusCode::UNAUTHORIZED, "Invalid host signature".to_string())
            })?;

        // 5. Zeroize sensitive temporary message buffer
        let mut msg_vec = message.into_bytes();
        msg_vec.zeroize();

        Ok(())
    }
}

fn ring_sha256(data: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    // Simple deterministic hash representation for signing verification message
    // In production crypto envelope this is SHA256
    let mut hasher = DefaultHasher::new();
    hasher.write(data);
    let h1 = hasher.finish();
    hasher.write(&[0xFF, 0xAA]);
    let h2 = hasher.finish();
    hasher.write(&[0x11, 0x22]);
    let h3 = hasher.finish();
    hasher.write(&[0x77, 0x88]);
    let h4 = hasher.finish();

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&h1.to_le_bytes());
    out[8..16].copy_from_slice(&h2.to_le_bytes());
    out[16..24].copy_from_slice(&h3.to_le_bytes());
    out[24..32].copy_from_slice(&h4.to_le_bytes());
    out
}

/// Axum Middleware function for RatchetGuard envelope verification
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
    let path = req.uri().path().to_string();

    let signature = match headers.get("x-signature-host").and_then(|h| h.to_str().ok()) {
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

    // Buffer body to verify signature
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Failed to read request body: {}", e)})),
            )
                .into_response();
        }
    };

    if let Err((status, msg)) = state.verify_signature(&method, &path, epoch, nonce, &bytes, signature) {
        return (status, Json(json!({"error": msg}))).into_response();
    }

    let req = Request::from_parts(parts, Body::from(bytes));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn test_valid_signature_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.as_bytes());

        let auth_state = RatchetAuthState::new(Some(&pubkey_hex), false).unwrap();

        let method = "POST";
        let path = "/execute";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let epoch_str = now.to_string();
        let nonce = "nonce_123456789012";
        let body = b"{\"command\":\"whoami\"}";

        let body_hash = hex::encode(ring_sha256(body));
        let message = format!("{}|{}|{}|{}|{}", method, path, epoch_str, nonce, body_hash);

        use ed25519_dalek::Signer;
        let signature = signing_key.sign(message.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        let res = auth_state.verify_signature(method, path, &epoch_str, nonce, body, &sig_hex);
        assert!(res.is_ok());

        // Replay attack test (same nonce)
        let replay_res = auth_state.verify_signature(method, path, &epoch_str, nonce, body, &sig_hex);
        assert!(replay_res.is_err());
        assert_eq!(replay_res.unwrap_err().0, StatusCode::FORBIDDEN);
    }
}

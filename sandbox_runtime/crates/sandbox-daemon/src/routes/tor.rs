use axum::{http::StatusCode, Json};
use serde_json::json;
use std::fmt::Write as FmtWrite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

const TOR_CONTROL_COOKIE: &str = "/var/lib/tor/control_auth_cookie";

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02X}");
    }
    out
}

fn read_control_cookie_hex() -> Result<String, std::io::Error> {
    std::fs::read(TOR_CONTROL_COOKIE).map(|bytes| encode_hex(&bytes))
}

pub async fn handle_rotate_tor(
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    info!("Tor IP rotation requested via localhost cookie-authenticated ControlPort");

    let cookie = read_control_cookie_hex().map_err(|e| {
        warn!("Tor control cookie unavailable: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("Tor control cookie unavailable: {}", e)})),
        )
    })?;

    let mut stream = TcpStream::connect("127.0.0.1:9051").await.map_err(|e| {
        warn!("Tor ControlPort is not reachable: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Tor ControlPort unavailable: {}", e)})),
        )
    })?;

    let auth_command = format!("AUTHENTICATE {cookie}\r\n");
    stream
        .write_all(auth_command.as_bytes())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Tor ControlPort write failed: {}", e)})),
            )
        })?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Tor ControlPort read failed: {}", e)})),
        )
    })?;
    let auth_resp = String::from_utf8_lossy(&buf[..n]);
    if !auth_resp.starts_with("250") {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Tor cookie authentication rejected: {}", auth_resp.trim())})),
        ));
    }

    stream.write_all(b"SIGNAL NEWNYM\r\n").await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to send SIGNAL NEWNYM: {}", e)})),
        )
    })?;

    let n = stream.read(&mut buf).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to read NEWNYM response: {}", e)})),
        )
    })?;
    let sig_resp = String::from_utf8_lossy(&buf[..n]);
    if !sig_resp.starts_with("250") {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Tor NEWNYM signal rejected: {}", sig_resp.trim())})),
        ));
    }

    info!("Successfully sent authenticated SIGNAL NEWNYM to Tor ControlPort.");
    Ok(Json(json!({
        "status": "success",
        "message": "Tor circuit rotated successfully (SIGNAL NEWNYM applied)",
        "control_response": sig_resp.trim()
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_control_cookie_as_tor_auth_hex() {
        assert_eq!(encode_hex(&[0x00, 0xab, 0xff]), "00ABFF");
    }
}

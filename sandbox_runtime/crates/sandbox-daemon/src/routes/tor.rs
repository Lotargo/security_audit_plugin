use axum::{http::StatusCode, Json};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

pub async fn handle_rotate_tor() -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    info!("Tor IP rotation requested: Attempting to send SIGNAL NEWNYM to 127.0.0.1:9051");

    match TcpStream::connect("127.0.0.1:9051").await {
        Ok(mut stream) => {
            // 1. Authenticate to Tor ControlPort
            if let Err(e) = stream.write_all(b"AUTHENTICATE \"\"\r\n").await {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Tor ControlPort write failed: {}", e)})),
                ));
            }

            let mut buf = [0u8; 1024];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("Tor ControlPort read failed: {}", e)})),
                    ));
                }
            };
            let auth_resp = String::from_utf8_lossy(&buf[..n]);
            if !auth_resp.starts_with("250") {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Tor auth rejected: {}", auth_resp.trim())})),
                ));
            }

            // 2. Send SIGNAL NEWNYM for dynamic circuit rotation
            if let Err(e) = stream.write_all(b"SIGNAL NEWNYM\r\n").await {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to send SIGNAL NEWNYM: {}", e)})),
                ));
            }

            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("Failed to read NEWNYM response: {}", e)})),
                    ));
                }
            };
            let sig_resp = String::from_utf8_lossy(&buf[..n]);
            if !sig_resp.starts_with("250") {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Tor NEWNYM signal rejected: {}", sig_resp.trim())})),
                ));
            }

            info!("Successfully sent SIGNAL NEWNYM to Tor ControlPort.");
            Ok(Json(json!({
                "status": "success",
                "message": "Tor circuit rotated successfully (SIGNAL NEWNYM applied)",
                "control_response": sig_resp.trim()
            })))
        }
        Err(e) => {
            warn!("Tor service not reachable on 127.0.0.1:9051 (mock/dev fallback active): {}", e);
            Ok(Json(json!({
                "status": "simulated",
                "message": "Tor ControlPort unreachable in current environment, simulated IP rotation success",
                "detail": e.to_string()
            })))
        }
    }
}

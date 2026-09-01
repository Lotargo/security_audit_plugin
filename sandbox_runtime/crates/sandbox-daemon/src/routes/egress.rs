use axum::{http::StatusCode, Json};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};

use sandbox_kernel::egress::{EgressConfig, EgressManager};
use sandbox_kernel::panic::KillSwitch;

#[derive(Debug, Deserialize)]
pub struct EmergencyIsolateRequest {
    pub reason: Option<String>,
}

pub async fn handle_provision_egress(
    Json(config): Json<EgressConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    info!("Provisioning egress rules for mode: {:?}", config.mode);
    let manager = EgressManager::new();

    match manager.apply_rules(&config) {
        Ok(_) => Ok(Json(json!({
            "status": "success",
            "mode": config.mode,
            "allowed_cidrs": config.allowed_cidrs,
            "tor_enabled": config.tor_enabled,
            "proxy_enabled": config.proxy_enabled,
        }))),
        Err(e) => {
            error!("Failed to apply egress rules: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to apply egress rules: {}", e)})),
            ))
        }
    }
}

pub async fn handle_emergency_isolate(
    Json(payload): Json<EmergencyIsolateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let reason = payload
        .reason
        .unwrap_or_else(|| "Manual emergency isolation triggered".to_string());
    warn!("Emergency isolation request received: {}", reason);

    match KillSwitch::trigger(&reason) {
        Ok(_) => Ok(Json(json!({
            "status": "isolated",
            "reason": reason,
            "is_isolated": true
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to trigger kill switch: {}", e)})),
        )),
    }
}

pub async fn handle_isolation_status() -> Json<serde_json::Value> {
    Json(json!({
        "is_isolated": KillSwitch::is_isolated()
    }))
}

use std::path::PathBuf;
use std::sync::Arc;
use axum::{http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{error, info};

use sandbox_kernel::canary::CanaryManager;

#[derive(Debug, Deserialize)]
pub struct ArmCanaryRequest {
    pub base_dir: Option<String>,
}

pub async fn handle_arm_canary(
    Extension(canary_mgr): Extension<Arc<Mutex<CanaryManager>>>,
    Json(payload): Json<ArmCanaryRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let base_path = PathBuf::from(payload.base_dir.unwrap_or_else(|| "/workspace".to_string()));
    info!("Arming canary tripwires under base directory: {:?}", base_path);

    let mut mgr = canary_mgr.lock().await;
    match mgr.arm_canaries(&base_path).await {
        Ok(traps) => {
            let traps_summary: Vec<_> = traps.iter().map(|t| {
                json!({
                    "path": t.file_path.to_string_lossy(),
                    "type": t.trap_type,
                    "description": t.description
                })
            }).collect();

            Ok(Json(json!({
                "status": "armed",
                "traps_count": traps.len(),
                "traps": traps_summary
            })))
        }
        Err(e) => {
            error!("Failed to arm canaries: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to arm canaries: {}", e)})),
            ))
        }
    }
}

pub async fn handle_canary_status(
    Extension(canary_mgr): Extension<Arc<Mutex<CanaryManager>>>,
) -> Json<serde_json::Value> {
    let mgr = canary_mgr.lock().await;
    Json(json!({
        "is_armed": mgr.is_armed(),
        "traps_count": mgr.get_traps().len()
    }))
}

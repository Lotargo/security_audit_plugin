use axum::{http::StatusCode, Json};
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{error, info};

use sandbox_kernel::audit_exec_identity;

pub async fn handle_browser_audit(
    Json(config): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let config_bytes = serde_json::to_vec(&config).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid browser config: {}", e)})),
        )
    })?;

    let mut command = Command::new("node");
    command
        .arg("/opt/stealth/browser_launcher.js")
        .arg("--stdin-json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("HOME", "/tmp");

    #[cfg(unix)]
    {
        let (uid, gid) = audit_exec_identity();
        command.as_std_mut().uid(uid).gid(gid);
    }

    let mut child = command.spawn().map_err(|e| {
        error!("Failed to start browser launcher: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to start browser launcher"})),
        )
    })?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&config_bytes).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to pass browser config: {}", e)})),
            )
        })?;
    }

    let output = tokio::time::timeout(Duration::from_secs(150), child.wait_with_output())
        .await
        .map_err(|_| {
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({"error": "Browser audit timed out"})),
            )
        })?
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Browser process failed: {}", e)})),
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Browser audit failed: {}", stderr);
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "Browser audit process failed",
                "exit_code": output.status.code()
            })),
        ));
    }

    let report: Value = serde_json::from_slice(&output.stdout).map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("Invalid browser report JSON: {}", e)})),
        )
    })?;

    info!("Browser audit completed successfully");
    Ok(Json(report))
}

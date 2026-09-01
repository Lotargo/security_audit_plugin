use axum::{http::StatusCode, Json};
use serde_json::Value;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{error, info};

use sandbox_kernel::browser_exec_identity;

fn has_proxy(config: &Value) -> bool {
    config
        .get("proxy")
        .and_then(Value::as_str)
        .is_some_and(|proxy| !proxy.trim().is_empty())
}

fn has_scope_hosts(config: &Value) -> bool {
    config
        .get("allowed_hosts")
        .and_then(Value::as_array)
        .is_some_and(|hosts| {
            hosts
                .iter()
                .any(|host| host.as_str().is_some_and(|v| !v.trim().is_empty()))
        })
}

pub async fn handle_browser_audit(
    Json(config): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if has_proxy(&config) && !has_scope_hosts(&config) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Proxied browser audits require an explicit RoE host allowlist"
            })),
        ));
    }

    let config_bytes = serde_json::to_vec(&config).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid browser config: {}", e)})),
        )
    })?;

    let (uid, gid) = browser_exec_identity();
    let mut command = Command::new("setpriv");
    command
        .arg(format!("--reuid={uid}"))
        .arg(format!("--regid={gid}"))
        .arg("--clear-groups")
        .arg("--no-new-privs")
        .arg("--")
        .arg("node")
        .arg("/opt/stealth/browser_launcher.js")
        .arg("--stdin-json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("HOME", "/tmp");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxied_browser_requires_scope_hosts() {
        let config =
            serde_json::json!({"url": "https://example.com", "proxy": "socks5://127.0.0.1:9050"});
        assert!(has_proxy(&config));
        assert!(!has_scope_hosts(&config));

        let scoped = serde_json::json!({
            "url": "https://example.com",
            "proxy": "socks5://127.0.0.1:9050",
            "allowed_hosts": ["example.com"]
        });
        assert!(has_proxy(&scoped));
        assert!(has_scope_hosts(&scoped));
    }
}

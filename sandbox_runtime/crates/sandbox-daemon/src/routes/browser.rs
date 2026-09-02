use axum::{http::StatusCode, Json};
use serde_json::Value;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{error, info};

use sandbox_kernel::browser_exec_identity;

const SAFE_CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const TOR_BROWSER_PROXY: &str = "socks5://127.0.0.1:9050";
const TOR_HTTP_PROXY: &str = "socks5h://127.0.0.1:9050";

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

fn has_forbidden_authority_header(config: &Value) -> bool {
    ["auth_headers", "spoof_headers"].iter().any(|field| {
        config
            .get(field)
            .and_then(Value::as_object)
            .is_some_and(|headers| {
                headers.keys().any(|key| {
                    let normalized = key.trim().to_ascii_lowercase();
                    normalized == "host" || normalized == ":authority"
                })
            })
    })
}

fn proxy_is_managed_tor(config: &Value) -> bool {
    config
        .get("proxy")
        .and_then(Value::as_str)
        .is_none_or(|proxy| {
            let proxy = proxy.trim();
            proxy.is_empty() || proxy == TOR_BROWSER_PROXY || proxy == TOR_HTTP_PROXY
        })
}

pub async fn handle_browser_audit(
    Json(config): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !has_scope_hosts(&config) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Browser audits require an explicit RoE host allowlist"
            })),
        ));
    }
    if has_proxy(&config) && !proxy_is_managed_tor(&config) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Browser proxy must use the managed local Tor transport"
            })),
        ));
    }
    if has_forbidden_authority_header(&config) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Custom Host/:authority headers are forbidden by the RoE boundary"
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
    let mut command = Command::new("/usr/bin/setpriv");
    command
        .arg(format!("--reuid={uid}"))
        .arg(format!("--regid={gid}"))
        .arg("--clear-groups")
        .arg("--no-new-privs")
        .arg("--")
        .arg("/usr/bin/node")
        .arg("/opt/stealth/browser_launcher.js")
        .arg("--stdin-json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear()
        .env("HOME", "/tmp")
        .env("PATH", SAFE_CHILD_PATH)
        .env("LANG", "C.UTF-8")
        .env("CHROMIUM_PATH", "/usr/bin/chromium")
        .env("NODE_PATH", "/opt/stealth/node_modules");

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
    fn browser_always_requires_scope_hosts() {
        let direct = serde_json::json!({"url": "https://example.com"});
        assert!(!has_scope_hosts(&direct));

        let scoped = serde_json::json!({
            "url": "https://example.com",
            "allowed_hosts": ["example.com"]
        });
        assert!(has_scope_hosts(&scoped));
    }

    #[test]
    fn browser_rejects_authority_override_headers() {
        let spoofed = serde_json::json!({
            "url": "https://example.com",
            "allowed_hosts": ["example.com"],
            "spoof_headers": {"Host": "evil.example"}
        });
        assert!(has_forbidden_authority_header(&spoofed));

        let auth = serde_json::json!({
            "url": "https://example.com",
            "allowed_hosts": ["example.com"],
            "auth_headers": {":authority": "evil.example"}
        });
        assert!(has_forbidden_authority_header(&auth));
    }

    #[test]
    fn browser_proxy_is_limited_to_managed_tor() {
        let managed = serde_json::json!({"proxy": TOR_BROWSER_PROXY});
        let external = serde_json::json!({"proxy": "http://proxy.example:8080"});
        assert!(proxy_is_managed_tor(&managed));
        assert!(!proxy_is_managed_tor(&external));
    }
}

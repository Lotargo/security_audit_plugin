use axum::{http::StatusCode, Extension, Json};
use serde_json::Value;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::browser_sandbox;
use crate::evolve_events::EvolveEventSink;
use crate::surface_guard::{resolve_agent_surface, AgentSurface};
use sandbox_kernel::browser_exec_identity;
use sandbox_kernel::{EventSource, EvolveManager, RiskLevel, SecurityEvent, SecurityEventType};

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

fn evolve_session_id(config: &Value) -> Option<&str> {
    config.get("evolve_session_id").and_then(Value::as_str)
}

fn requested_url(config: &Value) -> Option<&str> {
    config.get("url").and_then(Value::as_str)
}

fn emit_browser_event(
    event_sink: &EvolveEventSink,
    config: &Value,
    event_type: SecurityEventType,
    risk: RiskLevel,
    result: &str,
) {
    let mut event = SecurityEvent::new(EventSource::Browser, event_type)
        .with_result(result.to_string())
        .with_risk_hint(risk);

    if let Some(session_id) = evolve_session_id(config) {
        event = event.with_session_id(session_id.to_string());
    }
    if let Some(url) = requested_url(config) {
        event = event.with_destination(url.to_string());
    }

    event_sink.emit(event);
}

fn emit_browser_policy_violation(event_sink: &EvolveEventSink, config: &Value, reason: &str) {
    let mut event = SecurityEvent::new(EventSource::Policy, SecurityEventType::PolicyViolation)
        .with_resource("browser_audit")
        .with_result(reason.to_string())
        .with_risk_hint(RiskLevel::Medium);

    if let Some(session_id) = evolve_session_id(config) {
        event = event.with_session_id(session_id.to_string());
    }
    if let Some(url) = requested_url(config) {
        event = event.with_destination(url.to_string());
    }

    event_sink.emit(event);
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
    Extension(event_sink): Extension<EvolveEventSink>,
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Json(config): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let surface = {
        let manager = evolve_mgr.lock().await;
        resolve_agent_surface(&manager, evolve_session_id(&config))
    }
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "browser service temporarily unavailable"})),
        )
    })?;
    if surface == AgentSurface::Deception {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "browser service temporarily unavailable"})),
        ));
    }

    if !has_scope_hosts(&config) {
        emit_browser_policy_violation(
            &event_sink,
            &config,
            "browser request missing explicit RoE host allowlist",
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Browser audits require an explicit RoE host allowlist"
            })),
        ));
    }
    if has_proxy(&config) && !proxy_is_managed_tor(&config) {
        emit_browser_policy_violation(
            &event_sink,
            &config,
            "browser attempted unmanaged proxy transport",
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Browser proxy must use the managed local Tor transport"
            })),
        ));
    }
    if has_forbidden_authority_header(&config) {
        emit_browser_policy_violation(
            &event_sink,
            &config,
            "browser attempted Host/:authority override",
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Custom Host/:authority headers are forbidden by the RoE boundary"
            })),
        ));
    }

    emit_browser_event(
        &event_sink,
        &config,
        SecurityEventType::BrowserNavigation,
        RiskLevel::Low,
        "started",
    );

    // ROADMAP п.11: isolate browser filesystem view. Never hand the real
    // /workspace to hostile web content; use a per-audit /tmp dir and force
    // out_dir into it even if the caller requested /workspace.
    let audit_id = evolve_session_id(&config).unwrap_or("browser-audit");
    let isolated_out = browser_sandbox::isolated_output_dir(audit_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to isolate browser output: {}", e)})),
        )
    })?;
    let mut config_value = config.clone();
    if let Some(obj) = config_value.as_object_mut() {
        obj.insert(
            "out_dir".to_string(),
            serde_json::Value::String(isolated_out.to_string_lossy().into_owned()),
        );
        // Defense in depth: strip legacy workspace output even if launcher defaults change.
        // isolated_out is already under /tmp.
    }
    let config_bytes = serde_json::to_vec(&config_value).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid browser config: {}", e)})),
        )
    })?;

    let (uid, gid) = browser_exec_identity();
    // Prefer bwrap filesystem isolation (п.10/п.11) where the kernel allows it;
    // fall back to the legacy setpriv path on runtimes where bwrap namespaces
    // are rejected (e.g. Docker Desktop pivot_root EPERM). out_dir stays
    // isolated under /var/tmp in both cases, never the real /workspace.
    let use_bwrap = browser_sandbox::is_bwrap_functional();
    if !use_bwrap {
        tracing::warn!("bwrap namespaces unavailable, browser audit uses setpriv fallback without filesystem view isolation");
    }
    let mut command = match use_bwrap
        .then(|| browser_sandbox::command(&isolated_out))
        .transpose()
    {
        Ok(Some(mut bwrap)) => {
            bwrap
                .arg("--")
                .arg("/usr/bin/setpriv")
                .arg(format!("--reuid={uid}"))
                .arg(format!("--regid={gid}"))
                .arg("--clear-groups")
                .arg("--bounding-set=-all")
                .arg("--inh-caps=-all")
                .arg("--ambient-caps=-all")
                .arg("--no-new-privs")
                .arg("--")
                .arg("/usr/bin/node")
                .arg("/opt/stealth/browser_launcher.js")
                .arg("--stdin-json")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            bwrap
        }
        Err(_) | Ok(None) => {
            let mut fallback = Command::new("/usr/bin/setpriv");
            fallback
                .arg(format!("--reuid={uid}"))
                .arg(format!("--regid={gid}"))
                .arg("--clear-groups")
                .arg("--bounding-set=-all")
                .arg("--inh-caps=-all")
                .arg("--ambient-caps=-all")
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
                .env("XDG_CONFIG_HOME", "/tmp")
                .env("XDG_CACHE_HOME", "/tmp")
                .env("USER", "audit-browser")
                .env("LOGNAME", "audit-browser")
                .env("PATH", SAFE_CHILD_PATH)
                .env("LANG", "C.UTF-8")
                .env("CHROMIUM_PATH", "/usr/lib/chromium/chromium")
                .env("NODE_PATH", "/opt/stealth/node_modules");
            fallback
        }
    };

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

    emit_browser_event(
        &event_sink,
        &config,
        SecurityEventType::BrowserNavigation,
        RiskLevel::Low,
        "completed",
    );
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

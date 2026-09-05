use axum::{http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::evolve_events::EvolveEventSink;
use crate::surface_guard::{resolve_agent_surface, AgentSurface};

use sandbox_kernel::containment::apply_runtime_containment_with_agent_allowlist;
use sandbox_kernel::egress::{is_valid_ip_or_cidr, EgressConfig, EgressError, EgressManager};
use sandbox_kernel::panic::KillSwitch;
use sandbox_kernel::stop_tor_best_effort;
use sandbox_kernel::{EventSource, EvolveManager, RiskLevel, SecurityEvent, SecurityEventType};

#[derive(Debug, Deserialize)]
pub struct EmergencyIsolateRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProvisionEgressRequest {
    #[serde(flatten)]
    pub config: EgressConfig,
    #[serde(default)]
    pub agent_allowed_cidrs: Vec<String>,
    #[serde(default)]
    pub evolve_session_id: Option<String>,
}

fn emit_egress_policy_violation(event_sink: &EvolveEventSink, reason: &str) {
    event_sink.emit(
        SecurityEvent::new(EventSource::Policy, SecurityEventType::PolicyViolation)
            .with_resource("egress_scope")
            .with_result(reason.to_string())
            .with_risk_hint(RiskLevel::Medium),
    );
}

fn isolation_latch_error() -> Option<(StatusCode, Json<serde_json::Value>)> {
    if KillSwitch::is_isolated() {
        Some((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Emergency isolation is latched for this runtime. Recreate/reset the sandbox before provisioning any new egress scope."
            })),
        ))
    } else {
        None
    }
}

fn bad_request(message: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": message.into()})),
    )
}

fn validate_agent_allowlist(
    config: &EgressConfig,
    agent_allowed_cidrs: &[String],
) -> Result<(), String> {
    for cidr in agent_allowed_cidrs {
        if !is_valid_ip_or_cidr(cidr) {
            return Err(format!("Invalid agent_allowed_cidrs entry: {cidr}"));
        }
        if cidr.trim() == "0.0.0.0/0" || cidr.trim() == "::/0" {
            return Err("Unbounded /0 CIDRs are not permitted for raw agent egress".to_string());
        }
        if !config
            .allowed_cidrs
            .iter()
            .any(|allowed| allowed.trim() == cidr.trim())
        {
            return Err(format!(
                "agent_allowed_cidrs must be a subset of allowed_cidrs: {cidr}"
            ));
        }
    }
    Ok(())
}

pub async fn handle_provision_egress(
    Extension(event_sink): Extension<EvolveEventSink>,
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Json(payload): Json<ProvisionEgressRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ProvisionEgressRequest {
        config,
        agent_allowed_cidrs,
        evolve_session_id,
    } = payload;

    let surface = {
        let manager = evolve_mgr.lock().await;
        resolve_agent_surface(&manager, evolve_session_id.as_deref())
    }
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "scope service temporarily unavailable"})),
        )
    })?;
    if surface == AgentSurface::Deception {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "scope service temporarily unavailable"})),
        ));
    }

    info!("Provisioning egress rules for mode: {:?}", config.mode);

    if let Some(error) = isolation_latch_error() {
        emit_egress_policy_violation(
            &event_sink,
            "attempted to provision egress while emergency isolation is latched",
        );
        return Err(error);
    }

    if config.proxy_enabled || config.proxy_target.is_some() {
        let reason =
            "External upstream proxy containment is not implemented safely; only managed Tor is supported";
        emit_egress_policy_violation(&event_sink, reason);
        return Err(bad_request(reason));
    }
    if config.tor_enabled && config.targets.is_empty() {
        let reason =
            "Tor egress requires at least one explicit target; transport alone is not audit scope";
        emit_egress_policy_violation(&event_sink, reason);
        return Err(bad_request(reason));
    }
    if let Err(message) = validate_agent_allowlist(&config, &agent_allowed_cidrs) {
        emit_egress_policy_violation(&event_sink, &message);
        return Err(bad_request(message));
    }

    let manager = EgressManager::new();
    if let Err(e) = manager.apply_rules(&config) {
        error!("Failed to apply egress rules: {}", e);
        let status = match &e {
            EgressError::InvalidAddress(_) | EgressError::InvalidPolicy(_) => {
                emit_egress_policy_violation(
                    &event_sink,
                    &format!("Rejected invalid egress policy: {e}"),
                );
                StatusCode::BAD_REQUEST
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return Err((
            status,
            Json(json!({"error": format!("Failed to apply egress rules: {}", e)})),
        ));
    }

    if let Err(e) = apply_runtime_containment_with_agent_allowlist(&config, &agent_allowed_cidrs) {
        // The base ruleset replacement removes any previous containment rules. If restoring the
        // process layer fails, stop Tor immediately so a pre-existing circuit cannot remain usable
        // through loopback by the agent identity.
        stop_tor_best_effort();
        error!("Failed to apply runtime containment: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Failed to apply runtime containment: {}", e)
            })),
        ));
    }

    Ok(Json(json!({
        "status": "success",
        "mode": config.mode,
        "allowed_cidrs": config.allowed_cidrs,
        "agent_allowed_cidrs": agent_allowed_cidrs,
        "tor_enabled": config.tor_enabled,
        "proxy_enabled": config.proxy_enabled,
    })))
}

pub async fn handle_emergency_isolate(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Json(payload): Json<EmergencyIsolateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let reason = payload
        .reason
        .unwrap_or_else(|| "Manual emergency isolation triggered".to_string());
    warn!("Emergency isolation request received: {}", reason);

    match KillSwitch::trigger(&reason) {
        Ok(_) => {
            let mut manager = evolve_mgr.lock().await;
            manager.mark_isolated();
            Ok(Json(json!({
                "status": "isolated",
                "reason": reason,
                "is_isolated": true
            })))
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_kernel::AuditMode;

    #[test]
    fn emergency_isolation_latch_rejects_reprovisioning() {
        // Exercise the latch without CAP_NET_ADMIN: cfg(test) does not propagate
        // to the sandbox-kernel dependency, so the privileged nft path is skipped
        // via explicit opt-in rather than a compile-time gate.
        std::env::set_var("SECURITY_AUDIT_SKIP_PRIVILEGED_NET", "1");
        KillSwitch::reset_isolation();
        KillSwitch::trigger("unit test isolation latch").unwrap();
        let (status, body) =
            isolation_latch_error().expect("latched isolation must reject egress provisioning");
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.0["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Recreate/reset"));
        KillSwitch::reset_isolation();
    }

    #[test]
    fn raw_agent_allowlist_must_be_valid_subset() {
        let config = EgressConfig {
            mode: AuditMode::Remote,
            allowed_cidrs: vec!["203.0.113.7/32".to_string()],
            ..Default::default()
        };

        assert!(validate_agent_allowlist(&config, &["203.0.113.7/32".to_string()]).is_ok());
        assert!(validate_agent_allowlist(&config, &["198.51.100.9/32".to_string()]).is_err());
        assert!(validate_agent_allowlist(&config, &["not-a-cidr".to_string()]).is_err());
    }
}

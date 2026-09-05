use axum::{extract::Query, http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::evolve_events::EvolveEventSink;
use crate::surface_guard::{resolve_agent_surface, AgentSurface};
use sandbox_kernel::tmux::TmuxManager;
use sandbox_kernel::{
    EventSource, EvolveManager, RiskLevel, SecurityEvent, SecurityEventType,
};

#[derive(Debug, Deserialize)]
pub struct StartBackgroundRequest {
    pub command: String,
    pub session: Option<String>,
    pub evolve_session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PollLogsQuery {
    pub session: Option<String>,
    pub last_lines: Option<usize>,
    pub evolve_session_id: Option<String>,
}

fn emit_background_event(
    event_sink: &EvolveEventSink,
    session_id: &str,
    event_type: SecurityEventType,
    command: Option<&str>,
    result: &str,
) {
    let mut event = SecurityEvent::new(EventSource::Process, event_type)
        .with_session_id(session_id.to_string())
        .with_result(result.to_string())
        .with_risk_hint(RiskLevel::Low)
        .with_metadata(json!({"execution_mode": "tmux_background"}));

    if let Some(command) = command {
        event = event.with_command(command.to_string());
    }

    event_sink.emit(event);
}

pub async fn handle_start_background(
    Extension(event_sink): Extension<EvolveEventSink>,
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Json(payload): Json<StartBackgroundRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session = payload.session.unwrap_or_else(|| {
        format!(
            "bg_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        )
    });
    let event_session_id = payload
        .evolve_session_id
        .unwrap_or_else(|| session.clone());

    let surface = {
        let manager = evolve_mgr.lock().await;
        resolve_agent_surface(&manager, Some(&event_session_id))
    }
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "background execution temporarily unavailable"})),
        )
    })?;

    if surface == AgentSurface::Deception {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "background execution temporarily unavailable"})),
        ));
    }

    info!(
        "Starting background task in tmux session '{}': {}",
        session, payload.command
    );

    match TmuxManager::start_session(&session, Some(&payload.command)) {
        Ok(_) => {
            emit_background_event(
                &event_sink,
                &event_session_id,
                SecurityEventType::ProcessExec,
                Some(&payload.command),
                "started",
            );
            Ok(Json(json!({
                "status": "started",
                "session": session,
                "command": payload.command
            })))
        }
        Err(e) => {
            emit_background_event(
                &event_sink,
                &event_session_id,
                SecurityEventType::ProcessExit,
                Some(&payload.command),
                "spawn_error",
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to start background task: {}", e)})),
            ))
        }
    }
}

pub async fn handle_poll_logs(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Query(query): Query<PollLogsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let surface = {
        let manager = evolve_mgr.lock().await;
        resolve_agent_surface(&manager, query.evolve_session_id.as_deref())
    }
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "background logs temporarily unavailable"})),
        )
    })?;
    if surface == AgentSurface::Deception {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "background logs temporarily unavailable"})),
        ));
    }

    let session = query.session.unwrap_or_else(|| "audit_session".to_string());
    let last_lines = query.last_lines.unwrap_or(0);

    let is_active = TmuxManager::is_session_active(&session);
    match TmuxManager::read_session_log_diff(&session, last_lines) {
        Ok((diff, total_lines)) => Ok(Json(json!({
            "session": session,
            "is_active": is_active,
            "log_diff": diff,
            "total_lines": total_lines,
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to poll logs: {}", e)})),
        )),
    }
}

pub async fn handle_kill_background(
    Extension(event_sink): Extension<EvolveEventSink>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session = payload
        .get("session")
        .and_then(|s| s.as_str())
        .unwrap_or("audit_session");

    match TmuxManager::kill_session(session) {
        Ok(_) => {
            emit_background_event(
                &event_sink,
                session,
                SecurityEventType::ProcessExit,
                None,
                "killed",
            );
            Ok(Json(json!({"status": "killed", "session": session})))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to kill session: {}", e)})),
        )),
    }
}

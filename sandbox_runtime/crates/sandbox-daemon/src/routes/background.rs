use axum::{extract::Query, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::json;
use tracing::info;

use sandbox_kernel::tmux::TmuxManager;

#[derive(Debug, Deserialize)]
pub struct StartBackgroundRequest {
    pub command: String,
    pub session: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PollLogsQuery {
    pub session: Option<String>,
    pub last_lines: Option<usize>,
}

pub async fn handle_start_background(
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

    info!(
        "Starting background task in tmux session '{}': {}",
        session, payload.command
    );

    match TmuxManager::start_session(&session, Some(&payload.command)) {
        Ok(_) => Ok(Json(json!({
            "status": "started",
            "session": session,
            "command": payload.command
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to start background task: {}", e)})),
        )),
    }
}

pub async fn handle_poll_logs(
    Query(query): Query<PollLogsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session = payload
        .get("session")
        .and_then(|s| s.as_str())
        .unwrap_or("audit_session");

    match TmuxManager::kill_session(session) {
        Ok(_) => Ok(Json(json!({"status": "killed", "session": session}))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to kill session: {}", e)})),
        )),
    }
}

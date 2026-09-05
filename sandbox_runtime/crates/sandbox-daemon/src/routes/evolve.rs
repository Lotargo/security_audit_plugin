use axum::{extract::Query, http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

use sandbox_kernel::EvolveManager;

#[derive(Debug, Deserialize)]
pub struct SetEvolveEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct TraceQuery {
    pub session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EvolveObserveRequest {
    pub category: String,
    pub technique: String,
    pub evidence: String,
    pub severity: Option<u8>,
    pub path: Option<String>,
}

pub async fn handle_set_enabled(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Json(payload): Json<SetEvolveEnabledRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.enabled && sandbox_kernel::KillSwitch::is_isolated() {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "cannot enable Evolve while the runtime is isolated; recreate or reset the sandbox first"})),
        ));
    }
    let mut manager = evolve_mgr.lock().await;
    manager.set_enabled(payload.enabled);
    Ok(Json(json!({"runtime": manager.status(), "feedback": manager.feedback_status().ok()})))
}

pub async fn handle_status(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
) -> Json<serde_json::Value> {
    let manager = evolve_mgr.lock().await;
    Json(json!({"runtime": manager.status(), "feedback": manager.feedback_status().ok()}))
}

pub async fn handle_observe(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Json(payload): Json<EvolveObserveRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.category.trim().is_empty()
        || payload.technique.trim().is_empty()
        || payload.evidence.trim().is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "category, technique, and evidence are required"})),
        ));
    }

    let manager = evolve_mgr.lock().await;
    match manager.observe_feedback(
        payload.category,
        payload.technique,
        payload.evidence,
        payload.severity.unwrap_or(3),
        payload.path,
    ) {
        Ok(event) => Ok(Json(json!({
            "status": "recorded",
            "event": event,
            "runtime": manager.status(),
            "feedback": manager.feedback_status().ok()
        }))),
        Err(error) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to record Evolve observation: {}", error)})),
        )),
    }
}

pub async fn handle_sessions(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
) -> Json<serde_json::Value> {
    let manager = evolve_mgr.lock().await;
    Json(json!({"sessions": manager.sessions()}))
}

pub async fn handle_trace(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Query(query): Query<TraceQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = evolve_mgr.lock().await;
    match manager.behavior_trace(&query.session_id) {
        Some(trace) => Ok(Json(json!(trace))),
        None => Err((StatusCode::NOT_FOUND, Json(json!({"error": "Evolve behavior trace not found"})))),
    }
}

pub async fn handle_events(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Query(query): Query<EventsQuery>,
) -> Json<serde_json::Value> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let manager = evolve_mgr.lock().await;
    Json(json!({"events": manager.recent_events(limit), "limit": limit}))
}

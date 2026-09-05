use axum::{extract::Query, http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::deception_exec;
use crate::deception_runtime::DeceptionRuntime;
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
pub struct DeceptionSessionRequest {
    pub session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct DeceptionExecRequest {
    pub session_id: String,
    pub command: String,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct DeceptionStatusQuery {
    pub session_id: Option<String>,
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

pub async fn handle_prepare_deception(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Extension(deception_runtime): Extension<Arc<Mutex<DeceptionRuntime>>>,
    Json(payload): Json<DeceptionSessionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let instance = {
        let mut manager = evolve_mgr.lock().await;
        manager
            .prepare_deception_for_session(&payload.session_id)
            .map_err(|error| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Failed to prepare deception: {}", error)})),
                )
            })?
    };

    let start_result = {
        let mut runtime = deception_runtime.lock().await;
        runtime.start_instance(&instance).await
    };

    match start_result {
        Ok(runtime) => Ok(Json(json!({
            "status": "prepared",
            "instance": instance,
            "runtime": runtime
        }))),
        Err(error) => {
            let mut manager = evolve_mgr.lock().await;
            let _ = manager.destroy_deception_for_session(&payload.session_id);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to start deception runtime: {}", error)})),
            ))
        }
    }
}

pub async fn handle_deception_status(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Extension(deception_runtime): Extension<Arc<Mutex<DeceptionRuntime>>>,
    Query(query): Query<DeceptionStatusQuery>,
) -> Json<serde_json::Value> {
    if let Some(session_id) = query.session_id.as_deref() {
        let instance = {
            let manager = evolve_mgr.lock().await;
            manager.deception_instance(session_id)
        };
        let runtime_status = {
            let runtime = deception_runtime.lock().await;
            runtime.status(session_id)
        };
        Json(json!({
            "instance": instance,
            "runtime": runtime_status
        }))
    } else {
        let runtime = deception_runtime.lock().await;
        Json(json!({"runtimes": runtime.statuses()}))
    }
}

pub async fn handle_destroy_deception(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Extension(deception_runtime): Extension<Arc<Mutex<DeceptionRuntime>>>,
    Json(payload): Json<DeceptionSessionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let runtime_destroyed = {
        let mut runtime = deception_runtime.lock().await;
        runtime.destroy(&payload.session_id).await.map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to stop deception runtime: {}", error)})),
            )
        })?
    };

    let instance_destroyed = {
        let mut manager = evolve_mgr.lock().await;
        manager
            .destroy_deception_for_session(&payload.session_id)
            .map_err(|error| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to destroy deception instance: {}", error)})),
                )
            })?
    };

    Ok(Json(json!({
        "status": "destroyed",
        "runtime_destroyed": runtime_destroyed,
        "instance_destroyed": instance_destroyed
    })))
}

pub async fn handle_deception_exec(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Extension(deception_runtime): Extension<Arc<Mutex<DeceptionRuntime>>>,
    Json(payload): Json<DeceptionExecRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let instance = {
        let manager = evolve_mgr.lock().await;
        manager.deception_instance(&payload.session_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "deception instance not found"})),
            )
        })?
    };

    {
        let runtime = deception_runtime.lock().await;
        if runtime.status(&payload.session_id).is_none() {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({"error": "deception services are not running for this session"})),
            ));
        }
    }

    deception_exec::execute(&instance, &payload.command, payload.timeout_secs.unwrap_or(30))
        .await
        .map(|result| Json(json!(result)))
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Deception execution failed: {}", error)})),
            )
        })
}

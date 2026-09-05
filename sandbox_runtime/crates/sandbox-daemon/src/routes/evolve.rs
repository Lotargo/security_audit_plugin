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

pub async fn handle_set_enabled(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Json(payload): Json<SetEvolveEnabledRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.enabled && sandbox_kernel::KillSwitch::is_isolated() {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "cannot enable Evolve while the runtime is isolated; recreate or reset the sandbox first"
            })),
        ));
    }

    let mut manager = evolve_mgr.lock().await;
    manager.set_enabled(payload.enabled);
    Ok(Json(json!(manager.status())))
}

pub async fn handle_status(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
) -> Json<serde_json::Value> {
    let manager = evolve_mgr.lock().await;
    Json(json!(manager.status()))
}

pub async fn handle_events(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Query(query): Query<EventsQuery>,
) -> Json<serde_json::Value> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let manager = evolve_mgr.lock().await;
    Json(json!({
        "events": manager.recent_events(limit),
        "limit": limit
    }))
}

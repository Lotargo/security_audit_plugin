use axum::{http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;

use sandbox_kernel::EvolveManager;

#[derive(Debug, Deserialize)]
pub struct EvolveObserveRequest {
    pub category: String,
    pub technique: String,
    pub evidence: String,
    pub severity: Option<u8>,
    pub path: Option<String>,
}

pub async fn handle_evolve_status(
    Extension(evolve): Extension<EvolveManager>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match evolve.status() {
        Ok(status) => Ok(Json(json!(status))),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to read Evolve status: {}", err)})),
        )),
    }
}

pub async fn handle_evolve_observe(
    Extension(evolve): Extension<EvolveManager>,
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

    match evolve.observe(
        payload.category,
        payload.technique,
        payload.evidence,
        payload.severity.unwrap_or(3),
        payload.path,
    ) {
        Ok(event) => match evolve.status() {
            Ok(status) => Ok(Json(json!({
                "status": "recorded",
                "event": event,
                "evolve": status
            }))),
            Err(err) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Observation recorded but status read failed: {}", err)})),
            )),
        },
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to record Evolve observation: {}", err)})),
        )),
    }
}

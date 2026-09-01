use axum::{
    middleware,
    routing::{get, post},
    Extension, Json, Router,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod routes;

use auth::{ratchet_auth_middleware, RatchetAuthState};
use sandbox_kernel::canary::CanaryManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "sandbox_daemon=info,sandbox_kernel=info,tower_http=info".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Security Audit Sandbox Daemon (Axum/Tokio)...");

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "9999".to_string())
        .parse()
        .unwrap_or(9999);

    let host_pubkey_hex = std::env::var("HOST_PUBKEY_HEX").ok();
    let session_key_hex = std::env::var("BRIDGE_SESSION_KEY_HEX").ok();
    let insecure_dev = std::env::var("SANDBOX_INSECURE_DEV")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if insecure_dev {
        warn!(
            "!!! WARNING: SANDBOX_INSECURE_DEV is enabled. RatchetGuard verification is bypassed."
        );
    }

    let _ = sandbox_kernel::tmux::TmuxManager::reap_orphaned_tmux_sessions();

    let auth_state = RatchetAuthState::new(
        host_pubkey_hex.as_deref(),
        session_key_hex.as_deref(),
        insecure_dev,
    )
    .expect("Failed to initialize RatchetAuthState");

    let canary_mgr = Arc::new(Mutex::new(CanaryManager::new()));

    let health_router = Router::new()
        .route("/health", get(handle_health))
        .layer(Extension(canary_mgr.clone()));

    let protected_routes = Router::new()
        .route("/execute", post(routes::exec::handle_execute))
        .route("/execute_tmux", post(routes::exec::handle_interactive_tmux))
        .route(
            "/provision_egress",
            post(routes::egress::handle_provision_egress),
        )
        .route(
            "/emergency_isolate",
            post(routes::egress::handle_emergency_isolate),
        )
        .route(
            "/isolation_status",
            get(routes::egress::handle_isolation_status),
        )
        .route(
            "/start_background",
            post(routes::background::handle_start_background),
        )
        .route("/poll_logs", get(routes::background::handle_poll_logs))
        .route(
            "/kill_background",
            post(routes::background::handle_kill_background),
        )
        .route("/rotate_tor", post(routes::tor::handle_rotate_tor))
        .route("/arm_canary", post(routes::canary::handle_arm_canary))
        .route("/canary_status", get(routes::canary::handle_canary_status))
        .route("/http_probe", post(routes::probe::handle_http_probe))
        .route(
            "/browser_audit",
            post(routes::browser::handle_browser_audit),
        )
        .layer(middleware::from_fn_with_state(
            auth_state.clone(),
            ratchet_auth_middleware,
        ))
        .layer(Extension(canary_mgr));

    let app = Router::new()
        .merge(health_router)
        .merge(protected_routes)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Sandbox Daemon listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_health(
    Extension(canary_mgr): Extension<Arc<Mutex<CanaryManager>>>,
) -> Json<serde_json::Value> {
    let mgr = canary_mgr.lock().await;
    Json(json!({
        "status": "ok",
        "service": "sandbox-daemon",
        "version": "0.1.0",
        "isolated": sandbox_kernel::KillSwitch::is_isolated(),
        "canary_armed": mgr.is_armed(),
        "canary_traps_count": mgr.get_traps().len(),
        "canary_triggered_count": mgr.triggered_count()
    }))
}

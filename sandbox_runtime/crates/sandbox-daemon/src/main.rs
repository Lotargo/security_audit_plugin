use axum::{
    middleware,
    routing::{get, post},
    Extension, Json, Router,
};
use serde_json::json;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod evolve_events;
mod routes;

use auth::{ratchet_auth_middleware, RatchetAuthState};
use evolve_events::EvolveEventSink;
use sandbox_kernel::canary::CanaryManager;
use sandbox_kernel::{
    apply_runtime_containment, audit_identity_conflicts_with_reserved_runtime_uid,
    configured_audit_exec_identity, EgressConfig, EgressManager, EvolveDecision, EvolveManager,
    KillSwitch, SecurityEventType,
};

fn validate_runtime_identity_contract() -> Result<(), Box<dyn std::error::Error>> {
    if configured_audit_exec_identity().is_none() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "AUDIT_EXEC_UID/AUDIT_EXEC_GID are required for sandbox runtime startup",
        )
        .into());
    }
    if audit_identity_conflicts_with_reserved_runtime_uid() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "AUDIT_EXEC_UID conflicts with a reserved Tor/browser runtime identity",
        )
        .into());
    }
    Ok(())
}

fn bootstrap_local_egress() -> Result<(), Box<dyn std::error::Error>> {
    let config = EgressConfig::default();
    EgressManager::new().apply_rules(&config)?;
    apply_runtime_containment(&config)?;
    Ok(())
}

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

    validate_runtime_identity_contract()?;

    if std::env::args().any(|arg| arg == "--bootstrap-local-egress") {
        bootstrap_local_egress()?;
        info!("Bootstrap local egress policy applied successfully");
        return Ok(());
    }

    // Defense in depth for direct daemon launches. The entrypoint already applies this policy
    // before Tor starts so there is no pre-daemon network window.
    bootstrap_local_egress()?;

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

    let evolve_mgr = Arc::new(Mutex::new(EvolveManager::new()));
    let (evolve_event_tx, mut evolve_event_rx) = mpsc::unbounded_channel();
    let evolve_event_sink = EvolveEventSink::new(evolve_event_tx);
    let canary_mgr = Arc::new(Mutex::new(CanaryManager::with_event_sender(
        evolve_event_sink.sender(),
    )));

    // Canary and future sensors publish facts into the Evolve event pipeline. The Evolve manager
    // decides the reaction. Until Deception Fabric exists, high-risk events intentionally retain
    // the existing fail-closed isolation behavior.
    let evolve_event_manager = evolve_mgr.clone();
    tokio::spawn(async move {
        while let Some(event) = evolve_event_rx.recv().await {
            let event_id = event.event_id.clone();
            let resource = event.resource.clone();
            let event_type = event.event_type;
            let trap_type = event
                .metadata
                .get("trap_type")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            let decision = {
                let mut manager = evolve_event_manager.lock().await;
                manager.ingest_event(event)
            };

            match decision {
                EvolveDecision::Observe => {
                    info!(event_id = %event_id, "Evolve recorded low-risk security event");
                }
                EvolveDecision::EnhancedTelemetry => {
                    warn!(
                        event_id = %event_id,
                        resource = ?resource,
                        "Evolve entered suspicious observation state"
                    );
                }
                EvolveDecision::LegacyIsolate | EvolveDecision::Isolate => {
                    let reason = format!(
                        "Evolve security event requires isolation: event_id={event_id}, resource={resource:?}"
                    );
                    match KillSwitch::trigger(&reason) {
                        Ok(()) => {
                            let mut manager = evolve_event_manager.lock().await;
                            manager.mark_isolated();
                            if event_type == SecurityEventType::CanaryAccess {
                                if let (Some(trap_type), Some(path)) =
                                    (trap_type.as_deref(), resource.as_deref())
                                {
                                    if let Err(error) = manager.activate_feedback_from_canary(
                                        trap_type,
                                        std::path::Path::new(path),
                                    ) {
                                        error!(
                                            event_id = %event_id,
                                            error = %error,
                                            "Evolve deeper deception activation failed after isolation"
                                        );
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            // KillSwitch itself is responsible for fail-closed behavior when the
                            // kernel blackout cannot be installed. Keep a loud daemon-side trace.
                            error!(
                                event_id = %event_id,
                                error = %err,
                                "Evolve isolation request failed"
                            );
                        }
                    }
                }
            }
        }
    });

    let health_router = Router::new()
        .route("/health", get(handle_health))
        .layer(Extension(canary_mgr.clone()))
        .layer(Extension(evolve_mgr.clone()));

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
        .route(
            "/evolve/enable",
            post(routes::evolve::handle_set_enabled),
        )
        .route("/evolve/status", get(routes::evolve::handle_status))
        .route("/evolve/observe", post(routes::evolve::handle_observe))
        .route("/evolve/sessions", get(routes::evolve::handle_sessions))
        .route("/evolve/trace", get(routes::evolve::handle_trace))
        .route("/evolve/events", get(routes::evolve::handle_events))
        .route("/http_probe", post(routes::probe::handle_http_probe))
        .route(
            "/browser_audit",
            post(routes::browser::handle_browser_audit),
        )
        .layer(middleware::from_fn_with_state(
            auth_state.clone(),
            ratchet_auth_middleware,
        ))
        .layer(Extension(canary_mgr))
        .layer(Extension(evolve_mgr))
        .layer(Extension(evolve_event_sink));

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
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
) -> Json<serde_json::Value> {
    let canary = canary_mgr.lock().await;
    let evolve = evolve_mgr.lock().await;
    Json(json!({
        "status": "ok",
        "service": "sandbox-daemon",
        "version": "0.1.0",
        "isolated": sandbox_kernel::KillSwitch::is_isolated(),
        "canary_armed": canary.is_armed(),
        "canary_traps_count": canary.get_traps().len(),
        "canary_triggered_count": canary.triggered_count(),
        "evolve": evolve.status(),
        "evolve_feedback": evolve.feedback_status().ok()
    }))
}

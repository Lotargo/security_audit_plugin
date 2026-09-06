use axum::{http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{error, info, warn};

use crate::deception_exec;
use crate::deception_runtime::DeceptionRuntime;
use crate::evolve_events::EvolveEventSink;
use crate::surface_guard::{resolve_agent_surface, AgentSurface};
#[cfg(not(target_os = "windows"))]
use sandbox_kernel::audit_exec_identity;
use sandbox_kernel::tmux::TmuxManager;
use sandbox_kernel::watchdog::{process_command_output, WatchdogResult};
use sandbox_kernel::{EventSource, EvolveManager, RiskLevel, SecurityEvent, SecurityEventType};

#[cfg(not(target_os = "windows"))]
const SAFE_CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    pub timeout_secs: Option<u64>,
    pub work_dir: Option<String>,
    pub evolve_session_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecResponse {
    pub output: String,
    pub exit_code: i32,
    pub is_truncated: bool,
    pub total_chars: usize,
    pub log_file_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InteractiveTmuxRequest {
    pub session: Option<String>,
    pub input: String,
    pub evolve_session_id: Option<String>,
}

// Eight telemetry fields map 1:1 onto SecurityEvent builders; bundling them into
// a struct would churn every call site for no behavior gain.
#[allow(clippy::too_many_arguments)]
fn emit_exec_event(
    event_sink: &EvolveEventSink,
    session_id: Option<&str>,
    event_type: SecurityEventType,
    command: &str,
    work_dir: &str,
    result: Option<String>,
    process_id: Option<u32>,
    metadata: serde_json::Value,
) {
    let mut event = SecurityEvent::new(EventSource::Process, event_type)
        .with_command(command.to_string())
        .with_resource(work_dir.to_string())
        .with_risk_hint(RiskLevel::Low)
        .with_metadata(metadata);

    if let Some(session_id) = session_id {
        event = event.with_session_id(session_id.to_string());
    }
    if let Some(result) = result {
        event = event.with_result(result);
    }
    if let Some(process_id) = process_id {
        event = event.with_process(process_id, Some(std::process::id()));
    }

    event_sink.emit(event);
}

pub async fn handle_execute(
    Extension(event_sink): Extension<EvolveEventSink>,
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Extension(deception_runtime): Extension<Arc<Mutex<DeceptionRuntime>>>,
    Json(payload): Json<ExecRequest>,
) -> Result<Json<ExecResponse>, (StatusCode, Json<serde_json::Value>)> {
    let timeout_secs = payload.timeout_secs.unwrap_or(60);
    let timeout_duration = Duration::from_secs(timeout_secs);
    let work_dir = payload.work_dir.unwrap_or_else(|| "/workspace".to_string());
    let command_text = payload.command;
    let evolve_session_id = payload.evolve_session_id;
    let cmd_id = format!(
        "exec_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let surface = {
        let manager = evolve_mgr.lock().await;
        resolve_agent_surface(&manager, evolve_session_id.as_deref())
    }
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "execution service temporarily unavailable"})),
        )
    })?;

    if surface == AgentSurface::Deception {
        let session_id = evolve_session_id
            .as_deref()
            .expect("surface guard requires a bound session for the alternate surface");
        let deception_instance = {
            let manager = evolve_mgr.lock().await;
            manager.deception_instance(session_id)
        };

        let Some(instance) = deception_instance else {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "execution service temporarily unavailable"})),
            ));
        };

        let runtime_ready = {
            let runtime = deception_runtime.lock().await;
            runtime.status(session_id).is_some()
        };
        if !runtime_ready {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "execution service temporarily unavailable"})),
            ));
        }

        emit_exec_event(
            &event_sink,
            Some(session_id),
            SecurityEventType::ProcessSpawn,
            &command_text,
            "/workspace",
            Some("alternate_surface_requested".to_string()),
            None,
            json!({
                "execution_mode": "sync",
                "execution_surface": "alternate",
                "timeout_secs": timeout_secs,
                "command_id": cmd_id
            }),
        );

        let result = deception_exec::execute(&instance, &command_text, timeout_secs)
            .await
            .map_err(|error| {
                error!(session_id = %session_id, error = %error, "Alternate execution failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "execution failed"})),
                )
            })?;

        let log_dir = PathBuf::from("/workspace").join("logs");
        let watchdog_res = process_command_output(&cmd_id, &result.output, &log_dir)
            .await
            .unwrap_or_else(|_| WatchdogResult {
                output: result.output.clone(),
                is_truncated: false,
                total_chars: result.output.len(),
                log_file_path: None,
            });

        emit_exec_event(
            &event_sink,
            Some(session_id),
            SecurityEventType::ProcessExit,
            &command_text,
            "/workspace",
            Some(format!("exit_code={}", result.exit_code)),
            None,
            json!({
                "execution_mode": "sync",
                "execution_surface": "alternate",
                "command_id": cmd_id,
                "is_truncated": watchdog_res.is_truncated,
                "total_chars": watchdog_res.total_chars
            }),
        );

        return Ok(Json(ExecResponse {
            output: watchdog_res.output,
            exit_code: result.exit_code,
            is_truncated: watchdog_res.is_truncated,
            total_chars: watchdog_res.total_chars,
            log_file_path: None,
        }));
    }

    emit_exec_event(
        &event_sink,
        evolve_session_id.as_deref(),
        SecurityEventType::ProcessSpawn,
        &command_text,
        &work_dir,
        Some("requested".to_string()),
        None,
        json!({
            "execution_mode": "sync",
            "timeout_secs": timeout_secs,
            "command_id": cmd_id
        }),
    );

    info!("Executing unprivileged audit command in '{}'", work_dir);

    #[cfg(target_os = "windows")]
    let mut cmd = {
        use std::process::Stdio;
        let mut c = Command::new("powershell");
        c.args(["-NoProfile", "-Command", &command_text]);
        c.stdin(Stdio::null());
        c.stdout(Stdio::piped());
        c.stderr(Stdio::piped());
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        use std::process::Stdio;
        let (uid, gid) = audit_exec_identity();
        let mut c = Command::new("/usr/bin/setpriv");
        c.arg(format!("--reuid={uid}"))
            .arg(format!("--regid={gid}"))
            .arg("--clear-groups")
            .arg("--bounding-set=-all")
            .arg("--inh-caps=-all")
            .arg("--ambient-caps=-all")
            .arg("--no-new-privs")
            .arg("--")
            .arg("/bin/sh")
            .arg("-c")
            .arg(&command_text);
        c.env_clear();
        c.env("HOME", "/tmp");
        c.env("PATH", SAFE_CHILD_PATH);
        c.env("LANG", "C.UTF-8");
        c.stdin(Stdio::null());
        c.stdout(Stdio::piped());
        c.stderr(Stdio::piped());
        c
    };

    if std::path::Path::new(&work_dir).exists() {
        cmd.current_dir(&work_dir);
    }
    cmd.kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            emit_exec_event(
                &event_sink,
                evolve_session_id.as_deref(),
                SecurityEventType::ProcessExit,
                &command_text,
                &work_dir,
                Some("spawn_error".to_string()),
                None,
                json!({"command_id": cmd_id}),
            );
            error!("Command execution failed: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Command spawn failed: {}", e)})),
            ));
        }
    };

    let process_id = child.id();
    emit_exec_event(
        &event_sink,
        evolve_session_id.as_deref(),
        SecurityEventType::ProcessExec,
        &command_text,
        &work_dir,
        Some("started".to_string()),
        process_id,
        json!({
            "execution_mode": "sync",
            "command_id": cmd_id
        }),
    );

    let output = match timeout(timeout_duration, child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            emit_exec_event(
                &event_sink,
                evolve_session_id.as_deref(),
                SecurityEventType::ProcessExit,
                &command_text,
                &work_dir,
                Some("wait_error".to_string()),
                process_id,
                json!({"command_id": cmd_id}),
            );
            error!("Command wait failed: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Command wait failed: {}", e)})),
            ));
        }
        Err(_) => {
            emit_exec_event(
                &event_sink,
                evolve_session_id.as_deref(),
                SecurityEventType::ProcessExit,
                &command_text,
                &work_dir,
                Some("timeout".to_string()),
                process_id,
                json!({
                    "command_id": cmd_id,
                    "timeout_secs": timeout_secs
                }),
            );
            warn!("Command execution timed out after {:?}", timeout_duration);
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({"error": format!("Command timed out after {}s", timeout_secs)})),
            ));
        }
    };

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_raw = if stderr.is_empty() {
        stdout.into_owned()
    } else {
        format!("{}\n[STDERR]\n{}", stdout, stderr)
    };

    let log_dir = PathBuf::from(&work_dir).join("logs");
    let watchdog_res = process_command_output(&cmd_id, &combined_raw, &log_dir)
        .await
        .unwrap_or_else(|_| WatchdogResult {
            output: combined_raw.clone(),
            is_truncated: false,
            total_chars: combined_raw.len(),
            log_file_path: None,
        });

    emit_exec_event(
        &event_sink,
        evolve_session_id.as_deref(),
        SecurityEventType::ProcessExit,
        &command_text,
        &work_dir,
        Some(format!("exit_code={exit_code}")),
        process_id,
        json!({
            "command_id": cmd_id,
            "is_truncated": watchdog_res.is_truncated,
            "total_chars": watchdog_res.total_chars,
            "log_file_path": watchdog_res.log_file_path
        }),
    );

    Ok(Json(ExecResponse {
        output: watchdog_res.output,
        exit_code,
        is_truncated: watchdog_res.is_truncated,
        total_chars: watchdog_res.total_chars,
        log_file_path: watchdog_res.log_file_path,
    }))
}

pub async fn handle_interactive_tmux(
    Extension(evolve_mgr): Extension<Arc<Mutex<EvolveManager>>>,
    Json(payload): Json<InteractiveTmuxRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session = payload
        .session
        .unwrap_or_else(|| "audit_session".to_string());

    let surface = {
        let manager = evolve_mgr.lock().await;
        resolve_agent_surface(&manager, payload.evolve_session_id.as_deref())
    }
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "interactive session temporarily unavailable"})),
        )
    })?;

    if surface == AgentSurface::Deception {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "interactive session temporarily unavailable"})),
        ));
    }

    info!("Sending interactive input to tmux session '{}'", session);

    // Interactive input is intentionally not copied into Evolve telemetry because it may contain
    // passwords, tokens or other secrets. Process-level tmux lifecycle remains observable through
    // background session events.
    match TmuxManager::send_input(&session, &payload.input) {
        Ok(_) => Ok(Json(json!({"status": "success", "session": session}))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to send input: {}", e)})),
        )),
    }
}

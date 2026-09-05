use axum::{http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, warn};

use crate::evolve_events::EvolveEventSink;
#[cfg(not(target_os = "windows"))]
use sandbox_kernel::audit_exec_identity;
use sandbox_kernel::tmux::TmuxManager;
use sandbox_kernel::watchdog::{process_command_output, WatchdogResult};
use sandbox_kernel::{EventSource, RiskLevel, SecurityEvent, SecurityEventType};

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
}

fn emit_exec_event(
    event_sink: &EvolveEventSink,
    session_id: Option<&str>,
    event_type: SecurityEventType,
    command: &str,
    work_dir: &str,
    result: Option<String>,
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

    event_sink.emit(event);
}

pub async fn handle_execute(
    Extension(event_sink): Extension<EvolveEventSink>,
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

    emit_exec_event(
        &event_sink,
        evolve_session_id.as_deref(),
        SecurityEventType::ProcessExec,
        &command_text,
        &work_dir,
        Some("started".to_string()),
        json!({
            "execution_mode": "sync",
            "timeout_secs": timeout_secs,
            "command_id": cmd_id
        }),
    );

    info!("Executing unprivileged audit command in '{}'", work_dir);

    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("powershell");
        c.args(["-NoProfile", "-Command", &command_text]);
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", &command_text]);
        let (uid, gid) = audit_exec_identity();
        #[cfg(unix)]
        {
            c.as_std_mut().uid(uid).gid(gid);
        }
        c.env_clear();
        c.env("HOME", "/tmp");
        c.env("PATH", SAFE_CHILD_PATH);
        c.env("LANG", "C.UTF-8");
        c
    };

    if std::path::Path::new(&work_dir).exists() {
        cmd.current_dir(&work_dir);
    }

    let output = match timeout(timeout_duration, cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            emit_exec_event(
                &event_sink,
                evolve_session_id.as_deref(),
                SecurityEventType::ProcessExit,
                &command_text,
                &work_dir,
                Some("spawn_error".to_string()),
                json!({"command_id": cmd_id}),
            );
            error!("Command execution failed: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Command spawn failed: {}", e)})),
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
    Json(payload): Json<InteractiveTmuxRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session = payload
        .session
        .unwrap_or_else(|| "audit_session".to_string());
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

use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, warn};

#[cfg(not(target_os = "windows"))]
use sandbox_kernel::audit_exec_identity;
use sandbox_kernel::tmux::TmuxManager;
use sandbox_kernel::watchdog::{process_command_output, WatchdogResult};

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    pub timeout_secs: Option<u64>,
    pub work_dir: Option<String>,
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

pub async fn handle_execute(
    Json(payload): Json<ExecRequest>,
) -> Result<Json<ExecResponse>, (StatusCode, Json<serde_json::Value>)> {
    let timeout_duration = Duration::from_secs(payload.timeout_secs.unwrap_or(60));
    let work_dir = payload.work_dir.unwrap_or_else(|| "/workspace".to_string());
    let cmd_id = format!(
        "exec_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    info!("Executing unprivileged audit command in '{}'", work_dir);

    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("powershell");
        c.args(["-NoProfile", "-Command", &payload.command]);
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.args(["-c", &payload.command]);
        let (uid, gid) = audit_exec_identity();
        #[cfg(unix)]
        {
            c.as_std_mut().uid(uid).gid(gid);
        }
        c.env("HOME", "/tmp");
        c
    };

    if std::path::Path::new(&work_dir).exists() {
        cmd.current_dir(&work_dir);
    }

    let output = match timeout(timeout_duration, cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            error!("Command execution failed: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Command spawn failed: {}", e)})),
            ));
        }
        Err(_) => {
            warn!("Command execution timed out after {:?}", timeout_duration);
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                Json(
                    json!({"error": format!("Command timed out after {}s", timeout_duration.as_secs())}),
                ),
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

    match TmuxManager::send_input(&session, &payload.input) {
        Ok(_) => Ok(Json(json!({"status": "success", "session": session}))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to send input: {}", e)})),
        )),
    }
}

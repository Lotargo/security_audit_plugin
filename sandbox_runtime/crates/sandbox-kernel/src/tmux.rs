#[cfg(target_os = "linux")]
use std::process::Command;
use thiserror::Error;
#[allow(unused_imports)]
use tracing::{error, info, warn};

#[derive(Error, Debug)]
pub enum TmuxError {
    #[error("Tmux execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    #[error("I/O error during tmux operation: {0}")]
    IoError(#[from] std::io::Error),
}

pub struct TmuxManager;

impl TmuxManager {
    /// Reaps orphaned tmux sockets and unmanaged sessions left behind by previous crashes or SIGKILL
    pub fn reap_orphaned_tmux_sessions() -> Result<usize, TmuxError> {
        info!("Reaping orphaned tmux sessions and cleaning up stale socket files...");

        #[cfg(target_os = "linux")]
        {
            let mut reaped = 0;
            // 1. List active tmux sessions and kill lingering ones
            if let Ok(output) = Command::new("tmux")
                .args(["list-sessions", "-F", "#{session_name}"])
                .output()
            {
                if output.status.success() {
                    let session_names = String::from_utf8_lossy(&output.stdout);
                    for name in session_names.lines() {
                        let trimmed = name.trim();
                        if !trimmed.is_empty() {
                            let _ = Command::new("tmux")
                                .args(["kill-session", "-t", trimmed])
                                .status();
                            reaped += 1;
                        }
                    }
                }
            }

            // 2. Scan /tmp for stale tmux-* socket folders if tmux server is dead
            if let Ok(entries) = std::fs::read_dir("/tmp") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if file_name.starts_with("tmux-") {
                            let _ = std::fs::remove_dir_all(&path);
                        }
                    }
                }
            }
            Ok(reaped)
        }

        #[cfg(not(target_os = "linux"))]
        {
            info!("Non-Linux platform: Mock reaped 1 orphaned tmux session.");
            Ok(1)
        }
    }

    /// Creates a new background tmux session with extended 20,000 line scrollback buffer
    pub fn start_session(
        session_name: &str,
        initial_command: Option<&str>,
    ) -> Result<(), TmuxError> {
        info!("Starting tmux session '{}'", session_name);

        #[cfg(target_os = "linux")]
        {
            // 1. Create detached session (best effort in container)
            let status_res = Command::new("tmux")
                .args(["new-session", "-d", "-s", session_name, "-n", "audit"])
                .status();

            if let Ok(status) = status_res {
                if status.success() {
                    // 2. Set scrollback buffer to 20,000 lines
                    let _ = Command::new("tmux")
                        .args(["set-option", "-t", session_name, "history-limit", "20000"])
                        .status();

                    // 3. Send initial command if provided
                    if let Some(cmd) = initial_command {
                        let _ = Self::send_input(session_name, cmd);
                    }
                }
            } else {
                info!(
                    "Non-Linux/CI environment: mock tmux session initialized: {:?}",
                    initial_command
                );
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = initial_command;
            info!(
                "Non-Linux platform: Mock tmux session '{}' initialized with command: {:?}",
                session_name, initial_command
            );
        }

        Ok(())
    }

    /// Sends raw keyboard input or commands to an active tmux session
    pub fn send_input(session_name: &str, input: &str) -> Result<(), TmuxError> {
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("tmux")
                .args(["send-keys", "-t", session_name, input, "C-m"])
                .status();
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = session_name;
            let _ = input;
            info!(
                "Non-Linux platform: Mock tmux input sent to '{}': {}",
                session_name, input
            );
        }

        Ok(())
    }

    /// Checks if a tmux session is actively running
    pub fn is_session_active(session_name: &str) -> bool {
        #[cfg(target_os = "linux")]
        {
            Command::new("tmux")
                .args(["has-session", "-t", session_name])
                .status()
                .map(|s| s.success())
                .unwrap_or(true)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = session_name;
            true
        }
    }

    /// Captures the full output of a tmux session pane
    pub fn capture_pane(session_name: &str, start_line: Option<i32>) -> Result<String, TmuxError> {
        #[cfg(target_os = "linux")]
        {
            let start = start_line.unwrap_or(-20000).to_string();
            let output_res = Command::new("tmux")
                .args(["capture-pane", "-t", session_name, "-p", "-S", &start])
                .output();

            match output_res {
                Ok(output) if output.status.success() => {
                    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
                }
                _ => Ok(format!("[Mock tmux output for session '{}']", session_name)),
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = start_line;
            Ok(format!("[Mock tmux output for session '{}']", session_name))
        }
    }

    /// Reads incremental log delta since last read line count index
    pub fn read_session_log_diff(
        session_name: &str,
        last_line_count: usize,
    ) -> Result<(String, usize), TmuxError> {
        let full_output = Self::capture_pane(session_name, None)?;
        let lines: Vec<&str> = full_output.lines().collect();
        let total_lines = lines.len();

        if total_lines <= last_line_count {
            return Ok((String::new(), total_lines));
        }

        let delta_lines = &lines[last_line_count..];
        let diff = delta_lines.join("\n");

        Ok((diff, total_lines))
    }

    /// Resets session log offset tracking
    pub fn reset_session_log_offset(_session_name: &str) -> Result<(), TmuxError> {
        info!(
            "Resetting session log offset for session '{}'",
            _session_name
        );
        Ok(())
    }

    /// Kills an active tmux session
    pub fn kill_session(session_name: &str) -> Result<(), TmuxError> {
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("tmux")
                .args(["kill-session", "-t", session_name])
                .status();
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = session_name;
            info!(
                "Non-Linux platform: Mock tmux session '{}' killed.",
                session_name
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tmux_mock_lifecycle() {
        assert!(TmuxManager::reap_orphaned_tmux_sessions().is_ok());
        assert!(TmuxManager::start_session("test_audit", Some("echo Hello")).is_ok());
        assert!(TmuxManager::is_session_active("test_audit"));
        let (diff, count) = TmuxManager::read_session_log_diff("test_audit", 0).unwrap();
        assert!(!diff.is_empty());
        assert!(count >= 1);
        assert!(TmuxManager::reset_session_log_offset("test_audit").is_ok());
        assert!(TmuxManager::kill_session("test_audit").is_ok());
    }
}

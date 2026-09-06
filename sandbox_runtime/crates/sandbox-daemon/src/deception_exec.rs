use crate::deception_sandbox;
use sandbox_kernel::{DeceptionInstance, DECEPTION_EXEC_GID, DECEPTION_EXEC_UID};
use serde::Serialize;
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;

const MAX_TIMEOUT_SECS: u64 = 120;

#[derive(Error, Debug)]
pub enum DeceptionExecError {
    #[error("deception instance is not validated")]
    UnvalidatedInstance,
    #[error("deception filesystem root does not exist")]
    MissingRoot,
    #[error("deception command must not be empty")]
    EmptyCommand,
    #[error("failed to spawn isolated deception command: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("deception command timed out")]
    Timeout,
}

#[derive(Debug, Serialize)]
pub struct DeceptionExecResult {
    pub output: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

pub async fn execute(
    instance: &DeceptionInstance,
    command: &str,
    timeout_secs: u64,
) -> Result<DeceptionExecResult, DeceptionExecError> {
    if !instance.validated {
        return Err(DeceptionExecError::UnvalidatedInstance);
    }
    if !instance.root.is_dir() {
        return Err(DeceptionExecError::MissingRoot);
    }
    if command.trim().is_empty() {
        return Err(DeceptionExecError::EmptyCommand);
    }

    let timeout_secs = timeout_secs.clamp(1, MAX_TIMEOUT_SECS);
    let mut process = deception_sandbox::command(&instance.root, false)?;
    process
        .arg("--")
        .arg("/usr/bin/prlimit")
        .arg("--nproc=128")
        .arg("--nofile=256")
        .arg("--core=0")
        .arg("--")
        .arg("/usr/bin/setpriv")
        .arg(format!("--reuid={DECEPTION_EXEC_UID}"))
        .arg(format!("--regid={DECEPTION_EXEC_GID}"))
        .arg("--clear-groups")
        .arg("--no-new-privs")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = process.spawn()?;
    let output = match timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await {
        Ok(output) => output?,
        Err(_) => return Err(DeceptionExecError::Timeout),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = if stderr.is_empty() {
        stdout.into_owned()
    } else if stdout.is_empty() {
        stderr.into_owned()
    } else {
        format!("{}\n[STDERR]\n{}", stdout, stderr)
    };

    Ok(DeceptionExecResult {
        output: combined,
        exit_code: output.status.code().unwrap_or(-1),
        timed_out: false,
    })
}


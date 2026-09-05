use sandbox_kernel::{DeceptionInstance, DECEPTION_EXEC_GID, DECEPTION_EXEC_UID};
use serde::Serialize;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;
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
    let mut process = Command::new("/usr/bin/bwrap");
    process
        .arg("--die-with-parent")
        .arg("--new-session")
        .arg("--unshare-pid")
        .arg("--unshare-ipc")
        .arg("--unshare-uts")
        .arg("--hostname")
        .arg("prod-app-01")
        .arg("--ro-bind")
        .arg("/usr")
        .arg("/usr");

    add_optional_ro_bind(&mut process, "/bin");
    add_optional_ro_bind(&mut process, "/lib");
    add_optional_ro_bind(&mut process, "/lib64");

    process
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--dir")
        .arg("/etc")
        .arg("--dir")
        .arg("/etc/ssl");

    if Path::new("/etc/ssl/certs").is_dir() {
        process
            .arg("--ro-bind")
            .arg("/etc/ssl/certs")
            .arg("/etc/ssl/certs");
    }

    for file in ["hosts", "hostname", "nsswitch.conf", "passwd", "group"] {
        let source = instance.root.join("etc").join(file);
        process
            .arg("--ro-bind")
            .arg(source)
            .arg(format!("/etc/{file}"));
    }

    process
        .arg("--bind")
        .arg(&instance.root)
        .arg("/workspace")
        .arg("--chdir")
        .arg("/workspace")
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
        .kill_on_drop(true)
        .env_clear()
        .env("HOME", "/workspace/home")
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8");

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

fn add_optional_ro_bind(process: &mut Command, source: &str) {
    if Path::new(source).exists() {
        process.arg("--ro-bind").arg(source).arg(source);
    }
}

use crate::deception_sandbox;
use sandbox_kernel::{DeceptionInstance, DECEPTION_EXEC_GID, DECEPTION_EXEC_UID};
use serde::Serialize;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const FS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Error, Debug)]
pub enum DeceptionFsError {
    #[error("invalid relative deception path")]
    InvalidPath,
    #[error("deception file exceeds the maximum size")]
    FileTooLarge,
    #[error("deception file is not valid UTF-8")]
    InvalidUtf8,
    #[error("deception filesystem command failed: {0}")]
    CommandFailed(String),
    #[error("deception filesystem operation timed out")]
    Timeout,
    #[error("deception filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Serialize)]
pub struct DeceptionReadResult {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct DeceptionWriteResult {
    pub path: String,
    pub bytes_written: usize,
}

pub async fn read_file(
    instance: &DeceptionInstance,
    relative_path: &str,
) -> Result<DeceptionReadResult, DeceptionFsError> {
    let relative = validate_relative_path(relative_path)?;
    let target = PathBuf::from("/workspace").join(&relative);
    let mut process = deception_sandbox::command(&instance.root, false)?;
    process
        .arg("--")
        .arg("/usr/bin/setpriv")
        .arg(format!("--reuid={DECEPTION_EXEC_UID}"))
        .arg(format!("--regid={DECEPTION_EXEC_GID}"))
        .arg("--clear-groups")
        .arg("--no-new-privs")
        .arg("--")
        .arg("/usr/bin/head")
        .arg("-c")
        .arg((MAX_FILE_BYTES + 1).to_string())
        .arg("--")
        .arg(&target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = process.spawn()?;
    let output = timeout(FS_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| DeceptionFsError::Timeout)??;

    if !output.status.success() {
        return Err(DeceptionFsError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    if output.stdout.len() > MAX_FILE_BYTES {
        return Err(DeceptionFsError::FileTooLarge);
    }

    let content = String::from_utf8(output.stdout).map_err(|_| DeceptionFsError::InvalidUtf8)?;
    Ok(DeceptionReadResult {
        path: relative.to_string_lossy().into_owned(),
        content,
    })
}

pub async fn write_file(
    instance: &DeceptionInstance,
    relative_path: &str,
    content: &str,
) -> Result<DeceptionWriteResult, DeceptionFsError> {
    if content.len() > MAX_FILE_BYTES {
        return Err(DeceptionFsError::FileTooLarge);
    }

    let relative = validate_relative_path(relative_path)?;
    let target = PathBuf::from("/workspace").join(&relative);
    let mut process = deception_sandbox::command(&instance.root, false)?;
    process
        .arg("--")
        .arg("/usr/bin/setpriv")
        .arg(format!("--reuid={DECEPTION_EXEC_UID}"))
        .arg(format!("--regid={DECEPTION_EXEC_GID}"))
        .arg("--clear-groups")
        .arg("--no-new-privs")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("mkdir -p -- \"$(dirname -- \"$1\")\" && cat > \"$1\"")
        .arg("deception-fs-write")
        .arg(&target)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = process.spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        DeceptionFsError::Io(IoError::new(
            ErrorKind::BrokenPipe,
            "deception write child did not expose stdin",
        ))
    })?;
    stdin.write_all(content.as_bytes()).await?;
    drop(stdin);

    let output = timeout(FS_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| DeceptionFsError::Timeout)??;
    if !output.status.success() {
        return Err(DeceptionFsError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    Ok(DeceptionWriteResult {
        path: relative.to_string_lossy().into_owned(),
        bytes_written: content.len(),
    })
}

fn validate_relative_path(value: &str) -> Result<PathBuf, DeceptionFsError> {
    if value.is_empty() || value.len() > 4096 {
        return Err(DeceptionFsError::InvalidPath);
    }

    let path = Path::new(value);
    if path.is_absolute() {
        return Err(DeceptionFsError::InvalidPath);
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(DeceptionFsError::InvalidPath)
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        Err(DeceptionFsError::InvalidPath)
    } else {
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_are_normalized_without_parent_escape() {
        assert_eq!(
            validate_relative_path("reports/./note.txt").unwrap(),
            PathBuf::from("reports/note.txt")
        );
        assert!(validate_relative_path("../secret").is_err());
        assert!(validate_relative_path("/etc/passwd").is_err());
        assert!(validate_relative_path("").is_err());
    }
}

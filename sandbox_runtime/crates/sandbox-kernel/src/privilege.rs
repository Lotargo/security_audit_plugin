/// Returns the explicitly configured numeric UID/GID for agent-controlled child processes.
/// DockerRunner always injects these variables for the production sandbox. Host-side unit tests
/// intentionally omit them and therefore keep the already-unprivileged test runner identity.
pub fn configured_audit_exec_identity() -> Option<(u32, u32)> {
    let uid = std::env::var("AUDIT_EXEC_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v != 0)?;
    let gid = std::env::var("AUDIT_EXEC_GID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v != 0)?;
    Some((uid, gid))
}

/// Fail-closed fallback for execution paths that must never inherit daemon root privileges.
pub fn audit_exec_identity() -> (u32, u32) {
    configured_audit_exec_identity().unwrap_or((65534, 65534))
}

pub const TOR_EXEC_UID: u32 = 65_531;
pub const TOR_EXEC_GID: u32 = 65_531;
pub const BROWSER_EXEC_UID: u32 = 65_532;
pub const BROWSER_EXEC_GID: u32 = 65_532;
pub const DECEPTION_EXEC_UID: u32 = 65_533;
pub const DECEPTION_EXEC_GID: u32 = 65_533;

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
    configured_audit_exec_identity().unwrap_or((65_534, 65_534))
}

/// Browser automation uses a dedicated identity so the agent shell cannot inherit managed proxy
/// access such as the local Tor SOCKS port.
pub fn browser_exec_identity() -> (u32, u32) {
    (BROWSER_EXEC_UID, BROWSER_EXEC_GID)
}

pub fn deception_exec_identity() -> (u32, u32) {
    (DECEPTION_EXEC_UID, DECEPTION_EXEC_GID)
}

pub fn audit_identity_conflicts_with_reserved_runtime_uid() -> bool {
    configured_audit_exec_identity()
        .map(|(uid, _)| {
            uid == TOR_EXEC_UID || uid == BROWSER_EXEC_UID || uid == DECEPTION_EXEC_UID
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_runtime_identities_are_non_root_and_distinct() {
        assert_ne!(TOR_EXEC_UID, 0);
        assert_ne!(BROWSER_EXEC_UID, 0);
        assert_ne!(TOR_EXEC_UID, BROWSER_EXEC_UID);
        assert_ne!(DECEPTION_EXEC_UID, 0);
        assert_ne!(DECEPTION_EXEC_UID, TOR_EXEC_UID);
        assert_ne!(DECEPTION_EXEC_UID, BROWSER_EXEC_UID);
    }
}

/// Returns the numeric UID/GID used for all agent-controlled child processes.
///
/// The Rust daemon itself intentionally remains privileged enough to manage nftables,
/// but arbitrary audit commands, tmux pane shells and browser children must never inherit
/// that privilege boundary. DockerRunner injects host-compatible numeric IDs so bind-mounted
/// workspaces remain usable without chowning the user's files.
pub fn audit_exec_identity() -> (u32, u32) {
    let uid = std::env::var("AUDIT_EXEC_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v != 0)
        .unwrap_or(65534);

    let gid = std::env::var("AUDIT_EXEC_GID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v != 0)
        .unwrap_or(65534);

    (uid, gid)
}

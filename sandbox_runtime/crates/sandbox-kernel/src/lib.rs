pub mod canary;
pub mod containment;
pub mod egress;
pub mod panic;
pub mod privilege;
pub mod tmux;
pub mod watchdog;

pub use canary::{CanaryManager, CanaryTrap};
pub use containment::{apply_runtime_containment, stop_tor_best_effort, ContainmentError};
pub use egress::{AuditMode, EgressConfig, EgressManager};
pub use panic::KillSwitch;
pub use privilege::{
    audit_exec_identity, audit_identity_conflicts_with_reserved_runtime_uid, browser_exec_identity,
    configured_audit_exec_identity, BROWSER_EXEC_GID, BROWSER_EXEC_UID, TOR_EXEC_GID, TOR_EXEC_UID,
};
pub use tmux::TmuxManager;
pub use watchdog::{process_command_output, WatchdogResult, MAX_OUTPUT_CHARS};

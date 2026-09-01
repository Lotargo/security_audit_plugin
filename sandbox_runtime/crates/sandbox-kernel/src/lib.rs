pub mod canary;
pub mod egress;
pub mod panic;
pub mod privilege;
pub mod tmux;
pub mod watchdog;

pub use canary::{CanaryManager, CanaryTrap};
pub use egress::{AuditMode, EgressConfig, EgressManager};
pub use panic::KillSwitch;
pub use privilege::{audit_exec_identity, configured_audit_exec_identity};
pub use tmux::TmuxManager;
pub use watchdog::{process_command_output, WatchdogResult, MAX_OUTPUT_CHARS};

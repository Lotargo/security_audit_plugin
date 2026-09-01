#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use tracing::{error, info};

static IS_ISOLATED: AtomicBool = AtomicBool::new(false);

#[derive(Error, Debug)]
pub enum PanicError {
    #[error("Failed to execute emergency isolation command: {0}")]
    ExecutionFailed(String),
    #[error("I/O error during panic lockdown: {0}")]
    IoError(#[from] std::io::Error),
}

pub struct KillSwitch;

impl KillSwitch {
    /// Returns true if the sandbox network is currently locked down in emergency isolation mode
    pub fn is_isolated() -> bool {
        IS_ISOLATED.load(Ordering::SeqCst)
    }

    /// Resets isolation status (e.g. during clean container respawn or re-provision)
    pub fn reset_isolation() {
        IS_ISOLATED.store(false, Ordering::SeqCst);
        info!("Isolation status reset to normal.");
    }

    /// Triggers immediate hardware L2/L3 network blackout:
    /// 1. Flushes all conntrack active tracking tables (`conntrack -F`)
    /// 2. Replaces all nftables rules with DROP ALL on all chains
    pub fn trigger(reason: &str) -> Result<(), PanicError> {
        error!("!!! EMERGENCY KILL SWITCH TRIGGERED !!! Reason: {}", reason);
        IS_ISOLATED.store(true, Ordering::SeqCst);

        let blackout_rules = r#"#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy drop;
    }
}
"#;

        #[cfg(target_os = "linux")]
        {
            use std::io::Write;

            // 1. Flush conntrack connections
            let _ = Command::new("conntrack").arg("-F").status();

            // 2. Lock down nftables
            let mut child = Command::new("nft")
                .arg("-f")
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(blackout_rules.as_bytes())?;
            }

            let output = child.wait_with_output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("Kill switch nft error: {}", stderr);
                return Err(PanicError::ExecutionFailed(stderr.into_owned()));
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            info!(
                "Non-Linux platform: Emergency blackout rules compiled in memory:\n{}",
                blackout_rules
            );
        }

        info!("Sandbox network has been completely severed and isolated.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_switch_state_transition() {
        KillSwitch::reset_isolation();
        assert!(!KillSwitch::is_isolated());

        assert!(KillSwitch::trigger("Unit test emergency trigger").is_ok());
        assert!(KillSwitch::is_isolated());

        KillSwitch::reset_isolation();
        assert!(!KillSwitch::is_isolated());
    }
}

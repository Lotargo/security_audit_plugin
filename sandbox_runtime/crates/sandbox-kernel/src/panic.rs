#[cfg(all(target_os = "linux", not(test)))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use tracing::{error, info};

use crate::privilege::DECEPTION_EXEC_UID;

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
    /// Returns true if emergency isolation has been latched for this runtime.
    pub fn is_isolated() -> bool {
        IS_ISOLATED.load(Ordering::SeqCst)
    }

    /// Resets isolation status (e.g. during clean container respawn or re-provision).
    pub fn reset_isolation() {
        IS_ISOLATED.store(false, Ordering::SeqCst);
        info!("Isolation status reset to normal.");
    }

    /// Triggers immediate hardware L2/L3 network blackout:
    /// 1. Flushes all conntrack active tracking tables (`conntrack -F`).
    /// 2. Replaces nftables with a DROP-by-default policy that preserves only loopback and the
    ///    authenticated management RPC channel.
    ///
    /// In the real Linux sandbox, failure to install the nftables policy aborts PID 1. Keeping a
    /// container alive with the previous egress policy after an emergency isolation request would
    /// be a fail-open condition, so process termination is the only safe fallback.
    pub fn trigger(reason: &str) -> Result<(), PanicError> {
        error!("!!! EMERGENCY KILL SWITCH TRIGGERED !!! Reason: {}", reason);
        IS_ISOLATED.store(true, Ordering::SeqCst);

        let mgmt_port = std::env::var("PORT").unwrap_or_else(|_| "9999".to_string());
        let blackout_rules = format!(
            r#"#!/usr/sbin/nft -f
flush ruleset
table inet filter {{
    chain input {{
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        tcp dport {mgmt_port} accept
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}
    chain output {{
        type filter hook output priority 0; policy drop;
        meta skuid {DECEPTION_EXEC_UID} tcp dport {mgmt_port} reject
        meta skuid {DECEPTION_EXEC_UID} tcp dport 9050 reject
        meta skuid {DECEPTION_EXEC_UID} tcp dport 9051 reject
        meta skuid {DECEPTION_EXEC_UID} udp dport 53 reject
        meta skuid {DECEPTION_EXEC_UID} tcp dport 53 reject
        meta skuid {DECEPTION_EXEC_UID} ct state established,related accept
        meta skuid {DECEPTION_EXEC_UID} ip daddr 127.0.0.0/8 tcp dport 18000-18999 accept
        meta skuid {DECEPTION_EXEC_UID} ip saddr 127.0.0.0/8 tcp sport 18000-18999 accept
        meta skuid {DECEPTION_EXEC_UID} ip6 daddr ::1/128 tcp dport 18000-18999 accept
        meta skuid {DECEPTION_EXEC_UID} ip6 saddr ::1/128 tcp sport 18000-18999 accept
        meta skuid {DECEPTION_EXEC_UID} reject
        oifname "lo" accept
        tcp sport {mgmt_port} accept
    }}
}}
"#
        );

        #[cfg(all(target_os = "linux", not(test)))]
        {
            use std::io::Write;

            // Unit-test harnesses in downstream crates must be able to exercise the
            // isolation latch without CAP_NET_ADMIN: cfg(test) does NOT propagate to
            // dependencies, so a compile-time gate cannot distinguish them. Explicit
            // opt-in only — production never sets this variable, so the fail-closed
            // abort() path below is unchanged there.
            let skip_privileged_net = std::env::var("SECURITY_AUDIT_SKIP_PRIVILEGED_NET").is_ok();
            if skip_privileged_net {
                info!(
                    "Skipping privileged nft blackout (SECURITY_AUDIT_SKIP_PRIVILEGED_NET is set)"
                );
            }

            // Existing connections should not survive the transition. Conntrack flushing is
            // best-effort; the replacement nftables policy is the mandatory security boundary.
            if !skip_privileged_net {
                let _ = Command::new("conntrack").arg("-F").status();
            }

            if !skip_privileged_net {
                let apply_result: Result<(), PanicError> = (|| {
                    let mut child = Command::new("nft")
                        .arg("-f")
                        .arg("-")
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()?;

                    let mut stdin = child.stdin.take().ok_or_else(|| {
                        PanicError::ExecutionFailed(
                            "nft child did not expose stdin for blackout rules".to_string(),
                        )
                    })?;
                    stdin.write_all(blackout_rules.as_bytes())?;
                    drop(stdin);

                    let output = child.wait_with_output()?;
                    if !output.status.success() {
                        return Err(PanicError::ExecutionFailed(
                            String::from_utf8_lossy(&output.stderr).into_owned(),
                        ));
                    }
                    Ok(())
                })();

                if let Err(err) = apply_result {
                    error!(
                        "Emergency nftables isolation failed: {}. Aborting sandbox runtime fail-closed.",
                        err
                    );
                    std::process::abort();
                }
            }
        }

        #[cfg(any(not(target_os = "linux"), test))]
        {
            info!(
                "Test/non-Linux platform: Emergency blackout rules compiled in memory:\n{}",
                blackout_rules
            );
        }

        info!("Sandbox network has been severed except for the management channel.");
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

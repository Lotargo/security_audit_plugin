use crate::egress::{split_ip_families, EgressConfig};
use crate::privilege::{configured_audit_exec_identity, TOR_EXEC_UID};
#[cfg(target_os = "linux")]
use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContainmentError {
    #[error("AUDIT_EXEC_UID/AUDIT_EXEC_GID must be configured before applying runtime containment")]
    MissingAuditIdentity,
    #[error("Failed to apply runtime containment rule: {0}")]
    RuleFailed(String),
    #[error("I/O error while applying runtime containment: {0}")]
    IoError(#[from] std::io::Error),
}

fn planned_rules(config: &EgressConfig, audit_uid: u32) -> Vec<Vec<String>> {
    let mut rules = vec![
        vec![
            "meta".into(),
            "skuid".into(),
            audit_uid.to_string(),
            "tcp".into(),
            "dport".into(),
            "9050".into(),
            "reject".into(),
        ],
        vec![
            "meta".into(),
            "skuid".into(),
            audit_uid.to_string(),
            "tcp".into(),
            "dport".into(),
            "9051".into(),
            "reject".into(),
        ],
    ];

    if config.tor_enabled {
        let (denied_v4, denied_v6) = split_ip_families(&config.denied_cidrs);
        if !denied_v4.is_empty() {
            rules.push(vec![
                "meta".into(),
                "skuid".into(),
                TOR_EXEC_UID.to_string(),
                "ip".into(),
                "daddr".into(),
                "@denied_private_cidrs_v4".into(),
                "reject".into(),
            ]);
        }
        if !denied_v6.is_empty() {
            rules.push(vec![
                "meta".into(),
                "skuid".into(),
                TOR_EXEC_UID.to_string(),
                "ip6".into(),
                "daddr".into(),
                "@denied_private_cidrs_v6".into(),
                "reject".into(),
            ]);
        }
        rules.push(vec![
            "meta".into(),
            "skuid".into(),
            TOR_EXEC_UID.to_string(),
            "tcp".into(),
            "accept".into(),
        ]);
    }

    rules
}

#[cfg(target_os = "linux")]
fn insert_output_rule(rule: &[String]) -> Result<(), ContainmentError> {
    let output = Command::new("nft")
        .args(["insert", "rule", "inet", "filter", "output"])
        .args(rule)
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(ContainmentError::RuleFailed(
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

/// Adds process-identity isolation on top of the CIDR RoE ruleset.
///
/// `nft insert` prepends rules, so they are installed in reverse order to preserve the desired
/// evaluation order: agent Tor denial first, Tor private-range denial second, Tor relay egress last.
pub fn apply_runtime_containment(config: &EgressConfig) -> Result<(), ContainmentError> {
    let (audit_uid, _) =
        configured_audit_exec_identity().ok_or(ContainmentError::MissingAuditIdentity)?;
    let rules = planned_rules(config, audit_uid);

    #[cfg(target_os = "linux")]
    for rule in rules.iter().rev() {
        insert_output_rule(rule)?;
    }

    #[cfg(not(target_os = "linux"))]
    let _ = rules;

    Ok(())
}

/// If containment cannot be restored after a ruleset replacement, stop Tor so an old circuit
/// cannot remain usable through loopback while the agent-specific deny rule is absent.
pub fn stop_tor_best_effort() {
    #[cfg(target_os = "linux")]
    {
        let uid = TOR_EXEC_UID.to_string();
        let _ = Command::new("pkill")
            .args(["-u", uid.as_str(), "tor"])
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::{AuditMode, EgressConfig};

    #[test]
    fn local_containment_blocks_agent_from_tor_services() {
        let rules = planned_rules(&EgressConfig::default(), 1001);
        assert_eq!(rules.len(), 2);
        assert!(rules[0]
            .join(" ")
            .contains("meta skuid 1001 tcp dport 9050 reject"));
        assert!(rules[1]
            .join(" ")
            .contains("meta skuid 1001 tcp dport 9051 reject"));
    }

    #[test]
    fn tor_containment_denies_private_ranges_before_relay_egress() {
        let config = EgressConfig {
            mode: AuditMode::Remote,
            tor_enabled: true,
            ..Default::default()
        };
        let rules = planned_rules(&config, 1001);
        let rendered: Vec<String> = rules.iter().map(|rule| rule.join(" ")).collect();

        let private_v4 = rendered
            .iter()
            .position(|rule| rule.contains("@denied_private_cidrs_v4 reject"))
            .unwrap();
        let tor_allow = rendered
            .iter()
            .position(|rule| rule == &format!("meta skuid {TOR_EXEC_UID} tcp accept"))
            .unwrap();
        assert!(private_v4 < tor_allow);
    }
}

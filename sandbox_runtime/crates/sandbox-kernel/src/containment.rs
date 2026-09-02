use crate::egress::{split_ip_families, EgressConfig};
use crate::privilege::{configured_audit_exec_identity, TOR_EXEC_UID};
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContainmentError {
    #[error(
        "AUDIT_EXEC_UID/AUDIT_EXEC_GID must be configured before applying runtime containment"
    )]
    MissingAuditIdentity,
    #[error("Failed to apply runtime containment rule: {0}")]
    RuleFailed(String),
    #[error("I/O error while applying runtime containment: {0}")]
    IoError(#[from] std::io::Error),
}

fn planned_rules(
    config: &EgressConfig,
    audit_uid: u32,
    agent_allowed_cidrs: &[String],
) -> Vec<Vec<String>> {
    // Agent-controlled shells never need direct access to Tor control services or DNS. Target
    // names are resolved by the trusted host for L3 pinning, while browser/probe clients use
    // their own managed resolver path. Blocking both UDP/TCP 53 closes DNS as an exfil channel.
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
        vec![
            "meta".into(),
            "skuid".into(),
            audit_uid.to_string(),
            "udp".into(),
            "dport".into(),
            "53".into(),
            "reject".into(),
        ],
        vec![
            "meta".into(),
            "skuid".into(),
            audit_uid.to_string(),
            "tcp".into(),
            "dport".into(),
            "53".into(),
            "reject".into(),
        ],
    ];

    // `allowed_cidrs` contains all host-pinned destinations needed by managed clients. Only the
    // explicit IP/CIDR subset is granted to the raw agent shell. Resolved domain addresses remain
    // managed-only so a shared CDN/reverse-proxy IP cannot expand domain RoE into arbitrary vhosts.
    let agent_allowed: BTreeSet<&str> = agent_allowed_cidrs
        .iter()
        .map(|cidr| cidr.trim())
        .collect();
    let managed_only: Vec<String> = config
        .allowed_cidrs
        .iter()
        .filter(|cidr| !agent_allowed.contains(cidr.trim()))
        .cloned()
        .collect();
    let (managed_v4, managed_v6) = split_ip_families(&managed_only);

    for cidr in managed_v4 {
        rules.push(vec![
            "meta".into(),
            "skuid".into(),
            audit_uid.to_string(),
            "ip".into(),
            "daddr".into(),
            cidr,
            "reject".into(),
        ]);
    }
    for cidr in managed_v6 {
        rules.push(vec![
            "meta".into(),
            "skuid".into(),
            audit_uid.to_string(),
            "ip6".into(),
            "daddr".into(),
            cidr,
            "reject".into(),
        ]);
    }

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
            "meta".into(),
            "l4proto".into(),
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
/// This strict entry point grants the raw agent shell no destination CIDRs. Production egress
/// provisioning uses `apply_runtime_containment_with_agent_allowlist` to opt in only explicit
/// IP/CIDR targets after validating that they are a subset of the kernel allowlist.
pub fn apply_runtime_containment(config: &EgressConfig) -> Result<(), ContainmentError> {
    apply_runtime_containment_with_agent_allowlist(config, &[])
}

/// Adds process-identity isolation while granting raw agent access only to the validated explicit
/// IP/CIDR subset supplied by the trusted provisioning route.
///
/// `nft insert` prepends rules, so they are installed in reverse order to preserve the desired
/// evaluation order: agent Tor/DNS/managed-target denial first, Tor private-range denial second,
/// Tor relay egress last.
pub fn apply_runtime_containment_with_agent_allowlist(
    config: &EgressConfig,
    agent_allowed_cidrs: &[String],
) -> Result<(), ContainmentError> {
    let (audit_uid, _) =
        configured_audit_exec_identity().ok_or(ContainmentError::MissingAuditIdentity)?;
    let rules = planned_rules(config, audit_uid, agent_allowed_cidrs);

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
    fn local_containment_blocks_agent_from_tor_and_dns_services() {
        let rules = planned_rules(&EgressConfig::default(), 1001, &[]);
        assert_eq!(rules.len(), 4);
        let rendered: Vec<String> = rules.iter().map(|rule| rule.join(" ")).collect();
        assert!(rendered
            .iter()
            .any(|rule| rule == "meta skuid 1001 tcp dport 9050 reject"));
        assert!(rendered
            .iter()
            .any(|rule| rule == "meta skuid 1001 tcp dport 9051 reject"));
        assert!(rendered
            .iter()
            .any(|rule| rule == "meta skuid 1001 udp dport 53 reject"));
        assert!(rendered
            .iter()
            .any(|rule| rule == "meta skuid 1001 tcp dport 53 reject"));
    }

    #[test]
    fn domain_pinned_cidrs_are_managed_only_but_explicit_ip_targets_remain_raw() {
        let config = EgressConfig {
            mode: AuditMode::Remote,
            allowed_cidrs: vec![
                "93.184.216.34/32".to_string(),
                "203.0.113.7/32".to_string(),
            ],
            ..Default::default()
        };
        let rules = planned_rules(&config, 1001, &["203.0.113.7/32".to_string()]);
        let rendered: Vec<String> = rules.iter().map(|rule| rule.join(" ")).collect();

        assert!(rendered.iter().any(|rule| {
            rule == "meta skuid 1001 ip daddr 93.184.216.34/32 reject"
        }));
        assert!(!rendered.iter().any(|rule| rule.contains("203.0.113.7/32 reject")));
    }

    #[test]
    fn tor_containment_blocks_agent_dns_and_denies_private_relays() {
        let config = EgressConfig {
            mode: AuditMode::Remote,
            tor_enabled: true,
            ..Default::default()
        };
        let rules = planned_rules(&config, 1001, &[]);
        let rendered: Vec<String> = rules.iter().map(|rule| rule.join(" ")).collect();

        assert!(rendered
            .iter()
            .any(|rule| rule == "meta skuid 1001 udp dport 53 reject"));
        assert!(rendered
            .iter()
            .any(|rule| rule == "meta skuid 1001 tcp dport 53 reject"));

        let private_v4 = rendered
            .iter()
            .position(|rule| rule.contains("@denied_private_cidrs_v4 reject"))
            .unwrap();
        let tor_allow = rendered
            .iter()
            .position(|rule| rule == &format!("meta skuid {TOR_EXEC_UID} meta l4proto tcp accept"))
            .unwrap();
        assert!(private_v4 < tor_allow);
    }
}

use super::DeceptionProfile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const FORBIDDEN_MARKERS: &[&str] = &["shadow", "decoy", "evolve", "synthetic", "honeypot"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentNarrative {
    pub session_id: String,
    pub environment: String,
    pub region: String,
    pub domain: String,
    pub primary_user: String,
    pub hostname: String,
    pub os_release: String,
    pub revealed_hosts: BTreeSet<String>,
}

impl EnvironmentNarrative {
    pub fn new(session_id: impl Into<String>, entry_profile: DeceptionProfile) -> Self {
        let hostname = entry_hostname(entry_profile).to_string();
        let mut revealed_hosts = BTreeSet::new();
        revealed_hosts.insert(hostname.clone());

        Self {
            session_id: session_id.into(),
            environment: "production".to_string(),
            region: "eu-central-1".to_string(),
            domain: "prod.internal".to_string(),
            primary_user: "deploy".to_string(),
            hostname,
            os_release: "Ubuntu 24.04.3 LTS".to_string(),
            revealed_hosts,
        }
    }

    pub fn reveal_host(&mut self, hostname: &str) -> bool {
        if !Self::hostname_is_safe(hostname) {
            return false;
        }
        self.revealed_hosts.insert(hostname.to_string())
    }

    pub fn hostname_is_safe(hostname: &str) -> bool {
        let normalized = hostname.trim().to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.starts_with('.')
            || normalized.ends_with('.')
            || !normalized
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.')
        {
            return false;
        }

        if FORBIDDEN_MARKERS
            .iter()
            .any(|marker| normalized.contains(marker))
        {
            return false;
        }

        normalized.ends_with(".internal")
    }
}

fn entry_hostname(profile: DeceptionProfile) -> &'static str {
    match profile {
        DeceptionProfile::DeveloperWorkstation => "dev-01.prod.internal",
        DeceptionProfile::CiRunner => "runner-02.prod.internal",
        DeceptionProfile::ApplicationServer => "app-01.prod.internal",
        DeceptionProfile::DatabaseHost => "db-prod.internal",
        DeceptionProfile::KubernetesNode => "worker-03.prod.internal",
        DeceptionProfile::BastionHost => "bastion.prod.internal",
        DeceptionProfile::SecretsService => "vault.prod.internal",
        DeceptionProfile::InternalApi => "api.prod.internal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrative_rejects_deception_markers() {
        assert!(!EnvironmentNarrative::hostname_is_safe(
            "vault-shadow.internal"
        ));
        assert!(!EnvironmentNarrative::hostname_is_safe(
            "evolve-node.internal"
        ));
        assert!(EnvironmentNarrative::hostname_is_safe(
            "db-prod.internal"
        ));
    }
}

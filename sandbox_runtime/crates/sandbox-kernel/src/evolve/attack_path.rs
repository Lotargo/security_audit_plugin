use super::{BehaviorTag, DeceptionProfile, EnvironmentNarrative, SecurityEvent};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowNodeState {
    Hidden,
    Exposed,
    Visited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowNode {
    pub node_id: String,
    pub profile: DeceptionProfile,
    pub service_name: String,
    pub hostname: String,
    pub port: u16,
    pub protocol: String,
    pub state: ShadowNodeState,
    pub next_nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowAttackPath {
    pub path_id: String,
    pub session_id: String,
    pub entry_node_id: String,
    pub active_node_id: String,
    pub generation: u64,
    pub narrative: EnvironmentNarrative,
    pub nodes: BTreeMap<String, ShadowNode>,
}

#[derive(Error, Debug)]
pub enum AttackPathError {
    #[error("Shadow Attack Path requires at least two distinct node profiles")]
    InsufficientNodes,
    #[error("Unsafe synthetic hostname in Shadow Attack Path: {0}")]
    UnsafeHostname(String),
    #[error("Duplicate node profile in Shadow Attack Path")]
    DuplicateProfile,
}

impl ShadowAttackPath {
    pub fn build(
        session_id: impl Into<String>,
        entry_profile: DeceptionProfile,
    ) -> Result<Self, AttackPathError> {
        let session_id = session_id.into();
        let profiles = topology_for(entry_profile);
        if profiles.len() < 2 {
            return Err(AttackPathError::InsufficientNodes);
        }

        let mut unique = BTreeSet::new();
        for profile in &profiles {
            if !unique.insert(profile.id()) {
                return Err(AttackPathError::DuplicateProfile);
            }
        }

        let mut nodes = BTreeMap::new();
        let mut ordered_ids = Vec::new();

        for (index, profile) in profiles.iter().copied().enumerate() {
            let spec = node_spec(profile);
            if !EnvironmentNarrative::hostname_is_safe(spec.hostname) {
                return Err(AttackPathError::UnsafeHostname(spec.hostname.to_string()));
            }

            let node_id = format!("node-{index}");
            ordered_ids.push(node_id.clone());
            nodes.insert(
                node_id.clone(),
                ShadowNode {
                    node_id,
                    profile,
                    service_name: spec.service_name.to_string(),
                    hostname: spec.hostname.to_string(),
                    port: spec.port,
                    protocol: spec.protocol.to_string(),
                    state: if index == 0 {
                        ShadowNodeState::Visited
                    } else if index == 1 {
                        ShadowNodeState::Exposed
                    } else {
                        ShadowNodeState::Hidden
                    },
                    next_nodes: Vec::new(),
                },
            );
        }

        for index in 0..ordered_ids.len().saturating_sub(1) {
            let current = ordered_ids[index].clone();
            let next = ordered_ids[index + 1].clone();
            if let Some(node) = nodes.get_mut(&current) {
                node.next_nodes.push(next);
            }
        }

        let entry_node_id = ordered_ids[0].clone();
        let active_node_id = entry_node_id.clone();
        let mut narrative = EnvironmentNarrative::new(&session_id, entry_profile);
        for node in nodes.values() {
            if node.state != ShadowNodeState::Hidden {
                narrative.reveal_host(&node.hostname);
            }
        }

        Ok(Self {
            path_id: format!("path-{}-{}", session_id, now_ms()),
            session_id,
            entry_node_id,
            active_node_id,
            generation: 1,
            narrative,
            nodes,
        })
    }

    pub fn all_profiles(&self) -> Vec<DeceptionProfile> {
        self.nodes.values().map(|node| node.profile).collect()
    }

    pub fn visible_nodes(&self) -> Vec<ShadowNode> {
        self.nodes
            .values()
            .filter(|node| node.state != ShadowNodeState::Hidden)
            .cloned()
            .collect()
    }

    pub fn observe(&mut self, event: &SecurityEvent, tags: &[BehaviorTag]) -> bool {
        let mut changed = false;
        let command = event
            .command
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let destination = event
            .destination
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();

        let visited_node = self.nodes.iter().find_map(|(node_id, node)| {
            if destination.contains(&node.hostname.to_ascii_lowercase())
                || command.contains(&node.hostname.to_ascii_lowercase())
            {
                Some(node_id.clone())
            } else {
                None
            }
        });

        if let Some(node_id) = visited_node {
            changed |= self.mark_visited(&node_id);
        }

        let target_profile = infer_target_profile(&command, tags);
        if let Some(profile) = target_profile {
            changed |= self.expose_profile(profile);
        } else if tags.contains(&BehaviorTag::Discovery)
            || tags.contains(&BehaviorTag::NetworkActivity)
        {
            changed |= self.expose_next_from_active();
        }

        if changed {
            self.generation = self.generation.saturating_add(1);
        }
        changed
    }

    fn mark_visited(&mut self, node_id: &str) -> bool {
        let mut changed = false;
        let next_nodes = if let Some(node) = self.nodes.get_mut(node_id) {
            if node.state != ShadowNodeState::Visited {
                node.state = ShadowNodeState::Visited;
                changed = true;
            }
            self.active_node_id = node_id.to_string();
            self.narrative.reveal_host(&node.hostname);
            node.next_nodes.clone()
        } else {
            return false;
        };

        for next_id in next_nodes {
            if let Some(next) = self.nodes.get_mut(&next_id) {
                if next.state == ShadowNodeState::Hidden {
                    next.state = ShadowNodeState::Exposed;
                    self.narrative.reveal_host(&next.hostname);
                    changed = true;
                }
            }
        }
        changed
    }

    fn expose_profile(&mut self, profile: DeceptionProfile) -> bool {
        let node_id = self
            .nodes
            .iter()
            .find_map(|(node_id, node)| (node.profile == profile).then(|| node_id.clone()));
        let Some(node_id) = node_id else {
            return false;
        };

        if let Some(node) = self.nodes.get_mut(&node_id) {
            if node.state == ShadowNodeState::Hidden {
                node.state = ShadowNodeState::Exposed;
                self.narrative.reveal_host(&node.hostname);
                return true;
            }
        }
        false
    }

    fn expose_next_from_active(&mut self) -> bool {
        let next_nodes = self
            .nodes
            .get(&self.active_node_id)
            .map(|node| node.next_nodes.clone())
            .unwrap_or_default();

        let mut changed = false;
        for next_id in next_nodes {
            if let Some(next) = self.nodes.get_mut(&next_id) {
                if next.state == ShadowNodeState::Hidden {
                    next.state = ShadowNodeState::Exposed;
                    self.narrative.reveal_host(&next.hostname);
                    changed = true;
                }
            }
        }
        changed
    }
}

struct NodeSpec {
    service_name: &'static str,
    hostname: &'static str,
    port: u16,
    protocol: &'static str,
}

fn node_spec(profile: DeceptionProfile) -> NodeSpec {
    match profile {
        DeceptionProfile::DeveloperWorkstation => NodeSpec {
            service_name: "dev-api",
            hostname: "dev-api.prod.internal",
            port: 18080,
            protocol: "http",
        },
        DeceptionProfile::CiRunner => NodeSpec {
            service_name: "artifact-api",
            hostname: "artifacts.prod.internal",
            port: 18081,
            protocol: "http",
        },
        DeceptionProfile::ApplicationServer => NodeSpec {
            service_name: "app-http",
            hostname: "app.prod.internal",
            port: 18082,
            protocol: "http",
        },
        DeceptionProfile::InternalApi => NodeSpec {
            service_name: "internal-api",
            hostname: "api.prod.internal",
            port: 18083,
            protocol: "http",
        },
        DeceptionProfile::KubernetesNode => NodeSpec {
            service_name: "kube-api",
            hostname: "control-plane.internal",
            port: 18084,
            protocol: "http",
        },
        DeceptionProfile::BastionHost => NodeSpec {
            service_name: "sshd",
            hostname: "bastion.prod.internal",
            port: 18022,
            protocol: "ssh",
        },
        DeceptionProfile::SecretsService => NodeSpec {
            service_name: "vault",
            hostname: "vault.prod.internal",
            port: 18200,
            protocol: "http",
        },
        DeceptionProfile::DatabaseHost => NodeSpec {
            service_name: "postgres",
            hostname: "db-prod.internal",
            port: 18432,
            protocol: "postgres",
        },
    }
}

fn topology_for(entry: DeceptionProfile) -> Vec<DeceptionProfile> {
    use DeceptionProfile::*;

    match entry {
        DeveloperWorkstation => vec![
            DeveloperWorkstation,
            BastionHost,
            ApplicationServer,
            DatabaseHost,
            SecretsService,
        ],
        CiRunner => vec![
            CiRunner,
            ApplicationServer,
            KubernetesNode,
            SecretsService,
            DatabaseHost,
        ],
        ApplicationServer => vec![
            ApplicationServer,
            InternalApi,
            DatabaseHost,
            SecretsService,
            BastionHost,
        ],
        DatabaseHost => vec![
            DatabaseHost,
            BastionHost,
            SecretsService,
            ApplicationServer,
            KubernetesNode,
        ],
        KubernetesNode => vec![
            KubernetesNode,
            SecretsService,
            InternalApi,
            DatabaseHost,
            BastionHost,
        ],
        BastionHost => vec![
            BastionHost,
            ApplicationServer,
            DatabaseHost,
            KubernetesNode,
            SecretsService,
        ],
        SecretsService => vec![
            SecretsService,
            ApplicationServer,
            DatabaseHost,
            KubernetesNode,
            BastionHost,
        ],
        InternalApi => vec![
            InternalApi,
            ApplicationServer,
            DatabaseHost,
            SecretsService,
            KubernetesNode,
        ],
    }
}

fn infer_target_profile(command: &str, tags: &[BehaviorTag]) -> Option<DeceptionProfile> {
    if command.contains("kubectl") || command.contains("kube") {
        return Some(DeceptionProfile::KubernetesNode);
    }
    if command.contains("ssh ") || command.starts_with("ssh") {
        return Some(DeceptionProfile::BastionHost);
    }
    if command.contains("psql") || command.contains("mysql") || command.contains("postgres") {
        return Some(DeceptionProfile::DatabaseHost);
    }
    if command.contains("vault")
        || command.contains("token")
        || tags.contains(&BehaviorTag::CredentialAccess)
        || tags.contains(&BehaviorTag::CredentialInterest)
    {
        return Some(DeceptionProfile::SecretsService);
    }
    if command.contains("curl") || command.contains("wget") {
        return Some(DeceptionProfile::InternalApi);
    }
    None
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evolve::{EventSource, SecurityEventType};

    #[test]
    fn path_starts_with_only_entry_and_next_node_visible() {
        let path = ShadowAttackPath::build("session-a", DeceptionProfile::SecretsService).unwrap();
        assert_eq!(path.visible_nodes().len(), 2);
        assert_eq!(
            path.nodes[&path.entry_node_id].state,
            ShadowNodeState::Visited
        );
    }

    #[test]
    fn behavior_can_expose_relevant_hidden_node() {
        let mut path = ShadowAttackPath::build("session-a", DeceptionProfile::CiRunner).unwrap();
        let event = SecurityEvent::new(EventSource::Process, SecurityEventType::ProcessExec)
            .with_command("kubectl get pods");

        assert!(path.observe(&event, &[BehaviorTag::Execution]));
        assert!(path
            .visible_nodes()
            .iter()
            .any(|node| node.profile == DeceptionProfile::KubernetesNode));
    }
}

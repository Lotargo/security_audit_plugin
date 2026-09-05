use super::{BehaviorTag, BehaviorTrace};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DECEPTION_ROOT: &str = "/workspace/.evolve-deception";
const SYNTHETIC_PORT_MIN: u16 = 18_000;
const SYNTHETIC_PORT_MAX: u16 = 18_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeceptionProfile {
    DeveloperWorkstation,
    CiRunner,
    ApplicationServer,
    DatabaseHost,
    KubernetesNode,
    BastionHost,
    SecretsService,
    InternalApi,
}

impl DeceptionProfile {
    pub fn id(self) -> &'static str {
        match self {
            Self::DeveloperWorkstation => "developer-workstation",
            Self::CiRunner => "ci-runner",
            Self::ApplicationServer => "application-server",
            Self::DatabaseHost => "database-host",
            Self::KubernetesNode => "kubernetes-node",
            Self::BastionHost => "bastion-host",
            Self::SecretsService => "secrets-service",
            Self::InternalApi => "internal-api",
        }
    }

    pub fn select(trace: &BehaviorTrace) -> Self {
        for event in trace.events.iter().rev() {
            let command = event.command.as_deref().unwrap_or_default().to_ascii_lowercase();
            let resource = event.resource.as_deref().unwrap_or_default().to_ascii_lowercase();

            if command.contains("kubectl") || resource.contains(".kube") {
                return Self::KubernetesNode;
            }
            if command.contains("ssh ") || resource.contains(".ssh") {
                return Self::BastionHost;
            }
            if command.contains("psql") || command.contains("mysql") || resource.contains("database") {
                return Self::DatabaseHost;
            }
            if resource.contains(".github") || resource.contains("gitlab") || command.contains("ci") {
                return Self::CiRunner;
            }
        }

        if trace.tags.contains(&BehaviorTag::CredentialAccess)
            || trace.tags.contains(&BehaviorTag::CredentialInterest)
        {
            Self::SecretsService
        } else if trace.tags.contains(&BehaviorTag::NetworkActivity) {
            Self::InternalApi
        } else {
            Self::DeveloperWorkstation
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionService {
    pub name: String,
    pub bind_host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionInstance {
    pub instance_id: String,
    pub session_id: String,
    pub profile: DeceptionProfile,
    pub root: PathBuf,
    pub planned_services: Vec<DeceptionService>,
    pub created_at_ms: u64,
    pub validated: bool,
}

#[derive(Error, Debug)]
pub enum DeceptionError {
    #[error("invalid deception session id")]
    InvalidSessionId,
    #[error("behavior trace is not available for session: {0}")]
    MissingBehaviorTrace(String),
    #[error("deception root escaped the trusted synthetic root")]
    UnsafeRoot,
    #[error("deception service attempted unsafe endpoint: {0}:{1}")]
    UnsafeService(String, u16),
    #[error("I/O error while preparing deception: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize deception manifest: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Default)]
pub struct DeceptionFabric {
    instances: HashMap<String, DeceptionInstance>,
}

impl DeceptionFabric {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare(
        &mut self,
        session_id: &str,
        trace: &BehaviorTrace,
    ) -> Result<DeceptionInstance, DeceptionError> {
        if !is_safe_session_id(session_id) {
            return Err(DeceptionError::InvalidSessionId);
        }

        let profile = DeceptionProfile::select(trace);
        let root = PathBuf::from(DECEPTION_ROOT).join(session_id);
        validate_root(&root)?;
        fs::create_dir_all(&root)?;

        let services = planned_services(profile);
        for service in &services {
            validate_service(service)?;
        }

        materialize_profile(&root, profile, &services)?;
        let instance = DeceptionInstance {
            instance_id: format!("decoy-{session_id}-{}", now_ms()),
            session_id: session_id.to_string(),
            profile,
            root,
            planned_services: services,
            created_at_ms: now_ms(),
            validated: true,
        };
        self.instances
            .insert(session_id.to_string(), instance.clone());
        Ok(instance)
    }

    pub fn instance(&self, session_id: &str) -> Option<&DeceptionInstance> {
        self.instances.get(session_id)
    }

    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    pub fn destroy(&mut self, session_id: &str) -> Result<bool, DeceptionError> {
        let Some(instance) = self.instances.remove(session_id) else {
            return Ok(false);
        };
        if instance.root.exists() {
            fs::remove_dir_all(instance.root)?;
        }
        Ok(true)
    }
}

fn is_safe_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= 64
        && session_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn validate_root(root: &Path) -> Result<(), DeceptionError> {
    if root.starts_with(DECEPTION_ROOT) {
        Ok(())
    } else {
        Err(DeceptionError::UnsafeRoot)
    }
}

fn validate_service(service: &DeceptionService) -> Result<(), DeceptionError> {
    let loopback = service.bind_host == "127.0.0.1" || service.bind_host == "::1";
    let safe_port = (SYNTHETIC_PORT_MIN..=SYNTHETIC_PORT_MAX).contains(&service.port);
    if loopback && safe_port && !matches!(service.port, 9050 | 9051 | 9999) {
        Ok(())
    } else {
        Err(DeceptionError::UnsafeService(
            service.bind_host.clone(),
            service.port,
        ))
    }
}

fn planned_services(profile: DeceptionProfile) -> Vec<DeceptionService> {
    let specs: &[(&str, u16, &str)] = match profile {
        DeceptionProfile::DeveloperWorkstation => &[("dev-api", 18080, "http")],
        DeceptionProfile::CiRunner => &[("artifact-api", 18081, "http")],
        DeceptionProfile::ApplicationServer => &[("app-http", 18082, "http")],
        DeceptionProfile::DatabaseHost => &[("postgres-shadow", 18432, "postgres")],
        DeceptionProfile::KubernetesNode => &[("kube-api-shadow", 18443, "https")],
        DeceptionProfile::BastionHost => &[("ssh-shadow", 18022, "ssh")],
        DeceptionProfile::SecretsService => &[("vault-shadow", 18200, "http")],
        DeceptionProfile::InternalApi => &[("internal-api-shadow", 18083, "http")],
    };

    specs
        .iter()
        .map(|(name, port, protocol)| DeceptionService {
            name: (*name).to_string(),
            bind_host: "127.0.0.1".to_string(),
            port: *port,
            protocol: (*protocol).to_string(),
        })
        .collect()
}

fn materialize_profile(
    root: &Path,
    profile: DeceptionProfile,
    services: &[DeceptionService],
) -> Result<(), DeceptionError> {
    let manifest = serde_json::json!({
        "environment": "production",
        "profile": profile.id(),
        "synthetic": true,
        "services": services,
    });
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    match profile {
        DeceptionProfile::DeveloperWorkstation => {
            write_file(root, "home/.env", "API_URL=http://internal-api.shadow\nDEPLOY_ENV=production\n")?;
            write_file(root, "home/.ssh/config", "Host bastion-prod\n  HostName bastion.shadow.internal\n  User deploy\n")?;
        }
        DeceptionProfile::CiRunner => {
            write_file(root, "ci/build.env", "REGISTRY=registry.shadow.internal\nDEPLOY_TARGET=production\n")?;
        }
        DeceptionProfile::ApplicationServer => {
            write_file(root, "app/runtime.env", "DATABASE_HOST=db.shadow.internal\nSECRETS_URL=http://vault.shadow.internal\n")?;
        }
        DeceptionProfile::DatabaseHost => {
            write_file(root, "database/replication.env", "PRIMARY=db-primary.shadow.internal\nREPLICA_USER=replicator\n")?;
        }
        DeceptionProfile::KubernetesNode => {
            write_file(root, "kubernetes/admin.conf", "apiVersion: v1\nclusters:\n- cluster:\n    server: https://kube-api.shadow.internal:6443\n  name: production\n")?;
        }
        DeceptionProfile::BastionHost => {
            write_file(root, "ssh/bastion.conf", "Host app-prod\n  HostName app.shadow.internal\n  User deploy\n")?;
        }
        DeceptionProfile::SecretsService => {
            write_file(root, "secrets/bootstrap.env", "VAULT_ADDR=http://vault.shadow.internal\nTOKEN_PATH=/run/secrets/bootstrap.token\n")?;
        }
        DeceptionProfile::InternalApi => {
            write_file(root, "api/config.json", "{\"upstream\":\"http://app.shadow.internal\",\"environment\":\"production\"}\n")?;
        }
    }

    Ok(())
}

fn write_file(root: &Path, relative: &str, value: &str) -> Result<(), std::io::Error> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, value)
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
    use crate::evolve::{EventSource, SecurityEvent, SecurityEventType};

    fn trace_with_command(command: &str) -> BehaviorTrace {
        let mut profiler = crate::evolve::BehaviorProfiler::new();
        let event = SecurityEvent::new(EventSource::Process, SecurityEventType::ProcessExec)
            .with_session_id("session-a")
            .with_command(command);
        profiler.observe(&event);
        profiler.trace("session-a").unwrap().clone()
    }

    #[test]
    fn profile_selection_tracks_behavior_context() {
        let trace = trace_with_command("kubectl get pods");
        assert_eq!(
            DeceptionProfile::select(&trace),
            DeceptionProfile::KubernetesNode
        );
    }

    #[test]
    fn prepared_services_are_loopback_only() {
        let trace = trace_with_command("whoami");
        let mut fabric = DeceptionFabric::new();
        let instance = fabric.prepare("session-a", &trace).unwrap();

        assert!(instance.validated);
        assert!(instance
            .planned_services
            .iter()
            .all(|service| service.bind_host == "127.0.0.1"));
        fabric.destroy("session-a").unwrap();
    }

    #[test]
    fn unsafe_session_id_is_rejected() {
        let trace = trace_with_command("whoami");
        let mut fabric = DeceptionFabric::new();
        assert!(matches!(
            fabric.prepare("../escape", &trace),
            Err(DeceptionError::InvalidSessionId)
        ));
    }
}

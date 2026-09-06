use super::{BehaviorTag, BehaviorTrace, ShadowAttackPath, ShadowNodeState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DECEPTION_ROOT: &str = "/var/lib/.sa-runtime/surfaces";
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
            let command = event
                .command
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let resource = event
                .resource
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();

            if command.contains("kubectl") || resource.contains(".kube") {
                return Self::KubernetesNode;
            }
            if command.contains("ssh ") || resource.contains(".ssh") {
                return Self::BastionHost;
            }
            if command.contains("psql")
                || command.contains("mysql")
                || resource.contains("database")
            {
                return Self::DatabaseHost;
            }
            if resource.contains(".github") || resource.contains("gitlab") || command.contains("ci")
            {
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
    pub hostname: String,
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
    #[error("failed to construct Shadow Attack Path: {0}")]
    AttackPath(String),
}

pub struct DeceptionFabric {
    instances: HashMap<String, DeceptionInstance>,
    base_root: PathBuf,
}

impl Default for DeceptionFabric {
    fn default() -> Self {
        Self {
            instances: HashMap::new(),
            base_root: PathBuf::from(DECEPTION_ROOT),
        }
    }
}

impl DeceptionFabric {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn with_root(base_root: impl Into<PathBuf>) -> Self {
        Self {
            instances: HashMap::new(),
            base_root: base_root.into(),
        }
    }

    pub fn prepare(
        &mut self,
        session_id: &str,
        trace: &BehaviorTrace,
    ) -> Result<DeceptionInstance, DeceptionError> {
        let profile = DeceptionProfile::select(trace);
        let path = ShadowAttackPath::build(session_id, profile)
            .map_err(|error| DeceptionError::AttackPath(error.to_string()))?;
        self.prepare_with_path(session_id, trace, &path)
    }

    pub fn prepare_with_path(
        &mut self,
        session_id: &str,
        trace: &BehaviorTrace,
        path: &ShadowAttackPath,
    ) -> Result<DeceptionInstance, DeceptionError> {
        if !is_safe_session_id(session_id) {
            return Err(DeceptionError::InvalidSessionId);
        }

        let profile = DeceptionProfile::select(trace);
        let root = self.base_root.join(session_id);
        validate_root(&root, &self.base_root)?;
        fs::create_dir_all(&root)?;
        restrict_staging_root(&self.base_root)?;
        make_session_directory_writable(&root)?;

        for node in path.nodes.values() {
            let service = DeceptionService {
                name: node.service_name.clone(),
                hostname: node.hostname.clone(),
                bind_host: "127.0.0.1".to_string(),
                port: node.port,
                protocol: node.protocol.clone(),
            };
            validate_service(&service)?;
        }

        let visible_services: Vec<DeceptionService> = path
            .visible_nodes()
            .into_iter()
            .map(|node| DeceptionService {
                name: node.service_name,
                hostname: node.hostname,
                bind_host: "127.0.0.1".to_string(),
                port: node.port,
                protocol: node.protocol,
            })
            .collect();

        materialize_profile(&root, profile, &visible_services)?;
        sync_path_projection(&root, path)?;
        let instance = DeceptionInstance {
            instance_id: format!("decoy-{session_id}-{}", now_ms()),
            session_id: session_id.to_string(),
            profile,
            root,
            planned_services: visible_services,
            created_at_ms: now_ms(),
            validated: true,
        };
        self.instances
            .insert(session_id.to_string(), instance.clone());
        Ok(instance)
    }

    pub fn sync_attack_path(
        &mut self,
        session_id: &str,
        path: &ShadowAttackPath,
    ) -> Result<(), DeceptionError> {
        let instance = self
            .instances
            .get_mut(session_id)
            .ok_or_else(|| DeceptionError::MissingBehaviorTrace(session_id.to_string()))?;
        sync_path_projection(&instance.root, path)?;
        instance.planned_services = path
            .visible_nodes()
            .into_iter()
            .map(|node| DeceptionService {
                name: node.service_name,
                hostname: node.hostname,
                bind_host: "127.0.0.1".to_string(),
                port: node.port,
                protocol: node.protocol,
            })
            .collect();
        Ok(())
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

fn validate_root(root: &Path, base_root: &Path) -> Result<(), DeceptionError> {
    if root.starts_with(base_root) {
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

fn materialize_profile(
    root: &Path,
    profile: DeceptionProfile,
    services: &[DeceptionService],
) -> Result<(), DeceptionError> {
    let service = services
        .first()
        .ok_or_else(|| DeceptionError::UnsafeService("missing".to_string(), 0))?;

    materialize_synthetic_etc(root, services)?;

    let visible_services: Vec<_> = services
        .iter()
        .map(|service| {
            serde_json::json!({
                "name": service.name,
                "host": service.hostname,
                "port": service.port,
                "protocol": service.protocol,
            })
        })
        .collect();
    let manifest = serde_json::json!({
        "environment": "production",
        "region": "eu-central-1",
        "services": visible_services,
    });
    let manifest_path = root.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    make_session_file_writable(&manifest_path)?;

    match profile {
        DeceptionProfile::DeveloperWorkstation => {
            write_file(
                root,
                "home/.env",
                &format!(
                    "API_URL=http://{}:{}\nDEPLOY_ENV=production\n",
                    service.hostname, service.port
                ),
            )?;
            write_file(
                root,
                "home/.ssh/config",
                "Host bastion-prod\n  HostName bastion.prod.internal\n  User deploy\n",
            )?;
        }
        DeceptionProfile::CiRunner => {
            write_file(
                root,
                "ci/build.env",
                &format!(
                    "ARTIFACT_API=http://{}:{}\nDEPLOY_TARGET=production\n",
                    service.hostname, service.port
                ),
            )?;
        }
        DeceptionProfile::ApplicationServer => {
            write_file(
                root,
                "app/runtime.env",
                &format!(
                    "HEALTH_API=http://{}:{}\nDATABASE_HOST=db-prod.internal\nSECRETS_URL=http://vault.prod.internal\n",
                    service.hostname, service.port
                ),
            )?;
        }
        DeceptionProfile::DatabaseHost => {
            write_file(
                root,
                "database/replication.env",
                &format!(
                    "PRIMARY={}:{}\nREPLICA_USER=replicator\n",
                    service.hostname, service.port
                ),
            )?;
        }
        DeceptionProfile::KubernetesNode => {
            write_file(
                root,
                "kubernetes/admin.conf",
                &format!(
                    "apiVersion: v1\nclusters:\n- cluster:\n    server: http://{}:{}\n  name: production\n",
                    service.hostname, service.port
                ),
            )?;
        }
        DeceptionProfile::BastionHost => {
            write_file(
                root,
                "ssh/bastion.conf",
                &format!(
                    "Host bastion-prod\n  HostName {}\n  Port {}\n  User deploy\n",
                    service.hostname, service.port
                ),
            )?;
        }
        DeceptionProfile::SecretsService => {
            write_file(
                root,
                "secrets/bootstrap.env",
                &format!(
                    "VAULT_ADDR=http://{}:{}\nTOKEN_PATH=/run/secrets/bootstrap.token\n",
                    service.hostname, service.port
                ),
            )?;
        }
        DeceptionProfile::InternalApi => {
            write_file(
                root,
                "api/config.json",
                &format!(
                    "{{\"endpoint\":\"http://{}:{}\",\"environment\":\"production\"}}\n",
                    service.hostname, service.port
                ),
            )?;
        }
    }

    Ok(())
}

fn write_file(root: &Path, relative: &str, value: &str) -> Result<(), std::io::Error> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, value)?;
    make_session_file_writable(&path)
}

fn sync_path_projection(root: &Path, path: &ShadowAttackPath) -> Result<(), DeceptionError> {
    let visible_nodes = path.visible_nodes();

    let mut hosts = String::from("127.0.0.1 localhost\n::1 localhost\n");
    let inventory: Vec<_> = visible_nodes
        .iter()
        .map(|node| {
            hosts.push_str(&format!("127.0.0.1 {}\n", node.hostname));
            serde_json::json!({
                "name": node.service_name,
                "host": node.hostname,
                "port": node.port,
                "protocol": node.protocol,
                "status": match node.state {
                    ShadowNodeState::Visited => "active",
                    ShadowNodeState::Exposed => "available",
                    ShadowNodeState::Hidden => "offline",
                }
            })
        })
        .collect();

    write_file(root, "etc/hosts", &hosts)?;
    write_file(
        root,
        "ops/service-map.json",
        &serde_json::to_string_pretty(&serde_json::json!({
            "environment": path.narrative.environment,
            "region": path.narrative.region,
            "services": inventory,
        }))?,
    )?;

    let active = path
        .nodes
        .get(&path.active_node_id)
        .map(|node| node.hostname.clone())
        .unwrap_or_else(|| path.narrative.hostname.clone());
    write_file(root, "ops/current-node", &format!("{}\n", active))?;

    // Update manifest.json with ONLY visible services to prevent hidden topology leakage
    let manifest_services: Vec<_> = visible_nodes
        .iter()
        .map(|node| {
            serde_json::json!({
                "name": node.service_name,
                "host": node.hostname,
                "port": node.port,
                "protocol": node.protocol,
            })
        })
        .collect();
    let manifest = serde_json::json!({
        "environment": "production",
        "region": "eu-central-1",
        "services": manifest_services,
    });
    let manifest_path = root.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    make_session_file_writable(&manifest_path)?;

    Ok(())
}

fn materialize_synthetic_etc(
    root: &Path,
    services: &[DeceptionService],
) -> Result<(), std::io::Error> {
    let mut hosts = String::from("127.0.0.1 localhost\n::1 localhost\n");
    for service in services {
        hosts.push_str(&format!("127.0.0.1 {}\n", service.hostname));
    }

    write_file(root, "etc/hosts", &hosts)?;
    write_file(root, "etc/hostname", "prod-app-01\n")?;
    write_file(
        root,
        "etc/nsswitch.conf",
        "hosts: files\npasswd: files\ngroup: files\n",
    )?;
    write_file(
        root,
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\ndeploy:x:65533:65533:Deployment:/workspace/home:/bin/bash\n",
    )?;
    write_file(root, "etc/group", "root:x:0:\ndeploy:x:65533:\n")?;
    Ok(())
}

fn restrict_staging_root(_path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn make_session_directory_writable(_path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o777))?;
    }
    Ok(())
}

fn make_session_file_writable(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        make_session_directory_writable(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    }
    Ok(())
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
    use tempfile::TempDir;

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
        let temp = TempDir::new().unwrap();
        let mut fabric = DeceptionFabric::with_root(temp.path().join("deception"));
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
        let temp = TempDir::new().unwrap();
        let mut fabric = DeceptionFabric::with_root(temp.path().join("deception"));
        assert!(matches!(
            fabric.prepare("../escape", &trace),
            Err(DeceptionError::InvalidSessionId)
        ));
    }
}

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(all(target_os = "linux", not(test)))]
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
#[cfg(all(target_os = "linux", not(test)))]
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
#[cfg(all(target_os = "linux", not(test)))]
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::info;
#[cfg(all(target_os = "linux", not(test)))]
use tracing::warn;

use crate::panic::KillSwitch;

#[derive(Error, Debug)]
pub enum FeedbackError {
    #[error("I/O error in Evolve feedback runtime: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to serialize Evolve feedback state: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Evolve feedback state mutex is poisoned")]
    StatePoisoned,
    #[error("Deception activation requires an already isolated runtime")]
    IsolationRequired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackPhase {
    Idle,
    Armed,
    IsolatedObserving,
    Adapted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEvent {
    pub id: u64,
    pub timestamp_ms: u64,
    pub source: String,
    pub category: String,
    pub technique: String,
    pub evidence: String,
    pub severity: u8,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackStatus {
    pub phase: FeedbackPhase,
    pub generation: u64,
    pub trigger_count: u64,
    pub observation_count: u64,
    pub patterns: BTreeMap<String, u64>,
    pub recommendations: Vec<String>,
    pub decoy_root: Option<String>,
    pub event_log: Option<String>,
}

#[derive(Debug, Clone)]
struct FeedbackState {
    phase: FeedbackPhase,
    generation: u64,
    trigger_count: u64,
    observation_count: u64,
    patterns: BTreeMap<String, u64>,
    recommendations: Vec<String>,
    decoy_root: Option<PathBuf>,
    event_log: Option<PathBuf>,
    profile_path: Option<PathBuf>,
    next_event_id: u64,
    watcher_started: bool,
}

impl Default for FeedbackState {
    fn default() -> Self {
        Self {
            phase: FeedbackPhase::Idle,
            generation: 0,
            trigger_count: 0,
            observation_count: 0,
            patterns: BTreeMap::new(),
            recommendations: Vec::new(),
            decoy_root: None,
            event_log: None,
            profile_path: None,
            next_event_id: 1,
            watcher_started: false,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedProfile {
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    trigger_count: u64,
    #[serde(default)]
    observation_count: u64,
    #[serde(default)]
    patterns: BTreeMap<String, u64>,
    #[serde(default)]
    recommendations: Vec<String>,
}

#[derive(Clone, Default)]
pub struct FeedbackMemory {
    inner: Arc<Mutex<FeedbackState>>,
}

impl FeedbackMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn arm(&self, base_dir: &Path) -> Result<FeedbackStatus, FeedbackError> {
        let metadata_root = base_dir.join(".evolve");
        let decoy_root = base_dir.join(".deployment").join("prod");
        fs::create_dir_all(&metadata_root)?;

        let event_log = metadata_root.join("events.jsonl");
        let profile_path = metadata_root.join("profile.json");
        let persisted = if profile_path.exists() {
            let raw = fs::read_to_string(&profile_path)?;
            serde_json::from_str::<PersistedProfile>(&raw).unwrap_or_default()
        } else {
            PersistedProfile::default()
        };

        {
            let mut state = self
                .inner
                .lock()
                .map_err(|_| FeedbackError::StatePoisoned)?;
            state.phase = FeedbackPhase::Armed;
            state.generation = persisted.generation;
            state.trigger_count = persisted.trigger_count;
            state.observation_count = persisted.observation_count;
            state.patterns = persisted.patterns;
            state.recommendations = persisted.recommendations;
            state.decoy_root = Some(decoy_root);
            state.event_log = Some(event_log);
            state.profile_path = Some(profile_path);
            state.next_event_id = state.observation_count.saturating_add(1);
        }

        self.persist_profile()?;
        info!("Evolve persistent feedback memory armed.");
        self.status()
    }

    pub fn status(&self) -> Result<FeedbackStatus, FeedbackError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| FeedbackError::StatePoisoned)?;
        Ok(FeedbackStatus {
            phase: state.phase,
            generation: state.generation,
            trigger_count: state.trigger_count,
            observation_count: state.observation_count,
            patterns: state.patterns.clone(),
            recommendations: state.recommendations.clone(),
            decoy_root: state
                .decoy_root
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            event_log: state
                .event_log
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
        })
    }

    pub fn observe(
        &self,
        category: impl Into<String>,
        technique: impl Into<String>,
        evidence: impl Into<String>,
        severity: u8,
        path: Option<String>,
    ) -> Result<FeedbackEvent, FeedbackError> {
        self.record_observation(
            "agent",
            category.into(),
            technique.into(),
            evidence.into(),
            severity,
            path,
        )
    }

    pub fn activate_after_isolation(
        &self,
        trap_type: &str,
        path: &Path,
    ) -> Result<FeedbackEvent, FeedbackError> {
        if !KillSwitch::is_isolated() {
            return Err(FeedbackError::IsolationRequired);
        }

        let decoy_root = {
            let mut state = self
                .inner
                .lock()
                .map_err(|_| FeedbackError::StatePoisoned)?;
            if matches!(state.phase, FeedbackPhase::Idle) {
                return Err(FeedbackError::IsolationRequired);
            }
            if !matches!(
                state.phase,
                FeedbackPhase::IsolatedObserving | FeedbackPhase::Adapted
            ) {
                state.phase = FeedbackPhase::IsolatedObserving;
                state.trigger_count = state.trigger_count.saturating_add(1);
                state.generation = state.generation.saturating_add(1);
            }
            state.decoy_root.clone()
        };

        if let Some(root) = decoy_root {
            self.materialize_decoy_surface(&root)?;
            let should_start = {
                let mut state = self
                    .inner
                    .lock()
                    .map_err(|_| FeedbackError::StatePoisoned)?;
                if state.watcher_started {
                    false
                } else {
                    state.watcher_started = true;
                    true
                }
            };
            if should_start {
                self.spawn_decoy_watcher(root);
            }
        }

        let (category, technique) = classify_canary(trap_type);
        let event = self.record_observation(
            "canary",
            category,
            technique,
            format!("Primary honeytoken touched: {}", path.display()),
            5,
            Some(path.to_string_lossy().into_owned()),
        )?;
        self.persist_profile()?;
        Ok(event)
    }

    fn record_observation(
        &self,
        source: impl Into<String>,
        category: impl Into<String>,
        technique: impl Into<String>,
        evidence: impl Into<String>,
        severity: u8,
        path: Option<String>,
    ) -> Result<FeedbackEvent, FeedbackError> {
        let source = source.into();
        let category = normalize_label(category.into());
        let technique = normalize_label(technique.into());
        let evidence = evidence.into();
        let severity = severity.clamp(1, 5);

        let (event, event_log) = {
            let mut state = self
                .inner
                .lock()
                .map_err(|_| FeedbackError::StatePoisoned)?;
            let key = format!("{}:{}", category, technique);
            let is_new = !state.patterns.contains_key(&key);
            *state.patterns.entry(key).or_insert(0) += 1;
            state.observation_count = state.observation_count.saturating_add(1);
            if is_new {
                state.generation = state.generation.saturating_add(1);
            }
            state.recommendations = build_recommendations(&state.patterns);
            if !matches!(state.phase, FeedbackPhase::Idle | FeedbackPhase::Armed) {
                state.phase = FeedbackPhase::Adapted;
            }

            let event = FeedbackEvent {
                id: state.next_event_id,
                timestamp_ms: unix_timestamp_ms(),
                source,
                category,
                technique,
                evidence,
                severity,
                path,
            };
            state.next_event_id = state.next_event_id.saturating_add(1);
            (event, state.event_log.clone())
        };

        if let Some(log_path) = event_log {
            append_json_line(&log_path, &event)?;
        }
        self.persist_profile()?;
        Ok(event)
    }

    fn persist_profile(&self) -> Result<(), FeedbackError> {
        let (profile_path, profile) = {
            let state = self
                .inner
                .lock()
                .map_err(|_| FeedbackError::StatePoisoned)?;
            let Some(path) = state.profile_path.clone() else {
                return Ok(());
            };
            (
                path,
                PersistedProfile {
                    generation: state.generation,
                    trigger_count: state.trigger_count,
                    observation_count: state.observation_count,
                    patterns: state.patterns.clone(),
                    recommendations: state.recommendations.clone(),
                },
            )
        };

        let tmp = profile_path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&profile)?)?;
        fs::rename(tmp, profile_path)?;
        Ok(())
    }

    fn materialize_decoy_surface(&self, root: &Path) -> Result<(), FeedbackError> {
        let db = root.join("database");
        let kube = root.join("kubernetes");
        let ssh = root.join("ssh");
        let notes = root.join("notes");
        fs::create_dir_all(&db)?;
        fs::create_dir_all(&kube)?;
        fs::create_dir_all(&ssh)?;
        fs::create_dir_all(&notes)?;

        write_if_missing(
            &root.join("manifest.json"),
            r#"{
  "environment": "production",
  "region": "eu-central",
  "database_config": ".deployment/prod/database/runtime.env",
  "kubernetes_admin": ".deployment/prod/kubernetes/admin.conf",
  "bastion_identity": ".deployment/prod/ssh/bastion_ed25519",
  "rotation_notes": ".deployment/prod/notes/rotation.txt"
}
"#,
        )?;
        write_if_missing(&db.join("runtime.env"), "DATABASE_HOST=db-prod.internal\nDATABASE_PORT=5432\nDATABASE_NAME=platform\nDATABASE_USER=svc_runtime\nDATABASE_PASSWORD=R7fQ9xN4vP2mL8cT6kW3\nREPLICA_HOST=db-replica.internal\n")?;
        write_if_missing(&kube.join("admin.conf"), "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://control-plane.internal:6443\n  name: production\ncontexts:\n- context:\n    cluster: production\n    user: deploy-admin\n  name: production\ncurrent-context: production\nusers:\n- name: deploy-admin\n  user:\n    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.evolve-decoy.invalid\n")?;
        write_if_missing(&ssh.join("bastion_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\nZXZvbHZlLWRlY295LWtleS10aGlzLWlzLW5vdC1hLXJlYWwta2V5LWFuZC1jYW5ub3Qt\nYXV0aGVudGljYXRlLWFueXdoZXJl\n-----END OPENSSH PRIVATE KEY-----\n")?;
        write_if_missing(&notes.join("rotation.txt"), "Production rotation notes\n- Deployment manifest is kept one directory above this file.\n- Legacy service credentials are retained for rollback testing.\n- Bastion identity is referenced by the deployment job.\n")?;
        Ok(())
    }

    #[cfg(all(target_os = "linux", not(test)))]
    fn spawn_decoy_watcher(&self, root: PathBuf) {
        let memory = self.clone();
        thread::spawn(move || {
            let root_arg = root.to_string_lossy().into_owned();
            let child = Command::new("inotifywait")
                .args([
                    "-m",
                    "-r",
                    "-q",
                    "-e",
                    "open,access,modify,attrib,delete,move",
                    "--format",
                    "%e|%w%f",
                    &root_arg,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();

            let Ok(mut child) = child else {
                warn!("inotifywait is unavailable; Evolve decoy telemetry is disabled.");
                return;
            };
            let Some(stdout) = child.stdout.take() else {
                warn!("inotifywait started without stdout; Evolve watcher stopped.");
                return;
            };

            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Some((mask, path)) = line.split_once('|') else {
                    continue;
                };
                if let Err(error) = memory.record_observation(
                    "deception",
                    "discovery",
                    "decoy_surface_interaction",
                    format!("Filesystem event {} on {}", mask, path),
                    5,
                    Some(path.to_string()),
                ) {
                    warn!("Failed to process Evolve decoy event: {}", error);
                }
            }
        });
    }

    #[cfg(any(not(target_os = "linux"), test))]
    fn spawn_decoy_watcher(&self, _root: PathBuf) {}
}

fn classify_canary(trap_type: &str) -> (&'static str, &'static str) {
    match trap_type {
        "aws_credentials" | "gcp_credentials" => {
            ("credential_access", "cloud_credentials_discovery")
        }
        "ssh_private_key" => ("credential_access", "ssh_key_discovery"),
        "kube_config" => ("cloud_control_plane", "kubernetes_config_discovery"),
        "env_secrets" => ("credential_access", "secret_file_discovery"),
        _ => ("discovery", "unknown_honeytoken_interaction"),
    }
}

fn build_recommendations(patterns: &BTreeMap<String, u64>) -> Vec<String> {
    let mut actions = BTreeSet::new();
    for key in patterns.keys() {
        if key.starts_with("credential_access:") {
            actions.insert("Increase secret-access telemetry and validate rotation/revocation paths for exposed credentials.".to_string());
            actions.insert(
                "Reduce long-lived credentials and prefer workload identity or short-lived tokens."
                    .to_string(),
            );
        }
        if key.starts_with("cloud_control_plane:") {
            actions.insert(
                "Tighten Kubernetes/cloud RBAC and alert on privileged configuration discovery."
                    .to_string(),
            );
        }
        if key.starts_with("discovery:") {
            actions.insert("Increase filesystem/service discovery telemetry around high-value deployment artifacts.".to_string());
        }
        if key.contains("ssh") {
            actions.insert(
                "Review SSH trust boundaries, bastion segmentation, and key-use telemetry."
                    .to_string(),
            );
        }
        if key.contains("decoy_surface_interaction") {
            actions.insert("Preserve the decoy path for the next generation and expand nearby inert artifacts.".to_string());
        }
    }
    if actions.is_empty() {
        actions.insert(
            "Continue collecting validated behavior before changing the defensive profile."
                .to_string(),
        );
    }
    actions.into_iter().collect()
}

fn normalize_label(value: String) -> String {
    let mut out = String::with_capacity(value.len().min(96));
    for ch in value.chars().take(96) {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_whitespace() || ch == ':' || ch == '/' {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed
    }
}

fn write_if_missing(path: &Path, content: &str) -> Result<(), std::io::Error> {
    if !path.exists() {
        fs::write(path, content)?;
    }
    Ok(())
}

fn append_json_line(path: &Path, event: &FeedbackEvent) -> Result<(), FeedbackError> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, event)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn deeper_decoy_is_containment_first() {
        KillSwitch::reset_isolation();
        let temp = TempDir::new().unwrap();
        let memory = FeedbackMemory::new();
        memory.arm(temp.path()).unwrap();
        assert!(!temp.path().join(".deployment/prod/manifest.json").exists());
        assert!(matches!(
            memory.activate_after_isolation("env_secrets", &temp.path().join(".env.decoy")),
            Err(FeedbackError::IsolationRequired)
        ));
        KillSwitch::trigger("feedback unit test").unwrap();
        memory
            .activate_after_isolation("env_secrets", &temp.path().join(".env.decoy"))
            .unwrap();
        assert!(temp.path().join(".deployment/prod/manifest.json").exists());
        KillSwitch::reset_isolation();
    }
}

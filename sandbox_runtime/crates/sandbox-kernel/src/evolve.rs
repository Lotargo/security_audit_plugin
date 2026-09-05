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
pub enum EvolveError {
    #[error("I/O error in Evolve runtime: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to serialize Evolve state: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Evolve state mutex is poisoned")]
    StatePoisoned,
    #[error("Emergency isolation failed while activating deception: {0}")]
    IsolationFailed(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvolvePhase {
    Idle,
    Armed,
    IsolatedObserving,
    Adapted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolveEvent {
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
pub struct EvolveStatus {
    pub phase: EvolvePhase,
    pub generation: u64,
    pub trigger_count: u64,
    pub observation_count: u64,
    pub patterns: BTreeMap<String, u64>,
    pub recommendations: Vec<String>,
    pub decoy_root: Option<String>,
    pub event_log: Option<String>,
}

#[derive(Debug, Clone)]
struct EvolveState {
    phase: EvolvePhase,
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

impl Default for EvolveState {
    fn default() -> Self {
        Self {
            phase: EvolvePhase::Idle,
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
pub struct EvolveManager {
    inner: Arc<Mutex<EvolveState>>,
}

impl EvolveManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arms the adaptive deception layer.
    ///
    /// Persistent behavior memory lives under `.evolve/`; the attacker-facing filesystem
    /// surface lives under `.deployment/prod/`. The latter contains only inert, fake material.
    /// No decoy credential is backed by a real account or service.
    pub fn arm(&self, base_dir: &Path) -> Result<EvolveStatus, EvolveError> {
        let metadata_root = base_dir.join(".evolve");
        let decoy_root = base_dir.join(".deployment").join("prod");
        fs::create_dir_all(&metadata_root)?;
        fs::create_dir_all(&decoy_root)?;

        let event_log = metadata_root.join("events.jsonl");
        let profile_path = metadata_root.join("profile.json");

        let persisted = if profile_path.exists() {
            let raw = fs::read_to_string(&profile_path)?;
            serde_json::from_str::<PersistedProfile>(&raw).unwrap_or_default()
        } else {
            PersistedProfile::default()
        };

        self.materialize_decoy_surface(&decoy_root)?;

        let should_start_watcher = {
            let mut state = self.inner.lock().map_err(|_| EvolveError::StatePoisoned)?;
            state.phase = EvolvePhase::Armed;
            state.generation = persisted.generation;
            state.trigger_count = persisted.trigger_count;
            state.observation_count = persisted.observation_count;
            state.patterns = persisted.patterns;
            state.recommendations = persisted.recommendations;
            state.decoy_root = Some(decoy_root.clone());
            state.event_log = Some(event_log);
            state.profile_path = Some(profile_path);
            state.next_event_id = state.observation_count.saturating_add(1);
            let should_start = !state.watcher_started;
            state.watcher_started = true;
            should_start
        };

        self.persist_profile()?;
        if should_start_watcher {
            self.spawn_decoy_watcher(decoy_root);
        }
        info!("Evolve adaptive deception layer armed.");
        self.status()
    }

    pub fn status(&self) -> Result<EvolveStatus, EvolveError> {
        let state = self.inner.lock().map_err(|_| EvolveError::StatePoisoned)?;
        Ok(EvolveStatus {
            phase: state.phase.clone(),
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

    /// Called by the canary subsystem when a primary honeytoken is touched.
    ///
    /// The first action is always containment. Only after the network is severed does the
    /// runtime switch into local deception/observation mode.
    pub fn activate_from_canary(
        &self,
        trap_type: &str,
        path: &Path,
    ) -> Result<EvolveEvent, EvolveError> {
        self.ensure_isolated(&format!(
            "Evolve canary trigger: {} ({})",
            trap_type,
            path.display()
        ))?;

        let (category, technique) = classify_canary(trap_type);
        self.record_observation(
            "canary",
            category,
            technique,
            format!("Primary honeytoken touched: {}", path.display()),
            5,
            Some(path.to_string_lossy().into_owned()),
        )
    }

    /// Records a validated defensive observation and updates the deterministic behavior memory.
    /// This is intentionally explainable rather than an opaque online-learning model.
    pub fn observe(
        &self,
        category: impl Into<String>,
        technique: impl Into<String>,
        evidence: impl Into<String>,
        severity: u8,
        path: Option<String>,
    ) -> Result<EvolveEvent, EvolveError> {
        self.record_observation(
            "agent",
            category.into(),
            technique.into(),
            evidence.into(),
            severity,
            path,
        )
    }

    fn ensure_isolated(&self, reason: &str) -> Result<(), EvolveError> {
        let should_trigger = {
            let mut state = self.inner.lock().map_err(|_| EvolveError::StatePoisoned)?;
            match state.phase {
                EvolvePhase::Idle | EvolvePhase::Armed => {
                    state.phase = EvolvePhase::IsolatedObserving;
                    state.trigger_count = state.trigger_count.saturating_add(1);
                    state.generation = state.generation.saturating_add(1);
                    true
                }
                EvolvePhase::IsolatedObserving | EvolvePhase::Adapted => false,
            }
        };

        if should_trigger && !KillSwitch::is_isolated() {
            KillSwitch::trigger(reason)
                .map_err(|e| EvolveError::IsolationFailed(e.to_string()))?;
        }

        self.persist_profile()?;
        Ok(())
    }

    fn record_observation(
        &self,
        source: impl Into<String>,
        category: impl Into<String>,
        technique: impl Into<String>,
        evidence: impl Into<String>,
        severity: u8,
        path: Option<String>,
    ) -> Result<EvolveEvent, EvolveError> {
        let source = source.into();
        let category = normalize_label(category.into());
        let technique = normalize_label(technique.into());
        let evidence = evidence.into();
        let severity = severity.clamp(1, 5);

        let (event, event_log) = {
            let mut state = self.inner.lock().map_err(|_| EvolveError::StatePoisoned)?;
            let pattern_key = format!("{}:{}", category, technique);
            let is_new_pattern = !state.patterns.contains_key(&pattern_key);
            *state.patterns.entry(pattern_key).or_insert(0) += 1;
            state.observation_count = state.observation_count.saturating_add(1);
            if is_new_pattern {
                state.generation = state.generation.saturating_add(1);
            }
            state.recommendations = build_recommendations(&state.patterns);
            if !matches!(state.phase, EvolvePhase::Idle | EvolvePhase::Armed) {
                state.phase = EvolvePhase::Adapted;
            }

            let event = EvolveEvent {
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

    fn persist_profile(&self) -> Result<(), EvolveError> {
        let (profile_path, profile) = {
            let state = self.inner.lock().map_err(|_| EvolveError::StatePoisoned)?;
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

        let tmp_path = profile_path.with_extension("json.tmp");
        fs::write(&tmp_path, serde_json::to_vec_pretty(&profile)?)?;
        fs::rename(tmp_path, profile_path)?;
        Ok(())
    }

    fn materialize_decoy_surface(&self, root: &Path) -> Result<(), EvolveError> {
        let database_dir = root.join("database");
        let kube_dir = root.join("kubernetes");
        let ssh_dir = root.join("ssh");
        let notes_dir = root.join("notes");
        fs::create_dir_all(&database_dir)?;
        fs::create_dir_all(&kube_dir)?;
        fs::create_dir_all(&ssh_dir)?;
        fs::create_dir_all(&notes_dir)?;

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

        write_if_missing(
            &database_dir.join("runtime.env"),
            r#"DATABASE_HOST=db-prod.internal
DATABASE_PORT=5432
DATABASE_NAME=platform
DATABASE_USER=svc_runtime
DATABASE_PASSWORD=R7fQ9xN4vP2mL8cT6kW3
REPLICA_HOST=db-replica.internal
"#,
        )?;

        write_if_missing(
            &kube_dir.join("admin.conf"),
            r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://control-plane.internal:6443
  name: production
contexts:
- context:
    cluster: production
    user: deploy-admin
  name: production
current-context: production
users:
- name: deploy-admin
  user:
    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.evolve-decoy.invalid
"#,
        )?;

        write_if_missing(
            &ssh_dir.join("bastion_ed25519"),
            r#"-----BEGIN OPENSSH PRIVATE KEY-----
ZXZvbHZlLWRlY295LWtleS10aGlzLWlzLW5vdC1hLXJlYWwta2V5LWFuZC1jYW5ub3Qt
YXV0aGVudGljYXRlLWFueXdoZXJl
-----END OPENSSH PRIVATE KEY-----
"#,
        )?;

        write_if_missing(
            &notes_dir.join("rotation.txt"),
            r#"Production rotation notes
- Deployment manifest is kept one directory above this file.
- Legacy service credentials are retained for rollback testing.
- Bastion identity is referenced by the deployment job.
"#,
        )?;

        Ok(())
    }

    #[cfg(all(target_os = "linux", not(test)))]
    fn spawn_decoy_watcher(&self, decoy_root: PathBuf) {
        let manager = self.clone();
        thread::spawn(move || {
            let root_arg = decoy_root.to_string_lossy().into_owned();
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
                warn!("inotifywait is unavailable; Evolve decoy access telemetry is disabled.");
                return;
            };

            let Some(stdout) = child.stdout.take() else {
                warn!("inotifywait started without stdout; Evolve watcher stopped.");
                return;
            };

            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                let Some((event_mask, path)) = line.split_once('|') else {
                    continue;
                };

                if let Err(err) = manager.handle_decoy_touch(event_mask, path) {
                    warn!("Failed to process Evolve decoy event: {}", err);
                }
            }
        });
    }

    #[cfg(any(not(target_os = "linux"), test))]
    fn spawn_decoy_watcher(&self, _decoy_root: PathBuf) {}

    fn handle_decoy_touch(&self, event_mask: &str, path: &str) -> Result<(), EvolveError> {
        self.ensure_isolated(&format!("Adaptive deception surface touched: {}", path))?;
        self.record_observation(
            "deception",
            "discovery",
            "decoy_surface_interaction",
            format!("Filesystem event {} on {}", event_mask, path),
            5,
            Some(path.to_string()),
        )?;
        Ok(())
    }
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
            actions.insert(
                "Increase secret-access telemetry and validate rotation/revocation paths for exposed credentials."
                    .to_string(),
            );
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
            actions.insert(
                "Increase filesystem/service discovery telemetry around high-value deployment artifacts."
                    .to_string(),
            );
        }
        if key.contains("ssh") {
            actions.insert(
                "Review SSH trust boundaries, bastion segmentation, and key-use telemetry."
                    .to_string(),
            );
        }
        if key.contains("decoy_surface_interaction") {
            actions.insert(
                "Preserve the decoy path for the next generation and expand nearby inert artifacts."
                    .to_string(),
            );
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

fn append_json_line(path: &Path, event: &EvolveEvent) -> Result<(), EvolveError> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, event)?;
    file.write_all(b"\n")?;
    file.flush()?;
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
    fn arm_materializes_decoys_and_persists_profile() {
        let tmp = TempDir::new().unwrap();
        let manager = EvolveManager::new();

        let status = manager.arm(tmp.path()).unwrap();
        assert_eq!(status.phase, EvolvePhase::Armed);
        assert!(tmp.path().join(".deployment/prod/manifest.json").exists());
        assert!(tmp.path().join(".evolve/profile.json").exists());
    }

    #[test]
    fn observations_create_explainable_adaptation_patterns() {
        let tmp = TempDir::new().unwrap();
        let manager = EvolveManager::new();
        manager.arm(tmp.path()).unwrap();

        let event = manager
            .observe(
                "credential_access",
                "ssh_key_discovery",
                "test observation",
                4,
                Some("/workspace/.ssh/id_rsa".to_string()),
            )
            .unwrap();

        assert_eq!(event.severity, 4);
        let status = manager.status().unwrap();
        assert_eq!(status.observation_count, 1);
        assert!(status
            .patterns
            .contains_key("credential_access:ssh_key_discovery"));
        assert!(status
            .recommendations
            .iter()
            .any(|r| r.contains("SSH trust boundaries")));
    }
}

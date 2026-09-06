use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::fs;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};

use crate::evolve::{EventSource, RiskLevel, SecurityEvent, SecurityEventType};
use crate::panic::KillSwitch;

#[derive(Error, Debug)]
pub enum CanaryError {
    #[error("Failed to plant canary honeytoken file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Canary watcher error: {0}")]
    WatcherError(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanaryTrap {
    pub file_path: PathBuf,
    pub trap_type: String,
    pub description: String,
}

#[derive(Debug, Clone)]
struct CanaryBaseline {
    path: PathBuf,
    trap_type: String,
    len: u64,
    accessed: Option<std::time::SystemTime>,
    modified: Option<std::time::SystemTime>,
}

pub struct CanaryManager {
    traps: Vec<CanaryTrap>,
    is_armed: Arc<AtomicBool>,
    triggered_count: Arc<AtomicUsize>,
    watch_generation: Arc<AtomicU64>,
    event_sender: Option<UnboundedSender<SecurityEvent>>,
}

impl Default for CanaryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CanaryManager {
    pub fn new() -> Self {
        Self {
            traps: Vec::new(),
            is_armed: Arc::new(AtomicBool::new(false)),
            triggered_count: Arc::new(AtomicUsize::new(0)),
            watch_generation: Arc::new(AtomicU64::new(0)),
            event_sender: None,
        }
    }

    /// Creates a canary manager whose trip events are delegated to the Evolve event pipeline.
    ///
    /// If the receiver disappears, canary handling fails closed and falls back to KillSwitch.
    pub fn with_event_sender(event_sender: UnboundedSender<SecurityEvent>) -> Self {
        Self {
            event_sender: Some(event_sender),
            ..Self::new()
        }
    }

    /// Plants deceptive honeytoken files into the target filesystem.
    pub async fn arm_canaries(&mut self, base_dir: &Path) -> Result<Vec<CanaryTrap>, CanaryError> {
        self.arm_canaries_for_session(base_dir, None).await
    }

    /// Plants canaries and associates future trigger events with a behavioral Evolve session.
    pub async fn arm_canaries_for_session(
        &mut self,
        base_dir: &Path,
        session_id: Option<String>,
    ) -> Result<Vec<CanaryTrap>, CanaryError> {
        let mut planted = Vec::new();

        // 1. AWS Credentials Honeypot
        let aws_dir = base_dir.join(".aws");
        fs::create_dir_all(&aws_dir).await?;
        let aws_creds = aws_dir.join("credentials");
        let aws_content = r#"[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
"#;
        fs::write(&aws_creds, aws_content).await?;
        planted.push(CanaryTrap {
            file_path: aws_creds,
            trap_type: "aws_credentials".to_string(),
            description: "Decoy AWS root credentials trap".to_string(),
        });

        // 2. SSH Private Key Honeypot
        let ssh_dir = base_dir.join(".ssh");
        fs::create_dir_all(&ssh_dir).await?;
        let ssh_key = ssh_dir.join("id_rsa");
        let ssh_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDDecoyHoneytokenKeyForAttackerDetectionOnly1234567890abcdef==
-----END OPENSSH PRIVATE KEY-----
"#;
        fs::write(&ssh_key, ssh_content).await?;
        planted.push(CanaryTrap {
            file_path: ssh_key,
            trap_type: "ssh_private_key".to_string(),
            description: "Decoy SSH RSA private key trap".to_string(),
        });

        // 3. Environment Decoy Honeypot
        let env_decoy = base_dir.join(".env.decoy");
        let env_content = r#"DATABASE_URL="postgres://admin:SuperSecretCanaryPass123@db.internal:5432/prod_db"
JWT_SECRET="decoy-canary-secret-token-audit-trap-999"
STRIPE_API_KEY="sk_live_51CanaryDecoyKeyDoNotUseExfiltrationTrap"
"#;
        fs::write(&env_decoy, env_content).await?;
        planted.push(CanaryTrap {
            file_path: env_decoy,
            trap_type: "env_secrets".to_string(),
            description: "Decoy production database and API credentials trap".to_string(),
        });

        // 4. Kubernetes Config Honeypot
        let kube_dir = base_dir.join(".kube");
        fs::create_dir_all(&kube_dir).await?;
        let kube_config = kube_dir.join("config");
        let kube_content = r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s-prod.internal.cluster:6443
    insecure-skip-tls-verify: true
  name: prod-k8s
contexts:
- context:
    cluster: prod-k8s
    user: admin-canary
  name: prod-cluster
current-context: prod-cluster
users:
- name: admin-canary
  user:
    token: canary-k8s-service-account-token-do-not-use-exfil
"#;
        fs::write(&kube_config, kube_content).await?;
        planted.push(CanaryTrap {
            file_path: kube_config,
            trap_type: "kube_config".to_string(),
            description: "Decoy Kubernetes cluster admin configuration trap".to_string(),
        });

        // 5. Google Cloud Service Account Honeypot
        let gcp_dir = base_dir.join(".gcp");
        fs::create_dir_all(&gcp_dir).await?;
        let gcp_creds = gcp_dir.join("credentials.json");
        let gcp_content = r#"{
  "type": "service_account",
  "project_id": "corp-security-audit-prod",
  "private_key_id": "canary9876543210abcdef",
  "client_email": "sa-canary-trap@corp-security-audit-prod.iam.gserviceaccount.com",
  "client_id": "123456789012345678901"
}
"#;
        fs::write(&gcp_creds, gcp_content).await?;
        planted.push(CanaryTrap {
            file_path: gcp_creds,
            trap_type: "gcp_credentials".to_string(),
            description: "Decoy GCP IAM service account credential trap".to_string(),
        });

        self.traps = planted.clone();
        self.is_armed.store(true, Ordering::SeqCst);
        let generation = self.watch_generation.fetch_add(1, Ordering::SeqCst) + 1;

        // Capture baseline metadata synchronously BEFORE returning from arm.
        // This eliminates the race condition where callers modify the canary immediately
        // after arming, causing an async watcher to capture the modified file as baseline.
        let mut initial_meta = Vec::with_capacity(planted.len());
        for trap in &planted {
            if let Ok(meta) = std::fs::metadata(&trap.file_path) {
                initial_meta.push(CanaryBaseline {
                    path: trap.file_path.clone(),
                    trap_type: trap.trap_type.clone(),
                    len: meta.len(),
                    accessed: meta.accessed().ok(),
                    modified: meta.modified().ok(),
                });
            }
        }

        self.spawn_watcher(initial_meta, session_id, generation);

        info!("Armed {} canary honeytoken tripwires.", planted.len());
        Ok(planted)
    }

    fn spawn_watcher(
        &self,
        initial_meta: Vec<CanaryBaseline>,
        session_id: Option<String>,
        generation: u64,
    ) {
        let is_armed = self.is_armed.clone();
        let triggered_count = self.triggered_count.clone();
        let watch_generation = self.watch_generation.clone();
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            info!("Canary metadata watcher loop started.");

            // Phase 8.1 keeps the existing metadata polling source and decouples its reaction.
            // EVENT_MODEL.md tracks the later migration to fanotify/inotify.
            while is_armed.load(Ordering::SeqCst)
                && watch_generation.load(Ordering::SeqCst) == generation
            {
                tokio::time::sleep(Duration::from_millis(500)).await;

                for baseline in &initial_meta {
                    if let Ok(meta) = std::fs::metadata(&baseline.path) {
                        let current_len = meta.len();
                        let current_accessed = meta.accessed().ok();
                        let current_modified = meta.modified().ok();

                        let len_changed = current_len != baseline.len;
                        let mtime_changed = match (baseline.modified, current_modified) {
                            (Some(orig), Some(curr)) => curr != orig,
                            _ => false,
                        };
                        let modified = len_changed || mtime_changed;
                        let accessed = match (baseline.accessed, current_accessed) {
                            (Some(orig), Some(curr)) => curr > orig,
                            _ => false,
                        };

                        if modified || accessed {
                            handle_canary_trigger(
                                event_sender.as_ref(),
                                triggered_count.as_ref(),
                                &baseline.path,
                                &baseline.trap_type,
                                session_id.as_deref(),
                            );
                            if watch_generation.load(Ordering::SeqCst) == generation {
                                is_armed.store(false, Ordering::SeqCst);
                            }
                            return;
                        }
                    }
                }
            }
        });
    }

    pub fn is_armed(&self) -> bool {
        self.is_armed.load(Ordering::SeqCst)
    }

    pub fn triggered_count(&self) -> usize {
        self.triggered_count.load(Ordering::SeqCst)
    }

    pub fn get_traps(&self) -> &[CanaryTrap] {
        &self.traps
    }

    pub fn watch_generation(&self) -> u64 {
        self.watch_generation.load(Ordering::SeqCst)
    }
}

fn handle_canary_trigger(
    event_sender: Option<&UnboundedSender<SecurityEvent>>,
    triggered_count: &AtomicUsize,
    path: &Path,
    trap_type: &str,
    session_id: Option<&str>,
) {
    triggered_count.fetch_add(1, Ordering::SeqCst);
    error!(
        "TRIPWIRE TRIGGERED! Unauthorized access or modification on canary: {:?}",
        path
    );

    let mut event = SecurityEvent::new(EventSource::Canary, SecurityEventType::CanaryAccess)
        .with_resource(path.to_string_lossy().into_owned())
        .with_risk_hint(RiskLevel::High)
        .with_metadata(serde_json::json!({
            "trap_type": trap_type,
            "legacy_reaction": "isolate"
        }));
    if let Some(session_id) = session_id {
        event = event.with_session_id(session_id.to_string());
    }

    if let Some(sender) = event_sender {
        if sender.send(event).is_ok() {
            return;
        }

        error!("Evolve event receiver unavailable; falling back to emergency isolation.");
    }

    // Compatibility/failure fallback. The daemon uses the event-driven path, but a standalone
    // CanaryManager without an Evolve receiver must preserve the old fail-closed behavior.
    let _ = KillSwitch::trigger(&format!("Canary trap triggered: {:?}", path));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_arm_canaries() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = CanaryManager::new();

        let traps = manager.arm_canaries(temp_dir.path()).await.unwrap();
        assert_eq!(traps.len(), 5);
        assert!(manager.is_armed());
        assert_eq!(manager.triggered_count(), 0);

        for trap in &traps {
            assert!(trap.file_path.exists());
        }
    }

    #[tokio::test]
    async fn rearm_advances_watcher_generation() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = CanaryManager::new();

        manager.arm_canaries(temp_dir.path()).await.unwrap();
        let first_generation = manager.watch_generation();
        manager.arm_canaries(temp_dir.path()).await.unwrap();
        let second_generation = manager.watch_generation();

        assert!(second_generation > first_generation);
    }

    #[tokio::test]
    async fn trigger_emits_evolve_event_when_receiver_exists() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let triggered_count = AtomicUsize::new(0);
        let path = Path::new("/workspace/.env.decoy");

        handle_canary_trigger(
            Some(&sender),
            &triggered_count,
            path,
            "env_secrets",
            Some("audit-session-1"),
        );

        let event = receiver.recv().await.expect("expected canary event");
        assert_eq!(triggered_count.load(Ordering::SeqCst), 1);
        assert_eq!(event.source, EventSource::Canary);
        assert_eq!(event.event_type, SecurityEventType::CanaryAccess);
        assert_eq!(event.resource.as_deref(), Some("/workspace/.env.decoy"));
        assert_eq!(event.session_id.as_deref(), Some("audit-session-1"));
        assert_eq!(event.risk_hint, Some(RiskLevel::High));
    }

    #[tokio::test]
    async fn immediate_modification_detected_without_race() {
        let temp_dir = TempDir::new().unwrap();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let mut manager = CanaryManager::with_event_sender(sender);

        let traps = manager
            .arm_canaries_for_session(temp_dir.path(), Some("session-test".to_string()))
            .await
            .unwrap();

        // Immediately touch/modify one of the traps without delay
        let env_decoy = traps.iter().find(|t| t.trap_type == "env_secrets").unwrap();
        tokio::fs::write(&env_decoy.file_path, "MODIFIED_IMMEDIATELY")
            .await
            .unwrap();

        // The watcher polls every 500ms, wait for it
        let event = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("timeout waiting for canary trigger")
            .expect("event stream closed");

        assert_eq!(event.event_type, SecurityEventType::CanaryAccess);
        assert_eq!(event.session_id.as_deref(), Some("session-test"));
        assert_eq!(manager.triggered_count(), 1);
    }

    #[tokio::test]
    async fn same_size_overwrite_detected_via_mtime() {
        let temp_dir = TempDir::new().unwrap();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let mut manager = CanaryManager::with_event_sender(sender);

        let traps = manager
            .arm_canaries_for_session(temp_dir.path(), Some("session-mtime".to_string()))
            .await
            .unwrap();

        let env_decoy = traps.iter().find(|t| t.trap_type == "env_secrets").unwrap();
        let orig_content = tokio::fs::read_to_string(&env_decoy.file_path)
            .await
            .unwrap();
        let mut altered_chars: Vec<char> = orig_content.chars().collect();
        // Change one character to keep identical length
        if let Some(first) = altered_chars.first_mut() {
            *first = if *first == 'X' { 'Y' } else { 'X' };
        }
        let altered: String = altered_chars.into_iter().collect();
        assert_eq!(altered.len(), orig_content.len());

        // Sleep briefly to ensure mtime timestamp tick differs
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::fs::write(&env_decoy.file_path, altered)
            .await
            .unwrap();

        let event = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("timeout waiting for same-size overwrite trigger")
            .expect("event stream closed");

        assert_eq!(event.event_type, SecurityEventType::CanaryAccess);
        assert_eq!(event.session_id.as_deref(), Some("session-mtime"));
    }
}

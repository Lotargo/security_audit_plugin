use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::fs;
use tracing::{error, info};

use crate::evolve::EvolveManager;
use crate::panic::KillSwitch;

#[derive(Error, Debug)]
pub enum CanaryError {
    #[error("Failed to plant canary honeytoken file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Canary watcher error: {0}")]
    WatcherError(String),
    #[error("Failed to arm adaptive deception layer: {0}")]
    EvolveError(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanaryTrap {
    pub file_path: PathBuf,
    pub trap_type: String,
    pub description: String,
}

pub struct CanaryManager {
    traps: Vec<CanaryTrap>,
    is_armed: Arc<AtomicBool>,
    triggered_count: Arc<AtomicUsize>,
    evolve: EvolveManager,
}

impl Default for CanaryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CanaryManager {
    pub fn new() -> Self {
        Self::with_evolve(EvolveManager::new())
    }

    pub fn with_evolve(evolve: EvolveManager) -> Self {
        Self {
            traps: Vec::new(),
            is_armed: Arc::new(AtomicBool::new(false)),
            triggered_count: Arc::new(AtomicUsize::new(0)),
            evolve,
        }
    }

    /// Plants primary honeytokens and arms the deeper Evolve deception surface.
    pub async fn arm_canaries(&mut self, base_dir: &Path) -> Result<Vec<CanaryTrap>, CanaryError> {
        self.evolve
            .arm(base_dir)
            .map_err(|e| CanaryError::EvolveError(e.to_string()))?;

        let mut planted = Vec::new();

        // 1. AWS credentials honeytoken. Values are inert and are not backed by any account.
        let aws_dir = base_dir.join(".aws");
        fs::create_dir_all(&aws_dir).await?;
        let aws_creds = aws_dir.join("credentials");
        let aws_content = r#"[default]
aws_access_key_id = AKIA7Q2M4N8P6R3T5V9X
aws_secret_access_key = m7Q2vN8pR5tK3xL9cD4sF6hJ1wB0eU7yZ2aM5nP8
region = eu-central-1
"#;
        fs::write(&aws_creds, aws_content).await?;
        planted.push(CanaryTrap {
            file_path: aws_creds,
            trap_type: "aws_credentials".to_string(),
            description: "Decoy AWS credentials trap".to_string(),
        });

        // 2. SSH private-key honeytoken. The material is deliberately non-functional.
        let ssh_dir = base_dir.join(".ssh");
        fs::create_dir_all(&ssh_dir).await?;
        let ssh_key = ssh_dir.join("id_rsa");
        let ssh_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
ZXZvbHZlLWRlY295LWtleS10aGlzLWlzLW5vdC1hLXJlYWwta2V5LWFuZC1jYW5ub3Qt
YXV0aGVudGljYXRlLWFueXdoZXJl
-----END OPENSSH PRIVATE KEY-----
"#;
        fs::write(&ssh_key, ssh_content).await?;
        planted.push(CanaryTrap {
            file_path: ssh_key,
            trap_type: "ssh_private_key".to_string(),
            description: "Decoy SSH private key trap".to_string(),
        });

        // 3. Environment honeytoken points toward the deeper inert deployment surface.
        let env_decoy = base_dir.join(".env.decoy");
        let env_content = r#"DATABASE_URL="postgres://svc_runtime:R7fQ9xN4vP2mL8cT6kW3@db-prod.internal:5432/platform"
JWT_SECRET="v3-prod-runtime-4f2c9e8b1d7a"
DEPLOYMENT_MANIFEST=".deployment/prod/manifest.json"
"#;
        fs::write(&env_decoy, env_content).await?;
        planted.push(CanaryTrap {
            file_path: env_decoy,
            trap_type: "env_secrets".to_string(),
            description: "Decoy production environment secrets trap".to_string(),
        });

        // 4. Kubernetes configuration honeytoken.
        let kube_dir = base_dir.join(".kube");
        fs::create_dir_all(&kube_dir).await?;
        let kube_config = kube_dir.join("config");
        let kube_content = r#"apiVersion: v1
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
    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.inert-runtime-token.invalid
"#;
        fs::write(&kube_config, kube_content).await?;
        planted.push(CanaryTrap {
            file_path: kube_config,
            trap_type: "kube_config".to_string(),
            description: "Decoy Kubernetes admin configuration trap".to_string(),
        });

        // 5. GCP service-account metadata honeytoken. No usable private key is present.
        let gcp_dir = base_dir.join(".gcp");
        fs::create_dir_all(&gcp_dir).await?;
        let gcp_creds = gcp_dir.join("credentials.json");
        let gcp_content = r#"{
  "type": "service_account",
  "project_id": "platform-prod-eu",
  "private_key_id": "8f3d7c1a52b94e60",
  "client_email": "runtime-deployer@platform-prod-eu.iam.gserviceaccount.com",
  "client_id": "109284736501928473650"
}
"#;
        fs::write(&gcp_creds, gcp_content).await?;
        planted.push(CanaryTrap {
            file_path: gcp_creds,
            trap_type: "gcp_credentials".to_string(),
            description: "Decoy GCP service-account metadata trap".to_string(),
        });

        self.traps = planted.clone();
        self.is_armed.store(true, Ordering::SeqCst);

        self.spawn_watcher(planted.clone());

        info!(
            "Armed {} primary honeytoken tripwires with Evolve deception.",
            planted.len()
        );
        Ok(planted)
    }

    fn spawn_watcher(&self, traps: Vec<CanaryTrap>) {
        let is_armed = self.is_armed.clone();
        let triggered_count = self.triggered_count.clone();
        let evolve = self.evolve.clone();

        tokio::spawn(async move {
            info!("Canary access watcher loop started.");

            let mut initial_meta: Vec<(CanaryTrap, u64, Option<std::time::SystemTime>)> = Vec::new();
            for trap in &traps {
                if let Ok(meta) = std::fs::metadata(&trap.file_path) {
                    initial_meta.push((trap.clone(), meta.len(), meta.accessed().ok()));
                }
            }

            while is_armed.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(500)).await;

                for (trap, orig_len, orig_accessed) in &initial_meta {
                    let path = &trap.file_path;
                    if let Ok(meta) = std::fs::metadata(path) {
                        let modified = meta.len() != *orig_len;
                        let accessed = match (orig_accessed, meta.accessed().ok()) {
                            (Some(orig), Some(curr)) => curr > *orig,
                            _ => false,
                        };

                        if modified || accessed {
                            triggered_count.fetch_add(1, Ordering::SeqCst);
                            error!(
                                "TRIPWIRE TRIGGERED! Unauthorized access or modification on canary: {:?}",
                                path
                            );

                            if let Err(err) = evolve.activate_from_canary(&trap.trap_type, path) {
                                error!(
                                    "Evolve activation failed after canary trigger: {}. Falling back to direct kill switch.",
                                    err
                                );
                                let _ = KillSwitch::trigger(&format!(
                                    "Canary trap triggered after Evolve failure: {:?}",
                                    path
                                ));
                            }

                            is_armed.store(false, Ordering::SeqCst);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_arm_canaries() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = CanaryManager::new();

        let traps = manager.arm_canaries(temp_dir.path()).await.unwrap();
        assert_eq!(traps.len(), 5);
        assert!(manager.is_armed());
        assert_eq!(manager.triggered_count(), 0);
        assert!(temp_dir
            .path()
            .join(".deployment/prod/manifest.json")
            .exists());

        for trap in &traps {
            assert!(trap.file_path.exists());
        }
    }
}

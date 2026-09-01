use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::fs;
use tracing::{error, info};

use crate::panic::KillSwitch;

#[derive(Error, Debug)]
pub enum CanaryError {
    #[error("Failed to plant canary honeytoken file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Canary watcher error: {0}")]
    WatcherError(String),
}

#[derive(Debug, Clone)]
pub struct CanaryTrap {
    pub file_path: PathBuf,
    pub trap_type: String,
    pub description: String,
}

pub struct CanaryManager {
    traps: Vec<CanaryTrap>,
    is_armed: Arc<AtomicBool>,
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
        }
    }

    /// Plants deceptive honeytoken files into the target filesystem
    pub async fn arm_canaries(&mut self, base_dir: &Path) -> Result<Vec<CanaryTrap>, CanaryError> {
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

        self.traps = planted.clone();
        self.is_armed.store(true, Ordering::SeqCst);

        // Spawn background file access monitor
        self.spawn_watcher(planted.clone());

        info!("Armed {} canary honeytoken tripwires.", planted.len());
        Ok(planted)
    }

    fn spawn_watcher(&self, traps: Vec<CanaryTrap>) {
        let is_armed = self.is_armed.clone();

        tokio::spawn(async move {
            info!("Canary inotify/access watcher loop started.");

            // Record initial metadata timestamps and size
            let mut initial_meta: Vec<(PathBuf, u64, Option<std::time::SystemTime>)> = Vec::new();
            for trap in &traps {
                if let Ok(meta) = std::fs::metadata(&trap.file_path) {
                    let len = meta.len();
                    let accessed = meta.accessed().ok();
                    initial_meta.push((trap.file_path.clone(), len, accessed));
                }
            }

            while is_armed.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(500)).await;

                for (path, orig_len, orig_accessed) in &initial_meta {
                    if let Ok(meta) = std::fs::metadata(path) {
                        let current_len = meta.len();
                        let current_accessed = meta.accessed().ok();

                        let modified = current_len != *orig_len;
                        let accessed = match (orig_accessed, current_accessed) {
                            (Some(orig), Some(curr)) => curr > *orig,
                            _ => false,
                        };

                        if modified || accessed {
                            error!("TRIPWIRE TRIGGERED! Unauthorized access or modification on canary: {:?}", path);
                            let _ =
                                KillSwitch::trigger(&format!("Canary trap triggered: {:?}", path));
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
        assert_eq!(traps.len(), 3);
        assert!(manager.is_armed());

        for trap in &traps {
            assert!(trap.file_path.exists());
        }
    }
}

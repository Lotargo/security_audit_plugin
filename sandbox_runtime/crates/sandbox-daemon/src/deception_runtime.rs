use sandbox_kernel::{
    deception_exec_identity, DeceptionInstance, DeceptionService,
};
use serde::Serialize;
use std::collections::HashMap;
use std::process::Stdio;
use thiserror::Error;
use tokio::process::{Child, Command};

const SAFE_CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SERVICE_BINARY: &str = "/usr/local/bin/deception-service";

#[derive(Error, Debug)]
pub enum DeceptionRuntimeError {
    #[error("deception instance is not validated")]
    UnvalidatedInstance,
    #[error("deception session is already running: {0}")]
    AlreadyRunning(String),
    #[error("failed to start deception service {0}: {1}")]
    SpawnFailed(String, std::io::Error),
    #[error("deception service exited during startup: {0}")]
    EarlyExit(String),
    #[error("failed to stop deception service: {0}")]
    StopFailed(std::io::Error),
}

#[derive(Debug, Clone, Serialize)]
pub struct RunningServiceStatus {
    pub name: String,
    pub bind_host: String,
    pub port: u16,
    pub protocol: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeceptionRuntimeStatus {
    pub session_id: String,
    pub services: Vec<RunningServiceStatus>,
}

struct RunningService {
    descriptor: DeceptionService,
    child: Child,
}

pub struct DeceptionRuntime {
    sessions: HashMap<String, Vec<RunningService>>,
}

impl Default for DeceptionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl DeceptionRuntime {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub async fn start_instance(
        &mut self,
        instance: &DeceptionInstance,
    ) -> Result<DeceptionRuntimeStatus, DeceptionRuntimeError> {
        if !instance.validated {
            return Err(DeceptionRuntimeError::UnvalidatedInstance);
        }
        if self.sessions.contains_key(&instance.session_id) {
            return Err(DeceptionRuntimeError::AlreadyRunning(
                instance.session_id.clone(),
            ));
        }

        let (uid, gid) = deception_exec_identity();
        let mut started = Vec::new();

        for service in &instance.planned_services {
            let mut command = Command::new("/usr/bin/setpriv");
            command
                .arg(format!("--reuid={uid}"))
                .arg(format!("--regid={gid}"))
                .arg("--clear-groups")
                .arg("--no-new-privs")
                .arg("--")
                .arg(SERVICE_BINARY)
                .arg("--bind")
                .arg(&service.bind_host)
                .arg("--port")
                .arg(service.port.to_string())
                .arg("--protocol")
                .arg(&service.protocol)
                .arg("--service")
                .arg(&service.name)
                .arg("--profile")
                .arg(instance.profile.id())
                .arg("--session")
                .arg(&instance.session_id)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .env_clear()
                .env("HOME", "/tmp")
                .env("PATH", SAFE_CHILD_PATH)
                .env("LANG", "C.UTF-8")
                .current_dir("/tmp");

            let child = command.spawn().map_err(|error| {
                DeceptionRuntimeError::SpawnFailed(service.name.clone(), error)
            })?;
            started.push(RunningService {
                descriptor: service.clone(),
                child,
            });
        }

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let failed_service = started.iter_mut().find_map(|running| {
            if running.child.try_wait().ok().flatten().is_some() {
                Some(running.descriptor.name.clone())
            } else {
                None
            }
        });

        if let Some(service_name) = failed_service {
            for running in &mut started {
                if running.child.try_wait().ok().flatten().is_none() {
                    let _ = running.child.kill().await;
                }
                let _ = running.child.wait().await;
            }
            return Err(DeceptionRuntimeError::EarlyExit(service_name));
        }

        self.sessions.insert(instance.session_id.clone(), started);
        Ok(self
            .status(&instance.session_id)
            .expect("session was inserted after successful startup"))
    }

    pub fn status(&self, session_id: &str) -> Option<DeceptionRuntimeStatus> {
        self.sessions.get(session_id).map(|services| DeceptionRuntimeStatus {
            session_id: session_id.to_string(),
            services: services
                .iter()
                .map(|running| RunningServiceStatus {
                    name: running.descriptor.name.clone(),
                    bind_host: running.descriptor.bind_host.clone(),
                    port: running.descriptor.port,
                    protocol: running.descriptor.protocol.clone(),
                    pid: running.child.id(),
                })
                .collect(),
        })
    }

    pub fn statuses(&self) -> Vec<DeceptionRuntimeStatus> {
        let mut statuses: Vec<_> = self
            .sessions
            .keys()
            .filter_map(|session_id| self.status(session_id))
            .collect();
        statuses.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        statuses
    }

    pub async fn destroy(
        &mut self,
        session_id: &str,
    ) -> Result<bool, DeceptionRuntimeError> {
        let Some(mut services) = self.sessions.remove(session_id) else {
            return Ok(false);
        };

        for running in &mut services {
            if running.child.try_wait().ok().flatten().is_none() {
                running
                    .child
                    .kill()
                    .await
                    .map_err(DeceptionRuntimeError::StopFailed)?;
            }
            running
                .child
                .wait()
                .await
                .map_err(DeceptionRuntimeError::StopFailed)?;
        }
        Ok(true)
    }
}

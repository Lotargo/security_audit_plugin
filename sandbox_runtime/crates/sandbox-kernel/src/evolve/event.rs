use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Canary,
    Filesystem,
    Process,
    Network,
    Browser,
    HttpProbe,
    Policy,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    FileOpen,
    FileRead,
    FileWrite,
    FileDelete,
    ProcessSpawn,
    ProcessExec,
    ProcessExit,
    NetworkConnect,
    NetworkListen,
    DnsAttempt,
    CredentialAccess,
    CanaryAccess,
    Discovery,
    PrivilegeAttempt,
    PersistenceAttempt,
    LateralMovementAttempt,
    BrowserNavigation,
    HttpRequest,
    PolicyViolation,
    EscapeAttempt,
    ControlPlaneAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub session_id: Option<String>,
    pub timestamp_ms: u64,
    pub source: EventSource,
    pub event_type: SecurityEventType,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub uid: Option<u32>,
    pub resource: Option<String>,
    pub destination: Option<String>,
    pub command: Option<String>,
    pub arguments: Vec<String>,
    pub result: Option<String>,
    pub risk_hint: Option<RiskLevel>,
    pub metadata: Value,
}

impl SecurityEvent {
    pub fn new(source: EventSource, event_type: SecurityEventType) -> Self {
        let timestamp_ms = now_ms();
        let sequence = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);

        Self {
            event_id: format!("evt-{timestamp_ms}-{sequence}"),
            session_id: None,
            timestamp_ms,
            source,
            event_type,
            process_id: None,
            parent_process_id: None,
            uid: None,
            resource: None,
            destination: None,
            command: None,
            arguments: Vec::new(),
            result: None,
            risk_hint: None,
            metadata: Value::Object(Default::default()),
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn with_risk_hint(mut self, risk: RiskLevel) -> Self {
        self.risk_hint = Some(risk);
        self
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_ids_are_unique() {
        let first = SecurityEvent::new(EventSource::System, SecurityEventType::PolicyViolation);
        let second = SecurityEvent::new(EventSource::System, SecurityEventType::PolicyViolation);
        assert_ne!(first.event_id, second.event_id);
    }

    #[test]
    fn risk_rank_is_monotonic() {
        assert!(RiskLevel::Critical.rank() > RiskLevel::High.rank());
        assert!(RiskLevel::High.rank() > RiskLevel::Medium.rank());
        assert!(RiskLevel::Medium.rank() > RiskLevel::Low.rank());
    }
}

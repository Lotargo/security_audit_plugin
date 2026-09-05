use super::{RiskLevel, SecurityEvent, SecurityEventType};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, VecDeque};

const DEFAULT_TRACE_EVENT_CAPACITY: usize = 256;
const DEFAULT_SESSION_ID: &str = "runtime-default";

fn default_trace_event_capacity() -> usize {
    DEFAULT_TRACE_EVENT_CAPACITY
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorTag {
    Execution,
    Discovery,
    CredentialInterest,
    NetworkActivity,
    BrowserActivity,
    PolicyBoundary,
    PrivilegeActivity,
    PersistenceActivity,
    LateralMovement,
    CanaryInteraction,
    EscapeActivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAssessment {
    pub risk_level: RiskLevel,
    pub tags: Vec<BehaviorTag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorTrace {
    pub session_id: String,
    pub started_at_ms: u64,
    pub last_event_at_ms: u64,
    pub risk_level: RiskLevel,
    pub tags: BTreeSet<BehaviorTag>,
    pub events: VecDeque<SecurityEvent>,
    #[serde(skip, default = "default_trace_event_capacity")]
    event_capacity: usize,
}

impl BehaviorTrace {
    fn new(session_id: impl Into<String>, first_timestamp_ms: u64, event_capacity: usize) -> Self {
        Self {
            session_id: session_id.into(),
            started_at_ms: first_timestamp_ms,
            last_event_at_ms: first_timestamp_ms,
            risk_level: RiskLevel::Low,
            tags: BTreeSet::new(),
            events: VecDeque::with_capacity(event_capacity),
            event_capacity,
        }
    }

    fn push_event(&mut self, event: SecurityEvent) {
        self.last_event_at_ms = event.timestamp_ms;
        if self.events.len() >= self.event_capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }
}

pub struct BehaviorProfiler {
    traces: HashMap<String, BehaviorTrace>,
    event_capacity: usize,
}

impl Default for BehaviorProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl BehaviorProfiler {
    pub fn new() -> Self {
        Self {
            traces: HashMap::new(),
            event_capacity: DEFAULT_TRACE_EVENT_CAPACITY,
        }
    }

    pub fn observe(&mut self, event: &SecurityEvent) -> BehaviorAssessment {
        let session_id = event
            .session_id
            .as_deref()
            .unwrap_or(DEFAULT_SESSION_ID)
            .to_string();
        let mut tags = classify_event(event);
        let base_risk = deterministic_event_risk(event);

        let event_capacity = self.event_capacity;
        let trace = self.traces.entry(session_id.clone()).or_insert_with(|| {
            BehaviorTrace::new(session_id, event.timestamp_ms, event_capacity)
        });

        let sequence_risk = sequence_risk(trace, event, &tags);
        let effective_risk = max_risk(base_risk, sequence_risk);

        for tag in &tags {
            trace.tags.insert(*tag);
        }
        if effective_risk.rank() > trace.risk_level.rank() {
            trace.risk_level = effective_risk;
        }

        let mut normalized_event = event.clone();
        normalized_event.risk_hint = Some(effective_risk);
        trace.push_event(normalized_event);

        tags.sort();
        tags.dedup();

        BehaviorAssessment {
            risk_level: effective_risk,
            tags,
        }
    }

    pub fn trace(&self, session_id: &str) -> Option<&BehaviorTrace> {
        self.traces.get(session_id)
    }

    pub fn trace_count(&self) -> usize {
        self.traces.len()
    }

    pub fn traces(&self) -> Vec<BehaviorTrace> {
        let mut traces: Vec<_> = self.traces.values().cloned().collect();
        traces.sort_by(|left, right| left.started_at_ms.cmp(&right.started_at_ms));
        traces
    }
}

fn max_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel {
    if left.rank() >= right.rank() {
        left
    } else {
        right
    }
}

fn deterministic_event_risk(event: &SecurityEvent) -> RiskLevel {
    let hinted = event.risk_hint.unwrap_or(RiskLevel::Low);
    let structural = match event.event_type {
        SecurityEventType::EscapeAttempt | SecurityEventType::ControlPlaneAccess => {
            RiskLevel::Critical
        }
        SecurityEventType::CanaryAccess
        | SecurityEventType::CredentialAccess
        | SecurityEventType::PrivilegeAttempt
        | SecurityEventType::PersistenceAttempt
        | SecurityEventType::LateralMovementAttempt => RiskLevel::High,
        SecurityEventType::PolicyViolation => RiskLevel::Medium,
        _ => RiskLevel::Low,
    };

    max_risk(hinted, structural)
}

fn classify_event(event: &SecurityEvent) -> Vec<BehaviorTag> {
    let mut tags = Vec::new();

    match event.event_type {
        SecurityEventType::ProcessSpawn
        | SecurityEventType::ProcessExec
        | SecurityEventType::ProcessExit => tags.push(BehaviorTag::Execution),
        SecurityEventType::Discovery => tags.push(BehaviorTag::Discovery),
        SecurityEventType::CredentialAccess => tags.push(BehaviorTag::CredentialInterest),
        SecurityEventType::NetworkConnect
        | SecurityEventType::NetworkListen
        | SecurityEventType::DnsAttempt
        | SecurityEventType::HttpRequest => tags.push(BehaviorTag::NetworkActivity),
        SecurityEventType::BrowserNavigation => tags.push(BehaviorTag::BrowserActivity),
        SecurityEventType::PolicyViolation => tags.push(BehaviorTag::PolicyBoundary),
        SecurityEventType::PrivilegeAttempt => tags.push(BehaviorTag::PrivilegeActivity),
        SecurityEventType::PersistenceAttempt => tags.push(BehaviorTag::PersistenceActivity),
        SecurityEventType::LateralMovementAttempt => tags.push(BehaviorTag::LateralMovement),
        SecurityEventType::CanaryAccess => {
            tags.push(BehaviorTag::CanaryInteraction);
            tags.push(BehaviorTag::CredentialInterest);
        }
        SecurityEventType::EscapeAttempt | SecurityEventType::ControlPlaneAccess => {
            tags.push(BehaviorTag::EscapeActivity);
        }
        _ => {}
    }

    if let Some(command) = event.command.as_deref() {
        classify_command(command, &mut tags);
    }

    tags
}

fn classify_command(command: &str, tags: &mut Vec<BehaviorTag>) {
    let normalized = command.trim().to_ascii_lowercase();
    let first = normalized.split_whitespace().next().unwrap_or_default();

    if matches!(
        first,
        "whoami"
            | "id"
            | "uname"
            | "hostname"
            | "ip"
            | "ifconfig"
            | "netstat"
            | "ss"
            | "ps"
            | "env"
            | "printenv"
            | "mount"
            | "df"
    ) {
        tags.push(BehaviorTag::Discovery);
    }

    if matches!(first, "curl" | "wget" | "nc" | "ncat" | "ssh") {
        tags.push(BehaviorTag::NetworkActivity);
    }

    if normalized.contains(".ssh/")
        || normalized.contains(".aws/credentials")
        || normalized.contains(".kube/config")
        || normalized.contains(".env")
    {
        tags.push(BehaviorTag::CredentialInterest);
    }
}

fn sequence_risk(
    trace: &BehaviorTrace,
    event: &SecurityEvent,
    current_tags: &[BehaviorTag],
) -> RiskLevel {
    if matches!(
        event.event_type,
        SecurityEventType::EscapeAttempt | SecurityEventType::ControlPlaneAccess
    ) {
        return RiskLevel::Critical;
    }

    let previous_tags = &trace.tags;
    let discovery_then_network = previous_tags.contains(&BehaviorTag::Discovery)
        && current_tags.contains(&BehaviorTag::NetworkActivity);
    let credential_then_network = previous_tags.contains(&BehaviorTag::CredentialInterest)
        && current_tags.contains(&BehaviorTag::NetworkActivity);
    let repeated_policy_boundary = previous_tags.contains(&BehaviorTag::PolicyBoundary)
        && current_tags.contains(&BehaviorTag::PolicyBoundary);

    if credential_then_network {
        return RiskLevel::High;
    }

    if discovery_then_network || repeated_policy_boundary {
        return RiskLevel::Medium;
    }

    RiskLevel::Low
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evolve::{EventSource, SecurityEventType};

    #[test]
    fn discovery_followed_by_network_activity_raises_medium_risk() {
        let mut profiler = BehaviorProfiler::new();

        let discovery =
            SecurityEvent::new(EventSource::Process, SecurityEventType::ProcessExec)
                .with_session_id("session-a")
                .with_command("whoami");
        let network =
            SecurityEvent::new(EventSource::Process, SecurityEventType::ProcessExec)
                .with_session_id("session-a")
                .with_command("curl https://example.com");

        assert_eq!(profiler.observe(&discovery).risk_level, RiskLevel::Low);
        assert_eq!(profiler.observe(&network).risk_level, RiskLevel::Medium);

        let trace = profiler.trace("session-a").expect("trace should exist");
        assert!(trace.tags.contains(&BehaviorTag::Discovery));
        assert!(trace.tags.contains(&BehaviorTag::NetworkActivity));
        assert_eq!(trace.events.len(), 2);
    }

    #[test]
    fn credential_interest_followed_by_network_activity_is_high_risk() {
        let mut profiler = BehaviorProfiler::new();

        let credential =
            SecurityEvent::new(EventSource::Process, SecurityEventType::ProcessExec)
                .with_session_id("session-a")
                .with_command("cat ~/.ssh/id_rsa");
        let network =
            SecurityEvent::new(EventSource::Process, SecurityEventType::ProcessExec)
                .with_session_id("session-a")
                .with_command("curl https://example.com");

        profiler.observe(&credential);
        assert_eq!(profiler.observe(&network).risk_level, RiskLevel::High);
    }

    #[test]
    fn control_plane_access_is_always_critical() {
        let mut profiler = BehaviorProfiler::new();
        let event =
            SecurityEvent::new(EventSource::Policy, SecurityEventType::ControlPlaneAccess)
                .with_session_id("session-a");

        assert_eq!(profiler.observe(&event).risk_level, RiskLevel::Critical);
    }

    #[test]
    fn trace_buffer_is_bounded() {
        let mut profiler = BehaviorProfiler::new();
        profiler.event_capacity = 2;

        for index in 0..3 {
            let event =
                SecurityEvent::new(EventSource::Process, SecurityEventType::ProcessExec)
                    .with_session_id("session-a")
                    .with_command(format!("echo {index}"));
            profiler.observe(&event);
        }

        assert_eq!(
            profiler
                .trace("session-a")
                .expect("trace should exist")
                .events
                .len(),
            2
        );
    }
}

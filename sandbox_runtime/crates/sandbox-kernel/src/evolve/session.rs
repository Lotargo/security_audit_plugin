use super::{EvolveState, RiskLevel, SecurityEvent};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolveSession {
    pub session_id: String,
    pub created_at_ms: u64,
    pub last_event_at_ms: u64,
    pub state: EvolveState,
    pub risk_level: RiskLevel,
    pub event_refs: Vec<String>,
    pub process_roots: Vec<u32>,
    pub active_deception_profile: Option<String>,
    pub shadow_path_id: Option<String>,
    pub attack_trace_id: Option<String>,
    pub real_surface_revoked: bool,
}

impl EvolveSession {
    pub fn new(session_id: impl Into<String>) -> Self {
        let now = now_ms();
        Self {
            session_id: session_id.into(),
            created_at_ms: now,
            last_event_at_ms: now,
            state: EvolveState::Observe,
            risk_level: RiskLevel::Low,
            event_refs: Vec::new(),
            process_roots: Vec::new(),
            active_deception_profile: None,
            shadow_path_id: None,
            attack_trace_id: None,
            real_surface_revoked: false,
        }
    }

    pub fn record_event(&mut self, event: &SecurityEvent) {
        self.last_event_at_ms = event.timestamp_ms;
        self.event_refs.push(event.event_id.clone());

        if let Some(pid) = event.process_id {
            if !self.process_roots.contains(&pid) {
                self.process_roots.push(pid);
            }
        }

        if let Some(risk) = event.risk_hint {
            if risk.rank() > self.risk_level.rank() {
                self.risk_level = risk;
            }
        }
    }
}

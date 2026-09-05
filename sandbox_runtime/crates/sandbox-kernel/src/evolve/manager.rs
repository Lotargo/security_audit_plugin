use super::{
    EvolveSession, EvolveState, RiskLevel, SecurityEvent, StateTransitionError,
};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

const DEFAULT_EVENT_CAPACITY: usize = 1024;
const DEFAULT_SESSION_ID: &str = "runtime-default";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolveDecision {
    LegacyIsolate,
    Observe,
    EnhancedTelemetry,
    Isolate,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvolveStatus {
    pub enabled: bool,
    pub state: EvolveState,
    pub events_buffered: usize,
    pub sessions: usize,
}

pub struct EvolveManager {
    enabled: bool,
    state: EvolveState,
    events: VecDeque<SecurityEvent>,
    sessions: HashMap<String, EvolveSession>,
    event_capacity: usize,
}

impl Default for EvolveManager {
    fn default() -> Self {
        Self::new()
    }
}

impl EvolveManager {
    pub fn new() -> Self {
        let mut sessions = HashMap::new();
        sessions.insert(
            DEFAULT_SESSION_ID.to_string(),
            EvolveSession::new(DEFAULT_SESSION_ID),
        );

        Self {
            enabled: false,
            state: EvolveState::Observe,
            events: VecDeque::with_capacity(DEFAULT_EVENT_CAPACITY),
            sessions,
            event_capacity: DEFAULT_EVENT_CAPACITY,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn state(&self) -> EvolveState {
        self.state
    }

    pub fn status(&self) -> EvolveStatus {
        EvolveStatus {
            enabled: self.enabled,
            state: self.state,
            events_buffered: self.events.len(),
            sessions: self.sessions.len(),
        }
    }

    pub fn recent_events(&self, limit: usize) -> Vec<SecurityEvent> {
        let limit = limit.min(self.events.len());
        self.events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    pub fn transition(&mut self, next: EvolveState) -> Result<(), StateTransitionError> {
        if !self.state.can_transition_to(next) {
            return Err(StateTransitionError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }

        self.state = next;
        Ok(())
    }

    pub fn mark_isolated(&mut self) {
        if self.state != EvolveState::Isolate {
            self.state = EvolveState::Isolate;
        }

        for session in self.sessions.values_mut() {
            session.state = EvolveState::Isolate;
        }
    }

    pub fn ingest_event(&mut self, mut event: SecurityEvent) -> EvolveDecision {
        let session_id = event
            .session_id
            .clone()
            .unwrap_or_else(|| DEFAULT_SESSION_ID.to_string());
        event.session_id = Some(session_id.clone());

        let session = self
            .sessions
            .entry(session_id.clone())
            .or_insert_with(|| EvolveSession::new(session_id));
        session.record_event(&event);

        let risk = event.risk_hint.unwrap_or(RiskLevel::Low);
        self.push_event(event);

        if !self.enabled {
            return EvolveDecision::LegacyIsolate;
        }

        match risk {
            RiskLevel::Low => EvolveDecision::Observe,
            RiskLevel::Medium => {
                self.enter_suspect_state();
                EvolveDecision::EnhancedTelemetry
            }
            RiskLevel::High | RiskLevel::Critical => {
                self.enter_suspect_state();

                // Phase 8.1 intentionally fails closed here. The event pipeline is active, but
                // Deception Fabric is not implemented yet, so high-risk behavior cannot safely be
                // redirected and must still escalate to existing isolation.
                EvolveDecision::Isolate
            }
        }
    }

    fn enter_suspect_state(&mut self) {
        if self.state == EvolveState::Observe {
            let _ = self.transition(EvolveState::Suspect);
        }

        if let Some(session) = self.sessions.get_mut(DEFAULT_SESSION_ID) {
            if session.state == EvolveState::Observe {
                session.state = EvolveState::Suspect;
            }
        }
    }

    fn push_event(&mut self, event: SecurityEvent) {
        if self.events.len() >= self.event_capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evolve::{EventSource, SecurityEventType};

    #[test]
    fn disabled_manager_preserves_legacy_isolation_decision() {
        let mut manager = EvolveManager::new();
        let event = SecurityEvent::new(EventSource::Canary, SecurityEventType::CanaryAccess)
            .with_risk_hint(RiskLevel::High);

        assert_eq!(
            manager.ingest_event(event),
            EvolveDecision::LegacyIsolate
        );
        assert_eq!(manager.recent_events(10).len(), 1);
    }

    #[test]
    fn enabled_medium_risk_enters_suspect_without_isolation() {
        let mut manager = EvolveManager::new();
        manager.set_enabled(true);

        let event = SecurityEvent::new(EventSource::Policy, SecurityEventType::PolicyViolation)
            .with_risk_hint(RiskLevel::Medium);

        assert_eq!(
            manager.ingest_event(event),
            EvolveDecision::EnhancedTelemetry
        );
        assert_eq!(manager.state(), EvolveState::Suspect);
    }

    #[test]
    fn enabled_high_risk_fails_closed_until_deception_exists() {
        let mut manager = EvolveManager::new();
        manager.set_enabled(true);

        let event = SecurityEvent::new(EventSource::Canary, SecurityEventType::CanaryAccess)
            .with_risk_hint(RiskLevel::High);

        assert_eq!(manager.ingest_event(event), EvolveDecision::Isolate);
        assert_eq!(manager.state(), EvolveState::Suspect);
    }

    #[test]
    fn event_buffer_is_bounded() {
        let mut manager = EvolveManager::new();
        manager.event_capacity = 2;

        for _ in 0..3 {
            manager.ingest_event(SecurityEvent::new(
                EventSource::System,
                SecurityEventType::PolicyViolation,
            ));
        }

        assert_eq!(manager.recent_events(10).len(), 2);
    }
}

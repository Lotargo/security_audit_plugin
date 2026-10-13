use sandbox_kernel::{EvolveManager, EvolveState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSurface {
    Real,
    Deception,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentSurfaceUnavailable;

pub fn resolve_agent_surface(
    manager: &EvolveManager,
    session_id: Option<&str>,
) -> Result<AgentSurface, AgentSurfaceUnavailable> {
    let session_state = session_id.and_then(|id| manager.session_state(id));

    // REAL XOR SHADOW: Once REAL has been revoked for a session during deception
    // engagement, REAL must NEVER become visible to that session again, even if
    // subsequent deception startup fails and the system drops to ISOLATE.
    if manager.is_real_surface_revoked(session_id) {
        return match manager.state() {
            EvolveState::Deceive => match session_state {
                Some(EvolveState::Deceive) => Ok(AgentSurface::Deception),
                _ => Err(AgentSurfaceUnavailable),
            },
            _ => Err(AgentSurfaceUnavailable),
        };
    }

    match manager.state() {
        EvolveState::Observe | EvolveState::Suspect => match session_state {
            Some(EvolveState::Deceive) => Ok(AgentSurface::Deception),
            Some(EvolveState::Engage)
            | Some(EvolveState::Learn)
            | Some(EvolveState::Adapt)
            | Some(EvolveState::Isolate) => Err(AgentSurfaceUnavailable),
            _ => Ok(AgentSurface::Real),
        },
        EvolveState::Deceive => match session_state {
            Some(EvolveState::Deceive) => Ok(AgentSurface::Deception),
            _ => Err(AgentSurfaceUnavailable),
        },
        EvolveState::Engage | EvolveState::Learn | EvolveState::Adapt => {
            Err(AgentSurfaceUnavailable)
        }
        // Terminal ISOLATE is network containment, not deception. Local forensics
        // commands must keep working so callers can verify fail-closed egress
        // (curl exits non-zero) via normal exec; the nftables kill-switch already
        // blocks the actual network path.
        //
        // ROADMAP п.4: global fail-closed latch. If ANY session has ever had REAL
        // revoked (deception engagement started), ISOLATE must deny REAL for ALL
        // sessions, including unknown/other session IDs. Only pure manual isolation
        // without any engagement keeps forensics Real.
        EvolveState::Isolate => {
            if manager.is_real_surface_revoked(None) {
                return Err(AgentSurfaceUnavailable);
            }
            Ok(AgentSurface::Real)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_kernel::{
        EventSource, EvolveDecision, RiskLevel, SecurityEvent, SecurityEventType,
    };

    #[test]
    fn ordinary_runtime_resolves_to_real_surface() {
        let manager = EvolveManager::new();
        assert_eq!(
            resolve_agent_surface(&manager, None),
            Ok(AgentSurface::Real)
        );
    }

    #[test]
    fn engagement_state_denies_new_agent_work() {
        let mut manager = EvolveManager::new();
        manager.set_enabled(true);
        let event = SecurityEvent::new(EventSource::Canary, SecurityEventType::CanaryAccess)
            .with_session_id("session-a")
            .with_risk_hint(RiskLevel::High);
        assert_eq!(manager.ingest_event(event), EvolveDecision::EngageDeception);
        manager.begin_deception_engagement("session-a").unwrap();

        assert!(resolve_agent_surface(&manager, Some("session-a")).is_err());
        assert!(resolve_agent_surface(&manager, None).is_err());
    }

    #[test]
    fn deceive_state_requires_the_bound_deceived_session() {
        let mut manager = EvolveManager::new();
        manager.set_enabled(true);
        let event = SecurityEvent::new(EventSource::Canary, SecurityEventType::CanaryAccess)
            .with_session_id("session-a")
            .with_risk_hint(RiskLevel::High);
        manager.ingest_event(event);
        manager.begin_deception_engagement("session-a").unwrap();
        manager.mark_deception_active("session-a").unwrap();

        assert_eq!(
            resolve_agent_surface(&manager, Some("session-a")),
            Ok(AgentSurface::Deception)
        );
        assert!(resolve_agent_surface(&manager, None).is_err());
        assert!(resolve_agent_surface(&manager, Some("wrong-session")).is_err());
    }

    #[test]
    fn failed_deception_engagement_dropping_to_isolate_denies_real_surface() {
        let mut manager = EvolveManager::new();
        manager.set_enabled(true);
        let event = SecurityEvent::new(EventSource::Canary, SecurityEventType::CanaryAccess)
            .with_session_id("session-a")
            .with_risk_hint(RiskLevel::High);
        manager.ingest_event(event);
        manager.begin_deception_engagement("session-a").unwrap();

        // Simulate bwrap / runtime failure: mark_isolated() is called
        manager.mark_isolated();
        assert_eq!(manager.state(), EvolveState::Isolate);

        // Invariant check: REAL must NOT be returned!
        assert!(resolve_agent_surface(&manager, Some("session-a")).is_err());
        assert!(resolve_agent_surface(&manager, None).is_err());
    }

    #[test]
    fn failed_engagement_denies_other_and_unknown_sessions_in_isolate() {
        let mut manager = EvolveManager::new();
        manager.set_enabled(true);
        let event = SecurityEvent::new(EventSource::Canary, SecurityEventType::CanaryAccess)
            .with_session_id("session-a")
            .with_risk_hint(RiskLevel::High);
        manager.ingest_event(event);
        manager.begin_deception_engagement("session-a").unwrap();
        manager.mark_isolated();

        // ROADMAP п.4: другой/неизвестный session ID не должен получить Real.
        assert!(resolve_agent_surface(&manager, Some("session-b")).is_err());
        assert!(resolve_agent_surface(&manager, Some("unknown-session-xyz")).is_err());
    }

    #[test]
    fn manual_isolation_without_deception_engagement_allows_real_forensics() {
        let mut manager = EvolveManager::new();
        manager.set_enabled(true);

        // Manual kill switch or emergency isolation without deception engagement
        manager.mark_isolated();
        assert_eq!(manager.state(), EvolveState::Isolate);

        assert_eq!(
            resolve_agent_surface(&manager, None),
            Ok(AgentSurface::Real)
        );
        assert_eq!(
            resolve_agent_surface(&manager, Some("session-forensics")),
            Ok(AgentSurface::Real)
        );
    }
}

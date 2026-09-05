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
        EvolveState::Engage
        | EvolveState::Learn
        | EvolveState::Adapt
        | EvolveState::Isolate => Err(AgentSurfaceUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_kernel::{EventSource, EvolveDecision, RiskLevel, SecurityEvent, SecurityEventType};

    #[test]
    fn ordinary_runtime_resolves_to_real_surface() {
        let manager = EvolveManager::new();
        assert_eq!(resolve_agent_surface(&manager, None), Ok(AgentSurface::Real));
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
}

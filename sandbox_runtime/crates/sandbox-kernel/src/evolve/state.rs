use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EvolveState {
    Observe,
    Suspect,
    Engage,
    Deceive,
    Learn,
    Adapt,
    Isolate,
}

impl Default for EvolveState {
    fn default() -> Self {
        Self::Observe
    }
}

impl EvolveState {
    pub fn can_transition_to(self, next: Self) -> bool {
        if next == Self::Isolate && self != Self::Isolate {
            return true;
        }

        matches!(
            (self, next),
            (Self::Observe, Self::Suspect)
                | (Self::Suspect, Self::Observe)
                | (Self::Suspect, Self::Engage)
                | (Self::Engage, Self::Suspect)
                | (Self::Engage, Self::Deceive)
                | (Self::Deceive, Self::Learn)
                | (Self::Learn, Self::Adapt)
                | (Self::Adapt, Self::Observe)
        )
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateTransitionError {
    #[error("invalid Evolve state transition: {from:?} -> {to:?}")]
    InvalidTransition { from: EvolveState, to: EvolveState },
    #[error("Evolve session not found: {0}")]
    MissingSession(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_pipeline_transitions_are_allowed() {
        assert!(EvolveState::Observe.can_transition_to(EvolveState::Suspect));
        assert!(EvolveState::Suspect.can_transition_to(EvolveState::Engage));
        assert!(EvolveState::Engage.can_transition_to(EvolveState::Deceive));
        assert!(EvolveState::Deceive.can_transition_to(EvolveState::Learn));
        assert!(EvolveState::Learn.can_transition_to(EvolveState::Adapt));
        assert!(EvolveState::Adapt.can_transition_to(EvolveState::Observe));
    }

    #[test]
    fn every_active_state_can_isolate() {
        for state in [
            EvolveState::Observe,
            EvolveState::Suspect,
            EvolveState::Engage,
            EvolveState::Deceive,
            EvolveState::Learn,
            EvolveState::Adapt,
        ] {
            assert!(state.can_transition_to(EvolveState::Isolate));
        }
    }

    #[test]
    fn unsafe_skip_is_rejected() {
        assert!(!EvolveState::Observe.can_transition_to(EvolveState::Deceive));
        assert!(!EvolveState::Observe.can_transition_to(EvolveState::Adapt));
        assert!(!EvolveState::Isolate.can_transition_to(EvolveState::Observe));
    }
}

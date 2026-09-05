use sandbox_kernel::SecurityEvent;
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;

#[derive(Clone)]
pub struct EvolveEventSink {
    sender: UnboundedSender<SecurityEvent>,
}

impl EvolveEventSink {
    pub fn new(sender: UnboundedSender<SecurityEvent>) -> Self {
        Self { sender }
    }

    pub fn sender(&self) -> UnboundedSender<SecurityEvent> {
        self.sender.clone()
    }

    /// Best-effort telemetry delivery.
    ///
    /// Security enforcement must never depend on this return value. Route-level RoE checks
    /// continue to deny locally, while canary has its own fail-closed fallback if the receiver
    /// disappears.
    pub fn emit(&self, event: SecurityEvent) -> bool {
        let event_id = event.event_id.clone();
        if self.sender.send(event).is_ok() {
            true
        } else {
            warn!(event_id = %event_id, "Evolve event receiver is unavailable");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_kernel::{EventSource, SecurityEventType};
    use tokio::sync::mpsc;

    #[test]
    fn sink_delivers_event_to_receiver() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let sink = EvolveEventSink::new(sender);
        let event =
            SecurityEvent::new(EventSource::Process, SecurityEventType::ProcessExec);

        assert!(sink.emit(event));
        assert!(receiver.try_recv().is_ok());
    }

    #[test]
    fn sink_reports_closed_receiver_without_panicking() {
        let (sender, receiver) = mpsc::unbounded_channel();
        drop(receiver);
        let sink = EvolveEventSink::new(sender);
        let event =
            SecurityEvent::new(EventSource::System, SecurityEventType::PolicyViolation);

        assert!(!sink.emit(event));
    }
}

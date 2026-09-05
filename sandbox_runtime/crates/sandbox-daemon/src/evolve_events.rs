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

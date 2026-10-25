//! Events pushed from the controller to the UI, without ever blocking the
//! controller.
//!
//! The controller calls its sink from inside its own tasks, and a sink that
//! waited for a slow UI would stall the tunnel. The queue therefore never
//! waits: telemetry, speedtest progress and log lines are dropped when it is
//! full, and any other event that finds no room raises a flag that ends the
//! session. A state change is never lost silently.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use orion_core::backend::EventSink;
use orion_core::events::ClientEvent;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Notify};

/// Events the queue holds before it drops or overflows.
pub const EVENT_QUEUE: usize = 1024;

/// Whether an event may be dropped when the queue is full.
pub fn is_droppable(event: &ClientEvent) -> bool {
    matches!(
        event,
        ClientEvent::Telemetry { .. } | ClientEvent::Log { .. } | ClientEvent::SpeedTest { .. }
    )
}

/// Sending side of the events of one session. Clones share the same queue.
#[derive(Clone)]
pub struct EventQueue {
    sender: mpsc::Sender<ClientEvent>,
    overflowed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl EventQueue {
    /// A queue, and the receiver that drains it.
    pub fn new() -> (Self, mpsc::Receiver<ClientEvent>) {
        let (sender, receiver) = mpsc::channel(EVENT_QUEUE);
        let queue = Self {
            sender,
            overflowed: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        };
        (queue, receiver)
    }

    /// The sink the controller pushes into. It never waits and never panics.
    pub fn sink(&self) -> EventSink {
        let queue = self.clone();
        Arc::new(move |event| queue.push(event))
    }

    /// Whether a critical event found no room: the session must end.
    pub fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
    }

    /// Completes when a critical event has found no room.
    pub async fn overflow(&self) {
        self.notify.notified().await;
    }

    fn push(&self, event: ClientEvent) {
        match self.sender.try_send(event) {
            // A receiver that is gone has no one left to inform.
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(event)) => {
                if is_droppable(&event) {
                    return;
                }
                self.overflowed.store(true, Ordering::Release);
                self.notify.notify_one();
            }
        }
    }
}

#[cfg(test)]
mod tests;

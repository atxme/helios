use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::NegotiationHandler;

#[derive(Clone, Copy)]
pub(crate) struct Deadline(pub(crate) Instant);

impl Deadline {
    pub(crate) fn starting_now() -> Self {
        Self(Instant::now() + crate::MAX_CONNECTION_LIFETIME)
    }

    pub(crate) fn clamp(self, phase: Duration) -> Duration {
        phase.min(self.remaining())
    }

    pub(crate) fn remaining(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }
}

pub(crate) struct RollbackGuard {
    handler: Arc<dyn NegotiationHandler>,
    transaction_id: [u8; 16],
    public_key: String,
    armed: bool,
}

impl RollbackGuard {
    pub(crate) fn arm(
        handler: Arc<dyn NegotiationHandler>,
        transaction_id: [u8; 16],
        public_key: String,
    ) -> Self {
        Self {
            handler,
            transaction_id,
            public_key,
            armed: true,
        }
    }

    pub(crate) async fn roll_back(&mut self) {
        if !self.armed {
            return;
        }
        self.handler
            .rollback(self.transaction_id, &self.public_key)
            .await;
        self.armed = false;
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RollbackGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        tracing::warn!(
            transaction = %hex::encode(self.transaction_id),
            peer = %self.public_key,
            "connection destroyed with a candidate PSK posed; rolling back out of band"
        );
        let handler = Arc::clone(&self.handler);
        let transaction_id = self.transaction_id;
        let public_key = std::mem::take(&mut self.public_key);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move { handler.rollback(transaction_id, &public_key).await });
        }
    }
}

//! Bounded local protocol between Orion and the Astra companion.
//!
//! The companion must use the interactive user's WebAuthn session, and the
//! authority vault stays on its side: Orion never opens it, and no inherited
//! standard handle carries anything between them. The companion connects back
//! to a loopback listener and authenticates the one short-lived session before
//! any command is accepted.

use serde::{Deserialize, Serialize};

/// Protocol version carried by the first frame.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum JSON frame accepted on the local channel.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// First frame sent by the companion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraIpcHello {
    pub protocol_version: u16,
    pub token: String,
}

/// The only actions Orion may ask of the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "command")]
pub enum AstraIpcCommand {
    Continue,
    Cancel,
}

/// Stable UI phases for one client CA-TLS rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AstraCaTlsPhase {
    Idle,
    Starting,
    AwaitingFirstKey,
    ProcessingFirstKey,
    AwaitingSecondKey,
    ProcessingSecondKey,
    Finalizing,
    Prepared,
    Deposited,
    AwaitingPromotionKey,
    Promoting,
    Promoted,
    Failed,
    Cancelled,
}

impl AstraCaTlsPhase {
    pub fn can_continue(self) -> bool {
        matches!(
            self,
            Self::AwaitingFirstKey
                | Self::AwaitingSecondKey
                | Self::Prepared
                | Self::AwaitingPromotionKey
        )
    }

    pub fn can_cancel(self) -> bool {
        matches!(self, Self::AwaitingFirstKey | Self::AwaitingSecondKey)
    }

    pub fn is_actionable_or_terminal(self) -> bool {
        self.can_continue()
            || matches!(
                self,
                Self::Deposited | Self::Promoted | Self::Failed | Self::Cancelled
            )
    }
}

/// Manifest Orion displays before either security key is touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCaTlsManifest {
    pub reason: String,
    pub requested_by: String,
    pub fingerprint: String,
    pub current_ca_tls_epoch: u64,
    pub next_ca_tls_epoch: u64,
    pub activation_at: u64,
    pub not_after: u64,
    pub outgoing_anchor_fingerprint: String,
    pub affected_ca: String,
    pub target_count: usize,
}

/// Complete observable state. It contains public metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCaTlsStatus {
    pub phase: AstraCaTlsPhase,
    pub message: String,
    pub can_continue: bool,
    pub can_cancel: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_key_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_key_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_ca_tls_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<AstraCaTlsManifest>,
}

impl AstraCaTlsStatus {
    pub fn new(phase: AstraCaTlsPhase, message: impl Into<String>) -> Self {
        Self {
            phase,
            message: message.into(),
            can_continue: phase.can_continue(),
            can_cancel: phase.can_cancel(),
            first_key_label: None,
            second_key_label: None,
            output_path: None,
            next_ca_tls_epoch: None,
            activation_at: None,
            not_after: None,
            manifest: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_precommit_waits_can_be_cancelled() {
        assert!(AstraCaTlsPhase::AwaitingFirstKey.can_cancel());
        assert!(AstraCaTlsPhase::AwaitingSecondKey.can_cancel());
        assert!(!AstraCaTlsPhase::Finalizing.can_cancel());
        assert!(!AstraCaTlsPhase::Prepared.can_cancel());
        assert!(!AstraCaTlsPhase::Deposited.can_cancel());
    }

    #[test]
    fn wire_commands_are_closed_and_explicit() {
        let command: AstraIpcCommand =
            serde_json::from_str(r#"{"command":"continue"}"#).expect("command");
        assert_eq!(command, AstraIpcCommand::Continue);
        assert!(serde_json::from_str::<AstraIpcCommand>(r#"{"command":"run","args":[]}"#).is_err());
    }
}

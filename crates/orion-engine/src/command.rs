//! Commands from the UI to the engine.
//!
//! The list below is the authorization policy: the UI can ask for nothing
//! outside it. There is no generic variant, no variant names an executable or
//! an output path, and a secret enters only through [`SecretInput`].

use std::fmt;

use aether::certificates::approval::AstraRenewalApproval;
use orion_core::certificate_approval::{ApprovalManifest, ApprovalMaterial};
use orion_core::enrollment::PendingEnrollment;
use orion_core::vault::VaultPosture;
use orion_core::{
    CertificateAction, CertificateActionState, CertificateInventory, KeyNegotiationSettings,
    ProfileIssues, SpeedTestResult,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::view::{
    AboutView, ActionOutcome, ConfigView, ImportOutcome, InvitationPreviewView,
    KeyNegotiationSupport, ProfileCertificates, RenewalProgress,
};

/// A secret on its way from the UI to the engine.
///
/// The only type through which a secret enters the engine. Its `Debug` output
/// is masked, and no reply carries a secret back.
pub struct SecretInput(Zeroizing<String>);

impl SecretInput {
    /// The secret itself: read it only where it is consumed.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for SecretInput {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInput(…)")
    }
}

/// Writes the secret in clear: only the UI serializes it, toward the engine.
impl Serialize for SecretInput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for SecretInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// What the Profiles screen sends back when the user saves or validates.
///
/// The secrets are **write-only and optional**: the interface never received
/// them, so it cannot send them back, and `None` therefore means *keep what is
/// stored*. That asymmetry is deliberate: it is what lets a profile be edited
/// without its private key ever making the round trip.
///
/// # Naming, and the bug it caused
///
/// The profile fields keep serde's **snake_case**, because that is what
/// `ClientProfile` and `KeyNegotiationSettings` use on the wire and what the
/// screen echoes back after receiving a profile view. A blanket
/// `rename_all = "camelCase"` here made every one of them a different name —
/// `save_profile` then refused the payload with `missing field peerPublicKey`,
/// and no test caught it: the TypeScript suite mocks the command, and the Rust
/// suite builds the struct directly. Neither crossed the boundary where the
/// names actually have to agree. `the_frontend_payload_deserialises` does.
///
/// Only the two **intents** are camelCase, because they exist nowhere else and
/// the screen writes them by hand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDraft {
    pub name: String,
    pub endpoint: String,
    pub peer_public_key: String,
    pub address: Option<String>,
    /// Absent from a payload means `None`, like every optional field here:
    /// the screen always sends it, and a save without it is a profile
    /// without IPv6.
    pub address_v6: Option<String>,
    pub allowed_ips: String,
    pub persistent_keepalive: u16,
    pub heliosd_url: Option<String>,
    pub ssh_target: Option<String>,
    pub key_negotiation: Option<KeyNegotiationSettings>,
    /// Adopts the key sitting in the engine's single staged-key slot.
    ///
    /// Set by the screen after `generate_private_key` or `adopt_private_key`
    /// has already produced one and shown its **public** half. The private half
    /// never travels back: it waited in the engine the whole time.
    #[serde(default, rename = "useStagedKey")]
    pub use_staged_key: bool,
    /// Clears the stored static PSK.
    #[serde(default, rename = "clearPresharedKey")]
    pub clear_preshared_key: bool,
    /// Adopts the PSK sitting in the engine's single staged-PSK slot.
    ///
    /// The enrolment document remains the ordinary way a static PSK arrives.
    /// It is not the only one: an operator who rotates a PSK out of band, or
    /// who runs a gateway pinned to `static_psk`, otherwise had to reissue a
    /// whole profile to change one value. The direction is what makes it
    /// acceptable: the secret enters once, on an explicit gesture, and no path
    /// returns it (ADR-006 §5), exactly as for [`Self::use_staged_key`].
    #[serde(default, rename = "useStagedPsk")]
    pub use_staged_psk: bool,
}

/// Commands the UI may send. Each variant is one entry of the partition's
/// « Moteur » column; the arguments keep the names of the Tauri commands they
/// replace.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum EngineCommand {
    GetState,
    BackendKind,
    AdapterIsUp,
    AboutOrion,
    KeyNegotiationSupport,
    RunSpeedTest {
        mode: String,
    },

    Connect {
        name: Option<String>,
    },
    Disconnect,
    RenewPsk,

    GetConfig,
    ImportProfile {
        contents: SecretInput,
        file_name: String,
    },
    VaultPosture,
    AllowUnencryptedVolume,
    GeneratePrivateKey,
    AdoptPrivateKey {
        private_key: SecretInput,
    },
    DiscardStagedKey,
    AdoptPresharedKey {
        preshared_key: SecretInput,
    },
    DiscardStagedPsk,
    SshCommand {
        name: Option<String>,
    },
    SaveProfile {
        draft: ProfileDraft,
    },
    DeleteProfile {
        name: String,
    },
    SelectProfile {
        name: String,
    },
    ValidateProfile {
        draft: ProfileDraft,
    },

    PreviewEnrollmentInvitation {
        contents: String,
    },
    BeginEnrollment {
        invitation: String,
        confirmed_ca_fingerprint: String,
        requested_name: String,
    },
    ListPendingEnrollments,
    ExportPendingRequest {
        request_id: String,
    },
    DiscardPendingEnrollment {
        request_id: String,
    },

    CertificateInventory {
        key_negotiation: Option<KeyNegotiationSettings>,
    },
    CertificateOverview,
    CertificateActions {
        key_negotiation: Option<KeyNegotiationSettings>,
    },
    RunCertificateAction {
        name: String,
        action: CertificateAction,
    },
    ResumeCertificateRecovery {
        operation_id: String,
    },
    CertificateApprovalManifest {
        name: String,
    },
    CertificateApprovalMaterial {
        name: String,
    },
    SubmitCertificateApproval {
        name: String,
        approval: Box<AstraRenewalApproval>,
    },
    LastCertificateError {
        name: String,
    },

    Shutdown,
}

/// What the engine answers. Each variant is the return type of one command
/// of the partition; the frame carries `Result<EngineReply, String>`, so no
/// variant stands for a failure.
///
/// No variant carries a secret: the views hold public keys and redacted
/// profiles only, and [`SecretInput`] has no path back out.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reply", content = "value", rename_all = "snake_case")]
pub enum EngineReply {
    Unit,
    State(String),
    Backend(String),
    Flag(bool),
    About(AboutView),
    KeyNegotiation(KeyNegotiationSupport),
    SpeedTest(SpeedTestResult),
    Config(ConfigView),
    Imported(ImportOutcome),
    VaultPosture(VaultPosture),
    PublicKey(String),
    SshCommand(String),
    Issues(ProfileIssues),
    InvitationPreview(InvitationPreviewView),
    EnrollmentStarted(String),
    PendingEnrollments(Vec<PendingEnrollment>),
    RequestFile(String),
    CertificateInventory(CertificateInventory),
    CertificateOverview(Vec<ProfileCertificates>),
    CertificateActions(Vec<CertificateActionState>),
    ActionOutcome(ActionOutcome),
    ApprovalManifest(ApprovalManifest),
    RenewalProgress(RenewalProgress),
    ApprovalMaterial(Box<ApprovalMaterial>),
    LastError(Option<String>),
}

#[cfg(test)]
mod tests;

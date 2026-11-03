//! The views the interface displays.
//!
//! They moved here from the Tauri shell so the engine can send them. The field
//! names and serde attributes are the wire format the screens read: a rename
//! here is a rename in the interface.

use std::collections::BTreeMap;

use orion_core::certificate_renewal::RenewalStep;
use orion_core::{ClientConfig, ClientProfile};
use serde::{Deserialize, Serialize};

/// What the About box states.
///
/// Four facts, and each one is there because a support exchange asked for it:
/// which version is installed, whether it drives a real adapter or the dry-run
/// backend, what a profile file looks like, and where the log is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AboutView {
    pub version: String,
    pub backend: String,
    /// Extension of an Orion profile, without the dot. Read from Rust rather
    /// than written in the interface: it is the same string the file
    /// association and the import filter use, and three copies of it would
    /// eventually disagree.
    pub profile_extension: String,
    pub log_path: Option<String>,
}

/// What this machine can do with the gateway's key-negotiation port.
///
/// The negotiation itself is no longer a build option — it is compiled into
/// every Orion, because a binary that looks normal and refuses every pinned
/// profile at connection time is indistinguishable, for the user, from a
/// broken gateway. What remains conditional is the **machine**: the protected
/// certificate store is supplied by the shell, and DPAPI exists only on
/// Windows. The screen says so instead of letting the user find out when the
/// connection fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyNegotiationSupport {
    pub identity_store: bool,
}

/// A profile **as the interface is allowed to see it** (ADR-006 §5).
///
/// # Why the WireGuard private key is not in here
///
/// It used to be. `get_config` cloned the whole `ClientProfile` across the
/// Tauri IPC, and the Profiles screen put it in a text field with a button to
/// reveal it. That single path defeated most of what the vault buys: the key
/// was serialised into a JSON message, parsed into a JavaScript `String` —
/// immutable, garbage-collected, impossible to wipe — held in a DOM node's
/// value for as long as the screen lived, and readable by anything that could
/// reach the WebView. Sealing a secret on disk and then handing it to a
/// browser engine is protecting the quiet half of its life.
///
/// ADR-006 §5 already forbids exactly this for the `nomade` passphrase — "ni le
/// DOM WebView2, ni JavaScript, ni un message Tauri sérialisé". The private key
/// is the secret that actually brings the tunnel up. The same rule applies, and
/// applies more.
///
/// What the screen genuinely needs is here: everything it displays or edits,
/// plus the **public** key it exists to show the operator, plus two booleans
/// saying whether the secrets are present. Nothing it needs requires the
/// secret itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileView {
    pub name: String,
    pub endpoint: String,
    pub peer_public_key: String,
    pub address: Option<String>,
    /// IPv6 VIP, `…/128`. `null` for every profile without one, which is
    /// what the screen shows as an IPv4-only tunnel.
    pub address_v6: Option<String>,
    pub allowed_ips: String,
    pub persistent_keepalive: u16,
    pub heliosd_url: Option<String>,
    pub ssh_target: Option<String>,
    pub key_negotiation: Option<orion_core::KeyNegotiationSettings>,
    /// Which of the two shapes of spec §19 this profile is.
    ///
    /// Resolved, never `null`: a profile sealed before the discriminant
    /// existed still has a kind, and the screen shows what the connection
    /// path will act on rather than what the file happens to record.
    pub profile_type: String,
    /// Public half of the profile's WireGuard key. The one value of the pair
    /// that is *meant* to leave the machine — it is what the operator admits.
    pub public_key: Option<String>,
    /// Whether a private key is stored. The screen shows a state, not a value.
    pub has_private_key: bool,
    /// Whether a **static** PSK is stored. A negotiated one is never at rest.
    pub has_static_psk: bool,
    /// The stored list captures all of IPv4 and lets IPv6 out.
    ///
    /// Decided by `orion-core`, not by the screen: the posture panel warns on
    /// it, and a rule re-derived in TypeScript is one more place for the two
    /// to disagree about which profiles leak. Reported only — the stored list
    /// is never widened on the user's behalf.
    pub ipv6_uncaptured_full_tunnel: bool,
}

impl From<&ClientProfile> for ProfileView {
    fn from(profile: &ClientProfile) -> Self {
        Self {
            name: profile.name.clone(),
            endpoint: profile.endpoint.clone(),
            peer_public_key: profile.peer_public_key.clone(),
            address: profile.address.clone(),
            address_v6: profile.address_v6.clone(),
            allowed_ips: profile.allowed_ips.clone(),
            persistent_keepalive: profile.persistent_keepalive,
            heliosd_url: profile.heliosd_url.clone(),
            ssh_target: profile.ssh_target.clone(),
            key_negotiation: profile.key_negotiation.clone(),
            profile_type: profile.kind().as_str().to_string(),
            public_key: profile.public_key(),
            has_private_key: !profile.private_key.is_empty(),
            has_static_psk: profile.has_static_psk(),
            ipv6_uncaptured_full_tunnel: profile.ipv6_uncaptured_full_tunnel(),
        }
    }
}

/// The configuration as the interface sees it: profiles, redacted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigView {
    pub profiles: Vec<ProfileView>,
    pub selected: Option<String>,
    /// Why the vault could not be opened at start-up, when it could not.
    ///
    /// An empty list says nothing about its cause: after a failed migration,
    /// this is the message that says the legacy vault was kept, and why.
    pub vault_error: Option<String>,
}

impl From<&ClientConfig> for ConfigView {
    fn from(config: &ClientConfig) -> Self {
        Self {
            profiles: config.profiles.iter().map(ProfileView::from).collect(),
            selected: config.selected.clone(),
            vault_error: None,
        }
    }
}

/// Result of an import: the draft profile, and whether an identity was sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportOutcome {
    /// The draft, redacted. Its private key waits in `pending_imports`.
    pub profile: ProfileView,
    /// `true` when a signed document completed its pending enrollment and the
    /// identity it yields is sealed.
    pub identity_sealed: bool,
    /// Why the draft has no private key: a classic invitation no local key
    /// completes, or a signed document no pending enrollment answers.
    pub private_key_missing: Option<String>,
    /// What else the document leaves to fill in, if anything.
    pub incomplete: Option<String>,
    /// What the document said that Orion read and does **not** apply.
    ///
    /// A wg-quick file routinely carries `DNS`, `MTU` or `Table`. Refusing the
    /// file over them made Orion unable to open an ordinary WireGuard
    /// configuration; dropping them without a word would hand back a tunnel
    /// that differs from the one the file describes. They are imported, and
    /// reported.
    pub notices: Vec<String>,
}

/// What the screen shows of an invitation before the user confirms it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationPreviewView {
    pub server_name: String,
    /// The `CA-PQ` fingerprint, in groups of four, to compare with what the
    /// operator reads out.
    pub ca_fingerprint: String,
    pub expires_at_unix: u64,
    /// The invitation text, returned as received: the confirmation call sends
    /// it back, so the backend keeps no state between the two.
    pub invitation_token: String,
}

/// Everything the Certificates screen shows, for every profile at once.
///
/// One command rather than two per profile, and the reason is the protected
/// store: answering unseals it, and a screen listing six profiles would
/// otherwise make twelve DPAPI round trips to build one view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileCertificates {
    pub name: String,
    /// Protected identity the profile names. Empty when it negotiates nothing.
    pub identity: String,
    /// The profile carries a key-negotiation block.
    pub negotiates: bool,
    pub inventory: orion_core::CertificateInventory,
    pub actions: Vec<orion_core::CertificateActionState>,
    pub last_error: Option<String>,
}

/// What one press produced, per profile.
///
/// A map and not a single step, because one of the four actions is
/// device-wide: returning the progress of the profile the press happened to
/// start from would have attributed five other renewals to it, and hidden the
/// approval each of them is waiting for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub progress: BTreeMap<String, RenewalProgress>,
    /// Profiles that could not be advanced, and why.
    ///
    /// Only ever populated by the fleet action: a single-profile press reports
    /// its refusal as an error, exactly as before.
    pub refused: BTreeMap<String, String>,
}

impl ActionOutcome {
    pub fn of(name: &str, step: RenewalProgress) -> Self {
        Self {
            progress: [(name.to_string(), step)].into_iter().collect(),
            refused: BTreeMap::new(),
        }
    }
}

/// Where a renewal stands, as the Certificates surface states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "step")]
pub enum RenewalProgress {
    AwaitingOperator {
        operation_id: String,
    },
    Issuing {
        operation_id: String,
    },
    Committed {
        generation: u64,
    },
    /// A §7.5 recovery, waiting on an operator who is not on this machine.
    ///
    /// The operator works on **their** workstation, so nothing here can be
    /// launched: the operation identifier is what travels between the two
    /// people.
    RecoveryAwaitingOperator {
        operation_id: String,
    },
    Recovered {
        generation: u64,
        activation_at: u64,
    },
    RolledBack {
        generation: u64,
        available_until: u64,
    },
}

impl RenewalProgress {
    pub fn of_recovery(step: &orion_core::certificate_recovery::RecoveryStep) -> Self {
        use orion_core::certificate_recovery::RecoveryStep;
        match step {
            RecoveryStep::AwaitingOperator { operation_id } => Self::RecoveryAwaitingOperator {
                operation_id: operation_id.to_hex(),
            },
            RecoveryStep::Issuing { operation_id } => Self::Issuing {
                operation_id: operation_id.to_hex(),
            },
            RecoveryStep::Recovered {
                generation,
                activation_at,
            } => Self::Recovered {
                generation: *generation,
                activation_at: *activation_at,
            },
        }
    }
}

impl RenewalProgress {
    pub fn of(step: &RenewalStep) -> Self {
        match step {
            RenewalStep::AwaitingOperator { operation_id } => Self::AwaitingOperator {
                operation_id: operation_id.to_hex(),
            },
            RenewalStep::Issuing { operation_id } => Self::Issuing {
                operation_id: operation_id.to_hex(),
            },
            RenewalStep::Committed { generation } => Self::Committed {
                generation: *generation,
            },
        }
    }
}

#[cfg(test)]
mod tests;

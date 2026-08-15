//! The four certificate actions of spec §12.2, and what gates each one.
//!
//! # Why the gate is a value and not a disabled button
//!
//! §12.2 asks for «Renouveler maintenant», «Renouveler tous les profils Helios
//! de cet appareil», «Récupérer le certificat expiré» and «Revenir
//! temporairement à l'ancienne identité», each offered *quand la machine
//! d'état l'autorise*. A screen that greys a button out and says nothing
//! leaves the user with the same question they started with — the interface
//! knows exactly why, and refuses to say.
//!
//! So the decision lives here, next to the state it reads, and it carries its
//! reason. The screen renders the reason; it does not invent one. When an
//! action becomes reachable, the surface does not change: the block simply
//! stops being returned.
//!
//! # Limite connue : aucune de ces actions ne s'exécute encore
//!
//! Two of them — recovery and rollback — need an operator hardware credential
//! and the `astra-signer` companion, which Astra itself refuses with `501`
//! (spec §12.3). That is a known, documented gap.
//!
//! The other two are blocked by one of two things, and which one matters: the
//! first is the operator's to fix, the second is ours.
//!
//! The ordinary §7 renewal has the client sign a rotation request, hand it to
//! Astra's delegated issuer, relay the resulting staging to the gateway, and
//! commit the grant it gets back. To do that a client must hold the trust
//! domain identifier, the Astra authority it is allowed to talk to with its
//! pinned service key, and the client `CA-TLS` anchor its own new leaf will
//! chain to. **A profile enrolled before §19 carries none of the three** — it
//! pins the *gateway's* material and the name of a protected identity, and
//! nothing else.
//!
//! That material now has a home — `KeyNegotiationSettings::trust`, carried by
//! the `.orion` document and the vault manifest — so a profile enrolled since
//! §19 holds it. What remains is the client half of the §7 exchange itself,
//! and [`CertificateActionBlock::RenewalPathNotWired`] names that instead.
//!
//! Either way the refusal happens **before** a key pair is generated or an
//! authority is asked to certify anything: a button that produced a key and
//! then discovered it could not finish would leave a half-rotation behind on
//! every press.

use serde::{Deserialize, Serialize};

use crate::certificate_inventory::{CertificateInventory, CertificatePhase};
use crate::KeyNegotiationSettings;

/// The four actions spec §12.2 requires the Profiles surface to offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateAction {
    /// Ordinary §7 renewal of this profile's client identity, brought forward.
    RenewNow,
    /// The same, for every Helios profile on this device.
    RenewEveryProfile,
    /// §15 recovery of an identity that has already expired.
    RecoverExpired,
    /// The bounded service rollback of §7.5, during an overlap.
    RollbackToPrevious,
}

impl CertificateAction {
    /// The label the interface must show.
    ///
    /// Fixed here rather than in the screen because §12.2 is explicit about
    /// them: no global action may hide behind an ambiguous «Renouveler».
    pub const fn label(self) -> &'static str {
        match self {
            Self::RenewNow => "Renouveler maintenant",
            Self::RenewEveryProfile => "Renouveler tous les profils Helios de cet appareil",
            Self::RecoverExpired => "Récupérer le certificat expiré",
            Self::RollbackToPrevious => "Revenir temporairement à l'ancienne identité",
        }
    }

    pub const fn all() -> [Self; 4] {
        [
            Self::RenewNow,
            Self::RenewEveryProfile,
            Self::RecoverExpired,
            Self::RollbackToPrevious,
        ]
    }
}

/// Why an action cannot run right now.
///
/// Every variant is a *different* thing for the user to do, which is the whole
/// reason they are distinct: importing an enrolment file, running Orion on a
/// machine with a protected store, and waiting for a format migration are not
/// interchangeable answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CertificateActionBlock {
    /// The profile negotiates nothing: it has no certificate to renew.
    NoNegotiation,
    /// This machine has no protected identity store at all.
    NoIdentityStore,
    /// The profile names an identity this machine has not sealed.
    IdentityMissing { identity: String },
    /// Nothing has expired, so there is nothing to recover.
    NothingExpired,
    /// No previous identity is held, so there is nothing to roll back to.
    NoPreviousIdentity,
    /// The profile carries no trust domain, no Astra authority and no client
    /// `CA-TLS`: §19's discriminant.
    TrustMaterialMissing,
    /// The trust material is there; the client half of §7 is not wired yet.
    RenewalPathNotWired,
    /// Needs a hardware credential and the `astra-signer` companion.
    OperatorCredentialRequired,
}

impl CertificateActionBlock {
    /// The sentence the interface shows, as-is.
    pub fn message(&self) -> String {
        match self {
            Self::NoNegotiation => {
                "Ce profil ne négocie pas de clé : il ne porte aucun certificat client à \
                 renouveler."
                    .into()
            }
            Self::NoIdentityStore => {
                "Aucun stockage protégé d'identité sur ce poste : le certificat client ne peut \
                 être ni relu ni rescellé. Le scellement passe par DPAPI, qui n'existe que sous \
                 Windows."
                    .into()
            }
            Self::IdentityMissing { identity } => format!(
                "Aucune identité protégée nommée « {identity} » sur ce poste : importer d'abord \
                 le fichier d'enrôlement fourni par l'opérateur."
            ),
            Self::NothingExpired => {
                "Aucun certificat de ce profil n'est expiré : la récupération ne s'applique qu'à \
                 une identité dont la validité est passée."
                    .into()
            }
            Self::NoPreviousIdentity => {
                "Ce poste ne détient aucune identité précédente : le retour arrière n'existe que \
                 pendant le chevauchement qui suit un renouvellement."
                    .into()
            }
            Self::TrustMaterialMissing => {
                "Ce profil ne porte pas le matériel de confiance qu'un renouvellement exige — \
                 domaine de confiance, autorité Astra épinglée et CA TLS cliente. Il a été \
                 enrôlé avant que le format ne les transporte : demander à l'opérateur un \
                 document réémis, qui les portera."
                    .into()
            }
            Self::RenewalPathNotWired => {
                "Ce profil porte bien son matériel de confiance, mais le chemin de \
                 renouvellement du §7 — requête au délégué Astra, staging relayé à la gateway, \
                 commit du grant — n'est pas encore branché côté client."
                    .into()
            }
            Self::OperatorCredentialRequired => {
                "Cette opération exige une clé matérielle d'opérateur et le compagnon \
                 « astra-signer », qu'Astra refuse explicitement dans cette version."
                    .into()
            }
        }
    }
}

/// One action and whether it may run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateActionState {
    pub action: CertificateAction,
    pub label: String,
    /// `None` when the action may run.
    pub blocked_by: Option<CertificateActionBlock>,
    pub message: Option<String>,
}

impl CertificateActionState {
    fn blocked(action: CertificateAction, block: CertificateActionBlock) -> Self {
        Self {
            action,
            label: action.label().to_string(),
            message: Some(block.message()),
            blocked_by: Some(block),
        }
    }
}

/// What blocks the two renewal actions, in the order the user can act on.
///
/// The order matters more than it looks: a machine with no protected store
/// and a profile with no identity are both true on a fresh Linux build, and
/// naming the store first sends the user to the right problem. The format gap
/// comes last because it is the only one they cannot fix themselves.
fn renewal_block(
    settings: Option<&KeyNegotiationSettings>,
    inventory: &CertificateInventory,
    identity_store: bool,
) -> Option<CertificateActionBlock> {
    let settings = settings?;
    if !identity_store {
        return Some(CertificateActionBlock::NoIdentityStore);
    }
    if !inventory.identity_sealed {
        return Some(CertificateActionBlock::IdentityMissing {
            identity: settings.identity.clone(),
        });
    }
    // The §19 material, if the document carried it. A profile written before
    // the discriminant has none, and that is the honest reason to give — it is
    // the one the operator can fix, by re-issuing a document that carries it.
    if settings.trust.is_none() {
        return Some(CertificateActionBlock::TrustMaterialMissing);
    }
    Some(CertificateActionBlock::RenewalPathNotWired)
}

/// Whether anything this profile depends on has already expired.
fn anything_expired(inventory: &CertificateInventory) -> bool {
    [
        inventory.gateway_pq.as_ref(),
        inventory.gateway_ca_tls.as_ref(),
        inventory.client_tls.as_ref(),
        inventory.client_pq.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|facts| facts.phase == CertificatePhase::Expired)
}

/// The state of all four actions for one profile.
pub fn action_states(
    settings: Option<&KeyNegotiationSettings>,
    inventory: &CertificateInventory,
    identity_store: bool,
) -> Vec<CertificateActionState> {
    let Some(settings) = settings else {
        // Nothing to renew, nothing to recover, nothing to roll back to.
        return CertificateAction::all()
            .into_iter()
            .map(|action| {
                CertificateActionState::blocked(action, CertificateActionBlock::NoNegotiation)
            })
            .collect();
    };

    let renewal = renewal_block(Some(settings), inventory, identity_store);
    CertificateAction::all()
        .into_iter()
        .map(|action| match action {
            CertificateAction::RenewNow | CertificateAction::RenewEveryProfile => {
                match renewal.clone() {
                    Some(block) => CertificateActionState::blocked(action, block),
                    None => CertificateActionState {
                        action,
                        label: action.label().to_string(),
                        blocked_by: None,
                        message: None,
                    },
                }
            }
            // Recovery is about an expired identity, and only about that. On a
            // profile whose certificates are healthy the honest answer is
            // "rien à récupérer", not the operator credential the user cannot
            // produce either way.
            CertificateAction::RecoverExpired => {
                if anything_expired(inventory) {
                    CertificateActionState::blocked(
                        action,
                        CertificateActionBlock::OperatorCredentialRequired,
                    )
                } else {
                    CertificateActionState::blocked(action, CertificateActionBlock::NothingExpired)
                }
            }
            // A rollback needs a previous identity held locally. Nothing keeps
            // one: the protected store holds exactly one bundle per name.
            CertificateAction::RollbackToPrevious => {
                CertificateActionState::blocked(action, CertificateActionBlock::NoPreviousIdentity)
            }
        })
        .collect()
}

/// Runs an action, or says why it cannot.
///
/// Every path currently returns the block, and that is deliberate: the failure
/// happens **before** a key pair is generated or an authority is asked to
/// certify anything. A button that produced a key and then discovered it could
/// not finish would leave a half-rotation behind on every press.
pub fn run(
    action: CertificateAction,
    settings: Option<&KeyNegotiationSettings>,
    inventory: &CertificateInventory,
    identity_store: bool,
) -> Result<(), CertificateActionBlock> {
    let state = action_states(settings, inventory, identity_store)
        .into_iter()
        .find(|state| state.action == action)
        .ok_or(CertificateActionBlock::NoNegotiation)?;
    match state.blocked_by {
        Some(block) => Err(block),
        // Unreachable while the trust material is missing, and left as the
        // shape the §7 driver will fill rather than an `unreachable!()`.
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_inventory::CertificateFacts;
    use aether::key_negotiation::ProtectionMode;

    fn settings() -> KeyNegotiationSettings {
        KeyNegotiationSettings {
            mode: ProtectionMode::MlKem,
            minimum_mode: ProtectionMode::MlKem,
            endpoint: "gateway:51821".into(),
            server_name: "gateway.example".into(),
            gateway_ca_der: String::new(),
            gateway_pq_certificate: String::new(),
            identity: "orion-poste".into(),
            trust: None,
        }
    }

    fn facts(phase: CertificatePhase) -> CertificateFacts {
        CertificateFacts {
            subject: "CN=poste".into(),
            issuer: "CN=CA".into(),
            fingerprint: "ff".into(),
            not_before: 0,
            not_after: 100,
            renewal_at: 80,
            phase,
        }
    }

    fn state_of(
        states: &[CertificateActionState],
        action: CertificateAction,
    ) -> &CertificateActionState {
        states
            .iter()
            .find(|state| state.action == action)
            .expect("every action is reported")
    }

    /// §12.2 names four actions. All four are always reported — an action the
    /// screen never hears about is one the user cannot be told the state of.
    #[test]
    fn all_four_actions_are_always_reported() {
        let states = action_states(None, &CertificateInventory::default(), false);
        assert_eq!(states.len(), 4);
        for action in CertificateAction::all() {
            assert_eq!(state_of(&states, action).action, action);
        }
    }

    /// A profile that negotiates nothing has no certificate to renew, and that
    /// is the reason shown — not the format gap, which is not its problem.
    #[test]
    fn a_profile_without_negotiation_is_blocked_on_that_and_nothing_else() {
        let states = action_states(None, &CertificateInventory::default(), true);
        for state in &states {
            assert_eq!(
                state.blocked_by,
                Some(CertificateActionBlock::NoNegotiation)
            );
        }
    }

    /// The reasons are ordered by what the user can act on: a machine with no
    /// protected store is told about the store, not about an identity it could
    /// not have sealed anyway.
    #[test]
    fn the_missing_store_outranks_the_missing_identity() {
        let settings = settings();
        let states = action_states(Some(&settings), &CertificateInventory::default(), false);
        assert_eq!(
            state_of(&states, CertificateAction::RenewNow).blocked_by,
            Some(CertificateActionBlock::NoIdentityStore)
        );

        let states = action_states(Some(&settings), &CertificateInventory::default(), true);
        assert_eq!(
            state_of(&states, CertificateAction::RenewNow).blocked_by,
            Some(CertificateActionBlock::IdentityMissing {
                identity: "orion-poste".into()
            })
        );
    }

    /// With everything present locally, what remains is the format gap — and
    /// it is named, because it is the operator who fixes it, by re-issuing a
    /// document that carries the material.
    #[test]
    fn a_ready_machine_is_blocked_only_on_the_missing_trust_material() {
        let settings = settings();
        let inventory = CertificateInventory {
            identity_sealed: true,
            client_pq: Some(facts(CertificatePhase::RenewalDue)),
            ..CertificateInventory::default()
        };
        let states = action_states(Some(&settings), &inventory, true);
        for action in [
            CertificateAction::RenewNow,
            CertificateAction::RenewEveryProfile,
        ] {
            assert_eq!(
                state_of(&states, action).blocked_by,
                Some(CertificateActionBlock::TrustMaterialMissing)
            );
        }
        assert!(state_of(&states, CertificateAction::RenewNow)
            .message
            .as_ref()
            .is_some_and(|message| message.contains("domaine de confiance")));
    }

    /// A profile enrolled since §19 carries the material, so the reason moves
    /// to the one thing left: the client half of the exchange. Naming the
    /// format gap there would send the operator re-issuing a document that is
    /// already correct.
    #[test]
    fn a_profile_carrying_its_trust_material_is_blocked_on_the_path_instead() {
        let mut settings = settings();
        settings.trust = Some(crate::config::TrustMaterial {
            trust_domain_id: "0102030405060708090a0b0c0d0e0f10".into(),
            ca_epoch: 1,
            ca_pq_public_key: String::new(),
            ca_tls_epoch: 1,
            client_tls_ca_der: String::new(),
            client_generation: 4,
            astra_authority_url: "https://astra.example".into(),
            astra_service_key_epoch: 1,
            astra_service_public_key: String::new(),
        });
        let inventory = CertificateInventory {
            identity_sealed: true,
            ..CertificateInventory::default()
        };
        assert_eq!(
            state_of(
                &action_states(Some(&settings), &inventory, true),
                CertificateAction::RenewNow
            )
            .blocked_by,
            Some(CertificateActionBlock::RenewalPathNotWired)
        );
    }

    /// Recovery answers about expiry first. Telling a user with healthy
    /// certificates that they need a YubiKey answers a question they did not
    /// ask.
    #[test]
    fn recovery_reports_the_expiry_before_the_credential() {
        let settings = settings();
        let healthy = CertificateInventory {
            identity_sealed: true,
            client_pq: Some(facts(CertificatePhase::Valid)),
            ..CertificateInventory::default()
        };
        assert_eq!(
            state_of(
                &action_states(Some(&settings), &healthy, true),
                CertificateAction::RecoverExpired
            )
            .blocked_by,
            Some(CertificateActionBlock::NothingExpired)
        );

        let expired = CertificateInventory {
            identity_sealed: true,
            client_pq: Some(facts(CertificatePhase::Expired)),
            ..CertificateInventory::default()
        };
        assert_eq!(
            state_of(
                &action_states(Some(&settings), &expired, true),
                CertificateAction::RecoverExpired
            )
            .blocked_by,
            Some(CertificateActionBlock::OperatorCredentialRequired)
        );
    }

    /// Running a blocked action fails **before** anything is generated: a
    /// half-rotation left behind on every press is worse than a refusal.
    #[test]
    fn running_a_blocked_action_refuses_with_its_own_reason() {
        let settings = settings();
        let inventory = CertificateInventory {
            identity_sealed: true,
            ..CertificateInventory::default()
        };
        assert_eq!(
            run(
                CertificateAction::RenewNow,
                Some(&settings),
                &inventory,
                true
            ),
            Err(CertificateActionBlock::TrustMaterialMissing)
        );
    }
}

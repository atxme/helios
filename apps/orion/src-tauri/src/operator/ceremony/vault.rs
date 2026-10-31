//! The vault and domain gestures, run as an operator ceremony.
//!
//! The sequences are [`astra_operator::vault_gestures`]'s; this module only
//! puts the presses between them. Every gesture checks what it can before a
//! key is asked anything and publishes the manifest of what it will fix, then
//! asks one key at a time. A refusal before the first key leaves no key asked
//! and nothing written.
//!
//! Every opening a key releases stays in this thread: none is published,
//! logged nor handed to the caller. `keys` carries the label of each key that
//! answered, and nothing else about it.

use std::path::Path;
use std::sync::mpsc::Receiver;

use aether::certificates::encoding::{Fingerprint, Id16, TrustDomainId};
use aether::certificates::operator_session::{
    AstraManifest, DomainCreationManifest, DomainFinalizationManifest, GatewayBootstrapManifest,
    GestureState, KeyAdditionManifest, KeyMarkingManifest, KeyPurpose, KeyRemovalManifest,
    KeySlotLabel, OperationLocator, OperatorStatus, Refusal, RemoteState,
};
use aether_fido::authenticator::{Authenticator, AuthenticatorError};
use astra_operator::authenticator::Opened;
use astra_operator::bootstrap::{
    self, BootstrapPlan, Bootstrapped, Finalization, BOOTSTRAP_CERTIFICATE_FILE,
    BOOTSTRAP_LEAF_DAYS,
};
use astra_operator::gestures::{GestureError, NewAuthority, NewKey};
use astra_operator::vault::{AuthorityVault, SlotRole};
use astra_operator::vault_gestures::{self as gestures, SetupRefusal};

use super::{now_unix, open_key, Ceremony, Press};
use crate::operator::{parse_slot_id, ArtifactEncoding, KeyRole, OperatorArtifact, VaultGesture};

/// Runs one vault or domain gesture to its end against the vault at
/// `vault_path`, publishing every state it reaches and handing the `CA-TLS`
/// a finalization issues to `deposit`.
pub fn run_vault(
    session_id: Id16,
    gesture: VaultGesture,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    vault_path: &Path,
) -> Result<(), String> {
    let mut ceremony = Ceremony::new(
        session_id,
        OperationLocator {
            kind: gesture.operation(),
            operation_id: None,
        },
    );
    publish(ceremony.status());
    let mut run = VaultRun {
        ceremony: &mut ceremony,
        presses: &presses,
        publish,
        vault_path,
    };

    match gesture {
        VaultGesture::CreateDomain {
            rp_id,
            authority_url,
            first_label,
            second_label,
        } => run.create_domain(DomainCreationManifest {
            rp_id,
            // As the relay will record it.
            authority_url: authority_url.trim_end_matches('/').to_string(),
            first_label: first_label.trim().to_string(),
            second_label: second_label.trim().to_string(),
        }),
        VaultGesture::AddKey { label, role } => run.add_key(label.trim(), role),
        VaultGesture::RemoveKey { slot_id } => run.remove_key(&slot_id),
        VaultGesture::MarkKey { slot_id, lost } => run.mark_key(&slot_id, lost),
        VaultGesture::FinalizeDomain => run.finalize(deposit),
        VaultGesture::BootstrapGateway { request } => run.bootstrap_gateway(&request, deposit),
    }
}

/// The refusal a vault check names, as the window says it.
fn refusal_of_setup(refusal: SetupRefusal) -> Refusal {
    match refusal {
        SetupRefusal::VaultExists => Refusal::VaultExists,
        SetupRefusal::LocationUnavailable => Refusal::LocationUnavailable,
        SetupRefusal::VaultFull => Refusal::VaultFull,
        SetupRefusal::MinimumKeys => Refusal::MinimumKeys,
        // The slot the window named is not this vault's: it was showing
        // another one.
        SetupRefusal::UnknownSlot => Refusal::HandoffMismatch,
        // The window offers no state change on a revoked key: a gesture asking
        // for one did not come from what it showed.
        SetupRefusal::KeyRevoked => Refusal::HandoffMismatch,
        SetupRefusal::KeyBeingRemoved => Refusal::KeyBeingRemoved,
        SetupRefusal::GatewayIdentityMissing => Refusal::GatewayIdentityMissing,
        SetupRefusal::DomainComplete => Refusal::DomainComplete,
        SetupRefusal::OtherGateway => Refusal::OtherGateway,
        SetupRefusal::BootstrapRequestInvalid => Refusal::BootstrapRequestInvalid,
        SetupRefusal::SignerRevoked => Refusal::SignerRevoked,
        // What would be written is no longer what the window showed.
        SetupRefusal::PlanChanged => Refusal::DomainChanged,
    }
}

/// The refusal a gesture's error stands for.
///
/// The check it carries, when it carries one. Else `KeyDeclined` only when the
/// key itself, or the platform call to it, failed. Anything else failed after
/// the key answered — a write, a signature, the proof of the anchors — and is
/// `Internal`: telling the operator the key refused would send them to retry
/// a key that did its part, over a vault that may already have moved.
fn refusal_of(error: &anyhow::Error) -> Refusal {
    for cause in error.chain() {
        if let Some(refusal) = cause.downcast_ref::<SetupRefusal>() {
            return refusal_of_setup(*refusal);
        }
        if cause.downcast_ref::<AuthenticatorError>().is_some()
            || matches!(
                cause.downcast_ref::<GestureError>(),
                Some(GestureError::Authenticator(_))
            )
        {
            return Refusal::KeyDeclined;
        }
    }
    Refusal::Internal
}

/// One gesture in progress: the ceremony, its presses and its publisher.
struct VaultRun<'a> {
    ceremony: &'a mut Ceremony,
    presses: &'a Receiver<Press>,
    publish: &'a mut dyn FnMut(OperatorStatus),
    vault_path: &'a Path,
}

impl VaultRun<'_> {
    /// Publishes `refusal` as the end of the ceremony and returns `message`.
    fn refuse<T>(&mut self, refusal: Refusal, message: String) -> Result<T, String> {
        self.ceremony.refuse(refusal);
        (self.publish)(self.ceremony.status());
        Err(message)
    }

    fn refuse_setup<T>(&mut self, refusal: SetupRefusal) -> Result<T, String> {
        self.refuse(refusal_of_setup(refusal), refusal.to_string())
    }

    fn done(&mut self) -> Result<(), String> {
        self.ceremony.gesture = GestureState::Done;
        (self.publish)(self.ceremony.status());
        Ok(())
    }

    /// The vault and its fingerprint, or a published `VaultUnavailable`.
    fn load(&mut self) -> Result<(AuthorityVault, Fingerprint), String> {
        match super::load_with_fingerprint(self.vault_path) {
            Ok(loaded) => Ok(loaded),
            Err(error) => self.refuse(Refusal::VaultUnavailable, format!("{error:#}")),
        }
    }

    /// Whether the credential document in place could be re-signed by the
    /// gesture, settled before any key: a refusal here costs no press.
    fn check_document(&mut self) -> Result<(), String> {
        match gestures::check_document(self.vault_path) {
            Ok(()) => Ok(()),
            Err(refusal) => self.refuse_setup(refusal),
        }
    }

    /// Shows the manifest; nothing is asked of a key before this.
    fn show(&mut self, manifest: AstraManifest) {
        self.ceremony.remote = RemoteState::AwaitingOperator;
        self.ceremony.manifest = Some(manifest);
    }

    /// Asks for the `index`-th key of `of`, for `purpose`, and connects it.
    /// `None` is an abandonment, already published.
    fn ask_key(
        &mut self,
        index: u8,
        of: u8,
        purpose: KeyPurpose,
    ) -> Result<Option<Box<dyn Authenticator>>, String> {
        self.ceremony.gesture = GestureState::AwaitingKey { index, of, purpose };
        let offered = self.ceremony.status();
        (self.publish)(offered.clone());
        open_key(self.ceremony, self.presses, self.publish, &offered)
    }

    /// Records the label of the key that answered at `index`.
    fn answered(&mut self, index: u8, label: &str) {
        self.ceremony.keys.push(KeySlotLabel {
            slot: index.to_string(),
            label: label.to_string(),
        });
    }

    /// Opens the vault with the `index`-th key of `of`, any enrolled key but
    /// the one `removing` names. The key is let go before this returns, so
    /// the next one can be plugged in its place.
    fn open_vault(
        &mut self,
        vault: &AuthorityVault,
        index: u8,
        of: u8,
        removing: Option<&[u8; 16]>,
    ) -> Result<Option<Opened>, String> {
        self.open_vault_for(vault, index, of, removing, KeyPurpose::OpenVault)
    }

    /// [`Self::open_vault`], the key asked for under `purpose`.
    fn open_vault_for(
        &mut self,
        vault: &AuthorityVault,
        index: u8,
        of: u8,
        removing: Option<&[u8; 16]>,
        purpose: KeyPurpose,
    ) -> Result<Option<Opened>, String> {
        let Some(key) = self.ask_key(index, of, purpose)? else {
            return Ok(None);
        };
        // The PIN is empty for the reason `open_key` refused a transport that
        // wants one: the platform collects it in its own dialog.
        let opening = match removing {
            Some(slot) => gestures::open_for_removal(key.as_ref(), vault, slot, ""),
            None => astra_operator::gestures::open_with_authorized_key(key.as_ref(), vault, "")
                .map_err(anyhow::Error::from),
        };
        let opened = match opening {
            Ok(opened) => opened,
            Err(error) => {
                // A check the opening carries is named; anything else is the
                // key that did not open.
                let refusal = match refusal_of(&error) {
                    Refusal::Internal => Refusal::KeyDeclined,
                    refusal => refusal,
                };
                return self.refuse(refusal, format!("{error:#}"));
            }
        };
        drop(key);
        if let Ok(slot) = vault.slot_for_credential(&opened.credential_id) {
            let label = slot.label.clone();
            self.answered(index, &label);
        }
        Ok(Some(opened))
    }

    /// The first vault of a domain: the first key creates it, the second is
    /// registered with the opening the first released, and both are proved
    /// to read the anchors.
    ///
    /// Stopped after the first key, the one-key vault stays: it is the only
    /// object that opens the anchors just drawn, and the operator adds the
    /// second key to it.
    fn create_domain(&mut self, manifest: DomainCreationManifest) -> Result<(), String> {
        if let Err(refusal) = gestures::check_creation(self.vault_path) {
            return self.refuse_setup(refusal);
        }
        let trust_domain_id = match aether::random::public_bytes::<16>()
            .map_err(|error| error.to_string())
            .and_then(|bytes| TrustDomainId::new(bytes).map_err(|error| error.to_string()))
        {
            Ok(id) => id,
            Err(error) => {
                return self.refuse(
                    Refusal::Internal,
                    format!("tirage de l'identifiant de domaine : {error}"),
                )
            }
        };
        let request = NewAuthority {
            rp_id: manifest.rp_id.clone(),
            trust_domain_id,
            label: manifest.first_label.clone(),
            role: SlotRole::Primary,
        };
        let authority_url = manifest.authority_url.clone();
        let second = NewKey {
            label: manifest.second_label.clone(),
            role: SlotRole::Recovery,
        };
        self.show(AstraManifest::DomainCreation(manifest));

        let Some(key) = self.ask_key(1, 2, KeyPurpose::RegisterKey)? else {
            return Ok(());
        };
        let first = match gestures::create_first_key(
            self.vault_path,
            &request,
            &authority_url,
            key.as_ref(),
            "",
            now_unix(),
        ) {
            Ok(opening) => opening,
            Err(error) => return self.refuse(refusal_of(&error), format!("{error:#}")),
        };
        drop(key);
        self.answered(1, &request.label);

        let Some(key) = self.ask_key(2, 2, KeyPurpose::RegisterKey)? else {
            return Ok(());
        };
        let added = match gestures::add_key_with(
            self.vault_path,
            &first,
            key.as_ref(),
            &second,
            "",
            now_unix(),
        ) {
            Ok(added) => added,
            Err(error) => return self.refuse(refusal_of(&error), format!("{error:#}")),
        };
        drop(key);
        self.answered(2, &second.label);

        if let Err(error) = gestures::prove_opens(self.vault_path, &[&first, &added.opening]) {
            return self.refuse(refusal_of(&error), format!("{error:#}"));
        }
        self.done()
    }

    /// A further key: one the vault opens for, then the new one.
    fn add_key(&mut self, label: &str, role: KeyRole) -> Result<(), String> {
        let (vault, fingerprint) = self.load()?;
        if let Err(refusal) = gestures::check_addition(&vault) {
            return self.refuse_setup(refusal);
        }
        self.check_document()?;
        self.show(AstraManifest::KeyAddition(KeyAdditionManifest {
            vault_fingerprint: fingerprint,
            label: label.to_string(),
            role: role.name().to_string(),
        }));

        let Some(opening) = self.open_vault(&vault, 1, 2, None)? else {
            return Ok(());
        };
        let Some(key) = self.ask_key(2, 2, KeyPurpose::RegisterKey)? else {
            return Ok(());
        };
        let request = NewKey {
            label: label.to_string(),
            role: role.slot_role(),
        };
        let added = match gestures::add_key_with(
            self.vault_path,
            &opening,
            key.as_ref(),
            &request,
            "",
            now_unix(),
        ) {
            Ok(added) => added,
            Err(error) => return self.refuse(refusal_of(&error), format!("{error:#}")),
        };
        drop(key);
        self.answered(2, label);

        // As at creation, both openings already held are proved to read the
        // anchors: the second key of a one-key vault, added from its banner,
        // gets the trial ADR-008 §4 asks for. No press.
        if let Err(error) = gestures::prove_opens(self.vault_path, &[&opening, &added.opening]) {
            return self.refuse(refusal_of(&error), format!("{error:#}"));
        }
        self.done()
    }

    /// A key withdrawn, with another key's opening.
    fn remove_key(&mut self, slot_id: &str) -> Result<(), String> {
        let slot = self.slot_id(slot_id)?;
        let (vault, fingerprint) = self.load()?;
        let manifest = match gestures::check_removal(&vault, &slot) {
            Ok(removed) => KeyRemovalManifest {
                vault_fingerprint: fingerprint,
                slot_id: slot_id.to_string(),
                label: removed.label.clone(),
                role: KeyRole::of(removed.role).name().to_string(),
            },
            Err(refusal) => return self.refuse_setup(refusal),
        };
        self.check_document()?;
        self.show(AstraManifest::KeyRemoval(manifest));

        // The key being removed is left out of what the platform asks for:
        // presenting it costs no PIN and no touch for a refusal.
        let Some(opening) = self.open_vault(&vault, 1, 1, Some(&slot))? else {
            return Ok(());
        };
        self.signing();
        match gestures::remove_key_with(self.vault_path, &opening, &slot, now_unix()) {
            Ok(()) => self.done(),
            Err(error) => self.refuse(refusal_of(&error), format!("{error:#}")),
        }
    }

    /// A key signed lost, or active again.
    fn mark_key(&mut self, slot_id: &str, lost: bool) -> Result<(), String> {
        let slot = self.slot_id(slot_id)?;
        let (vault, fingerprint) = self.load()?;
        let manifest = match gestures::check_marking(self.vault_path, &vault, &slot) {
            Ok(marked) => KeyMarkingManifest {
                vault_fingerprint: fingerprint,
                slot_id: slot_id.to_string(),
                label: marked.label.clone(),
                lost,
            },
            Err(refusal) => return self.refuse_setup(refusal),
        };
        self.check_document()?;
        self.show(AstraManifest::KeyMarking(manifest));

        let Some(opening) = self.open_vault(&vault, 1, 1, None)? else {
            return Ok(());
        };
        self.signing();
        match gestures::mark_key_with(self.vault_path, &opening, &slot, lost, now_unix()) {
            Ok(_) => self.done(),
            Err(error) => self.refuse(refusal_of(&error), format!("{error:#}")),
        }
    }

    /// What the domain still lacks, issued under one key: its `CA-TLS`, handed
    /// over as a file, and its credential document.
    fn finalize(&mut self, deposit: &mut dyn FnMut(OperatorArtifact)) -> Result<(), String> {
        let (vault, fingerprint) = self.load()?;
        let plan = match gestures::finalization(self.vault_path) {
            Ok(plan) => plan,
            Err(refusal) => return self.refuse_setup(refusal),
        };
        self.show(AstraManifest::DomainFinalization(
            DomainFinalizationManifest {
                vault_fingerprint: fingerprint,
                server_name: plan.server_name,
                gateway_wg_public_key: plan.gateway_wg_public_key,
                issues_ca_tls: plan.issues_ca_tls,
                ca_tls_days: gestures::CA_TLS_DAYS,
                issues_credentials: plan.issues_credentials,
            },
        ));

        let Some(opening) = self.open_vault(&vault, 1, 1, None)? else {
            return Ok(());
        };
        self.signing();
        match gestures::finalize_with(self.vault_path, &opening, now_unix()) {
            Ok(finalized) => {
                if let Some(pem) = finalized.ca_tls_pem {
                    deposit(OperatorArtifact {
                        file_name: "ca-tls.pem".to_string(),
                        contents: pem,
                        encoding: ArtifactEncoding::Text,
                        fingerprint: None,
                    });
                }
                self.done()
            }
            Err(error) => self.refuse(refusal_of(&error), format!("{error:#}")),
        }
    }

    /// A gateway's leaf, under two keys, then whatever the domain still lacks.
    ///
    /// The request is checked as a plan before any key is asked anything. Both
    /// openings are proved to read the anchors by `bootstrap_with`, which this
    /// relies on rather than repeating the trial.
    fn bootstrap_gateway(
        &mut self,
        request: &str,
        deposit: &mut dyn FnMut(OperatorArtifact),
    ) -> Result<(), String> {
        let (vault, fingerprint) = self.load()?;
        let plan = match bootstrap::bootstrap_plan(self.vault_path, request) {
            Ok(plan) => plan,
            Err(refusal) => return self.refuse_setup(refusal),
        };
        self.show(AstraManifest::GatewayBootstrap(GatewayBootstrapManifest {
            vault_fingerprint: fingerprint,
            server_name: plan.request.server_name.clone(),
            gateway_wg_public_key: plan.request.gateway_wg_public_key,
            request_fingerprint: plan.request.fingerprint(),
            leaf_days: BOOTSTRAP_LEAF_DAYS,
            issues_ca_tls: plan.issues_ca_tls,
            ca_tls_days: gestures::CA_TLS_DAYS,
            issues_credentials: plan.issues_credentials,
        }));

        let Some(first) = self.open_vault(&vault, 1, 2, None)? else {
            return Ok(());
        };
        let Some(second) = self.open_vault_for(&vault, 2, 2, None, KeyPurpose::SecondApproval)?
        else {
            return Ok(());
        };
        self.issue_bootstrap(&plan, &first, &second, deposit)
    }

    /// Issues the bootstrap with the two openings, once the second key has
    /// answered. One key presented twice is refused here, before the signing
    /// state and with nothing written.
    fn issue_bootstrap(
        &mut self,
        plan: &BootstrapPlan,
        first: &Opened,
        second: &Opened,
        deposit: &mut dyn FnMut(OperatorArtifact),
    ) -> Result<(), String> {
        if first.credential_id == second.credential_id {
            // The repeated key is not a second approver: its entry, and only
            // its, is withdrawn.
            self.ceremony.keys.retain(|key| key.slot != "2");
            return self.refuse(
                Refusal::KeyRepeated,
                "le même credential a été présenté deux fois : l'amorçage en exige deux distincts"
                    .to_string(),
            );
        }
        self.signing();
        match bootstrap::bootstrap_with(self.vault_path, plan, first, second, now_unix()) {
            Ok(bootstrapped) => self.conclude_bootstrap(bootstrapped, deposit),
            Err(error) => self.refuse(refusal_of(&error), format!("{error:#}")),
        }
    }

    /// Hands over what a bootstrap wrote, then ends the ceremony: done, or
    /// `Internal` when the finalization failed after the leaf. The leaf is
    /// deposited first either way, so a late failure never hides it.
    fn conclude_bootstrap(
        &mut self,
        bootstrapped: Bootstrapped,
        deposit: &mut dyn FnMut(OperatorArtifact),
    ) -> Result<(), String> {
        match deposit_bootstrapped(bootstrapped, deposit) {
            None => self.done(),
            Some(chain) => self.refuse(
                Refusal::Internal,
                format!("feuille émise et écrite, finalisation du domaine en échec : {chain}"),
            ),
        }
    }

    /// The slot the gesture names. Validated on arrival, so a failure here is
    /// a gesture that did not come through the window.
    fn slot_id(&mut self, slot_id: &str) -> Result<[u8; 16], String> {
        match parse_slot_id(slot_id) {
            Ok(slot) => Ok(slot),
            Err(message) => self.refuse(Refusal::HandoffMismatch, message),
        }
    }

    /// The vault is open and `CA-PQ` signs: nothing is cancellable from here.
    fn signing(&mut self) {
        self.ceremony.gesture = GestureState::Signing;
        (self.publish)(self.ceremony.status());
    }
}

/// Hands over the public files a bootstrap produced: the leaf with its
/// fingerprint, then the `CA-TLS` when the finalization issued it. Returns the
/// finalization's error chain when it failed after the leaf.
fn deposit_bootstrapped(
    bootstrapped: Bootstrapped,
    deposit: &mut dyn FnMut(OperatorArtifact),
) -> Option<String> {
    deposit(OperatorArtifact {
        file_name: BOOTSTRAP_CERTIFICATE_FILE.to_string(),
        contents: bootstrapped.leaf_json,
        encoding: ArtifactEncoding::Text,
        fingerprint: Some(bootstrapped.leaf_fingerprint),
    });
    match bootstrapped.finalization {
        Finalization::NotNeeded => None,
        Finalization::Issued(finalized) => {
            if let Some(pem) = finalized.ca_tls_pem {
                deposit(OperatorArtifact {
                    file_name: "ca-tls.pem".to_string(),
                    contents: pem,
                    encoding: ArtifactEncoding::Text,
                    fingerprint: None,
                });
            }
            None
        }
        Finalization::Failed(chain) => Some(chain),
    }
}

#[cfg(test)]
mod tests;

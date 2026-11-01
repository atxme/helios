//! The delegation of Astra's issuer (ADR-008 §9.5), run as an operator
//! ceremony.
//!
//! The sequences are [`astra_operator::operations::issuer`]'s; this module
//! only puts the presses between them. The domain, the campaign and the
//! request are settled as a plan, and everything the plan refuses is
//! published before a key is asked anything. The manifest shown is the
//! plan's, and the plan is what is signed.
//!
//! In a campaign, one key approves the campaign and the vault then opens for
//! that credential alone; the result is deposited on the relay's origin.
//! Offline, for a domain whose relay names no origin, one key opens the vault
//! and the authorization is handed over as a file.
//!
//! Every opening a key releases stays in this thread: none is published,
//! logged nor handed to the caller.

use std::path::Path;
use std::sync::mpsc::Receiver;

use aether::certificates::encoding::Id16;
use aether::certificates::operator_session::{
    AstraManifest, GestureState, KeyPurpose, KeySlotLabel, OperationLocator, OperatorStatus,
    Refusal, RemoteState,
};
use aether_fido::authenticator::Authenticator;
use astra_operator::authenticator::Opened;
use astra_operator::operations::issuer::{
    self, CampaignDelegation, IssuerPlan, IssuerRefusal, AUTHORIZATION_FILE,
};
use astra_operator::vault::AuthorityVault;

use super::{now_unix, open_key, Ceremony, Press};
use crate::operator::{ArtifactEncoding, IssuerGesture, OperatorArtifact};

/// Runs one delegation to its end against the vault at `vault_path`,
/// publishing every state it reaches and handing an offline authorization to
/// `deposit`.
pub fn run_issuer(
    session_id: Id16,
    gesture: IssuerGesture,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    vault_path: &Path,
) -> Result<(), String> {
    let operation = gesture.operation_id();
    let mut ceremony = Ceremony::new(
        session_id,
        OperationLocator {
            kind: gesture.operation(),
            operation_id: operation.clone().ok().flatten(),
        },
    );
    publish(ceremony.status());
    let mut run = IssuerRun {
        ceremony: &mut ceremony,
        presses: &presses,
        publish,
        vault_path,
    };

    match operation {
        // Validated on arrival: a failure here is a gesture that did not
        // come through the window.
        Err(message) => run.refuse(Refusal::HandoffMismatch, message),
        Ok(Some(operation)) => run.in_campaign(operation, gesture.request()),
        Ok(None) => run.offline(gesture.request(), deposit),
    }
}

/// The refusal a plan names, as the window says it.
fn refusal_of_plan(refusal: &IssuerRefusal) -> Refusal {
    match refusal {
        IssuerRefusal::RequestInvalid => Refusal::DelegationRequestInvalid,
        IssuerRefusal::RequestMismatch => Refusal::DelegationRequestMismatch,
        // A campaign of another family, or a file for a domain that has a
        // campaign path: what was asked is not what this domain signs.
        IssuerRefusal::NotADelegation | IssuerRefusal::OriginRecorded => Refusal::ManifestMismatch,
        IssuerRefusal::CaTlsMissing => Refusal::CaTlsMissing,
        IssuerRefusal::CaTlsUnusable => Refusal::CaTlsUnusable,
        // What would be signed is no longer what the window showed.
        IssuerRefusal::PlanChanged => Refusal::DomainChanged,
        IssuerRefusal::Vault(_) => Refusal::VaultUnavailable,
    }
}

/// The plan's refusal an error chain carries, when it carries one.
fn plan_refusal_in(error: &anyhow::Error) -> Option<Refusal> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<IssuerRefusal>())
        .map(refusal_of_plan)
}

/// A campaign that could not be fetched or verified: the refusal it names,
/// else a hand-off that does not hold.
fn refusal_of_campaign(error: &anyhow::Error) -> Refusal {
    plan_refusal_in(error).unwrap_or(Refusal::HandoffMismatch)
}

/// An offline signature that failed after the key answered: the refusal it
/// names, else `Internal` — the key did its part.
fn refusal_of_signature(error: &anyhow::Error) -> Refusal {
    plan_refusal_in(error).unwrap_or(Refusal::Internal)
}

/// The gesture in a campaign that failed: the deposit once the approval and
/// the delegation were prepared, else the refusal the error names, else the
/// key — its approval, or the opening restricted to the credential that
/// approved.
fn refusal_of_gesture(error: &anyhow::Error, prepared: bool) -> Refusal {
    if prepared {
        return Refusal::AuthorityRefused { status: 0 };
    }
    plan_refusal_in(error).unwrap_or(Refusal::KeyDeclined)
}

/// One delegation in progress: the ceremony, its presses and its publisher.
struct IssuerRun<'a> {
    ceremony: &'a mut Ceremony,
    presses: &'a Receiver<Press>,
    publish: &'a mut dyn FnMut(OperatorStatus),
    vault_path: &'a Path,
}

impl IssuerRun<'_> {
    /// Publishes `refusal` as the end of the ceremony and returns `message`.
    fn refuse<T>(&mut self, refusal: Refusal, message: String) -> Result<T, String> {
        self.ceremony.refuse(refusal);
        (self.publish)(self.ceremony.status());
        Err(message)
    }

    fn done(&mut self) -> Result<(), String> {
        self.ceremony.gesture = GestureState::Done;
        (self.publish)(self.ceremony.status());
        Ok(())
    }

    /// Shows what the plan will sign; nothing is asked of a key before this.
    fn show(&mut self, plan: &IssuerPlan) {
        self.ceremony.remote = RemoteState::AwaitingOperator;
        self.ceremony.manifest = Some(AstraManifest::IssuerAuthorization(plan.manifest.clone()));
    }

    /// Asks for the one key of the delegation, for `purpose`, and connects
    /// it. `None` is an abandonment, already published.
    fn ask_key(&mut self, purpose: KeyPurpose) -> Result<Option<Box<dyn Authenticator>>, String> {
        self.ceremony.gesture = GestureState::AwaitingKey {
            index: 1,
            of: 1,
            purpose,
        };
        let offered = self.ceremony.status();
        (self.publish)(offered.clone());
        open_key(self.ceremony, self.presses, self.publish, &offered)
    }

    /// The vault is open, or about to be, and `CA-PQ` signs: nothing is
    /// cancellable from here.
    fn signing(&mut self) {
        self.ceremony.gesture = GestureState::Signing;
        (self.publish)(self.ceremony.status());
    }

    /// The ordinary path: the campaign is fetched from the relay's origin and
    /// verified, the request is checked against it, then one key approves,
    /// opens and signs, and the result is deposited on the origin.
    fn in_campaign(&mut self, operation: Id16, request: &str) -> Result<(), String> {
        let delegation = match CampaignDelegation::begin(self.vault_path, operation, now_unix()) {
            Ok(delegation) => delegation,
            Err(error) => return self.refuse(refusal_of_campaign(&error), format!("{error:#}")),
        };
        let plan = match issuer::plan(
            self.vault_path,
            request,
            Some(delegation.campaign()),
            now_unix(),
        ) {
            Ok(plan) => plan,
            Err(refusal) => return self.refuse(refusal_of_plan(&refusal), refusal.to_string()),
        };
        self.show(&plan);

        let Some(key) = self.ask_key(KeyPurpose::ApproveCampaign)? else {
            return Ok(());
        };
        self.signing();

        // Published as they are reached: the deposit is a network call, and
        // the operator sees that the delegation was signed before it.
        let mut prepared = false;
        let ceremony = &mut *self.ceremony;
        let publish = &mut *self.publish;
        // The PIN is empty for the reason `open_key` refused a transport that
        // wants one: the platform collects it in its own dialog.
        let outcome = delegation.approve_and_sign(
            self.vault_path,
            &plan,
            key.as_ref(),
            "",
            now_unix(),
            &mut |state| {
                prepared |= state == RemoteState::Prepared;
                ceremony.remote = state;
                publish(ceremony.status());
            },
        );
        drop(key);
        match outcome {
            Ok(()) => self.done(),
            Err(error) => self.refuse(refusal_of_gesture(&error, prepared), format!("{error:#}")),
        }
    }

    /// The last resort: the plan refuses a domain that has an origin, one key
    /// opens the vault, and the authorization is handed over as a file.
    fn offline(
        &mut self,
        request: &str,
        deposit: &mut dyn FnMut(OperatorArtifact),
    ) -> Result<(), String> {
        let plan = match issuer::plan(self.vault_path, request, None, now_unix()) {
            Ok(plan) => plan,
            Err(refusal) => return self.refuse(refusal_of_plan(&refusal), refusal.to_string()),
        };
        let vault = match astra_operator::store::load(self.vault_path) {
            Ok(vault) => vault,
            Err(error) => return self.refuse(Refusal::VaultUnavailable, format!("{error:#}")),
        };
        self.show(&plan);

        let Some(opened) = self.open_vault(&vault)? else {
            return Ok(());
        };
        self.sign_offline(&plan, &opened, deposit)
    }

    /// Opens the vault with any key it holds a slot for. The key is let go
    /// before this returns.
    fn open_vault(&mut self, vault: &AuthorityVault) -> Result<Option<Opened>, String> {
        let Some(key) = self.ask_key(KeyPurpose::OpenVault)? else {
            return Ok(None);
        };
        let opened =
            match astra_operator::gestures::open_with_authorized_key(key.as_ref(), vault, "") {
                Ok(opened) => opened,
                Err(error) => return self.refuse(Refusal::KeyDeclined, format!("{error:#}")),
            };
        drop(key);
        if let Ok(slot) = vault.slot_for_credential(&opened.credential_id) {
            self.ceremony.keys.push(KeySlotLabel {
                slot: "1".to_string(),
                label: slot.label.clone(),
            });
        }
        Ok(Some(opened))
    }

    /// Signs the delegation of an offline plan with the opening the key
    /// released, and hands the authorization over.
    ///
    /// The plan is settled again from the domain as it is now: a relay that
    /// gained an origin since the manifest, or any other change, refuses the
    /// signature.
    fn sign_offline(
        &mut self,
        plan: &IssuerPlan,
        opened: &Opened,
        deposit: &mut dyn FnMut(OperatorArtifact),
    ) -> Result<(), String> {
        self.signing();
        let authorization = match issuer::sign_offline(self.vault_path, plan, opened, now_unix()) {
            Ok(authorization) => authorization,
            Err(error) => return self.refuse(refusal_of_signature(&error), format!("{error:#}")),
        };
        // What `astra issuer install --authorization` reads.
        let contents = match serde_json::to_string_pretty(&authorization) {
            Ok(contents) => contents,
            Err(error) => {
                return self.refuse(
                    Refusal::Internal,
                    format!("encodage de l'autorisation : {error}"),
                )
            }
        };
        deposit(OperatorArtifact {
            file_name: AUTHORIZATION_FILE.to_string(),
            contents,
            encoding: ArtifactEncoding::Text,
            fingerprint: None,
        });
        self.done()
    }
}

#[cfg(test)]
mod tests;

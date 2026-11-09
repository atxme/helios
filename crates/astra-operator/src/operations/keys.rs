//! The keys a ceremony has proved, shared by the rotation and the revocation.
//!
//! A key is proved once, by the touch that opens the vault, before any campaign
//! exists. What it released is kept in memory until the signature, or until the
//! campaign expires, and each ceremony then asks one approval per key.

use std::marker::PhantomData;
use std::path::Path;

use aether::certificates::approval::CredentialRegistry;
use anyhow::Result;

use crate::authenticator::{Authenticator, AuthenticatorError, Opened};
use crate::gestures::{self, GestureError};
use crate::signing::ANCHOR_ROTATION_CREDENTIALS;
use crate::vault::AuthorityVault;
use crate::{credentials, store};

/// This ceremony has no way to ask for a PIN: the platform's dialog does, and the
/// value never crosses into this process. Orion refuses a transport that wants one
/// before reaching here.
pub(super) const NO_PIN: &str = "";

/// Why a key was turned down. Nothing is lost: the operator can try again.
///
/// An error type so that [`OpenedRotation::sign_and_journal`] can also say
/// [`KeyStep::Expired`], which a caller reads with `downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyStep {
    /// This key does not open the vault.
    #[error("clé absente du coffre")]
    NotEnrolled,
    /// This key opens the vault, and the credential document marks it lost or revoked:
    /// it approves nothing, and another key can take its place.
    #[error("clé marquée perdue ou révoquée")]
    NotApprovable,
    /// This key has already answered: two touches of one token are not two people.
    #[error("clé déjà utilisée")]
    Repeated,
    /// Not a key this step can take: outside the two validated, or one that has
    /// approved already, which the platform cannot tell apart once it is not offered.
    #[error("autre clé attendue")]
    NotValidated,
    /// No key answered, or the operator cancelled the gesture.
    #[error("geste de la clé annulé")]
    Declined,
    /// The campaign's window closed. Nothing was signed.
    #[error("campagne expirée")]
    Expired,
}

/// The keys proved so far, and what each one released.
///
/// Dropping it wipes the openings, which is what abandoning a ceremony comes to.
///
/// The marker removes `Send` and `Sync` from it and from whatever holds it, so these
/// openings stay on the thread of the ceremony that asked for them.
pub struct ValidatedKeys {
    pub(super) vault: AuthorityVault,
    /// The credential document beside the vault, read when the keys are validated, to
    /// turn a key marked lost down at that point. It is the local copy only. A
    /// rotation's [`open`](super::rotation::open) checks the keys again against the
    /// document it has verified under `CA-PQ`. A revocation under the outgoing anchor
    /// checks its approvals against the document Astra serves instead
    /// ([`super::revocation::open`]), so the two can differ, and the served one decides.
    pub(super) registry: Option<Box<CredentialRegistry>>,
    pub(super) openings: Vec<Opened>,
    _thread: PhantomData<*const ()>,
}

impl ValidatedKeys {
    pub fn new(vault_path: &Path) -> Result<Self> {
        Ok(Self {
            vault: store::load(vault_path)?,
            registry: credentials::load(&credentials::path_beside(vault_path))?.map(Box::new),
            openings: Vec::with_capacity(ANCHOR_ROTATION_CREDENTIALS),
            _thread: PhantomData,
        })
    }

    /// One touch: proves this key opens the anchors, and returns the label of its
    /// slot. Opens no campaign, and asks the remote nothing.
    pub fn validate(&mut self, key: &dyn Authenticator) -> Result<String, KeyStep> {
        if self.openings.len() >= ANCHOR_ROTATION_CREDENTIALS {
            return Err(KeyStep::NotValidated);
        }
        let opened = gestures::open_with_authorized_key(key, &self.vault, NO_PIN)
            .map_err(key_step_of_opening)?;
        self.keep(opened)
    }

    /// Keeps what a key released, once the checks every ceremony makes have passed.
    ///
    /// For a caller that opened the vault itself, with the one credential its
    /// approval named. Returns the label of the slot.
    pub(super) fn keep(&mut self, opened: Opened) -> Result<String, KeyStep> {
        if self.is_validated(&opened.credential_id) {
            return Err(KeyStep::Repeated);
        }
        gestures::prove_anchors_open(&self.vault, &opened).map_err(|_| KeyStep::NotEnrolled)?;
        // With no document, `open` refuses before any campaign, whatever the keys.
        if let Some(registry) = &self.registry {
            if !may_approve(registry, &opened.credential_id) {
                return Err(KeyStep::NotApprovable);
            }
        }
        let label = self
            .vault
            .slot_for_credential(&opened.credential_id)
            .map_err(|_| KeyStep::NotEnrolled)?
            .label
            .clone();
        self.openings.push(opened);
        Ok(label)
    }

    pub fn count(&self) -> usize {
        self.openings.len()
    }

    pub(super) fn is_validated(&self, credential_id: &[u8]) -> bool {
        self.openings
            .iter()
            .any(|opening| opening.credential_id == credential_id)
    }
}

/// The token did not say which credential it holds: it holds none of those offered,
/// or something got in the way of the gesture.
pub fn key_step_of_opening(error: GestureError) -> KeyStep {
    match error {
        GestureError::Authenticator(AuthenticatorError::UnknownCredential)
        | GestureError::Vault(_) => KeyStep::NotEnrolled,
        _ => KeyStep::Declined,
    }
}

/// Whether the document lets this credential approve: `active`, and nothing else.
pub(super) fn may_approve(registry: &CredentialRegistry, credential_id: &[u8]) -> bool {
    registry
        .approvable()
        .iter()
        .any(|binding| binding.credential_id == credential_id)
}

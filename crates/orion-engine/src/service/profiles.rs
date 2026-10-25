//! The profiles family: reading the configuration, importing a profile, the
//! vault's posture, the SSH command, the validation of a draft, the staged
//! keys, and saving, deleting and selecting a profile. The shell reaches them
//! through the engine.

use aether::{SecretString, TunnelState};
use orion_core::{
    complete_profile_import, inspect_profile, parse_profile_import, vault::VaultPosture,
    ClientProfile, ProfileIssues, ProtectedIdentityStore,
};

use super::certificates::now_unix;
use super::{EngineService, StagedKey, StagedPsk};
use crate::command::{ProfileDraft, SecretInput};
use crate::events::EventQueue;
use crate::view::{ConfigView, ImportOutcome, ProfileView};

/// Merges a saved draft onto what is stored, keeping every secret in Rust.
///
/// `stored` is `None` for a profile the user is creating, which is the one
/// case where a key must be generated: refusing instead would leave the
/// screen with no way at all to make a profile, and inventing an empty key
/// would produce one that fails `validate` with a message about enrolment.
pub fn merge_draft(
    draft: ProfileDraft,
    stored: Option<&ClientProfile>,
    staged: Option<&StagedKey>,
    staged_psk: Option<&StagedPsk>,
) -> Result<ClientProfile, String> {
    let stored_kind = stored.map(ClientProfile::kind);
    let mut profile = match stored {
        Some(profile) => profile.duplicate(),
        None => ClientProfile {
            name: draft.name.clone(),
            ..ClientProfile::default()
        },
    };
    if draft.use_staged_key {
        let staged = staged.ok_or(
            "aucune clé en attente : générer ou importer une clé privée avant d'enregistrer",
        )?;
        // The public half was shown, copied, and handed to the operator for
        // admission. Saving a private key that derives to anything else
        // would produce a profile whose handshakes never succeed, with
        // nothing on either side naming the cause — the gateway admitted a
        // key this profile does not hold. Re-deriving costs microseconds.
        let derived = aether::wg::public_from_private(staged.private_key.expose())
            .map_err(|error| format!("clé en attente illisible : {error}"))?;
        if derived != staged.public_key {
            return Err(
                "la clé en attente ne correspond plus à la clé publique affichée — \
                 regénérer avant d'enregistrer"
                    .into(),
            );
        }
        // The draft takes its own zeroizing copy; the staged source stays
        // protected until the caller drops it.
        profile.private_key = staged.private_key.duplicate();
    }
    if draft.use_staged_psk {
        let staged = staged_psk
            .ok_or("aucun PSK en attente : saisir le PSK statique avant d'enregistrer")?;
        // The draft owns its zeroizing PSK independently of the staging slot.
        profile.preshared_key = Some(staged.value.duplicate());
    }
    // After adoption, never before: clearing is what the screen sends when
    // the requested mode no longer tolerates a static PSK, and that verdict
    // has to apply to the value being adopted too. The other order let a
    // PSK typed under `static_psk` survive a switch to ML-KEM made in the
    // same edit.
    if draft.clear_preshared_key {
        profile.preshared_key = None;
    }
    profile.name = draft.name;
    profile.endpoint = draft.endpoint;
    profile.peer_public_key = draft.peer_public_key;
    profile.address = draft.address;
    profile.address_v6 = draft.address_v6;
    profile.allowed_ips = draft.allowed_ips;
    profile.persistent_keepalive = draft.persistent_keepalive;
    profile.heliosd_url = draft.heliosd_url;
    profile.ssh_target = draft.ssh_target;
    profile.key_negotiation = draft.key_negotiation;
    // An existing stable profile keeps its declared variant. Switching
    // between classic and Helios requires another profile identifier (spec
    // §14, §19); deriving the kind from the edited block here made deleting
    // that block a persistent downgrade. A new draft has no history and is
    // stamped from the shape the user chose before its first save.
    profile.profile_type = Some(stored_kind.unwrap_or_else(|| {
        if profile.key_negotiation.is_some() {
            orion_core::ProfileKind::HeliosKeyNegotiation
        } else {
            orion_core::ProfileKind::Classic
        }
    }));
    profile.check_kind().map_err(|error| error.to_string())?;
    // A stored profile never carries a negotiated PSK: that one only ever
    // exists in the ephemeral copy the backend mounts.
    profile.preshared_key_is_negotiated = false;
    Ok(profile)
}

/// Selects the profile that is actually being edited.
///
/// An import is a replacement transaction, not a suggestion layered over a
/// profile with the same display name. In particular, its private WireGuard
/// key and its sealed negotiation identity were issued as one pair.
pub fn profile_edit_base<'a>(
    pending_import: Option<&'a ClientProfile>,
    stored: Option<&'a ClientProfile>,
) -> Option<&'a ClientProfile> {
    pending_import.or(stored)
}

/// Completes a signed v5 document against the pending enrollment it answers.
///
/// Its signature is verified under the `CA-PQ` key pinned when the user
/// confirmed the invitation, and only then is anything sealed or shown.
fn complete_signed_document(
    document: &aether::key_negotiation::EnrollmentDocument,
    profile: orion_core::ClientProfile,
    notices: Vec<String>,
) -> Result<(orion_core::CompletedImport, bool), String> {
    let outcome = ProtectedIdentityStore::for_current_user()
        .and_then(|store| {
            orion_core::enrollment::complete_enrollment(&store, document, profile, now_unix())
        })
        // `{:#}` keeps the anyhow context chain: the reason is the useful half.
        .map_err(|error| format!("{error:#}"))?;
    let sealed = matches!(
        outcome,
        orion_core::enrollment::EnrollmentOutcome::Completed { .. }
    );
    Ok((
        orion_core::CompletedImport::from_enrollment(outcome, notices),
        sealed,
    ))
}

/// Destroys the pending enrollment record once its profile is saved.
///
/// The profile is already persisted when this runs, so a failure is not a
/// failed save: the record left behind holds sealed keys the user can still
/// discard from the enrollment list.
fn settle_saved_enrollment(identity: &str) {
    if let Err(error) = ProtectedIdentityStore::for_current_user()
        .and_then(|store| orion_core::enrollment::settle_enrollment(&store, identity))
    {
        tracing::warn!(error = %format!("{error:#}"), "pending enrollment record kept after save");
    }
}

impl EngineService {
    pub async fn get_config(&self) -> Result<ConfigView, String> {
        Ok(ConfigView::from(&*self.config.lock().await))
    }

    /// Decodes a document chosen by the user without persisting it.
    ///
    /// The UI displays the result as a draft: a valid file therefore never
    /// silently replaces a profile with the same name. The identity, on the other
    /// hand, is sealed straight away — it is a secret, and the shorter it stays
    /// in memory the better.
    pub async fn import_profile(
        &self,
        contents: &str,
        file_name: &str,
    ) -> Result<ImportOutcome, String> {
        let imported =
            parse_profile_import(contents, file_name).map_err(|error| error.to_string())?;
        self.finish_import(imported).await
    }

    /// Completes the draft and reports what became of it.
    ///
    /// Shared by the two import paths on purpose: the file picker and the system
    /// association must not differ by one gesture — a document that seals its
    /// identity on a double-click and not through the button would be
    /// impossible to explain.
    async fn finish_import(
        &self,
        imported: orion_core::ProfileImport,
    ) -> Result<ImportOutcome, String> {
        if let Some(document) = &imported.enrollment {
            let (completed, identity_sealed) =
                complete_signed_document(document, imported.profile, imported.notices)?;
            return Ok(self.stage_import(completed, identity_sealed).await);
        }
        let mut completed = {
            let config = self.config.lock().await;
            complete_profile_import(imported.profile, &config, imported.notices)
                .map_err(|error| error.to_string())?
        };

        // The staged key is the missing candidate.
        //
        // `complete_profile_import` looks among **saved** profiles, which is
        // exactly where a key generated three minutes ago is not: it sits in the
        // staging slot, waiting for a save that cannot happen until this import
        // completes. The staged key is the one the user just obtained for this
        // very purpose, so adopting it is what they meant.
        if completed.profile.private_key.is_empty() {
            if let Some(staged) = self.staged_key.lock().await.take() {
                // Transfer an explicit zeroizing copy into the completed import;
                // `staged` is dropped immediately afterwards.
                completed.profile.private_key = staged.private_key.duplicate();
                completed.private_key_missing = None;
            }
        }

        // The vault never opened: the profile list this import was matched against
        // is empty because nothing was read, not because nothing matches. Blaming
        // the document here sends the user to look for a key they may well have.
        if completed.private_key_missing.is_some() {
            if let Some(cause) = &self.vault_error {
                completed.private_key_missing = Some(format!(
                    "le coffre de ce poste n'a pas pu être ouvert ({cause}), donc aucun profil \
                     enregistré n'a été lu : le document n'est pas en cause. Corriger l'accès au \
                     coffre, puis réimporter."
                ));
            }
        }
        Ok(self.stage_import(completed, false).await)
    }

    /// Keeps the draft's private key in the backend and returns its redacted view.
    async fn stage_import(
        &self,
        completed: orion_core::CompletedImport,
        identity_sealed: bool,
    ) -> ImportOutcome {
        // The draft goes to the screen redacted; its private key stays here until
        // the user saves. Returning it whole is what put a WireGuard private key
        // into the WebView in the first place (ADR-006 §5).
        let view = ProfileView::from(&completed.profile);
        self.pending_imports
            .lock()
            .await
            .insert(completed.profile.name.clone(), completed.profile);

        ImportOutcome {
            profile: view,
            identity_sealed,
            private_key_missing: completed.private_key_missing,
            incomplete: completed.incomplete,
            notices: completed.notices,
        }
    }

    /// Public key corresponding to a profile's private key.
    ///
    /// This is what the user communicates to the operator to be admitted on the
    /// gateway (ADR-004 §6): deriving it here avoids making them manipulate
    /// their private key in a terminal to obtain a value that is, itself, public.
    /// What the vault can honestly claim about itself (ADR-006 §3).
    ///
    /// Read on every call rather than cached: BitLocker can be suspended and the
    /// memory-lock privilege can change while Orion runs, and a posture panel that
    /// showed a stale "protected" would be worse than one that showed nothing.
    pub fn vault_posture(&self) -> Result<VaultPosture, String> {
        Ok(self.store.posture())
    }

    /// Persists the user's informed choice to keep profiles on a bare volume.
    ///
    /// This command is deliberately separate from import/save: the interface must
    /// first state the guarantees being withdrawn, and an ordinary write must
    /// never turn a missing BitLocker posture into consent by itself.
    pub fn allow_unencrypted_volume(&self) -> Result<VaultPosture, String> {
        let posture = self.store.posture();
        if posture.volume_protected || posture.unencrypted_volume_waived {
            return Ok(posture);
        }
        self.store
            .persist_unencrypted_volume_waiver()
            .map_err(|error| error.to_string())?;
        tracing::warn!(
            "CHIFFREMENT DE VOLUME NON EXIGÉ après confirmation dans Orion — les anciens blocs disque, le fichier d'échange et celui d'hibernation ne sont pas couverts"
        );
        Ok(self.store.posture())
    }

    /// Reports the faulty fields of a profile being edited.
    ///
    /// Validation stays **on the Rust side**: the UI highlights what the core
    /// refuses, it doesn't reimplement its rules. Two rule sets would eventually
    /// diverge, and the UI would accept values the connection rejects.
    pub async fn validate_profile(&self, draft: ProfileDraft) -> Result<ProfileIssues, String> {
        // Merged against what is stored before judging: the draft carries no
        // private key by construction, so inspecting it on its own would report
        // "clé privée requise" on every profile that has one — a red field the
        // user cannot clear, on a value they are not allowed to see.
        let cfg = self.config.lock().await;
        // The pending import is the profile being edited, even when it replaces a
        // stored profile with the same name. Looking at the stored key here would
        // report a valid replacement as if its new negotiation identity belonged
        // to the old WireGuard key, then `save_profile` would persist that split.
        // Peeked, not removed: validation runs on every keystroke.
        let pending = self
            .pending_imports
            .lock()
            .await
            .get(&draft.name)
            .map(ClientProfile::duplicate);
        let known = cfg.find(&draft.name);
        let stored = profile_edit_base(pending.as_ref(), known);
        // Validation runs on every keystroke: the staged secrets are read, never
        // taken.
        let staged = self.staged_key.lock().await;
        let staged_psk = self.staged_psk.lock().await;
        let profile = merge_draft(draft, stored, staged.as_ref(), staged_psk.as_ref())?;
        if let Some(known) = known {
            profile
                .check_replacement_of(known)
                .map_err(|error| error.to_string())?;
        }
        Ok(inspect_profile(&profile))
    }

    /// The same command line, for the user to paste into their own terminal.
    ///
    /// Kept beside the shell's `open_ssh_terminal` rather than replaced by it:
    /// the launcher legitimately refuses on machines with no standard-user
    /// token — UAC off, the built-in Administrator account, a service context —
    /// and on those the copy is the whole feature rather than a consolation.
    pub async fn ssh_command(&self, name: Option<String>) -> Result<String, String> {
        let target = self.resolve_ssh_target(name).await?;
        Ok(format!("ssh {target}"))
    }

    /// Resolves the SSH destination, and checks it is safe to act on.
    ///
    /// Shared by the two commands below, because they must agree on every gate:
    /// one launches a terminal, the other only copies a line, and a destination
    /// good enough for the second is exactly the one good enough for the first.
    ///
    /// The tunnel must be up — the gateway answers SSH on its tunnel address
    /// alone, and the host could otherwise resolve to something else entirely on
    /// the clear network. And the destination is re-validated here even though
    /// import and save already did: this is where a profile field stops being
    /// data and starts being a command line.
    async fn resolve_ssh_target(&self, name: Option<String>) -> Result<String, String> {
        let cfg = self.config.lock().await;
        let profile = match &name {
            Some(name) => cfg.find(name),
            None => cfg.selected.as_deref().and_then(|s| cfg.find(s)),
        }
        .ok_or("aucun profil sélectionné")?;
        let target = profile
            .ssh_target
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(
                "ce profil ne déclare aucune destination SSH — la renseigner dans « Profils → \
                 Avancé → Destination SSH »",
            )?;
        drop(cfg);

        let target = target.trim().to_string();
        orion_core::profile_import::validate_ssh_target(&target)
            .map_err(|error| error.to_string())?;

        if self.controller.state() != TunnelState::Up {
            return Err(
                "le tunnel n'est pas monté : la gateway n'est joignable en SSH qu'à travers lui"
                    .into(),
            );
        }
        Ok(target)
    }

    /// Draws a WireGuard key pair and returns its **public** half.
    ///
    /// The private half stays in the engine's staged-key slot until the profile
    /// is saved. Returning the public key straight away is what makes the enrolment
    /// workflow possible at all: the user copies it, hands it to the operator, and
    /// receives an admitted profile — none of which can happen if the key only
    /// comes into existence when the form is submitted.
    pub async fn generate_private_key(&self) -> Result<String, String> {
        let pair = aether::wg::generate_keypair()
            .map_err(|error| format!("génération de la paire de clés : {error}"))?;
        let aether::wg::Keypair {
            private_key,
            public_key,
        } = pair;
        let returned_public_key = public_key.clone();
        *self.staged_key.lock().await = Some(StagedKey {
            private_key,
            public_key,
        });
        Ok(returned_public_key)
    }

    /// Adopts a private key the user supplies, and returns its public half.
    ///
    /// # Why this exists, having been refused once
    ///
    /// An earlier revision removed every way of entering a key, on the grounds
    /// that one arriving through the interface has crossed JavaScript. That is
    /// true, and it is a real cost — but it left no path for the ordinary case of
    /// a key produced by `wg genkey` or carried by an existing `wg-quick` file, and
    /// a client that cannot accept an existing identity is not a client.
    ///
    /// The direction is what makes this acceptable. A key **entering** crosses the
    /// IPC once, at an explicit gesture, and the field is cleared immediately
    /// after. A key **leaving** would sit in the DOM for as long as the screen
    /// lives, on every render, for a value nobody asked to see. ADR-006 §5 forbids
    /// the second; this is not it.
    ///
    /// Validation happens here rather than on screen: `orion-core` owns the rules,
    /// and a key the interface accepted but the core refuses would be a profile
    /// that fails at connection time with a message about enrolment.
    pub async fn adopt_private_key(&self, private_key: SecretInput) -> Result<String, String> {
        // The `SecretInput` it came in is zeroized when this call returns;
        // `trim().to_owned()` makes the one remaining copy, held in a zeroizing
        // container at once.
        let normalized = SecretString::new(private_key.expose().trim().to_owned());
        let public_key = aether::wg::public_from_private(normalized.expose()).map_err(|_| {
            "clé privée invalide : une clé WireGuard est 32 octets encodés en base64 \
             (44 caractères finissant par « = »)"
                .to_string()
        })?;
        *self.staged_key.lock().await = Some(StagedKey {
            private_key: normalized,
            public_key: public_key.clone(),
        });
        Ok(public_key)
    }

    /// Drops the staged key without saving it.
    pub async fn discard_staged_key(&self) -> Result<(), String> {
        // `Drop` zeroizes it: cancelling must not leave the key in memory for the
        // rest of the session.
        self.staged_key.lock().await.take();
        Ok(())
    }

    /// Holds a static PSK the user supplies, until the profile is saved.
    ///
    /// Validated here and not on screen, for the reason [`Self::adopt_private_key`]
    /// gives: `aether` owns the shape of a WireGuard secret, and a value the
    /// interface accepted but WireGuard refuses would produce a profile whose
    /// handshakes fail with nothing naming the cause. A PSK is a 32-byte base64
    /// value — the same shape as a key, which is why the same validator answers.
    ///
    /// Nothing is returned but success: unlike a key pair there is no public half
    /// to show, and echoing the secret back would put it in the DOM for the life
    /// of the screen.
    pub async fn adopt_preshared_key(&self, preshared_key: SecretInput) -> Result<(), String> {
        let value = SecretString::new(preshared_key.expose().trim().to_owned());
        aether::wg::validate_key(value.expose()).map_err(|_| {
            "PSK invalide : un PSK WireGuard est 32 octets encodés en base64 \
             (44 caractères finissant par « = »), tel que le produit `wg genpsk`"
                .to_string()
        })?;
        *self.staged_psk.lock().await = Some(StagedPsk { value });
        Ok(())
    }

    /// Drops the staged PSK without saving it.
    pub async fn discard_staged_psk(&self) -> Result<(), String> {
        self.staged_psk.lock().await.take();
        Ok(())
    }

    /// Merges a draft onto the stored profile and seals the result.
    ///
    /// The volume-encryption gate is here rather than in the store because this is
    /// the moment a secret is about to be written: ADR-006 §3 makes BitLocker a
    /// **verified prerequisite**, not a recommendation, because application
    /// encryption reaches neither the old SSD blocks nor the hibernation file.
    pub async fn save_profile(&self, draft: ProfileDraft) -> Result<ConfigView, String> {
        let mut cfg = self.config.lock().await;
        self.require_protected_volume()?;
        // A pending import wins over the stored profile of the same name. An
        // imported document may carry a *new* WireGuard private key together
        // with a newly sealed key-negotiation identity. Keeping the old profile
        // here would pair those two identities from different admissions: the
        // gateway accepts the TLS certificate, then rejects the request because
        // its WireGuard key is the old one. Ordinary edits never have a pending
        // import, so they still use the stored profile and preserve its secrets.
        let pending = self.pending_imports.lock().await.remove(&draft.name);
        let known = cfg.find(&draft.name);
        let stored = profile_edit_base(pending.as_ref(), known);
        // Taken, not peeked: the key is now the profile's, and leaving a copy in
        // the slot would let the next profile saved adopt it too.
        let staged = self.staged_key.lock().await.take();
        let staged_psk = self.staged_psk.lock().await.take();
        let profile = merge_draft(draft, stored, staged.as_ref(), staged_psk.as_ref())?;
        if let Some(known) = known {
            profile
                .check_replacement_of(known)
                .map_err(|error| error.to_string())?;
        }
        let selected = profile.name.clone();
        self.store
            .save_profile(&profile)
            .map_err(|e| e.to_string())?;
        if let Some(block) = &profile.key_negotiation {
            settle_saved_enrollment(&block.identity);
        }
        cfg.upsert(profile).map_err(|error| error.to_string())?;
        cfg.selected = Some(selected.clone());
        self.store.select(&selected).map_err(|e| e.to_string())?;
        Ok(ConfigView::from(&*cfg))
    }

    /// Removes a profile, unmounting its tunnel first if that tunnel is the one up.
    ///
    /// The order is the whole point (spec §12.2). The signed `release` that frees
    /// the gateway's PSK slot travels **inside** the tunnel and is signed by the
    /// profile's own identity, so it has to leave before either disappears.
    /// Deleting first left the slot held until the gateway reclaimed it on
    /// handshake silence, five minutes later — and left the adapter mounted for a
    /// profile that no longer existed.
    pub async fn delete_profile(
        &self,
        name: String,
        events: &EventQueue,
    ) -> Result<ConfigView, String> {
        // Before the configuration lock, not after: the disconnection is a network
        // round trip, and `stop_connection` rebuilds nothing that needs the config
        // — but holding a lock across it would stall every other command for the
        // two seconds the release is allowed.
        if self.controller.mounted_profile().await.as_deref() == Some(name.as_str()) {
            self.stop_connection(events.sink()).await?;
        }
        let mut cfg = self.config.lock().await;
        self.store
            .remove_profile(&name)
            .map_err(|e| e.to_string())?;
        cfg.remove(&name);
        Ok(ConfigView::from(&*cfg))
    }

    /// Selects a profile that is in the configuration.
    ///
    /// The tray's connect gesture selects through this command too, and it needs
    /// the unknown name refused here: the store would otherwise accept a name it
    /// does not hold and the connection would fail later without naming it.
    pub async fn select_profile(&self, name: String) -> Result<ConfigView, String> {
        let mut cfg = self.config.lock().await;
        if cfg.find(&name).is_none() {
            return Err(format!("profil « {name} » introuvable"));
        }
        self.store.select(&name).map_err(|e| e.to_string())?;
        cfg.selected = Some(name);
        Ok(ConfigView::from(&*cfg))
    }

    /// Refuses to write a secret onto a volume nothing encrypts (ADR-006 §3).
    ///
    /// `Indeterminate` refuses just like `Unprotected`: a posture we cannot
    /// establish is a posture we cannot promise, and the failure mode of guessing
    /// "probably fine" is a user believing their disk is protected when it is not.
    fn require_protected_volume(&self) -> Result<(), String> {
        self.store.may_write_secrets().map_err(|error| {
            format!(
                "{error} `danger_allow_unencrypted_volume = true` dans settings.toml l'autorise \
                 explicitement, en retirant la couverture des anciens blocs disque et du fichier \
                 d'hibernation."
            )
        })
    }
}

#[cfg(test)]
mod tests;

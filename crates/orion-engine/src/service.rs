//! The engine's tunnel state, built once at start-up.
//!
//! [`EngineService::open`] assembles what the tunnel needs: the controller with
//! its protected identities, and the vault with the configuration read from it.
//! The shell's commands reach these fields; their bodies stay where they are.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
};

use aether::SecretString;
use orion_core::{
    backend::EventSink, protected_root::EnginePaths, telemetry, ClientConfig, ClientProfile,
    ProtectedIdentityStore, VpnBackend, VpnController,
};
use tokio::sync::{watch, Mutex};

use crate::command::{EngineCommand, EngineReply};
use crate::events::EventQueue;
use crate::serve::Engine;

mod app;
pub mod certificates;
mod connection;
mod profiles;
pub use app::PROFILE_EXTENSION;
pub use profiles::{merge_draft, profile_edit_base};

/// The tunnel-side state of the engine, held for the life of the process.
///
/// Fields stay public while the shell's commands still reach them; each one
/// closes when its family moves into the service.
pub struct EngineService {
    pub controller: Arc<VpnController>,
    /// Vault-backed store. `config` below is the in-memory view the UI reads;
    /// this is what actually persists, and it never writes a secret in the
    /// clear (ADR-006 §3).
    pub store: Arc<orion_core::vault::ProfileStore>,
    pub config: Arc<Mutex<ClientConfig>>,
    pub telemetry: Arc<TelemetryManager>,
    /// Serializes the expensive benchmark. The UI disables its button, but
    /// the Rust boundary still refuses a second IPC invocation so two tests
    /// cannot divide the same path and both report half of its capacity.
    pub speedtest: Mutex<()>,
    /// Imported profiles the user has not saved yet, keyed by display name.
    ///
    /// # Why the secret waits here rather than on screen
    ///
    /// An import produces a **draft**: the user reviews the endpoint and the
    /// pinned fingerprint before committing, and a valid file must not silently
    /// replace a profile of the same name. That review used to happen with the
    /// private key sitting in a WebView text field, because the draft was
    /// returned whole to JavaScript.
    ///
    /// The draft still goes to the screen — redacted — and the key it carries
    /// waits here instead, for the one gesture that follows. `save_profile`
    /// takes it; anything else drops it when Orion closes, which loses nothing:
    /// the document can be imported again.
    pub pending_imports: Arc<Mutex<std::collections::HashMap<String, ClientProfile>>>,
    /// The key the user just generated or pasted, waiting to be saved.
    ///
    /// # The workflow this exists for
    ///
    /// Admission is out of band (ADR-004 §6): the user needs a **public** key
    /// to hand the operator *before* a profile can be completed, since the
    /// gateway must admit it before the first handshake. Producing that key
    /// only at save time made the screen show a dash where the value belonged,
    /// and left no way to copy it.
    ///
    /// So the key is drawn on the spot and its public half returned at once —
    /// visible, copiable, and stable until the profile is saved. The private
    /// half stays here. One slot rather than a map: the screen edits one
    /// profile at a time, and a slot that could hold two keys would eventually
    /// attach the wrong one.
    pub staged_key: Arc<Mutex<Option<StagedKey>>>,
    /// Static PSK entered on screen, held until the profile is saved.
    ///
    /// Same slot discipline as [`Self::staged_key`] and the same reason: the
    /// secret crosses the IPC once, at an explicit gesture, and never comes
    /// back out. `None` means "no new PSK this session" — whatever the profile
    /// already held is left alone.
    pub staged_psk: Arc<Mutex<Option<StagedPsk>>>,
    /// Why the vault could not be opened at startup, if it could not.
    ///
    /// Orion keeps running — the screen is more useful than a blank window —
    /// but on an empty profile list, and that emptiness poisons every later
    /// diagnosis. An import then concludes that no key of this machine matches
    /// the admitted one, which is false: the machine's keys were never read.
    /// Carrying the cause lets those messages say so.
    pub vault_error: Option<String>,
    /// The handshake-inference loop of the current connection, if one runs.
    ///
    /// One at a time, like telemetry, and for the same reason: each connection
    /// starts one, and a connection that failed leaves a loop with nothing left
    /// to infer. Without this slot every attempt piled up another task polling
    /// the adapter every three seconds for the life of the process.
    pub handshake_poll: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Where this run writes its log, when it writes one.
    ///
    /// A release build has no console (`windows_subsystem = "windows"`), so the
    /// file is the only trace left of a start that went wrong — and a path
    /// nobody can find is a file nobody reads. The About box states it.
    pub log_path: Option<PathBuf>,
    /// Last certificate action that failed, per profile — the «dernière
    /// erreur» spec §12.2 asks the Certificates surface to display.
    ///
    /// In memory rather than persisted: it describes an attempt made in this
    /// session, and a message surviving a restart would outlive the situation
    /// it described — an identity imported since, a store now available.
    pub last_certificate_error: Arc<Mutex<std::collections::HashMap<String, String>>>,
    /// Renewals opened in this session, by profile name.
    ///
    /// Held in memory and nowhere else, because the session carries the
    /// candidate **private keys**. That is what makes an abandoned renewal
    /// leave nothing behind: closing Orion drops them, the authority's
    /// operation expires on its own, and the active generation was never
    /// touched. The cost is that a restart reopens rather than resumes — the
    /// cheap failure, since nothing was committed.
    pub renewals: Arc<Mutex<std::collections::HashMap<String, InFlightRenewal>>>,
    /// One automatic renewal timer for the mounted profile. It is cancelled
    /// with the connection so reconnecting cannot leave stale tasks racing a
    /// newer profile.
    pub certificate_renewal_task: Arc<StdMutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Recoveries of expired identities in progress (§7.5).
    ///
    /// A separate map, for the same reason Astra keeps a separate store: a
    /// recovery reaches past a validity period, and an identifier from one
    /// must never resolve where an ordinary renewal is resumed. Absence
    /// carries the rule; a comparison would only describe it.
    pub recoveries: Arc<Mutex<std::collections::HashMap<String, InFlightRecovery>>>,
    /// Version of the application the engine runs in, for the About box.
    ///
    /// Passed in by the shell: a crate-level `CARGO_PKG_VERSION` here would
    /// report the engine's own version, not the one the user installed.
    app_version: &'static str,
}

impl EngineService {
    /// Builds the engine's tunnel state on `paths`.
    ///
    /// Only the protected identity store is still resolved from the current
    /// user; the vault and the configuration live under `paths.vault`. A vault
    /// that cannot be read leaves an empty configuration and records why in
    /// [`EngineService::vault_error`]. `app_version` is the shell's version,
    /// reported by the About box.
    pub fn open(
        paths: EnginePaths,
        backend: Arc<dyn VpnBackend>,
        log_path: Option<PathBuf>,
        app_version: &'static str,
    ) -> Result<Arc<Self>, String> {
        let controller = VpnController::new(backend);
        // The protected identity store is the platform's: `orion-core` states
        // the boundary, the platform implementation lives with the platform.
        let controller = match ProtectedIdentityStore::for_current_user() {
            Ok(store) => controller.with_key_negotiation_identities(Arc::new(store)),
            Err(error) => {
                // Not fatal: profiles without negotiation still connect, and the
                // Profiles screen reports the missing store rather than letting
                // the failure surface as an unexplained refused connection.
                tracing::warn!(%error, "no protected identity store on this machine");
                controller
            }
        };
        let controller = Arc::new(controller);

        // Le stockage des profils passe par le coffre (ADR-006 §3) : `profiles.toml`
        // n'est plus qu'un format d'import. Hors Windows le fournisseur refuse, et
        // c'est le comportement spécifié — écrire la racine en clair offrirait une
        // protection que l'écran promettrait sans la rendre.
        let store_dir = paths.vault;

        // Le contournement matériel est un choix local, lu à chaque démarrage. Un
        // fichier illisible ne l'active jamais : appliquer la valeur permissive
        // parce qu'une lecture a échoué est la façon dont une dégradation arrive
        // sans que personne l'ait décidée.
        let (settings, complaint) = orion_core::vault::LocalSettings::load(&store_dir);
        if let Some(complaint) = complaint {
            tracing::warn!(%complaint, "réglages locaux du coffre");
        }
        let waived = settings.danger_allow_software_keystore;
        let bare_volume = settings.danger_allow_unencrypted_volume;

        let store = Arc::new(
            orion_core::vault::ProfileStore::new(
                store_dir.clone(),
                Box::new(
                    orion_core::vault::windows::PlatformRootKeyProvider::new(
                        store_dir.join("device-root"),
                    )
                    .allowing_software_keystore(waived),
                ),
            )
            .allowing_software_keystore(waived)
            .allowing_unencrypted_volume(bare_volume),
        );

        // Deux situations opposées, deux messages. Les confondre créditerait
        // l'opérateur d'une décision qu'il n'a pas prise, ou masquerait celle
        // qu'il a prise (ADR-006 §3).
        if waived {
            // À **chaque** démarrage, pas seulement à l'activation : une
            // dégradation qui ne se rappelle plus finit par être oubliée.
            tracing::warn!(
                "SÉCURITÉ MATÉRIELLE DÉSACTIVÉE par danger_allow_software_keystore — \
                 la résistance à la copie inter-machine, au rollback matériel et à un \
                 administrateur de domaine détenant les clés DPAPI n'est plus assurée"
            );
        } else if !store.probe_hardware_root() {
            tracing::error!(
                "aucune racine matérielle sur ce poste et aucun contournement déclaré — \
                 Orion refuse de conserver des secrets. Poser \
                 `danger_allow_software_keystore = true` dans {} l'autorise \
                 explicitement, en retirant les garanties correspondantes",
                store_dir
                    .join(orion_core::vault::settings::SETTINGS_FILE)
                    .display()
            );
        }
        // Une configuration héritée est reprise dans le coffre avant tout usage, et
        // ses profils restent bloqués jusqu'à rotation de clé : le sceller ne
        // rappelle pas les copies déjà parties en sauvegarde.
        //
        // La migration est conditionnée au chiffrement du volume (ADR-006 §3) :
        // elle réécrit le secret ailleurs sur le même disque, et sur un volume nu
        // cela le recopie sans retirer l'ancien. Mieux vaut laisser le fichier
        // hérité en place, visible dans la posture, que produire une seconde copie
        // en croyant l'avoir protégée.
        if bare_volume {
            // À chaque démarrage, comme pour le coffre logiciel : une dégradation
            // qui cesse de se rappeler finit par être oubliée.
            tracing::warn!(
                "CHIFFREMENT DE VOLUME NON EXIGÉ par danger_allow_unencrypted_volume — \
                 les anciens blocs disque, le fichier d'échange et celui d'hibernation ne sont \
                 pas couverts"
            );
        }
        if let Err(error) = store.may_write_secrets() {
            tracing::error!(
                %error,
                "migration du fichier hérité suspendue. `danger_allow_unencrypted_volume = true` \
                 dans {} l'autorise explicitement",
                store_dir
                    .join(orion_core::vault::settings::SETTINGS_FILE)
                    .display()
            );
        } else {
            match store.migrate_legacy() {
                Ok(report) if !report.migrated.is_empty() => tracing::warn!(
                    profils = ?report.rotation_required,
                    "profils repris du fichier en clair — rotation de clé obligatoire"
                ),
                Ok(_) => {}
                Err(error) => tracing::error!(%error, "migration du fichier hérité impossible"),
            }
        }
        // A vault that would not open leaves Orion running on an **empty** profile
        // list, and every later message then reasons from that emptiness: an import
        // reports that no key of this machine matches the admitted one, when the
        // truth is that the machine's keys were never read. The cause is recorded
        // so those messages can name it instead of blaming the document.
        let mut vault_error = None;
        let config = store.load().unwrap_or_else(|error| {
            tracing::error!(%error, "coffre illisible — aucun profil chargé");
            vault_error = Some(error.to_string());
            ClientConfig::default()
        });

        Ok(Arc::new(Self {
            controller,
            store,
            config: Arc::new(Mutex::new(config)),
            telemetry: Arc::new(TelemetryManager::default()),
            speedtest: Mutex::new(()),
            pending_imports: Arc::new(Mutex::new(std::collections::HashMap::new())),
            staged_key: Arc::new(Mutex::new(None)),
            staged_psk: Arc::new(Mutex::new(None)),
            handshake_poll: StdMutex::new(None),
            vault_error,
            log_path,
            last_certificate_error: Arc::new(Mutex::new(std::collections::HashMap::new())),
            renewals: Arc::new(Mutex::new(std::collections::HashMap::new())),
            certificate_renewal_task: Arc::new(StdMutex::new(None)),
            recoveries: Arc::new(Mutex::new(std::collections::HashMap::new())),
            app_version,
        }))
    }
}

/// One recovery in progress: the session that drives it, and its profile.
pub struct InFlightRecovery {
    pub session: orion_core::certificate_recovery::RecoverySession,
    pub settings: orion_core::KeyNegotiationSettings,
}

/// One renewal in progress: what drives it, and the state it writes into.
pub struct InFlightRenewal {
    pub session: orion_core::certificate_renewal::RenewalSession,
    pub store: orion_core::certificates::TrustStore,
    pub settings: orion_core::KeyNegotiationSettings,
    /// The approval request, once read and verified.
    ///
    /// Held between the read and the ceremony so that what is signed is what
    /// was shown: a screen that displayed one manifest and then re-fetched
    /// before touching the key would be asking for a touch on something the
    /// user never saw.
    pub approval: Option<orion_core::certificate_approval::VerifiedApproval>,
}

/// A WireGuard key pair held between its creation and its save.
///
/// Never `Clone`, never `Serialize`: only [`StagedKey::public_key`] is meant to
/// leave this process, and it does so as a plain `String` the caller asks for
/// explicitly (ADR-006 §5).
pub struct StagedKey {
    pub private_key: SecretString,
    pub public_key: String,
}

/// A static PSK held between the moment it is typed and the save.
///
/// Nothing of it is meant to leave this process — not even a public half, for
/// there is none. The screen learns only that a value is waiting.
pub struct StagedPsk {
    pub value: SecretString,
}

/// Answer to a command the engine does not serve yet. Each family that moves
/// into the engine replaces its arms below; the generic one goes away with the
/// last family.
const NOT_SERVED: &str = "Cette commande n'est pas servie par le moteur.";

#[async_trait::async_trait]
impl Engine for EngineService {
    async fn handle(
        &self,
        command: EngineCommand,
        events: &EventQueue,
    ) -> Result<EngineReply, String> {
        match command {
            EngineCommand::GetState => Ok(EngineReply::State(self.get_state())),
            EngineCommand::BackendKind => Ok(EngineReply::Backend(self.backend_kind().to_string())),
            EngineCommand::AdapterIsUp => Ok(EngineReply::Flag(self.adapter_is_up())),
            EngineCommand::AboutOrion => Ok(EngineReply::About(self.about_orion())),
            EngineCommand::KeyNegotiationSupport => {
                Ok(EngineReply::KeyNegotiation(self.key_negotiation_support()))
            }
            EngineCommand::RunSpeedTest { mode } => self
                .run_speed_test(mode, events)
                .await
                .map(EngineReply::SpeedTest),
            EngineCommand::Connect { name } => self
                .start_connection(events, name)
                .await
                .map(|()| EngineReply::Unit),
            EngineCommand::Disconnect => self
                .stop_connection(events.sink())
                .await
                .map(|()| EngineReply::Unit),
            EngineCommand::RenewPsk => self.renew_psk(events).await.map(|()| EngineReply::Unit),
            EngineCommand::GetConfig => self.get_config().await.map(EngineReply::Config),
            EngineCommand::ImportProfile {
                contents,
                file_name,
            } => self
                .import_profile(contents.expose(), &file_name)
                .await
                .map(EngineReply::Imported),
            EngineCommand::VaultPosture => self.vault_posture().map(EngineReply::VaultPosture),
            EngineCommand::AllowUnencryptedVolume => self
                .allow_unencrypted_volume()
                .map(EngineReply::VaultPosture),
            EngineCommand::SshCommand { name } => {
                self.ssh_command(name).await.map(EngineReply::SshCommand)
            }
            EngineCommand::ValidateProfile { draft } => {
                self.validate_profile(draft).await.map(EngineReply::Issues)
            }
            // Served by the transport before it reaches the engine.
            EngineCommand::Shutdown => Ok(EngineReply::Unit),
            EngineCommand::ImportProfilePath { .. }
            | EngineCommand::GeneratePrivateKey
            | EngineCommand::AdoptPrivateKey { .. }
            | EngineCommand::DiscardStagedKey
            | EngineCommand::AdoptPresharedKey { .. }
            | EngineCommand::DiscardStagedPsk
            | EngineCommand::SaveProfile { .. }
            | EngineCommand::DeleteProfile { .. }
            | EngineCommand::SelectProfile { .. }
            | EngineCommand::PreviewEnrollmentInvitation { .. }
            | EngineCommand::BeginEnrollment { .. }
            | EngineCommand::ListPendingEnrollments
            | EngineCommand::ExportPendingRequest { .. }
            | EngineCommand::DiscardPendingEnrollment { .. }
            | EngineCommand::CertificateInventory { .. }
            | EngineCommand::CertificateOverview
            | EngineCommand::CertificateActions { .. }
            | EngineCommand::RunCertificateAction { .. }
            | EngineCommand::ResumeCertificateRecovery { .. }
            | EngineCommand::CertificateApprovalManifest { .. }
            | EngineCommand::ApproveCertificateRenewal { .. }
            | EngineCommand::CertificateApprovalNeedsPin { .. }
            | EngineCommand::LastCertificateError { .. } => Err(NOT_SERVED.into()),
        }
    }

    /// Disconnects and stops what the connection started. The event side is
    /// discarded: the UI that would have listened has gone. Idempotent.
    async fn teardown(&self) {
        let discard: EventSink = Arc::new(|_| {});
        if let Err(error) = self.stop_connection(discard).await {
            tracing::warn!(%error, "déconnexion à la fermeture du moteur");
        }
    }
}

/// Manages the telemetry task's lifecycle (only one active at a time).
#[derive(Default)]
pub struct TelemetryManager {
    cancel: StdMutex<Option<watch::Sender<bool>>>,
}

impl TelemetryManager {
    /// Starts a telemetry loop toward `url`, cancelling any previous one.
    pub fn start(&self, url: String, sink: EventSink) {
        self.stop();
        let (tx, rx) = watch::channel(false);
        *self
            .cancel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tx);
        tokio::spawn(telemetry::run(url, sink, rx));
    }

    /// Cancels the current telemetry loop, if any.
    pub fn stop(&self) {
        if let Some(tx) = self
            .cancel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = tx.send(true);
        }
    }
}

#[cfg(test)]
mod tests;

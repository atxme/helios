//! Certificate work the tunnel starts on its own: the trust refresh asked
//! once per connection, the automatic renewal that follows it, and the
//! renewal step both share. The shell's commands reach the same renewal map
//! through [`drive_renewal_in_map`].

use std::sync::Arc;

use aether::TunnelState;
use orion_core::{backend::EventSink, ClientEvent, VpnController};
use tokio::sync::Mutex;

use super::InFlightRenewal;
use crate::view::RenewalProgress;

/// Wall clock in Unix seconds, for the lifecycle's own arithmetic.
///
/// A clock behind the certificate's `not_before` reads as "not yet valid" and
/// one far ahead reads as expired, which is exactly what the connection would
/// conclude: the panel is wrong in the same direction as the failure, rather
/// than reassuring while the handshake refuses.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Asks the gateway, once per connection, whether this profile is behind.
///
/// # Why it is spawned and never awaited
///
/// It runs from the event sink, which the tunnel's own state machine drives. A
/// trust update that blocked there would make a gateway that accepts the
/// connection and then stalls hold up the client's notion of being connected —
/// the update is a convenience, the tunnel is the product.
///
/// Every outcome is said in the log the user actually reads, including the
/// refusals: a client that silently never catches up on a revocation is the
/// one failure this whole path exists to prevent, and «nothing happened» is
/// indistinguishable from «nothing was owed» unless one of them is written
/// down.
pub fn spawn_trust_refresh(
    settings: orion_core::KeyNegotiationSettings,
    heliosd_url: String,
    sink: EventSink,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match orion_core::trust_update::refresh(&settings, &heliosd_url, now_unix()).await {
            Ok(orion_core::trust_update::TrustUpdateOutcome::UpToDate) => {
                tracing::debug!("mise à jour de confiance : rien à récupérer");
            }
            Ok(orion_core::trust_update::TrustUpdateOutcome::Applied { objects }) => {
                let message = format!(
                    "confiance mise à jour : {objects} objet(s) signé(s) appliqué(s) depuis la \
                     gateway"
                );
                tracing::info!(objects, "mise à jour de confiance appliquée");
                sink(ClientEvent::log("info", message));
            }
            Err(error) => {
                // Not fatal, and deliberately not silent. The tunnel works;
                // what may not is a future renewal, and that is worth a line
                // now rather than a refusal nobody can explain later.
                let message = format!(
                    "mise à jour de confiance impossible : {error}. Le tunnel n'est pas \
                             affecté."
                );
                tracing::warn!(%error, "mise à jour de confiance refusée");
                sink(ClientEvent::log("warn", message));
            }
        }
    })
}

/// Runs the ordinary client renewal at the fixed 80 % threshold.
///
/// The task is tied to the mounted connection. It first lets the authenticated
/// trust refresh finish, then waits for the locally computed threshold. A
/// reconnect cancels this task and creates a new one from the current durable
/// state, so no timer can act for a profile that is no longer mounted.
pub fn spawn_automatic_certificate_renewal(
    prerequisite: tokio::task::JoinHandle<()>,
    controller: Arc<VpnController>,
    renewals: Arc<Mutex<std::collections::HashMap<String, InFlightRenewal>>>,
    profile_name: String,
    settings: orion_core::KeyNegotiationSettings,
    heliosd_url: String,
    sink: EventSink,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = prerequisite.await;
        let now = now_unix();
        let inventory = orion_core::certificate_inventory::inventory(Some(&settings), now);
        let Some(client) = inventory.client_pq else {
            tracing::warn!(profile = %profile_name, "automatic renewal skipped: client PQ certificate is unavailable");
            return;
        };
        if client.phase == orion_core::certificate_inventory::CertificatePhase::Expired {
            sink(ClientEvent::log(
                "warn",
                format!(
                    "certificat du profil « {profile_name} » expiré : le renouvellement automatique ne peut plus prouver une identité active ; utiliser la récupération YubiKey"
                ),
            ));
            return;
        }

        let wait = client.renewal_at.saturating_sub(now);
        if wait > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        }
        if controller.state() != TunnelState::Up
            || controller.mounted_profile().await.as_deref() != Some(profile_name.as_str())
        {
            return;
        }

        match drive_renewal_in_map(&renewals, &profile_name, settings, heliosd_url).await {
            Ok(RenewalProgress::Committed { generation }) => {
                tracing::info!(profile = %profile_name, generation, "automatic certificate renewal committed");
                sink(ClientEvent::log(
                    "info",
                    format!(
                        "certificats du profil « {profile_name} » renouvelés automatiquement ; génération {generation} prête pour le chevauchement"
                    ),
                ));
            }
            Ok(progress) => {
                tracing::warn!(profile = %profile_name, ?progress, "automatic certificate renewal remains in progress");
                sink(ClientEvent::log(
                    "warn",
                    format!(
                        "renouvellement automatique du profil « {profile_name} » incomplet ; Orion réessaiera à la prochaine connexion"
                    ),
                ));
            }
            Err(error) => {
                tracing::warn!(profile = %profile_name, %error, "automatic certificate renewal failed");
                sink(ClientEvent::log(
                    "warn",
                    format!(
                        "renouvellement automatique du profil « {profile_name} » impossible : {error}. Orion réessaiera à la prochaine connexion"
                    ),
                ));
            }
        }
    })
}

/// Advances the renewal of `name` by one step, opening it if none is in flight.
///
/// The renewal map is the one the shell's renewal commands also drive, so a
/// step taken by either is the step the other resumes.
pub async fn drive_renewal_in_map(
    renewals: &Arc<Mutex<std::collections::HashMap<String, InFlightRenewal>>>,
    name: &str,
    settings: orion_core::KeyNegotiationSettings,
    url: String,
) -> Result<RenewalProgress, String> {
    let mut renewals = renewals.lock().await;
    if let Some(in_flight) = renewals.get_mut(name) {
        let step = orion_core::certificate_renewal::resume(
            &mut in_flight.session,
            &mut in_flight.store,
            &in_flight.settings,
            now_unix(),
        )
        .await
        .map_err(|error| error.to_string())?;
        let progress = RenewalProgress::of(&step, &in_flight.session);
        if matches!(
            step,
            orion_core::certificate_renewal::RenewalStep::Committed { .. }
        ) {
            renewals.remove(name);
        }
        return Ok(progress);
    }

    let (session, store, step) =
        orion_core::certificate_renewal::begin(&settings, &url, now_unix())
            .await
            .map_err(|error| error.to_string())?;
    let progress = RenewalProgress::of(&step, &session);
    if !matches!(
        step,
        orion_core::certificate_renewal::RenewalStep::Committed { .. }
    ) {
        renewals.insert(
            name.to_string(),
            InFlightRenewal {
                session,
                store,
                settings,
                approval: None,
            },
        );
    }
    Ok(progress)
}

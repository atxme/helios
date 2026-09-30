//! Orion's bounded, no-console CA-TLS companion workflow.
//!
//! The authority vault and every FIDO operation remain in `astra-signer`.
//! Orion owns only a loopback socket, a one-use authentication token and the
//! public progress messages defined in `aether`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::vault::{AuthorityVault, CaTlsAdvance};
use aether::certificates::encoding::{DerCertificate, Id16, MlDsa87PublicKey};
use aether::certificates::operator_ipc::{
    AstraCaTlsManifest, AstraCaTlsPhase, AstraCaTlsStatus, AstraIpcCommand, AstraIpcHello,
    MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use aether::certificates::status::{AstraRotationCampaign, AstraSignerResult, CampaignApproval};
use aether::certificates::transport::TrustUpdateObject;
use aether::certificates::window::TransitionWindow;
use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::authenticator::{self, Authenticator, Opened, Transport};
use crate::signing::{self, CampaignApprovalSession, DomainIdentity};
use crate::{campaign::Campaign, credentials, gestures, handoff, prepared, store};

const DAY_SECS: u64 = 86_400;
const IPC_TIMEOUT: Duration = Duration::from_secs(20);

/// Fixed arguments accepted by the Orion-only helper mode.
pub struct HelperOptions {
    pub vault_path: PathBuf,
    pub heliosd_url: String,
    pub operation_id: String,
    pub output_path: PathBuf,
    pub ipc_address: String,
    pub ipc_token: Zeroizing<String>,
    pub prepare_days: u64,
    pub overlap_days: u64,
    pub validity_days: u64,
}

/// The verified campaign and its still-uncommitted two-key ceremony.
pub struct CaTlsCeremony {
    vault_path: PathBuf,
    output_path: PathBuf,
    channel: Campaign,
    request: crate::origin::CampaignRequest,
    vault: AuthorityVault,
    identity: DomainIdentity,
    active_certificate: DerCertificate,
    window: TransitionWindow,
    validity: (u64, u64),
    approval: Option<CampaignApprovalSession>,
    first_opening: Option<Opened>,
    pub manifest: AstraCaTlsManifest,
}

impl CaTlsCeremony {
    /// Verifies every remote and local input before a key is requested.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        vault_path: &Path,
        channel: Campaign,
        operation_id: &str,
        origin: Option<&str>,
        output_path: &Path,
        prepare_days: u64,
        overlap_days: u64,
        validity_days: u64,
        now: u64,
    ) -> Result<Self> {
        let operation = Id16::parse_hex(operation_id)
            .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
        if prepared::load(&prepared::path_beside(vault_path))?.is_some() {
            bail!(
                "une rotation CA-TLS est déjà préparée ; la reprendre avant d'en ouvrir une autre"
            );
        }

        let vault = store::load(vault_path)?;
        let relay = handoff::DomainHandoff::beside(vault_path, &vault)?;
        let identity = handoff::identity_of(&relay)?;
        let ca_pq_public_key = MlDsa87PublicKey::parse(&relay.ca_pq_public_key)?;
        let active_certificate = DerCertificate::parse(relay.require(
            relay.ca_tls_certificate.as_ref(),
            "le certificat CA-TLS en service",
            "--ca-tls-certificate",
        )?)?;
        let registry =
            credentials::load(&credentials::path_beside(vault_path))?.ok_or_else(|| {
                anyhow::anyhow!(
                    "aucun document de credentials : l'émettre par `astra-signer bindings`"
                )
            })?;

        let expected_url = handoff::expected_authority_url(&relay, &channel)?;
        let request = channel.fetch(&operation)?;
        handoff::verify_campaign_request(&relay, &vault, &request, &expected_url, now)?;
        let campaign = request.campaign.as_ref().clone();
        if !campaign.scope.rotates_authority() {
            bail!("cette campagne ne fait tourner aucune ancre. Rien n'a été signé.");
        }

        let day =
            |days: u64| -> Result<u64> { days.checked_mul(DAY_SECS).context("durée hors bornes") };
        let activation_at = now
            .checked_add(day(prepare_days)?)
            .context("délai hors bornes")?;
        let window = TransitionWindow::new(
            now,
            activation_at,
            activation_at
                .checked_add(day(overlap_days)?)
                .context("délai hors bornes")?,
        )?;
        let validity = (
            now,
            now.checked_add(day(validity_days)?)
                .context("durée hors bornes")?,
        );
        let webauthn_origin = origin
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://{}", vault.rp_id));
        let approval = CampaignApprovalSession::new(
            &campaign,
            &registry,
            &identity,
            &ca_pq_public_key,
            &vault.rp_id,
            &webauthn_origin,
            now,
        )?;
        if approval.required() != 2 {
            bail!(
                "une rotation d'autorité exige exactement deux credentials distincts, la campagne en demande {}",
                approval.required()
            );
        }

        let manifest = manifest_of(&campaign, &identity, &active_certificate, window)?;

        Ok(Self {
            vault_path: vault_path.to_path_buf(),
            output_path: output_path.to_path_buf(),
            channel,
            request,
            vault,
            identity,
            active_certificate,
            window,
            validity,
            approval: Some(approval),
            first_opening: None,
            manifest,
        })
    }

    /// Opens and approves with the one key currently connected.
    pub fn approve_key(&mut self, key: &dyn Authenticator, pin: &str, now: u64) -> Result<String> {
        let approval = self
            .approval
            .as_mut()
            .context("la cérémonie est déjà finalisée")?;
        let opened = gestures::open_with_authorized_key(key, &self.vault, pin)?;
        let label = self
            .vault
            .slot_for_credential(&opened.credential_id)?
            .label
            .clone();
        let offered = approval.offered_credentials();
        let assertion = key.approve(
            approval.webauthn_rp_id(),
            &offered,
            approval.client_data_json(),
            pin,
        )?;
        approval.accept_for(assertion, Some(&opened.credential_id), now)?;
        if self.first_opening.is_none() {
            self.first_opening = Some(opened);
        }
        Ok(label)
    }

    /// Commits the already-approved decision locally and records exact replay bytes.
    pub fn finalize(&mut self, now: u64) -> Result<prepared::PreparedRotation> {
        let approval = self
            .approval
            .take()
            .context("la cérémonie est déjà finalisée")?
            .finish(now)?;
        let opening = self
            .first_opening
            .as_ref()
            .context("aucune clé n'a ouvert le coffre")?;
        let rotated = signing::rotate_ca_tls(
            &mut self.vault,
            opening,
            &self.identity,
            &self.active_certificate,
            self.window,
            self.validity,
        )?;
        let transition_document = rotated.transition.clone();
        let object = TrustUpdateObject::ClientTlsCaTransition(Box::new(rotated.transition));
        self.request
            .campaign
            .covers_authority_object(&object)
            .context("la transition signée ne correspond pas à la campagne approuvée")?;

        store::save(&self.vault_path, &self.vault)?;
        let result = campaign_result(&approval, vec![object.clone()]);
        let record = prepared::PreparedRotation {
            kind: prepared::PreparedKind::CaTls,
            operation_id: self.request.operation_id.to_hex(),
            result_token: self.request.result_token.clone(),
            result,
            transition_path: self.output_path.display().to_string(),
            next_ca_tls_epoch: self.manifest.next_ca_tls_epoch,
            next_ca_tls_certificate: rotated.next_certificate.to_base64(),
            activation_at: self.window.activation_at,
            not_after: self.window.not_after,
            submitted: false,
            prepared_at: now,
            manifest: Some(self.manifest.clone()),
        };
        let prepared_path = prepared::path_beside(&self.vault_path);
        prepared::save(&prepared_path, &record)?;
        // The bare transition, not the tagged `TrustUpdateObject` envelope: the
        // envelope is what Astra's registry routes on, while this file is what
        // `heliosd install-client-tls-ca` reads — and that reader refuses an
        // unknown `kind` field.
        let encoded =
            serde_json::to_vec_pretty(&transition_document).context("encodage de la transition")?;
        std::fs::write(&self.output_path, &encoded)
            .with_context(|| format!("écriture de {}", self.output_path.display()))?;
        Ok(record)
    }

    pub fn submit(&self, record: &mut prepared::PreparedRotation) -> Result<()> {
        submit_prepared(&self.channel, &self.vault_path, record)
    }
}

/// Runs the private helper protocol. Errors after connection are reported to Orion.
pub fn run_helper(options: HelperOptions) -> Result<()> {
    let address: SocketAddr = options
        .ipc_address
        .parse()
        .context("adresse IPC Orion invalide")?;
    if !address.ip().is_loopback() {
        bail!("le compagnon Orion accepte uniquement une adresse loopback");
    }
    let decoded = hex::decode(options.ipc_token.as_str()).context("jeton IPC Orion invalide")?;
    if decoded.len() != 32 {
        bail!("le jeton IPC Orion doit contenir exactement 32 octets");
    }

    let mut stream = TcpStream::connect_timeout(&address, IPC_TIMEOUT)
        .context("connexion au canal local d'Orion")?;
    stream
        .set_write_timeout(Some(IPC_TIMEOUT))
        .context("configuration du canal local")?;
    send_frame(
        &mut stream,
        &AstraIpcHello {
            protocol_version: PROTOCOL_VERSION,
            token: options.ipc_token.to_string(),
        },
    )?;

    if let Err(error) = run_connected(&mut stream, options) {
        let _ = send_frame(
            &mut stream,
            &AstraCaTlsStatus::new(AstraCaTlsPhase::Failed, format!("{error:#}")),
        );
        return Err(error);
    }
    Ok(())
}

fn run_connected(stream: &mut TcpStream, options: HelperOptions) -> Result<()> {
    let prepared_path = prepared::path_beside(&options.vault_path);
    if let Some(mut record) = prepared::load(&prepared_path)? {
        return resume_existing(stream, &options, &mut record);
    }

    let channel = Campaign::select(None, Some(&options.heliosd_url))?;
    let mut ceremony = CaTlsCeremony::begin(
        &options.vault_path,
        channel,
        &options.operation_id,
        None,
        &options.output_path,
        options.prepare_days,
        options.overlap_days,
        options.validity_days,
        now_unix(),
    )?;
    let mut status = status_for(
        AstraCaTlsPhase::AwaitingFirstKey,
        "Campagne vérifiée. Branchez la première clé autorisée.",
        &ceremony.manifest,
        &options.output_path,
    );
    send_frame(stream, &status)?;
    if wait_for_continue(stream, &status)? == AstraIpcCommand::Cancel {
        return send_cancelled(stream, &status);
    }

    status.phase = AstraCaTlsPhase::ProcessingFirstKey;
    status.message = "Authentification de la première clé en cours.".into();
    status.can_continue = false;
    status.can_cancel = false;
    send_frame(stream, &status)?;
    let first = connect_platform_key()?;
    status.first_key_label = Some(ceremony.approve_key(first.as_ref(), "", now_unix())?);
    status.phase = AstraCaTlsPhase::AwaitingSecondKey;
    status.message = "Première clé reconnue. Débranchez-la et branchez la seconde.".into();
    status.can_continue = true;
    status.can_cancel = true;
    send_frame(stream, &status)?;
    if wait_for_continue(stream, &status)? == AstraIpcCommand::Cancel {
        return send_cancelled(stream, &status);
    }

    status.phase = AstraCaTlsPhase::ProcessingSecondKey;
    status.message = "Authentification de la seconde clé en cours.".into();
    status.can_continue = false;
    status.can_cancel = false;
    send_frame(stream, &status)?;
    let second = connect_platform_key()?;
    status.second_key_label = Some(ceremony.approve_key(second.as_ref(), "", now_unix())?);
    status.phase = AstraCaTlsPhase::Finalizing;
    status.message = "Deux clés distinctes reconnues. Préparation de la transition.".into();
    send_frame(stream, &status)?;

    let mut record = ceremony.finalize(now_unix())?;
    status.phase = AstraCaTlsPhase::Prepared;
    status.message = "Transition préparée localement ; dépôt auprès d'Astra en cours.".into();
    status.can_continue = true;
    status.can_cancel = false;
    send_frame(stream, &status)?;
    loop {
        match ceremony.submit(&mut record) {
            Ok(()) => {
                status.phase = AstraCaTlsPhase::Deposited;
                status.message = format!(
                    "Transition déposée. La promotion sera possible à partir de {}.",
                    record.not_after
                );
                status.can_continue = false;
                send_frame(stream, &status)?;
                return Ok(());
            }
            Err(error) => {
                status.message = format!(
                    "Transition préparée, mais le dépôt a échoué : {error:#}. Réessayer ne redemande aucune clé."
                );
                send_frame(stream, &status)?;
                if wait_for_continue(stream, &status)? != AstraIpcCommand::Continue {
                    bail!("une décision durable préparée ne peut plus être annulée");
                }
            }
        }
    }
}

fn resume_existing(
    stream: &mut TcpStream,
    options: &HelperOptions,
    record: &mut prepared::PreparedRotation,
) -> Result<()> {
    let mut status = status_from_record(record);
    if !record.submitted {
        status.phase = AstraCaTlsPhase::Prepared;
        status.message =
            "Une transition locale attend son dépôt. Aucune clé ne sera redemandée.".into();
        status.can_continue = true;
        send_frame(stream, &status)?;
        if wait_for_continue(stream, &status)? != AstraIpcCommand::Continue {
            bail!("une décision durable préparée ne peut plus être annulée");
        }
        let channel = Campaign::select(None, Some(&options.heliosd_url))?;
        submit_prepared(&channel, &options.vault_path, record)?;
        status.phase = AstraCaTlsPhase::Deposited;
        status.message = format!(
            "Transition déposée. La promotion sera possible à partir de {}.",
            record.not_after
        );
        status.can_continue = false;
        send_frame(stream, &status)?;
        return Ok(());
    }

    let now = now_unix();
    if now < record.not_after {
        status.phase = AstraCaTlsPhase::Deposited;
        status.message = format!(
            "Transition déposée ; l'ancre sortante émet jusqu'à {}.",
            record.not_after
        );
        status.can_continue = false;
        send_frame(stream, &status)?;
        return Ok(());
    }

    status.phase = AstraCaTlsPhase::AwaitingPromotionKey;
    status.message =
        "Le recouvrement est terminé. Branchez une clé autorisée pour promouvoir l'ancre.".into();
    status.can_continue = true;
    send_frame(stream, &status)?;
    if wait_for_continue(stream, &status)? != AstraIpcCommand::Continue {
        bail!("une rotation déposée ne peut pas être annulée");
    }
    status.phase = AstraCaTlsPhase::Promoting;
    status.message = "Promotion de l'ancre CA-TLS en cours.".into();
    status.can_continue = false;
    send_frame(stream, &status)?;
    let mut vault = store::load(&options.vault_path)?;
    let key = connect_platform_key()?;
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, "")?;
    match signing::advance_ca_tls(&mut vault, &opening, now_unix())? {
        CaTlsAdvance::Rotated { .. } => {
            store::save(&options.vault_path, &vault)?;
            let mut relay = handoff::DomainHandoff::beside(&options.vault_path, &vault)?;
            relay.ca_tls_epoch = Some(record.next_ca_tls_epoch);
            relay.ca_tls_certificate = Some(record.next_ca_tls_certificate.clone());
            handoff::save(&handoff::path_beside(&options.vault_path), &relay)?;
            prepared::clear(&prepared::path_beside(&options.vault_path))?;
            status.phase = AstraCaTlsPhase::Promoted;
            status.message = format!(
                "Ancre CA-TLS promue à l'époque {}.",
                record.next_ca_tls_epoch
            );
            send_frame(stream, &status)?;
            Ok(())
        }
        CaTlsAdvance::Awaiting { at } => bail!("promotion refusée avant {at}"),
        CaTlsAdvance::Idle => bail!("le coffre ne porte aucune fenêtre CA-TLS ouverte"),
    }
}

fn connect_platform_key() -> Result<Box<dyn Authenticator>> {
    let key = authenticator::connect(Transport::Platform)?;
    if key.needs_pin() {
        bail!("le mode Orion exige l'API WebAuthn de la plateforme ; le PIN ne traverse jamais l'interface");
    }
    Ok(key)
}

fn submit_prepared(
    channel: &Campaign,
    vault_path: &Path,
    record: &mut prepared::PreparedRotation,
) -> Result<()> {
    let operation = Id16::parse_hex(&record.operation_id)
        .map_err(|error| anyhow::anyhow!("rotation préparée illisible : {error}"))?;
    channel.submit(&operation, &record.result_token, &record.result)?;
    record.submitted = true;
    prepared::save(&prepared::path_beside(vault_path), record)
}

fn campaign_result(
    approval: &CampaignApproval,
    objects: Vec<TrustUpdateObject>,
) -> AstraSignerResult {
    AstraSignerResult {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        approval: Box::new(approval.clone()),
        objects,
        credential_registry: None,
        issuer_authorization: None,
    }
}

/// The public campaign summary both front ends show before a key is touched.
///
/// One constructor for the terminal and for Orion: the manifest is what the
/// operator compares against the campaign they asked for, and two independent
/// renderings of it could disagree about the very values that decide whether
/// the ceremony should continue.
pub fn manifest_of(
    campaign: &AstraRotationCampaign,
    identity: &DomainIdentity,
    active_certificate: &DerCertificate,
    window: TransitionWindow,
) -> Result<AstraCaTlsManifest> {
    Ok(AstraCaTlsManifest {
        reason: campaign.reason.clone(),
        requested_by: campaign.requested_by.clone(),
        fingerprint: campaign.fingerprint().to_hex(),
        current_ca_tls_epoch: identity.ca_tls_epoch,
        next_ca_tls_epoch: identity
            .ca_tls_epoch
            .checked_add(1)
            .context("époque CA-TLS hors bornes")?,
        activation_at: window.activation_at,
        not_after: window.not_after,
        outgoing_anchor_fingerprint: active_certificate.fingerprint().to_hex(),
        affected_ca: "client_tls".into(),
        target_count: campaign.targets.len(),
    })
}

fn status_for(
    phase: AstraCaTlsPhase,
    message: &str,
    manifest: &AstraCaTlsManifest,
    output: &Path,
) -> AstraCaTlsStatus {
    let mut status = AstraCaTlsStatus::new(phase, message);
    status.output_path = Some(output.display().to_string());
    status.next_ca_tls_epoch = Some(manifest.next_ca_tls_epoch);
    status.activation_at = Some(manifest.activation_at);
    status.not_after = Some(manifest.not_after);
    status.manifest = Some(manifest.clone());
    status
}

fn status_from_record(record: &prepared::PreparedRotation) -> AstraCaTlsStatus {
    let mut status = AstraCaTlsStatus::new(AstraCaTlsPhase::Prepared, "Transition préparée.");
    status.output_path = Some(record.transition_path.clone());
    status.next_ca_tls_epoch = Some(record.next_ca_tls_epoch);
    status.activation_at = Some(record.activation_at);
    status.not_after = Some(record.not_after);
    status.manifest = record.manifest.clone();
    status
}

fn send_cancelled(stream: &mut TcpStream, previous: &AstraCaTlsStatus) -> Result<()> {
    let mut status = previous.clone();
    status.phase = AstraCaTlsPhase::Cancelled;
    status.message = "Rotation annulée avant toute écriture durable.".into();
    status.can_continue = false;
    status.can_cancel = false;
    send_frame(stream, &status)
}

fn wait_for_continue(stream: &mut TcpStream, status: &AstraCaTlsStatus) -> Result<AstraIpcCommand> {
    let command: AstraIpcCommand = read_frame(stream)?.context("Orion a fermé le canal local")?;
    if command == AstraIpcCommand::Cancel && !status.can_cancel {
        bail!("annulation refusée après le début des écritures durables");
    }
    Ok(command)
}

fn send_frame<T: serde::Serialize>(stream: &mut TcpStream, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).context("encodage du message IPC")?;
    if bytes.len() > MAX_FRAME_BYTES {
        bail!("message IPC trop volumineux");
    }
    bytes.push(b'\n');
    stream.write_all(&bytes).context("écriture du canal IPC")
}

fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> Result<Option<T>> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).context("lecture du canal IPC")? {
            0 if bytes.is_empty() => return Ok(None),
            0 => bail!("message IPC tronqué"),
            _ if byte[0] == b'\n' => break,
            _ => {
                if bytes.len() == MAX_FRAME_BYTES {
                    bail!("message IPC trop volumineux");
                }
                bytes.push(byte[0]);
            }
        }
    }
    Ok(Some(
        serde_json::from_slice(&bytes).context("message IPC illisible")?,
    ))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_endpoint_must_be_loopback_and_token_is_exactly_256_bits() {
        assert!("127.0.0.1:1234"
            .parse::<SocketAddr>()
            .unwrap()
            .ip()
            .is_loopback());
        assert!(!"192.0.2.1:1234"
            .parse::<SocketAddr>()
            .unwrap()
            .ip()
            .is_loopback());
        assert_eq!(hex::decode("ab".repeat(32)).unwrap().len(), 32);
    }

    #[test]
    fn bounded_frames_round_trip_and_reject_unknown_commands() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let writer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connect");
            send_frame(&mut stream, &AstraIpcCommand::Continue).expect("send");
        });
        let (mut stream, _) = listener.accept().expect("accept");
        let command: AstraIpcCommand = read_frame(&mut stream).expect("read").expect("frame");
        assert_eq!(command, AstraIpcCommand::Continue);
        writer.join().expect("writer");
    }
}

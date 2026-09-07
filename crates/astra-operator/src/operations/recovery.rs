//! §7.5, as a ceremony rather than as a command.
//!
//! # The shape, and why it is two halves
//!
//! Everything that can be checked is checked before a key is asked for
//! anything, and what that check produces is a [`RecoveryManifest`] — the
//! typed record of what the operator is about to approve. Only then does the
//! gesture run. §12.2 asks that what is signed be what was shown; splitting
//! the ceremony at that seam is what makes the two the same object rather than
//! two descriptions of one intention.
//!
//! The split is also what a screen needs. A terminal could print facts and
//! then block on `stdin`; an interface has to render, wait for a human who may
//! be looking for their key, and act on a separate press. [`begin`] and
//! [`Verified::approve`] are those two moments.
//!
//! # What is not asked
//!
//! Nothing. The authority origin, the RP ID, the domain and the service key
//! come from the hand-off pinned beside the vault; the operation identifier
//! comes from the caller that opened it. The two durations are constants here
//! rather than parameters — see [`VALIDITY_DAYS`] and [`OVERLAP_DAYS`].

use std::path::Path;

use aether::certificates::client::ExpiredCertificateRecoveryRequest;
use aether::certificates::encoding::{DerCertificate, Id16, MlDsa87PublicKey};
use aether::certificates::operator_session::{RecoveryManifest, RemoteState};
use aether::certificates::window::TransitionWindow;
use anyhow::{bail, Context, Result};
use base64::Engine as _;

use crate::authenticator::Authenticator;
use crate::vault::AuthorityVault;
use crate::{authority, credentials, gestures, handoff, origin, store};

const DAY_SECS: u64 = 86_400;

/// How long the recovered generation is issued for.
///
/// A constant and not a question. It was already the default of the command
/// this replaces, nobody ever passed anything else, and a number an operator
/// is asked for while reaching for their security key is a number they will
/// accept unread. It belongs in a signed issuance policy; recording that here
/// is the honest interim.
pub const VALIDITY_DAYS: u64 = 365;

/// How long the expired generation is still tolerated after the change-over.
///
/// Short by construction: the leaf being replaced has **already expired**, so
/// it opens nothing and there is nothing to overlap with. What remains is the
/// margin for the gateway and the client to cross over.
pub const OVERLAP_DAYS: u64 = 1;

// The overlap is a margin inside a lifetime, never a lifetime of its own.
const _: () = assert!(OVERLAP_DAYS < VALIDITY_DAYS);

/// How far the window opens before the instant it activates on.
///
/// The window demands `not_before < activation_at` strictly, and back-dating
/// it is doubly deserved here: a machine left off long enough for its identity
/// to expire is a machine whose clock has had time to wander.
pub const WINDOW_BACKDATE_SECS: u64 = 300;

/// A recovery whose every input has been verified, waiting on a key.
///
/// Holds no secret: the vault is still sealed, and what is kept is the
/// description the operator is being shown plus the material needed to act on
/// it once they agree.
pub struct Verified {
    vault: AuthorityVault,
    identity: authority::DomainIdentity,
    registry: credentials::CredentialRegistry,
    ca_tls_certificate: DerCertificate,
    client: origin::Origin,
    operation: Id16,
    request: Box<ExpiredCertificateRecoveryRequest>,
    webauthn_origin: String,
    window: TransitionWindow,
    validity: (u64, u64),
    stage_expires_at: u64,
    now: u64,
    manifest: RecoveryManifest,
}

impl Verified {
    /// What the operator is approving. Rendered before any key is touched.
    pub fn manifest(&self) -> &RecoveryManifest {
        &self.manifest
    }

    pub fn operation(&self) -> Id16 {
        self.operation
    }
}

/// Verifies every input and describes the operation. Opens nothing.
///
/// # Where the origin comes from
///
/// From the hand-off pinned beside the vault, whenever it names one. A process
/// holding `CA-PQ` that learned where to send its signatures from whoever
/// asked would be authenticating nothing.
///
/// `offered_authority_url` exists for the compatibility CLI, whose flag
/// predates the hand-off field, and for a hand-off written before that field
/// existed. It is never preferred: when both are present and disagree, the
/// ceremony refuses rather than picking one. The caller that has no business
/// choosing — the helper Orion launches — passes `None`.
///
/// `offered_webauthn_origin` is the same bargain for the RP origin, which is
/// otherwise `https://<rp_id>`.
pub fn begin(
    vault_path: &Path,
    operation: Id16,
    offered_authority_url: Option<&str>,
    offered_webauthn_origin: Option<&str>,
    now: u64,
) -> Result<Verified> {
    let vault = store::load(vault_path)?;
    let handoff = handoff::DomainHandoff::beside(vault_path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let registry = credentials::load(&credentials::path_beside(vault_path))?.ok_or_else(|| {
        anyhow::anyhow!(
            "aucun document de credentials à côté du coffre : sans lui, aucune preuve opérateur \
             ne peut être nommée"
        )
    })?;
    let ca_tls_certificate = handoff.ca_tls_certificate.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "ce relais de domaine ne porte pas la CA-TLS cliente : sans elle la feuille TLS de la \
             génération récupérée ne chaîne à rien"
        )
    })?;
    let ca_tls_certificate = DerCertificate::new(
        base64::engine::general_purpose::STANDARD
            .decode(ca_tls_certificate.trim())
            .context("CA-TLS cliente : base64 illisible")?,
    )?;

    let authority_url = resolve_authority_url(
        handoff.astra_authority_url.as_deref(),
        offered_authority_url,
    )?;
    let client = origin::Origin::new(&authority_url)?;
    let view = client.recovery(&operation)?;
    let request = view
        .request
        .clone()
        .ok_or_else(|| anyhow::anyhow!("l'autorité ne rend pas la demande de cette opération"))?;

    let validity = (
        now,
        now.checked_add(VALIDITY_DAYS * DAY_SECS)
            .context("durée hors bornes")?,
    );
    // The recovered generation has nothing to overlap *with*, so it changes
    // over as early as the protocol allows. That instant is the end of the
    // staging lease, not `now`: §7.2 refuses a lease that outlives the
    // activation it prepares, so a window activating at `now` is refused by
    // the gateway a moment after the operator touched their key. Collapsing
    // the three instants onto `now` is refused earlier still, since a window
    // demands `not_before < activation_at < not_after` strictly. Both refusals
    // say the same thing: staging comes first, the change-over follows it.
    let stage_expires_at = request.expires_at;
    let window = TransitionWindow::new(
        now.saturating_sub(WINDOW_BACKDATE_SECS),
        stage_expires_at,
        stage_expires_at
            .checked_add(OVERLAP_DAYS * DAY_SECS)
            .context("durée hors bornes")?,
    )?;

    let manifest = RecoveryManifest {
        trust_domain_id: identity.trust_domain_id,
        peer_name: request.expired_pq_certificate.subject.clone(),
        client_wg_public_key: request.client_wg_public_key.to_base64(),
        expired_generation: request.expired_generation,
        next_generation: request.requested_generation,
        expired_since_secs: now.saturating_sub(request.expired_pq_certificate.not_after_unix),
        request_fingerprint: request.fingerprint(),
        ca_epoch: identity.ca_epoch,
        ca_tls_epoch: identity.ca_tls_epoch,
        activation_at: window.activation_at,
        not_after: window.not_after,
    };

    Ok(Verified {
        vault,
        identity,
        registry,
        ca_tls_certificate,
        client,
        operation,
        request,
        webauthn_origin: offered_webauthn_origin
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://{}", handoff.rp_id)),
        window,
        validity,
        stage_expires_at,
        now,
        manifest,
    })
}

impl Verified {
    /// Opens the vault twice and deposits both objects.
    ///
    /// `progress` is called as the authority's own state moves, so a caller
    /// that renders can say «déposé», «mis en scène», «accordé» rather than
    /// showing one spinner across three network round trips — the shape that
    /// made a refusal after the key touch indistinguishable from a hang.
    ///
    /// The two openings use one key and one PIN: the operator decides once,
    /// and the second signature is not a second decision.
    pub fn approve(
        self,
        key: &dyn Authenticator,
        pin: &str,
        progress: &mut dyn FnMut(RemoteState),
    ) -> Result<()> {
        let produced = authority::recover_expired_identity(
            &self.vault,
            key,
            pin,
            &self.identity,
            &self.registry,
            &self.ca_tls_certificate,
            &self.request,
            &self.request.client_wg_public_key.to_base64(),
            self.window,
            self.validity,
            Id16::new(random_id()?)?,
            random_id()?,
            &self.webauthn_origin,
            self.stage_expires_at,
            self.now,
        )?;
        progress(RemoteState::Prepared);
        let authorization = produced.authorization;

        let staged = self.client.deposit_recovery_authorization(
            &self.operation,
            &aether::certificates::transport::ExpiredRecoveryAuthorizationDeposit {
                authorization: Box::new(authorization.clone()),
                evidence: Box::new(produced.evidence),
            },
        )?;
        progress(RemoteState::Staged);

        let receipt = staged
            .receipt
            .ok_or_else(|| anyhow::anyhow!("l'autorité n'a pas rendu le reçu de la gateway"))?;
        let gateway_leaf = staged.gateway_pq_certificate.ok_or_else(|| {
            anyhow::anyhow!("l'autorité n'a pas rendu la feuille que la gateway sert")
        })?;
        // Compared to the gateway this vault's own hand-off names, before
        // anything is verified under it. Astra reads that leaf on the veth;
        // this end must not adopt an identity because the relay reported it.
        if gateway_leaf.wireguard_public_key != self.identity.gateway_wg_public_key.to_base64() {
            bail!(
                "la feuille que l'autorité annonce appartient à une autre gateway que celle que \
                 ce coffre épingle. Rien n'est signé."
            );
        }
        let gateway_pq_public_key = MlDsa87PublicKey::parse(&gateway_leaf.ml_dsa_87_public_key)?;
        let gateway_fingerprint =
            aether::certificates::gateway::pq_certificate_fingerprint(&gateway_leaf)?;

        progress(RemoteState::PendingGrant);
        let opening = gestures::open_with_authorized_key(key, &self.vault, pin)?;
        let grant = authority::grant_recovered_identity(
            &self.vault,
            &opening,
            &authorization,
            &receipt,
            &gateway_pq_public_key,
            &gateway_fingerprint,
        )?;
        self.client.deposit_recovery_grant(
            &self.operation,
            &aether::certificates::transport::ExpiredRecoveryGrantDeposit {
                grant: Box::new(grant),
            },
        )?;
        progress(RemoteState::Granted);
        Ok(())
    }
}

/// The pinned origin wins; a disagreement refuses.
///
/// Not «the caller's value if given», and not «the pin if given»: either rule
/// silently picks a side of a disagreement that means one of the two is wrong
/// about which domain this is. Refusing is the only answer that does not
/// choose for the operator.
fn resolve_authority_url(pinned: Option<&str>, offered: Option<&str>) -> Result<String> {
    match (pinned.map(str::trim), offered.map(str::trim)) {
        (Some(pinned), Some(offered))
            if pinned.trim_end_matches('/') != offered.trim_end_matches('/') =>
        {
            bail!(
                "ce coffre épingle l'origine « {pinned} » et on lui en présente « {offered} » : \
                 l'une des deux se trompe de domaine, et rien n'est signé tant que la question \
                 n'est pas tranchée"
            )
        }
        (Some(pinned), _) => Ok(pinned.to_string()),
        (None, Some(offered)) => Ok(offered.to_string()),
        (None, None) => bail!(
            "ce relais de domaine ne nomme pas l'origine de l'autorité : elle est écrite par \
             l'amorçage du domaine, et la prendre d'ailleurs reviendrait à laisser l'appelant \
             choisir où partent les signatures"
        ),
    }
}

fn random_id() -> Result<[u8; 16]> {
    let mut out = [0u8; 16];
    aether::random::fill_secret(&mut out)
        .map_err(|error| anyhow::anyhow!("générateur approuvé indisponible : {error}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The durations are constants because they are not decisions, and the
    /// overlap in particular is short **because the leaf being replaced has
    /// already expired**. A long overlap here would keep a dead identity
    /// nominally alive for no benefit.
    #[test]
    fn the_recovered_generation_overlaps_briefly_and_lives_a_year() {
        assert_eq!(VALIDITY_DAYS, 365);
        assert_eq!(OVERLAP_DAYS, 1);
    }

    /// The pin is the authority on where signatures go, and a caller that
    /// disagrees with it is a question, not an input.
    #[test]
    fn a_disagreement_about_the_origin_refuses_rather_than_choosing() {
        assert_eq!(
            resolve_authority_url(Some("https://a.example"), None).expect("pinned"),
            "https://a.example"
        );
        assert_eq!(
            resolve_authority_url(Some("https://a.example/"), Some("https://a.example"))
                .expect("same origin, one trailing slash"),
            "https://a.example/"
        );
        assert!(
            resolve_authority_url(Some("https://a.example"), Some("https://b.example")).is_err()
        );
        assert_eq!(
            resolve_authority_url(None, Some("https://b.example")).expect("legacy hand-off"),
            "https://b.example"
        );
        assert!(resolve_authority_url(None, None).is_err());
    }

    /// The two refusals that cost an evening, stated as arithmetic rather than
    /// as a comment: the window has to open strictly before it activates, and
    /// it has to activate no earlier than the end of the staging lease.
    #[test]
    fn the_window_satisfies_both_rules_that_bound_it() {
        let now: u64 = 1_800_000_000;
        let stage_expires_at = now + 300;
        let window = TransitionWindow::new(
            now.saturating_sub(WINDOW_BACKDATE_SECS),
            stage_expires_at,
            stage_expires_at + OVERLAP_DAYS * DAY_SECS,
        )
        .expect("both rules");
        assert!(window.not_before < window.activation_at);
        assert!(window.activation_at < window.not_after);
        assert!(
            stage_expires_at <= window.activation_at,
            "§7.2 refuses a staging lease that outlives the activation it prepares"
        );
    }
}

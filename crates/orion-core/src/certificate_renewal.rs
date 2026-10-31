//! The client half of the relayed renewal — spec §8.1.2.
//!
//! # What this module is, and what it deliberately is not
//!
//! A client whose leaf reaches 80 % of its life has to obtain a new one before
//! the old one expires, and it has exactly one way to do that while WireGuard
//! works: the five typed routes the gateway serves **inside the tunnel**. It
//! never dials Astra. `heliosd` resolves the peer from its VIP, relays a
//! canonical object it builds itself, and hands back what the authority
//! answered.
//!
//! The eight steps of §8.1.2 collapse, from this side, into six — two of them
//! this client's, four of them somebody else's:
//!
//! 1. **here** — generate the candidate keys, sign
//!    [`ClientCertificateRotationRequest`], post it to `request`;
//! 2. Helios authenticates the peer and relays;
//! 3. Astra verifies the due window and its narrow issuer delegation;
//! 4. Astra issues, Helios persists the candidate and signs its receipt, and
//!    Astra releases the grant — three steps this client only observes;
//! 5. **here** — verify the grant against what this store already trusts,
//!    persist the candidate, sign [`ClientCertificateStageCommit`], post it to
//!    `stage-commit`, and commit locally.
//!
//! No operator credential participates in this ordinary path. Recovery and
//! manual authority campaigns use their separate companion-backed flows.
//!
//! # Why the private keys never leave this process
//!
//! Both halves of the candidate identity — the TLS key and the ML-DSA-87 key —
//! are generated here and stay here. What travels is a PKCS#10 request and a
//! public key, each covered by a signature made with the matching private
//! half. That is what makes the grant's binding check meaningful: the
//! authority certifies a key somebody proved they hold, and
//! [`ClientCertificateRotationGrant::verify`] then refuses a leaf that
//! certifies any other one.
//!
//! # Why nothing is written before the grant verifies
//!
//! The candidate keys live in [`RenewalSession`] and are written to the
//! protected store only at the commit, in the same step that installs the
//! candidate generation. An interrupted renewal therefore leaves **nothing**:
//! no half-sealed identity, no orphan key, no slot naming a certificate this
//! machine has no private key for. The cost is that a crash loses the keys and
//! the operation has to be reopened — which is the cheap failure, because the
//! active generation is untouched and still connects.
//!

use aether::certificates::CertificateError;

// Named by the module documentation above, and by nothing else: an intra-doc
// link only resolves in the scope it is written in.
#[allow(unused_imports)]
use aether::certificates::client::{
    ClientCertificateRotationGrant, ClientCertificateRotationRequest, ClientCertificateStageCommit,
};

mod exchange;
mod promotion;
mod trust_store;

pub use exchange::{
    begin, resume, ActiveIdentity, CandidateKeys, RenewalRoutes, RenewalSession, RenewalStep,
    REQUEST_LIFETIME_SECS,
};
pub use promotion::{
    candidate_identity_of, promote_due, promote_local_identity_if_due, rollback_to_previous,
    ClientServiceRollback,
};
pub use trust_store::{open_or_seed, trust_store_path};

pub(crate) use promotion::prepare_identity_for_connection;
pub(crate) use trust_store::{client_pq_leaf, open_identity_store};

use exchange::{committed_and_waiting, horodatage};

#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    #[error("renewal refused: {0}")]
    Certificate(#[from] CertificateError),
    #[error("trust store: {0}")]
    Trust(#[from] crate::certificates::TrustError),
    #[error("protected identity store: {0}")]
    Identity(String),
    #[error(
        "la génération {generation} est déjà engagée et s'active le {activation_at} : rien à \
         renouveler tant qu'elle n'a pas pris la place de l'active"
    )]
    AlreadyCommitted {
        generation: u64,
        /// Rendered as a date: this string reaches the operator's screen.
        activation_at: String,
    },
    #[error(
        "la génération récupérée {generation} est commitée mais ne sera admise qu'à partir du \
         {activation_at}; réessayer la connexion après cette heure"
    )]
    ActivationPending {
        generation: u64,
        /// Rendered as a date: this string reaches the operator's screen.
        activation_at: String,
    },
    #[error("the gateway did not answer the renewal route: {0}")]
    Transport(String),
    #[error(
        "la gateway a refusé le renouvellement ({status}). Le motif détaillé reste dans son \
         journal : le canal in-tunnel ne le renvoie jamais au client."
    )]
    Refused { status: u16 },
    #[error(
        "cette gateway ne relaie aucune autorité de certification. Astra n'est pas déployé, ou \
         son canal privé est tombé — le renouvellement n'a pas d'autre chemin tant que le tunnel \
         fonctionne."
    )]
    AuthorityUnavailable,
    #[error("the gateway's answer is not a renewal operation: {0}")]
    Malformed(String),
    #[error(
        "l'opération de renouvellement a échoué côté autorité. Aucune assertion n'est plus \
         acceptée sous cet identifiant : en ouvrir une nouvelle."
    )]
    OperationFailed,
    #[error(
        "l'autorité demande encore une approbation YubiKey pour un renouvellement ordinaire. \
         Mettre Astra à jour : la politique courante autorise automatiquement une identité \
         active à partir de 80 % de sa validité."
    )]
    ObsoleteOperatorApproval,
    #[error("the operation named {returned} instead of {expected}")]
    OperationMismatch { expected: String, returned: String },
    #[error(
        "l'autorité annonce un grant disponible et n'en joint aucun : l'opération est \
         inutilisable en l'état."
    )]
    GrantMissing,
    #[error("the local clock is before the Unix epoch")]
    Clock,
    #[error("approbation : {0}")]
    Approval(#[from] crate::certificate_approval::ApprovalError),
    #[error(
        "la fenêtre de capacité de cette opération est passée : elle vaut cinq minutes. Relancer \
         le renouvellement."
    )]
    CapabilityWindowClosed,
    #[error(
        "ce profil ne porte pas le matériel de confiance qu'un renouvellement exige — domaine, \
         autorité Astra épinglée et CA TLS cliente. Demander à l'opérateur un document réémis."
    )]
    TrustMaterialMissing,
    #[error(
        "le magasin de confiance de ce poste ({path}) décrit « {held} » et non « {expected} ». \
         Il n'est ni adopté ni remplacé : il porte des décisions — générations préparées, \
         révocations — qu'un écrasement perdrait en silence."
    )]
    ForeignTrustStore {
        path: String,
        held: String,
        expected: String,
    },
    #[error(
        "le certificat client actif a expiré (échéance {not_after}). Il ne peut plus signer la \
         preuve de continuité qu'une rotation exige : c'est la récupération du §7.5 qu'il faut, \
         pas un renouvellement."
    )]
    ActiveExpired { not_after: u64 },
    #[error(
        "le retour à l'identité précédente n'est disponible que pendant le chevauchement actif"
    )]
    RollbackUnavailable,
}

#[cfg(all(test, feature = "certificate-signing"))]
mod tests;

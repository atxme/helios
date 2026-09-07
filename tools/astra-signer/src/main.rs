//! `astra-signer` — the operator companion of ADR-008 §4.
//!
//! It runs on the machine where the security key is plugged in, and it is the
//! only program in this repository that ever holds `CA-PQ` in the clear. Astra
//! stores the encrypted vault; the gateway never sees it; no browser touches
//! CTAP. The anchors exist in memory here, for the length of one operation,
//! and are zeroized after.
//!
//! # The gestures
//!
//! - `init` creates the vault around fresh anchors and registers the first
//!   key. It prints the **public** `CA-PQ` key — what `astra bootstrap` needs
//!   and the only half of the anchor that ever leaves this program.
//! - `enrol` registers another key. Two devices, plugged one at a time: the
//!   one already authorized opens the vault, the new one receives a slot.
//!   This is how a second key is added, and how a third or a fourth is,
//!   later, with no difference at all.
//! - `verify` proves a key opens the anchors. ADR-008 §4 finalises the
//!   bootstrap only «après enregistrement et essai des deux clés», and this is
//!   that trial.
//! - `list` prints the slot table, the vault fingerprint, and whether the
//!   authority is bootstrapped.
//! - `remove` withdraws a key, never the last recovery.
//! - `rename` changes a label, and needs no key: the label is deliberately
//!   outside everything cryptographic.
//! - `domain` records — and prints — the public values every signing command
//!   below reads: the gateway, the server name and the Astra service key this
//!   companion pins. Needs no key.
//! - `issue-ca-tls` self-signs the client TLS CA around the key the vault has
//!   held since the domain was created.
//! - `authorize-issuer` signs one `AstraIssuerAuthorization`: Astra's
//!   delegated issuer, bounded in time and in what it may ever emit.
//! - `bindings` re-emits the credential document from the key-slot table. Run
//!   automatically by every gesture that moves that table.
//! - `approve` approves one exact client renewal, from files or straight
//!   through the client's tunnel. **It does not open the vault**, and cannot:
//!   see [`astra_signer::authority::approve_renewal`].
//! - `approve-campaign` approves a manual rotation campaign, at as many
//!   distinct keys as its scope demands.
//! - `issue-gateway-bootstrap` verifies the public request of a new gateway
//!   and issues its epoch-1 leaf under `CA-PQ`, after two distinct keys.
//! - `rotate-ca-pq` moves the anchor, under two distinct keys.
//!
//! This file is the prompts and the printing. The sequences themselves are in
//! [`astra_signer::gestures`], where they are exercised.
//!
//! # Transport : le tunnel pour le renouvellement, des fichiers pour le reste
//!
//! `approve` sait désormais travailler **dans le tunnel** du client :
//! `--heliosd-url` et `--operation-id` remplacent `--request` et `--out`, et le
//! compagnon récupère la demande puis dépose son assertion par les routes
//! typées de `helios-api` (§8.1.2). C'est le chemin que l'IHM Orion lance, et
//! il tient debout parce que le compagnon tourne sur la machine du client : ces
//! routes authentifient le pair par sa VIP source, pas par un jeton porteur.
//!
//! Le transport ne décide de rien. La demande récupérée est signée par la clé
//! de service d'Astra et vérifiée contre le relais de domaine que ce compagnon
//! détient déjà — exactement comme une demande lue dans un fichier, puisque
//! c'est l'objet qui porte la signature et non le fil par lequel il arrive.
//!
//! `approve-campaign` a maintenant les **deux** transports : hors ligne par
//! `--campaign` et `--out`, ou par l'origine publique du §8.2 avec
//! `--authority-url` et `--operation-id`. C'est le canal que le relais
//! in-tunnel ne couvre pas — un opérateur sur son propre poste n'a aucune VIP
//! que la gateway résoudrait. L'origine ne décide de rien : la demande reste
//! vérifiée sous la clé de service que ce compagnon épingle, et le RP ID
//! annoncé est **comparé** à celui du coffre, jamais adopté.
//!
//! # Gestes qui voyagent par fichiers
//!
//! `issue-gateway-bootstrap` voyage nécessairement par fichiers : le domaine
//! neuf ne possède encore ni registre, ni clé de service, ni veth.
//! `authorize-issuer` et la forme hors ligne de `rotate-ca-pq` lisent aussi une
//! demande sur disque et écrivent leur résultat à côté. Elles ne portent pas
//! de campagne, donc rien ne les rattache à une opération : les routes du §8.2
//! sont liées à un `operation_id` et à un manifeste, et il n'existe pas encore
//! d'opération qui les décrive.
//!
//! # Limite connue : le matériel ne s'exerce pas en WSL2
//!
//! Voir [`astra_signer::authenticator`]. CTAP n'est pas une feature de
//! compilation : tout binaire porte la pile, et il n'existe aucun chemin qui
//! ouvre le coffre sans clé.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use aether::certificates::approval::CredentialState;
use aether::certificates::encoding::{
    validate_server_name, DerCertificate, Id16, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
};
use aether::certificates::transport::ClientRenewalOperationState;
use aether::certificates::window::TransitionWindow;
use anyhow::{bail, Context, Result};
use astra::vault::{AuthorityVault, KeySlot, SlotRole, MAX_SLOTS, REQUIRED_SLOTS};
use astra_signer::authenticator::{Opened, Transport};
use astra_signer::authority::{self, DelegationBounds, IssuerDelegationRequest};
use astra_signer::credentials;
use astra_signer::gestures::{self, NewAuthority, NewKey};
use astra_signer::{authenticator, documents, handoff, orion, prepared, store, tunnel};
use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

/// A day, in seconds. Every window below is expressed in days on the command
/// line, because that is the unit an operator reasons about.
const DAY_SECS: u64 = 86_400;

/// How far a recovery window opens before the instant it activates on.
///
/// A recovered identity has nothing to overlap with — the leaf it replaces
/// expired — so it activates at once. The window still needs a strictly
/// earlier opening, and dating it slightly in the past is also what a client
/// whose clock drifted while it was off needs: that drift is the ordinary
/// case here, since a machine left off long enough to expire is a machine
/// whose clock has had time to wander.
const RECOVERY_WINDOW_BACKDATE_SECS: u64 = 300;

/// Prepared before any of the four files of a CA-PQ rotation is replaced.
///
/// A filesystem cannot atomically rename four unrelated destinations.  This
/// private journal makes the operation replayable instead: after it exists,
/// every destination is an idempotent projection of these exact bytes.  A
/// crash can therefore leave an old or new value at each path, never an
/// unrecoverable rotation whose outgoing private key vanished before its
/// public transition was written.
const CA_PQ_ROTATION_JOURNAL: &str = "ca-pq-rotation.pending.json";
const CA_PQ_ROTATION_JOURNAL_VERSION: u16 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CaPqRotationJournal {
    format_version: u16,
    output_path: PathBuf,
    current_ca_public_key: MlDsa87PublicKey,
    vault: AuthorityVault,
    bindings: aether::certificates::approval::CredentialRegistry,
    transition: aether::certificates::authority::CaTransition,
    handoff: handoff::DomainHandoff,
}

#[derive(Parser)]
#[command(
    name = "astra-signer",
    version,
    about = "Compagnon opérateur d'Astra : ouvre le coffre d'autorité par une clé de sécurité \
             FIDO2 (ADR-008 §4)"
)]
struct Cli {
    /// Path of the encrypted vault. It is meant to be backed up.
    #[arg(long, env = "ASTRA_VAULT")]
    vault: Option<PathBuf>,
    /// Comment joindre la clé de sécurité.
    ///
    /// `platform` sous Windows : l'API du système, sans élévation, et c'est
    /// lui qui demande le PIN. `hid` parle CTAP2 directement — partout, mais
    /// sous Windows uniquement depuis un processus administrateur.
    ///
    /// Globale : elle est acceptée avant comme après la sous-commande, parce
    /// qu'un opérateur qui bascule de transport la tape naturellement à la fin
    /// de la ligne.
    #[arg(long, value_enum, global = true, default_value_t = TransportArg::default())]
    transport: TransportArg,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
enum TransportArg {
    /// L'API du système. Sans élévation ; le PIN est saisi par le système.
    #[cfg_attr(windows, default)]
    Platform,
    /// CTAP2 sur HID. Sous Windows, exige une console administrateur.
    #[cfg_attr(not(windows), default)]
    Hid,
}

impl From<TransportArg> for Transport {
    fn from(value: TransportArg) -> Self {
        match value {
            TransportArg::Platform => Transport::Platform,
            TransportArg::Hid => Transport::Hid,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum RoleArg {
    /// The key in daily use.
    Principale,
    /// A key kept elsewhere, whose only job is to survive the loss of another.
    Recuperation,
}

impl From<RoleArg> for SlotRole {
    fn from(value: RoleArg) -> Self {
        match value {
            RoleArg::Principale => SlotRole::Primary,
            RoleArg::Recuperation => SlotRole::Recovery,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RevokedHalvesArg {
    Both,
    Tls,
    Pq,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RevocationScopeArg {
    /// One admitted client's leaves.
    Client,
    /// The gateway's own leaves. Terminal for the whole domain's data plane.
    Gateway,
}

impl From<RevocationScopeArg> for aether::certificates::revocation::RevocationScope {
    fn from(value: RevocationScopeArg) -> Self {
        match value {
            RevocationScopeArg::Client => Self::Client,
            RevocationScopeArg::Gateway => Self::Gateway,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AbortReasonArg {
    /// L'opérateur renonce à la transition qu'il a fait signer.
    OperatorCancelled,
    /// Une décision plus récente la remplace avant son activation.
    SupersededBeforeActivation,
}

impl From<AbortReasonArg> for aether::certificates::gateway::AbortReason {
    fn from(value: AbortReasonArg) -> Self {
        match value {
            AbortReasonArg::OperatorCancelled => Self::OperatorCancelled,
            AbortReasonArg::SupersededBeforeActivation => Self::SupersededBeforeActivation,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RevocationReasonArg {
    KeyCompromise,
    SuspectedCompromise,
    Cessation,
    Superseded,
}

impl From<RevocationReasonArg> for aether::certificates::revocation::RevocationReason {
    fn from(value: RevocationReasonArg) -> Self {
        match value {
            RevocationReasonArg::KeyCompromise => Self::KeyCompromise,
            RevocationReasonArg::SuspectedCompromise => Self::SuspectedCompromise,
            RevocationReasonArg::Cessation => Self::Cessation,
            RevocationReasonArg::Superseded => Self::Superseded,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Creates the vault around fresh anchors and registers the first key.
    Init {
        /// WebAuthn RP ID the credentials are registered under. The same value
        /// `astra bootstrap --webauthn-rp-id` is given: an assertion made
        /// under one RP ID does not answer under another.
        #[arg(long)]
        rp_id: String,
        /// Trust domain identifier, 32 hex characters. Drawn at random when
        /// left out, which is the ordinary case — the domain does not exist
        /// before this command.
        #[arg(long)]
        trust_domain_id: Option<String>,
        #[arg(long)]
        label: String,
        #[arg(long, value_enum, default_value = "principale")]
        role: RoleArg,
    },
    /// Registers another security key. Two devices, plugged one at a time.
    Enrol {
        #[arg(long)]
        label: String,
        #[arg(long, value_enum, default_value = "recuperation")]
        role: RoleArg,
    },
    /// Proves a security key opens the anchors.
    Verify,
    /// Prints the slot table and the state of the authority.
    List,
    /// Withdraws a security key, never the last recovery.
    Remove {
        /// Slot identifier, 32 hex characters, as `list` prints it.
        #[arg(long)]
        slot: String,
    },
    /// Liste les périphériques HID visibles, et lesquels sont des clés FIDO2.
    ///
    /// À lancer quand `init` annonce qu'aucune clé n'est branchée alors qu'elle
    /// l'est : une clé de sécurité se reconnaît à son usage page HID `0xF1D0`,
    /// et lire cette valeur demande d'ouvrir le périphérique — ce qu'un
    /// processus non élevé ne peut pas faire sous Windows.
    Devices,
    /// Réécrit le relais public à côté du coffre, et l'affiche.
    ///
    /// Needs no security key: everything in it is public, and it is read by a
    /// deployment that must never see the authority — and by every commande de
    /// signature ci-dessous, qui y lit la gateway, le nom de service et la clé
    /// de service Astra plutôt que de les faire retaper.
    Domain {
        /// Clé publique WireGuard de la gateway, base64.
        #[arg(long)]
        gateway_wg_public_key: Option<String>,
        /// Nom de service de la gateway, tel que la politique l'épingle.
        #[arg(long)]
        server_name: Option<String>,
        /// Clé publique de service d'Astra, base64, telle que `astra
        /// bootstrap` l'imprime. Épinglée : une demande d'approbation est
        /// vérifiée sous elle avant d'être montrée à un opérateur.
        #[arg(long)]
        astra_service_public_key: Option<String>,
        #[arg(long)]
        astra_service_key_epoch: Option<u64>,
        /// Origine que le domaine déclare, telle qu'`astra init-trust-domain`
        /// l'a enregistrée. Comparée à celle que nomme toute demande signée —
        /// et seule source de cette comparaison lorsque la campagne passe par
        /// le tunnel, où aucune URL n'est composée.
        #[arg(long)]
        astra_authority_url: Option<String>,
    },
    /// Auto-signe le certificat `CA-TLS` client autour de la clé du coffre.
    IssueCaTls {
        /// Durée de validité, en jours.
        #[arg(long, default_value_t = 3650)]
        days: u64,
        /// Où écrire le certificat en PEM, en plus du relais.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Signe une `AstraIssuerAuthorization` pour l'émetteur délégué d'Astra.
    ///
    /// Avec `--authority-url` et `--operation-id`, la demande est **récupérée**
    /// par les routes du §8.2 et la délégation y est redéposée : la campagne
    /// nomme l'époque et les deux clés exactes qui seront certifiées, et
    /// l'opérateur les lit avant le toucher. Une demande de délégation ne
    /// porte aucune signature — hors campagne, ce compagnon signe donc le
    /// fichier qu'on lui présente, et rien ne le rattache à une autorité.
    AuthorizeIssuer {
        /// Demande de délégation produite par `astra issuer request`, en JSON.
        ///
        /// Le fichier reste le transport, même en campagne : la campagne est
        /// ce qui l'authentifie, pas ce qui le porte.
        #[arg(long)]
        request: PathBuf,
        /// Où écrire l'autorisation signée, en JSON.
        ///
        /// Facultatif en campagne : la délégation est déposée sur l'autorité.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Origine HTTPS publique d'Astra, p. ex. https://astra.example.
        #[arg(long, requires = "operation_id")]
        authority_url: Option<String>,
        /// Opération à approuver, 32 caractères hexadécimaux.
        ///
        /// Imprimée par `astra issuer request --reason --requested-by`.
        #[arg(long, requires = "authority_url")]
        operation_id: Option<String>,
        /// Origine WebAuthn attendue. Par défaut `https://<rp_id>`.
        #[arg(long)]
        origin: Option<String>,
        /// Durée de la délégation, en jours.
        #[arg(long, default_value_t = 30)]
        days: u64,
        /// Plafond de durée d'une leaf émise sous cette délégation, en jours.
        #[arg(long, default_value_t = 90)]
        leaf_days: u64,
    },
    /// Réémet le document de credentials à partir de la table de key-slots.
    Bindings {
        /// Key-slot à marquer « perdue », 32 caractères hexadécimaux.
        ///
        /// Une clé qu'on ne retrouve pas mais qu'on n'a pas retirée : elle
        /// n'approuve plus rien, et son key-slot ouvre toujours le coffre.
        /// Retirer le key-slot la révoque, ce qui est définitif.
        #[arg(long)]
        lost: Vec<String>,
        /// Key-slot à remettre « active », 32 caractères hexadécimaux.
        #[arg(long)]
        active: Vec<String>,
    },
    /// Approuve un renouvellement client. N'ouvre pas le coffre.
    Approve {
        /// `AstraCredentialApprovalRequest` signée par Astra, en JSON.
        ///
        /// Hors tunnel seulement. Dans le tunnel, la demande se récupère.
        #[arg(long, conflicts_with_all = ["heliosd_url", "operation_id"])]
        request: Option<PathBuf>,
        /// Où écrire l'approbation, en JSON. Astra y ajoute sa signature.
        #[arg(long, conflicts_with_all = ["heliosd_url", "operation_id"])]
        out: Option<PathBuf>,
        /// API de la gateway **dans** WireGuard, p. ex. http://100.64.0.1:8080.
        ///
        /// C'est le chemin que l'IHM Orion lance (§12.2), et il suppose que ce
        /// compagnon tourne sur la machine du client : les routes de
        /// renouvellement authentifient le pair par sa VIP source.
        #[arg(long, requires = "operation_id")]
        heliosd_url: Option<String>,
        /// Opération à approuver, 32 caractères hexadécimaux.
        #[arg(long, requires = "heliosd_url")]
        operation_id: Option<String>,
        /// Génération active telle que le consommateur la persiste.
        ///
        /// À défaut, celle que la demande annonce — ce qui suffit à un
        /// opérateur qui vient de la lire, et jamais à une vérification.
        #[arg(long)]
        active_generation: Option<u64>,
    },
    /// Approuve une campagne de rotation manuelle (spec §7.6).
    ApproveCampaign {
        /// `AstraRotationCampaign` en JSON.
        ///
        /// Hors ligne seulement. Avec `--authority-url`, la campagne se
        /// récupère et son approbation se dépose par les routes du §8.2.
        #[arg(long, conflicts_with_all = ["authority_url", "operation_id"])]
        campaign: Option<PathBuf>,
        /// Où écrire l'approbation, en JSON.
        #[arg(long, conflicts_with_all = ["authority_url", "operation_id"])]
        out: Option<PathBuf>,
        /// Origine HTTPS publique d'Astra, p. ex. https://astra.example.
        ///
        /// Le canal hors tunnel : c'est le cas que le relais in-tunnel ne
        /// couvre pas, un opérateur sur son propre poste, sans VIP que la
        /// gateway résoudrait.
        #[arg(long, requires = "operation_id")]
        authority_url: Option<String>,
        /// Opération à approuver, 32 caractères hexadécimaux.
        ///
        /// Imprimée par `astra campaign open` sur la machine qui fait tourner
        /// Astra.
        #[arg(long, requires = "authority_url")]
        operation_id: Option<String>,
        /// Origine WebAuthn signée d'Astra. À défaut, `https://` suivi du RP ID.
        #[arg(long)]
        origin: Option<String>,
    },
    /// Fait tourner `CA-PQ`, sous deux clés distinctes (spec §9.1).
    RotateCaPq {
        /// Où écrire la `CaTransition` signée, en JSON.
        #[arg(long)]
        out: PathBuf,
        /// Délai avant que la nouvelle ancre soit servie, en jours.
        #[arg(long, default_value_t = 1)]
        prepare_days: u64,
        /// Recouvrement pendant lequel les deux ancres vérifient, en jours.
        #[arg(long, default_value_t = 30)]
        overlap_days: u64,
        /// Origine publique d'Astra, pour rattacher la rotation à une campagne.
        ///
        /// Avec `--operation-id`, la rotation est l'exécution d'une campagne
        /// `trust_authorities` : l'approbation et l'objet signé partent dans
        /// le même dépôt, et Astra distribue la transition aux pairs. Sans
        /// elle, la rotation reste un fichier que personne ne consomme.
        #[arg(long)]
        authority_url: Option<String>,
        /// Identifiant imprimé par `astra campaign open --scope trust-authorities`.
        #[arg(long)]
        operation_id: Option<String>,
        /// Origine WebAuthn, si elle diffère de `https://<rp_id>`.
        #[arg(long)]
        origin: Option<String>,
    },
    /// Signs and deposits an emergency client revocation (spec §10).
    Revoke {
        #[arg(long)]
        authority_url: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        origin: Option<String>,
        #[arg(long, value_enum, default_value = "client")]
        scope: RevocationScopeArg,
        #[arg(long, value_enum, default_value = "both")]
        halves: RevokedHalvesArg,
        /// Signed cryptographic expiry printed by `astra revocation open`.
        ///
        /// A client generation retires both its leaves at once, so one value
        /// covers them. A gateway's two leaves are issued separately and do
        /// not share an expiry: name them with `--tls-not-after` and
        /// `--pq-not-after`, which override this one when given.
        #[arg(long)]
        not_after: Option<u64>,
        #[arg(long)]
        tls_not_after: Option<u64>,
        #[arg(long)]
        pq_not_after: Option<u64>,
        #[arg(long, value_enum, default_value = "key-compromise")]
        reason: RevocationReasonArg,
        /// La transition `emergency_replacement` que cette révocation autorise
        /// (§10.1), telle qu'elle a été signée.
        ///
        /// Sans elle, une gateway révoquée est terminale : plus aucune
        /// transition ne s'installe, sur aucun détenteur, et le service reste
        /// à terre jusqu'à ce que le domaine soit reconstruit. Le fichier est
        /// lu, pas l'empreinte saisie : une valeur retapée de travers laisse
        /// une gateway qui attend un document que plus personne ne peut
        /// produire.
        #[arg(long)]
        replacement_transition: Option<PathBuf>,
    },
    /// Émet hors ligne la première feuille PQ gateway sous `CA-PQ` (§13.1).
    ///
    /// Aucun registre Astra n'existe encore : la demande et la feuille
    /// voyagent par fichiers. Deux credentials distincts sont exigés parce
    /// que cette admission n'a aucune identité sortante pour prouver une
    /// continuité.
    IssueGatewayBootstrap {
        /// Demande publique exportée par `heliosd init-key-negotiation`.
        #[arg(long)]
        request: PathBuf,
        /// Où écrire la feuille PQ à rapporter à la gateway.
        #[arg(long)]
        out: PathBuf,
        /// Durée de vie de la feuille, en jours.
        #[arg(long, default_value_t = 365)]
        validity_days: u64,
    },
    /// Émet la feuille gateway suivante et signe sa transition (§11.1 étape 4).
    ///
    /// La gateway a scellé sa clé et exporté une demande ; cette commande
    /// l'émet sous `CA-PQ` et signe la décision qui l'installe. Elle ne change
    /// rien à l'identité servie : la transition porte sa propre fenêtre, et
    /// c'est `activation_at` qui bascule.
    ///
    /// Le fichier produit se rapporte sur la gateway, à
    /// `heliosd install-gateway-transition`.
    SignGatewayTransition {
        /// Origine publique d'Astra, pour un opérateur sans tunnel (§8.2).
        #[arg(long, conflicts_with = "heliosd_url")]
        authority_url: Option<String>,
        /// API de la gateway dans le tunnel, chemin prioritaire (§8.5).
        #[arg(long, conflicts_with = "authority_url")]
        heliosd_url: Option<String>,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        origin: Option<String>,
        /// La demande exportée par `heliosd prepare-gateway-certificate`.
        #[arg(long)]
        request: PathBuf,
        /// La feuille PQ en service, exportée par `astra gateway-identity open`.
        ///
        /// Elle vérifie la signature de continuité du §5 — la preuve que la
        /// demande vient bien de l'identité en place. Absente, la continuité
        /// n'est pas vérifiée et `--key-recovery` doit être explicite.
        #[arg(long)]
        active_certificate: Option<PathBuf>,
        /// La feuille TLS candidate de la gateway, en DER.
        #[arg(long)]
        tls_certificate: Option<PathBuf>,
        /// Où écrire la transition signée.
        #[arg(long)]
        out: PathBuf,
        /// Durée de vie de la nouvelle feuille, en jours.
        #[arg(long, default_value_t = 365)]
        validity_days: u64,
        /// Délai avant `activation_at`, en jours : le temps laissé au parc
        /// pour recevoir la décision avant qu'elle prenne effet.
        #[arg(long, default_value_t = 7)]
        prepare_days: u64,
        /// Recouvrement entre `activation_at` et le retrait, en jours.
        #[arg(long, default_value_t = 7)]
        overlap_days: u64,
        /// La demande n'a pas de signature de continuité (§5, clé perdue).
        #[arg(long)]
        key_recovery: bool,
        /// Remplace une identité **révoquée** (§6.1, motif
        /// `emergency_replacement`).
        ///
        /// La transition produite n'est acceptée que par une gateway révoquée
        /// dont la révocation nomme ce document exact, et elle est alors
        /// servie immédiatement : il n'y a plus d'identité sortante avec
        /// laquelle se recouvrir. La signer avant la révocation, qui la
        /// nommera par `astra-signer revoke --replacement-transition`.
        #[arg(long)]
        emergency_replacement: bool,
    },
    /// Fait tourner la CA TLS cliente sous `CA-PQ` (§9.4).
    ///
    /// L'ancre entrante est créée ici, auto-signée pour prouver qu'elle
    /// détient sa clé, et la transition qui l'installe est signée par `CA-PQ`
    /// — laquelle ne bouge pas. Le coffre scelle la clé suivante *à côté* de
    /// celle qui émet : c'est `promote-ca-tls` qui les échange à
    /// `activation_at`, puis détruit l'ancienne au retrait.
    RotateCaTls {
        /// Origine publique d'Astra, pour un opérateur sans tunnel (§8.2).
        #[arg(long, conflicts_with = "heliosd_url")]
        authority_url: Option<String>,
        /// API de la gateway dans le tunnel, chemin prioritaire (§8.5).
        #[arg(long, conflicts_with = "authority_url")]
        heliosd_url: Option<String>,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        origin: Option<String>,
        /// Où écrire la transition signée, pour la porter sur la gateway.
        #[arg(long)]
        out: PathBuf,
        /// Délai avant `activation_at`, en jours.
        #[arg(long, default_value_t = 7)]
        prepare_days: u64,
        /// Recouvrement pendant lequel les deux ancres sont acceptées.
        #[arg(long, default_value_t = 30)]
        overlap_days: u64,
        /// Durée de vie de l'ancre entrante, en jours.
        #[arg(long, default_value_t = 1825)]
        validity_days: u64,
    },
    /// Mène la rotation CA-TLS sous la conduite d'Orion, sans console (§9.4).
    ///
    /// Même cérémonie que `rotate-ca-tls`, et exactement les mêmes
    /// vérifications : seules les invites changent de support. Orion tient une
    /// socket loopback et un jeton à usage unique, ce compagnon s'y reconnecte
    /// et n'y publie que des états publics. Le coffre, le PIN et le geste FIDO
    /// ne quittent jamais ce processus.
    ///
    /// Les arguments sont composés par Orion, jamais saisis : la sous-commande
    /// n'est pas destinée à une frappe manuelle.
    #[command(hide = true)]
    Orion {
        /// API de la gateway dans le tunnel (§8.5).
        #[arg(long)]
        heliosd_url: String,
        #[arg(long)]
        operation_id: String,
        /// Où écrire la transition signée, pour la porter sur la gateway.
        #[arg(long)]
        out: PathBuf,
        /// Point d'écoute loopback ouvert par Orion.
        #[arg(long)]
        ipc_address: String,
        /// Jeton d'authentification du canal, 32 octets en hexadécimal.
        #[arg(long, env = "ASTRA_ORION_IPC_TOKEN", hide_env_values = true)]
        ipc_token: String,
        /// Délai avant `activation_at`, en jours.
        #[arg(long, default_value_t = 7)]
        prepare_days: u64,
        /// Recouvrement pendant lequel les deux ancres sont acceptées.
        #[arg(long, default_value_t = 30)]
        overlap_days: u64,
        /// Durée de vie de l'ancre entrante, en jours.
        #[arg(long, default_value_t = 1825)]
        validity_days: u64,
    },
    /// Rejoue le dépôt d'une rotation préparée mais jamais déposée.
    ///
    /// La cérémonie écrit sa décision avant d'en parler à quiconque. Si la
    /// machine s'est arrêtée entre l'écriture et le dépôt, ceci renvoie les
    /// mêmes octets : Astra traite un résultat identique comme le même, et
    /// aucune clé n'est redemandée — la décision a déjà été approuvée.
    ResumeRotation {
        /// Origine publique d'Astra, pour un opérateur sans tunnel (§8.2).
        #[arg(long, conflicts_with = "heliosd_url")]
        authority_url: Option<String>,
        /// API de la gateway dans le tunnel, chemin prioritaire (§8.5).
        #[arg(long, conflicts_with = "authority_url")]
        heliosd_url: Option<String>,
    },
    /// Signe un rollback de service vers l'ancienne identité gateway (§4.4).
    ///
    /// Pendant le recouvrement uniquement, et sans rien déplacer : aucun
    /// compteur ne bouge, le slot suivant reste scellé, et sa promotion a lieu
    /// à `not_after` comme prévu. La sélection expire d'elle-même, au plus tard
    /// avec le recouvrement.
    ///
    /// Hors campagne Astra, délibérément : un rollback ne distribue rien et ne
    /// change aucun état du domaine. La campagne est résolue localement depuis
    /// la transition elle-même, affichée, et attestée par une clé autorisée.
    SignGatewayRollback {
        /// La transition en recouvrement, telle qu'elle a été signée.
        #[arg(long)]
        transition: PathBuf,
        /// Où écrire l'autorisation signée.
        #[arg(long)]
        out: PathBuf,
        /// Durée de la sélection, en heures. Bornée par `not_after`.
        #[arg(long, default_value_t = 24)]
        hours: u64,
        /// Motif, affiché avant le toucher et scellé dans la campagne.
        #[arg(long)]
        reason: String,
        /// Qui demande, affiché avant le toucher.
        #[arg(long)]
        requested_by: String,
        #[arg(long)]
        origin: Option<String>,
    },
    /// Referme la fenêtre de rotation CA-TLS à `not_after` (§9.2).
    ///
    /// Une seule écriture scellée : la clé suivante devient celle qui émet et
    /// l'ancienne clé privée cesse d'exister. Pendant tout le recouvrement,
    /// l'autorité émet sous l'ancre sortante — la gateway compare
    /// `ca_tls_epoch` à l'identique et ne l'avance qu'à `not_after`. Appelée
    /// trop tôt, la commande n'écrit rien et dit quelle seconde elle attend.
    ///
    /// Limite connue : rien ne la lance à `not_after`. Le compagnon attend
    /// l'opérateur, et émet sous l'ancienne époque jusque-là.
    PromoteCaTls,
    /// Signe l'annulation d'une transition gateway en attente (§6.3).
    ///
    /// Refusée une fois la transition distribuée ou `activation_at` atteint :
    /// un client peut déjà l'avoir persistée, repartir hors ligne et
    /// promouvoir seul. L'époque reste consommée.
    AbortGatewayTransition {
        /// Origine publique d'Astra, pour un opérateur sans tunnel (§8.2).
        #[arg(long, conflicts_with = "heliosd_url")]
        authority_url: Option<String>,
        /// API de la gateway dans le tunnel, chemin prioritaire (§8.5).
        #[arg(long, conflicts_with = "authority_url")]
        heliosd_url: Option<String>,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        origin: Option<String>,
        /// La transition à annuler, telle qu'elle a été signée.
        #[arg(long)]
        transition: PathBuf,
        /// Où écrire l'avortement signé.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_enum, default_value = "operator-cancelled")]
        reason: AbortReasonArg,
    },
    /// Approuve la récupération d'une identité expirée (§7.5).
    ///
    /// Une seule commande, une seule clé branchée : elle lit la demande,
    /// l'affiche, prend l'assertion de l'opérateur, ouvre le coffre, émet les
    /// deux feuilles sous `CA-PQ` et `CA-TLS`, dépose l'autorisation, attend le
    /// reçu de la gateway et signe le grant. Le client, lui, n'a aucun tunnel :
    /// c'est ce que cette procédure répare.
    Recover {
        /// Origine publique d'Astra.
        #[arg(long)]
        authority_url: String,
        /// Identifiant imprimé par le client au moment où il a demandé.
        #[arg(long)]
        operation_id: String,
        /// Origine WebAuthn, si elle diffère de `https://<rp_id>`.
        #[arg(long)]
        origin: Option<String>,
        /// Durée de vie de la nouvelle génération, en jours.
        #[arg(long, default_value_t = 365)]
        validity_days: u64,
        /// Recouvrement avant que l'ancienne génération soit retirée, en jours.
        ///
        /// Court par défaut : l'ancienne a déjà expiré, elle n'ouvre plus rien,
        /// et le recouvrement n'existe ici que pour laisser la gateway et le
        /// client se croiser.
        #[arg(long, default_value_t = 1)]
        overlap_days: u64,
    },
    /// Renames a slot. Needs no security key.
    Rename {
        #[arg(long)]
        slot: String,
        #[arg(long)]
        label: String,
    },
}

fn main() -> Result<()> {
    std::thread::Builder::new()
        .name("astra-signer".into())
        .stack_size(astra_signer::WORK_STACK_BYTES)
        .spawn(run)
        .context("démarrage du fil de travail")?
        .join()
        .map_err(|_| anyhow::anyhow!("le fil de travail s'est interrompu"))?
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.vault {
        Some(path) => path,
        None => store::default_path()?,
    };

    let transport = cli.transport.into();
    match cli.command {
        Command::Init {
            rp_id,
            trust_domain_id,
            label,
            role,
        } => init(
            &path,
            &rp_id,
            trust_domain_id.as_deref(),
            &label,
            role.into(),
            transport,
        ),
        Command::Enrol { label, role } => enrol(&path, &label, role.into(), transport),
        Command::Verify => verify(&path, transport),
        Command::List => list(&path),
        Command::Devices => devices(),
        Command::Domain {
            gateway_wg_public_key,
            server_name,
            astra_service_public_key,
            astra_service_key_epoch,
            astra_authority_url,
        } => domain(
            &path,
            gateway_wg_public_key.as_deref(),
            server_name.as_deref(),
            astra_service_public_key.as_deref(),
            astra_service_key_epoch,
            astra_authority_url.as_deref(),
        ),
        Command::Remove { slot } => remove(&path, &slot, transport),
        Command::Rename { slot, label } => rename(&path, &slot, &label),
        Command::IssueCaTls { days, out } => issue_ca_tls(&path, days, out.as_deref(), transport),
        Command::AuthorizeIssuer {
            request,
            out,
            authority_url,
            operation_id,
            origin,
            days,
            leaf_days,
        } => authorize_issuer(
            &path,
            &request,
            out.as_deref(),
            authority_url.as_deref().zip(operation_id.as_deref()),
            days,
            leaf_days,
            origin.as_deref(),
            transport,
        ),
        Command::Bindings { lost, active } => bindings(&path, &lost, &active, transport),
        Command::Approve {
            request,
            out,
            heliosd_url,
            operation_id,
            active_generation,
        } => approve(
            &path,
            request.as_deref(),
            out.as_deref(),
            heliosd_url.as_deref(),
            operation_id.as_deref(),
            active_generation,
            transport,
        ),
        Command::ApproveCampaign {
            campaign,
            out,
            authority_url,
            operation_id,
            origin,
        } => approve_campaign(
            &path,
            campaign.as_deref(),
            out.as_deref(),
            authority_url.as_deref(),
            operation_id.as_deref(),
            origin.as_deref(),
            transport,
        ),
        Command::Recover {
            authority_url,
            operation_id,
            origin,
            validity_days,
            overlap_days,
        } => recover(
            &path,
            &authority_url,
            &operation_id,
            origin.as_deref(),
            validity_days,
            overlap_days,
            transport,
        ),
        Command::RotateCaPq {
            out,
            prepare_days,
            overlap_days,
            authority_url,
            operation_id,
            origin,
        } => rotate_ca_pq(
            &path,
            &out,
            prepare_days,
            overlap_days,
            authority_url.as_deref(),
            operation_id.as_deref(),
            origin.as_deref(),
            transport,
        ),
        Command::Revoke {
            authority_url,
            operation_id,
            origin,
            scope,
            halves,
            not_after,
            tls_not_after,
            pq_not_after,
            reason,
            replacement_transition,
        } => revoke(
            &path,
            &authority_url,
            &operation_id,
            origin.as_deref(),
            RevocationInputs {
                scope: scope.into(),
                halves,
                tls_not_after: tls_not_after.or(not_after),
                pq_not_after: pq_not_after.or(not_after),
                reason: reason.into(),
                replacement: replacement_transition,
            },
            transport,
        ),
        Command::IssueGatewayBootstrap {
            request,
            out,
            validity_days,
        } => issue_gateway_bootstrap(&path, &request, &out, validity_days, transport),
        Command::SignGatewayTransition {
            authority_url,
            heliosd_url,
            operation_id,
            origin,
            request,
            active_certificate,
            tls_certificate,
            out,
            validity_days,
            prepare_days,
            overlap_days,
            key_recovery,
            emergency_replacement,
        } => sign_gateway_transition(
            &path,
            astra_signer::campaign::Campaign::select(
                authority_url.as_deref(),
                heliosd_url.as_deref(),
            )?,
            &operation_id,
            origin.as_deref(),
            GatewayTransitionInputs {
                request: &request,
                active_certificate: active_certificate.as_deref(),
                tls_certificate: tls_certificate.as_deref(),
                out: &out,
                validity_days,
                prepare_days,
                overlap_days,
                key_recovery,
                emergency_replacement,
            },
            transport,
        ),
        Command::RotateCaTls {
            authority_url,
            heliosd_url,
            operation_id,
            origin,
            out,
            prepare_days,
            overlap_days,
            validity_days,
        } => rotate_ca_tls(
            &path,
            astra_signer::campaign::Campaign::select(
                authority_url.as_deref(),
                heliosd_url.as_deref(),
            )?,
            &operation_id,
            origin.as_deref(),
            &out,
            (prepare_days, overlap_days, validity_days),
            transport,
        ),
        Command::Orion {
            heliosd_url,
            operation_id,
            out,
            ipc_address,
            ipc_token,
            prepare_days,
            overlap_days,
            validity_days,
        } => orion::run_helper(orion::HelperOptions {
            vault_path: path,
            heliosd_url,
            operation_id,
            output_path: out,
            ipc_address,
            ipc_token: Zeroizing::new(ipc_token),
            prepare_days,
            overlap_days,
            validity_days,
        }),
        Command::ResumeRotation {
            authority_url,
            heliosd_url,
        } => resume_rotation(
            &path,
            astra_signer::campaign::Campaign::select(
                authority_url.as_deref(),
                heliosd_url.as_deref(),
            )?,
        ),
        Command::SignGatewayRollback {
            transition,
            out,
            hours,
            reason,
            requested_by,
            origin,
        } => sign_gateway_rollback(
            &path,
            &transition,
            &out,
            hours,
            &reason,
            &requested_by,
            origin.as_deref(),
            transport,
        ),
        Command::PromoteCaTls => promote_ca_tls(&path, transport),
        Command::AbortGatewayTransition {
            authority_url,
            heliosd_url,
            operation_id,
            origin,
            transition,
            out,
            reason,
        } => abort_gateway_transition(
            &path,
            astra_signer::campaign::Campaign::select(
                authority_url.as_deref(),
                heliosd_url.as_deref(),
            )?,
            &operation_id,
            origin.as_deref(),
            &transition,
            &out,
            reason.into(),
            transport,
        ),
    }
}

fn init(
    path: &Path,
    rp_id: &str,
    trust_domain_id: Option<&str>,
    label: &str,
    role: SlotRole,
    transport: Transport,
) -> Result<()> {
    if path.exists() {
        bail!(
            "un coffre existe déjà à {} : `enrol` ajoute une clé, `init` en créerait un second \
             dont les ancres n'ont rien à voir",
            path.display()
        );
    }
    let trust_domain_id = match trust_domain_id {
        Some(value) => TrustDomainId::parse_hex(value)
            .context("lecture de l'identifiant de domaine de confiance")?,
        None => TrustDomainId::new(random_id()?).context("tirage du domaine de confiance")?,
    };

    eprintln!("Brancher la clé de sécurité à enregistrer, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    let created = gestures::create_authority(
        key.as_ref(),
        &NewAuthority {
            rp_id: rp_id.to_string(),
            trust_domain_id,
            label: label.to_string(),
            role,
        },
        &pin,
        now_unix(),
    )?;
    store::save_new(path, &created.vault)?;
    // Written straight away: the three values below are what two other
    // programs need, and retyping a base64 anchor is where a deployment goes
    // wrong — silently, with the failure surfacing much later.
    let handoff_path = handoff::path_beside(path);
    handoff::save(&handoff_path, &handoff::DomainHandoff::of(&created.vault)?)?;

    println!("coffre            : {}", path.display());
    println!("relais            : {}", handoff_path.display());
    println!("domaine           : {}", created.vault.trust_domain_id);
    println!("empreinte coffre  : {}", created.vault.fingerprint()?);
    println!(
        "CA-PQ (publique)  : {}",
        created.ca_pq_public_key.to_base64()
    );
    println!(
        "CA-PQ empreinte   : {}",
        created.ca_pq_public_key.authority_fingerprint()
    );
    println!();
    println!(
        "`./scripts/deploy.sh` lit le relais et amorce Astra et la gateway sans qu'aucune de ces \
         valeurs soit recopiée à la main"
    );
    report_bootstrap_state(&created.vault);
    Ok(())
}

fn enrol(path: &Path, label: &str, role: SlotRole, transport: Transport) -> Result<()> {
    let mut vault = store::load(path)?;
    if vault.slots.len() >= MAX_SLOTS {
        bail!("le coffre est plafonné à {MAX_SLOTS} key-slots : en retirer un d'abord");
    }

    // The authorized key first. Registering before we knew we could open the
    // vault would leave an orphan credential on a fresh token, and an operator
    // with no way to tell which one it was.
    eprintln!("Brancher une clé DÉJÀ enregistrée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let opening = {
        let key = authenticator::connect(transport)?;
        let pin = pin_for(key.as_ref(), "PIN de la clé déjà enregistrée : ")?;
        let opened = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
        let slot = vault.slot_for_credential(&opened.credential_id)?;
        eprintln!("Clé reconnue : « {} » ({}).", slot.label, slot.role);
        opened
    };

    eprintln!();
    eprintln!("Débrancher cette clé, brancher la NOUVELLE, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la nouvelle clé : ")?;
    let slot_id = gestures::add_key(
        key.as_ref(),
        &mut vault,
        &opening,
        &NewKey {
            label: label.to_string(),
            role,
        },
        &pin,
        now_unix(),
    )?;
    store::save(path, &vault)?;
    // The credential document is rebuilt from the table that just moved, in
    // the same operation (spec §2.4). The key still plugged in is the new one,
    // and it is now a slot of this vault — so it can sign the document that
    // describes it.
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    resign_bindings(path, &vault, &opening)?;

    println!("key-slot         : {}", hex::encode(slot_id));
    println!("libellé          : {label}");
    println!("empreinte coffre : {}", vault.fingerprint()?);
    report_bootstrap_state(&vault);
    Ok(())
}

fn verify(path: &Path, transport: Transport) -> Result<()> {
    let vault = store::load(path)?;

    eprintln!("Brancher la clé de sécurité à éprouver, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
    let opened = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let slot = vault.slot_for_credential(&opened.credential_id)?.clone();
    gestures::prove_anchors_open(&vault, &opened)?;

    println!("key-slot         : {}", hex::encode(slot.slot_id));
    println!("libellé          : {}", slot.label);
    println!("rôle             : {}", slot.role);
    println!("ancres           : ouvertes");
    println!("empreinte coffre : {}", vault.fingerprint()?);
    report_bootstrap_state(&vault);
    Ok(())
}

fn list(path: &Path) -> Result<()> {
    let vault = store::load(path)?;
    println!("coffre           : {}", path.display());
    println!("domaine          : {}", vault.trust_domain_id);
    println!("RP ID WebAuthn   : {}", vault.rp_id);
    println!("empreinte coffre : {}", vault.fingerprint()?);
    println!("key-slots        : {}/{}", vault.slots.len(), MAX_SLOTS);
    for slot in &vault.slots {
        println!(
            "  {} — {} — {} — enregistrée le {}",
            hex::encode(slot.slot_id),
            slot.label,
            slot.role,
            slot.enrolled_at
        );
    }
    report_bootstrap_state(&vault);
    Ok(())
}

fn remove(path: &Path, slot: &str, transport: Transport) -> Result<()> {
    let mut vault = store::load(path)?;
    let removed = parse_slot_id(slot)?;
    let target: KeySlot = vault.slot(&removed)?.clone();

    eprintln!(
        "Retrait de « {} » ({}). Brancher une clé autorisée, puis appuyer sur Entrée.",
        target.label, target.role
    );
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé autorisée : ")?;
    let opened = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;

    gestures::remove_key(&mut vault, &opened, &removed)?;
    // Re-signed here, and this is where the withdrawn credential gets its
    // `revoked` row: «absent du document» n'est pas une décision qu'un
    // consommateur peut appliquer, un état signé l'est. Publish that terminal
    // decision first: a crash may then refuse a credential still present in
    // the old vault (fail closed), but can never leave an absent slot marked
    // active — ordinary approval does not open the vault and could otherwise
    // continue using the removed token.
    let opened = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    resign_bindings(path, &vault, &opened)?;
    store::save(path, &vault)?;

    println!("key-slot retiré  : {}", hex::encode(removed));
    println!("empreinte coffre : {}", vault.fingerprint()?);
    println!(
        "le corps a été rescellé : ce key-slot recollé depuis une sauvegarde n'ouvre plus ce \
         fichier. Une sauvegarde antérieure, elle, reste ouvrable par cette clé — si elle est \
         compromise, la réponse est une rotation de CA-PQ"
    );
    report_bootstrap_state(&vault);
    Ok(())
}

fn devices() -> Result<()> {
    let visible = authenticator::visible_devices();
    if visible.is_empty() {
        println!("aucun périphérique HID visible.");
        println!("ni clé, ni clavier, ni souris : c'est la pile HID du système qui ne répond pas.");
        return Ok(());
    }
    for device in &visible {
        println!(
            "{} {:04x}:{:04x} {}",
            match (device.fido, device.known_vendor) {
                (true, _) => "FIDO2 ",
                // Its vendor makes security keys, but no FIDO interface is
                // readable on it — the interesting line of the whole listing.
                (false, true) => "clé ? ",
                (false, false) => "      ",
            },
            device.vendor_id,
            device.product_id,
            device.product
        );
        println!("        {}", device.detail.trim());
    }
    let fido = visible.iter().filter(|device| device.fido).count();
    println!();
    println!("{} périphérique(s) HID, dont {fido} FIDO2.", visible.len());
    if fido == 0 {
        let suspects = visible.iter().filter(|device| device.known_vendor).count();
        println!();
        if suspects > 0 {
            println!(
                "{suspects} périphérique(s) marqués « clé ? » viennent d'un fabricant de clés de \
                 sécurité : la clé est branchée et vue par le système, seule son interface FIDO \
                 ne s'ouvre pas."
            );
        }
        println!(
            "Aucun n'expose l'usage page 0xF1D0. Ce n'est pas une question de modèle : rien ici \
             ne filtre sur le vendor ou le product."
        );
        if cfg!(windows) {
            println!(
                "Sous Windows, ouvrir un HID FIDO est réservé aux processus élevés depuis \
                 Windows 10 1903 — relancer dans une console administrateur. Si elle l'est déjà, \
                 vérifier `ykman config usb --list` : FIDO2 désactivé, l'interface n'existe pas."
            );
        } else {
            println!(
                "Sous Linux, il manque en général une règle udev donnant l'accès à l'utilisateur \
                 courant, ou l'application FIDO2 de la clé est désactivée."
            );
        }
    }
    Ok(())
}

fn domain(
    path: &Path,
    gateway_wg_public_key: Option<&str>,
    server_name: Option<&str>,
    astra_service_public_key: Option<&str>,
    astra_service_key_epoch: Option<u64>,
    astra_authority_url: Option<&str>,
) -> Result<()> {
    let vault = store::load(path)?;
    let handoff_path = handoff::path_beside(path);
    // Read first, then refreshed from the vault: rewriting from the vault
    // alone would drop the gateway and the pinned service key, and the next
    // signing command would ask an operator to retype them.
    let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;

    // Parsed before anything is written. A gateway key that is not a key, or a
    // service key that is not an ML-DSA-87 key, is a value every later command
    // would carry into a signed object.
    if let Some(value) = gateway_wg_public_key {
        WireGuardKey::parse(value).context("clé publique WireGuard de la gateway")?;
        handoff.gateway_wg_public_key = Some(value.trim().to_string());
    }
    if let Some(value) = server_name {
        validate_server_name(value.trim()).context("nom de service de la gateway")?;
        handoff.server_name = Some(value.trim().to_string());
    }
    if let Some(value) = astra_service_public_key {
        MlDsa87PublicKey::parse(value.trim()).context("clé publique de service d'Astra")?;
        handoff.astra_service_public_key = Some(value.trim().to_string());
    }
    if let Some(epoch) = astra_service_key_epoch {
        if epoch == 0 {
            bail!("l'époque de la clé de service Astra doit être non nulle");
        }
        handoff.astra_service_key_epoch = Some(epoch);
    }
    if let Some(value) = astra_authority_url {
        let value = value.trim();
        if !value.starts_with("https://") {
            bail!("l'origine de l'autorité doit être une URL https:// : {value}");
        }
        handoff.astra_authority_url = Some(value.trim_end_matches('/').to_string());
    }
    handoff::save(&handoff_path, &handoff)?;

    println!("relais           : {}", handoff_path.display());
    println!("domaine          : {}", handoff.trust_domain_id);
    println!("RP ID WebAuthn   : {}", handoff.rp_id);
    println!("CA-PQ (publique) : {}", handoff.ca_pq_public_key);
    println!("empreinte coffre : {}", handoff.vault_fingerprint);
    println!("époque CA-PQ     : {}", handoff.ca_epoch.unwrap_or(1));
    println!("époque CA-TLS    : {}", handoff.ca_tls_epoch.unwrap_or(1));
    println!(
        "gateway          : {}",
        handoff.gateway_wg_public_key.as_deref().unwrap_or("—")
    );
    println!(
        "nom de service   : {}",
        handoff.server_name.as_deref().unwrap_or("—")
    );
    println!(
        "origine autorité : {}",
        handoff.astra_authority_url.as_deref().unwrap_or("—")
    );
    println!(
        "clé Astra        : {}",
        match &handoff.astra_service_public_key {
            Some(key) => format!(
                "époque {} — {}",
                handoff.astra_service_key_epoch.unwrap_or(1),
                short_key(key)
            ),
            None => "—".into(),
        }
    );
    println!(
        "CA-TLS           : {}",
        match &handoff.ca_tls_certificate {
            Some(_) => "auto-signée",
            None => "— (`astra-signer issue-ca-tls`)",
        }
    );
    Ok(())
}

/// The domain identity every signing gesture is bound to.
///
/// Every value comes from the hand-off rather than from a command line: an
/// operator who retypes a gateway key eventually signs a delegation for the
/// wrong one, and `CA-PQ` vouching for it is not something a later check
/// undoes.
/// Opens the vault at one plugged-in key, and says which slot answered.
fn open_vault(vault: &AuthorityVault, transport: Transport, prompt: &str) -> Result<Opened> {
    eprintln!("{prompt}");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
    let opened = gestures::open_with_authorized_key(key.as_ref(), vault, &pin)?;
    let slot = vault.slot_for_credential(&opened.credential_id)?;
    eprintln!("Clé reconnue : « {} » ({}).", slot.label, slot.role);
    Ok(opened)
}

/// Re-emits the credential document from the key-slot table.
///
/// Called by every gesture that moves that table, in the same operation
/// (spec §2.4): a document describing a slot the vault no longer holds is a
/// signed lie, and nothing downstream can catch it.
///
/// A domain whose gateway is not recorded yet has no document to emit — the
/// bindings name the gateway — so this says so and changes nothing, rather
/// than emitting one bound to a guess.
fn resign_bindings(path: &Path, vault: &AuthorityVault, opening: &Opened) -> Result<()> {
    let handoff = handoff::DomainHandoff::beside(path, vault)?;
    let identity = match handoff::identity_of(&handoff) {
        Ok(identity) => identity,
        Err(_) => {
            println!(
                "credentials      : non émis — le relais ne porte pas encore la gateway. Après \
                 `astra-signer domain --gateway-wg-public-key … --server-name …`, lancer \
                 `astra-signer bindings`"
            );
            return Ok(());
        }
    };
    let registry_path = credentials::path_beside(path);
    let previous = credentials::load(&registry_path)?;
    let registry = authority::sign_credential_bindings(
        vault,
        opening,
        &identity,
        previous.as_ref(),
        &[],
        now_unix(),
    )?;
    credentials::save(&registry_path, &registry)?;
    println!(
        "credentials      : {} — époque {}",
        registry_path.display(),
        registry.credential_registry_epoch
    );
    Ok(())
}

fn issue_ca_tls(path: &Path, days: u64, out: Option<&Path>, transport: Transport) -> Result<()> {
    let vault = store::load(path)?;
    let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;
    if handoff.ca_tls_certificate.is_some() {
        bail!(
            "ce domaine porte déjà une CA-TLS à l'époque {} : `issue-ca-tls` initialise l'ancre, \
             il ne la remplace pas ; employer la transition CA-TLS du §9.4",
            handoff.ca_tls_epoch.unwrap_or(1)
        );
    }
    let identity = handoff::identity_of(&handoff)?;
    let not_before = now_unix();
    let not_after = not_before
        .checked_add(days.checked_mul(DAY_SECS).context("durée hors bornes")?)
        .context("durée hors bornes")?;

    let opening = open_vault(
        &vault,
        transport,
        "Auto-signature de CA-TLS. Brancher une clé autorisée, puis appuyer sur Entrée.",
    )?;
    let certificate = authority::issue_ca_tls(&vault, &opening, &identity, not_before, not_after)?;

    // The epoch moves with the certificate, in the same write: a hand-off
    // naming one epoch and carrying another would have every later delegation
    // refused at the gateway, under a signature that is perfectly valid.
    handoff.ca_tls_epoch = Some(identity.ca_tls_epoch);
    handoff.ca_tls_certificate = Some(certificate.to_base64());
    handoff::save(&handoff::path_beside(path), &handoff)?;
    if let Some(out) = out {
        std::fs::write(out, pem_of(&certificate))
            .with_context(|| format!("écriture de {}", out.display()))?;
        println!("certificat PEM   : {}", out.display());
    }

    println!(
        "relais           : {}",
        handoff::path_beside(path).display()
    );
    println!("époque CA-TLS    : {}", identity.ca_tls_epoch);
    println!("valide de        : {}", horodatage(not_before));
    println!("valide jusqu'à   : {}", horodatage(not_after));
    println!(
        "cette CA est épinglée par la gateway : la remplacer coupe tous les clients déjà \
         admis, et c'est la rotation du §9.4 qui la remplace"
    );
    Ok(())
}

/// Signs one bounded delegation to Astra's online issuer (spec §9.5).
///
/// # Why the campaign is the ordinary path
///
/// An [`IssuerDelegationRequest`] carries no signature. Read from a file, it
/// authorizes whoever handed the operator that file: substitute the ML-DSA-87
/// key, and the delegation certifies a key its holder chose. The campaign is
/// what closes that — it is signed by the authority's service key, it pins the
/// epoch and both public halves, and the operator reads them before the touch.
/// The offline form survives for a domain with no reachable origin, and says
/// so rather than pretending the two are equivalent.
#[allow(clippy::too_many_arguments)]
fn authorize_issuer(
    path: &Path,
    request_path: &Path,
    out: Option<&Path>,
    online: Option<(&str, &str)>,
    days: u64,
    leaf_days: u64,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::status::CampaignFamily;

    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_tls = DerCertificate::parse(handoff.require(
        handoff.ca_tls_certificate.as_ref(),
        "le certificat CA-TLS",
        "issue-ca-tls",
    )?)?;
    let campaign_context = match online {
        Some((authority_url, operation_id)) => {
            let operation = Id16::parse_hex(operation_id)
                .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
            let client = astra_signer::origin::Origin::new(authority_url)?;
            let request_document = origin_client_fetch(&client, &operation)?;
            handoff::verify_campaign_request(
                &handoff,
                &vault,
                &request_document,
                authority_url,
                now_unix(),
            )?;
            let campaign = request_document.campaign.as_ref().clone();
            if !matches!(campaign.scope.family(), CampaignFamily::IssuerDelegation) {
                bail!(
                    "cette opération n'autorise pas de délégation d'émetteur. Rien n'a été signé."
                );
            }
            Some((client, request_document, campaign))
        }
        None => None,
    };

    let request: IssuerDelegationRequest = documents::read(request_path)?;

    // The campaign pins the exact material, so a substituted request is
    // refused here — before the vault opens, and before the operator is asked
    // for anything.
    if let Some((_, _, campaign)) = &campaign_context {
        let csr = DerCertificate::new(
            <base64::engine::general_purpose::GeneralPurpose as base64::Engine>::decode(
                &base64::engine::general_purpose::STANDARD,
                request.tls_intermediate_csr.trim(),
            )
            .context("décodage de la demande d'intermédiaire")?,
        )?;
        let public_key_info =
            aether::certificates::x509::certification_request_public_key_info(&csr)?;
        let pq = MlDsa87PublicKey::parse(request.pq_issuer_public_key.trim())?;
        campaign
            .covers_issuer_delegation(
                identity.trust_domain_id,
                request.issuer_epoch,
                &aether::certificates::encoding::Fingerprint::of(pq.as_bytes()),
                &aether::certificates::encoding::Fingerprint::of(&public_key_info),
            )
            .context(
                "la demande de délégation n'est pas celle que la campagne nomme : époque ou clé \
                 substituée. Rien n'a été signé.",
            )?;
    }

    let not_before = now_unix();
    let bounds = DelegationBounds {
        maximum_leaf_lifetime_secs: leaf_days
            .checked_mul(DAY_SECS)
            .context("durée hors bornes")?,
        not_before,
        not_after: not_before
            .checked_add(days.checked_mul(DAY_SECS).context("durée hors bornes")?)
            .context("durée hors bornes")?,
    };

    println!("émetteur délégué : époque {}", request.issuer_epoch);
    println!("domaine          : {}", request.trust_domain_id);
    println!("gateway          : {}", identity.gateway_wg_public_key);
    println!("leaf au plus     : {leaf_days} jours");
    println!("délégation       : {days} jours");
    match &campaign_context {
        Some((_, _, campaign)) => {
            println!("campagne         : {}", campaign.campaign_id.to_hex());
            println!("empreinte        : {}", campaign.fingerprint());
            println!("motif            : {}", campaign.reason);
            println!("demandée par     : {}", campaign.requested_by);
        }
        None => println!(
            "hors campagne    : rien ne rattache cette demande à une autorité ; elle vaut ce que \
             vaut le fichier"
        ),
    }

    let authorization = match &campaign_context {
        Some((_, _, campaign)) => {
            let origin = origin
                .map(str::to_string)
                .unwrap_or_else(|| format!("https://{}", vault.rp_id));
            let registry =
                credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "aucun document de credentials : l'émettre par `astra-signer bindings`"
                    )
                })?;
            let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
            eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
            wait_for_operator()?;
            let key = authenticator::connect(transport)?;
            let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
            let approval = authority::approve_campaign(
                &[key.as_ref()],
                campaign,
                &registry,
                &identity,
                &ca_pq_public_key,
                &vault.rp_id,
                &origin,
                &[pin.as_str()],
                now_unix(),
            )?;
            let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
            let authorization = authority::authorize_issuer(
                &vault,
                &opening,
                &identity,
                &ca_tls,
                &request,
                &bounds,
                now_unix(),
            )?;
            (Some(approval), authorization)
        }
        None => {
            let opening = open_vault(
                &vault,
                transport,
                "Signature de la délégation. Brancher une clé autorisée, puis appuyer sur Entrée.",
            )?;
            let authorization = authority::authorize_issuer(
                &vault,
                &opening,
                &identity,
                &ca_tls,
                &request,
                &bounds,
                now_unix(),
            )?;
            (None, authorization)
        }
    };
    let (approval, authorization) = authorization;

    if let Some(out) = out {
        documents::write(out, &authorization)?;
        println!("autorisation     : {}", out.display());
    }
    match (&campaign_context, approval) {
        (Some((client, request_document, _)), Some(approval)) => {
            let mut result = campaign_result(&approval, Vec::new(), None);
            result.issuer_authorization = Some(Box::new(authorization));
            let state = client.submit(
                &request_document.operation_id,
                &request_document.result_token,
                &result,
            )?;
            println!("état             : {state:?}");
            println!(
                "la délégation est enregistrée par l'autorité ; redémarrer Astra pour émettre \
                 sous elle"
            );
        }
        _ => println!("à reporter sur l'autorité : astra issuer install --authorization <fichier>"),
    }
    println!(
        "cette délégation n'autorise qu'un renouvellement de leaf cliente admise, et rien \
         d'autre : ni gateway, ni CA, ni pair inconnu"
    );
    Ok(())
}

fn bindings(path: &Path, lost: &[String], active: &[String], transport: Transport) -> Result<()> {
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;

    // Slot identifiers rather than credential identifiers: `list` prints the
    // first, and a credential a decision is about is one the vault still
    // holds. Withdrawing a key already revokes it, and that is terminal.
    let mut overrides = Vec::new();
    for (slots, state) in [
        (lost, CredentialState::Lost),
        (active, CredentialState::Active),
    ] {
        for slot in slots {
            let slot_id = parse_slot_id(slot)?;
            overrides.push((vault.slot(&slot_id)?.credential_id()?, state));
        }
    }

    let registry_path = credentials::path_beside(path);
    let previous = credentials::load(&registry_path)?;
    let opening = open_vault(
        &vault,
        transport,
        "Signature du document de credentials. Brancher une clé autorisée, puis Entrée.",
    )?;
    let registry = authority::sign_credential_bindings(
        &vault,
        &opening,
        &identity,
        previous.as_ref(),
        &overrides,
        now_unix(),
    )?;
    credentials::save(&registry_path, &registry)?;

    println!("credentials      : {}", registry_path.display());
    println!("époque registre  : {}", registry.credential_registry_epoch);
    for line in credentials::summarize(&registry) {
        println!("{line}");
    }
    Ok(())
}

/// Where the request comes from, and where the assertion goes back to.
///
/// Two shapes, one gesture. What differs is only the transport, and the
/// verification is deliberately identical: the objects carry the signatures,
/// so a request fetched through a tunnel is trusted exactly as much — and
/// exactly as little — as one read from a path an operator typed.
enum ApprovalChannel {
    /// Files an operator names, for a machine outside the tunnel.
    Files { request: PathBuf, out: PathBuf },
    /// The client's own gateway, over the typed in-tunnel routes (§8.1.2).
    Tunnel {
        tunnel: tunnel::Tunnel,
        operation_id: Id16,
    },
}

#[allow(clippy::too_many_arguments)]
fn approve(
    path: &Path,
    request_path: Option<&Path>,
    out: Option<&Path>,
    heliosd_url: Option<&str>,
    operation_id: Option<&str>,
    active_generation: Option<u64>,
    transport: Transport,
) -> Result<()> {
    let channel = match (request_path, out, heliosd_url, operation_id) {
        (Some(request), Some(out), None, None) => ApprovalChannel::Files {
            request: request.to_path_buf(),
            out: out.to_path_buf(),
        },
        (None, None, Some(url), Some(operation)) => ApprovalChannel::Tunnel {
            tunnel: tunnel::Tunnel::new(url)?,
            operation_id: Id16::parse_hex(operation.trim())
                .context("identifiant d'opération invalide")?,
        },
        // Named rather than left to clap: `--request` without `--out` and
        // `--out` without `--request` are both legal for clap — neither
        // conflicts with anything — and the failure would otherwise be an
        // approval written nowhere, after the key was touched.
        _ => bail!(
            "choisir un chemin : soit --request et --out ensemble, soit --heliosd-url et \
             --operation-id ensemble"
        ),
    };

    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let service_key = MlDsa87PublicKey::parse(handoff.require(
        handoff.astra_service_public_key.as_ref(),
        "la clé de service d'Astra",
        "--astra-service-public-key",
    )?)?;
    let service_key_epoch = *handoff.require(
        handoff.astra_service_key_epoch.as_ref(),
        "l'époque de la clé de service d'Astra",
        "--astra-service-key-epoch",
    )?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!(
            "aucun document de credentials : l'émettre par `astra-signer bindings` avant \
             d'approuver quoi que ce soit"
        )
    })?;

    let (request, fetched) = match &channel {
        ApprovalChannel::Files { request, .. } => (
            Box::new(documents::read::<
                aether::certificates::approval::AstraCredentialApprovalRequest,
            >(request)?),
            None,
        ),
        ApprovalChannel::Tunnel {
            tunnel,
            operation_id,
        } => {
            println!("gateway          : demande récupérée dans le tunnel");
            let fetched = tunnel.fetch(operation_id)?;
            // Reported, never adopted. The RP ID the ceremony actually runs
            // under is the vault's, and a gateway that named another one would
            // otherwise have this key answer a challenge for another domain.
            if fetched.webauthn_rp_id != vault.rp_id {
                bail!(
                    "la gateway annonce le RP ID « {} » alors que ce coffre est celui de « {} ». \
                     Rien n'est signé : une assertion produite sous un autre RP ID vaudrait pour \
                     un autre domaine.",
                    fetched.webauthn_rp_id,
                    vault.rp_id
                );
            }
            println!("autorité annoncée: {}", fetched.authority_url);
            (fetched.approval_request, Some(fetched.result_token))
        }
    };

    // Shown before the key is touched, and shown from the request that Astra
    // signed rather than from anything this program chose.
    println!("opération        : {}", request.operation_id.to_hex());
    println!("client           : {}", request.client_wg_public_key);
    println!(
        "génération       : {} → {}",
        request.active_generation, request.requested_generation
    );
    println!(
        "demande          : {}",
        request.request_fingerprint.to_hex()
    );
    println!("expire à         : {}", horodatage(request.expires_at));

    // No vault, and no salt: §14.1 in the shape of a call. This is the whole
    // reason the vault is loaded above only for the hand-off and the registry.
    eprintln!("Brancher la clé d'approbation, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
    let approval = helios_fido::approve_renewal(
        key.as_ref(),
        &request,
        &service_key,
        service_key_epoch,
        &identity,
        &ca_pq_public_key,
        &registry,
        &vault.rp_id,
        active_generation,
        &pin,
        now_unix(),
    )?;

    match (&channel, fetched) {
        (ApprovalChannel::Files { out, .. }, _) => {
            documents::write(out, &approval)?;
            println!("approbation      : {}", out.display());
        }
        (
            ApprovalChannel::Tunnel {
                tunnel,
                operation_id,
            },
            Some(result_token),
        ) => {
            let state = tunnel.submit(operation_id, &result_token, &approval)?;
            println!("approbation      : déposée dans le tunnel");
            match state {
                ClientRenewalOperationState::PendingCommit => println!(
                    "état             : pending_commit — l'autorité a émis, la gateway a persisté \
                     et signé son reçu. Le client committe."
                ),
                ClientRenewalOperationState::PendingGrant => println!(
                    "état             : pending_grant — l'approbation est prise, l'émission est \
                     en cours."
                ),
                ClientRenewalOperationState::AwaitingOperator => bail!(
                    "l'autorité attend toujours un opérateur après avoir reçu cette assertion : \
                     elle ne l'a pas consommée. Ne pas réessayer sans savoir pourquoi."
                ),
                ClientRenewalOperationState::Failed => bail!(
                    "l'autorité a refusé après avoir reçu l'assertion. L'opération est terminée : \
                     le client doit en ouvrir une nouvelle."
                ),
            }
        }
        // Unreachable by construction: the tunnel arm always produces a token,
        // and the files arm never consults one. Named rather than unwrapped so
        // that a future third channel cannot silently drop the submission.
        (ApprovalChannel::Tunnel { .. }, None) => bail!(
            "aucun jeton de dépôt pour cette opération : l'assertion n'a été envoyée nulle part"
        ),
    }

    println!("empreinte        : {}", approval.fingerprint().to_hex());
    println!("valable jusqu'à  : {}", horodatage(approval.expires_at));
    println!(
        "le coffre n'a pas été ouvert : une approbation ordinaire n'obtient aucune sortie PRF \
         et Astra y ajoute sa propre signature"
    );
    Ok(())
}

/// Approves a manual campaign, offline or through Astra's public origin.
///
/// # Two transports, one ceremony
///
/// The gesture below is the same either way, and that is the point: what the
/// operator's key answers is the campaign fingerprint, recomputed from the
/// campaign itself. A campaign read from a file and one fetched from the
/// origin are the same object with the same signature over it — the wire
/// carries no authority.
///
/// The origin is the case the in-tunnel relay cannot cover (§8.2): an operator
/// on their own workstation has no VIP the gateway would resolve. What comes
/// back is compared against the vault's own relying party rather than adopted:
/// an assertion produced under another RP ID would be valid for another
/// domain.
#[allow(clippy::too_many_arguments)]
fn approve_campaign(
    path: &Path,
    campaign_path: Option<&Path>,
    out: Option<&Path>,
    authority_url: Option<&str>,
    operation_id: Option<&str>,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let online = match (authority_url, operation_id) {
        (Some(url), Some(id)) => {
            let operation =
                Id16::parse_hex(id).map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
            let origin_client = astra_signer::origin::Origin::new(url)?;
            let request = origin_client_fetch(&origin_client, &operation)?;
            Some((origin_client, request))
        }
        _ => None,
    };

    let campaign = match &online {
        Some((_, request)) => {
            handoff::verify_campaign_request(
                &handoff,
                &vault,
                request,
                authority_url.unwrap_or_default(),
                now_unix(),
            )?;
            request.campaign.as_ref().clone()
        }
        None => {
            let Some(campaign_path) = campaign_path else {
                bail!(
                    "donner soit --campaign et --out, soit --authority-url et --operation-id : \
                     un fichier hors ligne, ou l'origine publique du §8.2"
                );
            };
            if out.is_none() {
                bail!("--out est requis avec --campaign : sans lui l'approbation est perdue");
            }
            documents::read(campaign_path)?
        }
    };

    let origin = match origin {
        Some(origin) => origin.to_string(),
        None => format!("https://{}", vault.rp_id),
    };

    if campaign.scope.revokes() {
        bail!(
            "cette campagne retire une identité : l'exécuter par `astra-signer revoke \
             --authority-url … --operation-id …`, qui ouvre le coffre et dépose la décision \
             signée dans le même geste. Rien n'a été signé."
        );
    }
    if campaign.scope.rotates_authority() {
        // An anchor campaign is not approved and then applied: the approval
        // and the objects `CA-PQ` signs travel in one deposit (§0.6). Taking
        // the touch here would spend the operator's window on a result that
        // carries nothing.
        bail!(
            "cette campagne fait tourner une ancre : elle s'exécute par `astra-signer rotate-ca-pq \
             --authority-url … --operation-id …`, qui ouvre le coffre et rend les objets signés \
             dans le même dépôt. Rien n'a été signé."
        );
    }

    let required = usize::from(campaign.required_credentials);
    println!("campagne         : {}", campaign.campaign_id.to_hex());
    println!("portée           : {:?}", campaign.scope);
    println!("cibles           : {}", campaign.targets.len());
    println!("motif            : {}", campaign.reason);
    println!("demandée par     : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!("confirmations    : {required} clé(s) distincte(s)");

    // Plugged one at a time, and each connection is its own: two touches of
    // one token is what `approve_campaign` refuses, and asking for the keys
    // one after another is how an operator finds that out at the second.
    let mut keys = Vec::new();
    let mut pins = Vec::new();
    for index in 1..=required {
        eprintln!("Brancher la clé {index}/{required}, puis appuyer sur Entrée.");
        wait_for_operator()?;
        let key = authenticator::connect(transport)?;
        pins.push(pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?);
        keys.push(key);
    }
    let key_refs: Vec<&dyn astra_signer::authenticator::Authenticator> =
        keys.iter().map(|key| key.as_ref()).collect();
    let pin_refs: Vec<&str> = pins.iter().map(|pin| pin.as_str()).collect();

    let approval = authority::approve_campaign(
        &key_refs,
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &pin_refs,
        now_unix(),
    )?;

    match (&online, out) {
        (Some((client, request)), _) => {
            let result = campaign_result(&approval, Vec::new(), None);
            let state = client.submit(&request.operation_id, &request.result_token, &result)?;
            println!("opération        : {}", request.operation_id.to_hex());
            println!("état             : {state:?}");
            println!(
                "cette approbation est dépensée par la demande de chaque pair couvert, dans la \
                 fenêtre de la campagne. Un pair hors ligne pendant celle-ci n'est pas renouvelé."
            );
        }
        (None, Some(out)) => {
            documents::write(out, &approval)?;
            println!("approbation      : {}", out.display());
        }
        (None, None) => unreachable!("--out is required above when there is no origin"),
    }
    println!(
        "empreinte        : {}",
        approval.campaign_fingerprint.to_hex()
    );
    println!(
        "cette empreinte couvre les cibles et leur ordre : une cible ajoutée ensuite est \
         refusée, pas réapprouvée"
    );
    Ok(())
}

/// Reads the operation and its campaign, before anything is displayed.
///
/// Split out so the borrow of the client and the request it produced do not
/// have to be created in the same expression — and so the failure to fetch is
/// reported before an operator is asked to plug anything in.
/// Wraps what a ceremony produced into the one document §8.2 accepts.
///
/// Built here rather than by each gesture so the two cases stay visibly the
/// same shape: an ordinary campaign carries an approval and nothing else, an
/// anchor campaign carries the same approval plus what `CA-PQ` signed under
/// it. A second document for the second case would be a second thing to keep
/// equal on the wire.
fn campaign_result(
    approval: &aether::certificates::status::CampaignApproval,
    objects: Vec<aether::certificates::transport::TrustUpdateObject>,
    credential_registry: Option<Box<aether::certificates::approval::CredentialRegistry>>,
) -> aether::certificates::status::AstraSignerResult {
    aether::certificates::status::AstraSignerResult {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        approval: Box::new(approval.clone()),
        objects,
        credential_registry,
        issuer_authorization: None,
    }
}

/// What the operator decides about a revocation, and the authority does not.
struct RevocationInputs {
    scope: aether::certificates::revocation::RevocationScope,
    halves: RevokedHalvesArg,
    /// Signed expiry of each half. Absent means that half is not named.
    tls_not_after: Option<u64>,
    pq_not_after: Option<u64>,
    reason: aether::certificates::revocation::RevocationReason,
    /// The signed replacement transition this revocation names, if any.
    replacement: Option<std::path::PathBuf>,
}

/// Signs and deposits the revocation frozen into an Astra campaign (§10).
fn revoke(
    path: &Path,
    authority_url: &str,
    operation_id: &str,
    origin: Option<&str>,
    inputs: RevocationInputs,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::revocation::RevocationScope;

    let RevocationInputs {
        scope,
        halves,
        tls_not_after,
        pq_not_after,
        reason,
        replacement,
    } = inputs;
    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let client = astra_signer::origin::Origin::new(authority_url)?;
    let request = origin_client_fetch(&client, &operation)?;
    handoff::verify_campaign_request(&handoff, &vault, &request, authority_url, now_unix())?;
    let campaign = request.campaign.as_ref().clone();
    if !campaign.scope.revokes() {
        bail!("cette opération n'est pas une révocation. Rien n'a été signé.");
    }
    if campaign.targets.len() != 1 {
        bail!(
            "une révocation doit nommer exactement une identité, {} présentes. Rien n'a été signé.",
            campaign.targets.len()
        );
    }
    let target = campaign
        .targets
        .first()
        .context("la campagne ne nomme aucune identité")?;
    let revocation_epoch = target
        .epoch
        .checked_add(1)
        .context("revocation counter overflow")?;
    let (revoke_tls, revoke_pq) = match halves {
        RevokedHalvesArg::Both => (true, true),
        RevokedHalvesArg::Tls => (true, false),
        RevokedHalvesArg::Pq => (false, true),
    };
    // Each named half carries its own signed expiry (§10.1). A missing one is
    // refused rather than defaulted: an expiry chosen here would be an expiry
    // no leaf actually carries, and every recipient would refuse the object.
    if revoke_tls && tls_not_after.is_none() {
        bail!("--tls-not-after (or --not-after) is required to withdraw the TLS leaf");
    }
    if revoke_pq && pq_not_after.is_none() {
        bail!("--pq-not-after (or --not-after) is required to withdraw the PQ leaf");
    }
    let now = now_unix();

    // Read from the signed document rather than typed on a command line: a
    // fingerprint an operator retypes is a fingerprint that can be retyped
    // wrong, and the failure would be a revoked gateway waiting forever for a
    // transition nobody can produce.
    let replacement_transition_fingerprint = match &replacement {
        None => None,
        Some(source) => {
            if scope != RevocationScope::Gateway {
                bail!(
                    "--replacement-transition ne vaut que pour --scope gateway : une identité \
                     cliente révoquée est réadmise, elle n'est pas remplacée par une transition."
                );
            }
            let transition: aether::certificates::gateway::GatewayIdentityTransition =
                read_json(source, "la transition de remplacement")?;
            if transition.reason
                != aether::certificates::authority::RotationReason::EmergencyReplacement
            {
                bail!(
                    "cette transition ne porte pas le motif emergency_replacement : une gateway \
                     révoquée n'accepte que celui-là (§6.1). Rien n'a été signé."
                );
            }
            if transition.gateway_wg_public_key != target.identity_key
                || transition.server_name != campaign.server_name
            {
                bail!(
                    "la transition de remplacement vise une autre gateway que celle que cette \
                     révocation retire. Rien n'a été signé."
                );
            }
            Some(transition.fingerprint()?)
        }
    };

    println!("révocation       : {}", operation.to_hex());
    println!("portée           : {scope:?}");
    println!("identité         : {}", target.identity_key.to_base64());
    println!("gateway          : {}", campaign.server_name);
    println!("génération       : {}", target.generation);
    println!("compteur         : {} → {revocation_epoch}", target.epoch);
    println!(
        "feuilles         : {}",
        match (revoke_tls, revoke_pq) {
            (true, true) => "TLS et PQ",
            (true, false) => "TLS",
            (false, true) => "PQ",
            (false, false) => unreachable!("the command always selects a half"),
        }
    );
    println!(
        "échéances signées: TLS {} · PQ {}",
        tls_not_after.map_or("—".to_string(), horodatage),
        pq_not_after.map_or("—".to_string(), horodatage)
    );
    println!("effet            : immédiat ({})", horodatage(now));
    println!("catégorie        : {reason:?}");
    println!("motif            : {}", campaign.reason);
    println!("demandée par     : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!(
        "terminal         : {}",
        match (scope, replacement_transition_fingerprint) {
            (RevocationScope::Client, _) => "cette identité devra être réadmise".to_string(),
            (RevocationScope::Gateway, None) => "la gateway ne négociera plus ; aucune transition \
                                                 ne sera acceptée ensuite"
                .to_string(),
            (RevocationScope::Gateway, Some(fingerprint)) => format!(
                "la gateway ne négociera plus, sauf par la transition {fingerprint} — le seul \
                 document qu'elle acceptera ensuite"
            ),
        }
    );

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    let approval = authority::approve_campaign(
        &[key.as_ref()],
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &[pin.as_str()],
        now,
    )?;
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let decision = authority::RevocationDecision {
        scope,
        identity_key: target.identity_key,
        // §10.1 names the service only for a gateway: a client leaf is
        // identified by its WireGuard key, and a name there would be a second
        // identifier nobody verifies.
        server_name: match scope {
            RevocationScope::Client => None,
            RevocationScope::Gateway => Some(campaign.server_name.clone()),
        },
        revocation_epoch,
        revoked_tls: revoke_tls
            .then(|| tls_not_after.map(|at| (target.active_tls_certificate_fingerprint, at)))
            .flatten(),
        revoked_pq: revoke_pq
            .then(|| pq_not_after.map(|at| (target.active_pq_certificate_fingerprint, at)))
            .flatten(),
        effective_at: now,
        reason,
        replacement_transition_fingerprint,
    };
    let revocation = authority::sign_revocation(
        &vault,
        &opening,
        &identity,
        &ca_pq_public_key,
        &decision,
        target.epoch,
    )?;
    campaign
        .covers_revocation(&revocation)
        .context("la décision signée ne correspond pas à la campagne approuvée")?;

    let result = campaign_result(
        &approval,
        vec![
            aether::certificates::transport::TrustUpdateObject::CertificateRevocation(Box::new(
                revocation,
            )),
        ],
        None,
    );
    let state = client.submit(&request.operation_id, &request.result_token, &result)?;
    println!("état             : {state:?}");
    println!("décision déposée : Astra la relaie à la gateway et la distribue aux clients");
    Ok(())
}

/// Rotates the client `CA-TLS` under an approved authority campaign (§9.4).
///
/// # Why this one has no offline form
///
/// `rotate-ca-pq` can run without an authority because the operator's vault
/// **is** the `CA-PQ` authority: it holds the outgoing key and can vouch for
/// its successor alone. The client TLS anchor is different — the object that
/// installs it is authorised by `CA-PQ`, and what says *which* anchor is
/// current is the domain's registry, not this vault. A rotation resolved from
/// the vault alone could name an anchor the fleet retired months ago.
fn rotate_ca_tls(
    path: &Path,
    channel: astra_signer::campaign::Campaign,
    operation_id: &str,
    origin: Option<&str>,
    out: &Path,
    (prepare_days, overlap_days, validity_days): (u64, u64, u64),
    transport: Transport,
) -> Result<()> {
    use aether::certificates::transport::TrustUpdateObject;

    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let mut vault = store::load(path)?;
    // One window at a time, and one *finished* window at a time. A second
    // ceremony opened over an outstanding deposit would spend a second
    // campaign approval on a domain that has not accepted the first, and the
    // two rotations would then name each other's outgoing anchor.
    let prepared_path = prepared::path_beside(path);
    if let Some(outstanding) = prepared::load(&prepared_path)? {
        bail!(
            "une rotation CA-TLS est déjà préparée vers l'époque {} ({}) : {}. Rien n'a été signé.",
            outstanding.next_ca_tls_epoch,
            if outstanding.submitted {
                "déposée, en attente de promotion"
            } else {
                "jamais déposée"
            },
            if outstanding.submitted {
                "la mener à son terme par `astra-signer promote-ca-tls`"
            } else {
                "la déposer par `astra-signer resume-rotation`"
            }
        );
    }
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let active_certificate = DerCertificate::parse(handoff.require(
        handoff.ca_tls_certificate.as_ref(),
        "le certificat CA-TLS en service",
        "--ca-tls-certificate",
    )?)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let expected_url = handoff::expected_authority_url(&handoff, &channel)?;
    println!("transport        : {}", channel.description());
    let request = channel.fetch(&operation)?;
    handoff::verify_campaign_request(&handoff, &vault, &request, &expected_url, now_unix())?;
    let campaign = request.campaign.as_ref().clone();
    if !campaign.scope.rotates_authority() {
        bail!("cette campagne ne fait tourner aucune ancre. Rien n'a été signé.");
    }

    let now = now_unix();
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

    println!("rotation de CA-TLS: l'ancre du transport mTLS client change.");
    println!("opération        : {}", operation.to_hex());
    println!(
        "époque           : {} → {}",
        identity.ca_tls_epoch,
        identity.ca_tls_epoch + 1
    );
    println!("ancre sortante   : {}", active_certificate.fingerprint());
    println!("activation       : {}", horodatage(activation_at));
    println!("retrait          : {}", horodatage(window.not_after));
    println!("motif            : {}", campaign.reason);
    println!("demandée par     : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!(
        "effet            : pendant le recouvrement les deux chaînes sont acceptées ; après \
         not_after, une leaf émise sous l'ancienne ne monte plus de tunnel"
    );

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    let mut approval = authority::CampaignApprovalSession::new(
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        now,
    )?;

    // Approve with each key while it is still plugged in. Windows WebAuthn
    // handles are platform selectors, not handles tied to the physical token
    // present when `connect` ran; delaying both assertions until after the
    // swap makes the second token answer the first slot and leaves the first
    // token requested forever by the narrowed allow-list.
    let first = connect_authorized_key(
        &vault,
        transport,
        "Brancher la PREMIÈRE clé autorisée, puis appuyer sur Entrée.",
    )?;
    let offered = approval.offered_credentials();
    let assertion = first.key.approve(
        approval.webauthn_rp_id(),
        &offered,
        approval.client_data_json(),
        &first.pin,
    )?;
    approval.accept_for(assertion, Some(&first.opened.credential_id), now_unix())?;
    eprintln!();
    let second = connect_authorized_key(
        &vault,
        transport,
        "Débrancher celle-ci, brancher la SECONDE clé autorisée, puis Entrée.",
    )?;
    let offered = approval.offered_credentials();
    let assertion = second.key.approve(
        approval.webauthn_rp_id(),
        &offered,
        approval.client_data_json(),
        &second.pin,
    )?;
    approval.accept_for(assertion, Some(&second.opened.credential_id), now_unix())?;
    let approval = approval.finish(now_unix())?;

    let rotated = authority::rotate_ca_tls(
        &mut vault,
        &first.opened,
        &identity,
        &active_certificate,
        window,
        validity,
    )?;
    let transition_document = rotated.transition.clone();
    let object = TrustUpdateObject::ClientTlsCaTransition(Box::new(rotated.transition));
    campaign
        .covers_authority_object(&object)
        .context("la transition signée ne correspond pas à la campagne approuvée")?;

    // Signed, verified, and covered by the approval. Only now does anything
    // durable move, and the vault moves first: it is the one file on this
    // machine built to hold the successor's private half.
    store::save(path, &vault)?;

    let result = campaign_result(&approval, vec![object.clone()], None);
    let record = prepared::PreparedRotation {
        kind: prepared::PreparedKind::CaTls,
        operation_id: request.operation_id.to_hex(),
        result_token: request.result_token.clone(),
        result,
        transition_path: out.display().to_string(),
        next_ca_tls_epoch: identity.ca_tls_epoch + 1,
        next_ca_tls_certificate: rotated.next_certificate.to_base64(),
        activation_at: window.activation_at,
        not_after: window.not_after,
        submitted: false,
        prepared_at: now,
        // The same public campaign summary the terminal printed above. A
        // window survives its ceremony by days, and whatever resumes it — this
        // binary or the Orion companion — must be able to name what was
        // approved without re-fetching a campaign that is already closed.
        manifest: Some(orion::manifest_of(
            &campaign,
            &identity,
            &active_certificate,
            window,
        )?),
    };
    // Written before the deposit is attempted, and holding the exact bytes of
    // it. A crash after this point is a replay; a crash before it is a
    // ceremony that changed nothing anyone else can see.
    prepared::save(&prepared_path, &record)?;

    // The bare transition, not the tagged `TrustUpdateObject` envelope. The
    // envelope is what Astra's registry consumes; this file is what
    // `heliosd install-client-tls-ca` reads, and that reader refuses an
    // unknown `kind` field — so writing the envelope produced a file the very
    // command printed below could not parse.
    let encoded =
        serde_json::to_vec_pretty(&transition_document).context("encodage de la transition")?;
    std::fs::write(out, &encoded).with_context(|| format!("écriture de {}", out.display()))?;
    println!("transition écrite: {}", out.display());
    println!(
        "ancre entrante   : {}",
        rotated.next_certificate.fingerprint()
    );

    submit_prepared(&channel, &prepared_path, record)?;
    // The file is on *this* machine; the command runs on the gateway. Naming
    // the local path inside the remote command printed an instruction that
    // could not work — the operator has to copy the file across first.
    println!();
    println!("à reporter sur la gateway, en deux temps :");
    println!("  1. copier {} sur la gateway", out.display());
    println!("  2. y lancer : heliosd install-client-tls-ca <le fichier copié>");
    println!(
        "puis, à partir du {} : astra-signer promote-ca-tls",
        horodatage(window.not_after)
    );
    println!(
        "  (l'époque CA-TLS reste à {} pendant tout le recouvrement)",
        identity.ca_tls_epoch
    );
    Ok(())
}

/// Deposits a prepared rotation and records that it landed.
///
/// The record is updated **after** the authority accepts, never before: a
/// machine that marked it submitted and then failed to send would have lost
/// the only trace that anything still had to be sent.
fn submit_prepared(
    client: &astra_signer::campaign::Campaign,
    prepared_path: &Path,
    mut record: prepared::PreparedRotation,
) -> Result<()> {
    let operation = Id16::parse_hex(&record.operation_id)
        .map_err(|error| anyhow::anyhow!("rotation préparée illisible : {error}"))?;
    let state = client.submit(&operation, &record.result_token, &record.result)?;
    record.submitted = true;
    prepared::save(prepared_path, &record)?;
    println!("état             : {state:?}");
    Ok(())
}

/// Replays the deposit of a rotation the ceremony already committed to (§8.2).
fn resume_rotation(path: &Path, channel: astra_signer::campaign::Campaign) -> Result<()> {
    let prepared_path = prepared::path_beside(path);
    let Some(record) = prepared::load(&prepared_path)? else {
        println!("aucune rotation préparée : rien à reprendre.");
        return Ok(());
    };
    if record.submitted {
        println!(
            "la rotation vers l'époque {} est déjà déposée. La poursuivre par `astra-signer \
             promote-ca-tls` à partir de {}.",
            record.next_ca_tls_epoch,
            horodatage(record.activation_at)
        );
        return Ok(());
    }
    println!(
        "reprise du dépôt : rotation CA-TLS vers l'époque {}, préparée à {}.",
        record.next_ca_tls_epoch,
        horodatage(record.prepared_at)
    );
    println!("transition       : {}", record.transition_path);
    // No security key. The decision was approved when it was signed; this
    // sends bytes that already exist.
    println!("transport        : {}", channel.description());
    submit_prepared(&channel, &prepared_path, record)
}

/// Advances the open `CA-TLS` window by one step (§9.2).
fn promote_ca_tls(path: &Path, transport: Transport) -> Result<()> {
    use astra::vault::CaTlsAdvance;

    let mut vault = store::load(path)?;
    let prepared_path = prepared::path_beside(path);
    let Some(record) = prepared::load(&prepared_path)? else {
        bail!("aucune rotation CA-TLS en cours : rien à promouvoir.");
    };
    if !record.submitted {
        bail!(
            "la rotation vers l'époque {} n'a jamais été déposée : la promouvoir ici ferait \
             émettre sous une ancre que le domaine ignore. La déposer par `astra-signer \
             resume-rotation`.",
            record.next_ca_tls_epoch
        );
    }

    let now = now_unix();
    println!("rotation CA-TLS  : époque {}.", record.next_ca_tls_epoch);
    println!("activation parc  : {}", horodatage(record.activation_at));
    println!("retrait          : {}", horodatage(record.not_after));

    // One key: this executes a decision two credentials already approved. It
    // opens the vault, it does not authorise anything new.
    let opened = connect_authorized_key(
        &vault,
        transport,
        "Brancher une clé autorisée, puis appuyer sur Entrée.",
    )?;
    let opening = gestures::open_with_authorized_key(opened.key.as_ref(), &vault, &opened.pin)?;
    let advance = authority::advance_ca_tls(&mut vault, &opening, now)?;

    match &advance {
        CaTlsAdvance::Idle => {
            bail!(
                "le coffre ne porte aucune fenêtre CA-TLS ouverte alors qu'une rotation est \
                 enregistrée : les deux fichiers ne décrivent pas le même coffre."
            );
        }
        CaTlsAdvance::Awaiting { at } => {
            println!(
                "rien à faire : l'ancre sortante émet jusqu'à {at}. C'est le recouvrement — la \
                 gateway exige encore la génération {} et refuserait la suivante.",
                record.next_ca_tls_epoch - 1
            );
        }
        CaTlsAdvance::Rotated {
            certificate_fingerprint,
            destroyed_fingerprint,
        } => {
            store::save(path, &vault)?;
            // The hand-off moves with the vault, and only now: every issuance
            // command resolves its anchor and its generation from it, and the
            // gateway advances its own `ca_tls_epoch` at this same second.
            let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;
            handoff.ca_tls_epoch = Some(record.next_ca_tls_epoch);
            handoff.ca_tls_certificate = Some(record.next_ca_tls_certificate.clone());
            handoff::save(&handoff::path_beside(path), &handoff)?;
            prepared::clear(&prepared_path)?;
            println!("ancre en service : {certificate_fingerprint}");
            println!("époque CA-TLS    : {}", record.next_ca_tls_epoch);
            println!("clé privée détruite : {destroyed_fingerprint}");
            println!("fenêtre refermée : une nouvelle rotation peut être ouverte.");
        }
    }
    Ok(())
}

/// Issues the first gateway leaf without inventing an online Astra campaign.
fn issue_gateway_bootstrap(
    path: &Path,
    request_path: &Path,
    out: &Path,
    validity_days: u64,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::gateway::GatewayBootstrapRequest;
    use aether::certificates::status::CampaignScope;

    let vault = store::load(path)?;
    let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let request: GatewayBootstrapRequest =
        read_json(request_path, "la demande d'amorçage gateway")?;
    request.verify()?;
    // The gateway this domain serves, recorded once rather than retyped.
    //
    // This ceremony is the first thing that learns it, from a request the
    // gateway signed with its own sealed key, and every later command needs
    // it: `issue-ca-tls` pins the issuance policy over exactly these two
    // values. Leaving them out of the hand-off is what forces an operator to
    // pass `astra-signer domain --gateway-wg-public-key ...` by hand between
    // two steps that both already hold the value.
    //
    // Recorded, never replaced: ADR-008 binds a trust domain to one gateway,
    // so a request naming another one is a mistake to stop on, not a second
    // identity to adopt.
    let gateway_key = request.gateway_wg_public_key.to_base64();
    for (held, found, what) in [
        (
            handoff.gateway_wg_public_key.as_deref(),
            gateway_key.as_str(),
            "la clé publique WireGuard",
        ),
        (
            handoff.server_name.as_deref(),
            request.server_name.as_str(),
            "le nom de service",
        ),
    ] {
        if let Some(held) = held {
            if held != found {
                bail!(
                    "ce relais nomme déjà une autre gateway : {what} y vaut « {held} », la \
                     demande porte « {found} ». Un domaine de confiance sert une gateway et une \
                     seule."
                );
            }
        }
    }
    handoff.gateway_wg_public_key = Some(gateway_key);
    handoff.server_name = Some(request.server_name.clone());
    handoff::save(&handoff::path_beside(path), &handoff)?;
    let now = now_unix();
    let validity = validity_days
        .checked_mul(DAY_SECS)
        .and_then(|seconds| now.checked_add(seconds))
        .context("durée de validité hors bornes")?;

    let scope = CampaignScope::GatewayBootstrap;
    println!("amorçage gateway : émission de l'époque 1 sous CA-PQ");
    println!("gateway          : {}", request.server_name);
    println!(
        "identité         : {}",
        request.gateway_wg_public_key.to_base64()
    );
    println!("demande          : {}", request.fingerprint());
    println!("valide jusqu'à   : {}", horodatage(validity));
    println!(
        "credentials      : {} actifs distincts (admission sans continuité)",
        scope.required_credentials()
    );
    println!("transport        : fichiers uniquement ; Astra n'a encore aucun registre");

    let first = connect_authorized_key(
        &vault,
        transport,
        "Brancher le PREMIER credential autorisé, puis appuyer sur Entrée.",
    )?;
    eprintln!();
    let second = connect_authorized_key(
        &vault,
        transport,
        "Débrancher celui-ci, brancher le SECOND credential autorisé, puis Entrée.",
    )?;
    gestures::require_scope_credentials(scope, &[&first.opened, &second.opened])?;
    // Both credentials must open the current vault, not merely resolve to a
    // slot. This is the bootstrap trial ADR-008 requires before first use.
    gestures::prove_anchors_open(&vault, &first.opened)?;
    gestures::prove_anchors_open(&vault, &second.opened)?;

    let certificate = authority::issue_gateway_bootstrap_certificate(
        &vault,
        &first.opened,
        &ca_pq_public_key,
        &authority::GatewayBootstrapDecision {
            request: &request,
            leaf_validity: (now.saturating_sub(300), validity),
            serial: random_id()?,
        },
    )?;
    let encoded = serde_json::to_vec_pretty(&certificate).context("encodage de la feuille")?;
    std::fs::write(out, encoded).with_context(|| format!("écriture de {}", out.display()))?;
    println!("feuille écrite   : {}", out.display());
    println!("empreinte        : {}", certificate.fingerprint()?);
    Ok(())
}

/// Everything the gateway ceremony reads from the operator's command line.
struct GatewayTransitionInputs<'a> {
    request: &'a Path,
    active_certificate: Option<&'a Path>,
    tls_certificate: Option<&'a Path>,
    out: &'a Path,
    validity_days: u64,
    prepare_days: u64,
    overlap_days: u64,
    key_recovery: bool,
    emergency_replacement: bool,
}

/// Issues the next gateway leaf and signs its transition (spec §11.1 step 4).
fn sign_gateway_transition(
    path: &Path,
    channel: astra_signer::campaign::Campaign,
    operation_id: &str,
    origin: Option<&str>,
    inputs: GatewayTransitionInputs<'_>,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::gateway::{Continuity, GatewayCertificateRequest};
    use aether::certificates::status::CampaignFamily;

    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let expected_url = handoff::expected_authority_url(&handoff, &channel)?;
    println!("transport        : {}", channel.description());
    let request_document = channel.fetch(&operation)?;
    handoff::verify_campaign_request(
        &handoff,
        &vault,
        &request_document,
        &expected_url,
        now_unix(),
    )?;
    let campaign = request_document.campaign.as_ref().clone();
    if !matches!(campaign.scope.family(), CampaignFamily::GatewayIdentity) {
        bail!("cette opération ne décide pas l'identité gateway. Rien n'a été signé.");
    }
    let target = match campaign.targets.as_slice() {
        [only] => only,
        targets => bail!(
            "une décision gateway nomme exactement une identité, {} présentes. Rien n'a été signé.",
            targets.len()
        ),
    };

    let request: GatewayCertificateRequest = read_json(inputs.request, "la demande gateway")?;
    let epoch = target
        .epoch
        .checked_add(1)
        .context("époque de décision hors bornes")?;
    if request.gateway_identity_epoch != epoch {
        bail!(
            "la demande porte l'époque {} et cette campagne autorise la {epoch}. Rien n'a été \
             signé.",
            request.gateway_identity_epoch
        );
    }
    let now = now_unix();

    // The continuity signature proves the request comes from the identity in
    // place. It cannot be checked without that identity's public key, which
    // this companion does not hold — `astra gateway-identity open` exports it
    // from the daemon that serves it.
    let continuity_key = match inputs.active_certificate {
        Some(source) => {
            let served: aether::key_negotiation::PqCertificate =
                read_json(source, "la feuille en service")?;
            let fingerprint = aether::certificates::gateway::pq_certificate_fingerprint(&served)?;
            if !target
                .active_pq_certificate_fingerprint
                .matches(&fingerprint)
            {
                bail!(
                    "la feuille fournie n'est pas celle que la campagne épingle. Rien n'a été \
                     signé."
                );
            }
            Some(MlDsa87PublicKey::parse(&served.ml_dsa_87_public_key)?)
        }
        None if inputs.key_recovery => None,
        None => bail!(
            "--active-certificate est requis : sans la feuille en service, la continuité du §5 \
             n'est pas vérifiable. Une demande sans continuité exige --key-recovery."
        ),
    };
    request.verify(
        match continuity_key.as_ref() {
            Some(key) => Continuity::Required(key),
            None => Continuity::WaivedForKeyRecovery,
        },
        &identity.trust_domain_id,
        target.epoch,
        &campaign.gateway_wg_public_key,
        &campaign.server_name,
        now,
    )?;

    let next_tls = inputs
        .tls_certificate
        .map(|source| -> Result<DerCertificate> {
            let der = std::fs::read(source)
                .with_context(|| format!("lecture de {}", source.display()))?;
            Ok(DerCertificate::new(der)?)
        })
        .transpose()?;

    let day =
        |days: u64| -> Result<u64> { days.checked_mul(DAY_SECS).context("durée hors bornes") };
    let activation_at = now
        .checked_add(day(inputs.prepare_days)?)
        .context("durée hors bornes")?;
    let window = TransitionWindow::new(
        now,
        activation_at,
        activation_at
            .checked_add(day(inputs.overlap_days)?)
            .context("durée hors bornes")?,
    )?;
    let leaf_validity = (
        now,
        now.checked_add(day(inputs.validity_days)?)
            .context("durée hors bornes")?,
    );

    println!("opération        : {}", operation.to_hex());
    println!("gateway          : {}", campaign.server_name);
    println!(
        "identité         : {}",
        campaign.gateway_wg_public_key.to_base64()
    );
    println!("époque           : {} → {epoch}", target.epoch);
    println!(
        "feuille PQ       : {}",
        target.active_pq_certificate_fingerprint
    );
    println!(
        "feuille TLS      : {}",
        target.active_tls_certificate_fingerprint
    );
    println!(
        "TLS remplacée    : {}",
        match &next_tls {
            Some(certificate) => certificate.fingerprint().to_hex(),
            None => "inchangée".to_string(),
        }
    );
    println!(
        "continuité       : {}",
        if continuity_key.is_some() {
            "vérifiée"
        } else {
            "levée (récupération de clé)"
        }
    );
    println!("activation       : {}", horodatage(activation_at));
    println!("retrait          : {}", horodatage(window.not_after));
    println!("motif            : {}", campaign.reason);
    println!("demandée par     : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!("effet            : aucun avant activation_at ; heliosd redémarre à cet instant");

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    let approval = authority::approve_campaign(
        &[key.as_ref()],
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &[pin.as_str()],
        now,
    )?;
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let decision = authority::GatewayTransitionDecision {
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: campaign.gateway_wg_public_key,
        server_name: campaign.server_name.clone(),
        active_tls_fingerprint: target.active_tls_certificate_fingerprint,
        active_pq_fingerprint: target.active_pq_certificate_fingerprint,
        next_pq_public_key: request.new_ml_dsa_87_public_key.clone(),
        next_tls_certificate: next_tls,
        window,
        leaf_validity,
        reason: match (inputs.emergency_replacement, inputs.key_recovery) {
            (true, _) => aether::certificates::authority::RotationReason::EmergencyReplacement,
            (false, true) => aether::certificates::authority::RotationReason::KeyRecovery,
            (false, false) => aether::certificates::authority::RotationReason::Scheduled,
        },
        serial: random_id()?,
    };
    let transition = authority::sign_gateway_transition(
        &vault,
        &opening,
        &identity,
        &ca_pq_public_key,
        &decision,
    )?;
    campaign
        .covers_gateway_transition(&transition)
        .context("la décision signée ne correspond pas à la campagne approuvée")?;

    deposit_gateway_decision(
        &channel,
        &request_document,
        &approval,
        aether::certificates::transport::TrustUpdateObject::GatewayIdentityTransition(Box::new(
            transition,
        )),
        inputs.out,
        "transition",
    )
}

/// Signs the cancellation of a staged gateway transition (spec §6.3).
#[allow(clippy::too_many_arguments)]
fn abort_gateway_transition(
    path: &Path,
    channel: astra_signer::campaign::Campaign,
    operation_id: &str,
    origin: Option<&str>,
    transition_path: &Path,
    out: &Path,
    reason: aether::certificates::gateway::AbortReason,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::gateway::GatewayIdentityTransition;
    use aether::certificates::status::CampaignFamily;

    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let expected_url = handoff::expected_authority_url(&handoff, &channel)?;
    println!("transport        : {}", channel.description());
    let request_document = channel.fetch(&operation)?;
    handoff::verify_campaign_request(
        &handoff,
        &vault,
        &request_document,
        &expected_url,
        now_unix(),
    )?;
    let campaign = request_document.campaign.as_ref().clone();
    if !matches!(campaign.scope.family(), CampaignFamily::GatewayIdentity) {
        bail!("cette opération ne décide pas l'identité gateway. Rien n'a été signé.");
    }
    let target = match campaign.targets.as_slice() {
        [only] => only,
        targets => bail!(
            "une décision gateway nomme exactement une identité, {} présentes. Rien n'a été signé.",
            targets.len()
        ),
    };

    let transition: GatewayIdentityTransition =
        read_json(transition_path, "la transition à annuler")?;
    if transition.gateway_identity_epoch != target.epoch {
        bail!(
            "cette campagne porte la décision {} et la transition fournie la {}. Rien n'a été \
             signé.",
            target.epoch,
            transition.gateway_identity_epoch
        );
    }
    let now = now_unix();
    if now >= transition.window.activation_at {
        bail!(
            "activation_at est atteint : la transition est en recouvrement et ne s'annule plus \
             (§6.3). Promouvoir, puis préparer une nouvelle transition."
        );
    }

    println!("opération        : {}", operation.to_hex());
    println!("gateway          : {}", campaign.server_name);
    println!("époque annulée   : {}", transition.gateway_identity_epoch);
    println!("transition       : {}", transition.fingerprint()?);
    println!(
        "activation prévue: {}",
        horodatage(transition.window.activation_at)
    );
    println!("motif            : {reason:?}");
    println!("demandé par      : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!(
        "effet            : l'époque reste consommée ; la suivante repart une décision plus haut"
    );

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    let approval = authority::approve_campaign(
        &[key.as_ref()],
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &[pin.as_str()],
        now,
    )?;
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let abort = authority::sign_gateway_abort(
        &vault,
        &opening,
        &identity,
        &ca_pq_public_key,
        &authority::GatewayAbortDecision {
            transition: &transition,
            reason,
            campaign_fingerprint: campaign.fingerprint(),
            aborted_at: now,
        },
    )?;
    campaign
        .covers_gateway_abort(&abort)
        .context("l'avortement signé ne correspond pas à la campagne approuvée")?;

    deposit_gateway_decision(
        &channel,
        &request_document,
        &approval,
        aether::certificates::transport::TrustUpdateObject::GatewayTransitionAbort(Box::new(abort)),
        out,
        "avortement",
    )
}

/// Signs the temporary selection of the outgoing gateway leaf (spec §11.1
/// step 8).
///
/// # Why this one opens no Astra operation
///
/// Every other gateway gesture goes through the authority because it produces
/// a `TrustUpdateObject` the domain distributes. A rollback produces none: it
/// moves no counter, removes no slot, and no client ever sees it — §4.4 calls
/// it a service rollback precisely to say that. The authority's own guard
/// agrees, and by construction: a gateway-identity campaign result must carry
/// exactly one trust-update object, so depositing this would mean inventing a
/// distributable form of a decision that must never be distributed.
///
/// So the campaign is resolved here, from the signed transition itself —
/// §11.6 keeps that resolution local anyway — displayed in full, and attested
/// by one authorized key before `CA-PQ` signs. The record of the gesture is
/// the gateway's, which is where the selection takes effect.
#[allow(clippy::too_many_arguments)]
fn sign_gateway_rollback(
    path: &Path,
    transition_path: &Path,
    out: &Path,
    hours: u64,
    reason: &str,
    requested_by: &str,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::gateway::GatewayIdentityTransition;
    use aether::certificates::status::{
        AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind,
    };

    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let transition: GatewayIdentityTransition =
        read_json(transition_path, "la transition en recouvrement")?;
    if transition.gateway_wg_public_key != identity.gateway_wg_public_key {
        bail!("cette transition vise une autre gateway. Rien n'a été signé.");
    }
    let now = now_unix();
    if now < transition.window.activation_at {
        bail!(
            "activation_at n'est pas atteint : l'ancienne identité est encore celle qui sert, il              n'y a rien à retrouver. Pour annuler la transition, `abort-gateway-transition`              (§6.3)."
        );
    }
    if now >= transition.window.not_after {
        bail!(
            "le recouvrement est terminé : après not_after, ramener l'ancienne feuille serait un              rollback d'état, pas un rollback de service (§4.4)."
        );
    }
    let expires_at = hours
        .checked_mul(3_600)
        .and_then(|seconds| now.checked_add(seconds))
        .context("durée hors bornes")?
        .min(transition.window.not_after);

    // Resolved from the transition `CA-PQ` signed, never from a command line:
    // a campaign whose target an operator typed would describe a decision the
    // domain never took.
    let campaign = AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: Id16::new(aether::random::public_bytes::<16>()?)
            .map_err(|error| anyhow::anyhow!("identifiant de campagne : {error}"))?,
        trust_domain_id: identity.trust_domain_id,
        gateway_wg_public_key: identity.gateway_wg_public_key,
        server_name: identity.server_name.clone(),
        created_at: now,
        expires_at,
        scope: CampaignScope::GatewayIdentity,
        targets: vec![CampaignTarget {
            certificate_kind: CertificateKind::GatewayTls,
            identity_key: identity.gateway_wg_public_key,
            epoch: transition.gateway_identity_epoch,
            generation: transition.gateway_identity_epoch,
            active_tls_certificate_fingerprint: transition
                .active_gateway_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: transition.active_gateway_certificate_fingerprint,
        }],
        reason: reason.to_string(),
        requested_by: requested_by.to_string(),
        policy_fingerprint: identity.policy()?.fingerprint()?,
        required_credentials: CampaignScope::GatewayIdentity.required_credentials(),
    };

    println!("rollback de service : la gateway resert l'ancienne feuille.");
    println!("gateway          : {}", identity.server_name);
    println!("époque en cours  : {}", transition.gateway_identity_epoch);
    println!("transition       : {}", transition.fingerprint()?);
    println!(
        "feuille resservie: {}",
        transition.active_gateway_tls_certificate_fingerprint
    );
    println!("expire à         : {}", horodatage(expires_at));
    println!(
        "fin du recouvr.  : {}",
        horodatage(transition.window.not_after)
    );
    println!("motif            : {reason}");
    println!("demandé par      : {requested_by}");
    println!("empreinte        : {}", campaign.fingerprint());
    println!(
        "effet            : aucun compteur ne bouge, le slot suivant reste scellé et sa          promotion a lieu à not_after comme prévu"
    );

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    // The assertion attests the text above, not merely the vault: §7.6 binds a
    // rollback to a YubiKey campaign, and an unenrolled key is refused here
    // against the credential document `CA-PQ` signed.
    let approval = authority::approve_campaign(
        &[key.as_ref()],
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &[pin.as_str()],
        now,
    )?;
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let authorization = authority::sign_service_rollback(
        &vault,
        &opening,
        &identity,
        &ca_pq_public_key,
        &authority::ServiceRollbackDecision {
            transition: &transition,
            campaign_fingerprint: approval.campaign_fingerprint,
            expires_at,
        },
        now,
    )?;

    let encoded =
        serde_json::to_vec_pretty(&authorization).context("encodage de l'autorisation")?;
    std::fs::write(out, &encoded).with_context(|| format!("écriture de {}", out.display()))?;
    println!("autorisation écrite : {}", out.display());
    println!(
        "à reporter sur la gateway : console Certificats, ou POST \
         /api/certificates/gateway-transition/rollback"
    );
    println!(
        "puis redémarrer heliosd : la feuille en service est déscellée au démarrage et tenue \
         pour la vie du processus"
    );
    Ok(())
}

/// Writes the signed decision out, then deposits it.
///
/// The file first. The operator carries it to the gateway, and a deposit that
/// fails after `CA-PQ` has signed must not also lose the object — the
/// alternative is a second ceremony for a decision that already exists.
fn deposit_gateway_decision(
    client: &astra_signer::campaign::Campaign,
    request: &astra_signer::origin::CampaignRequest,
    approval: &aether::certificates::status::CampaignApproval,
    object: aether::certificates::transport::TrustUpdateObject,
    out: &Path,
    what: &str,
) -> Result<()> {
    let encoded = document_nu(&object)?;
    std::fs::write(out, &encoded).with_context(|| format!("écriture de {}", out.display()))?;
    println!("{what} écrit : {}", out.display());

    let result = campaign_result(approval, vec![object], None);
    let state = client.submit(&request.operation_id, &request.result_token, &result)?;
    println!("état             : {state:?}");
    println!();
    println!("à reporter sur la gateway, en deux temps :");
    println!("  1. copier {} sur la gateway", out.display());
    println!(
        "  2. y lancer : heliosd {} <le fichier copié>",
        if what == "transition" {
            "install-gateway-transition"
        } else {
            "abort-gateway-transition"
        }
    );
    Ok(())
}

/// The signed object as `heliosd` reads it: bare, without the routing envelope.
///
/// [`TrustUpdateObject`] is internally tagged, and that tag is how Astra's
/// registry tells one decision from another. The `heliosd install-*` readers
/// take one concrete type and refuse an unknown `kind` field, so a file
/// carrying the envelope is a file the command this companion prints cannot
/// parse. The envelope still travels to the authority; only the operator's
/// copy is unwrapped.
fn document_nu(object: &aether::certificates::transport::TrustUpdateObject) -> Result<Vec<u8>> {
    use aether::certificates::transport::TrustUpdateObject as Objet;

    let encoded = match object {
        Objet::GatewayIdentityTransition(transition) => serde_json::to_vec_pretty(transition),
        Objet::GatewayTransitionAbort(abort) => serde_json::to_vec_pretty(abort),
        Objet::CaTransition(transition) => serde_json::to_vec_pretty(transition),
        Objet::ClientTlsCaTransition(transition) => serde_json::to_vec_pretty(transition),
        // No `heliosd install-*` command reads the remaining variants from a
        // file; they reach the gateway through the distribution channel. The
        // envelope is kept rather than guessed at, so a future reader sees the
        // type it was given instead of an unlabelled body.
        other => serde_json::to_vec_pretty(other),
    };
    encoded.context("encodage de la décision signée")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T> {
    let raw = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("décodage de {what} : {}", path.display()))
}

fn origin_client_fetch(
    client: &astra_signer::origin::Origin,
    operation_id: &Id16,
) -> Result<astra_signer::origin::CampaignRequest> {
    client.fetch(operation_id)
}

/// Rotates `CA-PQ`, alone or as the execution of an authority campaign.
///
/// # Why the deposit happens before the vault moves
///
/// Astra learns of the successor first, and the local vault adopts it second.
/// The other order has a failed deposit leave an operator whose vault holds an
/// anchor the authority has never heard of: the next campaign would resolve
/// its target from the registry's old anchor, the companion would refuse the
/// mismatch, and there would be no gesture left that reconciles the two. A
/// deposit that fails before anything moves is simply a ceremony to redo.
///
/// The local half is still crash-safe on its own: the journal is written after
/// the deposit and replayed until every file has landed, so a resume needs no
/// network and no second touch.
#[allow(clippy::too_many_arguments)]
/// Recovers an identity whose leaf has expired (spec §7.5).
///
/// # Why one command and one connection
///
/// A recovery needs `CA-PQ` twice: once to authorize the staging, and once
/// again to sign the grant — which cannot exist until the gateway has
/// persisted the candidate and signed a receipt. Splitting that into two
/// commands would mean two ceremonies for one decision, and a second
/// ceremony's operator has no way to tell it is finishing the first. So the
/// key stays plugged and the vault stays open across one round trip through
/// the authority, which is what «the length of one operation» means here.
///
/// If anything fails before the grant is deposited, nothing has been installed
/// anywhere: the gateway holds a candidate under a lease it will purge, and the
/// operator reruns the command against a fresh request.
fn recover(
    path: &Path,
    authority_url: &str,
    operation_id: &str,
    origin: Option<&str>,
    validity_days: u64,
    overlap_days: u64,
    transport: Transport,
) -> Result<()> {
    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;
    let ca_tls_certificate = handoff.ca_tls_certificate.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "ce relais de domaine ne porte pas la CA-TLS cliente : l'émettre par `astra-signer \
             issue-ca-tls`, sinon la feuille TLS de la génération récupérée ne chaîne à rien"
        )
    })?;
    let ca_tls_certificate = DerCertificate::new(
        <base64::engine::general_purpose::GeneralPurpose as base64::Engine>::decode(
            &base64::engine::general_purpose::STANDARD,
            ca_tls_certificate.trim(),
        )
        .context("CA-TLS cliente : base64 illisible")?,
    )?;

    let client = astra_signer::origin::Origin::new(authority_url)?;
    let view = client.recovery(&operation)?;
    let request = view
        .request
        .clone()
        .ok_or_else(|| anyhow::anyhow!("l'autorité ne rend pas la demande de cette opération"))?;

    let origin = match origin {
        Some(origin) => origin.to_string(),
        None => format!("https://{}", vault.rp_id),
    };
    let now = now_unix();

    // Everything the operator has to weigh, before a key is asked for
    // anything. A recovery reaches past a validity period: the one fact that
    // must not be buried is *which* identity, and how long it has been dead.
    println!("récupération     : {}", operation.to_hex());
    println!("pair             : {}", request.client_wg_public_key);
    println!("gateway          : {}", request.server_name);
    println!(
        "génération       : {} → {}",
        request.expired_generation, request.requested_generation
    );
    println!(
        "expirée depuis   : {} s",
        now.saturating_sub(request.expired_pq_certificate.not_after_unix)
    );
    println!("empreinte        : {}", request.fingerprint());

    let validity = (
        now,
        now.checked_add(
            validity_days
                .checked_mul(DAY_SECS)
                .context("durée hors bornes")?,
        )
        .context("durée hors bornes")?,
    );
    let stage_expires_at = request.expires_at;
    // The recovered generation has nothing to overlap *with* — the leaf it
    // replaces has expired — so it changes over as early as the protocol
    // allows. That instant is the end of the staging lease, not `now`: §7.2
    // refuses a lease that outlives the activation it prepares, so a window
    // activating at `now` would be refused by the gateway a moment after the
    // operator touched their key. Which is what happened, every time.
    //
    // Making the three instants collapse onto `now` was refused earlier still,
    // since a window demands `not_before < activation_at < not_after`
    // strictly. Both refusals say the same thing: staging comes first, and the
    // change-over follows it.
    //
    // The bound is short — a recovery lives five minutes — so the wait is
    // measured in minutes and cannot drift.
    //
    // `not_before` is backdated by the clock-skew allowance leaves are issued
    // with, and doubly deserved here: a machine left off long enough for its
    // identity to expire is a machine whose clock has had time to wander.
    let window = TransitionWindow::new(
        now.saturating_sub(RECOVERY_WINDOW_BACKDATE_SECS),
        stage_expires_at,
        stage_expires_at
            .checked_add(
                overlap_days
                    .checked_mul(DAY_SECS)
                    .context("durée hors bornes")?,
            )
            .context("durée hors bornes")?,
    )?;

    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    let produced = authority::recover_expired_identity(
        &vault,
        key.as_ref(),
        &pin,
        &identity,
        &registry,
        &ca_tls_certificate,
        &request,
        &request.client_wg_public_key.to_base64(),
        window,
        validity,
        Id16::new(random_id()?)?,
        random_id()?,
        &origin,
        stage_expires_at,
        now,
    )?;
    let authorization = produced.authorization;

    let staged = client.deposit_recovery_authorization(
        &operation,
        &aether::certificates::transport::ExpiredRecoveryAuthorizationDeposit {
            authorization: Box::new(authorization.clone()),
            evidence: Box::new(produced.evidence),
        },
    )?;
    println!("stade            : {:?}", staged.state);

    let receipt = staged
        .receipt
        .ok_or_else(|| anyhow::anyhow!("l'autorité n'a pas rendu le reçu de la gateway"))?;
    let gateway_leaf = staged.gateway_pq_certificate.ok_or_else(|| {
        anyhow::anyhow!("l'autorité n'a pas rendu la feuille que la gateway sert")
    })?;
    // The leaf is compared to the gateway this vault's own hand-off names,
    // before anything is verified under it. Astra reads that leaf on the veth;
    // this end must not adopt an identity because the relay reported it.
    if gateway_leaf.wireguard_public_key != identity.gateway_wg_public_key.to_base64() {
        bail!(
            "la feuille que l'autorité annonce appartient à une autre gateway que celle que ce \
             coffre épingle. Rien n'est signé."
        );
    }
    let gateway_pq_public_key = MlDsa87PublicKey::parse(&gateway_leaf.ml_dsa_87_public_key)?;
    let gateway_fingerprint =
        aether::certificates::gateway::pq_certificate_fingerprint(&gateway_leaf)?;

    // The vault opens a second time for the grant. Same key, same session:
    // the operator is not asked to decide anything again, only to let the
    // second signature happen.
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let grant = authority::grant_recovered_identity(
        &vault,
        &opening,
        &authorization,
        &receipt,
        &gateway_pq_public_key,
        &gateway_fingerprint,
    )?;
    let granted = client.deposit_recovery_grant(
        &operation,
        &aether::certificates::transport::ExpiredRecoveryGrantDeposit {
            grant: Box::new(grant),
        },
    )?;
    println!("stade            : {:?}", granted.state);
    println!(
        "le client peut installer sa nouvelle génération et committer ; la gateway relaiera son \
         commit par le canal privé"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn rotate_ca_pq(
    path: &Path,
    out: &Path,
    prepare_days: u64,
    overlap_days: u64,
    authority_url: Option<&str>,
    operation_id: Option<&str>,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    let output_path = absolute_path(out)?;
    let journal_path = ca_pq_rotation_journal_path(path);
    if journal_path.exists() {
        let journal: CaPqRotationJournal =
            documents::read(&journal_path).context("reprise de la rotation CA-PQ préparée")?;
        if journal.output_path != output_path {
            bail!(
                "une rotation CA-PQ interrompue doit être reprise avec --out {}",
                journal.output_path.display()
            );
        }
        validate_ca_pq_rotation_journal(&journal)?;
        apply_ca_pq_rotation(path, &journal)?;
        std::fs::remove_file(&journal_path)
            .with_context(|| format!("suppression de {}", journal_path.display()))?;
        print_ca_pq_rotation(&journal);
        println!("reprise           : rotation préparée terminée sans nouvelle cérémonie");
        return Ok(());
    }

    let mut vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let current_ca_public_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;
    let now = now_unix();
    let activation_at = now
        .checked_add(
            prepare_days
                .checked_mul(DAY_SECS)
                .context("délai hors bornes")?,
        )
        .context("délai hors bornes")?;
    let window = TransitionWindow::new(
        now,
        activation_at,
        activation_at
            .checked_add(
                overlap_days
                    .checked_mul(DAY_SECS)
                    .context("délai hors bornes")?,
            )
            .context("délai hors bornes")?,
    )?;

    let online = match (authority_url, operation_id) {
        (Some(url), Some(id)) => {
            let operation =
                Id16::parse_hex(id).map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
            let client = astra_signer::origin::Origin::new(url)?;
            let request = origin_client_fetch(&client, &operation)?;
            handoff::verify_campaign_request(&handoff, &vault, &request, url, now_unix())?;
            let campaign = request.campaign.as_ref().clone();
            if !campaign.scope.rotates_authority() {
                bail!(
                    "cette campagne ne fait tourner aucune ancre : elle s'approuve par \
                     `astra-signer approve-campaign`. Rien n'a été signé."
                );
            }
            // The campaign was resolved from Astra's registry. If it names
            // another anchor than the one this vault holds, the two halves of
            // the domain disagree about what is current — and a rotation is
            // the last thing that should reconcile them.
            campaign
                .covers_authority_object(&anchor_probe(&identity, &current_ca_public_key, window)?)
                .context(
                    "la campagne ne nomme pas l'ancre que ce coffre détient : l'autorité et le \
                     compagnon ne décrivent pas le même domaine",
                )?;
            Some((client, request, campaign))
        }
        (None, None) => None,
        _ => bail!("--authority-url et --operation-id vont ensemble"),
    };

    println!(
        "rotation de CA-PQ : l'ancre du domaine change. Tout objet signé sous l'ancienne cesse \
         de vérifier au bout du recouvrement."
    );
    println!("préparation      : {prepare_days} jour(s)");
    println!("recouvrement     : {overlap_days} jour(s)");
    if let Some((_, _, campaign)) = &online {
        println!("campagne         : {}", campaign.campaign_id.to_hex());
        println!("empreinte        : {}", campaign.fingerprint());
        println!("motif            : {}", campaign.reason);
        println!("demandée par     : {}", campaign.requested_by);
    } else {
        println!(
            "hors campagne    : la transition sera écrite dans un fichier, et aucune autorité ne \
             la distribuera"
        );
    }

    let registry_path = credentials::path_beside(path);
    let previous = credentials::load(&registry_path)?;
    let approval_origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    let mut approval_session = match &online {
        Some((_, _, campaign)) => {
            let registry = previous.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "aucun document de credentials : l'émettre par `astra-signer bindings` avant \
                     d'exécuter une campagne d'autorité"
                )
            })?;
            Some(authority::CampaignApprovalSession::new(
                campaign,
                registry,
                &identity,
                &current_ca_public_key,
                &vault.rp_id,
                &approval_origin,
                now,
            )?)
        }
        None => None,
    };

    // Two distinct keys, plugged one after the other. Both are proven to open
    // the vault before anything is generated: an operator whose second key
    // does not work should find out now, and not after the anchor has moved.
    //
    // Each key stays connected for both of its jobs — the campaign assertion
    // and the key-slot opening. Asking for four plug cycles where two suffice
    // is how a ceremony gets abandoned halfway.
    let first = connect_authorized_key(
        &vault,
        transport,
        "Brancher la PREMIÈRE clé autorisée, puis appuyer sur Entrée.",
    )?;
    if let Some(session) = approval_session.as_mut() {
        let offered = session.offered_credentials();
        let assertion = first.key.approve(
            session.webauthn_rp_id(),
            &offered,
            session.client_data_json(),
            &first.pin,
        )?;
        session.accept_for(assertion, Some(&first.opened.credential_id), now_unix())?;
    }
    eprintln!();
    let second = connect_authorized_key(
        &vault,
        transport,
        "Débrancher celle-ci, brancher la SECONDE clé autorisée, puis Entrée.",
    )?;
    if let Some(session) = approval_session.as_mut() {
        let offered = session.offered_credentials();
        let assertion = second.key.approve(
            session.webauthn_rp_id(),
            &offered,
            session.client_data_json(),
            &second.pin,
        )?;
        session.accept_for(assertion, Some(&second.opened.credential_id), now_unix())?;
    }

    // The approval is taken **before** the anchor moves, under the credential
    // document the outgoing anchor signed — which is also the one Astra holds.
    let approval = approval_session
        .map(|session| session.finish(now_unix()))
        .transpose()?;

    let rotated = authority::rotate_ca_pq(
        &mut vault,
        &[&first.opened, &second.opened],
        &identity,
        previous.as_ref(),
        window,
        now,
    )?;
    let mut next_handoff = handoff;
    next_handoff.adopt(&vault)?;
    next_handoff.ca_epoch = Some(identity.ca_epoch + 1);
    let journal = CaPqRotationJournal {
        format_version: CA_PQ_ROTATION_JOURNAL_VERSION,
        output_path,
        current_ca_public_key,
        vault,
        bindings: rotated.bindings,
        transition: rotated.transition,
        handoff: next_handoff,
    };
    validate_ca_pq_rotation_journal(&journal)?;

    if let (Some((client, request, _)), Some(approval)) = (&online, &approval) {
        let result = campaign_result(
            approval,
            vec![
                aether::certificates::transport::TrustUpdateObject::CaTransition(Box::new(
                    journal.transition.clone(),
                )),
            ],
            Some(Box::new(journal.bindings.clone())),
        );
        let state = client.submit(&request.operation_id, &request.result_token, &result)?;
        println!("opération        : {}", request.operation_id.to_hex());
        println!("état             : {state:?}");
    }

    documents::write(&journal_path, &journal)
        .context("préparation durable de la rotation CA-PQ")?;
    apply_ca_pq_rotation(path, &journal)?;
    std::fs::remove_file(&journal_path)
        .with_context(|| format!("suppression de {}", journal_path.display()))?;

    print_ca_pq_rotation(&journal);
    println!("les key-slots n'ont pas bougé : chaque clé qui ouvrait le coffre l'ouvre encore");
    if online.is_some() {
        println!(
            "l'autorité distribue la transition aux pairs qui reviennent avant l'activation ; \
             au-delà, un pair en retard se répare par l'opérateur"
        );
    }
    Ok(())
}

/// The object a campaign target is compared against, before anything signs.
///
/// A placeholder transition carrying the outgoing epoch and fingerprint: what
/// [`AstraRotationCampaign::covers_authority_object`] reads is exactly those
/// two values, so comparing here costs no signature and answers the only
/// question that matters before a key is touched — does the authority name the
/// anchor this vault holds.
fn anchor_probe(
    identity: &authority::DomainIdentity,
    current: &MlDsa87PublicKey,
    window: TransitionWindow,
) -> Result<aether::certificates::transport::TrustUpdateObject> {
    use aether::certificates::authority::CaTransition;

    Ok(
        aether::certificates::transport::TrustUpdateObject::CaTransition(Box::new(CaTransition {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: identity.trust_domain_id,
            current_ca_epoch: identity.ca_epoch,
            next_ca_epoch: identity.ca_epoch + 1,
            current_ca_fingerprint: current.authority_fingerprint(),
            next_ca_public_key: current.clone(),
            next_ca_fingerprint: current.authority_fingerprint(),
            window,
            current_ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            next_ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        })),
    )
}

/// One security key, connected once and used for everything it owes.
struct ConnectedKey {
    key: Box<dyn astra_signer::authenticator::Authenticator>,
    /// Zeroized on drop, like every other PIN this program holds.
    pin: zeroize::Zeroizing<String>,
    opened: Opened,
}

fn connect_authorized_key(
    vault: &AuthorityVault,
    transport: Transport,
    prompt: &str,
) -> Result<ConnectedKey> {
    eprintln!("{prompt}");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
    let opened = gestures::open_with_authorized_key(key.as_ref(), vault, &pin)?;
    let slot = vault.slot_for_credential(&opened.credential_id)?;
    eprintln!("Clé reconnue : « {} » ({}).", slot.label, slot.role);
    Ok(ConnectedKey { key, pin, opened })
}

/// A Unix timestamp, as a date an operator can act on.
///
/// The raw seconds stay out of the operator-facing lines: a rotation window is
/// something someone has to diary, and «1791792171» is not a date anyone
/// compares to a calendar. The signed value remains a Unix instant; only this
/// operator-facing representation uses Europe/Paris civil time.
fn horodatage(seconds: u64) -> String {
    aether::display_time::format_paris_timestamp(seconds)
}

fn ca_pq_rotation_journal_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CA_PQ_ROTATION_JOURNAL)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("lecture du répertoire courant")?
            .join(path))
    }
}

fn validate_ca_pq_rotation_journal(journal: &CaPqRotationJournal) -> Result<()> {
    if journal.format_version != CA_PQ_ROTATION_JOURNAL_VERSION {
        bail!("version de journal de rotation CA-PQ non supportée");
    }
    let domain = TrustDomainId::parse_hex(&journal.handoff.trust_domain_id)?;
    let gateway = WireGuardKey::parse(journal.handoff.require(
        journal.handoff.gateway_wg_public_key.as_ref(),
        "la clé publique de la gateway",
        "--gateway-wg-public-key",
    )?)?;
    journal.transition.verify(
        &journal.current_ca_public_key,
        &domain,
        journal.transition.current_ca_epoch,
    )?;
    let next_ca = MlDsa87PublicKey::parse(journal.vault.ca_pq_public_key.trim())?;
    if next_ca != journal.transition.next_ca_public_key
        || journal.handoff.ca_epoch != Some(journal.transition.next_ca_epoch)
        || journal.handoff.ca_pq_public_key != journal.vault.ca_pq_public_key
        || journal.handoff.vault_fingerprint != journal.vault.fingerprint()?.to_hex()
    {
        bail!("le journal CA-PQ ne décrit pas un coffre, une transition et un relais uniques");
    }
    journal.bindings.verify(
        &next_ca,
        &domain,
        &gateway,
        journal.transition.next_ca_epoch,
        journal.bindings.credential_registry_epoch,
    )?;
    Ok(())
}

fn apply_ca_pq_rotation(vault_path: &Path, journal: &CaPqRotationJournal) -> Result<()> {
    // Every write is itself atomic. The journal remains until all four have
    // landed, so any prefix of this sequence is safely replayed.
    store::save(vault_path, &journal.vault)?;
    credentials::save(&credentials::path_beside(vault_path), &journal.bindings)?;
    documents::write(&journal.output_path, &journal.transition)?;
    handoff::save(&handoff::path_beside(vault_path), &journal.handoff)?;
    Ok(())
}

fn print_ca_pq_rotation(journal: &CaPqRotationJournal) {
    println!("transition       : {}", journal.output_path.display());
    println!("époque CA-PQ     : {}", journal.transition.next_ca_epoch);
    println!(
        "CA-PQ (publique) : {}",
        journal.transition.next_ca_public_key.to_base64()
    );
    println!(
        "CA-PQ empreinte  : {}",
        journal
            .transition
            .next_ca_public_key
            .authority_fingerprint()
    );
    println!(
        "credentials      : époque {}",
        journal.bindings.credential_registry_epoch
    );
}

/// The PEM form of a certificate, for the tools that read one.
fn pem_of(certificate: &DerCertificate) -> String {
    let body = certificate.to_base64();
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// The first characters of a base64 key — enough to tell two apart on a
/// terminal, never enough to be mistaken for the whole.
fn short_key(value: &str) -> String {
    value.chars().take(24).collect::<String>() + "…"
}

fn rename(path: &Path, slot: &str, label: &str) -> Result<()> {
    let mut vault = store::load(path)?;
    let slot_id = parse_slot_id(slot)?;
    vault.rename_slot(&slot_id, label)?;
    store::save(path, &vault)?;
    println!("key-slot         : {}", hex::encode(slot_id));
    println!("libellé          : {label}");
    Ok(())
}

/// Says, after every command that could change it, whether the authority may
/// be used at all — and what is missing when it may not.
fn report_bootstrap_state(vault: &AuthorityVault) {
    if vault.is_bootstrapped() {
        println!("autorité         : {} clés enregistrées", vault.slots.len());
        return;
    }
    println!(
        "autorité         : NON amorcée — {} clé(s) sur les {REQUIRED_SLOTS} exigées",
        vault.slots.len()
    );
    println!(
        "tant que la seconde clé n'est pas enrôlée (`astra-signer enrol`), perdre celle-ci perd \
         le domaine de confiance : aucune phrase de passe ne la remplace"
    );
}

fn wait_for_operator() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "cette commande demande de brancher une clé de sécurité : elle ne s'exécute pas sans \
             terminal"
        );
    }
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("lecture de la confirmation")?;
    Ok(())
}

/// Asks for the PIN only when the transport needs it.
///
/// On the platform transport the operating system collects it in its own
/// dialog. Prompting here would ask an operator for a secret this process has
/// no use for — and would then have to hold it.
fn pin_for(
    key: &dyn astra_signer::authenticator::Authenticator,
    prompt: &str,
) -> Result<Zeroizing<String>> {
    if !key.needs_pin() {
        eprintln!("Le système va demander le PIN et le contact de la clé.");
        return Ok(Zeroizing::new(String::new()));
    }
    ask_pin(prompt)
}

/// Reads the PIN without echoing it.
///
/// The prompt is printed by us rather than by `rpassword::prompt_password`:
/// that one writes straight to the terminal device, bypassing the stream every
/// other message goes through — and on a Windows console in a non-UTF-8 code
/// page it comes out as mojibake, on the one line an operator has to read
/// carefully.
fn ask_pin(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let pin = rpassword::read_password().context("lecture du PIN")?;
    if pin.is_empty() {
        bail!("PIN vide : la vérification utilisateur est exigée");
    }
    Ok(Zeroizing::new(pin))
}

fn parse_slot_id(value: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(value.trim())
        .with_context(|| format!("« {value} » n'est pas un identifiant de key-slot"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("un identifiant de key-slot fait 32 caractères hexadécimaux"))
}

fn random_id() -> Result<[u8; 16]> {
    let mut out = [0u8; 16];
    aether::random::fill_secret(&mut out)
        .map_err(|error| anyhow::anyhow!("générateur approuvé indisponible: {error}"))?;
    Ok(out)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::authority::ClientTlsCaTransition;
    use aether::certificates::encoding::{
        DerCertificate, Fingerprint, MlDsa87Signature, TrustDomainId,
    };
    use aether::certificates::transport::TrustUpdateObject;
    use aether::certificates::window::TransitionWindow;
    use aether::certificates::CERTIFICATE_FORMAT_VERSION;

    /// A recovery window has to clear two rules that pull against each other:
    /// `not_before < activation_at < not_after`, strictly, and a staging lease
    /// that never outlives the activation it prepares. Collapsing the three
    /// instants onto `now` broke the first; activating at `now` broke the
    /// second — and that one only surfaced at the gateway, a moment after the
    /// operator had already touched their key.
    #[test]
    fn a_recovery_window_clears_both_rules_it_has_to() {
        let now = 1_800_000_000u64;
        let stage_expires_at = now + 300;
        let window = TransitionWindow::new(
            now - RECOVERY_WINDOW_BACKDATE_SECS,
            stage_expires_at,
            stage_expires_at + 7 * DAY_SECS,
        )
        .expect("a recovery window is a valid window");
        aether::certificates::window::validate_lease(
            now,
            stage_expires_at,
            aether::certificates::window::MAX_STAGE_LEASE_SECS,
            &[window.activation_at, stage_expires_at],
        )
        .expect("the staging lease does not outlive the activation it prepares");
        assert_eq!(
            window.phase(now),
            aether::certificates::window::WindowPhase::Prepared,
            "the change-over waits for the staging, and for nothing else"
        );
    }

    fn transition() -> ClientTlsCaTransition {
        ClientTlsCaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            current_ca_tls_epoch: 1,
            next_ca_tls_epoch: 2,
            active_client_tls_ca_fingerprint: Fingerprint::of(b"ancre sortante"),
            next_client_tls_ca_certificate: DerCertificate::new(vec![0x30, 0x03, 0x02, 0x01, 0x00])
                .expect("certificate"),
            window: TransitionWindow {
                not_before: 10,
                activation_at: 20,
                not_after: 30,
            },
            ca_pq_signature: MlDsa87Signature::new(vec![7; 4627]).expect("signature"),
        }
    }

    /// The operator's copy is what `heliosd install-*` reads, so it carries no
    /// routing envelope.
    ///
    /// The tag `TrustUpdateObject` adds is how Astra's registry tells one
    /// decision from another; the gateway readers take one concrete type and
    /// refuse an unknown `kind`. Writing the envelope produced a file the very
    /// command this companion printed could not parse — which is the failure
    /// this test exists to keep from coming back.
    #[test]
    fn the_file_written_for_the_gateway_carries_no_routing_envelope() {
        let object = TrustUpdateObject::ClientTlsCaTransition(Box::new(transition()));
        let encoded = document_nu(&object).expect("encoding");

        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("readable JSON");
        assert!(
            value.get("kind").is_none(),
            "the gateway reader refuses an unknown `kind` field"
        );
        let parsed: ClientTlsCaTransition =
            serde_json::from_slice(&encoded).expect("the gateway must be able to read this file");
        assert_eq!(parsed.next_ca_tls_epoch, 2);
    }

    /// A rotation window is a date an operator diaries, not a raw counter.
    #[test]
    fn a_window_bound_is_printed_as_a_date() {
        assert_eq!(horodatage(1_791_792_171), "2026-10-12 10:02 CEST");
        // Out of range is named rather than silently rendered as an epoch.
        assert!(horodatage(u64::MAX).contains("hors plage"));
    }
}

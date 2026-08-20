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
//! # Limite connue : deux commandes voyagent encore par fichiers
//!
//! `authorize-issuer` et `rotate-ca-pq` lisent une demande sur disque et
//! écrivent leur résultat à côté. Elles ne portent pas de campagne, donc rien
//! ne les rattache à une opération : les routes du §8.2 sont liées à un
//! `operation_id` et à un manifeste, et il n'existe pas encore d'opération qui
//! les décrive.
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
use astra_signer::authority::{self, DelegationBounds, DomainIdentity, IssuerDelegationRequest};
use astra_signer::credentials;
use astra_signer::gestures::{self, NewAuthority, NewKey};
use astra_signer::{authenticator, documents, handoff, store, tunnel};
use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

/// A day, in seconds. Every window below is expressed in days on the command
/// line, because that is the unit an operator reasons about.
const DAY_SECS: u64 = 86_400;

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
    AuthorizeIssuer {
        /// Demande de délégation produite par Astra, en JSON.
        #[arg(long)]
        request: PathBuf,
        /// Où écrire l'autorisation signée, en JSON.
        #[arg(long)]
        out: PathBuf,
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
        } => domain(
            &path,
            gateway_wg_public_key.as_deref(),
            server_name.as_deref(),
            astra_service_public_key.as_deref(),
            astra_service_key_epoch,
        ),
        Command::Remove { slot } => remove(&path, &slot, transport),
        Command::Rename { slot, label } => rename(&path, &slot, &label),
        Command::IssueCaTls { days, out } => issue_ca_tls(&path, days, out.as_deref(), transport),
        Command::AuthorizeIssuer {
            request,
            out,
            days,
            leaf_days,
        } => authorize_issuer(&path, &request, &out, days, leaf_days, transport),
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
        Command::RotateCaPq {
            out,
            prepare_days,
            overlap_days,
        } => rotate_ca_pq(&path, &out, prepare_days, overlap_days, transport),
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
fn identity_of(handoff: &handoff::DomainHandoff) -> Result<DomainIdentity> {
    let gateway = handoff.require(
        handoff.gateway_wg_public_key.as_ref(),
        "la clé publique de la gateway",
        "--gateway-wg-public-key",
    )?;
    let server_name = handoff.require(
        handoff.server_name.as_ref(),
        "le nom de service de la gateway",
        "--server-name",
    )?;
    Ok(DomainIdentity {
        trust_domain_id: TrustDomainId::parse_hex(&handoff.trust_domain_id)?,
        gateway_wg_public_key: WireGuardKey::parse(gateway)?,
        server_name: server_name.clone(),
        ca_epoch: handoff.ca_epoch.unwrap_or(1),
        ca_tls_epoch: handoff.ca_tls_epoch.unwrap_or(1),
    })
}

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
    let identity = match identity_of(&handoff) {
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
    let identity = identity_of(&handoff)?;
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
    println!("valide de        : {not_before}");
    println!("valide jusqu'à   : {not_after}");
    println!(
        "cette CA est épinglée par la gateway : la remplacer coupe tous les clients déjà \
         admis, et c'est la rotation du §9.4 qui la remplace"
    );
    Ok(())
}

fn authorize_issuer(
    path: &Path,
    request_path: &Path,
    out: &Path,
    days: u64,
    leaf_days: u64,
    transport: Transport,
) -> Result<()> {
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = identity_of(&handoff)?;
    let ca_tls = DerCertificate::parse(handoff.require(
        handoff.ca_tls_certificate.as_ref(),
        "le certificat CA-TLS",
        "issue-ca-tls",
    )?)?;
    let request: IssuerDelegationRequest = documents::read(request_path)?;

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
    documents::write(out, &authorization)?;

    println!("autorisation     : {}", out.display());
    println!(
        "cette délégation n'autorise qu'un renouvellement de leaf cliente admise, et rien \
         d'autre : ni gateway, ni CA, ni pair inconnu"
    );
    Ok(())
}

fn bindings(path: &Path, lost: &[String], active: &[String], transport: Transport) -> Result<()> {
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = identity_of(&handoff)?;

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
    let identity = identity_of(&handoff)?;
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
    println!("expire à         : {}", request.expires_at);

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
    println!("valable jusqu'à  : {}", approval.expires_at);
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
    let identity = identity_of(&handoff)?;
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
            // Signed by Astra's service key, verified under the key this
            // companion already pins. A request that carried the key it is
            // checked against would authenticate nothing.
            //
            // The URL is checked **inside** the signature rather than against
            // a local copy: Astra signs the origin it serves itself, so an
            // operator pointed at another host gets a request whose
            // `authority_url` does not match what they dialled — and no
            // signature under the pinned service key can be produced for one
            // that does. That is why the hand-off records the key and not the
            // address.
            let service_key = handoff.astra_service_public_key.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "ce relais de domaine ne porte pas la clé de service Astra : la réémettre par \
                     `astra-signer domain`, sinon rien ne vérifie ce que l'origine renvoie"
                )
            })?;
            let service_key_epoch = handoff.astra_service_key_epoch.ok_or_else(|| {
                anyhow::anyhow!("ce relais de domaine ne porte pas l'époque de la clé de service")
            })?;
            request.signer_request.verify(
                &MlDsa87PublicKey::parse(service_key)?,
                service_key_epoch,
                authority_url.unwrap_or_default(),
                now_unix(),
            )?;
            if request.webauthn_rp_id != vault.rp_id {
                bail!(
                    "l'autorité annonce le RP ID « {} » alors que ce coffre épingle « {} ». Rien \
                     n'est signé : une assertion produite sous un autre RP ID vaudrait pour un \
                     autre domaine.",
                    request.webauthn_rp_id,
                    vault.rp_id
                );
            }
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
            let state = client.submit(&request.operation_id, &request.result_token, &approval)?;
            println!("opération        : {}", request.operation_id.to_hex());
            println!("état             : {state:?}");
            println!(
                "limite connue    : l'autorité a enregistré l'approbation, et rien ne l'applique \
                 encore. Aucun certificat n'a été émis, aucune transition déposée."
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
fn origin_client_fetch(
    client: &astra_signer::origin::Origin,
    operation_id: &Id16,
) -> Result<astra_signer::origin::CampaignRequest> {
    client.fetch(operation_id)
}

fn rotate_ca_pq(
    path: &Path,
    out: &Path,
    prepare_days: u64,
    overlap_days: u64,
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
    let identity = identity_of(&handoff)?;
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

    println!(
        "rotation de CA-PQ : l'ancre du domaine change. Tout objet signé sous l'ancienne cesse \
         de vérifier au bout du recouvrement."
    );
    println!("préparation      : {prepare_days} jour(s)");
    println!("recouvrement     : {overlap_days} jour(s)");

    // Two distinct keys, plugged one after the other. Both are proven to open
    // the vault before anything is generated: an operator whose second key
    // does not work should find out now, and not after the anchor has moved.
    let first = open_vault(
        &vault,
        transport,
        "Brancher la PREMIÈRE clé autorisée, puis appuyer sur Entrée.",
    )?;
    eprintln!();
    let second = open_vault(
        &vault,
        transport,
        "Débrancher celle-ci, brancher la SECONDE clé autorisée, puis Entrée.",
    )?;

    let registry_path = credentials::path_beside(path);
    let previous = credentials::load(&registry_path)?;
    let rotated = authority::rotate_ca_pq(
        &mut vault,
        &[&first, &second],
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
    documents::write(&journal_path, &journal)
        .context("préparation durable de la rotation CA-PQ")?;
    apply_ca_pq_rotation(path, &journal)?;
    std::fs::remove_file(&journal_path)
        .with_context(|| format!("suppression de {}", journal_path.display()))?;

    print_ca_pq_rotation(&journal);
    println!("les key-slots n'ont pas bougé : chaque clé qui ouvrait le coffre l'ouvre encore");
    Ok(())
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

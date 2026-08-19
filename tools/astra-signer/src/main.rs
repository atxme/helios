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
//! - `approve` approves one exact client renewal. **It does not open the
//!   vault**, and cannot: see [`astra_signer::authority::approve_renewal`].
//! - `approve-campaign` approves a manual rotation campaign, at as many
//!   distinct keys as its scope demands.
//! - `rotate-ca-pq` moves the anchor, under two distinct keys.
//!
//! This file is the prompts and the printing. The sequences themselves are in
//! [`astra_signer::gestures`], where they are exercised.
//!
//! # Limite connue : les documents voyagent par fichiers
//!
//! Chaque commande de signature lit une demande sur disque et écrit son
//! résultat à côté. Récupérer l'`AstraSignerRequest` et déposer le résultat par
//! les routes à jeton de capacité du §8.2 n'est pas câblé, parce qu'Astra les
//! sert en `501` : il n'y a rien à appeler. Ce qui débloque : les routes
//! `signer-requests`, `vaults` et `signer-results` côté Astra.
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
    validate_server_name, DerCertificate, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
};
use aether::certificates::window::TransitionWindow;
use anyhow::{bail, Context, Result};
use astra::vault::{AuthorityVault, KeySlot, SlotRole, MAX_SLOTS, REQUIRED_SLOTS};
use astra_signer::authenticator::{Opened, Transport};
use astra_signer::authority::{self, DelegationBounds, DomainIdentity, IssuerDelegationRequest};
use astra_signer::credentials;
use astra_signer::gestures::{self, NewAuthority, NewKey};
use astra_signer::{authenticator, documents, handoff, store};
use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

/// A day, in seconds. Every window below is expressed in days on the command
/// line, because that is the unit an operator reasons about.
const DAY_SECS: u64 = 86_400;

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
        #[arg(long)]
        request: PathBuf,
        /// Où écrire l'approbation, en JSON. Astra y ajoute sa signature.
        #[arg(long)]
        out: PathBuf,
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
        #[arg(long)]
        campaign: PathBuf,
        /// Où écrire l'approbation, en JSON.
        #[arg(long)]
        out: PathBuf,
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
            active_generation,
        } => approve(&path, &request, &out, active_generation, transport),
        Command::ApproveCampaign {
            campaign,
            out,
            origin,
        } => approve_campaign(&path, &campaign, &out, origin.as_deref(), transport),
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

fn approve(
    path: &Path,
    request_path: &Path,
    out: &Path,
    active_generation: Option<u64>,
    transport: Transport,
) -> Result<()> {
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
    let request: aether::certificates::approval::AstraCredentialApprovalRequest =
        documents::read(request_path)?;

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
    let approval = authority::approve_renewal(
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
    documents::write(out, &approval)?;

    println!("approbation      : {}", out.display());
    println!("empreinte        : {}", approval.fingerprint().to_hex());
    println!("valable jusqu'à  : {}", approval.expires_at);
    println!(
        "le coffre n'a pas été ouvert : une approbation ordinaire n'obtient aucune sortie PRF \
         et Astra y ajoute sa propre signature"
    );
    Ok(())
}

fn approve_campaign(
    path: &Path,
    campaign_path: &Path,
    out: &Path,
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
    let campaign: aether::certificates::status::AstraRotationCampaign =
        documents::read(campaign_path)?;
    let origin = match origin {
        Some(origin) => origin.to_string(),
        None => format!("https://{}", vault.rp_id),
    };

    let required = usize::from(campaign.required_credentials);
    println!("campagne         : {}", campaign.campaign_id.to_hex());
    println!("portée           : {:?}", campaign.scope);
    println!("cibles           : {}", campaign.targets.len());
    println!("motif            : {}", campaign.reason);
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
    documents::write(out, &approval)?;

    println!("approbation      : {}", out.display());
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

fn rotate_ca_pq(
    path: &Path,
    out: &Path,
    prepare_days: u64,
    overlap_days: u64,
    transport: Transport,
) -> Result<()> {
    let mut vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = identity_of(&handoff)?;
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
    // The vault first: it holds the private half, and a transition published
    // for an anchor the vault does not hold is a document nothing can honour.
    store::save(path, &vault)?;
    credentials::save(&registry_path, &rotated.bindings)?;
    documents::write(out, &rotated.transition)?;
    let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;
    handoff.ca_epoch = Some(identity.ca_epoch + 1);
    handoff::save(&handoff::path_beside(path), &handoff)?;

    println!("coffre           : {}", path.display());
    println!("transition       : {}", out.display());
    println!("époque CA-PQ     : {}", identity.ca_epoch + 1);
    println!(
        "CA-PQ (publique) : {}",
        rotated.next_ca_public_key.to_base64()
    );
    println!(
        "CA-PQ empreinte  : {}",
        rotated.next_ca_public_key.authority_fingerprint()
    );
    println!(
        "credentials      : époque {}",
        rotated.bindings.credential_registry_epoch
    );
    println!("les key-slots n'ont pas bougé : chaque clé qui ouvrait le coffre l'ouvre encore");
    Ok(())
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

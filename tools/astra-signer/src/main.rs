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
//!
//! This file is the prompts and the printing. The sequences themselves are in
//! [`astra_signer::gestures`], where they are exercised.
//!
//! # Limite connue : les commandes de signature ne sont pas ici
//!
//! Ce lot livre la gestion des key-slots — créer le coffre, y enrôler des clés,
//! les éprouver, en retirer. Émettre le certificat auto-signé `CA-TLS`, signer
//! une `AstraIssuerAuthorization` ou une campagne reste à faire : ce sont les
//! commandes de signature du §4, et elles supposent le registre Astra en face.
//! Le coffre les attend — il porte déjà les deux clés privées — et rien ici ne
//! prétend le contraire.
//!
//! # Limite connue : le matériel ne s'exerce pas en WSL2
//!
//! Voir [`astra_signer::authenticator`]. CTAP n'est pas une feature de
//! compilation : tout binaire porte la pile, et il n'existe aucun chemin qui
//! ouvre le coffre sans clé.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use aether::certificates::encoding::TrustDomainId;
use anyhow::{bail, Context, Result};
use astra::vault::{AuthorityVault, KeySlot, SlotRole, MAX_SLOTS, REQUIRED_SLOTS};
use astra_signer::authenticator::Transport;
use astra_signer::gestures::{self, NewAuthority, NewKey};
use astra_signer::{authenticator, handoff, store};
use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

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
    #[arg(long, value_enum, default_value_t = TransportArg::default())]
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
    /// deployment that must never see the authority.
    Domain,
    /// Renames a slot. Needs no security key.
    Rename {
        #[arg(long)]
        slot: String,
        #[arg(long)]
        label: String,
    },
}

fn main() -> Result<()> {
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
        Command::Domain => domain(&path),
        Command::Remove { slot } => remove(&path, &slot, transport),
        Command::Rename { slot, label } => rename(&path, &slot, &label),
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

fn domain(path: &Path) -> Result<()> {
    let vault = store::load(path)?;
    let handoff_path = handoff::path_beside(path);
    let handoff = handoff::DomainHandoff::of(&vault)?;
    handoff::save(&handoff_path, &handoff)?;

    println!("relais           : {}", handoff_path.display());
    println!("domaine          : {}", handoff.trust_domain_id);
    println!("RP ID WebAuthn   : {}", handoff.rp_id);
    println!("CA-PQ (publique) : {}", handoff.ca_pq_public_key);
    println!("empreinte coffre : {}", handoff.vault_fingerprint);
    Ok(())
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

fn ask_pin(prompt: &str) -> Result<Zeroizing<String>> {
    let pin = rpassword::prompt_password(prompt).context("lecture du PIN")?;
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
    use aws_lc_rs::rand::SecureRandom as _;
    let mut out = [0u8; 16];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| anyhow::anyhow!("générateur aléatoire indisponible"))?;
    Ok(out)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

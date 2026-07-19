//! Campagnes de bout en bout du provisioning post-quantique.
//!
//! # Un seul outil pour le dry-run et la cible
//!
//! Les scénarios sont écrits **contre l'API**, pas contre une implémentation :
//! le même binaire s'exécute contre un `heliosd --dev` sur WSL2 et contre une
//! gateway réelle. Seule la catégorie [`Category::PlanDeDonnees`] exige la
//! cible, parce qu'elle lit l'état WireGuard du noyau — ce qu'aucune simulation
//! ne peut prouver (voir `docs/testing/TESTING.md`).
//!
//! # La campagne est un client, elle n'en simule pas un
//!
//! Les scénarios réseau passent par [`orion_core::provision`], le code que le
//! client embarque réellement. Réécrire le protocole ici validerait cette
//! réécriture, pas Orion. C'est aussi ce qui fait de la campagne un test **du
//! client** autant que **du daemon** : une régression dans `orion-core` la fait
//! tomber.
//!
//! # Les scénarios ne modifient pas la configuration
//!
//! Aucun scénario ne déclare de pair ni ne touche à `network.toml`. L'admission
//! reste hors bande : c'est un invariant d'architecture, pas une lacune de
//! l'outil. Une campagne dont les clés ne sont pas admises **échoue** plutôt que
//! de s'auto-admettre, ce qui reviendrait à tester une gateway complaisante.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aether::enroll::{ProvisionResponse, PROTOCOL_VERSION};
use aether::pq::{Kem, MlKem768Kem};
use anyhow::{Context, Result};
use base64::Engine as _;
use orion_core::provisioning::{finish, ProvisionError};
use orion_core::ClientProfile;
use reqwest::Client;

use crate::{fail, ok};

/// Familles de scénarios, selon ce qu'elles exigent de l'environnement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Category {
    /// Logique du client seule : aucun daemon requis. Tourne partout.
    Client,
    /// Client ↔ daemon par HTTP. Dry-run ou cible indifféremment.
    Protocole,
    /// Lecture du plan de données WireGuard. **Cible uniquement.**
    PlanDeDonnees,
}

impl Category {
    fn label(self) -> &'static str {
        match self {
            Category::Client => "client",
            Category::Protocole => "protocole",
            Category::PlanDeDonnees => "plan de données",
        }
    }
}

/// Paramètres d'une campagne.
pub struct Options {
    /// Clé privée WireGuard du client (base64). Son pair doit être **admis**
    /// sur la gateway, sinon les scénarios réseau échouent — à raison.
    pub client_key: Option<String>,
    /// Clé publique WireGuard de la gateway (base64), telle que le profil
    /// l'attend. Sert à vérifier que la gateway est bien celle annoncée.
    pub gateway_key: Option<String>,
    /// Interface WireGuard à inspecter (`helios0`). Active la catégorie
    /// [`Category::PlanDeDonnees`].
    pub wg_iface: Option<String>,
    /// Ne joue qu'une catégorie.
    pub only: Option<Category>,
    /// Nombre de passes. Au-delà de 1, c'est une campagne d'endurance : elle
    /// révèle les fuites d'état que joue-une-fois ne montre pas (VIP qui
    /// dérive, PSK qui se fige, table de pairs qui gonfle).
    pub repeat: u32,
}

/// Issue d'un scénario. `Skip` n'est pas un échec : un scénario hors de portée
/// de l'environnement doit le **dire**, pas se taire ni mentir.
enum Outcome {
    Pass(String),
    Skip(String),
    Fail(String),
}

impl Outcome {
    fn pass(detail: impl Into<String>) -> Self {
        Outcome::Pass(detail.into())
    }
    fn skip(reason: impl Into<String>) -> Self {
        Outcome::Skip(reason.into())
    }
    fn fail(reason: impl Into<String>) -> Self {
        Outcome::Fail(reason.into())
    }
    /// Traduit une condition booléenne en issue, avec le message d'échec.
    fn check(condition: bool, detail: impl Into<String>, echec: impl Into<String>) -> Self {
        if condition {
            Outcome::pass(detail)
        } else {
            Outcome::fail(echec)
        }
    }
}

/// Génère une paire de clés WireGuard.
///
/// **La sortie standard ne porte que deux lignes `CLÉ=valeur`**, pour être
/// consommable par `eval` sans parsing fragile ; toute la mise en forme part
/// sur la sortie d'erreur. Mélanger les deux revient à faire dépendre un script
/// de la ponctuation d'un texte d'aide — ce qui casse au premier reformatage.
pub fn generate_keys() {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut raw = [0u8; 32];
    aws_lc_rs::rand::fill(&mut raw).expect("CSPRNG système indisponible");
    let secret = x25519_dalek::StaticSecret::from(raw);
    let public = x25519_dalek::PublicKey::from(&secret);
    let (prive, publique) = (
        engine.encode(secret.to_bytes()),
        engine.encode(public.as_bytes()),
    );

    println!("WG_PRIVATE_KEY={prive}");
    println!("WG_PUBLIC_KEY={publique}");

    eprintln!("\n\x1b[1mPaire de clés WireGuard\x1b[0m");
    eprintln!("───────────────────────");
    eprintln!("  Déclarer le pair sur la gateway (network.toml), puis relancer");
    eprintln!("  la campagne avec --client-key :\n");
    eprintln!("    [[peers]]");
    eprintln!("    name = \"campagne\"");
    eprintln!("    public_key = \"{publique}\"");
    eprintln!("    address = \"100.64.1.2/32\"\n");
}

/// Clé publique WireGuard dérivée d'une clé privée base64.
fn public_from_private(private_b64: &str) -> Result<String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let raw: [u8; 32] = engine
        .decode(private_b64.trim())
        .context("clé privée illisible (base64 attendu)")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("clé privée de longueur invalide (32 octets attendus)"))?;
    let secret = x25519_dalek::StaticSecret::from(raw);
    Ok(engine.encode(x25519_dalek::PublicKey::from(&secret).as_bytes()))
}

/// Profil jetable pour les scénarios purement locaux.
///
/// Ces scénarios éprouvent la logique de validation du client — refus d'une
/// gateway usurpée, d'un ciphertext malformé, d'une version inconnue. Aucun
/// pair réel n'est impliqué, donc exiger des clés admises n'aurait aucun sens :
/// la catégorie doit tourner partout, y compris dans la régression, sans
/// gateway ni configuration préalable.
fn profile_ephemere() -> ClientProfile {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut client = [0u8; 32];
    let mut gateway = [0u8; 32];
    aws_lc_rs::rand::fill(&mut client).expect("CSPRNG système indisponible");
    aws_lc_rs::rand::fill(&mut gateway).expect("CSPRNG système indisponible");
    let gateway_public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(gateway));

    ClientProfile {
        name: "campagne-locale".into(),
        endpoint: "127.0.0.1:51820".into(),
        private_key: engine.encode(client),
        peer_public_key: engine.encode(gateway_public.as_bytes()),
        ..ClientProfile::default()
    }
}

/// Profil client de campagne, bâti depuis les options.
fn profile(opts: &Options, url: &str) -> Result<ClientProfile> {
    let client_key = opts
        .client_key
        .as_deref()
        .context("--client-key requis pour les scénarios réseau")?;
    let gateway_key = opts
        .gateway_key
        .as_deref()
        .context("--gateway-key requis pour vérifier l'identité de la gateway")?;
    Ok(ClientProfile {
        name: "campagne".into(),
        // L'endpoint UDP ne sert pas ici : la campagne parle à l'API dans le
        // tunnel, elle ne monte pas le tunnel elle-même.
        endpoint: "127.0.0.1:51820".into(),
        private_key: client_key.to_string(),
        peer_public_key: gateway_key.to_string(),
        heliosd_url: Some(url.to_string()),
        ..ClientProfile::default()
    })
}

// ─── Scénarios : logique du client, sans daemon ───────────────────────────────

/// Construit une réponse de gateway plausible, signée d'aucune identité
/// particulière — c'est au client de juger.
fn reponse_pour(kem_public: &[u8], gateway_key: &str) -> ProvisionResponse {
    let (ciphertext, _) = MlKem768Kem::encapsulate(kem_public).expect("encapsulation ML-KEM");
    ProvisionResponse {
        protocol_version: PROTOCOL_VERSION,
        kem_ciphertext: ciphertext,
        gateway_nonce: [7u8; 16],
        assigned_address: "100.64.1.2/32".into(),
        gateway_wg_public_key: gateway_key.into(),
        psk_lifetime_secs: 3600,
    }
}

/// Une gateway qui n'est pas celle du profil doit être refusée, même si sa
/// cryptographie est parfaitement valide. Sans ce contrôle, une gateway
/// compromise négocierait un PSK avec le client.
fn scenario_identite_gateway(profil: &ClientProfile) -> Outcome {
    let (sk, pk) = match MlKem768Kem::generate() {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("génération ML-KEM impossible : {e}")),
    };
    let imposteur = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    let reponse = reponse_pour(&pk, imposteur);

    match finish(profil, &sk, &[42u8; 16], &reponse) {
        Err(ProvisionError::GatewayIdentityMismatch { .. }) => {
            Outcome::pass("gateway usurpée refusée")
        }
        Err(e) => Outcome::fail(format!("refusée, mais pour la mauvaise raison : {e}")),
        Ok(_) => Outcome::fail(
            "INVARIANTE VIOLÉE : le client a négocié un PSK avec une gateway \
             dont l'identité ne correspond pas à son profil",
        ),
    }
}

/// Un ciphertext malformé ne doit jamais produire de PSK.
fn scenario_ciphertext_malforme(profil: &ClientProfile) -> Outcome {
    let (sk, pk) = match MlKem768Kem::generate() {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("génération ML-KEM impossible : {e}")),
    };
    let mut reponse = reponse_pour(&pk, &profil.peer_public_key);
    reponse.kem_ciphertext = vec![0u8; 10];

    Outcome::check(
        finish(profil, &sk, &[42u8; 16], &reponse).is_err(),
        "ciphertext tronqué refusé",
        "un ciphertext de 10 octets a produit un PSK",
    )
}

/// Une version de protocole inconnue doit être refusée avant toute crypto.
fn scenario_version_protocole(profil: &ClientProfile) -> Outcome {
    let (sk, pk) = match MlKem768Kem::generate() {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("génération ML-KEM impossible : {e}")),
    };
    let mut reponse = reponse_pour(&pk, &profil.peer_public_key);
    reponse.protocol_version = PROTOCOL_VERSION.wrapping_add(1);

    Outcome::check(
        finish(profil, &sk, &[42u8; 16], &reponse).is_err(),
        "version incompatible refusée",
        "une version de protocole inconnue a été acceptée",
    )
}

// ─── Scénarios : client ↔ daemon ──────────────────────────────────────────────

/// Le tour nominal : un pair admis obtient un PSK exploitable.
async fn scenario_provisioning_nominal(profil: &ClientProfile, url: &str) -> Outcome {
    match orion_core::provision(profil, url).await {
        Err(e) => Outcome::fail(format!("{e}")),
        Ok(outcome) => {
            let engine = base64::engine::general_purpose::STANDARD;
            let taille = engine.decode(&outcome.preshared_key).map(|k| k.len());
            match taille {
                Ok(32) if outcome.lifetime > Duration::ZERO => Outcome::pass(format!(
                    "PSK 32 o, VIP {}, validité {} s",
                    outcome.address,
                    outcome.lifetime.as_secs()
                )),
                Ok(n) => Outcome::fail(format!(
                    "PSK de {n} octets : le slot WireGuard en exige exactement 32"
                )),
                Err(e) => Outcome::fail(format!("PSK non décodable en base64 : {e}")),
            }
        }
    }
}

/// Chaque session doit produire un PSK neuf : c'est ce qui borne la fenêtre
/// d'exploitation d'un PSK compromis, et donc tout l'intérêt du provisioning
/// face à un PSK statique.
async fn scenario_psk_frais(profil: &ClientProfile, url: &str) -> Outcome {
    let a = match orion_core::provision(profil, url).await {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("première session : {e}")),
    };
    let b = match orion_core::provision(profil, url).await {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("seconde session : {e}")),
    };

    Outcome::check(
        a.preshared_key != b.preshared_key,
        "deux sessions, deux PSK distincts",
        "PSK identique d'une session à l'autre : la rotation n'apporte rien \
         et un PSK compromis le reste",
    )
}

/// La VIP dérive de la clé publique, pas de la session : elle doit être stable
/// d'un provisioning à l'autre, sans état sur disque côté gateway.
async fn scenario_vip_stable(profil: &ClientProfile, url: &str) -> Outcome {
    let a = match orion_core::provision(profil, url).await {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("première session : {e}")),
    };
    let b = match orion_core::provision(profil, url).await {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("seconde session : {e}")),
    };

    Outcome::check(
        a.address == b.address,
        format!("VIP {} stable", a.address),
        format!(
            "VIP instable : {} puis {} — la dérivation ne peut pas dépendre de \
             la session",
            a.address, b.address
        ),
    )
}

/// Un pair jamais déclaré doit être refusé : le provisioning n'admet personne.
async fn scenario_pair_non_admis(profil: &ClientProfile, url: &str) -> Outcome {
    // Une clé fraîche, donc absente de `network.toml` par construction.
    let mut raw = [0u8; 32];
    if aws_lc_rs::rand::fill(&mut raw).is_err() {
        return Outcome::fail("CSPRNG système indisponible");
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let intrus = ClientProfile {
        private_key: engine.encode(raw),
        ..profil.clone()
    };

    match orion_core::provision(&intrus, url).await {
        Err(ProvisionError::Rejected { status: 403, .. }) => {
            Outcome::pass("pair inconnu refusé (403)")
        }
        Err(ProvisionError::Rejected { status, .. }) => {
            Outcome::fail(format!("refusé en {status} au lieu de 403"))
        }
        Err(e) => Outcome::fail(format!("refusé, mais pour la mauvaise raison : {e}")),
        Ok(_) => Outcome::fail(
            "INVARIANTE VIOLÉE : la gateway a provisionné une clé jamais \
             déclarée — l'admission hors bande ne tient plus",
        ),
    }
}

/// Noms de champs qui ne doivent jamais être sérialisés par une lecture.
///
/// La comparaison est **exacte**, pas par sous-chaîne : l'API expose
/// légitimement `preshared_key_configured` et `wg_private_key_configured`, des
/// booléens qui disent qu'un secret existe sans le divulguer. Les confondre
/// ferait échouer l'outil sur une API correcte.
const CHAMPS_SECRETS: [&str; 3] = ["preshared_key", "wg_private_key", "private_key"];

/// Cherche récursivement un champ secret sérialisé.
fn champ_secret(valeur: &serde_json::Value) -> Option<String> {
    match valeur {
        serde_json::Value::Object(map) => {
            for (cle, v) in map {
                if CHAMPS_SECRETS.contains(&cle.as_str()) {
                    return Some(cle.clone());
                }
                if let Some(trouve) = champ_secret(v) {
                    return Some(trouve);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().find_map(champ_secret),
        _ => None,
    }
}

/// Les lectures de l'API ne doivent jamais laisser filtrer un secret.
async fn scenario_secrets_absents_de_l_api(client: &Client, base: &str) -> Outcome {
    let corps: serde_json::Value = match client.get(format!("{base}/api/network")).send().await {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => return Outcome::fail(format!("réponse JSON illisible : {e}")),
        },
        Err(e) => return Outcome::fail(format!("appel impossible : {e}")),
    };

    match champ_secret(&corps) {
        Some(champ) => Outcome::fail(format!(
            "GET /api/network sérialise le champ `{champ}` — aucune lecture ne \
             doit exposer de secret"
        )),
        None => Outcome::pass("aucun champ secret dans GET /api/network"),
    }
}

/// Les mutations exigent du JSON : un corps non typé doit être refusé.
async fn scenario_mutation_sans_json(client: &Client, base: &str) -> Outcome {
    let reponse = client
        .post(format!("{base}/api/tunnel/start"))
        .header("content-type", "text/plain")
        .body("connect")
        .send()
        .await;

    match reponse {
        Err(e) => Outcome::fail(format!("appel impossible : {e}")),
        Ok(r) => Outcome::check(
            r.status() == 415,
            "corps non-JSON refusé (415)",
            format!("mutation acceptée en {} sans JSON", r.status()),
        ),
    }
}

// ─── Scénarios : plan de données (cible) ──────────────────────────────────────

/// Lit `wg show <iface> dump` et renvoie les lignes de pairs.
///
/// Format : la première ligne décrit l'interface, les suivantes les pairs —
/// `clé publique, PSK, endpoint, allowed-ips, dernier handshake, rx, tx,
/// keepalive`.
fn wg_dump(iface: &str) -> Result<Vec<Vec<String>>> {
    let sortie = std::process::Command::new("wg")
        .args(["show", iface, "dump"])
        .output()
        .context("`wg` introuvable — outil disponible uniquement sur la cible")?;
    if !sortie.status.success() {
        anyhow::bail!(
            "`wg show {iface} dump` a échoué : {}",
            String::from_utf8_lossy(&sortie.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&sortie.stdout)
        .lines()
        .skip(1) // ligne d'interface
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect())
}

/// Le PSK doit être **réellement** posé dans le slot WireGuard du noyau.
///
/// C'est la seule preuve qui compte : tout le reste peut réussir alors que le
/// plan de données n'a rien reçu. Aucune simulation ne peut l'établir.
fn scenario_psk_sur_l_interface(iface: &str, pair: &str) -> Outcome {
    let pairs = match wg_dump(iface) {
        Ok(p) => p,
        Err(e) => return Outcome::fail(format!("{e}")),
    };
    let Some(ligne) = pairs
        .iter()
        .find(|c| c.first().map(String::as_str) == Some(pair))
    else {
        return Outcome::fail(format!(
            "le pair {pair} est absent de {iface} : le provisioning ne l'a pas posé"
        ));
    };
    let psk = ligne.get(1).map(String::as_str).unwrap_or("(none)");

    Outcome::check(
        psk != "(none)" && !psk.is_empty(),
        "slot PresharedKey renseigné dans le noyau",
        "slot PresharedKey vide : le tunnel repose sur Curve25519 seul, donc \
         reste vulnérable au « récolter maintenant, déchiffrer plus tard »",
    )
}

/// Un handshake récent prouve que le PSK posé n'a pas cassé la session — le
/// risque exact d'un PSK unilatéral.
fn scenario_handshake_recent(iface: &str, pair: &str) -> Outcome {
    let pairs = match wg_dump(iface) {
        Ok(p) => p,
        Err(e) => return Outcome::fail(format!("{e}")),
    };
    let Some(ligne) = pairs
        .iter()
        .find(|c| c.first().map(String::as_str) == Some(pair))
    else {
        return Outcome::fail(format!("pair {pair} absent de {iface}"));
    };
    let horodatage: u64 = ligne.get(4).and_then(|v| v.parse().ok()).unwrap_or(0);
    if horodatage == 0 {
        return Outcome::fail(
            "aucun handshake depuis la pose du PSK — c'est la signature d'un \
             PSK présent d'un seul côté",
        );
    }
    let age = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().saturating_sub(horodatage))
        .unwrap_or(u64::MAX);

    Outcome::check(
        age < 180,
        format!("dernier handshake il y a {age} s"),
        format!("dernier handshake il y a {age} s (> REJECT_AFTER_TIME) : la session est morte"),
    )
}

// ─── Exécution ────────────────────────────────────────────────────────────────

/// Journalise une issue et indique si elle compte comme un échec.
fn rapporter(nom: &str, issue: &Outcome) -> bool {
    match issue {
        Outcome::Pass(d) => {
            println!("  {} {nom:<38} \x1b[2m{d}\x1b[0m", ok());
            false
        }
        Outcome::Skip(r) => {
            println!("  \x1b[90m—\x1b[0m {nom:<38} \x1b[90m{r}\x1b[0m");
            false
        }
        Outcome::Fail(r) => {
            println!("  {} {nom:<38} \x1b[31m{r}\x1b[0m", fail());
            true
        }
    }
}

fn entete(categorie: Category) {
    println!("\n\x1b[1m{}\x1b[0m", categorie.label());
    println!("{}", "─".repeat(categorie.label().chars().count()));
}

/// Exécute la campagne. Renvoie une erreur si au moins un scénario a échoué.
pub async fn run(client: &Client, base: &str, opts: Options) -> Result<()> {
    let joue = |c: Category| opts.only.is_none_or(|only| only == c);
    let mut echecs = 0usize;
    let mut joues = 0usize;

    println!("\n\x1b[1mCampagne de provisioning post-quantique\x1b[0m");
    println!("  cible   {base}");
    println!("  passes  {}", opts.repeat);

    for passe in 1..=opts.repeat {
        if opts.repeat > 1 {
            println!("\n\x1b[1m╌╌ passe {passe}/{} ╌╌\x1b[0m", opts.repeat);
        }

        // Le profil n'est requis que par les catégories réseau : une campagne
        // `--only client` doit tourner sans aucune clé.
        let profil = profile(&opts, base);

        if joue(Category::Client) {
            entete(Category::Client);
            // Ces scénarios n'impliquent aucun pair réel : à défaut de clés
            // fournies, un profil jetable suffit et rend la catégorie
            // exécutable partout.
            let p = match &profil {
                Ok(p) => p.clone(),
                Err(_) => profile_ephemere(),
            };
            for (nom, issue) in [
                (
                    "identité de gateway vérifiée",
                    scenario_identite_gateway(&p),
                ),
                (
                    "ciphertext malformé refusé",
                    scenario_ciphertext_malforme(&p),
                ),
                (
                    "version de protocole vérifiée",
                    scenario_version_protocole(&p),
                ),
            ] {
                joues += 1;
                echecs += usize::from(rapporter(nom, &issue));
            }
        }

        if joue(Category::Protocole) {
            entete(Category::Protocole);
            match &profil {
                Err(e) => {
                    rapporter("scénarios réseau", &Outcome::skip(format!("{e}")));
                }
                Ok(p) => {
                    let issues = vec![
                        (
                            "provisioning nominal",
                            scenario_provisioning_nominal(p, base).await,
                        ),
                        ("PSK frais par session", scenario_psk_frais(p, base).await),
                        (
                            "VIP stable entre sessions",
                            scenario_vip_stable(p, base).await,
                        ),
                        (
                            "pair non admis refusé",
                            scenario_pair_non_admis(p, base).await,
                        ),
                        (
                            "aucun secret dans l'API",
                            scenario_secrets_absents_de_l_api(client, base).await,
                        ),
                        (
                            "mutation sans JSON refusée",
                            scenario_mutation_sans_json(client, base).await,
                        ),
                    ];
                    for (nom, issue) in issues {
                        joues += 1;
                        echecs += usize::from(rapporter(nom, &issue));
                    }
                }
            }
        }

        if joue(Category::PlanDeDonnees) {
            entete(Category::PlanDeDonnees);
            match (&opts.wg_iface, &profil) {
                (None, _) => {
                    rapporter(
                        "plan de données",
                        &Outcome::skip("--wg-iface absent (cible uniquement)"),
                    );
                }
                (Some(_), Err(e)) => {
                    rapporter("plan de données", &Outcome::skip(format!("{e}")));
                }
                (Some(iface), Ok(p)) => {
                    let pair = match public_from_private(&p.private_key) {
                        Ok(k) => k,
                        Err(e) => anyhow::bail!("{e}"),
                    };
                    for (nom, issue) in [
                        (
                            "PSK posé dans le noyau",
                            scenario_psk_sur_l_interface(iface, &pair),
                        ),
                        (
                            "handshake vivant avec PSK",
                            scenario_handshake_recent(iface, &pair),
                        ),
                    ] {
                        joues += 1;
                        echecs += usize::from(rapporter(nom, &issue));
                    }
                }
            }
        }
    }

    println!();
    if echecs == 0 {
        println!("  {} campagne réussie — {joues} scénario(s)\n", ok());
        Ok(())
    } else {
        println!("  {} {echecs} échec(s) sur {joues} scénario(s)\n", fail());
        anyhow::bail!("campagne en échec")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_cle_publique_derive_de_la_privee_et_est_stable() {
        const PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let a = public_from_private(PRIV).unwrap();
        assert_eq!(a.len(), 44, "clé Curve25519 en base64");
        assert_eq!(a, public_from_private(PRIV).unwrap(), "dérivation stable");
    }

    #[test]
    fn cle_privee_invalide_signalee() {
        assert!(public_from_private("pas-du-base64").is_err());
        assert!(public_from_private("AAAA").is_err(), "longueur invalide");
    }

    /// Un profil incomplet doit bloquer les scénarios réseau **avant** tout
    /// appel : une campagne mal gréée doit le dire, pas échouer sur un timeout.
    #[test]
    fn profil_exige_les_deux_cles() {
        let sans_rien = Options {
            client_key: None,
            gateway_key: None,
            wg_iface: None,
            only: None,
            repeat: 1,
        };
        assert!(profile(&sans_rien, "http://x").is_err());

        let sans_gateway = Options {
            client_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into()),
            ..sans_rien
        };
        assert!(profile(&sans_gateway, "http://x").is_err());
    }

    /// Les scénarios client doivent tourner sans réseau : ils sont la base
    /// commune du dry-run et de la cible.
    #[test]
    fn les_scenarios_client_detectent_une_gateway_usurpee() {
        let profil = ClientProfile {
            name: "t".into(),
            endpoint: "127.0.0.1:51820".into(),
            private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            peer_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            ..ClientProfile::default()
        };
        assert!(matches!(
            scenario_identite_gateway(&profil),
            Outcome::Pass(_)
        ));
        assert!(matches!(
            scenario_ciphertext_malforme(&profil),
            Outcome::Pass(_)
        ));
        assert!(matches!(
            scenario_version_protocole(&profil),
            Outcome::Pass(_)
        ));
    }

    /// Le détecteur de secrets doit distinguer un secret sérialisé d'un simple
    /// indicateur de présence. Les confondre ferait échouer la campagne contre
    /// une API parfaitement correcte — c'est exactement ce qui est arrivé à la
    /// première version de ce scénario.
    #[test]
    fn indicateur_de_presence_n_est_pas_une_fuite() {
        let correct = serde_json::json!({
            "wg_private_key_configured": true,
            "peers": [{ "name": "poste", "preshared_key_configured": true }]
        });
        assert_eq!(champ_secret(&correct), None, "faux positif sur un booléen");

        let fuite_racine = serde_json::json!({ "wg_private_key": "AAAA" });
        assert_eq!(
            champ_secret(&fuite_racine).as_deref(),
            Some("wg_private_key")
        );

        // La fuite peut être imbriquée dans un tableau : le parcours doit
        // descendre, pas seulement regarder la racine.
        let fuite_imbriquee = serde_json::json!({
            "peers": [{ "name": "poste", "preshared_key": "secret" }]
        });
        assert_eq!(
            champ_secret(&fuite_imbriquee).as_deref(),
            Some("preshared_key")
        );
    }

    #[test]
    fn issue_check_traduit_la_condition() {
        assert!(matches!(Outcome::check(true, "d", "e"), Outcome::Pass(_)));
        assert!(matches!(Outcome::check(false, "d", "e"), Outcome::Fail(_)));
    }
}

//! Import de profils Orion depuis un document d'échange.
//!
//! Deux formats sont acceptés : le JSON Orion versionné, destiné aux outils
//! Helios, et le format `wg-quick` à un seul pair. L'import ne persiste rien :
//! il produit un [`ClientProfile`] validé que l'IHM présente comme brouillon.

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{ClientConfig, ClientProfile, DEFAULT_ALLOWED_IPS, DEFAULT_KEEPALIVE_SECS};

/// Identifiant stable du document JSON échangeable avec Orion.
pub const PROFILE_IMPORT_FORMAT: &str = "orion-profile";
/// Version courante du document JSON échangeable avec Orion.
pub const PROFILE_IMPORT_VERSION: u16 = 1;
/// Taille maximale d'un profil importé. Un profil normal tient dans quelques Ko.
pub const MAX_PROFILE_IMPORT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonEnvelope {
    #[serde(rename = "format")]
    _format: String,
    #[serde(rename = "version")]
    _version: u16,
    profile: JsonProfile,
}

#[derive(Deserialize)]
struct JsonHeader {
    format: String,
    version: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonProfile {
    name: String,
    endpoint: String,
    /// Absente dans un profil d'invitation : l'opérateur ne détient pas la clé
    /// privée du client et n'a donc rien à lui renvoyer (ADR-004 §6). L'IHM
    /// complète alors depuis le profil local de même nom.
    #[serde(default)]
    private_key: String,
    peer_public_key: String,
    #[serde(default)]
    preshared_key: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    allowed_ips: Option<String>,
    #[serde(default)]
    persistent_keepalive: Option<u16>,
    #[serde(default)]
    heliosd_url: Option<String>,
}

impl From<JsonProfile> for ClientProfile {
    fn from(profile: JsonProfile) -> Self {
        Self {
            name: profile.name,
            endpoint: profile.endpoint,
            private_key: profile.private_key,
            peer_public_key: profile.peer_public_key,
            preshared_key: profile.preshared_key,
            address: profile.address,
            allowed_ips: profile
                .allowed_ips
                .unwrap_or_else(|| DEFAULT_ALLOWED_IPS.to_string()),
            persistent_keepalive: profile
                .persistent_keepalive
                .unwrap_or(DEFAULT_KEEPALIVE_SECS),
            heliosd_url: profile.heliosd_url,
        }
    }
}

/// Décode un profil importé sans l'écrire sur disque.
///
/// Le suffixe du fichier choisit le parseur ; pour un fichier sans suffixe,
/// le premier caractère significatif permet de reconnaître JSON ou wg-quick.
pub fn parse_profile_import(contents: &str, file_name: &str) -> Result<ClientProfile> {
    if contents.len() > MAX_PROFILE_IMPORT_BYTES {
        anyhow::bail!(
            "fichier trop volumineux (maximum {} Kio)",
            MAX_PROFILE_IMPORT_BYTES / 1024
        );
    }

    let lower_name = file_name.to_ascii_lowercase();
    let trimmed = contents.trim_start_matches('\u{feff}').trim_start();
    let profile = if lower_name.ends_with(".json") || trimmed.starts_with('{') {
        parse_json(trimmed)?
    } else if lower_name.ends_with(".conf") || trimmed.starts_with('[') {
        parse_wg_quick(trimmed, file_name)?
    } else {
        anyhow::bail!("format inconnu : choisir un fichier Orion .json ou WireGuard .conf");
    };

    validate_imported_profile(profile)
}

/// Lit un profil depuis un chemin sans jamais allouer plus que la borne
/// d'import. La vérification porte sur les octets réellement lus : une taille
/// issue des métadonnées ne suffirait pas face à un fichier modifié en cours de
/// lecture.
pub fn read_profile_import_path(path: &Path) -> Result<ClientProfile> {
    let file = File::open(path).with_context(|| format!("ouverture de {}", path.display()))?;
    let mut bytes = Vec::with_capacity(MAX_PROFILE_IMPORT_BYTES.min(4096));
    file.take((MAX_PROFILE_IMPORT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("lecture de {}", path.display()))?;
    if bytes.len() > MAX_PROFILE_IMPORT_BYTES {
        anyhow::bail!(
            "fichier trop volumineux (maximum {} Kio)",
            MAX_PROFILE_IMPORT_BYTES / 1024
        );
    }
    let contents = String::from_utf8(bytes).context("le profil n'est pas encodé en UTF-8")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("le nom du profil n'est pas représentable en UTF-8")?;
    parse_profile_import(&contents, file_name)
}

/// Complète un document d'invitation depuis le profil local de même nom.
///
/// Les imports par sélecteur de fichier et par association système appellent
/// tous deux cette fonction. Une invitation reçue sur une autre machine est
/// refusée explicitement : fabriquer une nouvelle clé privée romprait
/// l'admission déjà liée à la clé publique originale.
pub fn complete_profile_import(
    mut profile: ClientProfile,
    config: &ClientConfig,
) -> Result<ClientProfile> {
    if profile.private_key.is_empty() {
        let existing = config
            .find(&profile.name)
            .filter(|candidate| !candidate.private_key.trim().is_empty())
            .with_context(|| {
                format!(
                    "ce profil ne contient pas de clé privée et aucun profil local « {} » n'en fournit une ; l'importer sur le poste qui a généré la clé ou demander un profil complet à l'opérateur",
                    profile.name
                )
            })?;
        profile.private_key = existing.private_key.clone();
    }
    profile.validate()?;
    Ok(profile)
}

fn parse_json(contents: &str) -> Result<ClientProfile> {
    // Lire d'abord l'en-tête garantit une erreur de version intelligible même
    // si une version future modifie entièrement la forme de `profile`.
    let header: JsonHeader =
        serde_json::from_str(contents).context("document JSON Orion invalide")?;
    if header.format != PROFILE_IMPORT_FORMAT {
        anyhow::bail!(
            "format JSON non reconnu : « {} » au lieu de « {PROFILE_IMPORT_FORMAT} »",
            header.format
        );
    }
    if header.version != PROFILE_IMPORT_VERSION {
        anyhow::bail!(
            "version de profil Orion non prise en charge : {} (version attendue : {PROFILE_IMPORT_VERSION})",
            header.version
        );
    }
    let envelope: JsonEnvelope =
        serde_json::from_str(contents).context("document JSON Orion invalide")?;
    Ok(envelope.profile.into())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WgSection {
    Interface,
    Peer,
}

fn parse_wg_quick(contents: &str, file_name: &str) -> Result<ClientProfile> {
    let mut section = None;
    let mut interface = HashMap::new();
    let mut peer = HashMap::new();
    let mut interface_count = 0_u8;
    let mut peer_count = 0_u8;

    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            section = match line[1..line.len() - 1].trim().to_ascii_lowercase().as_str() {
                "interface" => {
                    interface_count += 1;
                    if interface_count > 1 {
                        anyhow::bail!(
                            "ligne {line_number} : une seule section [Interface] est autorisée"
                        );
                    }
                    Some(WgSection::Interface)
                }
                "peer" => {
                    peer_count += 1;
                    if peer_count > 1 {
                        anyhow::bail!(
                            "ligne {line_number} : Orion accepte un seul pair par profil"
                        );
                    }
                    Some(WgSection::Peer)
                }
                other => anyhow::bail!("ligne {line_number} : section [{other}] inconnue"),
            };
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            anyhow::bail!("ligne {line_number} : propriété WireGuard mal formée");
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value.trim().to_string();
        let fields = match section {
            Some(WgSection::Interface) => &mut interface,
            Some(WgSection::Peer) => &mut peer,
            None => {
                anyhow::bail!("ligne {line_number} : propriété placée avant [Interface] ou [Peer]")
            }
        };
        if fields.insert(key.clone(), value).is_some() {
            anyhow::bail!("ligne {line_number} : propriété {key} déclarée plusieurs fois");
        }
    }

    if peer_count == 0 {
        anyhow::bail!("section [Peer] absente du fichier WireGuard");
    }
    if interface_count == 0 {
        anyhow::bail!("section [Interface] absente du fichier WireGuard");
    }
    reject_unsupported_fields(&interface, &["privatekey", "address"], "[Interface]")?;
    reject_unsupported_fields(
        &peer,
        &[
            "publickey",
            "presharedkey",
            "allowedips",
            "endpoint",
            "persistentkeepalive",
        ],
        "[Peer]",
    )?;

    let keepalive = match peer.get("persistentkeepalive") {
        Some(raw) => raw
            .parse::<u16>()
            .context("PersistentKeepalive doit être un entier entre 0 et 65535")?,
        None => DEFAULT_KEEPALIVE_SECS,
    };

    Ok(ClientProfile {
        name: profile_name_from_file(file_name),
        endpoint: required_field(&peer, "endpoint", "Endpoint")?,
        private_key: required_field(&interface, "privatekey", "PrivateKey")?,
        peer_public_key: required_field(&peer, "publickey", "PublicKey")?,
        preshared_key: peer.get("presharedkey").cloned(),
        address: interface.get("address").cloned(),
        allowed_ips: peer
            .get("allowedips")
            .cloned()
            .unwrap_or_else(|| DEFAULT_ALLOWED_IPS.to_string()),
        persistent_keepalive: keepalive,
        heliosd_url: None,
    })
}

fn reject_unsupported_fields(
    fields: &HashMap<String, String>,
    supported: &[&str],
    section: &str,
) -> Result<()> {
    if let Some(field) = fields
        .keys()
        .find(|field| !supported.contains(&field.as_str()))
    {
        anyhow::bail!(
            "propriété {field} de {section} non prise en charge par Orion ; la retirer modifierait le comportement du profil"
        );
    }
    Ok(())
}

fn required_field(
    fields: &HashMap<String, String>,
    normalized_name: &str,
    display_name: &str,
) -> Result<String> {
    fields
        .get(normalized_name)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .with_context(|| format!("propriété {display_name} requise"))
}

fn profile_name_from_file(file_name: &str) -> String {
    let basename = file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(file_name)
        .trim();
    let stem = basename.rsplit_once('.').map_or(basename, |(stem, _)| stem);
    if stem.trim().is_empty() {
        "profil-importé".to_string()
    } else {
        stem.trim().to_string()
    }
}

/// Diagnostic champ par champ d’un profil en cours d’édition.
///
/// `None` = rien à signaler. Chaque champ est indépendant des autres.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileIssues {
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub private_key: Option<String>,
    pub peer_public_key: Option<String>,
    pub preshared_key: Option<String>,
    pub address: Option<String>,
    pub allowed_ips: Option<String>,
    pub persistent_keepalive: Option<String>,
    pub heliosd_url: Option<String>,
}

impl ProfileIssues {
    /// `true` si au moins un champ est fautif.
    pub fn any(&self) -> bool {
        *self != Self::default()
    }
}

/// Relève **tous** les champs fautifs d’un profil en cours d’édition.
///
/// Contrairement à [`parse_profile_import`], qui refuse un document au premier
/// défaut, cette inspection ne s’arrête pas : l’IHM doit pouvoir surligner
/// chaque case en une passe, plutôt que d’en faire découvrir une à chaque
/// tentative d’enregistrement.
///
/// **Un champ vide n’est pas signalé.** Pendant la saisie, « pas encore
/// rempli » n’est pas « impossible » — noircir de rouge un profil neuf serait
/// du bruit. La complétude est jugée ailleurs, au moment de connecter.
///
/// Les validateurs sont ceux de l’import : c’est délibéré. Deux jeux de règles,
/// un pour l’import et un pour la saisie, finiraient par diverger et l’IHM
/// accepterait des valeurs que le cœur refuse.
pub fn inspect_profile(profile: &ClientProfile) -> ProfileIssues {
    /// Ne valide que si la valeur est renseignée.
    fn when_filled(value: &str, check: impl Fn(&str) -> Result<()>) -> Option<String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        check(trimmed).err().map(|error| error.to_string())
    }

    ProfileIssues {
        name: None,
        endpoint: when_filled(&profile.endpoint, validate_endpoint),
        private_key: when_filled(&profile.private_key, |value| {
            validate_wg_key(value, "clé privée")
        }),
        peer_public_key: when_filled(&profile.peer_public_key, |value| {
            validate_wg_key(value, "clé publique de la gateway")
        }),
        preshared_key: profile
            .preshared_key
            .as_deref()
            .and_then(|value| when_filled(value, |value| validate_wg_key(value, "PSK"))),
        address: profile.address.as_deref().and_then(|value| {
            when_filled(value, |value| validate_cidr(value, "adresse virtuelle"))
        }),
        allowed_ips: when_filled(&profile.allowed_ips, |value| {
            validate_cidr(value, "trafic capté")
        }),
        // Zéro n'est pas « vide » : c'est une valeur, et elle désactive le
        // keepalive alors qu'un client derrière NAT en dépend.
        persistent_keepalive: (profile.persistent_keepalive == 0)
            .then(|| "le keepalive doit être supérieur à zéro".to_string()),
        heliosd_url: profile
            .heliosd_url
            .as_deref()
            .and_then(|value| when_filled(value, validate_heliosd_url)),
    }
}

fn validate_imported_profile(mut profile: ClientProfile) -> Result<ClientProfile> {
    profile.name = profile.name.trim().to_string();
    profile.endpoint = profile.endpoint.trim().to_string();
    profile.private_key = profile.private_key.trim().to_string();
    profile.peer_public_key = profile.peer_public_key.trim().to_string();
    profile.allowed_ips = profile.allowed_ips.trim().to_string();
    profile.preshared_key = non_empty(profile.preshared_key);
    profile.address = non_empty(profile.address);
    profile.heliosd_url = non_empty(profile.heliosd_url);

    if profile.name.is_empty() {
        anyhow::bail!("le nom du profil est requis");
    }
    validate_endpoint(&profile.endpoint)?;
    // Un profil d'invitation arrive sans clé privée : l'opérateur n'a jamais
    // détenu celle du client, c'est précisément ce qui rend ce mode sûr. Le
    // document reste rejeté si la clé est présente mais malformée — une clé
    // tronquée n'est pas une invitation, c'est une erreur.
    if !profile.private_key.is_empty() {
        validate_wg_key(&profile.private_key, "clé privée du client")?;
    }
    validate_wg_key(&profile.peer_public_key, "clé publique de la gateway")?;
    if let Some(psk) = &profile.preshared_key {
        validate_wg_key(psk, "PresharedKey")?;
    }
    if profile.allowed_ips.is_empty() {
        anyhow::bail!("AllowedIPs ne peut pas être vide");
    }
    let address = profile
        .address
        .as_deref()
        .context("l'adresse virtuelle du client est requise")?;
    validate_cidr(address, "adresse virtuelle")?;
    validate_cidr(&profile.allowed_ips, "AllowedIPs")?;
    if profile.persistent_keepalive == 0 {
        anyhow::bail!("PersistentKeepalive doit être supérieur à zéro");
    }
    if let Some(url) = &profile.heliosd_url {
        validate_heliosd_url(url)?;
    }
    Ok(profile)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

/// Longueur d'une clé WireGuard : 32 octets bruts…
const WG_KEY_BYTES: usize = 32;
/// …soit exactement 44 caractères une fois encodés en base64.
const WG_KEY_BASE64_LEN: usize = 44;

/// Valide une clé Curve25519 encodée en base64.
///
/// Les messages disent ce qu'on attend, pas seulement que c'est refusé :
/// « base64 attendu » n'aide personne à voir qu'il manque un caractère au bout
/// d'un copier-coller tronqué. La longueur observée est donnée pour qu'on puisse
/// la comparer d'un coup d'œil aux 44 caractères attendus.
fn validate_wg_key(value: &str, label: &str) -> Result<()> {
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) else {
        anyhow::bail!(
            "{label} : caractères invalides. Une clé WireGuard fait {WG_KEY_BASE64_LEN} caractères base64 (A–Z, a–z, 0–9, + et /) et se termine par « = »."
        );
    };
    if decoded.len() != WG_KEY_BYTES {
        anyhow::bail!(
            "{label} : {} caractères au lieu de {WG_KEY_BASE64_LEN}. Une clé WireGuard fait {WG_KEY_BYTES} octets et se termine par « = » — vérifier que le copier-coller est complet.",
            value.chars().count()
        );
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.contains("://") {
        anyhow::bail!("Endpoint doit être une adresse UDP IP/FQDN:port, pas une URL");
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        anyhow::bail!("Endpoint invalide : port UDP absent");
    };
    if host.trim_matches(['[', ']']).is_empty() {
        anyhow::bail!("Endpoint invalide : hôte absent");
    }
    if host.chars().any(char::is_whitespace) {
        anyhow::bail!("Endpoint invalide : l'hôte contient un espace");
    }
    if host.starts_with('[') != host.ends_with(']') {
        anyhow::bail!("Endpoint invalide : adresse IPv6 mal délimitée");
    }
    let port = port
        .parse::<u16>()
        .context("Endpoint invalide : port UDP non numérique")?;
    if port == 0 {
        anyhow::bail!("Endpoint invalide : le port UDP doit être supérieur à zéro");
    }
    validate_endpoint_host(host)
}

/// Valide l'hôte d'un endpoint : littéral IPv6 entre crochets, adresse IPv4, ou
/// nom d'hôte.
///
/// Le cas qui motive cette fonction : `86.229.1286` n'est **ni** une IPv4 valide
/// (1286 dépasse 255) **ni** un nom d'hôte légitime — la RFC 1123 interdit qu'un
/// dernier label soit entièrement numérique, précisément pour qu'on ne puisse
/// pas confondre les deux. Sans cette règle, une IPv4 mal tapée passe pour un
/// nom de domaine et le défaut ne se révèle qu'au premier handshake, sous la
/// forme d'une résolution DNS qui échoue.
fn validate_endpoint_host(host: &str) -> Result<()> {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| anyhow::anyhow!("Endpoint invalide : adresse IPv6 illisible"));
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }

    if host.len() > 253 {
        anyhow::bail!("Endpoint invalide : nom d'hôte trop long");
    }
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            anyhow::bail!("Endpoint invalide : nom d'hôte mal formé");
        }
        if label.len() > 63 {
            anyhow::bail!("Endpoint invalide : partie de nom d'hôte trop longue");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            anyhow::bail!("Endpoint invalide : caractère interdit dans le nom d'hôte");
        }
        if label.starts_with('-') || label.ends_with('-') {
            anyhow::bail!("Endpoint invalide : nom d'hôte mal formé");
        }
    }
    if labels
        .last()
        .is_some_and(|label| label.chars().all(|c| c.is_ascii_digit()))
    {
        anyhow::bail!("Endpoint invalide : adresse IP mal formée");
    }
    Ok(())
}

fn validate_cidr(value: &str, label: &str) -> Result<()> {
    if value.contains(',') {
        anyhow::bail!("{label} invalide : Orion accepte un seul préfixe par profil");
    }
    let Some((address, prefix)) = value.split_once('/') else {
        anyhow::bail!("{label} invalide : notation CIDR attendue");
    };
    let address = address
        .parse::<IpAddr>()
        .with_context(|| format!("{label} invalide : adresse IP illisible"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("{label} invalide : préfixe non numérique"))?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        anyhow::bail!("{label} invalide : préfixe supérieur à {max_prefix}");
    }
    Ok(())
}

fn validate_heliosd_url(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .context("URL Helios interne invalide : schéma http:// ou https:// attendu")?;
    if rest.is_empty() || rest.chars().any(char::is_whitespace) {
        anyhow::bail!("URL Helios interne invalide");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_PRIVATE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const GATEWAY_PUBLIC: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    fn profil_complet() -> ClientProfile {
        ClientProfile {
            name: "poste".into(),
            endpoint: "vpn.example.net:51820".into(),
            private_key: CLIENT_PRIVATE.into(),
            peer_public_key: GATEWAY_PUBLIC.into(),
            address: Some("100.64.1.2/32".into()),
            allowed_ips: "0.0.0.0/0".into(),
            persistent_keepalive: 25,
            ..ClientProfile::default()
        }
    }

    /// Une IPv4 mal tapée ne doit pas passer pour un nom de domaine.
    ///
    /// `86.229.1286` est le cas réel : 1286 dépasse 255, mais la chaîne reste
    /// syntaxiquement acceptable comme suite de labels. Sans la règle RFC 1123
    /// sur le dernier label numérique, le défaut ne se révélait qu'au premier
    /// handshake, sous la forme d'une résolution DNS qui échoue.
    #[test]
    fn une_adresse_ip_mal_formee_ne_passe_pas_pour_un_nom_d_hote() {
        for accepte in [
            "86.229.12.86:51820",
            "vpn.example.net:51820",
            "gateway:51820",
            "[2a01:cb1e:101d:4b5c::1]:51820",
        ] {
            let profile = ClientProfile {
                endpoint: accepte.into(),
                ..profil_complet()
            };
            assert_eq!(
                inspect_profile(&profile).endpoint,
                None,
                "{accepte} aurait dû être accepté"
            );
        }

        for refuse in [
            "86.229.1286:51820",
            "256.1.1.1:51820",
            "10.0.0:51820",
            "[zz::1]:51820",
            "-mauvais.example.net:51820",
            "vpn..example.net:51820",
        ] {
            let profile = ClientProfile {
                endpoint: refuse.into(),
                ..profil_complet()
            };
            assert!(
                inspect_profile(&profile).endpoint.is_some(),
                "{refuse} aurait dû être refusé"
            );
        }
    }

    /// Le message doit dire **ce qu'on attend**, pas seulement que c'est refusé.
    /// « base64 attendu » n'aide pas à voir qu'un copier-coller a été tronqué ;
    /// la longueur observée face aux 44 caractères attendus, si.
    #[test]
    fn le_message_d_une_cle_invalide_donne_la_longueur_attendue() {
        let tronquee = &CLIENT_PRIVATE[..CLIENT_PRIVATE.len() - 4];
        let profile = ClientProfile {
            private_key: tronquee.into(),
            ..profil_complet()
        };
        let message = inspect_profile(&profile)
            .private_key
            .expect("une clé tronquée doit être refusée");
        assert!(message.contains("44"), "message : {message}");
        assert!(message.contains("clé privée"), "message : {message}");

        let profile = ClientProfile {
            peer_public_key: "pas du base64 !".into(),
            ..profil_complet()
        };
        let message = inspect_profile(&profile)
            .peer_public_key
            .expect("des caractères interdits doivent être refusés");
        assert!(message.contains("44"), "message : {message}");
    }

    #[test]
    fn un_profil_valide_ne_signale_aucun_champ() {
        assert!(!inspect_profile(&profil_complet()).any());
    }

    /// Pendant la saisie, « pas encore rempli » n’est pas « impossible » :
    /// noircir de rouge un profil neuf serait du bruit.
    #[test]
    fn les_champs_vides_ne_sont_pas_signales() {
        let issues = inspect_profile(&ClientProfile::default());
        assert_eq!(issues.endpoint, None);
        assert_eq!(issues.private_key, None);
        assert_eq!(issues.peer_public_key, None);
        assert_eq!(issues.address, None);
    }

    /// L’intérêt de l’inspection par rapport à l’import : elle ne s’arrête pas
    /// au premier défaut, sinon l’IHM en ferait découvrir un par tentative.
    #[test]
    fn tous_les_champs_fautifs_sont_releves_en_une_passe() {
        let profile = ClientProfile {
            endpoint: "https://vpn.example.net".into(),
            private_key: "pas-du-base64".into(),
            peer_public_key: "AAAA".into(),
            address: Some("100.64.1.2".into()),
            allowed_ips: "0.0.0.0/33".into(),
            persistent_keepalive: 0,
            heliosd_url: Some("100.64.0.1:8080".into()),
            ..profil_complet()
        };
        let issues = inspect_profile(&profile);

        assert!(issues.any());
        for (champ, valeur) in [
            ("endpoint", &issues.endpoint),
            ("private_key", &issues.private_key),
            ("peer_public_key", &issues.peer_public_key),
            ("address", &issues.address),
            ("allowed_ips", &issues.allowed_ips),
            ("persistent_keepalive", &issues.persistent_keepalive),
            ("heliosd_url", &issues.heliosd_url),
        ] {
            assert!(valeur.is_some(), "{champ} aurait dû être signalé");
        }
    }

    /// Zéro n’est pas « vide » : c’est une valeur, et elle coupe le keepalive
    /// dont un client derrière NAT dépend.
    #[test]
    fn un_keepalive_nul_est_signale_alors_qu_un_psk_absent_ne_l_est_pas() {
        let profile = ClientProfile {
            persistent_keepalive: 0,
            preshared_key: None,
            ..profil_complet()
        };
        let issues = inspect_profile(&profile);
        assert!(issues.persistent_keepalive.is_some());
        assert_eq!(issues.preshared_key, None);
    }

    #[test]
    fn importe_json_versionne_avec_defauts() {
        let raw = format!(
            r#"{{
                "format": "orion-profile",
                "version": 1,
                "profile": {{
                    "name": " portable ",
                    "endpoint": "vpn.example.net:51820",
                    "private_key": "{CLIENT_PRIVATE}",
                    "peer_public_key": "{GATEWAY_PUBLIC}",
                    "address": "100.64.1.2/32",
                    "heliosd_url": "http://100.64.0.1:8080"
                }}
            }}"#
        );

        let profile = parse_profile_import(&raw, "portable.json").unwrap();
        assert_eq!(profile.name, "portable");
        assert_eq!(profile.allowed_ips, DEFAULT_ALLOWED_IPS);
        assert_eq!(profile.persistent_keepalive, DEFAULT_KEEPALIVE_SECS);
        assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"));
    }

    /// Profil d'invitation (ADR-004 §6) : l'opérateur admet la clé publique que
    /// le client lui a transmise et renvoie tout **sauf** la clé privée, qu'il
    /// n'a jamais détenue. L'IHM la reprend du profil local de même nom.
    #[test]
    fn importe_une_invitation_sans_cle_privee() {
        let raw = format!(
            r#"{{
                "format": "orion-profile",
                "version": 1,
                "profile": {{
                    "name": "portable",
                    "endpoint": "vpn.example.net:51820",
                    "peer_public_key": "{GATEWAY_PUBLIC}",
                    "address": "100.64.1.2/32"
                }}
            }}"#
        );

        let profile = parse_profile_import(&raw, "portable.json").unwrap();
        assert!(
            profile.private_key.is_empty(),
            "l'invitation ne doit porter aucune clé privée"
        );
        assert_eq!(profile.peer_public_key, GATEWAY_PUBLIC);
        assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"));
        assert!(
            profile.validate().is_err(),
            "une invitation seule ne doit pas être présentée comme connectable"
        );
    }

    #[test]
    fn complete_une_invitation_avec_la_cle_locale_de_meme_nom() {
        let invitation = ClientProfile {
            name: "portable".into(),
            endpoint: "vpn.example.net:51820".into(),
            peer_public_key: GATEWAY_PUBLIC.into(),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        };
        let config = ClientConfig {
            profiles: vec![ClientProfile {
                name: "portable".into(),
                private_key: CLIENT_PRIVATE.into(),
                ..ClientProfile::default()
            }],
            selected: None,
        };

        let completed = complete_profile_import(invitation, &config).unwrap();
        assert_eq!(completed.private_key, CLIENT_PRIVATE);
    }

    #[test]
    fn refuse_une_invitation_sans_cle_locale_correspondante() {
        let invitation = ClientProfile {
            name: "portable".into(),
            endpoint: "vpn.example.net:51820".into(),
            peer_public_key: GATEWAY_PUBLIC.into(),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        };

        let error = complete_profile_import(invitation, &ClientConfig::default()).unwrap_err();
        assert!(error.to_string().contains("aucun profil local"));
    }

    /// Tolérer l'absence de clé privée ne doit pas faire tolérer une clé
    /// tronquée : ce n'est pas une invitation, c'est une corruption.
    #[test]
    fn une_cle_privee_presente_mais_malformee_reste_refusee() {
        let raw = r#"{
            "format": "orion-profile",
            "version": 1,
            "profile": {
                "name": "portable",
                "endpoint": "vpn.example.net:51820",
                "private_key": "AAAA",
                "peer_public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                "address": "100.64.1.2/32"
            }
        }"#;
        let erreur = parse_profile_import(raw, "portable.json").unwrap_err();
        assert!(
            erreur.to_string().contains("clé privée"),
            "message : {erreur}"
        );
    }

    /// `wg-quick` n'a pas de notion d'invitation : un fichier sans `PrivateKey`
    /// est un fichier incomplet, et le dire tôt évite un tunnel qui ne monte
    /// jamais sans explication.
    #[test]
    fn wg_quick_sans_cle_privee_reste_refuse() {
        let raw = format!(
            r#"
                [Interface]
                Address = 100.64.1.2/32

                [Peer]
                PublicKey = {GATEWAY_PUBLIC}
                Endpoint = vpn.example.net:51820
            "#
        );
        let erreur = parse_profile_import(&raw, "portable.conf").unwrap_err();
        assert!(
            erreur.to_string().contains("PrivateKey"),
            "message : {erreur}"
        );
    }

    #[test]
    fn importe_wg_quick_a_un_pair() {
        let raw = format!(
            r#"
                # profil émis par l'administrateur
                [Interface]
                PrivateKey = {CLIENT_PRIVATE}
                Address = 100.64.1.2/32

                [Peer]
                PublicKey = {GATEWAY_PUBLIC}
                AllowedIPs = 0.0.0.0/0
                Endpoint = 203.0.113.10:51820
                PersistentKeepalive = 25
            "#
        );

        let profile = parse_profile_import(&raw, r"C:\Profils\site-labo.conf").unwrap();
        assert_eq!(profile.name, "site-labo");
        assert_eq!(profile.endpoint, "203.0.113.10:51820");
        assert_eq!(profile.private_key, CLIENT_PRIVATE);
        assert_eq!(profile.peer_public_key, GATEWAY_PUBLIC);
        assert_eq!(profile.persistent_keepalive, 25);
    }

    #[test]
    fn refuse_json_inconnu_ou_champ_imprevu() {
        let wrong_version = r#"{
            "format": "orion-profile",
            "version": 2,
            "profile": {}
        }"#;
        assert!(parse_profile_import(wrong_version, "profil.json")
            .unwrap_err()
            .to_string()
            .contains("version"));

        let unknown_field = format!(
            r#"{{
                "format": "orion-profile",
                "version": 1,
                "profile": {{
                    "name": "site",
                    "endpoint": "vpn.example.net:51820",
                    "private_key": "{CLIENT_PRIVATE}",
                    "peer_public_key": "{GATEWAY_PUBLIC}",
                    "dns": "100.64.0.1"
                }}
            }}"#
        );
        assert!(parse_profile_import(&unknown_field, "profil.json").is_err());
    }

    #[test]
    fn refuse_plusieurs_pairs_et_options_non_appliquees() {
        let multiple = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820\n[Peer]\nPublicKey={GATEWAY_PUBLIC}"
        );
        assert!(parse_profile_import(&multiple, "multi.conf")
            .unwrap_err()
            .to_string()
            .contains("un seul pair"));

        let dns = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nDNS=100.64.0.1\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
        );
        assert!(parse_profile_import(&dns, "dns.conf")
            .unwrap_err()
            .to_string()
            .contains("dns"));
    }

    #[test]
    fn refuse_cles_et_endpoint_invalides() {
        let bad_key = format!(
            "[Interface]\nPrivateKey=court\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
        );
        assert!(parse_profile_import(&bad_key, "invalide.conf").is_err());

        let url = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=https://vpn.example.net"
        );
        assert!(parse_profile_import(&url, "url.conf")
            .unwrap_err()
            .to_string()
            .contains("pas une URL"));
    }

    #[test]
    fn refuse_un_profil_incomplet_ou_non_routable() {
        let no_address = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
        );
        assert!(parse_profile_import(&no_address, "sans-adresse.conf")
            .unwrap_err()
            .to_string()
            .contains("adresse virtuelle"));

        let no_keepalive = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820\nPersistentKeepalive=0"
        );
        assert!(parse_profile_import(&no_keepalive, "sans-keepalive.conf")
            .unwrap_err()
            .to_string()
            .contains("supérieur à zéro"));
    }

    #[test]
    fn refuse_un_document_demesure() {
        let raw = " ".repeat(MAX_PROFILE_IMPORT_BYTES + 1);
        assert!(parse_profile_import(&raw, "gros.json")
            .unwrap_err()
            .to_string()
            .contains("trop volumineux"));
    }

    #[test]
    fn lecture_par_chemin_reutilise_le_parseur_et_la_borne() {
        let directory = std::env::temp_dir().join(format!(
            "orion-import-chemin-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let profile_path = directory.join("portable.orionprofile");
        let raw = format!(
            r#"{{
                "format": "orion-profile",
                "version": 1,
                "profile": {{
                    "name": "portable",
                    "endpoint": "vpn.example.net:51820",
                    "private_key": "{CLIENT_PRIVATE}",
                    "peer_public_key": "{GATEWAY_PUBLIC}",
                    "address": "100.64.1.2/32"
                }}
            }}"#
        );
        std::fs::write(&profile_path, raw).unwrap();
        assert_eq!(
            read_profile_import_path(&profile_path).unwrap().name,
            "portable"
        );

        let oversized_path = directory.join("trop-grand.orionprofile");
        std::fs::write(&oversized_path, vec![b' '; MAX_PROFILE_IMPORT_BYTES + 1]).unwrap();
        assert!(read_profile_import_path(&oversized_path)
            .unwrap_err()
            .to_string()
            .contains("trop volumineux"));
        std::fs::remove_dir_all(directory).unwrap();
    }
}

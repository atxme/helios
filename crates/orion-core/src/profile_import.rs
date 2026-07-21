//! Import de profils Orion depuis un document d'échange.
//!
//! Deux formats sont acceptés : le JSON Orion versionné, destiné aux outils
//! Helios, et le format `wg-quick` à un seul pair. L'import ne persiste rien :
//! il produit un [`ClientProfile`] validé que l'IHM présente comme brouillon.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
use base64::Engine as _;
use serde::Deserialize;

use crate::{ClientProfile, DEFAULT_ALLOWED_IPS, DEFAULT_KEEPALIVE_SECS};

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
    profile.validate()?;
    validate_endpoint(&profile.endpoint)?;
    validate_wg_key(&profile.private_key, "clé privée du client")?;
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

fn validate_wg_key(value: &str, label: &str) -> Result<()> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| format!("{label} invalide : base64 attendu"))?;
    if decoded.len() != 32 {
        anyhow::bail!("{label} invalide : 32 octets attendus");
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
}

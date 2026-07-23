//! Admission d'un pair : l'étape hors bande que le provisioning ne fait jamais.
//!
//! Déclarer une clé publique dans `peers` est ce qui autorise un client à
//! monter le tunnel (voir [`crate`]). Cette opération se faisait à la main dans
//! `network.toml` ; elle est ici pour que les deux chemins de l'ADR-004 §4 —
//! local sur la gateway, et distant via l'API — partagent le **même** code.
//!
//! # Pourquoi ce n'est pas un simple `push`
//!
//! Trois règles doivent tenir ensemble, et aucune n'est évidente depuis
//! l'appelant :
//!
//! * la VIP vient de l'IPAM, pas d'un choix humain — dans WireGuard,
//!   `AllowedIPs` **est** la table de routage cryptographique, deux pairs ne
//!   peuvent pas revendiquer la même adresse ;
//! * l'adresse de la gateway est réservée : la lui attribuer couperait le plan
//!   de contrôle, donc le seul canal permettant de corriger l'erreur ;
//! * une clé publique déjà admise sous un autre nom est un doublon, pas un
//!   second pair : WireGuard indexe ses pairs par clé publique et le second
//!   écraserait silencieusement le premier.
//!
//! # Ce que l'admission ne fait pas
//!
//! Elle ne pose aucun PSK : celui-ci est dérivé à l'enrôlement ([`crate::session`])
//! et n'a pas de valeur avant. Elle ne révoque rien cryptographiquement non
//! plus — retirer un pair le fait tomber au prochain handshake, sans liste de
//! révocation (ADR-004).

use std::net::Ipv4Addr;

use aether::{wg, NetworkConfig, WgPeer};

use crate::ipam::{assign_vip, PeerTable, MAX_VIP_PROBES};

/// Refus d'admission. Chaque variante correspond à une règle explicite : une
/// admission ne doit jamais échouer « parce que ça n'a pas marché ».
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("nom de pair vide")]
    EmptyName,
    #[error("clé publique invalide : {0}")]
    Key(#[from] wg::WgKeyError),
    #[error("un pair nommé « {0} » est déjà admis")]
    NameTaken(String),
    #[error("cette clé publique est déjà admise sous le nom « {0} »")]
    KeyTaken(String),
    #[error("aucun pair nommé « {0} »")]
    Unknown(String),
    #[error("attribution de VIP impossible : {0}")]
    Ipam(#[from] crate::ipam::IpamError),
}

/// Admet un pair et lui attribue sa VIP.
///
/// La configuration n'est modifiée qu'en cas de succès : un refus laisse
/// `config` intacte, ce qui permet à l'appelant de la persister sans condition
/// après un `Ok`.
pub fn admit(
    config: &mut NetworkConfig,
    name: &str,
    public_key: &str,
    admin: bool,
) -> Result<WgPeer, AdmissionError> {
    let name = name.trim();
    let public_key = public_key.trim();

    if name.is_empty() {
        return Err(AdmissionError::EmptyName);
    }
    wg::validate_key(public_key)?;

    if let Some(existing) = config.peers.iter().find(|peer| peer.name.trim() == name) {
        return Err(AdmissionError::NameTaken(existing.name.clone()));
    }
    if let Some(existing) = config
        .peers
        .iter()
        .find(|peer| peer.public_key.trim() == public_key)
    {
        return Err(AdmissionError::KeyTaken(existing.name.clone()));
    }

    let raw = decode_key(public_key);
    let table = DeclaredPeers::new(config);
    let vip = assign_vip(&table, &raw, MAX_VIP_PROBES)?;

    let peer = WgPeer {
        name: name.to_string(),
        public_key: public_key.to_string(),
        address: format!("{vip}/32"),
        admin,
        // Le PSK naît de l'échange ML-KEM, pas de l'admission. Le poser ici
        // reviendrait à inventer un secret qu'aucun client ne connaît, et un
        // slot PSK renseigné d'un seul côté casse tous les handshakes du pair.
        preshared_key: None,
    };
    config.peers.push(peer.clone());
    Ok(peer)
}

/// Retire un pair de l'admission et le renvoie.
pub fn revoke(config: &mut NetworkConfig, name: &str) -> Result<WgPeer, AdmissionError> {
    let name = name.trim();
    let index = config
        .peers
        .iter()
        .position(|peer| peer.name.trim() == name)
        .ok_or_else(|| AdmissionError::Unknown(name.to_string()))?;
    Ok(config.peers.remove(index))
}

/// Table de VIP adossée à la configuration **déclarée**.
///
/// Le provisioning, lui, interroge la table **vivante** du noyau : les deux
/// vues coexistent volontairement. Celle-ci sert à choisir une adresse au
/// moment de l'admission, quand aucun tunnel n'existe encore.
struct DeclaredPeers {
    /// `(VIP, propriétaire)`. `None` désigne une adresse réservée, qu'aucun
    /// pair ne peut revendiquer — celle de la gateway elle-même.
    entries: Vec<(Ipv4Addr, Option<Vec<u8>>)>,
}

impl DeclaredPeers {
    fn new(config: &NetworkConfig) -> Self {
        let mut entries = Vec::with_capacity(config.peers.len() + 1);
        if let Some(addr) = host_of(&config.wg_address) {
            entries.push((addr, None));
        }
        for peer in &config.peers {
            // Une adresse illisible ne peut pas entrer en collision avec une VIP
            // dérivée : on l'ignore plutôt que de bloquer toute admission sur une
            // entrée héritée malformée.
            if let Some(addr) = host_of(&peer.address) {
                entries.push((addr, Some(decode_key(peer.public_key.trim()))));
            }
        }
        Self { entries }
    }
}

impl PeerTable for DeclaredPeers {
    fn is_taken_by_other(&self, addr: Ipv4Addr, pubkey: &[u8]) -> bool {
        self.entries.iter().any(|(taken, owner)| {
            *taken == addr
                && match owner {
                    Some(owner) => owner != pubkey,
                    None => true,
                }
        })
    }
}

/// Partie hôte d'une adresse CIDR (`100.64.1.2/32` → `100.64.1.2`).
fn host_of(cidr: &str) -> Option<Ipv4Addr> {
    cidr.trim().split('/').next()?.parse().ok()
}

/// Octets bruts d'une clé publique base64, vides si elle est illisible.
///
/// L'IPAM dérive la VIP des octets, jamais de l'encodage. Une clé illisible ne
/// peut pas arriver ici par [`admit`], qui valide avant ; le cas ne subsiste
/// que pour les entrées héritées d'une édition manuelle de `network.toml`.
fn decode_key(public_key: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::derive_cgnat_ip;

    fn cle(seed: u8) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    fn config() -> NetworkConfig {
        NetworkConfig {
            wg_address: "100.64.0.1/10".into(),
            ..NetworkConfig::default()
        }
    }

    #[test]
    fn admission_attribue_une_vip_en_32_dans_le_cgnat() {
        let mut config = config();
        let peer = admit(&mut config, "poste", &cle(1), false).expect("admission");

        assert!(peer.address.ends_with("/32"), "adresse : {}", peer.address);
        let addr = host_of(&peer.address).expect("adresse lisible");
        assert_eq!(addr.octets()[0], 100);
        assert!((64..=127).contains(&addr.octets()[1]));
        assert_eq!(config.peers.len(), 1);
        assert!(!peer.admin);
        assert!(
            peer.preshared_key.is_none(),
            "l'admission ne pose pas de PSK"
        );
    }

    /// L'intérêt de passer par l'IPAM : la gateway et le client dérivent la même
    /// adresse, donc l'enrôlement ne contredit pas l'admission.
    #[test]
    fn la_vip_admise_est_celle_que_le_provisioning_derive() {
        let mut config = config();
        let peer = admit(&mut config, "poste", &cle(7), false).expect("admission");
        assert_eq!(
            host_of(&peer.address).expect("adresse lisible"),
            derive_cgnat_ip(&[7u8; 32], 0)
        );
    }

    #[test]
    fn deux_pairs_recoivent_deux_vip() {
        let mut config = config();
        let a = admit(&mut config, "a", &cle(1), false).expect("admission a");
        let b = admit(&mut config, "b", &cle(2), false).expect("admission b");
        assert_ne!(a.address, b.address);
    }

    #[test]
    fn la_meme_cle_publique_est_refusee() {
        let mut config = config();
        admit(&mut config, "premier", &cle(3), false).expect("admission");
        let refus = admit(&mut config, "second", &cle(3), false);
        assert!(matches!(refus, Err(AdmissionError::KeyTaken(nom)) if nom == "premier"));
        assert_eq!(config.peers.len(), 1, "un refus ne modifie pas la config");
    }

    #[test]
    fn le_meme_nom_est_refuse() {
        let mut config = config();
        admit(&mut config, "poste", &cle(4), false).expect("admission");
        assert!(matches!(
            admit(&mut config, " poste ", &cle(5), false),
            Err(AdmissionError::NameTaken(_))
        ));
    }

    #[test]
    fn une_cle_invalide_est_refusee_avant_toute_ecriture() {
        let mut config = config();
        assert!(matches!(
            admit(&mut config, "poste", "pas-une-cle", false),
            Err(AdmissionError::Key(_))
        ));
        assert!(matches!(
            admit(&mut config, "poste", "", false),
            Err(AdmissionError::Key(_))
        ));
        assert!(config.peers.is_empty());
    }

    #[test]
    fn un_nom_vide_est_refuse() {
        let mut config = config();
        assert!(matches!(
            admit(&mut config, "   ", &cle(1), false),
            Err(AdmissionError::EmptyName)
        ));
    }

    /// L'adresse de la gateway est réservée : la lui prendre couperait le plan
    /// de contrôle, donc le seul canal permettant de réparer.
    #[test]
    fn la_vip_de_la_gateway_n_est_jamais_attribuee() {
        let cible = derive_cgnat_ip(&[9u8; 32], 0);
        let mut config = NetworkConfig {
            wg_address: format!("{cible}/10"),
            ..NetworkConfig::default()
        };
        let peer = admit(&mut config, "poste", &cle(9), false).expect("admission");
        assert_ne!(
            host_of(&peer.address).expect("adresse lisible"),
            cible,
            "la VIP de la gateway a été réattribuée"
        );
    }

    /// Le piège de l'ADR-004 §4 : ajouter un pair ne doit pas toucher aux
    /// secrets des autres, sous peine de casser tous leurs handshakes.
    #[test]
    fn l_admission_preserve_le_psk_des_autres_pairs() {
        let mut config = config();
        admit(&mut config, "ancien", &cle(1), true).expect("admission");
        config.peers[0].preshared_key = Some("psk-existant".into());

        admit(&mut config, "nouveau", &cle(2), false).expect("admission");

        assert_eq!(
            config.peers[0].preshared_key.as_deref(),
            Some("psk-existant")
        );
        assert!(config.peers[0].admin, "le rôle admin est préservé");
    }

    #[test]
    fn la_revocation_retire_le_pair_nomme() {
        let mut config = config();
        admit(&mut config, "a", &cle(1), false).expect("admission");
        admit(&mut config, "b", &cle(2), false).expect("admission");

        let retire = revoke(&mut config, "a").expect("révocation");
        assert_eq!(retire.name, "a");
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].name, "b");
    }

    #[test]
    fn revoquer_un_inconnu_echoue_sans_rien_changer() {
        let mut config = config();
        admit(&mut config, "a", &cle(1), false).expect("admission");
        assert!(matches!(
            revoke(&mut config, "fantome"),
            Err(AdmissionError::Unknown(_))
        ));
        assert_eq!(config.peers.len(), 1);
    }

    /// Une VIP libérée doit pouvoir être reprise par le même pair : la
    /// dérivation étant déterministe, réadmettre rend la même adresse.
    #[test]
    fn reamettre_apres_revocation_rend_la_meme_vip() {
        let mut config = config();
        let avant = admit(&mut config, "a", &cle(1), false).expect("admission");
        revoke(&mut config, "a").expect("révocation");
        let apres = admit(&mut config, "a", &cle(1), false).expect("réadmission");
        assert_eq!(avant.address, apres.address);
    }
}

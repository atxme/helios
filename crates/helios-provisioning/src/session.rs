//! Traitement d'une session de provisioning, côté gateway.
//!
//! Transport-agnostique : cette logique ne sait rien de TLS ni de sockets. Elle
//! consomme une [`ProvisionRequest`] et produit une [`ProvisionResponse`] plus
//! le PSK à installer. Le canal réel (TLS 1.3 ancré TPM, *à l'intérieur* du
//! tunnel) l'enveloppe sans la modifier — ce découpage rend tout l'échange
//! testable sans réseau, y compris sur WSL2, avec la **vraie** crypto ML-KEM.
//!
//! # Ce que cette session ne fait pas
//!
//! Elle n'admet pas un client inconnu. WireGuard étant fondé sur Noise_IK, un
//! pair non déclaré ne peut pas monter le tunnel, donc ne peut pas atteindre ce
//! code. L'admission est **hors bande** (voir [`crate`] et `aether::enroll`) :
//! ici, on refuse un pair inconnu avec [`EnrollError::UnknownPeer`] plutôt que
//! de l'enrôler à la volée.

use std::net::Ipv4Addr;

use aether::enroll::{
    derive_psk, EnrollError, ProvisionRequest, ProvisionResponse, Psk, NONCE_LEN, PROTOCOL_VERSION,
};
use aether::pq::{Kem, MlKem768Kem};

use crate::ipam::{assign_vip, PeerTable};

/// Durée de validité par défaut d'un PSK, en secondes (1 heure).
///
/// Borne la fenêtre d'exploitation d'un PSK compromis. Trop court, on
/// multiplie les rotations — et chaque rotation est un moment de fragilité
/// (voir `rotation`).
pub const DEFAULT_PSK_LIFETIME_SECS: u32 = 3600;

/// Nombre de sondes d'anti-collision de VIP.
const MAX_VIP_PROBES: u32 = 64;

/// Le registre des pairs admis, côté gateway.
///
/// L'admission est hors bande : cette interface ne fait que *consulter*. Une
/// implémentation typique lit la liste `peers` de `network.toml`.
pub trait AdmittedPeers {
    /// Ce pair a-t-il été admis (clé publique WireGuard, base64) ?
    fn is_admitted(&self, wg_public_key: &str) -> bool;
}

/// Résultat d'une session réussie.
#[derive(Debug)]
pub struct Provisioned {
    /// À renvoyer au client sur le canal de contrôle.
    pub response: ProvisionResponse,
    /// PSK à installer sur le pair WireGuard côté gateway. **Secret.**
    pub psk: Psk,
    /// VIP retenue pour ce pair.
    pub address: Ipv4Addr,
}

/// Paramètres invariants de la gateway pour une session.
pub struct GatewayIdentity<'a> {
    /// Clé publique WireGuard de la gateway (base64).
    pub wg_public_key: &'a str,
    /// Durée de validité annoncée pour le PSK.
    pub psk_lifetime_secs: u32,
}

/// Traite une demande de provisioning.
///
/// `gateway_nonce` est injecté plutôt que tiré ici : cela rend la fonction
/// déterministe et donc testable de bout en bout. En production, l'appelant le
/// tire du CSPRNG de l'OS — voir [`fresh_nonce`].
pub fn handle_request<P, T>(
    request: &ProvisionRequest,
    gateway: &GatewayIdentity<'_>,
    admitted: &P,
    peers: &T,
    gateway_nonce: [u8; NONCE_LEN],
) -> Result<Provisioned, EnrollError>
where
    P: AdmittedPeers,
    T: PeerTable,
{
    // 1. Validation structurelle avant toute opération coûteuse ou secrète.
    request.validate()?;

    // 2. L'admission est un prérequis, pas un effet de bord de cette session.
    if !admitted.is_admitted(&request.client_wg_public_key) {
        return Err(EnrollError::UnknownPeer);
    }

    // 3. VIP dérivée de la clé publique WireGuard du client : stable d'une
    //    session à l'autre et d'un redémarrage à l'autre, sans état sur disque.
    let pubkey_bytes = decode_wg_key(&request.client_wg_public_key)?;
    let address =
        assign_vip(peers, &pubkey_bytes, MAX_VIP_PROBES).map_err(|_| EnrollError::UnknownPeer)?;

    // 4. Encapsulation ML-KEM vers la clé éphémère du client. C'est la gateway
    //    qui encapsule : la fraîcheur du secret ne dépend donc pas d'un client
    //    potentiellement compromis.
    let (ciphertext, kem_secret) = MlKem768Kem::encapsulate(&request.kem_public_key)
        .map_err(|_| EnrollError::BadKemPublicKey(request.kem_public_key.len()))?;

    // 5. PSK lié aux deux nonces et aux deux identités.
    let psk = derive_psk(
        &kem_secret,
        &request.client_nonce,
        &gateway_nonce,
        &request.client_wg_public_key,
        gateway.wg_public_key,
    )?;

    Ok(Provisioned {
        response: ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: ciphertext,
            gateway_nonce,
            assigned_address: format!("{address}/32"),
            gateway_wg_public_key: gateway.wg_public_key.to_string(),
            psk_lifetime_secs: gateway.psk_lifetime_secs,
        },
        psk,
        address,
    })
}

/// Décode une clé publique WireGuard base64 en ses 32 octets bruts.
///
/// Ce sont ces octets — pas la chaîne base64 — qui alimentent l'IPAM : la
/// dérivation de VIP doit être indépendante de l'encodage.
fn decode_wg_key(b64: &str) -> Result<Vec<u8>, EnrollError> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| EnrollError::MissingClientKey)?;
    if raw.len() != 32 {
        return Err(EnrollError::MissingClientKey);
    }
    Ok(raw)
}

/// Tire un nonce de session depuis le CSPRNG du système.
pub fn fresh_nonce() -> [u8; NONCE_LEN] {
    use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
    let mut nonce = [0u8; NONCE_LEN];
    // `SystemRandom` ne peut échouer que si l'OS n'a pas d'entropie : dans ce
    // cas on ne doit surtout pas continuer avec un nonce prévisible.
    SystemRandom::new()
        .fill(&mut nonce)
        .expect("CSPRNG système indisponible — impossible de provisionner sûrement");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::enroll::PROTOCOL_VERSION;
    use std::collections::HashSet;

    struct Registry(HashSet<String>);
    impl AdmittedPeers for Registry {
        fn is_admitted(&self, k: &str) -> bool {
            self.0.contains(k)
        }
    }

    struct EmptyTable;
    impl PeerTable for EmptyTable {
        fn is_taken_by_other(&self, _: Ipv4Addr, _: &[u8]) -> bool {
            false
        }
    }

    const CLIENT_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const GATEWAY_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn registry() -> Registry {
        Registry(HashSet::from([CLIENT_KEY.to_string()]))
    }

    fn gateway() -> GatewayIdentity<'static> {
        GatewayIdentity {
            wg_public_key: GATEWAY_KEY,
            psk_lifetime_secs: DEFAULT_PSK_LIFETIME_SECS,
        }
    }

    /// Simule le client : génère sa paire ML-KEM éphémère et sa requête.
    fn client_request() -> (
        <MlKem768Kem as Kem>::SecretKey,
        [u8; NONCE_LEN],
        ProvisionRequest,
    ) {
        let (dk, ek) = MlKem768Kem::generate().unwrap();
        let client_nonce = [42u8; NONCE_LEN];
        let req = ProvisionRequest {
            protocol_version: PROTOCOL_VERSION,
            client_wg_public_key: CLIENT_KEY.into(),
            kem_public_key: ek,
            client_nonce,
        };
        (dk, client_nonce, req)
    }

    /// L'échange complet, avec la **vraie** crypto ML-KEM : les deux bouts
    /// doivent dériver le même PSK. C'est le test qui valide le protocole.
    #[test]
    fn echange_complet_les_deux_bouts_derivent_le_meme_psk() {
        let (dk, client_nonce, req) = client_request();
        let gw_nonce = [7u8; NONCE_LEN];

        // ── Côté gateway ──
        let out = handle_request(&req, &gateway(), &registry(), &EmptyTable, gw_nonce).unwrap();
        out.response.validate().unwrap();

        // ── Côté client : décapsule et dérive de son côté ──
        let kem_secret = MlKem768Kem::decapsulate(&dk, &out.response.kem_ciphertext).unwrap();
        let client_psk = derive_psk(
            &kem_secret,
            &client_nonce,
            &out.response.gateway_nonce,
            CLIENT_KEY,
            &out.response.gateway_wg_public_key,
        )
        .unwrap();

        assert_eq!(
            *client_psk, *out.psk,
            "client et gateway doivent dériver un PSK identique, sinon le \
             handshake WireGuard échouerait silencieusement"
        );
    }

    #[test]
    fn la_vip_est_stable_entre_deux_sessions() {
        let (_, _, req1) = client_request();
        let (_, _, req2) = client_request();
        let a =
            handle_request(&req1, &gateway(), &registry(), &EmptyTable, [1; NONCE_LEN]).unwrap();
        let b =
            handle_request(&req2, &gateway(), &registry(), &EmptyTable, [2; NONCE_LEN]).unwrap();
        assert_eq!(
            a.address, b.address,
            "la VIP dérive de la clé, pas de la session"
        );
        assert!(a.response.assigned_address.ends_with("/32"));
    }

    #[test]
    fn deux_sessions_donnent_des_psk_differents() {
        let (_, _, req) = client_request();
        let a = handle_request(&req, &gateway(), &registry(), &EmptyTable, [1; NONCE_LEN]).unwrap();
        let b = handle_request(&req, &gateway(), &registry(), &EmptyTable, [2; NONCE_LEN]).unwrap();
        assert_ne!(*a.psk, *b.psk, "chaque session doit produire un PSK frais");
    }

    /// Un client non admis est refusé : cette session ne fait pas d'admission.
    #[test]
    fn pair_non_admis_refuse() {
        let (_, _, mut req) = client_request();
        req.client_wg_public_key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into();
        let err = handle_request(&req, &gateway(), &registry(), &EmptyTable, [0; NONCE_LEN]);
        assert_eq!(err.unwrap_err(), EnrollError::UnknownPeer);
    }

    #[test]
    fn version_incompatible_refusee_avant_toute_crypto() {
        let (_, _, mut req) = client_request();
        req.protocol_version = 99;
        assert!(matches!(
            handle_request(&req, &gateway(), &registry(), &EmptyTable, [0; NONCE_LEN]),
            Err(EnrollError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn cle_kem_malformee_refusee() {
        let (_, _, mut req) = client_request();
        req.kem_public_key = vec![0u8; 10];
        assert!(matches!(
            handle_request(&req, &gateway(), &registry(), &EmptyTable, [0; NONCE_LEN]),
            Err(EnrollError::BadKemPublicKey(10))
        ));
    }

    #[test]
    fn les_nonces_tires_sont_distincts() {
        assert_ne!(fresh_nonce(), fresh_nonce());
    }
}

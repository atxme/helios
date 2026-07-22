//! Attribution d'adresses virtuelles (VIP) déterministe et **sans état sur
//! disque** (ADR-001, §4).
//!
//! WireGuard n'a pas de Config Payload : la gateway doit choisir la VIP du
//! client. Plutôt que de tenir une base de données (SQL/fichier) à sauvegarder,
//! migrer et corrompre, on **dérive** la VIP du seul identifiant stable et unique
//! d'un pair WireGuard : sa clé publique Curve25519.
//!
//! ```text
//! VIP = 100.64.0.0/10 | BLAKE3(clé_publique)[0..22 bits]
//! ```
//!
//! Le seul « état » est la table de pairs vivante du noyau, consultée à
//! l'enrôlement pour lever les rares collisions (§4). Rien n'est persisté :
//! après un redémarrage, chaque client retrouve sa VIP par re-dérivation.

use std::net::Ipv4Addr;

/// Plage partagée RFC 6598 (CGNAT) : `100.64.0.0/10`, ~4,19 M d'adresses.
///
/// Choisie pour ne collisionner ni avec les box résidentielles (`192.168/16`)
/// ni avec les réseaux d'entreprise (`10/8`). Un `/16` avait été envisagé puis
/// rejeté : 7,3 % de collision à 100 clients (ADR-001, §4).
const CGNAT_BASE: u32 = 0x6440_0000; // 100.64.0.0
/// Préfixe /10 → 22 bits d'hôte utilisables.
const HOST_BITS: u32 = 22;
const HOST_MASK: u32 = (1 << HOST_BITS) - 1;

/// Nombre d'adresses assignables dans la plage, hors réservées (voir plus bas).
pub const POOL_SIZE: u32 = 1 << HOST_BITS;

/// Nombre de sondes d'anti-collision de VIP.
///
/// Partagé par l'enrôlement et l'admission : deux bornes différentes rendraient
/// l'adresse choisie dépendante du chemin emprunté, alors que tout l'intérêt de
/// la dérivation est qu'elle soit la même partout.
pub const MAX_VIP_PROBES: u32 = 64;

/// Vue en lecture seule de la table de pairs WireGuard vivante.
///
/// Abstraite en trait pour rester **testable sur WSL2** : l'implémentation réelle
/// (cible) interrogera le noyau via `defguard_wireguard_rs` ; les tests
/// fournissent une fausse table en mémoire. La gateway ne persiste jamais cette
/// information — elle se reconstruit à mesure que les clients se reconnectent.
pub trait PeerTable {
    /// La VIP `addr` est-elle déjà attribuée à un pair dont la clé publique
    /// **diffère** de `pubkey` ? (Un pair ne collisionne jamais avec lui-même.)
    fn is_taken_by_other(&self, addr: Ipv4Addr, pubkey: &[u8]) -> bool;
}

/// Erreurs d'attribution.
#[derive(Debug, thiserror::Error)]
pub enum IpamError {
    /// Le pool est saturé, ou la résolution de collision a épuisé ses essais.
    #[error("aucune VIP libre après {0} tentatives")]
    Exhausted(u32),
}

/// Dérive l'adresse candidate n° `counter` pour cette clé publique.
///
/// Déterministe : même `(pubkey, counter)` ⇒ même adresse, sur toutes les
/// gateways et après tout redémarrage. Le `counter` n'intervient que pour
/// contourner une collision (cas rare) ; à `counter = 0` on obtient la VIP
/// « naturelle » du client.
pub fn derive_cgnat_ip(pubkey: &[u8], counter: u32) -> Ipv4Addr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pubkey);
    hasher.update(&counter.to_le_bytes());
    let digest = hasher.finalize();

    let mut first4 = [0u8; 4];
    first4.copy_from_slice(&digest.as_bytes()[..4]);
    let host = u32::from_le_bytes(first4) & HOST_MASK;

    Ipv4Addr::from(CGNAT_BASE | normalize_host(host))
}

/// Écarte les hôtes réservés du `/10` : `.0` (adresse réseau) et l'hôte tout-à-1
/// (broadcast). On remappe déterministement ces deux cas vers des hôtes valides
/// plutôt que de les tirer, pour ne jamais attribuer une VIP inutilisable.
fn normalize_host(host: u32) -> u32 {
    match host {
        0 => 1,
        h if h == HOST_MASK => HOST_MASK - 1,
        h => h,
    }
}

/// Attribue une VIP à `pubkey`, en évitant les collisions avec la table vivante.
///
/// Sonde `derive_cgnat_ip(pubkey, i)` pour `i = 0, 1, 2, …` et renvoie la
/// première adresse non détenue par une **autre** clé. `max_probes` borne la
/// boucle (collision astronomiquement improbable, mais on ne boucle jamais sans
/// fin). Sans disque : l'unique source de vérité est `table`.
pub fn assign_vip<T: PeerTable>(
    table: &T,
    pubkey: &[u8],
    max_probes: u32,
) -> Result<Ipv4Addr, IpamError> {
    for i in 0..max_probes {
        let candidate = derive_cgnat_ip(pubkey, i);
        if !table.is_taken_by_other(candidate, pubkey) {
            if i > 0 {
                tracing::warn!(
                    counter = i,
                    vip = %candidate,
                    "collision VIP résolue par re-dérivation"
                );
            }
            return Ok(candidate);
        }
    }
    Err(IpamError::Exhausted(max_probes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Fausse table de pairs en mémoire : `VIP -> clé publique propriétaire`.
    #[derive(Default)]
    struct FakeTable {
        owners: HashMap<Ipv4Addr, Vec<u8>>,
    }
    impl FakeTable {
        fn insert(&mut self, addr: Ipv4Addr, pubkey: &[u8]) {
            self.owners.insert(addr, pubkey.to_vec());
        }
    }
    impl PeerTable for FakeTable {
        fn is_taken_by_other(&self, addr: Ipv4Addr, pubkey: &[u8]) -> bool {
            self.owners
                .get(&addr)
                .map(|owner| owner != pubkey)
                .unwrap_or(false)
        }
    }

    #[test]
    fn vip_dans_la_plage_cgnat() {
        // Tout ce qui sort doit appartenir à 100.64.0.0/10.
        for seed in 0u8..50 {
            let vip = derive_cgnat_ip(&[seed; 32], 0);
            let oct = vip.octets();
            assert_eq!(oct[0], 100, "vip={vip}");
            assert!((64..=127).contains(&oct[1]), "vip={vip} hors /10");
        }
    }

    #[test]
    fn derivation_deterministe() {
        let pk = [7u8; 32];
        assert_eq!(derive_cgnat_ip(&pk, 0), derive_cgnat_ip(&pk, 0));
        // Deux clés différentes ⇒ (quasi toujours) deux VIP différentes.
        assert_ne!(
            derive_cgnat_ip(&[1u8; 32], 0),
            derive_cgnat_ip(&[2u8; 32], 0)
        );
    }

    #[test]
    fn meme_client_recupere_sa_vip_apres_reboot() {
        // Table vide = état « après redémarrage » : aucune persistance.
        let table = FakeTable::default();
        let pk = [42u8; 32];
        let avant = assign_vip(&table, &pk, 64).unwrap();
        let apres = assign_vip(&FakeTable::default(), &pk, 64).unwrap();
        assert_eq!(avant, apres, "la VIP doit être stable sans état sur disque");
    }

    #[test]
    fn collision_resolue_par_re_derivation() {
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        // On force une collision : on occupe la VIP naturelle de B avec A.
        let vip_b_naturelle = derive_cgnat_ip(&pk_b, 0);
        let mut table = FakeTable::default();
        table.insert(vip_b_naturelle, &pk_a);

        let vip_b = assign_vip(&table, &pk_b, 64).unwrap();
        assert_ne!(vip_b, vip_b_naturelle, "B doit éviter la VIP prise par A");
        assert_eq!(
            vip_b,
            derive_cgnat_ip(&pk_b, 1),
            "B bascule sur le compteur 1"
        );
    }

    #[test]
    fn client_ne_collisionne_pas_avec_lui_meme() {
        // Si la VIP est déjà à MOI (reconnexion), je la garde — pas de dérive.
        let pk = [9u8; 32];
        let vip = derive_cgnat_ip(&pk, 0);
        let mut table = FakeTable::default();
        table.insert(vip, &pk);
        assert_eq!(assign_vip(&table, &pk, 64).unwrap(), vip);
    }

    #[test]
    fn jamais_d_hote_reserve() {
        assert_eq!(normalize_host(0), 1);
        assert_eq!(normalize_host(HOST_MASK), HOST_MASK - 1);
        assert_eq!(normalize_host(1234), 1234);
    }
}

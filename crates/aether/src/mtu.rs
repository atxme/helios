//! Calcul du MTU d'un tunnel WireGuard.
//!
//! WireGuard laisse 1420 par défaut, ce qui suppose un transport à 1500. Dès
//! que le lien qui porte le tunnel est plus étroit — WSL2 à 1280, PPPoE à 1492,
//! tunnels IPv6, réseaux mobiles — les paquets chiffrés dépassent le MTU du
//! transport et sont **jetés en silence**.
//!
//! Le symptôme égare : le handshake passe (petits paquets), les requêtes
//! courtes aussi, et seules les grosses disparaissent — un ciphertext ML-KEM,
//! par exemple. Le diagnostic ressemble alors à une panne applicative.
//!
//! # Pourquoi le calcul est ici
//!
//! Les deux bouts en ont besoin et doivent s'accorder : la gateway pour son
//! interface, Orion pour la sienne. Le partager évite deux arithmétiques qui
//! divergent.
//!
//! # Ce que ce module ne résout pas
//!
//! Le MTU WireGuard est **par interface, pas par pair**. La gateway n'ayant
//! qu'une interface pour tous ses clients, elle ne peut pas servir un MTU
//! différent à chacun : elle prend une valeur dérivée de son WAN, et les
//! clients dont le chemin est plus étroit relèvent du MSS clamping (TCP) ou du
//! PMTUD (UDP). Côté client, en revanche, une interface ne porte qu'un pair :
//! le MTU y est donc exactement celui du chemin.
//!
//! Les jumbo frames ne sont pas traitées : un jumbo n'existe que si *chaque*
//! saut l'accepte, ce qui exclut un client road-warrior joignant la gateway par
//! Internet, où le PMTU est en pratique ≤ 1500.

/// Surcoût d'encapsulation WireGuard, en octets.
///
/// Détail : en-tête IPv6 (40) + UDP (8) + en-tête WireGuard (16) + tag
/// Poly1305 (16). En IPv4 l'en-tête n'est que de 20 octets, soit 60 au total.
///
/// On retient systématiquement le cas IPv6, le plus coûteux. Distinguer les
/// deux familles gagnerait 20 octets de charge utile, au prix d'une décision
/// prise à l'exécution sur l'adresse du pair — se tromper coûte un tunnel qui
/// perd silencieusement ses gros paquets, ce qui n'en vaut pas la peine.
pub const SURCOUT_WIREGUARD: u32 = 80;

/// MTU plancher, en octets.
///
/// 576 est le minimum qu'un hôte IPv4 doit accepter (RFC 791). Un plancher à
/// 1280 — minimum IPv6 — serait ici contre-productif : sur un transport déjà à
/// 1280, il annulerait le calcul et reproduirait exactement la panne que ce
/// module corrige.
pub const MTU_PLANCHER: u32 = 576;

/// MTU par défaut d'un transport dont on n'a pas su lire la valeur.
pub const MTU_TRANSPORT_DEFAUT: u32 = 1500;

/// MTU à poser sur l'interface WireGuard, déduit du MTU du lien qui la porte.
///
/// ```
/// use aether::mtu::tunnel_mtu;
/// assert_eq!(tunnel_mtu(1500), 1420); // Ethernet : la valeur usuelle
/// assert_eq!(tunnel_mtu(1280), 1200); // WSL2 : là où le défaut échoue
/// ```
pub fn tunnel_mtu(mtu_transport: u32) -> u32 {
    mtu_transport
        .saturating_sub(SURCOUT_WIREGUARD)
        .max(MTU_PLANCHER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_cas_ethernet_donne_la_valeur_usuelle() {
        // 1420 est le défaut de WireGuard : sur un transport à 1500, le calcul
        // doit retomber dessus, sinon il change le comportement nominal.
        assert_eq!(tunnel_mtu(1500), 1420);
    }

    #[test]
    fn un_transport_etroit_est_reduit_et_non_planche_a_1280() {
        // Non-régression du bug constaté sur cible : un plancher à 1280 aurait
        // laissé 1280 ici, soit exactement le MTU du transport — donc des
        // paquets chiffrés systématiquement trop gros.
        assert_eq!(tunnel_mtu(1280), 1200);
        assert!(tunnel_mtu(1280) < 1280);
    }

    #[test]
    fn le_surcout_couvre_la_mesure_sur_materiel() {
        // Mesuré sur cible, transport à 1280 : 1220 passe, 1221 échoue. Le
        // surcoût réel en IPv4 est donc de 60 octets, et la valeur retenue doit
        // rester sous cette limite pour couvrir aussi IPv6.
        let limite_ipv4_mesuree = 1280 - 60;
        assert!(tunnel_mtu(1280) <= limite_ipv4_mesuree);
    }

    #[test]
    fn le_pppoe_est_pris_en_compte() {
        assert_eq!(tunnel_mtu(1492), 1412);
    }

    #[test]
    fn un_transport_absurde_ne_deborde_pas() {
        assert_eq!(tunnel_mtu(0), MTU_PLANCHER);
        assert_eq!(tunnel_mtu(10), MTU_PLANCHER);
    }

    #[test]
    fn un_jumbo_local_est_transmis_sans_plafonnement() {
        // Gateway et client sur un même LAN jumbo : le calcul ne doit pas
        // brider ce que le lien permet réellement.
        assert_eq!(tunnel_mtu(9000), 8920);
    }
}

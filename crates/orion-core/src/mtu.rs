//! MTU du lien qui porte le tunnel, côté client.
//!
//! Le calcul lui-même vit dans [`aether::mtu`], partagé avec la gateway. Ce
//! module ne fournit que l'entrée : le MTU du transport.
//!
//! # Pourquoi le client, et pas seulement la gateway
//!
//! Le MTU WireGuard est **par interface**. La gateway n'en ayant qu'une pour
//! tous ses clients, elle ne peut pas servir une valeur différente à chacun.
//! Côté client, en revanche, une interface ne porte qu'un pair : son MTU peut
//! donc coller exactement au chemin. C'est ce qui rend un poste sur un lien à
//! 1500 et un autre à 1280 simultanément fonctionnels, sans configuration.
//!
//! # Limite connue : Linux seulement
//!
//! La détection s'appuie sur `/proc/net/route` et `/sys/class/net`, absents
//! ailleurs. Sur Windows et macOS, [`mtu_transport`] renvoie `None` et le
//! backend laisse le défaut de WireGuard (1420) — le comportement d'avant ce
//! module, correct tant que le transport est à 1500, et pris en défaut en
//! dessous.
//!
//! Ce qui débloquerait ces plateformes : `GetIfEntry2` sur Windows,
//! `getifaddrs` sur macOS, ou une dépendance d'énumération d'interfaces. Aucune
//! n'est dans le workspace aujourd'hui, et aucune n'est vérifiable depuis la
//! cible Linux d'essai — l'ajouter sans pouvoir l'exercer déplacerait le risque
//! sans le réduire.

/// MTU du lien portant la route par défaut, ou `None` si indéterminable.
///
/// La route par défaut est le bon repère pour un client road-warrior : sa
/// gateway est distante, donc joignable par elle. Un déploiement où la gateway
/// est sur le LAN emprunterait une route connectée, mais son MTU est alors
/// celui de la même interface physique.
pub fn mtu_transport() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        let iface = iface_route_defaut(&table)?;
        let brut = std::fs::read_to_string(format!("/sys/class/net/{iface}/mtu")).ok()?;
        brut.trim().parse().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Interface portant la route par défaut, extraite de `/proc/net/route`.
///
/// Le format est tabulaire : `Iface Destination Gateway Flags …`, les adresses
/// en hexadécimal petit-boutiste. La route par défaut est celle dont la
/// destination vaut zéro.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn iface_route_defaut(table: &str) -> Option<&str> {
    table
        .lines()
        .skip(1) // ligne d'en-tête
        .filter_map(|ligne| {
            let mut champs = ligne.split_whitespace();
            let iface = champs.next()?;
            let destination = champs.next()?;
            // `u32::from_str_radix` plutôt qu'une comparaison à "00000000" :
            // le noyau peut zéro-padder différemment selon les versions.
            (u32::from_str_radix(destination, 16).ok()? == 0).then_some(iface)
        })
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t01004E0A\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00004E0A\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\t0\t0";

    #[test]
    fn la_route_par_defaut_est_reconnue() {
        assert_eq!(iface_route_defaut(TABLE), Some("eth0"));
    }

    #[test]
    fn une_table_sans_route_par_defaut_ne_renvoie_rien() {
        let sans_defaut = "Iface\tDestination\tGateway\n\
             eth0\t00004E0A\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\t0\t0";
        assert_eq!(iface_route_defaut(sans_defaut), None);
    }

    #[test]
    fn la_premiere_route_par_defaut_l_emporte() {
        // Plusieurs défauts coexistent quand deux liens sont montés ; le noyau
        // les ordonne par métrique croissante, donc le premier est l'actif.
        let deux = "Iface\tDestination\tGateway\n\
             wlan0\t00000000\t01004E0A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
             eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0";
        assert_eq!(iface_route_defaut(deux), Some("wlan0"));
    }

    #[test]
    fn une_table_vide_ou_tronquee_ne_panique_pas() {
        assert_eq!(iface_route_defaut(""), None);
        assert_eq!(iface_route_defaut("Iface\tDestination"), None);
        assert_eq!(iface_route_defaut("Iface\neth0"), None);
        assert_eq!(iface_route_defaut("Iface\neth0\tPASDELHEXA"), None);
    }
}

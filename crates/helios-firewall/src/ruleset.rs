//! Rendu d'une politique + d'un état en un jeu de règles déclaratif.
//!
//! Le jeu de règles produit est volontairement exprimé en syntaxe nftables
//! lisible : c'est l'artefact que `DryRunBackend` journalise et que l'on peut
//! comparer (diff) entre deux états. Le `NetlinkBackend` construit l'équivalent
//! via l'API Netlink à partir de la même intention.

use helios_core::{FirewallPolicy, TunnelState};

/// Verdict d'une règle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

/// Jeu de règles complet d'une table `inet helios`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    /// Politique par défaut des chaînes à hook (drop = fail-closed).
    pub default_verdict: Verdict,
    /// Règles, exprimées en syntaxe nftables pour lisibilité et diff.
    pub rules: Vec<String>,
}

/// Construit le jeu de règles pour `(policy, state)`.
///
/// Quel que soit l'état, on autorise toujours :
/// * la loopback,
/// * le trafic déjà établi/connexe (les SA en cours), et
/// * la négociation IKE vers les pairs déclarés (UDP 500/4500 + ESP).
///
/// Règles spéciales par état :
/// * `CaptivePortal` — HTTP/HTTPS vers la passerelle locale uniquement.
/// * `Up`/`Rekeying` + split-tunnel — CIDRs locaux bypassent le tunnel.
/// * `Up`/`Rekeying` + MSS clamping — limite la taille des SYN sortants.
pub fn render(policy: &FirewallPolicy, state: TunnelState) -> Ruleset {
    let mut rules = Vec::new();

    // Restriction d'accès à l'interface d'administration — en TÊTE de chaîne,
    // avant même le loopback, pour bloquer toute connexion hors `admin_iface`.
    if let (Some(port), Some(iface)) = (policy.admin_port, policy.admin_iface.as_deref()) {
        rules.push(format!(
            "tcp dport {port} ct state new iifname \"{iface}\" accept"
        ));
        rules.push(format!("tcp dport {port} ct state new drop"));
    }

    // Toujours autorisé.
    rules.push("iif \"lo\" accept".to_string());
    rules.push("ct state established,related accept".to_string());

    // Négociation IKE et transport ESP vers les pairs autorisés, en clair.
    for peer in &policy.ike_peers {
        rules.push(format!(
            "oifname \"{wan}\" ip daddr {peer} udp dport {{ 500, 4500 }} accept",
            wan = policy.wan_iface
        ));
        rules.push(format!(
            "oifname \"{wan}\" ip daddr {peer} meta l4proto esp accept",
            wan = policy.wan_iface
        ));
    }

    // SSH d'administration, autorisé quel que soit l'état du tunnel.
    for src in &policy.allow_ssh_from {
        rules.push(format!("ip saddr {src} tcp dport 22 accept"));
    }

    if state.captive_portal_active() {
        // Portail captif : lever le kill-switch uniquement pour HTTP/HTTPS
        // vers la passerelle locale identifiée lors de la détection.
        match &policy.captive_portal_gateway {
            Some(gw) => {
                rules.push(format!(
                    "oifname \"{wan}\" ip daddr {gw} tcp dport {{ 80, 443 }} accept",
                    wan = policy.wan_iface
                ));
                rules.push(format!("# portail captif : HTTP/HTTPS autorisés vers {gw}"));
            }
            None => {
                // Passerelle inconnue : autoriser HTTP/HTTPS vers toute destination
                // pour que le navigateur puisse joindre la page d'accueil du portail.
                rules.push(format!(
                    "oifname \"{wan}\" tcp dport {{ 80, 443 }} accept",
                    wan = policy.wan_iface
                ));
                rules.push(
                    "# portail captif : HTTP/HTTPS autorisés (passerelle inconnue)".to_string(),
                );
            }
        }
    } else if state.traffic_allowed() {
        // MSS clamping : limite la taille des segments TCP pour éviter la
        // fragmentation des paquets ESP (appliqué avant le forward LAN→WAN).
        if let Some(mss) = policy.mss_clamp {
            rules.push(format!(
                "oifname \"{wan}\" tcp flags syn tcp option maxseg size set {mss}",
                wan = policy.wan_iface
            ));
        }

        // Split-tunneling : les CIDRs locaux bypassent le tunnel IPsec.
        // Le noyau les achemine via la table de routage locale (pas via XFRM).
        for cidr in &policy.split_tunnel_cidrs {
            rules.push(format!("ip daddr {cidr} accept"));
        }

        // Tunnel opérationnel : on forwarde le LAN. XFRM se charge du chiffrement
        // en sortie ; un paquet non protégé par une policy IPsec ne sortira pas.
        for lan in &policy.lan_ifaces {
            rules.push(format!(
                "iifname \"{lan}\" oifname \"{wan}\" accept",
                wan = policy.wan_iface
            ));
        }
    } else {
        rules.push(format!(
            "# tunnel {state:?} : kill-switch engagé, aucun forward LAN -> {wan}",
            wan = policy.wan_iface
        ));
    }

    // En fail-open, la politique par défaut devient accept hors tunnel (déconseillé).
    let default_verdict = if policy.is_fail_closed() || state.traffic_allowed() {
        Verdict::Drop
    } else {
        Verdict::Accept
    };

    Ruleset {
        default_verdict,
        rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_core::PolicyMode;

    fn policy() -> FirewallPolicy {
        FirewallPolicy {
            wan_iface: "eth0".into(),
            lan_ifaces: vec!["eth1".into()],
            ike_peers: vec!["203.0.113.10".into()],
            mode: PolicyMode::FailClosed,
            allow_ssh_from: vec![],
            admin_port: None,
            admin_iface: None,
            split_tunnel_cidrs: vec![],
            mss_clamp: None,
            captive_portal_gateway: None,
        }
    }

    #[test]
    fn down_blocks_lan_forward() {
        let rs = render(&policy(), TunnelState::Down);
        assert_eq!(rs.default_verdict, Verdict::Drop);
        assert!(!rs.rules.iter().any(|r| r.contains("iifname \"eth1\"")));
        // IKE reste autorisé pour pouvoir (re)monter le tunnel.
        assert!(rs.rules.iter().any(|r| r.contains("udp dport")));
    }

    #[test]
    fn up_allows_lan_forward() {
        let rs = render(&policy(), TunnelState::Up);
        assert!(rs
            .rules
            .iter()
            .any(|r| r.contains("iifname \"eth1\" oifname \"eth0\" accept")));
    }

    #[test]
    fn fail_closed_default_is_always_drop() {
        for st in [TunnelState::Down, TunnelState::Failed, TunnelState::Connecting] {
            assert_eq!(render(&policy(), st).default_verdict, Verdict::Drop);
        }
    }

    #[test]
    fn captive_portal_allows_http_to_gateway() {
        let mut p = policy();
        p.captive_portal_gateway = Some("192.168.1.1".into());
        let rs = render(&p, TunnelState::CaptivePortal);
        assert!(rs.rules.iter().any(|r| r.contains("192.168.1.1") && r.contains("tcp dport")));
        assert!(!rs.rules.iter().any(|r| r.contains("iifname \"eth1\" oifname")));
        assert_eq!(rs.default_verdict, Verdict::Drop);
    }

    #[test]
    fn captive_portal_without_gateway_allows_all_http() {
        let rs = render(&policy(), TunnelState::CaptivePortal);
        assert!(rs.rules.iter().any(|r| r.contains("tcp dport { 80, 443 } accept")));
    }

    #[test]
    fn split_tunnel_adds_bypass_rules() {
        let mut p = policy();
        p.split_tunnel_cidrs = vec!["192.168.1.0/24".into(), "10.0.0.0/8".into()];
        let rs = render(&p, TunnelState::Up);
        assert!(rs.rules.iter().any(|r| r.contains("ip daddr 192.168.1.0/24 accept")));
        assert!(rs.rules.iter().any(|r| r.contains("ip daddr 10.0.0.0/8 accept")));
        assert!(rs.rules.iter().any(|r| r.contains("iifname \"eth1\"")));
    }

    #[test]
    fn mss_clamping_added_when_up() {
        let mut p = policy();
        p.mss_clamp = Some(1398);
        let rs = render(&p, TunnelState::Up);
        assert!(rs.rules.iter().any(|r| r.contains("maxseg size set 1398")));
        // MSS clamping absent quand le tunnel est Down
        let rs_down = render(&p, TunnelState::Down);
        assert!(!rs_down.rules.iter().any(|r| r.contains("maxseg")));
    }
}

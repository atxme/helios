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
/// Le trafic LAN -> WAN n'est forwardé que lorsque le tunnel est opérationnel.
pub fn render(policy: &FirewallPolicy, state: TunnelState) -> Ruleset {
    let mut rules = Vec::new();

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

    if state.traffic_allowed() {
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
}

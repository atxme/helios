//! Rendu d'une politique + d'un état en un jeu de règles **structuré**.
//!
//! Le jeu de règles est une structure de données, pas du texte : c'est elle que
//! le backend Netlink traduit en expressions, et dont le [`crate::DryRunBackend`]
//! et l'API dérivent la syntaxe nftables lisible via [`Display`]. L'inverse —
//! produire du texte puis le re-parser — serait fragile et ferait diverger
//! silencieusement l'affichage de ce qui est réellement appliqué.
//!
//! Chaque règle porte la **chaîne à hook** à laquelle elle appartient : le
//! trafic destiné à la gateway elle-même (écoute WireGuard, API, SSH) va dans
//! `input`, le trafic du LAN qui la traverse dans `forward`, et le trafic
//! qu'elle émet dans `output`. Les confondre laisserait passer — ou bloquerait —
//! le mauvais trafic.

use std::fmt;

use aether::{FirewallPolicy, TunnelState};

/// Verdict d'une règle ou politique par défaut d'une chaîne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

/// Chaîne à hook Netfilter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainKind {
    /// Trafic à destination de la gateway elle-même.
    Input,
    /// Trafic qui traverse la gateway (LAN -> WAN).
    Forward,
    /// Trafic émis par la gateway.
    Output,
}

impl ChainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChainKind::Input => "input",
            ChainKind::Forward => "forward",
            ChainKind::Output => "output",
        }
    }
}

/// Protocole de transport pour un match de port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    Tcp,
    Udp,
}

impl L4 {
    fn as_str(self) -> &'static str {
        match self {
            L4::Tcp => "tcp",
            L4::Udp => "udp",
        }
    }
}

/// Un critère de correspondance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    /// `iif "lo"` — interface d'entrée loopback.
    Loopback,
    /// `ct state established,related`
    Established,
    /// `iifname "<iface>"`
    InIface(String),
    /// `oifname "<iface>"`
    OutIface(String),
    /// `<proto> dport <port>`
    DestPort { port: u16, proto: L4 },
    /// `<proto> dport { a, b }` — ensemble de ports.
    DestPortSet { ports: Vec<u16>, proto: L4 },
    /// `ip daddr <addr>` — IP ou CIDR.
    DestNet(String),
    /// `ip saddr <addr>` — IP ou CIDR.
    SourceNet(String),
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Match::Loopback => write!(f, "iif \"lo\""),
            Match::Established => write!(f, "ct state established,related"),
            Match::InIface(i) => write!(f, "iifname \"{i}\""),
            Match::OutIface(i) => write!(f, "oifname \"{i}\""),
            Match::DestPort { port, proto } => write!(f, "{} dport {port}", proto.as_str()),
            Match::DestPortSet { ports, proto } => {
                let list: Vec<String> = ports.iter().map(u16::to_string).collect();
                write!(f, "{} dport {{ {} }}", proto.as_str(), list.join(", "))
            }
            Match::DestNet(a) => write!(f, "ip daddr {a}"),
            Match::SourceNet(a) => write!(f, "ip saddr {a}"),
        }
    }
}

/// Une règle : une chaîne, des critères, un verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub chain: ChainKind,
    pub matches: Vec<Match>,
    pub verdict: Verdict,
    /// Justification, pour la lecture humaine. Aucun effet sur le filtrage.
    pub note: Option<String>,
}

impl Rule {
    fn new(chain: ChainKind, matches: Vec<Match>, verdict: Verdict) -> Self {
        Self { chain, matches, verdict, note: None }
    }

    fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for m in &self.matches {
            write!(f, "{m} ")?;
        }
        match self.verdict {
            Verdict::Accept => write!(f, "accept"),
            Verdict::Drop => write!(f, "drop"),
        }
    }
}

/// Jeu de règles complet de la table `inet helios`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    /// Politique par défaut des chaînes à hook (`Drop` = fail-closed).
    pub default_verdict: Verdict,
    pub rules: Vec<Rule>,
    /// MSS clamping demandé, le cas échéant.
    ///
    /// Volontairement **hors** de `rules` : c'est une action de *mangle*
    /// (réécriture d'option TCP), pas un verdict de filtrage, et l'API haut
    /// niveau de `rustables` ne l'exprime pas. Voir le backend Netlink.
    pub mss_clamp: Option<u16>,
}

impl Ruleset {
    /// Règles d'une chaîne donnée, dans l'ordre.
    pub fn chain(&self, kind: ChainKind) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(move |r| r.chain == kind)
    }
}

/// Construit le jeu de règles pour `(policy, state)`.
///
/// Invariants, quel que soit l'état :
/// * loopback et trafic établi/connexe toujours acceptés ;
/// * le port d'écoute WireGuard reste joignable, sans quoi aucun client ne
///   pourrait (re)monter le tunnel ;
/// * le forward LAN -> WAN n'est ouvert que dans l'état `Up`.
pub fn render(policy: &FirewallPolicy, state: TunnelState) -> Ruleset {
    use ChainKind::{Forward, Input, Output};
    let mut rules = Vec::new();
    let wan = policy.wan_iface.clone();

    // ── Administration : l'API ne doit être joignable qu'à travers le tunnel ──
    // En tête de chaîne, avant même le loopback.
    if let (Some(port), Some(iface)) = (policy.admin_port, policy.admin_iface.as_deref()) {
        rules.push(
            Rule::new(
                Input,
                vec![
                    Match::DestPort { port, proto: L4::Tcp },
                    Match::InIface(iface.to_string()),
                ],
                Verdict::Accept,
            )
            .with_note("API d'administration : uniquement via l'interface du tunnel"),
        );
        rules.push(
            Rule::new(
                Input,
                vec![Match::DestPort { port, proto: L4::Tcp }],
                Verdict::Drop,
            )
            .with_note(
                "toute autre origine est refusée. Pas de `ct state new` : le drop couvre \
                 aussi les connexions déjà établies depuis une autre interface — plus \
                 strict, et exprimable en Netlink",
            ),
        );
    }

    // ── Toujours autorisé ────────────────────────────────────────────────────
    for chain in [Input, Forward, Output] {
        rules.push(Rule::new(chain, vec![Match::Loopback], Verdict::Accept));
        rules.push(Rule::new(chain, vec![Match::Established], Verdict::Accept));
    }

    // ── Écoute WireGuard (rôle serveur) ──────────────────────────────────────
    // Les clients road-warrior arrivent depuis des IP inconnues et changeantes :
    // impossible de scoper par source. C'est l'unique ouverture entrante du
    // modèle fail-closed, et elle est indispensable au handshake.
    if let Some(port) = policy.wg_listen_port {
        rules.push(
            Rule::new(
                Input,
                vec![
                    Match::InIface(wan.clone()),
                    Match::DestPort { port, proto: L4::Udp },
                ],
                Verdict::Accept,
            )
            .with_note("écoute WireGuard — sans cette règle, aucun client ne peut handshaker"),
        );
    }

    // ── Transport WireGuard sortant vers des pairs statiques (site-à-site) ───
    // Scopé par destination : ouvrir 51820 en sortie sans restreindre la
    // destination serait une fuite.
    for peer in &policy.wg_peers {
        rules.push(Rule::new(
            Output,
            vec![
                Match::OutIface(wan.clone()),
                Match::DestNet(peer.clone()),
                Match::DestPort { port: 51820, proto: L4::Udp },
            ],
            Verdict::Accept,
        ));
    }

    // ── SSH d'administration, quel que soit l'état du tunnel ─────────────────
    for src in &policy.allow_ssh_from {
        rules.push(Rule::new(
            Input,
            vec![
                Match::SourceNet(src.clone()),
                Match::DestPort { port: 22, proto: L4::Tcp },
            ],
            Verdict::Accept,
        ));
    }

    if state.captive_portal_active() {
        // Portail captif : on lève le kill-switch pour HTTP/HTTPS seulement.
        let ports = Match::DestPortSet { ports: vec![80, 443], proto: L4::Tcp };
        match &policy.captive_portal_gateway {
            Some(gw) => {
                for chain in [Output, Forward] {
                    rules.push(
                        Rule::new(
                            chain,
                            vec![
                                Match::OutIface(wan.clone()),
                                Match::DestNet(gw.clone()),
                                ports.clone(),
                            ],
                            Verdict::Accept,
                        )
                        .with_note(format!("portail captif : HTTP/HTTPS vers {gw}")),
                    );
                }
            }
            None => {
                // Passerelle inconnue : on laisse le navigateur atteindre la
                // page d'accueil du portail, quelle qu'en soit la destination.
                for chain in [Output, Forward] {
                    rules.push(
                        Rule::new(
                            chain,
                            vec![Match::OutIface(wan.clone()), ports.clone()],
                            Verdict::Accept,
                        )
                        .with_note("portail captif : passerelle inconnue"),
                    );
                }
            }
        }
    } else if state.traffic_allowed() {
        // Split-tunneling : les CIDRs locaux contournent le tunnel.
        for cidr in &policy.split_tunnel_cidrs {
            rules.push(Rule::new(
                Forward,
                vec![Match::DestNet(cidr.clone())],
                Verdict::Accept,
            ));
        }

        // Tunnel opérationnel : on forwarde le LAN. WireGuard chiffre en sortie ;
        // un paquet non capturé par l'interface du tunnel ne sortira pas.
        for lan in &policy.lan_ifaces {
            rules.push(Rule::new(
                Forward,
                vec![Match::InIface(lan.clone()), Match::OutIface(wan.clone())],
                Verdict::Accept,
            ));
        }
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
        mss_clamp: state.traffic_allowed().then_some(policy.mss_clamp).flatten(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::PolicyMode;

    fn policy() -> FirewallPolicy {
        FirewallPolicy {
            wan_iface: "eth0".into(),
            lan_ifaces: vec!["eth1".into()],
            wg_peers: vec!["203.0.113.10".into()],
            wg_listen_port: Some(51820),
            mode: PolicyMode::FailClosed,
            allow_ssh_from: vec![],
            admin_port: None,
            admin_iface: None,
            split_tunnel_cidrs: vec![],
            mss_clamp: None,
            captive_portal_gateway: None,
        }
    }

    /// Rendu textuel d'une chaîne, pour des assertions lisibles.
    fn text(rs: &Ruleset, kind: ChainKind) -> Vec<String> {
        rs.chain(kind).map(|r| r.to_string()).collect()
    }

    #[test]
    fn down_blocks_lan_forward() {
        let rs = render(&policy(), TunnelState::Down);
        assert_eq!(rs.default_verdict, Verdict::Drop);
        assert!(!text(&rs, ChainKind::Forward)
            .iter()
            .any(|r| r.contains("iifname \"eth1\"")));
    }

    /// Sans cette règle, aucun client road-warrior ne peut handshaker : le
    /// fail-closed jette les paquets entrants. C'est la condition d'accès.
    #[test]
    fn le_port_d_ecoute_est_ouvert_en_entree() {
        for st in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
            let rs = render(&policy(), st);
            assert!(
                text(&rs, ChainKind::Input)
                    .iter()
                    .any(|r| r == "iifname \"eth0\" udp dport 51820 accept"),
                "état {st:?} : le port d'écoute WireGuard doit rester joignable"
            );
        }
    }

    #[test]
    fn pas_d_ouverture_entrante_sans_role_serveur() {
        let mut p = policy();
        p.wg_listen_port = None;
        let rs = render(&p, TunnelState::Down);
        assert!(!text(&rs, ChainKind::Input)
            .iter()
            .any(|r| r.contains("udp dport 51820")));
    }

    /// L'écoute WireGuard est en `input` (trafic vers la gateway), le forward
    /// LAN en `forward`. Les confondre bloquerait ou ouvrirait le mauvais trafic.
    #[test]
    fn les_regles_sont_dans_la_bonne_chaine() {
        let rs = render(&policy(), TunnelState::Up);
        assert!(text(&rs, ChainKind::Input)
            .iter()
            .any(|r| r.contains("udp dport 51820")));
        assert!(text(&rs, ChainKind::Forward)
            .iter()
            .any(|r| r.contains("iifname \"eth1\" oifname \"eth0\"")));
        // Le transport sortant vers un pair statique est en `output`.
        assert!(text(&rs, ChainKind::Output)
            .iter()
            .any(|r| r.contains("ip daddr 203.0.113.10")));
    }

    #[test]
    fn up_allows_lan_forward() {
        let rs = render(&policy(), TunnelState::Up);
        assert!(text(&rs, ChainKind::Forward)
            .iter()
            .any(|r| r == "iifname \"eth1\" oifname \"eth0\" accept"));
    }

    #[test]
    fn fail_closed_default_is_always_drop() {
        for st in [TunnelState::Down, TunnelState::Failed, TunnelState::Connecting] {
            assert_eq!(render(&policy(), st).default_verdict, Verdict::Drop);
        }
    }

    #[test]
    fn admin_api_restreinte_a_l_interface_du_tunnel() {
        let mut p = policy();
        p.admin_port = Some(8080);
        p.admin_iface = Some("helios0".into());
        let rs = render(&p, TunnelState::Up);
        let input = text(&rs, ChainKind::Input);

        // L'accept scopé doit précéder le drop générique.
        let accept = input.iter().position(|r| r.contains("helios0")).unwrap();
        let drop = input
            .iter()
            .position(|r| r == "tcp dport 8080 drop")
            .unwrap();
        assert!(accept < drop, "l'accept scopé doit primer sur le drop");
    }

    #[test]
    fn captive_portal_allows_http_to_gateway() {
        let mut p = policy();
        p.captive_portal_gateway = Some("192.168.1.1".into());
        let rs = render(&p, TunnelState::CaptivePortal);
        assert!(rs
            .rules
            .iter()
            .any(|r| r.to_string().contains("192.168.1.1") && r.to_string().contains("dport")));
        assert!(!text(&rs, ChainKind::Forward)
            .iter()
            .any(|r| r.contains("iifname \"eth1\" oifname")));
        assert_eq!(rs.default_verdict, Verdict::Drop);
    }

    #[test]
    fn captive_portal_without_gateway_allows_all_http() {
        let rs = render(&policy(), TunnelState::CaptivePortal);
        assert!(rs
            .rules
            .iter()
            .any(|r| r.to_string().contains("tcp dport { 80, 443 } accept")));
    }

    #[test]
    fn split_tunnel_adds_bypass_rules() {
        let mut p = policy();
        p.split_tunnel_cidrs = vec!["192.168.1.0/24".into(), "10.0.0.0/8".into()];
        let rs = render(&p, TunnelState::Up);
        let fwd = text(&rs, ChainKind::Forward);
        assert!(fwd.iter().any(|r| r == "ip daddr 192.168.1.0/24 accept"));
        assert!(fwd.iter().any(|r| r == "ip daddr 10.0.0.0/8 accept"));
        assert!(fwd.iter().any(|r| r.contains("iifname \"eth1\"")));
    }

    /// Le MSS clamping est une action de mangle, pas un verdict : il vit hors
    /// de `rules` et n'est retenu que tunnel opérationnel.
    #[test]
    fn mss_clamping_hors_des_regles_et_seulement_up() {
        let mut p = policy();
        p.mss_clamp = Some(1380);
        assert_eq!(render(&p, TunnelState::Up).mss_clamp, Some(1380));
        assert_eq!(render(&p, TunnelState::Down).mss_clamp, None);
    }
}

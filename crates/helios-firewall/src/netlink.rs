//! Backend Netlink réel, basé sur `rustables` (nf_tables).
//!
//! ⚠️ **Cible uniquement.** Ce module se compile partout, mais ne peut être
//! *exercé* que sur un kernel disposant de `nf_tables` — pas WSL2. À valider sur
//! la machine dédiée :
//!
//! ```sh
//! cargo build -p heliosd --features netlink
//! sudo ./target/debug/heliosd run
//! sudo nft list table inet helios
//! ```
//!
//! # Atomicité et fail-closed
//!
//! Toute l'application passe par **une seule transaction Netlink** (`Batch`) :
//! le kernel l'applique en entier ou pas du tout. Il n'existe donc aucun instant
//! où la table serait à moitié peuplée — c'est-à-dire aucun instant où le
//! kill-switch serait partiellement levé.
//!
//! La table est **recréée à chaque application** (`Add`, `Del`, puis `Add` dans
//! la même transaction) : c'est le seul moyen d'obtenir un remplacement atomique
//! sans laisser traîner d'anciennes règles.
//!
//! Le premier `Add` garantit l'existence de la table avant sa suppression. Le
//! noyau ne tolère **pas** un `Del` sur une table absente : il répond `ENOENT`
//! et rejette la transaction entière. Sans ce `Add`, aucun kill-switch n'était
//! posé au tout premier démarrage d'une machine et heliosd s'arrêtait — un
//! comportement que seul un essai sur cible réelle pouvait révéler.
//!
//! # Limite connue : MSS clamping
//!
//! `Ruleset::mss_clamp` n'est **pas** appliqué ici : réécrire l'option TCP MSS
//! est une action de *mangle* que l'API haut niveau de `rustables` n'expose pas.
//! C'est une optimisation de performance (éviter la fragmentation), pas une
//! règle de sécurité : son absence ne laisse aucune brèche. Elle est journalisée
//! en `warn` pour ne pas disparaître en silence.

use std::net::IpAddr;
use std::str::FromStr;

use aether::{FirewallPolicy, HeliosError, Result, TunnelState};
use async_trait::async_trait;
use rustables::{
    expr::Masquerade, Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol,
    ProtocolFamily, Rule as NfRule, Table,
};
use tracing::{info, warn};

use crate::ruleset::{render, ChainKind, Match, Ruleset, Verdict, L4};
use crate::FirewallBackend;

const TABLE_NAME: &str = "helios";

pub struct NetlinkBackend {
    table_name: String,
}

impl NetlinkBackend {
    pub fn new() -> Self {
        Self {
            table_name: TABLE_NAME.to_string(),
        }
    }

    fn err(msg: impl std::fmt::Display) -> HeliosError {
        HeliosError::Firewall(msg.to_string())
    }

    fn hook_class(kind: ChainKind) -> HookClass {
        match kind {
            ChainKind::Input => HookClass::In,
            ChainKind::Forward => HookClass::Forward,
            ChainKind::Output => HookClass::Out,
        }
    }

    /// Applique un critère à une règle en construction.
    fn apply_match(rule: NfRule, m: &Match) -> Result<NfRule> {
        let proto = |p: L4| match p {
            L4::Tcp => Protocol::TCP,
            L4::Udp => Protocol::UDP,
        };

        Ok(match m {
            Match::Established => rule.established().map_err(Self::err)?,
            Match::InIface(i) => rule.iiface(i).map_err(Self::err)?,
            Match::OutIface(i) => rule.oiface(i).map_err(Self::err)?,
            Match::DestPort { port, proto: p } => rule.dport(*port, proto(*p)),
            Match::DestPortSet { .. } => {
                return Err(Self::err(
                    "ensemble de ports : doit être éclaté par expand_port_sets avant traduction",
                ))
            }
            Match::DestNet(addr) => Self::match_net(rule, addr, false)?,
            Match::SourceNet(addr) => Self::match_net(rule, addr, true)?,
        })
    }

    /// Applique un match d'adresse, en acceptant IP simple ou CIDR.
    fn match_net(rule: NfRule, addr: &str, source: bool) -> Result<NfRule> {
        if addr.contains('/') {
            let net = ipnetwork::IpNetwork::from_str(addr)
                .map_err(|e| Self::err(format!("CIDR `{addr}` invalide : {e}")))?;
            let r = if source {
                rule.snetwork(net)
            } else {
                rule.dnetwork(net)
            };
            r.map_err(Self::err)
        } else {
            let ip = IpAddr::from_str(addr)
                .map_err(|e| Self::err(format!("IP `{addr}` invalide : {e}")))?;
            Ok(if source {
                rule.saddr(ip)
            } else {
                rule.daddr(ip)
            })
        }
    }

    /// Éclate un `DestPortSet` en une liste de jeux de critères à port unique.
    /// Le filtrage résultant est identique.
    fn expand_port_sets(matches: &[Match]) -> Vec<Vec<Match>> {
        let Some(idx) = matches
            .iter()
            .position(|m| matches!(m, Match::DestPortSet { .. }))
        else {
            return vec![matches.to_vec()];
        };
        let Match::DestPortSet { ports, proto } = &matches[idx] else {
            unreachable!()
        };

        ports
            .iter()
            .map(|port| {
                let mut copy = matches.to_vec();
                copy[idx] = Match::DestPort {
                    port: *port,
                    proto: *proto,
                };
                copy
            })
            .collect()
    }

    /// Séquence de messages appliquée à la table elle-même, dans cet ordre.
    ///
    /// Le `Add` initial n'est pas décoratif : sans lui, le `Del` porte sur une
    /// table absente au tout premier démarrage, le noyau répond `ENOENT` et
    /// rejette la transaction entière — donc pas de kill-switch, et heliosd
    /// s'arrête. Constaté sur cible réelle ; le dry-run ne pouvait pas le voir.
    const SEQUENCE_TABLE: [MsgType; 3] = [MsgType::Add, MsgType::Del, MsgType::Add];

    /// Construit la transaction complète pour ce jeu de règles.
    ///
    /// Ne touche à rien : en cas d'erreur de traduction, on renvoie `Err` sans
    /// avoir rien envoyé au kernel — la politique précédente reste en place, ce
    /// qui est le comportement fail-closed attendu.
    fn build_batch(&self, rs: &Ruleset) -> Result<Batch> {
        let mut batch = Batch::new();
        let table = Table::new(ProtocolFamily::Inet).with_name(self.table_name.clone());

        // Remplacement atomique : retrait de l'ancienne table et recréation dans
        // la même transaction.
        //
        // Le premier `Add` n'est pas redondant. Contrairement à ce qu'on
        // pourrait attendre, le noyau ne tolère pas un `Del` sur une table
        // absente : il répond `ENOENT` et **rejette la transaction entière**.
        // Sur une machine où `inet helios` n'a jamais existé — donc à tout
        // premier démarrage — le pare-feu ne s'appliquait pas et heliosd
        // s'arrêtait sur « application du pare-feu ».
        //
        // L'idiome nftables consiste à garantir l'existence de la table avant
        // de la supprimer : `Add` (no-op si présente), `Del` (désormais sûr),
        // puis `Add` pour repartir d'une table vide.
        for msg in Self::SEQUENCE_TABLE {
            batch.add(&table, msg);
        }

        let policy = match rs.default_verdict {
            Verdict::Drop => ChainPolicy::Drop,
            Verdict::Accept => ChainPolicy::Accept,
        };

        for kind in [ChainKind::Input, ChainKind::Forward, ChainKind::Output] {
            let chain = Chain::new(&table)
                .with_name(kind.as_str())
                .with_hook(Hook::new(Self::hook_class(kind), 0))
                .with_policy(policy)
                .add_to_batch(&mut batch);

            for rule in rs.chain(kind) {
                for matches in Self::expand_port_sets(&rule.matches) {
                    let mut nf = NfRule::new(&chain).map_err(Self::err)?;
                    for m in &matches {
                        nf = Self::apply_match(nf, m)?;
                    }
                    nf = match rule.verdict {
                        Verdict::Accept => nf.accept(),
                        Verdict::Drop => nf.drop(),
                    };
                    nf.add_to_batch(&mut batch);
                }
            }
        }

        // ── Masquerade des clients du tunnel ─────────────────────────────────
        // Chaîne d'un autre type (`nat`) et d'un autre hook (`postrouting`), donc
        // hors de la boucle ci-dessus. Elle vit dans la **même** transaction :
        // le NAT et le filtrage doivent apparaître et disparaître ensemble, sinon
        // il existe un instant où l'un protège sans l'autre.
        //
        // Priorité 100 (`NF_IP_PRI_NAT_SRC`) : c'est la place attendue d'un
        // source-NAT, après le filtrage.
        if let Some(out_iface) = &rs.masquerade_out {
            let chain = Chain::new(&table)
                .with_name("postrouting")
                .with_hook(Hook::new(HookClass::PostRouting, 100))
                .with_type(ChainType::Nat)
                // Pas de politique par défaut sur une chaîne NAT : elle ne rend
                // pas de verdict de filtrage, elle réécrit ou laisse passer.
                .add_to_batch(&mut batch);

            NfRule::new(&chain)
                .map_err(Self::err)?
                .oiface(out_iface)
                .map_err(Self::err)?
                .with_expr(Masquerade::default())
                .add_to_batch(&mut batch);
        }

        Ok(batch)
    }

    fn commit(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        let rs = render(policy, state);

        if let Some(mss) = rs.mss_clamp {
            warn!(
                "MSS clamping ({mss} octets) non appliqué : action de mangle non exprimable \
                 via rustables. Optimisation de performance, aucune brèche de sécurité."
            );
        }

        let batch = self.build_batch(&rs)?;
        batch.send().map_err(|e| {
            Self::err(format!(
                "transaction Netlink refusée (table {} inchangée) : {e}",
                self.table_name
            ))
        })?;

        info!(
            "table inet {} appliquée — politique {:?}, {} règle(s), état {:?}",
            self.table_name,
            rs.default_verdict,
            rs.rules.len(),
            state
        );
        Ok(())
    }
}

impl Default for NetlinkBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallBackend for NetlinkBackend {
    async fn apply(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        self.commit(policy, state)
    }

    async fn teardown(&self) -> Result<()> {
        // Le kill-switch est laissé **engagé** à l'arrêt : on ne supprime jamais
        // la table (invariant fail-closed). Cette méthode n'existe que pour la
        // symétrie du trait.
        warn!(
            "teardown ignoré : la table inet {} est laissée en place (fail-closed)",
            self.table_name
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_ensembles_de_ports_sont_eclates() {
        let matches = vec![
            Match::OutIface("eth0".into()),
            Match::DestPortSet {
                ports: vec![80, 443],
                proto: L4::Tcp,
            },
        ];
        let expanded = NetlinkBackend::expand_port_sets(&matches);
        assert_eq!(expanded.len(), 2);
        assert!(expanded[0].contains(&Match::DestPort {
            port: 80,
            proto: L4::Tcp
        }));
        assert!(expanded[1].contains(&Match::DestPort {
            port: 443,
            proto: L4::Tcp
        }));
        // Les autres critères sont préservés dans chaque règle produite.
        assert!(expanded[0].contains(&Match::OutIface("eth0".into())));
    }

    #[test]
    fn la_table_est_creee_avant_d_etre_supprimee() {
        // Non-régression : `Del` d'abord échouait en `ENOENT` sur une machine
        // où `inet helios` n'avait jamais existé, et le noyau rejetait toute
        // la transaction — aucun kill-switch posé, démarrage impossible.
        let seq = NetlinkBackend::SEQUENCE_TABLE;
        assert_eq!(seq[0], MsgType::Add, "la table doit exister avant le Del");
        let del = seq
            .iter()
            .position(|m| *m == MsgType::Del)
            .expect("un Del est attendu");
        assert!(del > 0, "aucun Add ne précède le Del");
        assert_eq!(
            seq[del + 1],
            MsgType::Add,
            "la table doit être recréée après le Del"
        );
    }

    #[test]
    fn un_jeu_sans_ensemble_reste_intact() {
        let matches = vec![Match::InIface("lo".into())];
        assert_eq!(NetlinkBackend::expand_port_sets(&matches), vec![matches]);
    }

    #[test]
    fn parsing_des_adresses() {
        assert!(ipnetwork::IpNetwork::from_str("10.0.0.0/8").is_ok());
        assert!(IpAddr::from_str("203.0.113.10").is_ok());
        assert!(ipnetwork::IpNetwork::from_str("pas-un-cidr").is_err());
    }
}

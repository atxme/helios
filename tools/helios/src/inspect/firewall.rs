//! The nftables ruleset heliosd renders, read back in plain words.
//!
//! `/firewall --raw` keeps the exact text; this view is for reading what
//! the gateway lets in and out. Rules that differ in a single respect (one
//! per uplink, TCP and UDP of the same port) become one line, and the
//! ruleset's own comment says why.

use crate::ui::{clean, Tone, Ui};

use super::FirewallView;

/// One rule, translated into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    verdict: String,
    /// Protocols, ports, states — what the rule is about.
    what: Vec<String>,
    from: Vec<String>,
    to: Vec<String>,
    /// Ingress interfaces (`iifname`), read as "on".
    inbound: Vec<String>,
    /// Egress interfaces (`oifname`), read as "via".
    outbound: Vec<String>,
    comment: String,
}

impl Rule {
    /// The parts that may be merged, in a fixed order.
    fn parts(&self) -> [&Vec<String>; 5] {
        [
            &self.what,
            &self.from,
            &self.to,
            &self.inbound,
            &self.outbound,
        ]
    }

    fn parts_mut(&mut self) -> [&mut Vec<String>; 5] {
        [
            &mut self.what,
            &mut self.from,
            &mut self.to,
            &mut self.inbound,
            &mut self.outbound,
        ]
    }

    /// Same meaning in every respect but at most one part: that part's
    /// values are unioned. Anything else is kept apart.
    fn absorb(&mut self, other: &Rule) -> bool {
        if self.verdict != other.verdict || self.comment != other.comment {
            return false;
        }
        let differing: Vec<usize> = (0..5)
            .filter(|&index| self.parts()[index] != other.parts()[index])
            .collect();
        match differing.as_slice() {
            [] => true,
            [index] if !self.parts()[*index].is_empty() && !other.parts()[*index].is_empty() => {
                let target = &mut self.parts_mut()[*index];
                for value in other.parts()[*index] {
                    if !target.contains(value) {
                        target.push(value.clone());
                    }
                }
                true
            }
            _ => false,
        }
    }

    fn sentence(&self) -> String {
        let mut text = describe_what(&self.what);
        if text.is_empty() {
            text = if self.from.is_empty() && self.to.is_empty() {
                let lo = ["lo".to_owned()];
                if (self.inbound == lo && self.outbound.is_empty())
                    || (self.outbound == lo && self.inbound.is_empty())
                {
                    return "loopback".to_owned();
                }
                "everything".to_owned()
            } else {
                "traffic".to_owned()
            };
        }
        if !self.from.is_empty() {
            text.push_str(&format!(" from {}", self.from.join(", ")));
        }
        if !self.to.is_empty() {
            text.push_str(&format!(" to {}", self.to.join(", ")));
        }
        if !self.inbound.is_empty() {
            text.push_str(&format!(" on {}", self.inbound.join(", ")));
        }
        if !self.outbound.is_empty() {
            text.push_str(&format!(" via {}", self.outbound.join(", ")));
        }
        text
    }
}

/// `TCP 5202` and `UDP 5202` read as `TCP/UDP 5202`.
fn describe_what(what: &[String]) -> String {
    if let [first, second] = what {
        if let (Some(port), Some(other)) = (first.strip_prefix("TCP "), second.strip_prefix("UDP "))
        {
            if port == other {
                return format!("TCP/UDP {port}");
            }
        }
    }
    what.join(", ")
}

struct Chain {
    name: String,
    policy: String,
    rules: Vec<Rule>,
}

const VERDICTS: &[&str] = &[
    "accept",
    "drop",
    "reject",
    "return",
    "masquerade",
    "snat",
    "dnat",
    "redirect",
];

fn unquote(value: &str) -> String {
    clean(value.trim_matches('"'))
}

fn host(value: &str) -> String {
    let value = unquote(value);
    value
        .strip_suffix("/32")
        .or_else(|| value.strip_suffix("/128"))
        .map_or(value.clone(), str::to_owned)
}

/// Reads the words of one nftables match. A word it does not know is kept
/// as is: nothing of the rule is ever hidden.
fn translate(verdict: &str, words: &[&str], comment: &str) -> Rule {
    let mut rule = Rule {
        verdict: verdict.to_owned(),
        what: Vec::new(),
        from: Vec::new(),
        to: Vec::new(),
        inbound: Vec::new(),
        outbound: Vec::new(),
        comment: comment.to_owned(),
    };
    let mut index = 0;
    // A value is one word, or a `{ a, b }` set.
    let value = |index: &mut usize| -> String {
        let Some(first) = words.get(*index) else {
            return String::new();
        };
        *index += 1;
        if *first != "{" {
            return clean(first);
        }
        let mut items = Vec::new();
        while let Some(word) = words.get(*index) {
            *index += 1;
            if *word == "}" {
                break;
            }
            items.push(clean(word.trim_end_matches(',')));
        }
        items.join(", ")
    };
    // Unknown words stay together as one phrase, in their order.
    let mut raw_run = false;
    while index < words.len() {
        let word = words[index];
        let next = words.get(index + 1).copied();
        index += 1;
        let continuing = raw_run;
        raw_run = false;
        match (word, next) {
            ("iifname", _) => rule.inbound.push(unquote(&value(&mut index))),
            ("oifname", _) => rule.outbound.push(unquote(&value(&mut index))),
            ("ip" | "ip6", Some("saddr")) => {
                index += 1;
                rule.from.push(host(&value(&mut index)));
            }
            ("ip" | "ip6", Some("daddr")) => {
                index += 1;
                rule.to.push(host(&value(&mut index)));
            }
            ("tcp" | "udp", Some("dport")) => {
                index += 1;
                rule.what
                    .push(format!("{} {}", word.to_uppercase(), value(&mut index)));
            }
            ("tcp" | "udp", Some("sport")) => {
                index += 1;
                rule.what.push(format!(
                    "{} from port {}",
                    word.to_uppercase(),
                    value(&mut index)
                ));
            }
            ("ct", Some("state")) => {
                index += 1;
                rule.what.push(match value(&mut index).as_str() {
                    "invalid" => "invalid connections".to_owned(),
                    "established,related" | "related,established" => {
                        "replies to existing connections".to_owned()
                    }
                    other => format!("connections in state {other}"),
                });
            }
            ("meta", Some("l4proto")) => {
                index += 1;
                rule.what.push(match value(&mut index).as_str() {
                    "icmp" => "ICMP".to_owned(),
                    "ipv6-icmp" => "ICMPv6".to_owned(),
                    other => other.to_uppercase(),
                });
            }
            ("meta", Some("mark")) => {
                index += 1;
                rule.what
                    .push(format!("traffic marked {}", value(&mut index)));
            }
            _ => {
                match rule.what.last_mut().filter(|_| continuing) {
                    Some(phrase) => {
                        phrase.push(' ');
                        phrase.push_str(&clean(word));
                    }
                    None => rule.what.push(clean(word)),
                }
                raw_run = true;
            }
        }
    }
    rule
}

fn parse(text: &str) -> Vec<Chain> {
    let mut chains: Vec<Chain> = Vec::new();
    for raw in text.lines() {
        let line = clean(raw);
        let line = line.trim();
        if line.is_empty() || line == "}" || line.starts_with("table ") {
            continue;
        }
        if let Some(name) = line.strip_prefix("chain ") {
            chains.push(Chain {
                name: name.trim_end_matches('{').trim().to_owned(),
                policy: String::new(),
                rules: Vec::new(),
            });
            continue;
        }
        let Some(chain) = chains.last_mut() else {
            continue;
        };
        if line.starts_with("type ") {
            if let Some(policy) = line.split("policy ").nth(1) {
                chain.policy = policy.trim_end_matches(';').trim().to_owned();
            }
            continue;
        }
        let (rule, comment) = match line.split_once("  # ") {
            Some((rule, comment)) => (rule.trim(), comment.trim()),
            None => (line, ""),
        };
        let mut words: Vec<&str> = rule.split_whitespace().collect();
        let verdict = match words.last() {
            Some(last) if VERDICTS.contains(last) => words.pop().unwrap_or_default(),
            _ => "",
        };
        words.retain(|word| *word != "counter");
        chain.rules.push(translate(verdict, &words, comment));
    }
    for chain in &mut chains {
        chain.rules = merge(std::mem::take(&mut chain.rules));
    }
    chains
}

/// Folds a rule into an earlier one when only one part differs. It may
/// reach back only across rules with the same verdict: moving it past a
/// rule with another verdict could change what the ruleset means.
fn merge(rules: Vec<Rule>) -> Vec<Rule> {
    let mut merged: Vec<Rule> = Vec::new();
    for rule in rules {
        let mut absorbed = false;
        for earlier in merged.iter_mut().rev() {
            if earlier.verdict != rule.verdict {
                break;
            }
            if earlier.absorb(&rule) {
                absorbed = true;
                break;
            }
        }
        if !absorbed {
            merged.push(rule);
        }
    }
    merged
}

fn chain_title(name: &str) -> &str {
    match name {
        "input" => "Incoming",
        "forward" => "Forwarded",
        "output" => "Outgoing",
        "prerouting" => "Before routing",
        "postrouting" => "After routing",
        other => other,
    }
}

pub fn render_firewall(ui: &Ui, view: &FirewallView) -> String {
    let chains = parse(&view.rules);
    let mode = if view.dry_run { " · dry-run" } else { "" };
    let mut out = ui.title(
        "Firewall",
        &format!(
            "default {}{mode} · what may enter, cross and leave the gateway",
            clean(&view.default_verdict)
        ),
    );
    for (index, chain) in chains.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let mut subtitle = Vec::new();
        if !chain.policy.is_empty() {
            subtitle.push(format!("otherwise {}", chain.policy));
        }
        subtitle.push(format!("{} rules", chain.rules.len()));
        out.push_str(&ui.section(chain_title(&chain.name), &subtitle.join(" · ")));
        for rule in &chain.rules {
            let (word, tone) = match rule.verdict.as_str() {
                "accept" => ("allow", Tone::Good),
                "drop" => ("drop", Tone::Bad),
                "reject" => ("reject", Tone::Bad),
                "" => ("", Tone::Dim),
                other => (other, Tone::Good),
            };
            out.push_str(&format!(
                "    {} {}\n",
                ui.paint(&format!("{word:<6}"), tone),
                ui.fit(&rule.sentence(), 11)
            ));
            if !rule.comment.is_empty() {
                out.push_str(&format!(
                    "           {}\n",
                    ui.paint(&ui.fit(&rule.comment, 11), Tone::Dim)
                ));
            }
        }
    }
    out.push('\n');
    out.push_str(&ui.note("/firewall --raw prints the exact nftables ruleset."));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn said(rule: &str) -> String {
        let words: Vec<&str> = rule.split_whitespace().collect();
        translate("accept", &words, "").sentence()
    }

    #[test]
    fn matches_read_as_sentences() {
        assert_eq!(said("ct state invalid"), "invalid connections");
        assert_eq!(
            said("ct state established,related"),
            "replies to existing connections"
        );
        assert_eq!(said("iifname \"lo\""), "loopback");
        assert_eq!(
            said("tcp dport 8080 iifname \"helios0\""),
            "TCP 8080 on helios0"
        );
        assert_eq!(said("tcp dport 8080"), "TCP 8080");
        assert_eq!(
            said("iifname \"astra0\" ip saddr 10.88.7.2/32 ip daddr 10.88.7.1/32 tcp dport 8444"),
            "TCP 8444 from 10.88.7.2 to 10.88.7.1 on astra0"
        );
        assert_eq!(
            said("iifname \"nordlynx\" ip saddr 100.70.36.212/32 tcp dport { 22, 49111 }"),
            "TCP 22, 49111 from 100.70.36.212 on nordlynx"
        );
        assert_eq!(
            said("iifname \"nordlynx\" ip saddr 100.70.36.212/32 ip daddr 10.0.0.0/8"),
            "traffic from 100.70.36.212 to 10.0.0.0/8 on nordlynx"
        );
        assert_eq!(
            said("oifname \"enp3s0\" udp sport 51820"),
            "UDP from port 51820 via enp3s0"
        );
        assert_eq!(
            said("oifname \"wlo1\" meta mark 0xe1f1"),
            "traffic marked 0xe1f1 via wlo1"
        );
        assert_eq!(said("fib daddr type local"), "fib daddr type local");
    }

    const RULESET: &str = "table inet helios {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state invalid counter drop  # invalid conntrack state: dropped before every opening
    tcp dport 8080 iifname \"helios0\" accept  # administration API: only via the tunnel interface
    tcp dport 8080 drop  # any other origin is refused
    iifname \"lo\" accept
    iifname \"enp3s0\" udp dport 51820 accept  # WireGuard listener
    iifname \"wlo1\" udp dport 51820 accept  # WireGuard listener
    iifname \"helios0\" meta l4proto icmp accept  # ping on the tunnel
    iifname \"helios0\" meta l4proto ipv6-icmp accept  # ping on the tunnel
    iifname \"helios0\" tcp dport 5202 accept  # iperf3 server
    iifname \"helios0\" udp dport 5202 accept  # iperf3 server
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    iifname \"nordlynx\" ip saddr 100.70.36.212/32 ip daddr 10.0.0.0/8 drop  # no local network
    iifname \"nordlynx\" ip saddr 100.70.36.212/32 ip daddr 192.168.0.0/16 drop  # no local network
    iifname \"nordlynx\" ip saddr 100.70.36.212/32 oifname \"enp3s0\" accept  # routed Meshnet peer
    iifname \"nordlynx\" ip saddr 100.70.36.212/32 oifname \"wlo1\" accept  # routed Meshnet peer
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oifname \"enp3s0\" udp dport 53 accept  # DNS
    oifname \"enp3s0\" udp dport 123 accept  # NTP
    oifname \"wlo1\" udp dport 53 accept  # DNS
    oifname \"wlo1\" udp dport 123 accept  # NTP
  }
}";

    fn view() -> FirewallView {
        FirewallView {
            rules: RULESET.into(),
            default_verdict: "drop".into(),
            dry_run: false,
        }
    }

    #[test]
    fn the_ruleset_reads_as_what_may_enter_and_leave() {
        let text = render_firewall(&Ui::plain(None), &view());
        assert!(
            text.contains("\n\n  Incoming  otherwise drop · 7 rules\n"),
            "{text}"
        );
        for expected in [
            "    drop   invalid connections\n           invalid conntrack state: dropped before every opening\n",
            "    allow  TCP 8080 on helios0\n           administration API: only via the tunnel interface\n",
            "    drop   TCP 8080\n",
            "    allow  loopback\n",
            "    allow  UDP 51820 on enp3s0, wlo1\n           WireGuard listener\n",
            "    allow  ICMP, ICMPv6 on helios0\n           ping on the tunnel\n",
            "    allow  TCP/UDP 5202 on helios0\n           iperf3 server\n",
            "    drop   traffic from 100.70.36.212 to 10.0.0.0/8, 192.168.0.0/16 on nordlynx\n",
            "    allow  UDP 53 via enp3s0, wlo1\n           DNS\n",
            "    allow  traffic from 100.70.36.212 on nordlynx via enp3s0, wlo1\n           routed Meshnet peer\n",
            "    allow  UDP 123 via enp3s0, wlo1\n           NTP\n",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
        assert!(
            !text.contains("iifname") && !text.contains("dport"),
            "{text}"
        );
        assert!(!text.contains("\n\n\n"), "{text}");
    }

    #[test]
    fn a_rule_never_moves_past_one_with_another_verdict() {
        let rules = "chain input {
    type filter hook input priority filter; policy drop;
    iifname \"a\" tcp dport 22 accept
    iifname \"a\" tcp dport 22 drop
    iifname \"b\" tcp dport 22 accept
  }";
        let text = render_firewall(
            &Ui::plain(None),
            &FirewallView {
                rules: rules.into(),
                default_verdict: "drop".into(),
                dry_run: false,
            },
        );
        assert!(
            text.contains("allow  TCP 22 on a\n    drop   TCP 22 on a\n    allow  TCP 22 on b\n"),
            "{text}"
        );
    }

    #[test]
    fn narrow_terminals_cut_lines_instead_of_wrapping_them() {
        let text = render_firewall(&Ui::plain(Some(40)), &view());
        assert!(text.lines().all(|line| line.chars().count() < 40), "{text}");
    }
}

//! The ruleset as applied, its reapplication, the captive portal and the split tunnel.

use super::*;

#[derive(Serialize)]
pub struct FirewallRulesResponse {
    pub rules: String,
    pub default_verdict: String,
    pub dry_run: bool,
}

#[derive(Deserialize)]
pub struct ApplyRulesRequest {
    pub rules: String,
}

#[derive(Deserialize)]
pub struct SplitTunnelRequest {
    pub cidrs: Vec<String>,
}

pub async fn firewall_rules_get(
    State(s): State<AppState>,
) -> Result<Json<FirewallRulesResponse>, (StatusCode, String)> {
    let state = *s.tunnel_state.read().await;
    let policy = s.policy.read().await;
    let rs = ruleset::render(&policy, state)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let verdict_str = rs.default_verdict.as_str();

    // Rendered faithfully to what the Netlink backend actually applies:
    // `prerouting` when it has rules, under its own `accept` policy, then
    // three hooked chains, each with the default policy.
    let mut lines = vec!["table inet helios {".to_string()];
    let prerouting = ruleset::ChainKind::Prerouting;
    if rs.chain(prerouting).next().is_some() {
        let name = prerouting.as_str();
        lines.push(format!("  chain {name} {{"));
        lines.push(format!(
            "    type filter hook {name} priority filter; policy accept;"
        ));
        for rule in rs.chain(prerouting) {
            match &rule.note {
                Some(note) => lines.push(format!("    {rule}  # {note}")),
                None => lines.push(format!("    {rule}")),
            }
        }
        lines.push("  }".to_string());
    }
    for kind in [
        ruleset::ChainKind::Input,
        ruleset::ChainKind::Forward,
        ruleset::ChainKind::Output,
    ] {
        let name = kind.as_str();
        lines.push(format!("  chain {name} {{"));
        lines.push(format!(
            "    type filter hook {name} priority filter; policy {verdict_str};"
        ));
        for rule in rs.chain(kind) {
            match &rule.note {
                Some(note) => lines.push(format!("    {rule}  # {note}")),
                None => lines.push(format!("    {rule}")),
            }
        }
        lines.push("  }".to_string());
    }
    if !rs.masquerade_out.is_empty() {
        lines.push("  chain postrouting {".to_string());
        lines.push("    type nat hook postrouting priority srcnat;".to_string());
        for rule in rs.masquerade_rules() {
            lines.push(format!("    {rule}  # tunnel clients' Internet egress"));
        }
        lines.push("  }".to_string());
    }
    let mss_clamps: Vec<_> = rs.mss_clamps().collect();
    if !mss_clamps.is_empty() {
        lines.push("  chain mss {".to_string());
        lines.push("    type filter hook forward priority mangle;".to_string());
        for (family, value) in mss_clamps {
            let family = match family {
                helios_firewall::ruleset::AddressFamily::Ipv4 => "ipv4",
                helios_firewall::ruleset::AddressFamily::Ipv6 => "ipv6",
            };
            for (iface_match, iface) in [
                ("iifname", rs.wg_iface.as_str()),
                ("oifname", rs.wg_iface.as_str()),
            ] {
                lines.push(format!(
                    "    {iface_match} \"{iface}\" meta nfproto {family} meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set {value}"
                ));
            }
        }
        lines.push("  }".to_string());
    }
    lines.push("}".to_string());

    Ok(Json(FirewallRulesResponse {
        rules: lines.join("\n"),
        default_verdict: verdict_str.to_string(),
        dry_run: s.dry_run,
    }))
}

pub async fn firewall_rules_apply(
    State(s): State<AppState>,
    Json(body): Json<ApplyRulesRequest>,
) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::ApplyFirewallRules(body.rules))
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    })
}

pub async fn captive_portal_release(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::AcknowledgeCaptivePortal)
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    })
}

/// Replaces the CIDRs that bypass the tunnel.
///
/// `OrchestratorCmd` has no reply channel, so this check is the refusal the
/// caller sees: each entry goes through the parser the ruleset compiler uses,
/// and one it would refuse is answered `400`, naming it, with nothing sent.
/// The orchestrator checks the resulting policy again before applying it.
pub async fn split_tunnel_set(
    State(s): State<AppState>,
    Json(body): Json<SplitTunnelRequest>,
) -> Result<Json<CmdResponse>, (StatusCode, String)> {
    for cidr in &body.cidrs {
        ruleset::parse_network(cidr).map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                format!("split-tunnel CIDR refused: {error}"),
            )
        })?;
    }

    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::SetSplitTunnel(body.cidrs))
        .await
        .is_ok();
    Ok(Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    }))
}

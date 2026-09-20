# Firewall v2 — audit, modèle et validation

Ce document décrit l’état courant du chantier Firewall v2. Il complète
`ARCHITECTURE.md` et l’ADR-001 sans modifier leurs invariants : la policy est
compilée vers une IR structurée, puis le backend Netlink construit une unique
transaction atomique. Le texte affiché par le dry-run et l’API reste une vue de
debug ; il n’est jamais reparsé pour produire les règles noyau.

## Pipeline et responsabilités

```text
aether::FirewallPolicy + TunnelState
                 ↓
helios_firewall::ruleset::render
                 ↓
Result<Ruleset { Rule { Match, Action, Verdict }, NAT, MSS }>
                 ↓
DryRunBackend / vue API     NetlinkBackend
                                 ↓
                    rustables::Batch unique
                                 ↓
                         nf_tables noyau
```

`FirewallPolicy` exprime l’intention opérateur. Les modules voisins de
`ruleset.rs` compilent chaque capacité sans appeler le noyau. `Ruleset` est la
source de vérité. `NetlinkBackend::build_batch` traduit la totalité du modèle
avant tout envoi ; une primitive non traduisible annule la construction. Le
backend n’ajoute aucune règle absente de l’IR.

Les nouveaux concepts structurés sont :

- `ConnectionState` et `ConnectionStates`, sans ensemble vide ou bit inconnu ;
- `AddressFamily`, utilisé pour distinguer ICMPv4 et ICMPv6 ;
- `Action`, distinct du `Verdict`, avec compteur, log et limite de débit ;
- `RateLimit`, dont débit et burst sont nécessairement non nuls ;
- `Counter::Anonymous` et `Counter::Named`, sans conversion silencieuse entre
  les deux.
- `IpNetwork` dans `SourceNet` et `DestNet` : une adresse invalide est refusée
  pendant la compilation de la policy et ne peut pas entrer dans l’IR.

## Cartographie de la policy jusqu’au Netlink

| Champ `FirewallPolicy` | Compilation | IR | Traduction Netlink |
| --- | --- | --- | --- |
| `wan_ifaces` | `transport`, `gateway_wan`, `meshnet`, `kill_switch` | `InIface` / `OutIface` | `Meta(IifName/OifName)` + `Cmp` |
| `lan_ifaces` | `kill_switch`, `meshnet` | `InIface` / `OutIface` | `Meta` + `Cmp` |
| `wg_peers` | `transport::site_to_site_peers` | `DestNet`, UDP dport | famille réseau + `Payload` + `Cmp` |
| `wg_listen_port` | `transport::wireguard_listener` | interface, UDP dport/sport | `Meta`, `Payload`, `Cmp` |
| `key_negotiation_port` | `transport::key_negotiation_listener` | interface, UDP dport/sport | `Meta`, `Payload`, `Cmp` |
| `mode` | `render` | `Ruleset::default_verdict` | `ChainPolicy` des trois chaînes |
| `allow_ssh_from` | `administration::ssh_sources` | `SourceNet`, TCP dport 22 | famille réseau + `Payload` + `Cmp` |
| `admin_ifaces` | `administration::out_of_band_admin_ifaces` | `InIface`, TCP dport 22 | `Meta`, `Payload`, `Cmp` |
| `allow_dhcp_on_wan` | `gateway_wan::dhcp_lease_renewal` | interface, UDP 67/68 | `Meta`, `Payload`, `Cmp` |
| `allow_client_internet` | `kill_switch::state_gated_openings` | forward WG → WAN + `masquerade_out` | règle filter + chaîne NAT/`Masquerade` |
| `allow_tunnel_icmp` | `tunnel_interface::openings` | deux `Icmp(AddressFamily)` | `Meta(L4Proto)` + `Cmp` 1 ou 58 |
| `allow_gateway_egress` | `gateway_wan::gateway_own_egress` | ports DNS/NTP/HTTP(S) sur WAN | `Meta`, `Payload`, `Cmp` |
| `allow_ssh_over_tunnel` | `tunnel_interface::openings` | interface WG, TCP dport 22 | `Meta`, `Payload`, `Cmp` |
| `iperf_port` | `tunnel_interface::openings` | TCP/UDP input et output | `Meta`, `Payload`, `Cmp` |
| `wg_iface` | plusieurs modules | `InIface` / `OutIface` | `Meta` + `Cmp` |
| `admin_port`, `admin_iface` | `administration::admin_api` | accept borné puis drop générique | règles ordonnées dans `input` |
| `split_tunnel_cidrs` | `kill_switch::state_gated_openings` | `DestNet` | famille réseau + masque + `Cmp` |
| `mss_clamp` | policy runtime, acceptée seulement si le backend l’annonce | `Ruleset::mss_clamp` si trafic autorisé | capacité non annoncée par Netlink ; refus défensif avant envoi |
| `captive_portal_gateway` | `kill_switch::state_gated_openings` | WAN, destination, TCP 80/443 | `Meta`, famille réseau, `Payload`, `Cmp` |
| `nordvpn_meshnet` | `meshnet::nordvpn_meshnet` | marque, interface, pairs, ports, ICMPv4 | `Meta`, famille réseau, `Payload`, `Cmp` |

Les invariants sans champ de configuration sont compilés directement :

| Invariant | IR | Netlink |
| --- | --- | --- |
| état conntrack invalide | première règle de chaque chaîne, `ConnectionStates::INVALID`, compteur inline, drop | `Conntrack(State)` + `Bitwise` + `Cmp` + `Counter` + verdict drop |
| retour de flux | `ESTABLISHED_RELATED`, accept | même triplet conntrack avec masque `0b110` |
| loopback | interface `lo`, accept | `Meta` + `Cmp` + verdict accept |
| canal Astra | tuples interface/source/destination/port fixes | expressions ordinaires de l’IR |
| NAT client | une interface par uplink, uniquement tunnel autorisé | chaîne `postrouting` dans le même `Batch` |

## Ordre des règles conntrack

`ct state invalid drop` est placé à la tête de `input`, `forward` et `output`.
Ce choix est plus strict qu’un placement après les ouvertures : un paquet
invalide ne peut pas être sauvé par l’acceptation spécifique de l’API, d’un
listener public ou d’une interface de tunnel. L’acceptation API bornée reste
avant l’acceptation générale `established,related`, afin qu’une connexion API
établie depuis une mauvaise interface continue d’être refusée. Les golden tests
verrouillent cet ordre complet.

## Capacités

| Capacité | État | Détail |
| --- | --- | --- |
| `ct state invalid drop` | **SUPPORTED** | IR typée, rendu déterministe, compteur inline, Netlink et ordre testés |
| rate limiting | **BLOCKED BY BACKEND** | IR complète ; `rustables 0.8.7` n’expose pas `limit`, donc traduction refusée |
| logging | **PARTIAL** | IR et expression Netlink disponibles ; aucune policy active sans limite anti-flood |
| compteurs inline | **SUPPORTED** | appliqués sur les drops invalides |
| compteurs nommés | **BLOCKED BY BACKEND** | identité conservée dans l’IR ; pas d’objet compteur ni `objref` dans `rustables` |
| ICMPv4 | **SUPPORTED** | famille explicite, règle tunnel et Meshnet, protocole Netlink 1 |
| ICMPv6 | **SUPPORTED** | famille explicite, règle tunnel, protocole Netlink 58 ; pas d’IPAM IPv6 ajouté |
| types ICMP | **PARTIAL** | protocole seulement ; pas encore de primitive de type commune aux deux familles |
| adresses IPv4/IPv6 | **SUPPORTED** | `SourceNet`/`DestNet` portent des `IpNetwork` validés ; le backend n’analyse plus de texte |
| MSS clamp | **BLOCKED BY BACKEND** | `exthdr`/écriture d’option TCP absents ; Netlink n’annonce pas la capacité, donc la sonde conserve la mesure mais ne modifie pas la policy ; une IR construite directement avec un clamp reste refusée avant envoi |
| anti-spoof `fib` | **BLOCKED BY BACKEND** | expression absente et sémantique de routage à borner avant activation |
| NAT/masquerade | **SUPPORTED** | comportement existant conservé dans la transaction atomique |
| remplacement atomique | **SUPPORTED** | `Add → Del → Add`, chaînes filter et NAT, un seul `Batch::send` |

## Audit de `rustables 0.8.7`

La version verrouillée expose les expressions `bitwise`, `cmp`, `ct`, compteur
inline, `immediate`, log, lookup, masquerade, meta, NAT, payload et reject. Cela
couvre les règles actuelles, les états conntrack, ICMP par numéro de protocole,
les compteurs inline et le logging.

Elle ne modélise pas :

- `limit`, nécessaire au rate limiting et au logging borné ;
- `fib`, nécessaire à un anti-spoof fondé sur le routage ;
- les objets compteurs nommés et l’expression `objref` ;
- `exthdr`, nécessaire pour localiser puis modifier l’option TCP MSS.

Les constantes UAPI générées existent, car le noyau sait représenter ces
expressions. Cela ne suffit pas : `ExpressionVariant` est fermé,
`RawExpression` ne permet pas de choisir un nom d’expression et le module de
sérialisation Netlink est privé. Une crate consommatrice ne peut donc pas
ajouter proprement une expression manquante.

État amont vérifié le 20 septembre 2026 : le
[projet GitLab](https://gitlab.com/rustwall/rustables) reste la source déclarée
et [`rustables 0.8.8`](https://docs.rs/crate/rustables/0.8.8) a été publié le
23 juin 2026. Le projet est donc encore publié, avec une cadence faible ; cette
seule publication ne justifie ni une montée de version ni un fork. L’audit de
capacités ci-dessus reste celui de la `0.8.7` verrouillée par Helios.

Les options techniques disponibles si un besoin bloquant apparaît sont, par
ordre de proximité avec l’existant :

1. contribuer ou maintenir un petit fork de `rustables` ajoutant `limit`,
   `fib`, `objref`/objets et `exthdr`, avec tests d’octets et tests noyau ;
2. évaluer un backend Netlink Rust plus complet, en reprouvant l’atomicité,
   les politiques de chaîne, NAT et chaque expression ;
3. évaluer `nftnl`/`libnftnl`, au prix d’une dépendance C et d’un nouvel
   adaptateur bas niveau.

La génération de commandes `nft`, le reparsing de texte et l’API JSON pilotée
par un processus externe ne sont pas des solutions acceptées pour Helios.

Helios ne maintient pas de fork dans ce lot. `fib` reste différé par sa
sémantique multi-uplink/policy-routing, les compteurs inline couvrent le besoin
actuel sans `objref`, et le MSS clamp est une optimisation de performance dont
l’absence n’ouvre pas de faille. Le déclencheur retenu pour réévaluer un fork
est une exigence de rate limiting, notamment avant d’activer le logging en
production. À ce moment-là, l’état de maintenance amont de `rustables` devra
être revérifié avant de choisir entre contribution, fork ou autre backend.

## Anti-spoofing et routage

Une règle générale du type `fib saddr . iif oif missing drop` n’est pas activée.
Helios combine plusieurs uplinks, du policy routing, WireGuard, NordVPN Meshnet
et éventuellement Tailscale. Une recherche FIB dans la mauvaise table peut
classer comme usurpé un paquet valide d’un overlay ou d’un retour asymétrique.

L’activation exige au minimum :

- un scope explicite par interface WAN, sans appliquer la règle aux overlays ;
- une décision documentée sur les marques et tables de policy routing ;
- des essais de retour asymétrique et de bascule multi-uplink ;
- des essais WireGuard, Meshnet et Tailscale sur la cible ;
- une expression `fib` réellement encodée par le backend.

Tant que ces conditions ne sont pas réunies, différer la règle évite une
régression de disponibilité sans prétendre fournir une protection absente.

## Validation sur cible Linux

Ces essais nécessitent une gateway de laboratoire avec accès console. Ils ne
doivent pas être lancés sur une appliance de production.

### Préparation

```bash
cargo build -p heliosd --features netlink
sudo ./target/debug/heliosd run
sudo nft -a list table inet helios
```

Assertions initiales :

```bash
sudo nft list chain inet helios input
sudo nft list chain inet helios forward
sudo nft list chain inet helios output
sudo nft list chain inet helios postrouting
```

- chaque chaîne filter commence par `ct state invalid counter drop` ;
- `ct state established,related accept` est présent après ce drop ;
- `icmp` et `ipv6-icmp` sont deux règles distinctes sur l’interface Helios
  lorsque `allow_tunnel_icmp` est actif ;
- le masquerade n’existe que lorsque le tunnel autorise le trafic client, avec
  une règle par uplink déclaré.

### Compteur invalide

Depuis un hôte de test relié à l’interface concernée, envoyer un flux que
conntrack classe réellement `invalid` (par exemple un paquet TCP forgé hors
fenêtre dans une connexion contrôlée), puis comparer :

```bash
sudo nft reset counters table inet helios
sudo nft list chain inet helios input
# émission du paquet invalide depuis l’hôte de test
sudo nft list chain inet helios input
```

Le compteur de la première règle augmente et aucun listener Helios ne reçoit le
paquet. Un simple paquet SYN+FIN ne constitue pas une preuve suffisante : il
faut confirmer sa classification avec conntrack ou la trace nftables.

### ICMP et ICMPv6

Avec un pair WireGuard de test :

```bash
ping -I helios0 <adresse-v4-gateway>
ping -6 -I helios0 <adresse-v6-gateway>
sudo nft list chain inet helios input
```

Le test IPv6 n’est applicable que si une adresse IPv6 a été posée manuellement
pour la campagne ; Firewall v2 n’ajoute ni IPAM IPv6 ni adressage WireGuard
IPv6. Vérifier qu’aucune règle ICMP tunnel n’apparaît sur une interface WAN.

### Atomicité

Faire alterner plusieurs fois `Down` et `Up` tout en maintenant un flux témoin
et un `nft monitor`, puis vérifier :

- aucune table partielle n’est observable ;
- le NAT apparaît et disparaît dans la même transition que les ouvertures
  filter ;
- un échec de traduction provoqué en environnement de développement conserve
  le ruleset précédent ;
- aucune application règle par règle n’apparaît dans la trace.

### Capacités non validables dans ce lot

Le rate limiting, les compteurs nommés, l’anti-spoof `fib` et le MSS clamp ne
doivent pas être marqués comme validés sur cible : le backend ne les annonce
pas ou les refuse encore. Vérifier en revanche qu’une sonde MTU réussie avec le
backend Netlink journalise une seule fois l’absence de clamping, laisse
`mss_clamp` vide et ne coupe pas la connexion. Le logging est encodable, mais
aucune policy de production ne l’active avant de disposer d’un rate limit qui
empêche le log flood.

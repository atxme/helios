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
- `AddressFamily`, utilisé pour distinguer ICMPv4 et ICMPv6, et par
  `Match::Family`, garde `meta nfproto` d’une règle qui ne nomme aucune
  adresse ;
- `Icmpv6Type`, énumération fermée des messages ICMPv6 que Helios ouvre (ND,
  découverte de routeur, MLD), portée par `Match::Icmpv6Type` : un type absent
  de l’énumération, Redirect (137) en tête, n’est pas représentable ;
- `Match::Ipv6HopLimit`, dont la garde `meta nfproto ipv6` fait partie de la
  traduction : une lecture du hop limit sans garde n’est pas représentable ;
- `MasqueradeRule`, dérivée de `Ruleset::masquerade_out` par
  `Ruleset::masquerade_rules` : seule source des règles NAT, traduite par le
  backend et affichée par le dry-run, l’API et les golden tests ;
- `Action`, distinct du `Verdict`, avec compteur, log et limite de débit ;
- `RateLimit`, dont débit et burst sont nécessairement non nuls ;
- `Counter::Anonymous` et `Counter::Named`, sans conversion silencieuse entre
  les deux.
- `IpNetwork` dans `SourceNet` et `DestNet` : une adresse invalide est refusée
  pendant la compilation de la policy et ne peut pas entrer dans l’IR.

## Cartographie de la policy jusqu’au Netlink

| Champ `FirewallPolicy` | Compilation | IR | Traduction Netlink |
| --- | --- | --- | --- |
| `wan_ifaces` | `transport`, `gateway_wan`, `link_ipv6`, `meshnet`, `kill_switch` | `InIface` / `OutIface` | `Meta(IifName/OifName)` + `Cmp` |
| `lan_ifaces` | `link_ipv6`, `kill_switch`, `meshnet` | `InIface` / `OutIface` | `Meta` + `Cmp` |
| `wg_peers` | `transport::site_to_site_peers` | `DestNet`, UDP dport | famille réseau + `Payload` + `Cmp` |
| `wg_listen_port` | `transport::wireguard_listener` | interface, UDP dport/sport | `Meta`, `Payload`, `Cmp` |
| `key_negotiation_port` | `transport::key_negotiation_listener` | interface, UDP dport/sport | `Meta`, `Payload`, `Cmp` |
| `mode` | `render` | `Ruleset::default_verdict` | `ChainPolicy` des trois chaînes |
| `allow_ssh_from` | `administration::ssh_sources` | `SourceNet`, TCP dport 22 | famille réseau + `Payload` + `Cmp` |
| `admin_ifaces` | `administration::out_of_band_admin_ifaces` | `InIface`, TCP dport 22 | `Meta`, `Payload`, `Cmp` |
| `allow_dhcp_on_wan` | `gateway_wan::dhcp_lease_renewal` | DHCPv4 : interface, UDP 67/68, sans famille ; DHCPv6 : interface, `Family(Ipv6)`, UDP 547 en sortie et 546 en entrée | `Meta`, `Payload`, `Cmp` ; pour DHCPv6, `Meta(NfProto)` + `Cmp` 10 avant le port |
| `allow_client_internet` | `kill_switch::state_gated_openings` | forward `Family(Ipv4)` WG → WAN + `masquerade_out`, rendu en `MasqueradeRule` `Family(Ipv4)` + `OutIface` | `Meta(NfProto)` + `Cmp` 2 en tête de la règle filter et de la règle NAT, puis `Masquerade` |
| `allow_tunnel_icmp` | `tunnel_interface::openings` | deux `Icmp(AddressFamily)` | `Meta(L4Proto)` + `Cmp` 1 ou 58 |
| `allow_gateway_egress` | `gateway_wan::gateway_own_egress` | ports DNS/NTP/HTTP(S) sur WAN | `Meta`, `Payload`, `Cmp` |
| `allow_ssh_over_tunnel` | `tunnel_interface::openings` | interface WG, TCP dport 22 | `Meta`, `Payload`, `Cmp` |
| `iperf_port` | `tunnel_interface::openings` | TCP/UDP input et output | `Meta`, `Payload`, `Cmp` |
| `wg_iface` | plusieurs modules | `InIface` / `OutIface` | `Meta` + `Cmp` |
| `admin_port`, `admin_iface` | `administration::admin_api` | accept borné puis drop générique | règles ordonnées dans `input` |
| `split_tunnel_cidrs` | `kill_switch::state_gated_openings` | `DestNet` | famille réseau + masque + `Cmp` |
| `mss_clamp` | policy runtime, acceptée seulement si le backend l’annonce | `Ruleset::mss_clamp` si trafic autorisé | capacité non annoncée par Netlink ; refus défensif avant envoi |
| `captive_portal_gateway` | `kill_switch::state_gated_openings` | WAN, destination, TCP 80/443 | `Meta`, famille réseau, `Payload`, `Cmp` |
| `nordvpn_meshnet` | `meshnet::nordvpn_meshnet` | marque, interface, pairs, ports ; `Icmp` et drops des réseaux locaux de la famille du pair (`PRIVATE_IPV4_CIDRS` ou `PRIVATE_IPV6_CIDRS`) avant ses accepts | `Meta`, famille réseau, `Payload`, `Cmp` |

Les invariants sans champ de configuration sont compilés directement :

| Invariant | IR | Netlink |
| --- | --- | --- |
| état conntrack invalide | première règle de chaque chaîne, `ConnectionStates::INVALID`, compteur inline, drop | `Conntrack(State)` + `Bitwise` + `Cmp` + `Counter` + verdict drop |
| retour de flux | `ESTABLISHED_RELATED`, accept | même triplet conntrack avec masque `0b110` |
| loopback | interface `lo`, accept | `Meta` + `Cmp` + verdict accept |
| canal Astra | tuples interface/source/destination/port fixes | expressions ordinaires de l’IR |
| ND IPv6, tous états | `link_ipv6::link_control` : sur chaque WAN et LAN, `input` et `output`, `Icmpv6Type` NS (135) / NA (136) + `Ipv6HopLimit(255)`, accept | `Meta(L4Proto)` + `Cmp` 58, `Payload` transport 0/1 + `Cmp` type, `Meta(NfProto)` + `Cmp` 10, `Payload` réseau 7/1 + `Cmp` 255 |
| découverte de routeur, tous états | sur chaque WAN seulement : RS (133) en `output`, RA (134) en `input`, `Ipv6HopLimit(255)` ; aucune sur un WAN qui tient aussi un autre rôle | mêmes expressions que ND |
| MLD, tous états | sur chaque WAN et LAN, `input` et `output`, `Family(Ipv6)` + `Icmpv6Type` 130, 131, 132, 143 | `Meta(NfProto)` + `Cmp` 10, `Meta(L4Proto)` + `Cmp` 58, `Payload` transport 0/1 + `Cmp` type |
| NAT client | une interface par uplink, garde `meta nfproto ipv4`, uniquement tunnel autorisé | chaîne `postrouting` dans le même `Batch` |

## Ordre des règles conntrack

`ct state invalid drop` est placé à la tête de `input`, `forward` et `output`.
Ce choix est plus strict qu’un placement après les ouvertures : un paquet
invalide ne peut pas être sauvé par l’acceptation spécifique de l’API, d’un
listener public ou d’une interface de tunnel. L’acceptation API bornée reste
avant l’acceptation générale `established,related`, afin qu’une connexion API
établie depuis une mauvaise interface continue d’être refusée. Les golden tests
verrouillent cet ordre complet.

## Aucun relais IPv6 des clients du tunnel

La table est de famille `inet` : une règle qui ne nomme aucune adresse
s’applique à IPv4 et à IPv6. Deux règles de la sortie Internet des clients
(`allow_client_internet`) sont dans ce cas et portent donc la garde
`meta nfproto ipv4` (`ADRESSAGE-IPV6.md` §6.4) :

- le `forward` de `wg_iface` vers chaque WAN, sans quoi l’activation de
  `net.ipv6.conf.all.forwarding` relaierait l’IPv6 d’un client ;
- le masquerade de `postrouting`, sans quoi le premier paquet IPv6 relayé serait
  NAT66-é.

Les uplinks masqués et les états où le NAT existe sont inchangés. La garde du
masquerade n’est pas une donnée de `Ruleset::masquerade_out`, qui ne liste que
des uplinks : `Ruleset::masquerade_rules` l’ajoute, et un masquerade sans garde
ou IPv6 n’est pas représentable. Aujourd’hui les `AllowedIPs` IPv4 `/32` tiennent
déjà l’IPv6 hors de `helios0` ; la garde rend l’invariant explicite avant tout
VIP IPv6.

`ruleset/tests/ipv6_relay.rs` verrouille l’invariant pour chaque `TunnelState`,
`allow_client_internet` actif ou non, sur deux uplinks : toute règle `forward`
de `wg_iface` vers un WAN porte `Family(Ipv4)`, chaque masquerade commence par
cette garde, aucune règle `forward` ni aucun masquerade ne sélectionne l’IPv6
(`Family(Ipv6)`, `Icmpv6Type` ou `Ipv6HopLimit`), et les seules règles qui le
sélectionnent sont le contrôle des liens de la gateway, en `input` et `output`
sur ses interfaces WAN et LAN (section suivante). Le test sur `forward` doit
échouer le jour où la future spécification B ouvrira un relais IPv6
(`ETUDE-IPV6.md` §6.5). Le golden `UP_EVERY_CAPABILITY_OPEN` montre les deux
gardes et les tests du backend vérifient la paire `Meta(NfProto)` + `Cmp` 2
avant l’interface et le `Masquerade`.

Restent hors de ce lot et agnostiques à la famille : le `forward` LAN → WAN
site-to-site et, en portail captif sans passerelle connue, le `forward`
HTTP/HTTPS vers le WAN. Les contournements `split_tunnel_cidrs` et les règles
Meshnet nomment une adresse et reçoivent déjà la garde de sa famille. La
restriction du masquerade à `iifname wg_iface` reste une décision ouverte.

### Réseaux locaux Meshnet par famille

Un pair Meshnet routant sans la permission « réseau local » reçoit, avant ses
accepts, un `drop` vers chaque réseau local **de sa propre famille** :
`PRIVATE_IPV4_CIDRS` (`10.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`,
`192.168.0.0/16`) pour un pair IPv4, `PRIVATE_IPV6_CIDRS` (`fc00::/7`,
`fe80::/10`) pour un pair IPv6. Un drop qui associerait une source IPv6 à une
destination IPv4 ne correspondrait à aucun paquet, et l’accept suivant ouvrirait
les réseaux locaux IPv6. L’ouverture ICMP suit de même la famille du pair
(`Icmp(Ipv4)` ou `Icmp(Ipv6)`). Le rendu IPv4 est inchangé, golden compris.

Ce chemin IPv6 n’est atteignable qu’en construisant la `FirewallPolicy` dans le
code : `aether` refuse toujours un CIDR Meshnet IPv6 (`valid_ipv4_cidr`), car
NordVPN attribue des adresses Meshnet IPv4. `ruleset/tests/meshnet_ipv6.rs`
couvre ces politiques hors du balayage de `ipv6_relay.rs`, qui porte sur ce
qu’une configuration validée produit ; le test Netlink correspondant vérifie la
traduction IPv6 des deux adresses, chacune derrière `meta nfproto ipv6`.

Limite connue : la liste IPv6 ne contient que les portées ULA et lien-local.
Un préfixe global sur le lien du WAN n’en fait pas partie, alors que son
équivalent IPv4 est le plus souvent RFC 1918 et donc refusé. Accepter des pairs
Meshnet IPv6 dans la configuration demande de trancher ce point et un essai sur
cible d’un pair routant en IPv6.

## Contrôle IPv6 des liens : ND, RA, MLD, DHCPv6

### Pourquoi ND exige des règles et ARP non

La table `inet` et la policy `drop` de ses chaînes s’appliquent à l’IPv6. En
IPv4, la résolution de voisins passe par ARP, qui n’est pas un paquet IP : une
table `inet` ne le voit pas, et la policy ne le bloque jamais. C’est pourquoi
l’IPv4 du WAN fonctionne sans règle dédiée. En IPv6, la résolution de voisins
(Neighbor Solicitation / Advertisement), la découverte de routeur (Router
Solicitation / Advertisement) et MLD sont des messages ICMPv6 : ils traversent
les chaînes filtrées. Conntrack ne les sauve pas : il les classe `untracked`,
ni `invalid` ni `established,related` (comportement noyau, à vérifier sur
cible). Sans règle explicite, un WAN qui obtient son IPv6 par SLAAC perd la
résolution de voisins, puis sa route par défaut IPv6 à l’expiration de la durée
de vie du dernier RA accepté.

### Ce qui est ouvert

Le module `ruleset/link_ipv6.rs` rend ces règles dans **tous** les
`TunnelState` et quel que soit `mode` : elles relèvent du fonctionnement du
lien, ne relaient rien, et doivent survivre au kill-switch comme le
renouvellement DHCPv4. Elles sont placées après les ouvertures de la gateway
sur le WAN, donc après `ct state invalid drop` en tête de chaîne, et ne sont
portées par aucun drapeau : sur une interface sans IPv6, elles ne
correspondent à rien.

| Messages | Chaînes | Interfaces | Garde réseau |
| --- | --- | --- | --- |
| NS (135), NA (136) | `input`, `output` | chaque WAN et chaque LAN | `ip6 hoplimit 255` |
| RS (133) | `output` | chaque WAN | `ip6 hoplimit 255` |
| RA (134) | `input` | chaque WAN | `ip6 hoplimit 255` |
| MLD query (130), report (131), done (132), MLDv2 report (143) | `input`, `output` | chaque WAN et chaque LAN | `meta nfproto ipv6` |
| DHCPv6 client, UDP 547 sortant / 546 entrant | `output` / `input` | chaque WAN, derrière `allow_dhcp_on_wan` | `meta nfproto ipv6` |

- **Portée par interface, jamais par adresse** : ND et MLD utilisent des
  sources link-local et des destinations multicast de portée lien, qui
  n’appartiennent à aucun réseau configuré.
- **Hop limit 255** : la RFC 4861 impose qu’un message ND arrive avec un hop
  limit de 255 et qu’un récepteur rejette tout autre. Un routeur décrémente ce
  champ ; 255 prouve donc que le paquet a été émis sur le lien, ce qui rend ND
  et la découverte de routeur infalsifiables depuis l’extérieur du lien. La
  règle l’exige aussi, pour ne rien accepter de plus large que ce qu’une pile
  conforme traiterait. La traduction Netlink place la garde
  `meta nfproto ipv6` devant la lecture du champ : dans une table `inet`, le
  même octet d’un en-tête IPv4 n’est pas un hop limit.
- **MLD** est émis avec un hop limit de 1 (RFC 2710, RFC 3810) et n’est pas
  comparé à 255 ; ses règles portent une garde `meta nfproto ipv6` explicite,
  puisque rien d’autre n’y fixe la famille réseau.
- **RA sur les WAN seulement** : la gateway est un hôte sur son uplink et un
  routeur partout ailleurs. Un RA accepté depuis `wg_iface`, un LAN,
  `admin_ifaces` ou l’interface Meshnet serait un RA rogue capable de lui
  imposer une route par défaut. Un WAN déclaré aussi dans l’un de ces rôles ne
  reçoit ni RS ni RA.
- **Aucune règle sur les overlays** (`wg_iface`, `admin_ifaces`, Meshnet) : ce
  sont des tunnels de niveau 3 sans adresse de lien, sur lesquels le noyau ne
  résout pas de voisins.
- **Aucune règle `forward`** : le trafic link-local n’est jamais routé, et la
  gateway ne relaie pas d’IPv6 (`ADRESSAGE-IPV6.md` §6.4).
- **DHCPv6** suit `allow_dhcp_on_wan` : le drapeau répond à « l’adresse du WAN
  vient-elle d’un bail ? », question indépendante de la famille. La paire
  DHCPv4 67/68 existante n’est pas modifiée et reste sans garde de famille.

### Ce qui reste fermé

- **Redirect (137)** n’est pas représentable dans `Icmpv6Type` : il tombe sur
  la policy `drop`.
- **Echo request / reply** sur le WAN, comme en IPv4.
- **Erreurs ICMPv6** (Destination Unreachable 1, Packet Too Big 2, Time
  Exceeded 3, Parameter Problem 4) : aucune ouverture inconditionnelle. Liées à
  un flux suivi, elles sont `related` et déjà acceptées par
  `ct state established,related`, Packet Too Big compris.

**Limitation connue, à vérifier sur cible** : un Packet Too Big qui concerne un
flux d’encapsulation que conntrack ne suit pas, ou plus (entrée UDP du
transport WireGuard expirée), n’est pas `related` et tombe sur la policy
`drop` ; la découverte de MTU de ce transport en IPv6 serait alors un trou
noir. Ce qui la lève : observer le cas sur une gateway à WAN IPv6, puis
décider une acceptation du type 2 scopée par interface (`ETUDE-IPV6.md` §9.1).

`ruleset/tests/link_ipv6.rs` balaie les deux `mode` et chaque `TunnelState`
sur deux uplinks, un LAN, le tunnel, un overlay d’administration et Meshnet ;
les golden tests montrent l’ordre complet et les tests du backend vérifient la
séquence exacte des expressions d’une règle NS.

## Capacités

| Capacité | État | Détail |
| --- | --- | --- |
| `ct state invalid drop` | **SUPPORTED** | IR typée, rendu déterministe, compteur inline, Netlink et ordre testés |
| rate limiting | **BLOCKED BY BACKEND** | IR complète ; `rustables 0.8.7` n’expose pas `limit`, donc traduction refusée |
| logging | **PARTIAL** | IR et expression Netlink disponibles ; aucune policy active sans limite anti-flood |
| compteurs inline | **SUPPORTED** | appliqués sur les drops invalides |
| compteurs nommés | **BLOCKED BY BACKEND** | identité conservée dans l’IR ; pas d’objet compteur ni `objref` dans `rustables` |
| ICMPv4 | **SUPPORTED** | famille explicite, règle tunnel et Meshnet, protocole Netlink 1 |
| ICMPv6 | **SUPPORTED** | famille explicite, règle tunnel et Meshnet (pair IPv6, politique construite dans le code), protocole Netlink 58 ; pas d’IPAM IPv6 ajouté |
| types ICMPv6 | **SUPPORTED** | `Match::Icmpv6Type`, énumération fermée (ND, RS/RA, MLD) ; `Meta(L4Proto)` + `Cmp` 58, `Payload` transport offset 0 longueur 1 + `Cmp` |
| types ICMPv4 | **PARTIAL** | protocole seulement ; l’API haut niveau de `rustables` n’expose pas l’octet de type ICMPv4 et aucun encodeur vérifié n’existe |
| hop limit IPv6 | **SUPPORTED** | `Match::Ipv6HopLimit`, garde `Meta(NfProto)` + `Cmp` 10 puis `Payload` réseau offset 7 longueur 1 + `Cmp` |
| adresses IPv4/IPv6 | **SUPPORTED** | `SourceNet`/`DestNet` portent des `IpNetwork` validés ; le backend n’analyse plus de texte |
| MSS clamp | **BLOCKED BY BACKEND** | `exthdr`/écriture d’option TCP absents ; Netlink n’annonce pas la capacité, donc la sonde conserve la mesure mais ne modifie pas la policy ; une IR construite directement avec un clamp reste refusée avant envoi. La valeur est le MSS IPv4 du tunnel (`aether::mtu::mss_ipv4`, MTU du tunnel − 40) : l’encodeur qui débloquera le clamp devra la garder par `meta nfproto ipv4`, l’IPv6 recevant `aether::mtu::mss_ipv6` (− 60) sous `meta nfproto ipv6` |
| anti-spoof `fib` | **BLOCKED BY BACKEND** | expression absente et sémantique de routage à borner avant activation |
| garde de famille `meta nfproto` | **SUPPORTED** | `Match::Family`, `Meta(NfProto)` + `Cmp` 2 ou 10, la même paire que `rustables` émet devant une adresse |
| NAT/masquerade | **SUPPORTED** | IPv4 seulement (`meta nfproto ipv4`), aucun NAT66 ; uplinks et conditions d’état inchangés, dans la transaction atomique |
| remplacement atomique | **SUPPORTED** | `Add → Del → Add`, chaînes filter et NAT, un seul `Batch::send` |

## Audit de `rustables 0.8.7`

La version verrouillée expose les expressions `bitwise`, `cmp`, `ct`, compteur
inline, `immediate`, log, lookup, masquerade, meta, NAT, payload et reject. Cela
couvre les règles actuelles, les états conntrack, ICMP par numéro de protocole,
le type ICMPv6 et le hop limit IPv6 (`HighLevelPayload`, champs
`ICMPv6HeaderField::Type` et `IPv6HeaderField::HopLimit`), les compteurs inline
et le logging.

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

### NAT et sortie client limités à IPv4

Tunnel `Up` et `allow_client_internet` actif :

```bash
sudo nft list chain inet helios postrouting
sudo nft list chain inet helios forward
```

- chaque règle de `postrouting` montre `meta nfproto ipv4 oifname "<wan>"
  masquerade`, une par uplink ;
- chaque règle `forward` depuis `helios0` vers un WAN montre `meta nfproto ipv4`
  avec `iifname "helios0" oifname "<wan>" accept` ;
- aucune règle `masquerade` ni `forward` depuis `helios0` n’apparaît sans cette
  garde.

L’ordre imprimé par `nft` est à vérifier sur cible : le batch place la garde
avant les interfaces, et le noyau devrait restituer cet ordre, mais seule une
lecture réelle le confirme. De même, vérifier que `nft` affiche bien la garde
seule, sans l’absorber comme dépendance implicite, puisque aucune adresse ne la
suit. Enfin, le NAT44 doit rester inchangé : depuis un client, `curl -4` vers
une destination Internet passe par la gateway et sort avec l’adresse de
l’uplink actif.

### Contrôle IPv6 du WAN (ND, RA, MLD, DHCPv6)

Gateway de laboratoire dont le WAN obtient une adresse IPv6 par SLAAC, policy
`drop`, tunnel `Down` puis `Up` :

```bash
sudo nft list chain inet helios input
sudo nft list chain inet helios output
sudo nft list chain inet helios forward
ip -6 addr show dev <wan>
ip -6 neigh show dev <wan>
ip -6 route show default
```

- `input` et `output` montrent, pour chaque WAN et LAN, les règles
  `icmpv6 type nd-neighbor-solicit` / `nd-neighbor-advert` avec
  `ip6 hoplimit 255`, et les quatre règles MLD avec `meta nfproto ipv6` ;
  `nd-router-advert` n’apparaît qu’en `input` sur un WAN, `nd-router-solicit`
  qu’en `output` sur un WAN ;
- `forward` ne contient aucune règle `icmpv6` ;
- `ip -6 neigh` est peuplé (routeur amont au moins `REACHABLE` ou `STALE`) ;
- la route par défaut IPv6 apparaît `proto ra` et **survit au-delà de la durée
  de vie du RA** (`router lifetime`, lisible avec `rdisc6 <wan>` ou dans
  `ip -6 route show default` via `expires`) : la noter, attendre plus que cette
  durée, vérifier que la route a été rafraîchie et non retirée ;
- avec `allow_dhcp_on_wan = true` et un serveur DHCPv6 en amont, les règles
  `meta nfproto ipv6 udp dport 547` (sortie) et `546` (entrée) sont présentes
  et le bail IPv6 se renouvelle.

À vérifier sur cible, sans conclusion possible depuis WSL :

- l’ordre d’impression par `nft` : le batch place l’ICMPv6 avant la garde du
  hop limit, et `nft` peut absorber la garde `meta nfproto ipv6` comme
  dépendance implicite de `ip6 hoplimit` dans son affichage ;
- la classification `untracked` des messages ND, RS/RA et MLD par conntrack
  (par exemple avec `conntrack -E` ou une trace `nft monitor trace`) ;
- le cas Packet Too Big hors flux suivi décrit dans la limitation connue
  ci-dessus.

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

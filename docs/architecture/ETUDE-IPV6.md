# Étude — support IPv6 dual-stack

Statut : **étude**, aucune décision acceptée. Ce document décrit l'état du
dépôt au 30 septembre 2026 (branche `feature/support-ipv6`,
commit `4a0d8ba`) et propose un plan. Il ne modifie aucun invariant d'ADR ; les
points qui en toucheraient un sont signalés comme décisions à prendre.

Convention : chaque affirmation renvoie à un fichier et un symbole. « À vérifier
sur cible » signifie que le comportement dépend du noyau ou de Windows et ne
peut pas être prouvé depuis WSL2 (voir `docs/testing/TESTING.md`).

---

## 1. Résumé exécutif

Helios est **IPv4-only par construction dans son plan d'adressage** (IPAM
CGNAT, VIP `/32`, identité API, routage VIP), mais **déjà largement
agnostique dans son plan de filtrage** : la table nftables est de famille
`inet`, l'IR du firewall porte des `IpNetwork` typés, et le backend Netlink
émet la garde `meta nfproto` correcte pour chaque adresse.

Trois constats dominent :

1. **Fuite IPv6 côté Orion, aujourd'hui, sans aucun changement Helios.** Le
   défaut `DEFAULT_ALLOWED_IPS = "0.0.0.0/0"` (`orion-core/src/config.rs:28`)
   et le preset `full` d'Orion (`apps/orion/src/splitTunnel.ts:49`) ne
   capturent pas `::/0`. Sur un poste dual-stack, tout le trafic IPv6 sort en
   clair hors tunnel. L'invariante de l'ADR-001 §3 bis (« le drop natif de
   WireGuard devient le kill-switch ») ne couvre que l'IPv4. C'est le premier
   ticket à traiter, indépendamment du reste.
2. **Le firewall gateway casserait l'IPv6 du WAN s'il en avait.** La politique
   `drop` des chaînes `inet` s'applique à IPv6, et aucune règle n'ouvre la
   Neighbor Discovery, les Router Advertisements, MLD ni DHCPv6 sur le WAN
   (`helios-firewall/src/ruleset/gateway_wan.rs`). Les messages ND sont
   `untracked` pour conntrack, donc ni `established` ni `related` ne les
   sauvent. Conséquence probable, à vérifier sur cible : une gateway qui
   obtient une adresse IPv6 sur son WAN perd la résolution de voisins, puis sa
   route par défaut IPv6 à l'expiration du RA.
3. **Le NAT est déjà implicitement dual-stack, sans l'avoir décidé.** Le
   masquerade est émis dans une chaîne `nat` de la table `inet`, filtré sur
   `oifname` seulement (`helios-firewall/src/netlink/transaction.rs:130`). Dès
   qu'un paquet IPv6 serait relayé vers le WAN, il serait NAT66-é. Aujourd'hui
   aucun paquet IPv6 n'entre par `helios0` (les `AllowedIPs` gateway sont des
   `/32` IPv4), mais le forward LAN→WAN est lui aussi agnostique.

Le chemin recommandé est **incrémental** : conserver le VIP IPv4 CGNAT comme
ancre d'identité et de contrôle, ajouter un VIP IPv6 ULA optionnel par pair,
généraliser les quelques types `String`/`Ipv4Addr` qui portent une adresse,
centraliser la logique de famille dans `helios-firewall` et `vip_routing`, et
traiter IPv6 en sortie Internet comme une **décision explicite** (blackhole par
défaut, NAT66 ou préfixe routé en opt-in).

---

## 2. État actuel du support IPv6

| Domaine | État | Justification |
| --- | --- | --- |
| IR firewall | **Prêt** | `Match::SourceNet/DestNet(IpNetwork)`, `AddressFamily` (`helios-firewall/src/ruleset/nftables.rs`) |
| Backend Netlink, adresses | **Prêt** | `match_net` → `rustables::Rule::snetwork/saddr`, qui émettent `meta nfproto ipv4/ipv6` avant le payload (`rustables-0.8.7/src/rule_methods.rs:46-107`) |
| Table nftables | **Prêt** | `Table::new(ProtocolFamily::Inet)` (`transaction.rs:56`) |
| ICMPv6 tunnel | **Partiel** | `Match::Icmp(Ipv6)` rendu sur `helios0` (`tunnel_interface.rs`), sans discrimination de type |
| ICMPv6 WAN (ND, RA, PTB, MLD) | **Absent** | aucune règle ; ND `untracked` → drop par la policy |
| Conntrack | **Prêt** | `ct state` est indépendant de la famille dans `inet` ; masque structuré (`expressions.rs::connection_states`) |
| NAT | **Implicite, non décidé** | masquerade `inet` sans `nfproto` |
| Anti-spoofing | **Absent (v4 et v6)** | `fib` non encodable (`FIREWALL-V2.md`) ; Helios ne règle pas `rp_filter` |
| Config `network.toml` | **IPv4 imposé** | `validate_peer_identities` exige `/32` IPv4 (`aether/src/config.rs:735`) ; `valid_ipv4_cidr` pour Meshnet (`:51`) |
| IPAM | **IPv4 only** | `CGNAT_BASE: u32`, `derive_cgnat_ip -> Ipv4Addr` (`helios-provisioning/src/ipam.rs:23,64`) |
| Routage VIP | **IPv4 only, documenté** | `vip_routing.rs` « Limite connue », `parse_cidr -> Ipv4Addr` |
| WireGuard gateway | **Partiel** | `defguard` générique, mais une seule adresse et un seul `AllowedIPs` par pair (`helios-wireguard/src/lib.rs:73,99`, `kernel.rs:71,115`) |
| WireGuard Orion | **Partiel** | endpoint `[v6]:port` validé, `AllowedIPs` multi-familles, mais adresse unique et défaut `0.0.0.0/0` |
| Négociation QUIC | **Partiel** | budget par `/64` prêt (`aether-key-negotiation/src/rate_limit.rs:15`) mais écoute `0.0.0.0` seulement (`heliosd/src/key_negotiation/server.rs:118`) |
| API | **Partiel** | `IpAddr` partout, mais correspondance `/32` par chaîne (`helios-api/src/auth.rs:122-131`) et bind formaté sans crochets (`aether/src/config.rs:1083,1096`) |
| DNS | **Faible** | premier résultat de `getaddrinfo`, deux résolutions indépendantes, DNS client non tunnelisé |
| MTU | **Partiel** | surcoût externe IPv6 déjà pris (`aether/src/mtu.rs:41`) ; aucun garde-fou pour le minimum IPv6 interne (1280) |
| Tests | **Faible** | quelques tests unitaires v6 (firewall, rate limit, Astra) ; aucun test netns ; campagne cible v4 |

---

## 3. Inventaire des dépendances IPv4

Difficulté : F = faible, M = moyenne, E = élevée. Impact : ce qui casse ou fuit
si la dépendance reste en place alors que l'IPv6 est activé.

### 3.1 `aether` (contrats partagés)

| Fichier / symbole | Dépendance exacte | Diff. | Impact |
| --- | --- | --- | --- |
| `config.rs:16` `DEFAULT_WG_ADDRESS = "100.64.0.1/10"`, `:18` `DEFAULT_WG_API_URL` | adresse tunnel unique, IPv4 | F | aucune tant que v4 reste l'ancre |
| `config.rs` `NetworkConfig::wg_address: String` | une seule adresse, texte non typé | M | pas de VIP gateway v6 exprimable |
| `config.rs` `WgPeer::address: String` | une seule adresse, doc « `/32` » | M | pas de VIP pair v6 |
| `config.rs:720-745` `validate_peer_identities` | `prefix == "32"` et `parse::<Ipv4Addr>()` | M | refuse tout pair v6 — **fail-closed, correct aujourd'hui** |
| `config.rs:51` `valid_ipv4_cidr` (Meshnet) | parser maison IPv4 | F | refuse les pairs Meshnet v6 — cohérent avec `PRIVATE_IPV4_CIDRS`, voir §3.2 |
| `config.rs:1066-1099` `api_bind`, `speedtest_bind` | `format!("{host}:{port}")` sans crochets | F | une adresse v6 produirait `fd00::1:8080`, illisible par `SocketAddr` |
| `config.rs:1018` `cidr_contains` | déjà famille-aware (`is_ipv4`, octets) | — | réutilisable |
| `enroll.rs:100` `ProvisionResponse::assigned_address: String` | une seule adresse | M | format réseau à versionner |
| `mtu.rs:41,49` `SURCOUT_WIREGUARD = 80`, `MTU_PLANCHER = 576` | plancher IPv4 | M | un tunnel à MTU < 1280 ne peut pas porter d'IPv6 interne (Linux retire l'IPv6 d'une interface sous 1280, à vérifier sur cible) |
| `policy.rs` `FirewallPolicy::*_cidrs: Vec<String>` | texte, analysé à la compilation de la policy | — | déjà dual-stack via `ipnetwork` |

### 3.2 `helios-firewall`

| Fichier / symbole | Dépendance exacte | Diff. | Impact |
| --- | --- | --- | --- |
| `ruleset.rs:74` `PRIVATE_IPV4_CIDRS` | liste RFC 1918 + link-local v4 | F | un pair Meshnet routant en v6 atteindrait les réseaux locaux v6 (ULA, `fe80::/10`) : les drops ne portent que `ip daddr` |
| `ruleset/meshnet.rs:62` `Match::Icmp(AddressFamily::Ipv4)` | ICMP Meshnet v4 seulement | F | pair Meshnet v6 : `ip6 saddr X meta l4proto icmp` ne matche jamais |
| `ruleset/gateway_wan.rs` `dhcp_lease_renewal` | UDP 67/68 uniquement | F | pas de DHCPv6 (546/547) |
| `ruleset/gateway_wan.rs` (absence) | aucune ouverture ICMPv6 ND/RA/MLD | M | IPv6 WAN inutilisable sous policy `drop` |
| `ruleset/astra_channel.rs` `10.88.7.x/32` | pont Docker IPv4 figé | — | à conserver en IPv4 (canal local, compose fige ces adresses) |
| `netlink/transaction.rs:120-132` masquerade | `oifname` seul, pas de `nfproto` | F | NAT66 implicite ; aussi appliqué au trafic LAN, pas seulement aux clients tunnel |
| `netlink/expressions.rs` `icmp_protocol` | `meta l4proto 1|58`, pas de type | M | ne peut pas exprimer « ND seulement » ; voir §6.3 : `rustables` 0.8.7 expose `TransportHeaderField::ICMPv6(Type)` |
| `ruleset/transport.rs` `site_to_site_peers` | port `51820` codé en dur | F | indépendant de la famille, à noter |

### 3.3 `helios-provisioning`

| Fichier / symbole | Dépendance exacte | Diff. | Impact |
| --- | --- | --- | --- |
| `ipam.rs:23-29` `CGNAT_BASE: u32`, `HOST_BITS = 22` | arithmétique `u32` | M | pas de dérivation v6 |
| `ipam.rs:47` `PeerTable::is_taken_by_other(Ipv4Addr, ..)` | trait IPv4 | M | toute table de collision est v4 |
| `ipam.rs:64` `derive_cgnat_ip -> Ipv4Addr` | idem | M | — |
| `admission.rs:128` `format!("{vip}/32")`, `:169` `entries: Vec<(Ipv4Addr, ..)>`, `:203` `host_of -> Ipv4Addr` | IPv4 | M | admission n'attribue qu'un VIP v4 |
| `session.rs:50,111` `ProvisionedSession::address: Ipv4Addr`, `format!("{address}/32")` | IPv4 | M | provisioning in-tunnel v4 |

### 3.4 `heliosd`

| Fichier / symbole | Dépendance exacte | Diff. | Impact |
| --- | --- | --- | --- |
| `vip_routing.rs` (tout le module) | `Plan::source: Ipv4Addr`, `parse_cidr`, `network_of` en `u32`, `ip rule/route` sans `-6` | M | les VIP v6 ne seraient pas épinglés ; Tailscale installe aussi des règles v6 |
| `orchestrator/data_plane.rs:39,49` `wg_config` | une adresse, un `allowed_ips` | F | projection à élargir |
| `orchestrator/data_plane.rs:213` `IP_FORWARD_PATH = /proc/sys/net/ipv4/ip_forward` | contrôle v4 seul | F | aucun avertissement si `net.ipv6.conf.all.forwarding = 0` |
| `orchestrator/probes.rs:83,96` `mtu = mss + 40`, `mtu - 100` | en-têtes IPv4 (20+20) et WG v4 (60) | F | MSS faux de 20 à 40 octets pour TCP interne v6 ; sans effet tant que le clamp reste bloqué par le backend |
| `key_negotiation/server.rs:118` `Ipv4Addr::UNSPECIFIED` | écoute v4 seulement | F | négociation impossible pour un client IPv6-only |
| `uplink.rs:265-300` | lit `/proc/net/route` **et** `/proc/net/ipv6_route` | — | déjà dual-stack |

### 3.5 `helios-wireguard`

| Fichier / symbole | Dépendance exacte | Diff. | Impact |
| --- | --- | --- | --- |
| `lib.rs:73` `InterfaceConfig::address: String` | une adresse | F | pas de v6 sur `helios0` |
| `lib.rs:99` `PeerConfig::allowed_ips: String` | un préfixe par pair | F | pas de `/128` à côté du `/32` |
| `kernel.rs:71,115` `vec![allowed]`, `vec![address]` | idem | F | `defguard` accepte déjà des `Vec<IpAddrMask>` |

Le backend noyau n'appelle jamais `set_endpoint` (`kernel.rs`, doc de module) :
le roaming v4↔v6 d'un client est géré par WireGuard, et
`PeerStatus::endpoint` vient de `SocketAddr::to_string()`, qui produit déjà
`[2001:db8::1]:51820`.

### 3.6 `helios-api`

| Fichier / symbole | Dépendance exacte | Diff. | Impact |
| --- | --- | --- | --- |
| `auth.rs:122-131` `resolve` | `prefix == "32" && host == source.to_string()` | M | un pair v6 n'est jamais reconnu ; une source `::ffff:a.b.c.d` (socket dual-stack) non plus |
| `provision.rs:153` `format!("{}/32", ..)`, `:217-245` `PeerAddressTable` en `Ipv4Addr` | IPv4, ignore explicitement les v6 (`:223`) | M | collisions v6 invisibles |

### 3.7 `orion-core` et `apps/orion`

| Fichier / symbole | Dépendance exacte | Diff. | Impact |
| --- | --- | --- | --- |
| `orion-core/src/config.rs:28` `DEFAULT_ALLOWED_IPS = "0.0.0.0/0"` | tunnel complet v4 seulement | **F** | **fuite IPv6 aujourd'hui** |
| `apps/orion/src/splitTunnel.ts:49` `EVERYTHING = '0.0.0.0/0'`, `:46` `PRIVATE_RANGES` v4 | presets v4 | F | idem ; preset `private` ignore les ULA |
| `apps/orion/src/splitTunnel.ts:34` `DEFAULT_GATEWAY_HOST = '100.64.0.1'` | repli v4 | F | acceptable (ancre v4) |
| `orion-core/src/config.rs:450` `ClientProfile::address: Option<String>` | une adresse (validée par `validate_cidr`, qui accepte v6) | M | pas de dual-stack interne |
| `orion-core/src/backend/wireguard.rs:200` `addresses: vec![address]` | une adresse | F | — |
| `orion-core/src/backend/wireguard.rs:126` `set_endpoint` → `defguard::utils::resolve` = `to_socket_addrs().next()` | premier résultat, synchrone | M | famille choisie par l'ordre `getaddrinfo`, pas de repli |
| `orion-core/src/key_negotiation.rs:507` `resolve_remote` | `lookup_host(..).find(port != 0)` = premier résultat | M | idem, et résolution indépendante de celle de l'endpoint WG |
| `orion-core/src/profile_import/field_rules.rs:35-107` `validate_endpoint` | gère `[v6]:port` | — | déjà correct |
| `orion-core/src/net_pin.rs` `negotiation_socket` | choisit `0.0.0.0` ou `::` selon la famille, `IPV6_UNICAST_IF` sur Windows | — | déjà dual-stack |
| `orion-core/src/key_negotiation.rs:699-720` `parse_prefix/prefix_contains` | famille-aware | — | déjà dual-stack |
| `orion-core/src/profile_import/json.rs:21,37,100` `deny_unknown_fields` | document `orion-profile` strict | M | tout nouveau champ casse les Orion antérieurs (fail-closed) |
| `apps/orion/src-tauri/src/astra.rs`, `operator.rs` `Ipv4Addr::LOCALHOST` | IPC local | — | à garder |

### 3.8 Outils et UI gateway

| Fichier / symbole | Dépendance exacte | Diff. | Impact |
| --- | --- | --- | --- |
| `tools/helios-ctl/src/profile.rs:351` `heliosd_url` | `parse::<Ipv4Addr>()` sinon `None` | F | acceptable tant que l'API reste sur le VIP v4 |
| `tools/helios-ctl/src/enroll.rs:382` `rsplit_once(':')` | correct pour `[v6]:port` | — | — |
| `orion-core/src/profile_import/field_rules.rs:162` SSH target `rsplit_once(':')` | `user@2001:db8::1` lu comme port `1` | F | à vérifier, faible impact |
| `web/src/views/System.tsx:278` placeholder `10.0.0.0/8` | cosmétique | F | — |
| `web/src/types.ts:21` `address: string` | une adresse par pair | F | affichage à élargir |

Aucune base de données : l'état persistant est `network.toml` (TOML), les
profils `orion-profile` (JSON) et les stores Astra. Aucun champ n'y est borné en
longueur ; la contrainte est dans les validateurs, pas dans le stockage.

---

## 4. Cartographie des flux d'adresses

```text
Opérateur / UI web / helios-ctl          Orion (profil JSON / wg-quick)
        │ network.toml (TOML, String)            │ ClientProfile (String)
        ▼                                        ▼
aether::NetworkConfig ── validate() ──┐   orion-core::profile_import::validate_*
   wg_address, peers[].address        │     (endpoint, AllowedIPs: déjà v4/v6)
   *_cidrs (String)                   │                │
        │                             │                ▼
        ├─► to_firewall_policy ─► FirewallPolicy (String)   defguard IpAddrMask
        │                               │                     (Windows: routes
        │                    helios_firewall::network()         ::/0 si présent)
        │                               ▼
        │                  IR Ruleset (IpNetwork typé)  ◄── abstraction famille ici
        │                               ▼
        │                  NetlinkBackend::match_net → meta nfproto + payload
        │                               ▼
        │                       table inet helios (noyau)
        │
        ├─► wg_config ─► InterfaceConfig{address} / PeerConfig{allowed_ips} ─► defguard ─► helios0
        ├─► vip_routing::plan ─► `ip rule` / `ip route` table 51820 (IPv4 seulement)
        ├─► api_bind / speedtest_bind ─► `host:port` (String) ─► TcpListener
        └─► helios_api::auth::resolve ◄── ConnectInfo<SocketAddr> (source)

helios_provisioning::{ipam, admission, session} ─► Ipv4Addr ─► "a.b.c.d/32" ─► network.toml / ProvisionResponse
```

Où l'adresse est :

- **parsée** : `helios_firewall::ruleset::network` (`IpNetwork`), `vip_routing::parse_cidr` (v4), `admission::host_of` (v4), `auth::resolve` (comparaison de chaîne), `defguard::IpAddrMask::from_str`, `orion-core::field_rules::validate_cidr/validate_endpoint`, `config::valid_ipv4_cidr` ;
- **validée** : `NetworkConfig::validate[_peer_identities]`, `ClientProfile::validate`, `helios-ctl check_allowed_ips` ;
- **stockée** : `network.toml`, `orion-profile`, en `String` partout ;
- **transformée** : IPAM (`u32`), `vip_routing::network_of` (`u32`), `api_bind` (`split('/')`) ;
- **envoyée à Linux** : Netlink nftables (typé), `defguard` Netlink WireGuard (typé), `ip` en sous-processus (texte) ;
- **utilisée pour nftables** : uniquement via l'IR, jamais par texte (`FIREWALL-V2.md`).

**Où placer l'abstraction.** La couche IR du firewall est déjà le bon modèle :
le domaine y manipule `IpNetwork`, la famille est déduite du type, et seul le
backend sait qu'IPv6 s'écrit `NFPROTO_IPV6` + offset `IPv6HeaderField`. Ce
qui manque est **en amont** : un type canonique d'adresse tunnel dans `aether`,
pour que `NetworkConfig`, l'IPAM, `vip_routing`, `helios-wireguard` et l'API
cessent de reparser des `String` chacun à leur manière (une dizaine de parseurs
distincts recensés ci-dessus).

---

## 5. Architecture cible

### 5.1 Principe : deux familles, un VIP v4 obligatoire

- Le VIP IPv4 CGNAT reste **obligatoire et unique** par pair. Il reste l'ancre
  de l'identité API (`ARCHITECTURE.md` : « la source résout vers le `/32`
  unique d'un pair »), de la release post-commit, du provisioning in-tunnel et
  du routage VIP. Aucune migration des configurations existantes.
- Un VIP IPv6 **optionnel**, `/128`, dans un préfixe ULA propre à la gateway.
  Jamais un `/64` par pair : un pair qui pourrait choisir son adresse dans un
  `/64` rendrait l'identité par adresse source ambiguë (adresses temporaires
  RFC 8981).
- On distingue explicitement **famille externe** (transport UDP vers
  l'endpoint) et **famille interne** (trafic dans le tunnel). Le transport
  IPv6 est presque gratuit et utile (réseaux mobiles IPv6-only + NAT64) ; le
  tunnel IPv6-only interne ne l'est pas, car le plan de contrôle vit sur le
  VIP v4. « Tunnel IPv6-only » est donc proposé au sens **transport** ; un
  tunnel sans VIP v4 n'est pas une cible (décision à confirmer).

### 5.2 Types

`std::net::IpAddr` suffit pour une adresse. Pour les préfixes, le dépôt utilise
déjà `ipnetwork 0.21` (`helios-firewall/Cargo.toml`, aligné sur les signatures
de `rustables`). Ajouter `ipnetwork` à `aether` n'introduit pas de nouvelle
crate dans `Cargo.lock`. Proposition, dans un module `aether::net` :

```rust
/// A tunnel address: one host inside the tunnel network, with the network's
/// prefix length (e.g. 100.64.0.1/10, fd12:3456:789a::1/64).
pub struct TunnelAddress(ipnetwork::IpNetwork);

/// Every address a peer owns inside the tunnel. v4 is mandatory; v6 is
/// optional. Two fields rather than a Vec: "zero v4" or "two v6" cannot be
/// written.
pub struct PeerVips {
    pub v4: Ipv4Addr,          // rendered as /32
    pub v6: Option<Ipv6Addr>,  // rendered as /128
}
```

Un `enum IpFamily { V4, V6 }` n'est pas nécessaire dans le domaine : la famille
se lit sur `IpAddr`/`IpNetwork`. `helios_firewall::AddressFamily` existe déjà
pour le seul cas où un match n'a pas d'adresse (ICMP) ; il faut le garder
local au firewall et ne pas le promouvoir dans `aether`.

Règles de canonicalisation, dans `aether::net`, à utiliser partout où une
source réseau est comparée ou comptée :

- `IpAddr::to_canonical()` (Rust ≥ 1.75, MSRV 1.88 OK) avant toute
  comparaison : une socket `[::]` dual-stack présente les clients v4 comme
  `::ffff:a.b.c.d` ;
- comparaison d'adresses typées, jamais de chaînes (`auth.rs` compare
  aujourd'hui `host == source.to_string()`).

### 5.3 Format de configuration (compatibilité)

Deux options pour `network.toml` :

| Option | Forme | Pour | Contre |
| --- | --- | --- | --- |
| A — champs séparés | `wg_address = "100.64.0.1/10"`, `wg_address_v6 = "fd…::1/64"` ; `address = "100.64.1.2/32"`, `address_v6 = "fd…::a/128"` | zéro migration, invariant v4 inchangé, validation locale | deux clés |
| B — liste | `address = ["100.64.1.2/32", "fd…::a/128"]`, lue « un ou plusieurs » comme `de_wan_ifaces` | une clé | réécriture en liste au premier save ; « exactement un v4 » devient une règle de validation |

**Recommandation : A.** Elle garde l'état invalide non représentable et suit la
règle « ne pas renommer une clé pour gagner un pluriel » déjà appliquée à
`wan_iface`. `PersistedNetworkConfig` et la vue API redigée ajoutent les champs
`_v6` en `Option` avec `skip_serializing_if = "Option::is_none"` : un fichier
sans IPv6 est réécrit à l'identique.

Réseau (`ProvisionResponse`) et document `orion-profile` : ajouter
`assigned_address_v6` / `address_v6` en `Option`. Le document étant
`deny_unknown_fields`, un Orion ancien **refusera** un profil qui porte ce
champ. C'est fail-closed et acceptable si `helios-ctl` n'émet le champ que
lorsque la gateway a un préfixe v6, et si le message d'erreur est explicite.

### 5.4 IPAM v6

- Préfixe tunnel : `wg_address_v6`, ou dérivé une fois de la clé publique
  WireGuard de la gateway (Global ID RFC 4193, 40 bits) et écrit dans
  `network.toml` à l'initialisation. Dériver à chaque démarrage lierait le
  préfixe à l'identité : une rotation de clé renumérote tous les clients.
  Décision à prendre.
- Hôte : `BLAKE3(pubkey || counter || "v6")[..8]` sur les 64 bits bas d'un
  `/64`, en excluant `::0` et `::1` (gateway). 2^64 hôtes : le sondage
  anti-collision reste, mais n'est plus qu'un garde-fou.
- `PeerTable` devient générique sur la famille, ou reçoit un second trait :
  `is_taken_by_other(IpAddr, &[u8])` suffit.

### 5.5 Où vit la logique de famille

| Couche | Connaît la famille ? | Comment |
| --- | --- | --- |
| `aether` (config, policy) | par le type seulement | `IpAddr`, `IpNetwork`, `PeerVips` |
| `helios-firewall::ruleset` | pour les seuls matches sans adresse | `AddressFamily` (ICMP, ND) ; capacités « par famille » générées par une fonction |
| `helios-firewall::netlink` | oui | `nfproto`, offsets, numéros de protocole |
| `heliosd::vip_routing` | oui | `ip -4` / `ip -6`, une table, deux règles |
| `helios-wireguard` | non | `Vec<IpAddrMask>` |
| `helios-api` | non | `IpAddr::to_canonical()` + comparaison typée |
| Orion | non, sauf presets | liste de préfixes |

Pour éviter le `if ipv6 { … } else { … }` dispersé : une seule fonction
d'expansion dans le firewall, `for family in policy.families()`, utilisée par
les rares capacités qui en dépendent (ICMP, ND, DHCP, NAT), et la famille
inférée du préfixe pour toutes les autres.

---

## 6. Adaptations nftables

### 6.1 Ce qui fonctionne déjà en `inet`

- chaînes `input/forward/output`, policy `drop`, ordre `ct state invalid` en tête ;
- `ct state established,related` (conntrack v6 : `nf_conntrack` gère les deux familles dans une table `inet`) ; un ICMPv6 Packet Too Big lié à un flux suivi est `related` et accepté, comme l'ICMPv4 « fragmentation needed » (`expressions.rs::connection_states`, doc) ;
- toutes les règles scopées par interface et port seulement : écoute WireGuard et négociation sur le WAN, egress DNS/HTTP/NTP de la gateway, SSH `admin_ifaces`, API sur `helios0`, speedtest, iperf ;
- règles à adresse : `allow_ssh_from`, `split_tunnel_cidrs`, `captive_portal_gateway`, `static_peer_addrs` acceptent déjà un préfixe v6 et reçoivent la bonne garde `nfproto` ;
- compteurs inline et log : indépendants de la famille.

### 6.2 Ce qui doit être généré par famille

| Capacité | v4 | v6 |
| --- | --- | --- |
| ICMP tunnel | `meta l4proto icmp` | `meta l4proto ipv6-icmp` (déjà là) |
| ND/RA/MLD WAN | — (ARP n'est pas filtré par `inet`) | types 133–137, 130–132, 143, sur chaque WAN et LAN, `input` et `output` |
| DHCP | UDP 67/68 | UDP 546 (client) / 547 (serveur), vers `ff02::1:2` |
| Réseaux locaux Meshnet | `PRIVATE_IPV4_CIDRS` | `fc00::/7`, `fe80::/10` |
| NAT | masquerade `nfproto ipv4` | décision §6.5 |

### 6.3 Discrimination des types ICMPv6

`FIREWALL-V2.md` et la doc de `Match::Icmp` notent l'absence de champ ICMPv4
typé dans l'API haut niveau de `rustables`. **Pour ICMPv6, elle existe** :
`rustables::expr::TransportHeaderField::ICMPv6(ICMPv6HeaderField::Type)`
(`rustables-0.8.7/src/expr/payload.rs:247-253,349`). Pour ICMPv4, la struct
`Payload` expose des setters publics `with_base/with_offset/with_len`
(générés par `rustables-macros`, `src/lib.rs:276-296`), ce qui permet un
encodeur vérifié sans fork. Proposition d'IR :

```rust
Match::IcmpType { family: AddressFamily, types: IcmpTypes }
```

traduit en `meta l4proto <58|1>` + `payload @th,0,8` + `cmp`, avec une règle
par type (comme `expand_port_sets`) tant que les sets ne sont pas utilisés.

### 6.4 Sets et concaténations

Helios n'utilise aujourd'hui **aucun set, map ni concaténation** :
`DestPortSet` est développé en règles unitaires (`expressions.rs::expand_port_sets`).
`rustables` sait créer des sets `ipv4_addr` (type 7) et `ipv6_addr` (type 8)
et un `Lookup` (`data_type.rs`, `expr/lookup.rs`), mais aucun drapeau
`interval` n'est visible : un set de préfixes CIDR n'est pas démontré. Un set
étant typé par famille, un set « adresses » deviendrait deux sets. Rien ne
l'impose : le volume de règles adresse est faible. **Recommandation : ne pas
introduire de sets pour l'IPv6** ; garder l'expansion par règle, cohérente avec
le reste du backend.

### 6.5 NAT pour IPv6

Le NAT44 existe parce que les VIP sont des adresses CGNAT non routables. Le
NAT66 n'est pas son équivalent naturel : IPv6 n'a pas de pénurie d'adresses, et
une traduction casse le bout-en-bout que l'IPv6 rétablit. Trois stratégies :

1. **Blackhole (défaut recommandé).** Le client capture `::/0`, la gateway ne
   relaie aucun IPv6 vers le WAN (`forward` wg→WAN restreint à `nfproto ipv4`,
   ou pas de VIP v6). Idéalement un `reject` ICMPv6 « administratively
   prohibited » plutôt qu'un `drop`, pour que Happy Eyeballs replie vite sur
   IPv4. Aucune fuite, aucun NAT66.
2. **Préfixe routé (propre, rare).** La gateway reçoit un préfixe GUA routé
   (statique ou DHCPv6-PD) et attribue des `/128` dedans. Pas de NAT. Exige
   que l'amont route le préfixe vers la gateway ; un simple `/64` on-link
   exigerait un proxy NDP. Hors du périmètre initial.
3. **NAT66 masquerade (opt-in explicite).** Justifiable pour un usage
   road-warrior « sortie par la gateway » : c'est la même propriété que le
   NAT44 déjà en place, et avec une source ULA la table de politique RFC 6724
   (précédence ULA 3 < IPv4 35) fait préférer IPv4 aux clients dual-stack, donc
   le NAT66 ne sert qu'aux destinations IPv6-only. Doit être un drapeau
   distinct (`allow_client_internet_v6`), jamais activé par
   `allow_client_internet`. NPTv6 (RFC 6296, sans état) serait préférable ;
   son encodage via `rustables` n'est pas vérifié.

Indépendamment du choix : scoper dès maintenant le masquerade existant à
`meta nfproto ipv4` (et, décision à prendre, à `iifname wg_iface`), pour que
l'activation de `net.ipv6.conf.all.forwarding` ne crée pas un NAT66 non décidé.

### 6.6 Conntrack, compteurs, logs, limites

Rien ne change : `ct state` est commun, les actions sont attachées à la règle
quel que soit son match. Les limitations restent celles de `rustables`
(`limit`, compteurs nommés, `fib`, `exthdr` non encodables). Point d'attention :
les messages ND sont `untracked` (conntrack ne crée pas d'entrée pour les types
133–137 et MLD) ; ils ne tombent pas dans `ct state invalid` mais ne sont pas
non plus `established` — d'où la nécessité de règles explicites. Comportement
noyau, à vérifier sur cible.

---

## 7. Adaptations routing

Constat : Helios **n'installe ni route par défaut, ni route statique, ni
gateway**. Il lit les routes par défaut v4 et v6 (`uplink.rs::default_route_metrics`)
et gère une seule table de policy routing, `51820`, pour épingler les VIP
(`vip_routing.rs`). Il ne touche à aucun sysctl.

| Élément | Existant | Dual-stack |
| --- | --- | --- |
| Table `51820` | `/32` v4 par pair | ajouter `/128` v6 par pair ; `ip -6 route flush table 51820` séparé |
| Règle `priority 32000` | `ip rule add to 100.64.0.0/10` | `ip -6 rule add to <ULA>/64` ; `flush_rules` doit aussi boucler sur `ip -6 rule del priority 32000` |
| Conflits d'autres VPN | NordVPN/Tailscale sur `100.64.0.0/10` | Tailscale utilise `fd7a:115c:a1e0::/48` et des règles v6 : risque moindre avec un ULA aléatoire, mais l'épinglage garde la même justification |
| `0.0.0.0/0` vs `::/0` | `uplink.rs` distingue déjà `::/0` d'une route hôte `::` | — |
| Gateway link-local | non géré (Helios n'écrit pas de routes par défaut) | aucune action ; si un jour Helios écrit des routes, une gateway `fe80::1` exige `dev <iface>` |
| Forwarding | avertit si `ipv4/ip_forward = 0` (`data_plane.rs:213`) | avertir aussi pour `net.ipv6.conf.all.forwarding` ; **et** avertir que ce passage désactive l'acceptation des RA sur le WAN sauf `accept_ra = 2` |
| `ip rule` d'autres VPN | coexistence par priorité | mêmes priorités en v6 ; vérifier sur cible les priorités réelles de NordVPN/Tailscale en v6 |

Le routage LAN IPv6 (annoncer un préfixe au LAN, RA, DHCPv6-PD) n'existe pas
en IPv4 non plus : Helios relaie, il n'adresse pas le LAN. À garder hors
périmètre.

---

## 8. Adaptations WireGuard

### 8.1 Gateway

- `InterfaceConfig::address: String` → `addresses: Vec<String>` (ou typé), une
  entrée v4 + une v6 optionnelle ; `defguard` prend déjà `Vec<IpAddrMask>`.
- `PeerConfig::allowed_ips: String` → `Vec`, `/32` + `/128` optionnel. La
  cryptokey routing de WireGuard assure alors l'anti-spoofing sur `helios0`
  pour les deux familles.
- L'écoute UDP noyau de WireGuard est déjà dual-stack (socket v4 et v6) ; la
  règle `input` est scopée par interface et port, donc déjà ouverte en v6. À
  vérifier sur cible avec un client en transport v6.
- MTU : avec un VIP v6, refuser (ou ne pas poser) l'adresse v6 si
  `tunnel_mtu(...) < 1280`, avec un message explicite ; sinon le noyau retire
  l'IPv6 de l'interface et la bring-up échoue de façon opaque.
- `disable_ipv6 = 1` global (courant sur appliance durcie) fera échouer la pose
  d'une adresse v6 : erreur typée et nommée, jamais repli silencieux.

### 8.2 Orion

| Scénario | Transport | `Address` | `AllowedIPs` | Remarque |
| --- | --- | --- | --- | --- |
| v4-only (existant) | v4 | `/32` | `0.0.0.0/0` **+ `::/0`** | `::/0` capturé et jeté côté gateway : bloque la fuite |
| transport v6 | endpoint `[2001:db8::1]:51820` | `/32` | `0.0.0.0/0, ::/0` | déjà validé par `validate_endpoint` ; exige l'écoute négociation en v6 |
| dual-stack | v4 ou v6 | `/32` + `/128` | `0.0.0.0/0, ::/0` | exige VIP v6 gateway |
| split | — | idem | préfixes v4 + ULA gateway `/128` | preset `private` : ajouter `fc00::/7` ? décision (capte aussi l'ULA locale) |

Points `defguard` à connaître (`defguard_wireguard_rs-0.11.0`) :

- Windows `configure_interface` transmet au pilote la liste **complète** des
  `AllowedIPs` (`set_config`, `wgapi_windows.rs:316`), puis retire en silence,
  sur sa copie locale, les préfixes et adresses d'une famille indisponible sur
  l'adaptateur, avant de créer les **routes** du système
  (`wgapi_windows.rs:356-401`). Le pilote annonce donc toujours `::/0`, mais
  aucune route `::/0` ne passe par le tunnel : l'IPv6 sort en clair, sans
  erreur. Relire la configuration du pilote ne suffit pas à le voir ; il faut
  aussi lire la table de routage de l'adaptateur. C'est ce que fait T02
  (fusionné), à valider sur VM Windows.
- `set_endpoint` résout de façon synchrone et garde le **premier** résultat
  (`utils.rs:603-612`).

### 8.3 Endpoints `[2001:db8::1]:51820`

Correctement gérés : `field_rules::validate_endpoint` (crochets requis),
`SocketAddr::to_string` côté gateway, `enroll.rs:382`
(`rsplit_once(':')` garde les crochets). Deux faiblesses : un nom résolu
seulement à `up()`, et `heliosd_url` v6 impossible (`helios-ctl profile.rs:351`),
ce qui est acceptable tant que l'API reste sur le VIP v4.

### 8.4 Firewall associé

Côté gateway : rien pour le transport v6 (scope interface). Pour un VIP v6 :
aucune règle à adresse n'existe sur `helios0` ; l'ICMPv6 y est déjà ouvert si
`allow_tunnel_icmp`. Forward wg→WAN : famille à restreindre selon §6.5.

---

## 9. ICMPv6 et Neighbor Discovery

### 9.1 Toujours autorisé, quel que soit `TunnelState`

Ces règles relèvent du fonctionnement du lien, pas du trafic relayé ; elles
n'ouvrent aucun chemin vers le LAN et doivent survivre au kill-switch, comme la
DHCP v4 actuelle.

| Type | Nom | Chaîne | Portée |
| --- | --- | --- | --- |
| 135 / 136 | Neighbor Solicitation / Advertisement | `input`, `output` | WAN, LAN, overlays ; hop-limit 255 exigé par RFC 4861 |
| 133 | Router Solicitation | `output` | WAN (la gateway est hôte sur son WAN) |
| 134 | Router Advertisement | `input` | WAN seulement ; **jamais** depuis `helios0` ni le LAN (RA rogue) |
| 137 | Redirect | refuser | — |
| 130–132, 143 | MLD query / report / done, MLDv2 report | `input`, `output` | WAN/LAN, source link-local |
| 2 | Packet Too Big | `input`, `forward`, `output` | tous ; déjà couvert par `related` pour les flux suivis, à ouvrir aussi hors flux pour PMTUD de l'encapsulation |
| 1, 3, 4 | Destination Unreachable, Time Exceeded, Parameter Problem | idem | `related` suffit dans la plupart des cas |
| 128 / 129 | Echo Request / Reply | `input` sur `helios0` (existant) ; WAN : décision (RFC 4890 recommande de ne pas bloquer echo en transit) | — |

Filtrage par hop-limit 255 : `rustables` expose
`IPv6HeaderField::HopLimit` (offset 7, longueur 1). T05 (fusionné) l'encode
derrière la garde `meta nfproto ipv6` et le vérifie par un test d'octets ;
l'application par le noyau reste à vérifier sur cible.

### 9.2 Hypothèses ARP / L2

Aucune dans le code : `grep` ne trouve ni ARP, ni `neigh`, ni filtrage L2
(`bridge`, `arp` family). Une table `inet` ne voit pas l'ARP, ce qui explique
que l'IPv4 fonctionne sous policy `drop` ; c'est précisément ce qui ne se
transpose pas, puisque ND passe par ICMPv6 dans la table filtrée.

### 9.3 Link-local et scope

- Aucune adresse `fe80::/10` n'est utilisée par Helios. ND et MLD sources
  `fe80::` doivent être acceptées par interface, jamais par adresse.
- Les zones (`%eth0`) : `std::net::Ipv6Addr` ne porte pas de scope ;
  `SocketAddrV6` le porte (`scope_id`). Aucun champ de configuration ne doit
  accepter un link-local sans interface ; `validate_cidr` d'Orion et
  `helios_firewall::network` refusent déjà `fe80::1%eth0` (parse échoue),
  comportement à conserver et à tester.
- WireGuard n'attribue pas de link-local à son interface (pas d'adresse L2) ;
  à vérifier sur cible.

### 9.4 Multicast requis

`ff02::1` (all-nodes, RA), `ff02::2` (all-routers, RS), `ff02::1:ffXX:XXXX`
(solicited-node, NS), `ff02::16` (MLDv2), `ff02::1:2` (DHCPv6). Tous sont
link-local : les autoriser dans `input/output` scopés aux interfaces
physiques, jamais en `forward`.

---

## 10. DNS

| Point | Constat | Référence |
| --- | --- | --- |
| API utilisée | `getaddrinfo` via `tokio::net::lookup_host` et `ToSocketAddrs` | `orion-core/src/key_negotiation.rs:507`, `defguard utils.rs:609` |
| A / AAAA | les deux, selon le résolveur système | — |
| Premier résultat | oui, aux deux endroits | `.find(port != 0)`, `.next()` |
| Cohérence | deux résolutions indépendantes : négociation et WireGuard peuvent choisir deux familles différentes | même nom d'hôte, deux appels |
| Repli | aucun : un AAAA injoignable fait échouer la négociation | — |
| Happy Eyeballs | absent ; pertinent pour la négociation (QUIC, un aller-retour) et pour le choix de l'endpoint WG | RFC 8305 |
| DNS du client | non tunnelisé, limite connue documentée | `helios-firewall/src/ruleset.rs` doc « DNS is not tunneled » |
| DNS de la gateway | egress UDP/TCP 53 scopé WAN, déjà agnostique | `gateway_wan.rs::gateway_own_egress` |

Recommandations : résoudre **une fois** le nom de l'endpoint, conserver la
liste ordonnée, tenter la négociation selon RFC 8305 (IPv6 d'abord, IPv4 après
~250 ms), puis poser l'endpoint WireGuard **sur l'adresse qui a négocié** (et
non sur un second `getaddrinfo`). Le budget par `/64` de la négociation reste
valable.

Fuite DNS IPv6 : même sans tunneliser le DNS, capturer `::/0` fait passer les
requêtes vers un résolveur IPv6 du réseau local **dans** le tunnel (et elles y
meurent en mode blackhole) : la résolution retombe sur les résolveurs v4, qui
eux fuient déjà (limite connue). Aucune aggravation, mais aucun gain non plus.

---

## 11. API, UI et configuration

| Élément | Suppose IPv4 ? | Action |
| --- | --- | --- |
| `auth::resolve` | oui (`"32"`, comparaison de chaîne) | comparer `IpAddr` canonique au v4 **ou** au v6 du pair ; unicité vérifiée sur l'union |
| `api_bind`, `speedtest_bind` | formatage sans crochets | construire un `SocketAddr` typé ; garder le bind v4 |
| `GET /api/network` (vue redigée) | champ `address` | ajouter `address_v6` |
| `POST /api/split-tunnel` | non (texte, validé à la compilation de policy) | tester v6 |
| `web/src/views/System.tsx` | placeholder v4 | ajouter un exemple v6 |
| `web/src/views/Clients.tsx` | affiche `endpoint` (déjà `[v6]:port`) et `address` | afficher `address_v6` |
| Orion `splitTunnel.ts` | presets v4 | `full` = `0.0.0.0/0, ::/0` ; `gateway` = `/32` (+ `/128` si connu) |
| Orion `validate_cidr`, `validate_endpoint` | non | — |
| helios-ctl `check_allowed_ips` | non (délègue à `orion-core`) | — |
| Messages d'erreur | « a /32 IPv4 is required » (`config.rs:737`) | reformuler lorsque v6 est accepté |

Aucune regex IPv4 côté UI gateway. Côté Orion, `isIpv4` / `isIpv6`
(`splitTunnel.ts:85-96`) ne servent qu'à dériver un préfixe hôte ; `isIpv6`
est permissif (`/^[0-9a-fA-F:.]+$/`) mais la validation autoritaire reste
Rust.

---

## 12. Stratégie de tests

Niveaux disponibles : unitaire (partout), golden tests du firewall
(`helios-firewall/src/ruleset/tests/golden.rs`), tests d'octets Netlink (sans
noyau), network namespace (Linux natif, **pas WSL2** pour nf_tables et
WireGuard noyau — `TESTING.md`), cible matérielle, VM Windows pour Orion.

| # | Scénario | Unitaire | Golden / octets | netns | Cible / VM |
| --- | --- | --- | --- | --- | --- |
| 1 | IPv4 uniquement | config, IPAM | golden inchangés (régression) | oui | campagne existante |
| 2 | IPv6 uniquement (transport) | endpoint, bind | — | client v6 → gateway | oui |
| 3 | dual-stack | `PeerVips`, auth | golden v4+v6 | oui | oui |
| 4 | firewall IPv6 | `render` | golden, octets `nfproto` | `nft list` | oui |
| 5 | TCP IPv6 | — | — | `socat` via tunnel | oui |
| 6 | UDP IPv6 | — | — | idem | oui |
| 7 | ICMPv6 | IR `IcmpType` | octets type/offset | `ping -6` | oui |
| 8 | Neighbor Discovery | IR | golden : règles présentes dans **tous** les états | veth + `ip -6 neigh` sous policy drop | oui |
| 9 | Path MTU Discovery | `tunnel_mtu` ≥ 1280 | — | veth MTU 1280/1400 + `tracepath -6` | oui |
| 10 | WireGuard IPv6 | `build_peer` multi | — | deux netns, endpoint `[..]` | oui |
| 11 | WireGuard dual-stack | idem | — | idem | VM Windows : `::/0` réellement posé |
| 12 | DNS AAAA | ordre RFC 8305 (résolveur injecté) | — | résolveur local avec A+AAAA, AAAA injoignable | VM |
| 13 | sets nftables IPv6 | — (pas de sets, §6.4) | — | — | — |
| 14 | anti-spoofing IPv6 | `AllowedIPs` `/128` | — | paquet source forgée via `helios0` rejeté par WG | oui |
| 15 | conntrack IPv6 | — | masque inchangé | `conntrack -L -f ipv6` | oui |
| 16 | default-drop | golden : IPv6 non ouvert hors ND | — | IPv6 LAN→WAN refusé hors `Up` | oui |
| 17 | régression IPv4 complète | suite actuelle | golden actuels **byte-identiques** | — | `bash scripts/regression.sh`, campagne cible |

Tests à ajouter en priorité, parce qu'ils verrouillent des invariants :

- golden : « aucune règle `forward` ne laisse passer `nfproto ipv6` vers un WAN
  tant que `allow_client_internet_v6` est faux » ;
- golden : « le masquerade porte `nfproto ipv4` » ;
- golden : « ND/RA présentes dans `Down`, `Connecting`, `Failed`,
  `CaptivePortal` et `Up` » ; « aucun RA accepté sur `wg_iface` ou `lan_ifaces` » ;
- `auth` : un pair avec `/32` + `/128` est reconnu par l'une ou l'autre
  source ; `::ffff:100.64.1.2` résout vers le pair v4 ; un v6 dupliqué est
  refusé ;
- `rate_bucket` : `::ffff:a.b.c.d` compte pour `a.b.c.d`, pas pour `::/64` ;
- Orion : le défaut et le preset `full` contiennent `::/0` ;
- config : un `network.toml` v4 existant se relit et se réécrit **à l'octet
  près** (tests de round-trip de `PersistedNetworkConfig`).

Le banc netns existe depuis le 18 octobre 2026 : `scripts/netns-bench.sh`
(T22), documenté dans `TESTING.md` comme ne prouvant pas le matériel. Il tourne
sans root dans un namespace utilisateur, y compris sous WSL2 : la réserve « pas
WSL2 » ci-dessus ne vaut plus pour le noyau WSL2 actuel. Il couvre les
scénarios 1, 3 à 8, 10, 14 et 16 ; 9, 12 et 15 restent à ajouter.

---

## 13. Risques

| Risque | Existant ? | Gravité | Mitigation |
| --- | --- | --- | --- |
| **Fuite IPv6 hors VPN côté Orion** (`0.0.0.0/0` seul) | **oui, aujourd'hui** | élevée | ticket T01, avant tout le reste |
| `::/0` retiré silencieusement par `defguard` Windows si IPv6 indisponible sur l'adaptateur | latent | élevée | relire la config appliquée, signaler (T02) |
| IPv6 WAN de la gateway cassé par policy drop (ND/RA) | latent, dès qu'un WAN reçoit de l'IPv6 | moyenne | T05 ; vérifier sur cible |
| NAT66 implicite par masquerade `inet` | latent | moyenne | T04 : `nfproto ipv4` |
| Forward LAN→WAN IPv6 en `Up` si l'opérateur active `ipv6.forwarding` | latent | moyenne | règle forward famille-aware, décision §6.5 |
| Pair Meshnet v6 atteignant les réseaux locaux v6 | bloqué par `valid_ipv4_cidr` | moyenne si levé | T06 avant d'accepter v6 Meshnet |
| Socket dual-stack `[::]` : sources `::ffff:` | latent | **élevée** : tous les IPv4 partagent le budget `/64` `::`, et l'API refuse tous les admins | canonicaliser (T08) avant tout bind `[::]` |
| Casse des `network.toml` existants | à éviter | élevée | option A, round-trip byte-identique |
| Orion ancien refusant un profil v6 (`deny_unknown_fields`) | certain si champ émis | faible (fail-closed) | émettre le champ seulement si v6 configuré ; message clair |
| MTU tunnel < 1280 sur transport étroit (1280 mesuré en campagne) | latent | moyenne | ne pas poser v6 sous 1280, avertir |
| `ipv6.forwarding = 1` désactive l'autoconfiguration du WAN | latent | moyenne | avertissement + `accept_ra = 2` documenté (Helios ne modifie pas les sysctls) |
| RA rogue reçu sur LAN ou tunnel | à créer | moyenne | RA acceptés sur WAN seulement |
| Route IPv6 non contrôlée d'un autre VPN capturant le préfixe ULA | latent | faible | épinglage v6 dans `vip_routing` |
| DNS leak IPv6 | inchangé (DNS non tunnelisé) | inchangé | limite connue ADR-004 lot 5 |
| Deux familles choisies pour négociation et WG | latent | faible | une résolution, RFC 8305 |
| MSS calculé avec en-têtes v4 | latent (clamp bloqué) | faible | T15 |
| `rustables` peu maintenu, `fib` absent → pas d'anti-spoofing v6 hors tunnel | existant (v4 aussi) | moyenne | cryptokey routing sur `helios0` ; `fib` reste différé (`FIREWALL-V2.md`) |
| Différences noyau : ND `untracked`, `inet nat` ≥ 5.2, DAD sur interface NOARP | à vérifier | — | campagne cible dédiée |

---

## 14. Roadmap

Ordre guidé par le risque : d'abord fermer ce qui fuit ou casse aujourd'hui
sans rien activer, puis figer le modèle d'adressage, ensuite les types, le
data plane, et seulement à la fin la politique de sortie.

Deux spécifications, à deux moments différents :

- **Spécification A — modèle d'adressage IPv6** (T00), **avant la phase 1**. Sans elle,
  T07 et T10–T14 trancheraient eux-mêmes ULA, `/64`, `/128` et stabilité du
  préfixe.
- **Spécification B — politique de sortie Internet IPv6** (T21), avant la phase 4 :
  elle ne conditionne que l'ouverture du `forward` v6.

```text
PHASE 0 — sécurité IPv6 actuelle, sans activer l'IPv6
  T01 ::/0 Orion · T02 contrôle defguard · T03 golden anti-relais v6
  T04 masquerade nfproto ipv4 · T05 ICMPv6 de contrôle WAN
  T06 protections Meshnet v6 · T08 canonicalisation ::ffff:
        │
SPEC A (T00) — IPv4 obligatoire, IPv6 optionnel, ULA /64, /128 par pair,
              génération et stabilité du préfixe, rôle du v6 dans l'identité API
        │
PHASE 1 — modèle réseau commun
  T07 aether::net (PeerVips, TunnelAddress) · T09 bind typé (SocketAddr)
        │
PHASE 2 — data plane
  T10 config _v6 · T11 IPAM ULA · T12 WireGuard multi-adresses
  T13 vip_routing v6 · T14 provisioning v6 · T15 MTU/MSS
        │
PHASE 3 — contrôle et client
  T16 auth API · T17 négociation QUIC v6 · T18 résolution RFC 8305
  T19 Orion dual-stack · T20 UI gateway
        │
SPEC B (T21) — blackhole/reject (V1), NAT66 opt-in, préfixe GUA routé (futur)
        │
PHASE 4 — forwarding IPv6 choisi explicitement · T22 banc netns · T23 campagne cible
```

T08 est avancé en phase 0 : il ne dépend d'aucune décision d'adressage, et il
supprime un piège latent (budget de négociation et auth API) avant que
quiconque ouvre une socket `[::]`.

Dépendances : T01–T06 et T08 aucune (T02 suit T01) ; T00 → T07 → T10 → T11,
T12, T13, T14 ; T08 → T16, T17 ; T12 + T13 + T14 → T19 ; T21 doit précéder
toute ouverture de `forward` v6 ; T22 peut démarrer dès la phase 0.

Nature des tickets de la phase 0 : T01, T03, T04 et T08 sont des changements
bornés, sans décision ouverte. T02 et T06 demandent peu de jugement. T05 n'est
pas mécanique : il ajoute une primitive d'IR (`Match::IcmpType`), son encodage
Netlink, et une décision sur le drapeau DHCPv6 ; il exige une validation cible.

---

## 15. Tickets

Chaque ticket est autonome, respecte `AGENTS.md` (pas de `TODO`, tests au bon
niveau, docs françaises mises à jour) et indique ce qui reste à vérifier sur
cible.

Avancement de `feature/support-ipv6`, suivi actualisé le 8 octobre 2026 :

| Ticket | État | Reste à faire |
| --- | --- | --- |
| T00 | spécification validée le 1er octobre 2026, avec l'IPAM unifié (§3 bis) | — |
| T01 | fusionné | VM Windows : `::/0` posé, `curl -6` bloqué ; ADR-001 §3 bis amendé le 2026-10-18 |
| T02 | fusionné | VM Windows : absence de faux positif, détection, fuite réelle |
| T03 + T04 | fusionnés | cible : batch accepté, NAT44 inchangé |
| T05 | fusionné | cible : ND `untracked`, voisins et route par défaut IPv6 stables, renouvellement DHCPv6 |
| T08 | fusionné | cible avec T17 : sources `::ffff:` sur socket `[::]` |
| T06 | fusionné | accepter des pairs Meshnet IPv6 exige de couvrir un préfixe global du lien WAN, puis un essai sur cible |
| T09 | fusionné | `heliosd run` refuse désormais une `wg_address` sans hôte IPv4 au lieu de basculer sur loopback |
| T07 | fusionné | — |
| T10 | fusionné ; commande livrée | `heliosd init-ipv6-prefix` génère et persiste un ULA une fois ; une répétition conserve le fichier. Changer `wg_address_v6` reste refusé à chaud (API 409) et exige un redémarrage |
| T11 + T14 | fusionnés (IPAM unifié) | ADR-001 §4 et ADR-004 §5 amendés le 2026-10-18 pour décrire l'IPAM unifié ; projection de `address_v6` livrée par T12/T13 |
| T12 + T13 | fusionnés, chemins dégradés revus | échec de la seconde montée IPv4 couvert en simulation, avec les deux causes conservées et le kill-switch engagé. Cible : adresse sur `helios0`, routes et règle `ip -6`, MTU, `disable_ipv6`, coexistence NordVPN/Tailscale et `ping -6` |
| T16 | couvert par T08 et T10 | une source IPv6 native n'est jamais un appelant ; `address_v6` exposée dans la vue redigée |
| T17 | fusionné | cible : `ss -ulpn` montre `[::]`, client IPv6 seul, repli `ipv6.disable=1` |
| T18 | fusionné | VM Windows : A+AAAA avec IPv6 cassée → IPv4 en ~250 ms ; un candidat perdant consomme une unité du budget par identité côté gateway |
| T19 | fusionné | VM Windows : code `#[cfg(windows)]` non compilé depuis WSL ; les deux adresses sur `orion0`, `ping -6 <préfixe>::1`, avertissement d'adresse non posée (`DisabledComponents=0xFF`), profil périmé, refus par un Orion antérieur |
| T20 | fusionné | — |
| Correctif split-tunnel | fusionné | un CIDR invalide est refusé (API 400, orchestrateur conserve la politique) ; `heliosd run` refuse aussi de démarrer sur un `network.toml` dont la politique ne compile pas |
| T21 | fusionné : rejet ICMPv6 « admin-prohibited » du forward IPv6 `wg_iface` → WAN dans tous les états, pas de NAT66 | cible : affichage `nft`, réponse ICMPv6 1/1, `curl -6` immédiat, navigateur dual-stack sans délai, `net.ipv6.icmp.ratelimit` |
| Split-tunnel limité au LAN | fusionné : les contournements de split-tunnel portent `iifname <lan>` dans les deux familles, aucun sans interface LAN ; ni le tunnel ni un WAN ne les atteignent | cible : `nft list chain inet helios forward` |
| Portail captif limité au LAN | fusionné : les ouvertures `forward` HTTP/HTTPS du portail portent `iifname <lan>`, aucune sans interface LAN ; `output` inchangé | cible : `nft list chain inet helios forward` en portail captif |
| T15 | encodeur livré | MSS IPv4 = MTU − 40 et IPv6 = MTU − 60 ; `exthdr` dans le même batch atomique, chaîne `mss` avant filtrage, SYN/SYN-ACK traversant WireGuard seulement. IPv6 omis sous MTU 1280 ; ABI et rendu testés. Cible : réécriture, somme TCP, valeur déjà inférieure conservée |
| T22 | fusionnable : `scripts/netns-bench.sh` | premier passage : rejet IPv6 de T21 jamais atteint avec `forwarding = 0` (TESTING.md, « Banc netns ») |
| T23 | à faire | — |

**T00 — Spécification A : modèle d'adressage IPv6**
- Fichiers : [`docs/specification/ADRESSAGE-IPV6.md`](../specification/ADRESSAGE-IPV6.md), index `docs/README.md`.
- Dépend : aucune ; bloque T07, T10–T14, T16.
- Contenu à trancher, une à deux pages :
  - VIP IPv4 CGNAT `/32` obligatoire et unique, inchangé ;
  - VIP IPv6 `/128` optionnel, jamais un `/64` par pair ;
  - préfixe ULA `/64` de la gateway : configuré ou dérivé **une fois** à l'initialisation puis persisté (et effet d'une rotation de clé gateway) ;
  - dérivation de l'hôte v6 et exclusions (`::0`, `::1`) ;
  - forme `PeerVips { v4, v6: Option }` et champs `_v6` dans `network.toml` ;
  - rôle du v6 dans l'identité API : l'API reste-t-elle sur le VIP v4 seul ;
  - « IPv6-only » limité au transport, pas au tunnel interne.
- Risque : nul (doc). Acceptation : spécification relue et validée par l'opérateur avant tout code de phase 1.

**T01 — Orion : capturer `::/0` par défaut**
- Fichiers : `crates/orion-core/src/config.rs` (`DEFAULT_ALLOWED_IPS`), `apps/orion/src/splitTunnel.ts` (`EVERYTHING`), `tools/helios-ctl/src/profile.rs`, `docs/adr/ADR-001-WIREGUARD.md` §3 bis.
- Changement : `"0.0.0.0/0, ::/0"`. Un profil enregistré avec `0.0.0.0/0` seul n'est jamais réécrit : `matchPreset` le lit comme `custom`, et Orion comme `helios-ctl` le signalent « tunnel complet IPv4 seulement » (décision opérateur : avertir sans réécrire).
- Tests : unitaires Rust et Vitest ; VM Windows dual-stack : `curl -6` échoue tunnel monté.
- Risque : moyen (apps v6-first ralenties jusqu'au repli v4).
- Acceptation : aucun paquet v6 sur l'interface physique tunnel monté (capture sur VM).

**T02 — Orion : vérifier les `AllowedIPs` réellement posés**
- Fichiers : `crates/orion-core/src/backend/wireguard.rs`.
- Dépend : T01.
- Changement : relire la configuration du pilote **et** les routes portées par l'adaptateur après `configure_interface` (voir §8.2 : le pilote garde `::/0` même quand la route n'est pas créée) ; si un préfixe demandé manque, état explicite et événement visible, sans démonter l'adaptateur.
- Tests : unitaire sur la comparaison ; VM avec IPv6 désactivé sur l'adaptateur.
- Risque : faible. Acceptation : écart signalé à l'UI.

**T03 — Firewall : verrouiller l'absence de relais IPv6**
- Fichiers : `crates/helios-firewall/src/ruleset/tests/golden.rs`, `egress.rs`.
- Changement : tests seulement, qui échoueront avec T04/T05 si un relais v6 apparaît.
- Risque : nul. Acceptation : golden verts, documentés dans `FIREWALL-V2.md`.

**T04 — Firewall : masquerade limité à IPv4**
- Fichiers : `crates/helios-firewall/src/ruleset/nftables.rs` (`Ruleset::masquerade_out`), `netlink/transaction.rs`.
- Changement : la règle NAT porte `meta nfproto ipv4` ; décider (et documenter) le scope `iifname wg_iface`.
- Tests : octets Netlink ; golden ; cible : `nft list chain inet helios postrouting`.
- Risque : moyen (NAT client). Acceptation : NAT44 inchangé sur cible.

**T05 — Firewall : ND, RA, MLD, DHCPv6 sur le WAN**
- Fichiers : `crates/helios-firewall/src/ruleset/gateway_wan.rs`, `nftables.rs` (`Match::IcmpType`), `netlink/expressions.rs`.
- Changement : `Match::IcmpType` (ICMPv6 via `TransportHeaderField::ICMPv6(Type)`) ; règles §9.1 dans tous les états ; DHCPv6 derrière `allow_dhcp_on_wan` (ou un drapeau distinct, décision).
- Tests : golden par état, octets, cible avec WAN SLAAC.
- Risque : moyen. Acceptation : `ip -6 neigh` peuplé et route par défaut v6 stable > durée de vie RA, sous policy drop.

**T06 — Meshnet : réseaux locaux v6**
- Fichiers : `crates/helios-firewall/src/ruleset.rs`, `meshnet.rs`, `crates/aether/src/config.rs` (`valid_ipv4_cidr`).
- Changement : liste privée par famille, ICMP par famille du pair ; n'accepter les CIDR v6 qu'après.
- Tests : golden. Risque : faible.

**T07 — `aether::net`**
- Fichiers : nouveau `crates/aether/src/net.rs`, `crates/aether/Cargo.toml` (`ipnetwork` déjà au lockfile).
- Changement : `TunnelAddress`, `PeerVips`, parse/Display compatibles avec les chaînes actuelles, `canonical_source`.
- Tests : unitaires, fuzz harness dans `aether::fuzzing` pour les parseurs.
- Risque : faible. Acceptation : aucun appelant migré encore.

**T08 — Canonicaliser les sources**
- Fichiers : `crates/aether-key-negotiation/src/rate_limit.rs` (`rate_bucket`), `crates/helios-api/src/auth.rs`, limiteurs Astra.
- Dépend : aucune (phase 0) ; T07 pourra ensuite regrouper l'appel dans `aether::net`.
- Changement : `IpAddr::to_canonical()` avant bucket et comparaison.
- Tests : `::ffff:a.b.c.d` → bucket v4. Risque : faible. Acceptation : prérequis à T17.

**T09 — Bind typé**
- Fichiers : `crates/aether/src/config.rs` (`api_bind`, `speedtest_bind`), `heliosd/src/daemon.rs`.
- Changement : retourner un `SocketAddr` ; le bind reste l'hôte v4.
- Tests : unitaires. Risque : faible.

**T10 — Configuration `_v6`**
- Fichiers : `crates/aether/src/config.rs` (`NetworkConfig`, `WgPeer`, `PersistedNetworkConfig`, `validate_peer_identities`), `crates/aether/src/config/tests.rs`.
- Dépend : T07.
- Changement : `wg_address_v6`, `address_v6` optionnels, `/128` exigé, unicité sur l'union, ULA exigé (décision), adoption runtime inchangée.
- Tests : round-trip byte-identique des fichiers v4 ; refus v6 mal formé ; hot reload.
- Risque : élevé (persistance). Acceptation : `config/network.toml` relu et réécrit à l'identique.

**T11 — IPAM unifié (IPv4 et IPv6)**
- Fichiers : `crates/helios-provisioning/src/{ipam,admission,session}.rs`, `crates/helios-api/src/provision.rs` (`PeerAddressTable`).
- Dépend : T07, T10.
- Changement : spécification A §3 et §3 bis. Un seul point d'attribution rendant `PeerVips`, appelé à l'admission seulement ; une seule vue de collision (déclarés ∪ table vivante ∪ réservations, deux familles) remplaçant `DeclaredPeers` et `PeerAddressTable` ; dérivation ULA §3.1 avec exclusions §3.2.
- Tests : déterminisme, exclusions, collisions par famille, vue unique utilisée par tous les chemins d'admission.
- Risque : moyen (admission). Acceptation : spécification A §9, critères 3 à 5 et 10.

**T12 — WireGuard multi-adresses**
- Fichiers : `crates/helios-wireguard/src/{lib,kernel,dryrun}.rs`, `crates/heliosd/src/orchestrator/data_plane.rs` (`wg_config`).
- Dépend : T10.
- Changement : `Vec` pour adresses et `AllowedIPs` ; erreur typée si IPv6 indisponible ; refus v6 si MTU < 1280.
- Tests : `build_peer` multi ; dry-run ; cible. Risque : moyen.

**T13 — `vip_routing` v6**
- Fichiers : `crates/heliosd/src/vip_routing.rs`.
- Dépend : T10.
- Changement : `Plan` par famille, `ip -6`, flush v6 des règles ; retirer la « Limite connue ».
- Tests : commandes générées. Cible : NordVPN/Tailscale actifs. Risque : moyen.

**T14 — Admission et provisioning v6**
- Fichiers : `crates/helios-provisioning/src/{admission,session}.rs`, `crates/helios-api/src/provision.rs`, `crates/aether/src/enroll.rs`, `crates/orion-core/src/backend/mod.rs` (message d'écart).
- Dépend : T11.
- Changement : spécification A §3 bis.2 règles 1, 4 et 7 ; le provisioning renvoie l'adresse **persistée** (IPv4 comprise) au lieu de re-dériver ; `assigned_address_v6` optionnel (§7.1) ; réadmission idempotente qui n'ajoute que la famille manquante.
- Tests : le cas divergent du §3 bis.1 (critère 11) ; réadmission (critère 12).
- Risque : moyen. Corrige aussi un défaut IPv4 existant (deux vérités sur le VIP en cas de collision).

**T15 — MTU et MSS par famille**
- Fichiers : `crates/aether/src/mtu.rs`, `crates/heliosd/src/orchestrator/probes.rs`.
- Changement : helper « IPv6 interne possible » (≥ 1280) ; MSS v6 = MTU − 60.
- Tests : unitaires. Risque : faible.

**T16 — Auth API v6**
- Fichiers : `crates/helios-api/src/auth.rs`, `routes.rs` (vue redigée).
- Dépend : T08, T10.
- Portée réduite par la [spécification A](../specification/ADRESSAGE-IPV6.md) §2.6 : en v1, l'identité reste le VIP IPv4 ; le ticket se limite à exposer `address_v6` dans la vue redigée et à vérifier qu'une source IPv6 n'est jamais un appelant.
- Tests : §12. Risque : élevé (autorisation). Acceptation : tests de sécurité `security_tests.rs` étendus.

**T17 — Négociation sur IPv6**
- Fichiers : `crates/heliosd/src/key_negotiation/server.rs`.
- Dépend : T08.
- Changement : écoute `[::]` dual-stack ou deux endpoints (décision : `quinn` sur deux sockets double l'état).
- Tests : interop `key_negotiation/tests/interop.rs` en v6 loopback. Cible : client v6. Risque : moyen.

**T18 — Résolution RFC 8305 côté Orion**
- Fichiers : `crates/orion-core/src/key_negotiation.rs` (`resolve_remote`), `backend/mod.rs`, `backend/wireguard.rs`.
- Changement : une résolution, tentatives échelonnées, endpoint WG = adresse négociée (littéral, plus de second `getaddrinfo`).
- Tests : résolveur injecté. Risque : moyen.

**T19 — Profil et Orion dual-stack**
- Fichiers : `crates/orion-core/src/{config.rs,profile_import/*}`, `backend/wireguard.rs`, `apps/orion/src/*`, `tools/helios-ctl/src/profile.rs`.
- Dépend : T14.
- Changement : `address_v6`, deux adresses sur l'adaptateur, presets.
- Tests : import/export, rejet par Orion ancien documenté. Risque : moyen.

**T20 — UI gateway**
- Fichiers : `web/src/{types.ts,views/Clients.tsx,views/System.tsx}`.
- Dépend : T16. Risque : faible. Respecter MUI et composants existants.

**T21 — Spécification B : politique de sortie Internet IPv6**
- Fichiers : nouvelle spécification sous `docs/specification/`, ou section ajoutée à la spécification A.
- Dépend : T00 ; peut être rédigé en parallèle des phases 1–3.
- Contenu : blackhole/reject en V1, NAT66 en opt-in (`allow_client_internet_v6`), préfixe GUA routé comme évolution ; sysctls (`forwarding`, `accept_ra = 2`) documentés, jamais modifiés en silence.
- Risque : nul (doc). Bloque toute ouverture `forward` v6.

**T22 — Banc netns**
- Fichiers : `scripts/` (nouveau), `docs/testing/TESTING.md`.
- Changement : deux netns + veth, gateway `--features netlink,wireguard`, scénarios §12.
- Risque : faible. Linux natif ou VM uniquement.

**T23 — Campagne cible IPv6**
- Fichiers : `scripts/target_campaign.py`, `docs/testing/TESTING.md`.
- Dépend : T05, T12, T13, T17, T19.
- Acceptation : scénarios 1–17 exécutés, résultats consignés, régression IPv4 complète.

---

## Synthèse

```text
IPv6 readiness: 3,5/10

Blocages majeurs:
- Adressage tunnel IPv4-only de bout en bout : IPAM u32 (ipam.rs), VIP /32 exigé
  (config.rs:735), une seule adresse par interface et par pair (helios-wireguard lib.rs:73,99).
- Identité API par comparaison de chaîne sur un /32 (auth.rs:122-131).
- Firewall sans ND/RA/MLD/DHCPv6 : une gateway au WAN IPv6 perd sa connectivité v6.
- Orion capture 0.0.0.0/0 seulement : fuite IPv6 actuelle.
- Négociation QUIC écoutant 0.0.0.0 uniquement (server.rs:118).

Refactors nécessaires avant IPv6:
- Type canonique d'adresse tunnel dans aether (fin de la dizaine de parseurs texte).
- Canonicalisation des sources (::ffff:) avant tout bind [::].
- Masquerade scopé à nfproto ipv4 ; décision NAT66 formalisée par spécification.
- vip_routing paramétré par famille.

Fonctionnalités déjà compatibles:
- Table nftables inet, IR typée IpNetwork, garde nfproto émise par rustables.
- ct state invalid / established,related communs aux deux familles.
- ICMPv6 sur le tunnel ; type ICMPv6 encodable avec rustables 0.8.7.
- Endpoints [v6]:port validés, AllowedIPs multi-familles, pinning socket v6 (net_pin).
- Budget de négociation par /64, détection de route par défaut ::/0 (uplink.rs).
- Surcoût MTU calculé sur l'en-tête externe IPv6.

Ordre recommandé:
1. Phase 0 : ::/0 Orion, masquerade v4, golden anti-relais v6, canonicalisation ::ffff:, ND/RA WAN.
2. Spécification A : modèle d'adressage IPv6 (avant tout code d'adressage).
3. Types aether::net, bind typé.
4. Configuration _v6 rétrocompatible, IPAM ULA, WireGuard multi-adresses, vip_routing v6.
5. Auth API, négociation v6, résolution RFC 8305, profil Orion dual-stack.
6. Spécification B : sortie Internet IPv6, puis banc netns et campagne cible.
```

**Justification de la note.** Douze axes notés 0, ½ ou 1 selon ce que le code
montre, puis ramenés sur 10 :

| Axe | Note | Élément observé |
| --- | --- | --- |
| IR firewall | 1 | `IpNetwork`, `AddressFamily` |
| Backend Netlink | ¾ | `inet`, `nfproto` ; pas de ND, NAT non scopé |
| Modèle de configuration | ¼ | `String`, v4 imposé |
| IPAM | 0 | `u32` |
| Routage VIP | 0 | `Ipv4Addr`, limite documentée |
| WireGuard gateway | ½ | `defguard` générique, champs uniques |
| Orion | ½ | endpoint/AllowedIPs v6 ; défaut v4, adresse unique |
| API | ¼ | `IpAddr`, mais `/32` textuel |
| Négociation | ½ | budget `/64` ; écoute v4 |
| DNS | ¼ | premier résultat, pas de RFC 8305 |
| Noyau (ND, RA, sysctls) | 0 | rien |
| Tests | ¼ | quelques unitaires v6, pas de netns |
| **Total** | **4,25 / 12 ≈ 3,5 / 10** | |

Ce qui reste à vérifier sur cible et n'a pas pu l'être ici : classement
`untracked` des messages ND par conntrack, application du masquerade `inet` aux
paquets IPv6, retrait de l'IPv6 d'une interface sous 1280 octets, écoute
dual-stack du module WireGuard, DAD sur `helios0`, comportement de
`wireguard-nt` avec `::/0` quand l'IPv6 est désactivé sur l'adaptateur.

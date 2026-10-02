# Spécification — modèle d'adressage IPv6 du tunnel

**Statut** : proposée le 30 septembre 2026, **validée par l'opérateur le
1er octobre 2026**, en cours d'implémentation sur `feature/support-ipv6` (§4 et §5 livrés par T07 et T10, §3, §3 bis et §7.1 par T11 et T14, §6.1 à §6.3 par T12 et T13). La validation porte aussi sur l'IPAM
unifié du §3 bis, qui absorbe une partie du chantier « IPAM / adressage
unifié ». Elle fixe
les décisions d'adressage que l'étude
[ETUDE-IPV6.md](../architecture/ETUDE-IPV6.md) laissait ouvertes (ticket T00).
Les tickets T07 et T10 à T14 de l'étude l'appliquent ; aucun ne doit trancher
autrement un point décidé ici.

Elle ne traite pas la sortie Internet IPv6 des clients (spécification B,
ticket T21). Tant que cette spécification B n'existe pas, **aucun paquet IPv6
n'est relayé** entre `wg_iface` et un WAN.

Le vocabulaire normatif est « doit », « ne doit pas », « peut ». Les
identifiants de code sont en anglais ; les noms de types sont des cibles, pas
des symboles existants.

## 1. Périmètre

Couvert :

- l'adresse IPv6 de la gateway dans le tunnel et celle de chaque pair ;
- la génération et la stabilité du préfixe tunnel ;
- la dérivation déterministe de l'adresse d'un pair ;
- le format de persistance (`network.toml`), de provisioning et de profil ;
- la projection vers WireGuard, le routage VIP et le firewall ;
- le rôle de l'adresse IPv6 dans l'identité.

Hors périmètre :

- la sortie Internet IPv6 (spécification B) ;
- l'adressage IPv6 du LAN (RA, DHCPv6, délégation de préfixe) : Helios
  n'adresse pas non plus le LAN en IPv4 ;
- un préfixe global (GUA) dans le tunnel : il relève de la spécification B ;
- un tunnel sans adresse IPv4 (§2.7).

## 2. Décisions

### 2.1 L'IPv4 reste obligatoire et inchangée

Chaque pair a exactement un VIP IPv4 `/32` dans `100.64.0.0/10`, attribué par
l'IPAM CGNAT existant (`helios_provisioning::ipam`). Cette spécification ne
change ni la dérivation, ni la validation, ni le routage de ce VIP.

### 2.2 L'IPv6 est optionnelle, par gateway puis par pair

- Une gateway sans `wg_address_v6` se comporte **exactement** comme
  aujourd'hui : aucun pair n'a de VIP IPv6, et rien de nouveau n'apparaît dans
  les fichiers, les profils, les routes ni le ruleset.
- Une gateway avec `wg_address_v6` attribue un VIP IPv6 à chaque pair admis
  ensuite, et à chaque pair existant qui en reçoit un par réadmission ou par
  déclaration de l'opérateur (§5.3).

### 2.3 Un pair a au plus une adresse IPv6, en `/128`

Jamais un `/64` ni un préfixe plus large par pair. Un pair libre de choisir son
adresse dans un préfixe pourrait émettre depuis plusieurs sources (adresses
temporaires RFC 8981), ce qui rendrait ambiguë toute association « adresse
source → pair ».

### 2.4 Le préfixe tunnel est un ULA `/64`

- Forme : `fdXX:XXXX:XXXX:0000::/64` — préfixe ULA `fd00::/8` (bit L = 1,
  RFC 4193), Global ID de 40 bits, Subnet ID `0000`.
- Adresse de la gateway : `<préfixe>::1`, donc `wg_address_v6 =
  "fdXX:XXXX:XXXX::1/64"`.
- Tout autre préfixe est refusé en v1 : un préfixe `fc00::/8` (L = 0, non
  défini), un GUA, un préfixe autre que `/64`, une adresse gateway autre que
  `::1`.

Le choix d'un ULA suit celui du CGNAT pour l'IPv4 : un espace privé, stable, que
la gateway attribue seule. Avec une source ULA, la table de politique RFC 6724
fait préférer l'IPv4 aux clients dual-stack pour les destinations globales, ce
qui garde le comportement actuel du trafic Internet.

### 2.5 Le préfixe est aléatoire, généré une fois, puis persisté

- Le Global ID est tiré **une fois** par `aether::random::fill_public`, par une
  commande opérateur explicite, et écrit dans `network.toml`. L'opérateur peut
  aussi l'écrire à la main.
- Il n'est **jamais** régénéré automatiquement, ni dérivé à chaque démarrage.
- Il n'est **pas** dérivé de la clé WireGuard de la gateway : une rotation de
  cette clé renumérotait sinon tous les pairs.

Changer le préfixe est un acte opérateur. Il renumérote tous les VIP IPv6 et
rend l'adresse IPv6 des profils déjà émis invalide. Le tunnel IPv4 de ces
profils continue de fonctionner (§2.6).

### 2.6 L'identité et le plan de contrôle restent en IPv4

En v1 :

- l'API d'administration, la release post-commit
  (`POST /api/key-negotiation/release`), le provisioning in-tunnel
  (`POST /api/provision`) et le speedtest écoutent sur le VIP IPv4 de la
  gateway seulement ;
- la résolution de l'appelant (`helios_api::auth`) ne s'appuie que sur le VIP
  IPv4 ; le VIP IPv6 n'est **pas** une source d'identité ;
- `heliosd_url` reste une URL IPv4.

Conséquence voulue : aucun invariant d'autorisation ne change. Ouvrir l'API en
IPv6 serait une évolution distincte, avec sa propre spécification.

Indépendamment de cette spécification, `auth` doit comparer des `IpAddr`
typées et canonicalisées (`to_canonical()`), et non des chaînes (ticket T08).

### 2.7 « IPv6-only » désigne le transport, pas le tunnel

- **Transport** : l'endpoint UDP (WireGuard et négociation) peut être IPv6. Ce
  point ne dépend pas du préfixe tunnel et n'est pas contraint ici.
- **Tunnel** : un pair a toujours son VIP IPv4. Un tunnel qui ne porterait que
  de l'IPv6 n'est pas une cible, puisque le plan de contrôle est en IPv4
  (§2.6).

## 3. Dérivation du VIP IPv6 d'un pair

### 3.1 Formule

```text
IID(pubkey, n) = BLAKE3("helios-ipam-v6-v1" || pubkey || n_le32)[0..8]
VIP6           = préfixe_gateway | IID          (64 bits bas)
```

- `pubkey` : les 32 octets bruts de la clé publique WireGuard du pair, comme
  pour l'IPv4.
- `n` : compteur de sondage, `u32` little-endian, en partant de 0.
- Le séparateur de domaine est obligatoire : l'IPv4 dérive
  `BLAKE3(pubkey || n)` sans séparateur, et les deux dérivations ne doivent pas
  partager leur entrée.
- La chaîne `helios-ipam-v6-v1` est figée : la changer renumérote tous les
  pairs.

### 3.2 Identifiants exclus

Un candidat est rejeté, et le compteur incrémenté, si son IID est :

- `0` (anycast Subnet-Router, RFC 4291) ;
- `1` (la gateway) ;
- `≥ 0xfdff_ffff_ffff_ff80`. La RFC 5453 ne réserve que la plage
  `fdff:ffff:ffff:ff80` à `fdff:ffff:ffff:ffff` (anycast de sous-réseau) ;
  l'exclusion est volontairement plus large, d'un seul seuil, au prix de moins
  de 1 % de l'espace. Elle est figée : la changer renumérote des pairs.

### 3.3 Collisions

- Même borne que l'IPv4 : `MAX_VIP_PROBES` (64). Au-delà : `IpamError::Exhausted`.
- La table de collision est la vue unique du §3 bis, commune aux deux
  familles.
- Les compteurs IPv4 et IPv6 sont **indépendants** : une collision IPv4
  n'avance pas le compteur IPv6.

Sur 2^64 identifiants, une collision est un garde-fou, pas un cas nominal.

## 3 bis. IPAM unifié (IPv4 et IPv6)

L'IPv6 ne doit pas ajouter un second IPAM à côté du premier. Cette section
fixe un seul mécanisme d'attribution, une seule vue des collisions et une seule
source de vérité pour les deux familles. Elle s'applique aussi à l'IPv4
existant.

### 3 bis.1 Constat sur l'IPv4 actuel

Deux vues de collision coexistent aujourd'hui :

- `DeclaredPeers` (`helios-provisioning/src/admission.rs`) lit les pairs
  déclarés dans `network.toml` et réserve l'adresse de la gateway. Elle sert à
  l'admission.
- `PeerAddressTable` (`helios-api/src/provision.rs`) lit la table WireGuard
  vivante. Elle ne réserve pas l'adresse de la gateway et ne voit pas un pair
  déclaré mais absent du plan de données. Elle sert au provisioning in-tunnel.

`helios_provisioning::session` **re-dérive** le VIP à chaque provisioning
(`assign_vip` sur la table vivante) et le renvoie dans
`ProvisionResponse::assigned_address`. Si l'admission a dû résoudre une
collision contre un pair déclaré qui n'est pas connecté, le provisioning
retombe sur une autre adresse que celle qui a été déclarée :

- la gateway garde l'adresse déclarée et journalise l'écart
  (`heliosd/src/orchestrator/data_plane.rs`, installation de PSK) ;
- Orion journalise « corriger le profil puis se reconnecter » vers l'adresse
  dérivée (`orion-core/src/backend/mod.rs`). Suivre ce conseil casserait le
  tunnel, puisque les `AllowedIPs` de la gateway portent l'adresse déclarée.

Le cas exige une collision, il est donc rare ; mais il y a deux vérités.

### 3 bis.2 Règles

1. **Un seul point d'attribution.** `helios_provisioning::ipam` expose une
   fonction qui rend un `PeerVips` complet (§4) : le VIP IPv4, et le VIP IPv6
   si la gateway a un préfixe. Elle est appelée **uniquement à l'admission**,
   par tous les chemins d'admission (`heliosd peer`, `helios-ctl peer`,
   admission avec identité de négociation), conformément à l'ADR-004 §5.
2. **Une seule vue des collisions.** Une seule fonction construit la vue, pour
   les deux familles, comme l'union de :
   - les adresses déclarées dans `network.toml` (`address`, `address_v6`) ;
   - les `AllowedIPs` de la table WireGuard vivante, toutes familles ;
   - les réservations : l'hôte de `wg_address`, `<préfixe>::1`, les IID exclus
     du §3.2, et les hôtes réservés du `/10` déjà écartés par l'IPAM IPv4.

   Le propriétaire d'une entrée est la clé publique brute ; un pair n'entre
   jamais en collision avec lui-même.
3. **La persistance fait foi.** L'adresse attribuée est écrite dans
   `network.toml` à l'admission, comme aujourd'hui pour l'IPv4. La dérivation
   sert à **choisir** une adresse, jamais à la **retrouver** : aucun chemin ne
   re-dérive l'adresse d'un pair déjà admis.
4. **Le provisioning rend l'adresse persistée.** `session.rs` et
   `POST /api/provision` renvoient le `PeerVips` déclaré du pair, sans appeler
   l'IPAM. Un pair admis sans adresse lisible est une erreur nommée, pas une
   occasion de dériver.
5. **Pas de résolution automatique a posteriori.** Deux pairs déclarés avec la
   même adresse (édition manuelle) sont refusés par `NetworkConfig::validate`
   (existant en IPv4, étendu à l'IPv6 par le §5.2). L'IPAM ne renumérote
   jamais un pair déclaré.
6. **Familles indépendantes.** Compteurs de sondage distincts (§3.3).
   Attribuer l'IPv6 d'un pair existant ne touche pas à son IPv4.
7. **Réadmission idempotente.** Réadmettre une clé déjà admise rend les mêmes
   adresses. Si la gateway a gagné un préfixe IPv6 depuis, seule la famille
   manquante est attribuée ; l'IPv4 déclarée reste telle quelle.

### 3 bis.3 Ce qui reste hors de l'IPAM

- L'adresse de la gateway (`wg_address`, `wg_address_v6`) : configuration
  opérateur, réservée par l'IPAM mais jamais attribuée par lui.
- Le routage VIP (§6.3) et les `AllowedIPs` (§6.1) consomment le `PeerVips`
  persisté ; ils ne dérivent rien.

### 3 bis.4 Implémentation (T11/T14)

Cette section décrit où vivent les règles ci-dessus ; elle ne change aucune
décision.

- Dérivation : `helios_provisioning::ipam` — `derive_cgnat_ip` (IPv4,
  inchangée) et `derive_ula_iid` (§3.1). Les huit octets du condensat sont lus
  dans l'ordre de l'adresse (gros-boutiste) : l'identifiant `fdff:ffff:ffff:ff80`
  du §3.2 se compare donc comme le nombre `0xfdff_ffff_ffff_ff80`. Un vecteur
  de référence fige la formule : la clé `[7u8; 32]` donne l'IID
  `0xf545e4780e887a7f` au compteur 0.
- Vue unique : `AddressView::new` (privé à la crate) construit la table de
  collision des deux familles à partir des pairs déclarés, de la table
  WireGuard vivante (`LivePeer`) et des réservations. Les IID exclus, `::1` et
  tout ce qui sort du préfixe sont réservés par
  `TunnelPrefixV6::check_peer_vip` ; les deux hôtes réservés du `/10` restent
  écartés par la dérivation IPv4. `DeclaredPeers`, `PeerAddressTable`, le
  trait `PeerTable` et `assign_vip` n'existent plus.
- Point d'attribution unique : `AddressView::assign`, privé lui aussi, appelé
  par `admission::admit_with_key_negotiation` seulement. Il rend un `PeerVips`
  complet, garde toute adresse déclarée et n'attribue que la famille manquante.
- Table vivante à l'admission : `POST /api/peers` (chemin de `helios-ctl peer`
  et `helios-ctl enroll`) passe l'instantané que l'orchestrateur republie ;
  `heliosd peer add` n'en passe aucun, ce processus n'ayant pas de plan de
  données. Les pairs déclarés sont toujours dans la vue.
- Réadmission : même nom, même clé et même identité (rôle, empreintes,
  plancher) rendent `Unchanged`, ou `Ipv6Added` si la gateway a gagné un
  préfixe depuis ; une autre identité est refusée (`ReadmissionDiffers`). Une
  réadmission n'écrit `network.toml` que si elle l'a modifié, et n'enregistre
  aucune génération de certificats.
- Provisioning : `session::handle_request` lit `WgPeer::vips` et remplit
  `assigned_address` et `assigned_address_v6` ; une adresse déclarée illisible
  donne `EnrollError::UndeclaredAddress` (HTTP 500). L'avertissement d'écart de
  l'installation de PSK (`heliosd`) reste comme garde-fou : il ne se déclenche
  plus que si `network.toml` a été rechargé entre la lecture et
  l'installation. Côté Orion, un écart signale un profil périmé, à faire
  réémettre par l'opérateur ; Orion ne réécrit pas le profil.

## 4. Types canoniques

Dans un module `aether::net` (ticket T07). `ipnetwork` est déjà au
`Cargo.lock` via `helios-firewall` ; aucune nouvelle crate.

```rust
/// Tunnel prefix of the gateway: an ULA /64 whose host ::1 is the gateway.
/// Construction refuses anything else (§2.4).
pub struct TunnelPrefixV6(Ipv6Addr);

/// Every address a peer owns inside the tunnel. Two fields rather than a
/// list: "no v4" and "two v6" cannot be written.
pub struct PeerVips {
    pub v4: Ipv4Addr,
    pub v6: Option<Ipv6Addr>,
}
```

Ces types exposent le rendu texte actuel (`100.64.1.2/32`, `fd…/128`) pour que
la persistance reste compatible. Le domaine ne manipule plus d'adresse en
`String` une fois le fichier lu.

Implémentation : `crates/aether/src/net.rs` (`TunnelPrefixV6`, `PeerVips`,
`canonical_source`, erreur `AddressError`), sans dépendance à `ipnetwork`.

## 5. Persistance

### 5.1 `network.toml`

```toml
wg_address    = "100.64.0.1/10"            # inchangé, obligatoire
wg_address_v6 = "fd3c:91a2:7e04::1/64"     # nouveau, optionnel

[[peers]]
name       = "laptop"
address    = "100.64.98.223/32"            # inchangé, obligatoire
address_v6 = "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/128"   # nouveau, optionnel
```

- Clés **séparées**, pas de liste : la clé `address` garde sa forme actuelle,
  sur le modèle de `wan_iface`.
- `PersistedNetworkConfig` n'écrit `wg_address_v6` et `address_v6` que s'ils
  sont présents. Un fichier sans IPv6 doit être relu puis réécrit **à
  l'identique, octet pour octet**.
- La vue API redigée (`GET /api/network`) expose `wg_address_v6` et
  `address_v6` ; elles ne sont pas secrètes. La règle « ne jamais reconstruire
  `network.toml` depuis cette vue » s'applique inchangée.
- `GET /api/status` porte aussi `address_v6` sur chacun de ses `peers` (même
  forme, `null` sans VIP IPv6), et `POST /api/peers` le renvoie : la console
  l'affiche sur la ligne du client qu'elle lit déjà, sans joindre une seconde
  requête par clé publique.

### 5.2 Validation (`NetworkConfig::validate`)

Refusé, avec une erreur nommée :

- `wg_address_v6` hors des règles du §2.4 ;
- `address_v6` présent alors que `wg_address_v6` est absent ;
- `address_v6` qui n'est pas un `/128` ;
- `address_v6` hors du préfixe de la gateway, ou égal à `::1` ;
- `address_v6` présent en double ;
- un IID exclu par le §3.2.

L'unicité IPv4 existante (`validate_peer_identities`) reste inchangée.

### 5.3 Adresse déclarée et adresse dérivée

Comme pour l'IPv4 (`heliosd/src/orchestrator/data_plane.rs`, installation de
PSK), l'adresse **déclarée** fait foi : si elle diffère de la dérivée, elle est
conservée et l'écart est journalisé. Changer l'`AllowedIPs` d'une session
vivante couperait le trafic.

Un pair existant sans `address_v6` n'en reçoit pas en silence au démarrage :
l'attribution passe par l'admission (`helios_provisioning::admission`), par la
réadmission, ou par une déclaration explicite.

### 5.4 Rechargement à chaud

- `address_v6` d'un pair : rechargé à chaud, par le chemin d'adoption existant
  (`NetworkConfig::adopt_runtime_secrets_from`), comme la table des pairs.
- `wg_address_v6` : exige un redémarrage, comme les autres paramètres que le
  plan de données ne peut pas changer en marche.

Implémentation (T10) : `crates/aether/src/config.rs`. Les deux clés sont
typées dès la lecture (`TunnelPrefixV6`, et un hôte `Ipv6Addr` écrit `…/128`),
ce qui refuse une forme invalide avant `validate` ; `validate_peer_vips_v6`
porte le reste du §5.2. `NetworkConfig::check_hot_reload` refuse tout
rechargement qui change `wg_address_v6` : le veilleur de `network.toml` le
journalise, l'orchestrateur l'émet comme événement, et `POST /api/network`
répond `409` sans rien écrire. Le round-trip octet pour octet est vérifié sur
le chemin d'écriture réel (`save` et `save_redacted`) avec un fichier de
production sans IPv6 ; `config/network.toml`, commenté à la main, atteint sa
forme normale à la première réécriture (les commentaires ne sont pas de la
configuration), puis n'en bouge plus.

## 6. Projection vers le plan de données

### 6.1 WireGuard

- Interface gateway : `[wg_address, wg_address_v6?]`.
- `AllowedIPs` d'un pair côté gateway : **exactement** `{v4/32}` plus
  `{v6/128}` s'il existe. Aucun autre préfixe n'est ajouté par cette
  spécification. La cryptokey routing assure ainsi le contrôle de source sur
  `wg_iface` pour les deux familles.

### 6.2 Conditions d'installation de l'IPv6

L'adresse IPv6 de l'interface n'est pas posée, et la gateway démarre en IPv4
seule dans un état **dégradé visible**, si :

- `tunnel_mtu(...) < 1280` (minimum IPv6, RFC 8200) ;
- le noyau refuse l'adresse (par exemple `disable_ipv6 = 1`).

L'échec porte une erreur typée et nommée. Il est journalisé, diffusé comme
événement, et exposé par l'API et le CLI. Ce n'est pas une ouverture : les
clients qui capturent `::/0` voient leur IPv6 jetée par WireGuard, comme sans
VIP IPv6.

### 6.3 Routage VIP

`heliosd::vip_routing` applique à l'IPv6 le même plan qu'à l'IPv4 :

- une route `/128` par pair dans la table `51820`, `dev <wg_iface> src
  <préfixe>::1` ;
- une règle `to <préfixe>/64 lookup 51820 priority 32000`, en famille IPv6 ;
- purge et retrait par famille : `ip -4` et `ip -6` sont distincts.

### 6.4 Firewall

Cette spécification n'ajoute aucune ouverture. En particulier :

- le `forward` de `wg_iface` vers un WAN reste **IPv4 seulement** ;
- le masquerade reste `meta nfproto ipv4` (ticket T04) ;
- l'ICMPv6 sur `wg_iface` suit `allow_tunnel_icmp`, comme aujourd'hui.

Entre pairs, le trafic IPv6 obéit aux mêmes règles que l'IPv4 : le `forward`
de `wg_iface` vers `wg_iface` n'est pas ouvert aujourd'hui, et cette
spécification ne l'ouvre pas.

### 6.5 Implémentation (T12/T13)

Cette section décrit où vivent les règles ci-dessus ; elle ne change aucune
décision.

- Plan de données : `helios_wireguard::InterfaceConfig::addresses` et
  `PeerConfig::allowed_ips` sont des listes, passées telles quelles à
  `defguard` par le backend noyau. `heliosd` les construit en un seul endroit,
  `orchestrator::data_plane::wg_config`, utilisé par la montée, l'installation
  de PSK et le rechargement : l'IPv4 déclarée d'abord, puis `<préfixe>::1/64`
  et le `/128` de chaque pair **seulement** si la montée a installé l'IPv6.
- Conditions du §6.2 : `ipv6_installability` écarte l'IPv6 avant la montée si
  `tunnel_mtu < 1280` (`aether::mtu::carries_ipv6`), si
  `net.ipv6.conf.{all,default}.disable_ipv6` vaut `1`, ou si le noyau n'a pas
  de pile IPv6 (répertoire `conf` absent ; chemin remplaçable par
  `HELIOS_IPV6_CONF_PATH` pour les tests). Aucun sysctl n'est modifié.
- Refus par le noyau malgré ces vérifications : la montée échoue côté noyau
  (`WgError::Interface`) ; l'interface à moitié configurée est démontée, puis
  remontée **une fois** sans IPv6. Ni une clé ni une adresse refusées avant
  tout effet de bord ne sont retentées. Si le démontage échoue, le démarrage
  échoue en le disant ; si la remontée IPv4 échoue, l'erreur nomme les deux
  échecs. Le kill-switch reste engagé tout du long.
- État dégradé visible : `aether::net::Ipv6TunnelStatus` (`not_configured`,
  `installed`, `unavailable`) et sa raison typée `Ipv6Unavailable`
  (`tunnel_mtu_too_small`, `disabled_by_kernel`, `no_kernel_support`,
  `address_refused`). La raison est journalisée et diffusée en événement
  `warn`, publiée dans `GET /api/status` (champ `ipv6`) et affichée par
  `helios-ctl status`. `heliosd status`, qui ne parle pas au démon, applique
  les mêmes vérifications préalables sur l'hôte. Sans `wg_address_v6`, l'état
  est `not_configured` et rien d'autre ne change.
- Routage VIP : `heliosd::vip_routing::plan_v6` et `apply_v6` appliquent le
  plan du §6.3 en famille IPv6 (`ip -6`), à partir des `AllowedIPs`
  effectivement posés ; les règles et la table sont purgées et retirées par
  famille. Aucune commande `ip -6` n'est lancée si l'IPv6 n'est pas installée.
  Limite connue : une règle IPv6 laissée par un arrêt brutal n'est purgée qu'à
  la prochaine montée qui installe l'IPv6 ; elle reste inerte d'ici là, ses
  routes ayant disparu avec l'interface.
- Essais sur cible : [TESTING.md](../testing/TESTING.md), « IPv6 du tunnel ».

## 7. Provisioning et profil

### 7.1 `ProvisionResponse`

Nouveau champ `assigned_address_v6: Option<String>`, avec `serde(default)` et
omis quand il est absent. `ProvisionResponse` n'est pas
`deny_unknown_fields` : un Orion antérieur l'ignore. Aucun changement de
`PROTOCOL_VERSION`.

### 7.2 Document `orion-profile`

- Nouveau champ `address_v6`, optionnel.
- Le document est `deny_unknown_fields` : un Orion antérieur **refuse** un
  profil qui porte ce champ. C'est un refus explicite, pas une ouverture.
- `helios-ctl` n'émet `address_v6` que si le pair en a un. Un profil émis par
  une gateway sans IPv6 reste lisible par tous les Orion.
- Le message de refus d'un Orion antérieur est hors de notre contrôle ; la
  documentation opérateur indique la version d'Orion minimale.

### 7.3 Orion

- L'adaptateur porte les deux adresses.
- `AllowedIPs` n'est pas défini par cette spécification : la capture de
  `::/0` relève du ticket T01, qui s'applique avec ou sans VIP IPv6.

## 8. Compatibilité

| Situation | Comportement attendu |
| --- | --- |
| `network.toml` existant, sans IPv6 | inchangé, réécrit à l'identique |
| Gateway IPv6, Orion antérieur, profil sans `address_v6` | IPv4 seule, fonctionne |
| Gateway IPv6, Orion antérieur, profil avec `address_v6` | profil refusé à l'import |
| Gateway sans IPv6, Orion récent | IPv4 seule, aucun champ v6 |
| Préfixe changé par l'opérateur | IPv4 intacte ; IPv6 des anciens profils hors préfixe, donc jetée par WireGuard |
| Pair ancien, sans `address_v6`, sur gateway IPv6 | IPv4 seule jusqu'à réadmission ou déclaration |

## 9. Critères d'acceptation

Les implémentations des tickets T07 et T10 à T14 doivent au minimum démontrer :

1. le round-trip octet pour octet de `config/network.toml` et d'un fichier de
   production sans IPv6 ;
2. le refus de chaque cas du §5.2, avec un message qui nomme le champ ;
3. la dérivation déterministe : même clé → même VIP IPv6, sur deux instances et
   après redémarrage ;
4. l'indépendance des dérivations IPv4 et IPv6 (séparateur de domaine) ;
5. les exclusions du §3.2 et la borne `MAX_VIP_PROBES` ;
6. un ruleset **identique** à celui d'aujourd'hui quand `wg_address_v6` est
   absent (golden tests inchangés) ;
7. des `AllowedIPs` gateway égaux exactement à `{v4/32, v6/128}` ;
8. le démarrage dégradé visible du §6.2 ;
9. l'absence de changement dans `helios_api::auth` hors canonicalisation ;
10. un seul constructeur de vue de collision et un seul point d'attribution,
    utilisés par tous les chemins d'admission (§3 bis.2) ;
11. le cas divergent du §3 bis.1 : un pair A déclaré mais déconnecté tient le
    VIP naturel de B ; B est admis sur un VIP sondé ; le provisioning de B
    renvoie **son adresse déclarée**, et aucun avertissement d'écart n'est
    émis côté gateway ni côté Orion ;
12. la réadmission idempotente, y compris l'ajout de la seule famille IPv6.

Sur cible, en plus : ajout de l'adresse sur `helios0`, routes et règle de la
table `51820` en IPv6, `ping -6` gateway ↔ pair avec `allow_tunnel_icmp`.

## 10. Correspondance avec l'étude

| Ticket | Sections applicables |
| --- | --- |
| T07 `aether::net` | §4 |
| T10 configuration `_v6` | §5 |
| T11 IPAM unifié (IPv4 et IPv6) | §3, §3 bis |
| T12 WireGuard multi-adresses | §6.1, §6.2 |
| T13 `vip_routing` IPv6 | §6.3 |
| T14 admission et provisioning | §3 bis.2 (règles 1, 4 et 7), §5.3, §7.1 |
| T16 auth API | §2.6 : canonicalisation seulement en v1 |
| T19 Orion dual-stack | §7.2, §7.3 |

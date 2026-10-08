# Spécification — sortie Internet IPv6 des clients du tunnel

**Statut** : validée le 2 octobre 2026 pour la V1 (rejet explicite, §3.1),
**implémentée sur `feature/support-ipv6`** (§7) ; le critère 4 (sur cible)
reste à observer. Le NAT66 (§3.2) est écarté de ce chantier. C'est la
spécification B annoncée par [ADRESSAGE-IPV6.md](ADRESSAGE-IPV6.md) (ticket
T21 de [l'étude](../architecture/ETUDE-IPV6.md)). La règle de l'adressage §6.4
reste en vigueur : **aucun paquet IPv6 n'est relayé** entre `wg_iface` et un
WAN.

Le vocabulaire normatif est « doit », « ne doit pas », « peut ». Les décisions
qui attendent l'opérateur sont regroupées au §6.

## 1. Point de départ

Sur `feature/support-ipv6` :

- Orion capture `::/0` par défaut (T01) : l'IPv6 d'un poste client entre dans
  le tunnel au lieu de sortir en clair.
- La gateway attribue un VIP IPv6 ULA `/128` par pair et le projette sur
  WireGuard et le routage VIP (T11 à T14, T12, T13).
- Le forward `wg_iface` vers WAN et le masquerade portent `meta nfproto ipv4`
  (T03, T04). Les golden tests `ipv6_relay` verrouillent l'absence de tout
  relais IPv6.

Conséquence actuelle : un paquet IPv6 qu'un client envoie vers Internet entre
dans le tunnel, n'est accepté par aucune règle `forward` et tombe sous la
politique `drop`. Rien ne fuit. Mais un `drop` est silencieux : une application
qui tente l'IPv6 en premier attend son propre délai avant de passer à l'IPv4,
de 250 ms (RFC 8305) à plusieurs secondes selon la pile.

## 2. Options étudiées

| Option | Principe | Pour | Contre |
| --- | --- | --- | --- |
| A. Blackhole silencieux | état actuel | rien à faire, aucune fuite | repli IPv4 lent pour certaines applications |
| B. Rejet explicite | `reject` ICMPv6 « administratively prohibited » sur le forward IPv6 issu de `wg_iface` | aucune fuite, repli IPv4 immédiat | une réponse ICMP par paquet refusé (voir §4.2) |
| C. NAT66 (masquerade IPv6) | les VIP ULA sont traduits vers l'adresse IPv6 du WAN | destinations IPv6-only joignables | casse le bout-en-bout ; exige un WAN IPv6 et le forwarding IPv6 du noyau |
| D. Préfixe global routé | la gateway reçoit un préfixe GUA routé (statique ou DHCPv6-PD) et attribue des `/128` dedans | IPv6 natif sans traduction | exige que l'amont route un préfixe vers la gateway ; renumérotation ; hors de portée actuelle |

Le NAT66 n'est pas l'équivalent naturel du NAT44. Le NAT44 existe parce que
les VIP CGNAT ne sont pas routables ; en IPv6, la pénurie n'existe pas. Il se
justifie seulement pour un usage « sortie par la gateway » où la propriété
recherchée est la même que celle du NAT44 déjà en place, et avec une nuance :
avec une source ULA, la table de politique RFC 6724 (précédence ULA 3,
IPv4 35) fait préférer l'IPv4 aux clients dual-stack pour toute destination
qui a les deux familles. Le NAT66 ne sert donc qu'aux destinations IPv6-only.

## 3. Décision proposée

### 3.1 V1 : rejet explicite (option B)

- Tout paquet IPv6 entrant par `wg_iface` et destiné à sortir par un WAN doit
  être **rejeté** par `reject` de type ICMPv6 « administratively prohibited »
  (`icmpx admin-prohibited`, encodable par `rustables 0.8.7` :
  `RejectType::IcmpxUnreach` + `IcmpCode::AdminProhibited`).
- La règle vit dans `forward`, après `ct state invalid drop` et les
  ouvertures existantes, scopée `iifname <wg_iface>` + `meta nfproto ipv6` +
  `oifname <wan>` pour chaque uplink.
- Elle est rendue **dans tous les états** du tunnel. Hors `Up`, la politique
  `drop` suffirait, mais le rejet garde le repli rapide pendant `Connecting`.
- Elle n'ouvre rien : son verdict est terminal et refuse.
- Le trafic IPv6 d'un client vers la gateway elle-même (`<préfixe>::1`) reste
  régi par les règles `input` existantes (`allow_tunnel_icmp`, etc.).

### 3.2 Option NAT66 en opt-in explicite (option C)

Si l'opérateur la retient (§6), elle doit respecter :

1. **Un drapeau dédié**, par exemple `allow_client_internet_v6`, faux par
   défaut. Il n'est **jamais** déduit de `allow_client_internet`.
2. **Mêmes conditions que l'IPv4** : forward et masquerade n'existent que
   dans un état où le trafic est autorisé, et entrent dans la même transaction
   atomique que le filtrage.
3. **Type fermé** : `MasqueradeRule` porte aujourd'hui une famille constante
   (`FAMILY = Ipv4`). L'ouvrir à l'IPv6 doit garder l'invariant « aucun
   masquerade sans garde de famille » : deux constructeurs nommés, pas une
   famille libre.
4. **Prérequis signalés, jamais corrigés en silence** : si le drapeau est vrai
   et que `net.ipv6.conf.all.forwarding = 0`, un avertissement visible, comme
   pour `ip_forward` (`heliosd/src/orchestrator/data_plane.rs`). Passer le
   forwarding à 1 désactive l'acceptation des RA sur le WAN sauf
   `accept_ra = 2` : l'avertissement doit le dire. Helios ne modifie aucun
   sysctl.
5. **Sans IPv6 installée** (adressage §6.2) : le drapeau est sans effet et
   l'état le dit.
6. Le rejet du §3.1 reste en place pour les WAN sans route IPv6 par défaut.

### 3.3 Hors de portée

- L'option D (préfixe global routé, DHCPv6-PD, proxy NDP).
- Le DNS des clients : il n'est toujours pas tunnelisé (limite connue
  ADR-004 lot 5). Cette spécification n'aggrave ni n'améliore ce point.
- L'IPv6 du LAN (site-à-site) : le forward LAN vers WAN reste sans garde de
  famille (étude §13) ; une décision séparée est nécessaire.

## 4. Points d'attention

### 4.1 Ordre des règles

Le rejet doit suivre l'acceptation `ct state established,related`, sinon il
couperait les réponses d'un éventuel flux NAT66. Il doit précéder la politique
`drop`, qui ne laisse rien passer de toute façon.

### 4.2 Volume de réponses ICMPv6

`rustables 0.8.7` n'encode pas `limit` (`FIREWALL-V2.md`) : le rejet ne peut
pas être borné en débit dans le ruleset. La génération d'ICMPv6 du noyau est
limitée par `net.ipv6.icmp.ratelimit` (défaut 1000 ms par destination, à
vérifier sur cible). Le destinataire est le pair lui-même, à travers son
tunnel authentifié : pas d'amplification vers un tiers.

### 4.3 Interaction avec T18

Orion met déjà l'IPv6 et l'IPv4 en concurrence pour joindre la gateway. Le
rejet du §3.1 concerne le trafic **dans** le tunnel vers Internet, pas la
connexion à la gateway.

## 5. Critères d'acceptation

1. Golden : une règle de rejet IPv6 par uplink, dans chaque état, avec
   `meta nfproto ipv6` ; sans le drapeau NAT66, aucune règle `accept` de
   `forward` qu'un paquet IPv6 entrant par `wg_iface` peut atteindre, hormis
   le retour de flux `ct state established,related` ; la seule règle
   `accept` de `forward` qui sélectionne l'IPv6 est le contournement
   split-tunnel, borné à `iifname <lan>` (§7) ; tests `ipv6_relay` mis à jour
   en conséquence.
2. Octets Netlink : `reject` `icmpx` `admin-prohibited` encodé exactement.
3. Avec le drapeau NAT66 (si retenu) : forward et masquerade IPv6 présents
   seulement en `Up`, dans la même transaction, absents sinon.
4. Sur cible : depuis un client, `curl -6 https://…` échoue immédiatement
   (pas après un délai) avec le rejet, et un navigateur dual-stack charge un
   site A+AAAA sans délai visible ; avec NAT66, `curl -6` sur une destination
   IPv6-only réussit et `nft list chain inet helios postrouting` montre le
   masquerade IPv6.

## 6. Décisions de l'opérateur

Prises le 2 octobre 2026 :

1. **Rejet explicite (option B) en V1** : le §3.1 est normatif.
2. **Pas de NAT66 dans ce chantier** : le §3.2 reste la condition d'un futur
   opt-in, et les critères d'acceptation 3 et la partie NAT66 du critère 4
   ne s'appliquent pas à la V1.
3. Sans objet tant que le NAT66 est écarté. La portée du masquerade IPv4
   (uplink seul, ou aussi `iifname <wg_iface>`) reste une question ouverte
   distincte.

## 7. Implémentation de la V1

- **Rendu** : `crates/helios-firewall/src/ruleset/client_ipv6_egress.rs`,
  appelé en dernier par `ruleset::render`. Une règle par uplink, dans tous les
  états et sous les deux `mode`, aucune sans `wg_iface` :
  `meta nfproto ipv6 iifname "<wg_iface>" oifname "<wan>" reject with icmpx admin-prohibited`.
  Ce sont les dernières règles de `forward`.
- **IR** : `Verdict::RejectAdminProhibited`, variante fermée ; la politique
  des chaînes devient `DefaultVerdict` (`Accept` ou `Drop`), si bien qu'une
  politique de rejet n'est pas représentable
  ([FIREWALL-V2.md](../architecture/FIREWALL-V2.md)).
- **Netlink** : expression `Reject` (`RejectType::IcmpxUnreach`,
  `IcmpCode::AdminProhibited`), sans verdict après elle, dans la même
  transaction que le reste du ruleset.
- **Critère 1** : golden tests et `ruleset/tests/ipv6_relay.rs` (présence,
  forme exacte, ordre, aucun `accept` en `forward` ne prend l'IPv6 entrant
  par `wg_iface` ou par un WAN, aucun masquerade IPv6). **Critère 2** : octets de l'expression dans un `Batch` finalisé
  (`netlink/expressions.rs`). **Critère 4** : procédure « Sortie Internet IPv6
  refusée » de [MANUAL-TESTING.md](../testing/MANUAL-TESTING.md), non encore
  exécutée.
- **Split-tunnel** : par décision de l'opérateur, les contournements
  `split_tunnel_cidrs` ne s'appliquent qu'au trafic entrant par une interface
  LAN, dans les deux familles. En `Up`, chaque interface de `lan_ifaces` et
  chaque CIDR IPv6 donnent
  `forward iifname "<lan>" ip6 daddr <cidr> accept` : l'IPv6 d'un client du
  tunnel atteint le rejet, et une nouvelle connexion entrant par un WAN vers
  un préfixe IPv6 global du LAN n'est pas acceptée. Sans interface LAN, aucun
  contournement n'est rendu, quel que soit `wg_iface` ; un CIDR invalide reste
  refusé (FIREWALL-V2, « Rejet explicite de la sortie IPv6 des clients »).
- **Portail captif** : par décision de l'opérateur, l'ouverture HTTP/HTTPS
  relayée en `CaptivePortal` ne s'applique qu'au trafic entrant par une
  interface LAN :
  `forward iifname "<lan>" oifname "<wan>" [ip daddr <passerelle>] tcp dport { 80, 443 } accept`,
  une règle par interface LAN et par WAN, aucune sans interface LAN ; les
  règles `output` de la gateway elle-même sont inchangées. Sans passerelle
  connue, la règle ne nomme aucune adresse : bornée au seul WAN, elle
  accepterait l'IPv6 d'un client du tunnel avant le rejet. Le balayage de
  `ipv6_relay` couvre la passerelle connue et inconnue.

# Architecture

Helios sépare strictement le **plan de contrôle** (user space) du **plan de
données** (kernel space).

## Plan de données (noyau)

Le traitement lourd — chiffrement/déchiffrement — ne remonte jamais en espace
utilisateur.

- **XFRM** : framework IPsec natif du noyau. Quand un paquet doit être protégé,
  XFRM applique l'encapsulation ESP, chiffre avec les algos du noyau, et renvoie
  le paquet sur l'interface physique. Les *Security Associations* (SA) et la
  *Security Policy Database* (SPD) y sont injectées par charon.
- **Netfilter / nftables** : le pare-feu/routeur aux hooks `input`/`forward`/
  `output`. C'est le **kill-switch** : politique par défaut `drop`, on n'autorise
  le forward LAN→WAN que lorsque le tunnel est opérationnel.

## Plan de contrôle (user space)

- **charon (strongSwan)** : négocie IKEv2 en clair (UDP 500/4500), se met
  d'accord sur les clés (ML-KEM / ECDHE), puis **descend** les SA/SPD dans XFRM
  et s'endort. Il ne touche jamais au trafic de données.
- **heliosd (Rust)** : l'orchestrateur. Il pilote charon via **VICI**, configure
  **nftables** via **Netlink**, et gère l'**OTA** via RAUC.

## Le kill-switch et la sémantique fail-closed

L'invariant central (`aether::state`) :

> Le trafic LAN n'est autorisé à sortir **que** lorsque le tunnel est `Up` ou
> `Rekeying`. Dans tout autre état (`Down`, `Connecting`, `Failed`), le
> kill-switch est engagé.

Conséquences concrètes :

1. `heliosd` engage le kill-switch **au démarrage, avant** tout contact réseau.
2. À l'arrêt, le kill-switch **reste engagé** (on ne « déverrouille » jamais en
   sortant).
3. Le backend Netlink, tant qu'il n'est pas finalisé, **refuse** d'appliquer une
   politique partielle plutôt que d'ouvrir une brèche.

## Pourquoi pas DPDK / AF_XDP ?

Ces approches « bypass kernel » se justifient pour saturer du 10/40 Gbps à des
millions de pps. Pour du Gigabit :

- la pile native fonctionne **par interruptions** (IRQ) : si rien ne passe, le
  CPU dort — pas de polling à 100 % d'un cœur ;
- on garde **tous les outils** standard (`ip xfrm state`, `nft list ruleset`,
  `tcpdump`) ;
- le code réseau/crypto du noyau est parmi les plus audités au monde.

## Flux de montée du tunnel

```
heliosd démarre
  └─ engage kill-switch (état Down, fail-closed)
  └─ VICI: load-conn  (proposition hybride PQ)
  └─ VICI: initiate
        charon ↔ pair : IKE_SA_INIT, IKE_AUTH  (ML-KEM + ECDHE)
        charon → XFRM : installe SA + SPD
  └─ état → Up
  └─ nftables: autorise forward LAN→WAN
```

# Architecture actuelle

Ce document décrit le code après la rupture IKEv2 → WireGuard (ADR-001) et
l’introduction des signatures hybrides d’artefacts (ADR-002). Les ADR conservent
le raisonnement historique ; ce document est la vue opérationnelle courante.

## Frontières du système

Helios est la gateway Linux. Orion est le client road-warrior. `aether` contient
les contrats purs partagés, sans ressource système au runtime.

```text
Orion (Tauri)                         Helios (appliance Linux)
┌─────────────────────┐              ┌───────────────────────────────┐
│ React ↔ commandes   │              │ heliosd                       │
│ Tauri               │              │  ├─ orchestrateur             │
│        │             │              │  ├─ API Axum / WebSocket      │
│ orion-core          │              │  ├─ provisioning ML-KEM       │
│  └─ backend WG      │◄─ WireGuard ─►│  ├─ backend WireGuard         │
└─────────────────────┘              │  ├─ pare-feu nftables         │
                                     │  ├─ TPM / séquestre           │
                                     │  └─ OTA RAUC A/B              │
                                     └───────────────────────────────┘
```

Le noyau transporte et chiffre les paquets via WireGuard. `heliosd` ne
réimplémente pas WireGuard : il monte l’interface, configure les pairs, observe
les handshakes et applique la politique nftables.

## Démarrage de la gateway

L’ordre est une propriété de sécurité :

1. charger la configuration et les secrets autorisés par le TPM ;
2. engager le kill-switch avant tout contact réseau ;
3. monter/configurer `helios0` et ses pairs ;
4. passer à `connecting` ;
5. interroger les handshakes toutes les 10 secondes ;
6. passer à `up` lorsqu’un handshake a moins de 150 secondes ;
7. revenir à `connecting` lorsque le handshake expire.

Seul `TunnelState::Up` autorise le trafic LAN. `down`, `connecting`, `failed` et
`captive_portal` restent fail-closed, à l’exception des ouvertures étroitement
déclarées pour le handshake, l’administration et le portail captif.

Le backend Netlink traduit d’abord la totalité du ruleset. Une erreur de
traduction n’envoie rien. Le lot est ensuite appliqué par une transaction
atomique : aucune application règle par règle n’est autorisée.

## Cycle de vie d’Orion

Orion monte son adaptateur directement depuis le profil : endpoint UDP, clé
privée client, clé publique gateway, VIP, `AllowedIPs`, keepalive et PSK
éventuel. L’API Helios n’intervient jamais dans la montée initiale puisqu’elle
vit derrière le tunnel.

Orion ne possède pas de kill-switch local. Avec `AllowedIPs = 0.0.0.0/0`, son
adaptateur doit rester monté après un échec pour que WireGuard capture et jette
les paquets. `down()` n’est appelé que lors d’une déconnexion explicite. Un
binaire compilé avec `orion/wireguard` refuse de démarrer si le backend réel ne
peut pas s’initialiser ; il ne retombe pas sur une simulation.

## API d’administration

L’API écoute sur l’adresse hôte de `wg_address` lorsque la gateway est prête,
sinon sur `127.0.0.1:8080`. nftables limite l’accès distant à `admin_iface`.

- les lectures d’état et de règles ne contiennent aucun secret ;
- `GET /api/network` renvoie une vue dédiée qui expose seulement si une clé
  privée ou un PSK est configuré ;
- `GET /api/trust` expose les algorithmes obligatoires et les empreintes du
  trousseau éditeur compilé, jamais les clés complètes ;
- toutes les mutations exigent `application/json` et aucun CORS permissif n’est
  activé ;
- le WebSocket diffuse les transitions et la télémétrie post-connexion.

Cette barrière HTTP protège des formulaires cross-origin ; elle ne remplace ni
le filtrage réseau ni une future authentification applicative.

## Provisioning et post-quantique

L’admission initiale de la clé publique WireGuard est hors bande. Une fois le
tunnel classique établi, Orion appelle `/api/provision` avec une clé ML-KEM-768
éphémère. Les deux côtés dérivent un PSK de 32 octets lié aux identités
WireGuard et aux nonces du protocole.

Le protocole, la dérivation et l’IPAM CGNAT déterministe sont implémentés. Le
câblage atomique final du PSK dans le plan de données gateway reste incomplet :
il ne faut pas présenter cette rotation comme prête pour la production.

## Démarrage vérifié et signature éditeur

`helio-tpm` scelle le secret qui protège l’identité WireGuard de la gateway sur
les PCR 0/4/7. Après une OTA, un billet de rescellement v2 doit porter deux
signatures valides sur les mêmes octets : Ed25519 et ML-DSA-65. L’époque de clé
est signée et sélectionne un trousseau public compilé.

Le compteur du billet est obligatoire et doit strictement augmenter. Sa
liaison PCR est facultative ; si elle est présente, elle doit correspondre. Le
format v1 Ed25519 seul est refusé sans fallback. La signature est produite hors
gateway par `helios-publisher`.

La récupération de l’identité WireGuard est volontairement inachevée : le
choix entre `TpmState.version` sur fichier et un compteur NV TPM doit être
tranché avant le lot 3 de l’ADR-002.

## Backends et validation

Les backends par défaut sont simulés. Les features matérielles sont `netlink`,
`wireguard`, `tpm` et `embed-ui`. Leur compilation sous WSL2 valide les types et
les contrats ; elle ne valide pas les effets noyau ou TPM. La recette matérielle
de [TESTING.md](TESTING.md) reste obligatoire avant livraison.

Lorsque le mode réel est demandé, une feature ou un backend indisponible arrête
le daemon. Une gateway ne retombe jamais silencieusement sur une simulation.

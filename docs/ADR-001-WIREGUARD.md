# ADR 001 — Bascule d'IKEv2/IPsec vers WireGuard

**Statut** : accepté — 2026-07-17
**Portée** : remplace le plan de données et le plan de contrôle décrits dans
`ARCHITECTURE.md`, et le mécanisme PQ décrit dans `POST-QUANTUM.md`. Ces deux
documents seront révisés une fois la bascule implémentée.

## Nomenclature

Cette bascule fixe la séparation des noms du projet :

- **Helios** — la gateway. Le démon `heliosd`, les crates `helios-*`, l'appliance
  Linux, le TPM, le kill-switch nftables.
- **Orion** — le client road-warrior. `orion-core` (ex-`helios-client-core`) et
  l'application Tauri `apps/orion` (ex-`apps/helios-client`).
- **`aether`** (ex-`helios-core`) — le **milieu partagé** par les deux : types
  communs, `TunnelState`, politiques de pare-feu. Zéro dépendance système.

Le nom est délibérément neutre : `helios-core` importé par le client aurait
signifié que la gateway possède le socle du client. L'éther est, dans la
cosmologie classique, la substance dont le ciel est fait — le milieu dans lequel
baignent aussi bien le soleil que les constellations. Il n'appartient à aucun des
deux.

## Contexte

L'architecture d'origine repose sur IKEv2/IPsec : `charon` (strongSwan, en C)
négocie, `heliosd` le pilote via VICI, XFRM chiffre dans le noyau. Le
post-quantique passe par la RFC 9370 (`ke1_mlkem768` dans la proposition IKE).

Ce choix tient sur la gateway Linux. Il ne tient pas côté client road-warrior :

- la pile IKEv2 native de Windows **ne supporte pas** l'échange ML-KEM (RFC 9370),
  ce qui interdit purement et simplement les profils PQ sur la cible client ;
- l'alternative — embarquer strongSwan sous Windows — impose une
  cross-compilation C et une cohabitation avec le service natif `IKEEXT` ;
- constat de fait : `helios-client-core/src/backend/windows.rs` et `macos.rs`
  n'ont jamais dépassé le stade du stub. La douleur est anticipée, pas mesurée —
  ce qui rend l'arbitrage peu coûteux **maintenant**.

WireGuard résout le problème client : une seule implémentation, pilotable depuis
Rust sur toutes les cibles, sans dépendance C à cross-compiler.

## Décision

On bascule sur WireGuard. Cinq points structurent la bascule.

### 1. Plan de données asymétrique

- **Gateway Linux (Helios)** : WireGuard **noyau**, piloté en netlink.
- **Client Orion** : `defguard_wireguard_rs`, qui impose l'implémentation selon
  la plateforme (voir l'amendement ci-dessous).

> **Amendement (implémentation, Phase C) — le client Windows passe par le noyau,
> pas par BoringTun.** Le plan d'origine prévoyait « BoringTun (userspace) +
> Wintun » sur Windows. À l'écriture du backend, constat : le module
> `wgapi_userspace` de `defguard_wireguard_rs` (celui qui embarque BoringTun) est
> `#[cfg(unix)]` — **indisponible sur Windows**. Le crate n'y propose que
> `WGApi<Kernel>`, adossé au pilote noyau **`wireguard-nt`**.
>
> | Plateforme | Implémentation retenue | Plan de données |
> |---|---|---|
> | Linux   | `WGApi<Kernel>`    | module noyau `wireguard` (netlink) |
> | Windows | `WGApi<Kernel>`    | pilote noyau `wireguard-nt` |
> | macOS   | `WGApi<Userspace>` | BoringTun embarqué |
>
> **Conséquence sur l'argumentaire d'origine** : la promesse « isolation à 100 %
> en user-space, aucun risque de BSOD » tombe pour Windows. Elle était de toute
> façon intenable — Wintun est lui-même un pilote NDIS noyau (voir les notes de
> vigilance). On ne supprime donc pas le composant noyau, on choisit lequel :
> `wireguard-nt` (WireGuard entier en noyau, ce qu'utilise le client officiel)
> plutôt que Wintun (adaptateur TUN en noyau, crypto en userspace).
>
> Revenir au plan initial est possible mais **sort de `defguard_wireguard_rs`** :
> il faudrait intégrer directement les crates `boringtun` et `wintun`, et écrire
> soi-même la gestion d'adaptateur que defguard fournit. À arbitrer si la
> surface noyau sous Windows est un critère dur.

On ne met pas BoringTun sur la gateway : ce serait troquer un plan de données
noyau (ESP/XFRM aujourd'hui) contre de l'userspace, dont le goulot est le coût
syscall/copie par paquet. Ce serait une régression de performance sur le
concentrateur.

`defguard_wireguard_rs` expose une API unifiée sur le noyau Linux, sur Windows et
sur BoringTun. L'asymétrie est un détail de configuration derrière une interface
unique, pas deux intégrations séparées.

> **Attention** : WireGuard n'utilise **pas** XFRM. XFRM est le framework IPsec.
> Le module noyau WireGuard a sa propre famille genl (`wireguard`).

### 2. Post-quantique : ML-KEM dans le slot PSK

On ne touche **pas** au handshake WireGuard. Le message d'initiation fait 148
octets à disposition fixe, un seul datagramme UDP, jamais fragmenté, avec
MAC1/MAC2 calculés sur ce layout exact. ML-KEM-768 (clé publique 1 184 o,
ciphertext 1 088 o) **n'y rentre pas** : l'« injecter » signifierait redéfinir le
format de message, fragmenter sur UDP et reconstruire la logique anti-DoS —
c'est-à-dire écrire un protocole cryptographique nouveau, sans interopérabilité
ni revue externe.

À la place : le secret ML-KEM alimente le slot **`PresharedKey`**, qui existe
déjà dans le format de fil et est déjà mélangé au handshake Noise.

Implémentation : **`aws-lc-rs`** (AWS-LC), **sans la feature `fips`**. ML-KEM-768
(FIPS 203) vit dans l'API `kem` standard, pas derrière FIPS. Concrètement, dans
`aether::pq` derrière le trait `Kem` (module `pq`, testé sur WSL2).

- **Sans `fips` → build statique et propre en cross-platform.** `aws-lc-sys`
  non-FIPS n'exige **ni CMake, ni Go, ni Ninja, ni bindgen** (bindings
  pré-générés, builder `cc`), seulement un compilateur C — que le projet requiert
  déjà via `ring`. Sur Windows x86-64, la feature `prebuilt-nasm` évite NASM.
  L'invariant « `cargo test` vert partout, WSL2 compris » est préservé.
- **Pas `oqs`/liboqs** : bindings C exigeant CMake — précisément la
  cross-compilation Windows qu'on fuit.
- **Pas la feature `fips`** : c'est la seule voie vers une validation
  **FIPS 140-3** avec ML-KEM, mais elle exige CMake + Go + Ninja + NASM, et son
  build FIPS n'est statique que sur Linux/BSD — ailleurs il produit une
  **bibliothèque partagée** (DLL crypto livrée avec le client). Rejeté ici ; voir
  ci-dessous pour la réactivation.

**Statut conformité — à énoncer honnêtement.** Sans `fips`, il n'y a **aucune
validation FIPS 140-3** : sur l'axe conformité, on est au même point qu'une
implémentation Rust pure. Ce qu'on gagne en choisissant quand même `aws-lc-rs` :
une seule lib crypto mature (la même que `rustls`/`reqwest` peuvent utiliser),
accélérée matériellement (AES-NI, AVX2, ARMv8 Crypto), et **le chemin de
réactivation FIPS tout tracé** — activer la feature `fips` plus tard ne touche
pas le code, seulement la CI (qui devra alors fournir la toolchain CMake/Go).

FIPS 140-3 n'est de toute façon pas une exigence contractuelle sur ce projet :
contrainte de marchés publics américains ; côté ANSSI, l'exigence est CSPN /
Critères Communs, et la position PQC publiée recommande l'**hybridation** — ce
que fait déjà ce design.

> **FIPS 203 ≠ FIPS 140-3.** Le premier est la *spécification* de l'algorithme
> ML-KEM, qu'`aws-lc-rs` implémente quelle que soit la feature. Le second est la
> *validation d'un module* par le CMVP, active uniquement avec la feature `fips`.
> L'algorithme est le bon standard NIST dans les deux cas.

L'API ML-KEM est minuscule (keygen / encaps / decaps) : elle est placée derrière
le trait `Kem`, comme `VpnBackend` ou `FirewallBackend`. Activer la feature
`fips` d'`aws-lc-rs`, ou basculer vers `libcrux-ml-kem` (Rust pur, vérifié en
F*), ne toucherait que `aether::pq`.

> **Ne pas revendiquer une preuve de sécurité formelle.** Ce design n'est **pas**
> Rosenpass. Rosenpass est un protocole UDP dédié avec sa propre preuve, sa
> vérification symbolique, Classic McEliece pour l'authenticité et des cookies
> anti *state-disruption*. Ce qu'on obtient ici, c'est la garantie du canal TLS
> plus celle de ML-KEM — solide et suffisant, mais à énoncer honnêtement.
>
> Rosenpass a été évalué et écarté : clés publiques McEliece de l'ordre du
> méga-octet, démon séparé, et il ne résout pas l'enrôlement (VIP, identité) —
> qu'il faut construire de toute façon. Un seul canal portant PSK **et**
> enrôlement est plus simple.

### 3. Machine à états : polling temporel

WireGuard est sans connexion. Il n'y a pas d'état « Up » à observer : on l'infère
d'un handshake récent.

- Seuil : `last_handshake_time` < **150 s** (marge sous les 180 s de
  `REJECT_AFTER_TIME` — à 179 s on flappe).
- **`PersistentKeepalive = 25`** obligatoire.

> **La raison du keepalive n'est pas celle qu'on croit.** WireGuard n'expire pas
> un tunnel par inactivité — il n'y a pas d'état `Expired`. Sans trafic, WG ne
> handshake simplement pas ; au premier paquet utile, il le fait. Le problème est
> que **notre inférence** conclurait faussement « down » et engagerait le
> kill-switch sur un tunnel parfaitement fonctionnel. Le keepalive garantit que
> `last_handshake_time` reste frais. Coût : batterie sur portable, et la
> propriété « silencieuse » de WireGuard est perdue.

`TunnelState` garde `Down` / `Connecting` / `Up` / `Failed` / `CaptivePortal`, et
perd **`Rekeying`** (WireGuard rekeye de façon transparente toutes les ~2 min,
sans état observable). Le roaming WireGuard étant natif et gratuit, tout
l'appareillage MOBIKE disparaît — **179 lignes** dans `orchestrator.rs`
(`spawn_mobike_monitor`, `netlink_addr_watcher`, `parse_ifa_address`,
`read_if_index`, `seed_wan_ip`, `trigger_mobike_update`), plus l'événement
`AddressChanged`. Côté Orion, le suivi de changement de réseau se fait via
`NotifyRouteChange2`.

**Le polling ne pilote pas le kill-switch.** Si la session WG est morte,
WireGuard **jette** les paquets — il ne les envoie pas en clair. Le vrai risque
de fuite est le **routage** : si l'interface WG disparaît, la route par défaut
retombe sur l'interface physique. Or la règle qui couvre ça, sur la gateway —
« rien ne sort du WAN sauf vers l'endpoint du pair » — est **indépendante de
l'état**. `traffic_allowed()` cesse donc d'être un organe de sécurité : il ne
sert qu'à l'IHM, à la télémétrie, et à la levée du kill-switch de la gateway
après installation du PSK (voir cinématique).

Côté Orion, cette même propriété — WireGuard jette au lieu de fuir — devient le
socle du modèle de sécurité client, sous réserve d'une invariante de cycle de vie
détaillée en §3 bis.

### 3 bis. Orion est fail-open : classification, et l'invariante qui la neutralise

**Décision : aucun pare-feu côté client.** Orion est un point de terminaison
road-warrior standard. Aucun module pare-feu applicatif, aucun sous-système
**WFP** (Windows Filtering Platform), aucun blocage de port n'est développé côté
client. La capture du trafic repose uniquement sur la **table de routage de
l'OS**, via l'adaptateur Wintun. `helios-firewall` devient **strictement
Linux-only**.

#### Classification

Cette décision introduit une faiblesse **CWE-636 — *Not Failing Securely
('Failing Open')*** :

> *« When the product encounters an error condition or failure, its design
> requires it to fall back to a state that is less secure than other options
> that are available. […] This weakness typically occurs as a result of wanting
> to "fail functional" to minimize administration and support costs, instead of
> "failing safe". »*
> — [MITRE, CWE-636](https://cwe.mitre.org/data/definitions/636.html)

Le motif décrit par MITRE est exactement le nôtre. On l'écrit plutôt que de le
maquiller.

#### Le mécanisme : repli de routage

La faille n'est pas un bug de notre code, c'est le comportement normal de la pile
NDIS de Windows :

1. L'adaptateur Wintun porte les routes du tunnel (`AllowedIPs = 0.0.0.0/0`), qui
   priment sur la route par défaut physique.
2. L'adaptateur disparaît.
3. Windows retire instantanément les routes associées et réélit l'interface
   physique comme passerelle par défaut.
4. Le trafic sort **en clair** sur le réseau hostile.

> **Nuance sur ce qui fuit réellement.** Les sockets TCP *en cours* sont liées à
> l'IP source du VIP (`100.64.x.y`) ; cette source disparaissant avec
> l'adaptateur, ces connexions **meurent** — elles ne fuient pas. Ce qui fuit,
> ce sont les **nouvelles** connexions et l'UDP. Opérationnellement c'est pire :
> le navigateur et les clients de synchronisation retentent seuls, réussissent en
> clair, et l'utilisateur ne voit **rien**.

#### L'invariante de conception qui supprime le vecteur exploitable

Le scénario d'attaque *DoS-to-cleartext* est réel : sur un Wi-Fi hostile, un
attaquant transforme un déni de service en interception. Mais **son déclencheur
n'est pas celui qu'on croit**.

Faire crasher BoringTun avec du trafic malformé est le chemin difficile —
BoringTun est en Rust, il n'y a pas de dépassement de tampon, il faut trouver un
chemin de panic. L'attaquant n'en a pas besoin : il lui suffit de **bloquer
l'UDP/51820**, ce qui ne demande aucune vulnérabilité.

Et là, tout dépend de nous :

- Si l'adaptateur Wintun **reste debout**, les paquets partent vers WireGuard,
  qui les **jette**. L'attaquant obtient un déni de service et **pas un octet en
  clair**.
- Si Orion, constatant l'échec, **démonte son adaptateur** et repasse en `Down`,
  la route disparaît et la fuite est instantanée.

Le déclencheur exploitable est donc **notre machine à états**, pas un bug de
BoringTun. D'où l'invariante :

> **Invariante Orion.** L'adaptateur Wintun, avec `AllowedIPs = 0.0.0.0/0`, est
> créé à la connexion et **n'est jamais démonté sur échec** — ni en `Connecting`,
> ni en `Failed`, ni après N tentatives. Il n'est retiré que sur **déconnexion
> explicite de l'utilisateur** ou fermeture de l'application.

Avec cette règle, **le drop natif de WireGuard devient le kill-switch** : pas de
WFP, pas de sublayers, pas de BFE, pas de filtres au boot. Une discipline de
cycle de vie dans `orion-core`, contrainte directement par la machine à états de
§3.

#### Le risque résiduel

Après l'invariante, il reste :

- **le crash du processus Orion** — les adaptateurs Wintun sont liés au handle du
  processus ; sa mort détruit l'adaptateur et la route. C'est précisément pour ça
  que le client WireGuard officiel fait tenir le handle par un service séparé ;
- la mise en veille / reprise et le retrait d'adaptateur au niveau OS ;
- la fermeture volontaire de l'application.

On passe donc de « **trivialement exploitable par quiconque sur le réseau** » à
« **nécessite un crash** ». C'est l'essentiel du bénéfice d'un WFP pour quelques
lignes de discipline. Fermer le reste — un service mince détenant le handle
indépendamment du worker — est une décision **différée**, pas refusée.

#### Pourquoi on l'accepte

Non pas parce que « tout le monde fait pareil » : cet argument est faux et se
réfute en une recherche. Le client **WireGuard officiel pour Windows implémente**
le kill-switch — l'option *« Block untunneled traffic (kill-switch) »* de
l'éditeur de tunnel pose des règles WFP, et prend tout son sens précisément avec
`AllowedIPs = 0.0.0.0/0`. (Et *Shields Up* de Tailscale n'est pas un
kill-switch : ça bloque les connexions **entrantes** depuis le tailnet.)

On l'accepte parce que le rapport coût/bénéfice est explicite : l'invariante
ci-dessus capture l'essentiel de la protection pour un coût quasi nul, là où le
WFP demanderait un sous-système Windows entier. C'est un **choix**, pas un oubli.

**Conséquence sur les invariants du projet.** La règle « fail-closed is a hard
rule » de `CLAUDE.md` ne vaut désormais que pour **Helios**. Le kill-switch de la
gateway ne protège pas Orion : deux machines, deux modèles de menace. nftables
sur l'appliance empêche le LAN *derrière la gateway* de fuir ; il ne fait rien
pour un portable sur le Wi-Fi d'un café.

### 4. Provisioning : reconstruire ce qu'IKEv2 donnait gratuitement

C'est le vrai coût de la bascule, et le seul chantier réellement neuf.

IKEv2 fournissait nativement deux choses que WireGuard **n'a pas** :

- **l'authentification** : X.509 / EAP / PSK (l'énumération `AuthConfig`).
  WireGuard n'a qu'un modèle — une clé publique Curve25519 statique par pair,
  listée en configuration. Pas de CA, pas de révocation, pas de credentials
  utilisateur.
- **l'adressage** : les Config Payloads attribuaient la VIP au client.
  WireGuard n'a rien : les adresses sont statiques des deux côtés.

Le nouveau crate `helios-provisioning` porte donc : enrôlement, authentification,
adressage, échange ML-KEM et rotation du PSK.

**Authentification.** Le canal TLS 1.3 est ancré dans le TPM **côté gateway** :
le secret descellé par `helio-tpm` (scellé sur PCR 0/4/7 — firmware, bootloader,
Secure Boot) déchiffre la clé privée TLS d'Helios. Le client, lui, est identifié
par sa **clé publique Curve25519 statique** — le seul modèle d'identité qu'ait
WireGuard. Orion n'a **aucune** intégration TPM, et n'en aura pas : cela
demanderait l'API TBS de Windows, un chantier sans rapport.

**Adressage CGNAT déterministe (IPAM sans état).** Le tunnel adopte la plage
partagée RFC 6598 — **`100.64.0.0/10`** — pour éliminer les collisions de routage
entre les box résidentielles (192.168.x.x) et les réseaux d'entreprise (10.x).

L'attribution est **déterministe, sans base de données ni fichier sur disque** :

```
VIP = 100.64.0.0/10 | BLAKE3(clé_publique_wg_client)[0..22 bits]
```

Le déterminisme remplace la persistance : après un redémarrage de la gateway,
aucun état d'adressage n'est rechargé — chaque client qui se reconnecte retrouve
sa VIP par re-dérivation.

> **Ne pas dériver depuis le TPM.** Une version antérieure de ce plan proposait
> `BLAKE3(identifiant matériel TPM)`. Cet identifiant **n'existe pas** :
> `helio-tpm` n'expose que `current_pcr_digest`, qui est une *mesure de la chaîne
> de boot* — donc **identique sur tous les appareils portant le même firmware**.
> Le dériver donnerait la même VIP à tous les clients. La clé publique WireGuard
> est unique, stable, déjà présente, et déjà l'identité du pair.

> **Ne pas utiliser un `/16`.** Une version antérieure proposait
> `100.64.0.0/16`, soit 65 536 adresses. Paradoxe des anniversaires
> (`p ≈ 1 - exp(-n²/2N)`) : **7,3 % de collision à 100 clients, 50 % à 300**. Or
> dans WireGuard, `AllowedIPs` **est** la table de routage cryptographique : deux
> pairs ne peuvent pas revendiquer la même adresse, et le second **vole
> silencieusement la route au premier**. C'est un détournement de trafic muet. Le
> `/10` complet (4,19 M d'adresses) ramène le risque à 0,12 % à 100 clients.

**Résolution de collision, toujours sans disque.** Le `/10` rend les collisions
rares, il ne les supprime pas (~11 % à 1 000 clients). À l'enrôlement, la gateway
sonde la **table de pairs WireGuard vivante** — que le noyau détient déjà — et
re-dérive avec un compteur si l'adresse est prise par une autre clé publique :

```
i = 0
loop {
    vip = derive(pubkey, i)
    if !peer_table.contains(vip) || peer_table.owner(vip) == pubkey { break }
    i += 1
}
```

Conséquence assumée : pour la paire de clients en collision — et pour elle seule
— la VIP peut changer d'un redémarrage de gateway à l'autre, l'ordre de
reconnexion pouvant différer.

> **Précision de vocabulaire.** « Aucun état » est faux : la gateway tient un
> état, la table de pairs WireGuard, dans le noyau. Ce qui est vrai et
> recherché, c'est **aucun état d'adressage persistant sur disque** — pas de SQL,
> pas de fichier, rien à sauvegarder, rien à corrompre, rien à migrer.

## Cinématique de montée — le point clé

**L'invariant « le canal de contrôle vit derrière le tunnel » est préservé.** Il
n'y a **aucune** fenêtre TLS pré-tunnel, aucun service exposé sur l'Internet
public avant que le tunnel ne soit monté.

C'est possible parce que **le PSK WireGuard est optionnel** : sans PSK, WireGuard
fonctionne sur les clés statiques Curve25519, en sécurité classique. On monte donc
classique, puis on **upgrade en PQ** :

```
1. WG monte SANS PSK (Curve25519 statique)
      état → Connecting
      kill-switch ENGAGÉ — aucun trafic utilisateur ne sort
2. Canal TLS (À L'INTÉRIEUR du tunnel, ancré TPM)
      échange ML-KEM-768 → PSK dérivé des deux côtés
3. PSK installé. Handshake WG suivant (≤ 2 min) réussit avec PSK
      état → Up
      kill-switch levé — le trafic passe, protégé PQ
```

### Pourquoi ce n'est pas un cercle vicieux cryptographique

Objection naturelle : « l'échange ML-KEM voyage dans un tunnel protégé seulement
par X25519 ; un attaquant quantique casse X25519 plus tard, lit le tunnel, et
récupère le PSK ».

Non. En cassant le tunnel, l'attaquant voit la **clé publique ML-KEM et le
ciphertext** — exactement ce que voit un attaquant passif d'un échange ML-KEM
mené en clair. ML-KEM résiste précisément à ça : sans la clé privée, le secret
partagé reste hors d'atteinte. **Le PSK est post-quantique même livré dans un
tunnel classique.**

Le seul trafic exposé au *harvest-now-decrypt-later* pendant la fenêtre classique
est l'échange ML-KEM lui-même, que ça n'affecte pas. Le trafic utilisateur ne
passe pas : le kill-switch est engagé jusqu'à `Up`.

Effet de bord bienvenu : **`Connecting` retrouve un sens fort**. Ce n'est plus
« on attend », c'est « tunnel classique monté, upgrade PQ en cours, trafic
interdit ».

### Rotation du PSK sans brique

Changer le PSK d'un pair vivant **ne casse pas la session en cours** : les clés
de session sont déjà dérivées. Le nouveau PSK ne sert qu'au handshake suivant,
soit ≤ 2 min plus tard — d'où une fenêtre confortable pour synchroniser les deux
bouts.

En cas de désynchronisation, chaque côté applique un **revert local sur timeout**,
sans avoir besoin de communiquer :

> pas de handshake réussi 180 s après l'installation de `PSK_new` → retour à
> `PSK_old`.

Deux timers locaux et déterministes convergent. Dernier filet : retour au mode
sans PSK → le tunnel classique remonte → le canal de contrôle redevient joignable
→ resynchronisation. Le kill-switch reste engagé pendant toute la séquence.

**Le pire cas est un DoS, pas une brique et pas une fuite.** C'est acceptable :
un DoS est de toute façon toujours disponible contre un VPN.

## Conséquences sur le workspace

Chiffres vérifiés contre l'arbre au 2026-07-17.

**Intacts** (1 969 lignes)
: `helio-tpm` (1 342) — le scellement PCR 0/4/7 et le ticket de rescellement
  Ed25519 sont inchangés. `SecretKey` déchiffrait des credentials IPsec ; une clé
  privée Curve25519 est un blob comme un autre. Le TPM devient en outre l'ancre
  d'authentification du canal de contrôle. `helios-api` (428) et `helios-update`
  (199) : zéro modification.

**Supprimés** (~820 lignes)
: `helios-vici` en entier (465) ; `aether/src/profiles.rs` (79) ; dans
  `heliosd/src/orchestrator.rs` : `bring_up_real` (56), `load_connection` (33),
  `initiate` (12) et les **179 lignes** de l'appareillage MOBIKE (lignes 560-738).

**Retouchés**
: `aether` — `TunnelState` perd `Rekeying`, les événements IKE cèdent la
  place au polling.

: `helios-firewall` — **périmètre réduit, strictement Linux-only**. Le crate perd
  toute cible Windows : le chantier WFP n'est pas développé (§3 bis). Il se
  concentre sur ses 386 lignes de rendu nftables pour la gateway. La boucle
  `ike_peers` de `ruleset.rs:54-61` (UDP 500/4500 en `:56`, ESP en `:60`) devient
  une seule règle **UDP/51820 vers l'IP du pair**. Le scoping par destination
  (`ip daddr {peer} udp dport …`) est **conservé tel quel** : autoriser
  l'UDP/51820 sans restreindre la destination serait une fuite. Une seule
  exception suffit, le canal de contrôle vivant dans le tunnel.

: `helios-client-core` (906) → **`orion-core`**, `apps/helios-client` →
  **`apps/orion`** (paquet Tauri `helios-client` → `orion`). Les backends
  `linux.rs` / `macos.rs` / `windows.rs` et l'énumération `AuthConfig`
  disparaissent avec IKEv2. L'invariante de cycle de vie de l'adaptateur (§3 bis)
  s'implémente ici.

**Nouveau**
: `helios-provisioning` — le seul chantier réellement neuf. Il porte
  l'enrôlement TLS 1.3 ancré TPM côté gateway, la dérivation d'adresse
  déterministe en mémoire (`derive_cgnat_ip()`), le sondage anti-collision contre
  la table de pairs, l'échange ML-KEM (`aws-lc-rs`, sans `fips`) et l'injection dynamique du PSK
  via `defguard_wireguard_rs`.

## Alternatives écartées

**BoringTun partout, y compris gateway** — régresse le plan de données du noyau
vers l'userspace sur le concentrateur. Écarté (voir §1).

**Injection de ML-KEM dans le handshake WireGuard** — revient à écrire un
protocole cryptographique nouveau, non interopérable et non revu. Écarté (§2).

**Rosenpass** — résout élégamment le PSK PQ avec une vraie preuve, mais clés
McEliece de l'ordre du Mo, démon séparé, et ne résout pas l'enrôlement. Écarté
(§2).

**Fenêtre TLS pré-tunnel pour le bootstrap** — casse l'invariant « le canal de
contrôle vit derrière le tunnel » et expose un service sur l'Internet public.
Rendu inutile par la cinématique classique-puis-upgrade. Écarté.

**`oqs` / liboqs, `aws-lc-rs` FIPS** — toolchain CMake/Go. Écarté (§2).

**Kill-switch WFP sur le client** — apporterait le fail-closed complet à Orion,
au prix d'un sous-système Windows entier. Écarté : l'invariante de cycle de vie
(§3 bis) en capture l'essentiel pour un coût quasi nul.

**Service Windows détenant le handle Wintun** — fermerait le dernier vecteur (le
crash du processus). **Différé**, pas refusé (§3 bis).

**IPAM avec base de données** — assignation de VIP persistée (SQL ou fichier).
Écarté : une base à sauvegarder, migrer et corrompre pour une information que la
dérivation déterministe reconstruit gratuitement (§4).

**VIP dérivée d'un identifiant TPM, plage `/16`** — écarté pour cause
d'identifiant inexistant et de collisions d'adresses. Détail en §4, car l'erreur
est instructive.

## Notes de vigilance

**« Zéro dépendance C » n'est pas un objectif atteignable, et ne l'a jamais été.**
`ring` 0.17.14 est déjà dans le `Cargo.lock` via `reqwest` + `rustls-tls` : c'est
du C et de l'assembleur dérivés de BoringSSL. Le critère utile n'est pas « C ou
pas C » mais **« ça construit en cross-platform, ou ça exige une toolchain
CMake/Go/Ninja »**. Ring utilise le crate `cc` avec de l'asm vendored et
construit sur Windows avec un simple compilateur C — c'est ce qui le rend
tolérable là où liboqs et `aws-lc-fips-sys` ne le sont pas.

**Wintun est un pilote noyau NDIS**, pas de l'userspace. La DLL n'est que le shim.
On ne supprime pas le composant noyau côté Windows : on le **déplace** de
`IKEEXT` (maintenu par Microsoft, livré par Windows Update) vers un pilote tiers
qu'il faut distribuer soi-même, dont la signature dépend de WireGuard LLC. C'est
un transfert de risque, pas une élimination — à assumer consciemment.

**Le fail-closed ne couvre plus que la gateway.** Orion est fail-open par
conception (CWE-636), atténué mais non supprimé par l'invariante de §3 bis. Toute
relecture future de `CLAUDE.md` doit lire « fail-closed is a hard rule » comme
s'appliquant à **Helios uniquement**.

**BoringTun est en restructuration** ; son dépôt déconseille explicitement de
dépendre de `master` (NordSecurity l'a forké en `neptun` pour cette raison).
Utiliser les versions crates.io, et traiter ce point comme un choix de
supply-chain conscient pour un composant de sécurité.

## À valider sur cible uniquement

Conformément au découpage WSL2/cible du projet, ne peuvent **pas** être validés
en développement :

- le backend WireGuard noyau (netlink) sur la gateway ;
- Wintun, la capture par table de routage, et **l'invariante de cycle de vie de
  l'adaptateur** (§3 bis) sur le client Orion — dont le test décisif : *bloquer
  l'UDP/51820 et vérifier qu'aucun paquet ne sort en clair* ;
- la rotation PSK réelle et ses timers de revert.

Restent testables partout, en `dry_run` : la machine à états, le rendu des règles
firewall, la dérivation d'adresse et le sondage anti-collision, la logique
d'enrôlement et l'échange ML-KEM (`aws-lc-rs`, statique, compilateur C requis mais pas de CMake).

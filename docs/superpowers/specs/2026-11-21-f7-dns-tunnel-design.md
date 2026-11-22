# F7 — DNS des postes dans le tunnel (décision D5)

Statut : **conception**, 21 novembre 2026. Tranche D5 et décrit F7 de la
[feuille de route](../../ROADMAP.md).

## 1. Intention

Un poste Orion en tunnel complet protège tout son trafic, sauf ses requêtes
DNS : il garde le résolveur de son réseau local, qui voit tous les noms
consultés, et le FAI du poste avec lui. La limite est documentée en trois
endroits (`helios-firewall/src/ruleset.rs`, `aether::policy`,
ADR-006). Le but est que ces requêtes passent par le tunnel vers un résolveur
public, sans que la résolution casse quand quelque chose tourne mal.

Le départ de Quad9 de France le 24 novembre 2026, après une décision de
justice, a fixé deux exigences : le résolveur ne doit **jamais** être codé en
dur au point qu'un changement de fournisseur demande une nouvelle version, et
un changement doit atteindre tout le parc depuis un seul endroit.

## 2. Décisions de l'utilisateur

- **D5 tranché : résolveur public joint par le tunnel**, pas de résolveur sur
  la passerelle.
- **Option C** : la passerelle propose un résolveur, chaque poste peut le
  remplacer dans Orion.
- **Défaut : DNS4EU non filtré**, `86.54.11.100` et `86.54.11.200`
  ([joindns4.eu](https://www.joindns4.eu/for-public)). DNS4EU applique les
  blocages ordonnés par la justice française, comme tout résolveur public
  servant la France : les requêtes sortent par la passerelle, en France.
  Accepté.
- **Transport de la proposition : lue par Orion à chaque connexion**
  (approche 2 ci-dessous).

## 3. Objectifs, non-objectifs, anti-objectifs

Objectifs :

1. un profil Helios en tunnel complet résout par le tunnel, vers le résolveur
   proposé par la passerelle, ou celui que l'utilisateur a choisi ;
2. l'opérateur change le résolveur du parc dans `network.toml`, sans
   réémettre de profil ; les postes suivent à leur prochaine connexion ;
3. un profil classique (import wg-quick) applique sa ligne `DNS =`, aujourd'hui importée comme
   simple avertissement ;
4. ce qui est appliqué se voit dans Orion, et un échec d'application se dit.

Non-objectifs : DoH/DoT ; résolveur IPv6 ; résolveur sur la passerelle ;
blocage WFP du port 53 sur les autres cartes ; DNS partagé par domaine
(split DNS) ; édition depuis la console web ; macOS.

Anti-objectifs, échecs même si « ça marche » :

- un crash d'Orion qui laisse le poste **sans aucune résolution** ;
- un poste qui affiche « protégé » alors que son DNS sort hors du tunnel ;
- pousser un DNS par le tunnel à un profil « Helios seul », ou quand la
  passerelle ne route pas vers Internet : la résolution casserait.

## 4. Approches considérées

| | Approche | Pour | Contre |
|---|---|---|---|
| 1 | Proposition **dans le profil `.orion`** (`client_dns` recopié par `helios profile emit`) | Aucune route nouvelle, valeur connue dès le montage | Changer de résolveur oblige à réémettre et réimporter chaque profil — le cas Quad9 ; un document portant le champ est refusé par un Orion antérieur, comme `address_v6` |
| **2** | **Proposition lue à la connexion** sur une route du tunnel réservée aux pairs | Un changement dans `network.toml` atteint tout le parc ; format de profil inchangé ; profils existants couverts | Quelques secondes sur le défaut avant lecture ; une route de plus |
| 3 | Défaut dans Orion seulement, réglage par poste (option B) | Le plus simple | Écarté par l'utilisateur : chaque poste à reprendre quand un fournisseur disparaît |

**Retenue : 2**, la seule qui remplace un résolveur disparu en un seul endroit.

## 5. Conception

### 5.1 Contrat partagé (`aether`)

- `DEFAULT_CLIENT_DNS: [Ipv4Addr; 2]` = DNS4EU non filtré. Seule occurrence
  des adresses dans le code.
- Type de la réponse de la route (§5.3) et validation d'une liste de
  résolveurs : IPv4 seulement, unicast public (ni privé, ni CGNAT
  `100.64.0.0/10`, ni bouclage, ni lien local, ni multicast, ni `0.0.0.0`),
  sans doublon, 1 à 3 entrées. Une adresse privée serait jetée par le refus
  des réseaux locaux du pare-feu ; une IPv6, par le rejet de la sortie IPv6
  du tunnel : les deux sont refusées à la validation plutôt que de casser en
  silence.

### 5.2 Passerelle : configuration

`NetworkConfig` reçoit `client_dns: Option<Vec<Ipv4Addr>>`, `#[serde(default)]` :

- **absent** : la passerelle propose `DEFAULT_CLIENT_DNS` ;
- **liste** : la passerelle propose cette liste, validée (§5.1) au chargement
  et au rechargement à chaud — un `network.toml` invalide est refusé comme
  aujourd'hui, jamais corrigé ;
- **liste vide** `[]` : l'opérateur ne propose aucun DNS tunnelé.

Rechargement à chaud par le chemin d'adoption existant ; le champ n'est pas
un secret. `NetworkConfigView` l'expose en lecture.

### 5.3 Passerelle : route

`GET /api/client/dns`, derrière `auth::require_peer`, dans le groupe des
routes de pair (`helios-api/src/lib.rs`, à côté de `/api/provision`).
Réponse :

```json
{ "servers": ["86.54.11.100", "86.54.11.200"] }
```

`servers` est **vide** quand `client_dns = []` **ou** quand
`allow_client_internet` est faux : le résolveur ne serait pas joignable par le
tunnel. Aucun détail de politique dans la réponse au-delà de cette liste. La
route lit la configuration courante (`AppState.network`), pas une copie.

Aucune règle de pare-feu nouvelle : le forward `wg_iface → wan` et le NAT de
`allow_client_internet` portent déjà ces requêtes.

### 5.4 Orion : profil

`ClientProfile` reçoit `dns: Option<Vec<Ipv4Addr>>` :

- pour un profil **Helios** : `None` = « proposé par la passerelle »
  (défaut) ; `Some(liste)` = remplacement par l'utilisateur, validé comme
  §5.1 ;
- pour un profil **classique** (`ProfileKind::Classic`, import wg-quick) : la
  ligne `DNS =` importée, réduite à ses
  adresses IPv4 valides. Les entrées IPv6 et les domaines de recherche de la
  ligne restent un avertissement à l'import, sous la forme actuelle de
  `wg_unapplied_notice`, qui nomme ce qui n'est pas appliqué. Pas de ligne :
  `None`, et rien n'est appliqué, comme aujourd'hui.

Le champ entre dans le manifeste scellé (version 9, lecture de la version 8
conservée, encodage inchangé pour un profil sans DNS, sur le modèle de
`MANIFEST_VERSION_WITHOUT_ADDRESS_V6`) et dans ce que le moteur reçoit ;
le protocole du moteur change de version si son schéma l'exige.

### 5.5 Orion : application

Condition commune : le profil capture `0.0.0.0/0`. Sinon aucun DNS n'est
appliqué, et un remplacement saisi sur un tel profil est conservé mais
signalé « non appliqué : le profil ne capture pas tout le trafic ».

1. **Au montage** (`WireGuardBackend::up`), après la configuration de
   l'adaptateur : `set_dns(DnsConfig::full_tunnel(servers))` de `defguard`
   avec, dans l'ordre : le remplacement de l'utilisateur, sinon (profil
   Helios) `DEFAULT_CLIENT_DNS`, sinon (classique) sa ligne `DNS =`.
   Le moteur appelle le backend par une méthode nouvelle de `VpnBackend`
   (`set_dns` / retrait), implémentée aussi par `DryRunBackend`.
   Sous Windows, `defguard` pose la règle NRPT `.` sur l'adaptateur, retire
   les règles d'un adaptateur disparu à la création d'une interface et les
   siennes au retrait : aucun nettoyage propre à Orion.
2. **Une fois `Up`**, pour tout profil Helios, remplacement compris : lecture de
   `GET /api/client/dns` sur `heliosd_url`, à côté du démarrage de la
   télémétrie (`orion-engine/src/service.rs`, `TelemetryManager::start`).
   Une lecture par connexion, avec reprise bornée tant qu'elle échoue
   (passerelle ancienne : 404, ou injoignable) ; en échec définitif, le
   défaut reste appliqué et c'est dit.
   - liste non vide : sans remplacement, nouvel appel `set_dns` si elle
     diffère de l'appliquée ; avec remplacement, rien ne change ;
   - liste vide : retrait du DNS de l'adaptateur, **remplacement compris**
     (le poste revient à son DNS local), signalé « la passerelle ne propose
     pas de DNS par le tunnel ». La passerelle répond vide quand elle ne
     route pas vers Internet : un résolveur public, même choisi par
     l'utilisateur, y serait injoignable (anti-objectif 3). *Choix de
     conception* : le remplacement ne remplace qu'une proposition non vide.
3. **Déconnexion explicite** : `remove_interface` retire la règle. Aucun
   changement au cycle de vie de l'adaptateur (ADR-001 §3 bis) : tant qu'il
   est monté, une requête DNS vers le résolveur part dans le tunnel et
   WireGuard la jette si la session est morte, comme le reste du trafic.

Un échec de `set_dns` n'est ni relancé en boucle ni avalé : il est rapporté
comme les écarts de capture (`CaptureCheck` / `assess_capture`), et
l'interface affiche que les requêtes DNS sortent hors du tunnel. Le tunnel
reste monté.

**Crash d'Orion** : la règle NRPT orpheline pointe vers un résolveur public,
que le poste joint alors en direct : la résolution continue (anti-objectif 1).

### 5.6 Orion : interface

- Profils, section « Avancé » : « DNS » — « Proposé par la passerelle »
  (défaut, profils Helios) ou « Personnalisé » avec une à trois adresses
  IPv4, validées à la saisie comme §5.1. Pour un wg-quick : la liste importée,
  modifiable.
- Panneau de posture : une ligne « DNS » qui donne les serveurs appliqués et
  leur origine (passerelle, défaut, personnalisé, profil), en ambre quand le
  DNS n'est pas appliqué alors que le profil est en tunnel complet.

Composants, espacements et libellés repris de l'existant (AGENTS.md, UI).

## 6. Contraintes

- Fail-closed aux frontières : validation stricte, aucun repli silencieux
  vers le DNS local présenté comme protégé.
- Aucune dépendance nouvelle : `defguard_wireguard_rs` 0.12 porte déjà
  `set_dns` (Windows : `SetInterfaceDnsSettings` + NRPT ; Linux :
  `systemd-resolved` ou `resolvconf`).
- Le profil `.orion` émis ne change pas : un Orion antérieur continue de
  l'importer.
- Compatibilité : un Orion récent face à une passerelle sans la route garde le
  défaut DNS4EU (404 traité comme « pas de proposition »).

## 7. Validation

- Unitaires : validation §5.1 ; route (proposition par défaut, liste, vide,
  `allow_client_internet` faux, pair inconnu refusé) ; priorité d'application
  §5.5 ; import wg-quick ; manifeste v8 → v9 et retour.
- Banc netns (côté passerelle seulement, le client du banc est un `wg` nu, pas
  Orion) : la route répond depuis le tunnel avec la liste de `network.toml`,
  vide quand `allow_client_internet` est faux ; une requête UDP/53 du client
  vers l'hôte « Internet » du banc traverse le tunnel et le NAT.
- Cible Windows (MANUAL-TESTING, nouvelle recette) : `Get-DnsClientNrptPolicy`
  montre la règle `.`, `Resolve-DnsName` répond, une capture sur la carte
  physique ne voit aucun port 53, crash d'Orion puis résolution toujours
  possible, profil « Helios seul » sans règle.

## 8. Documentation à mettre à jour

Les trois mentions de limite (ruleset, policy, ADR-006), SORTIE-IPV6 §
« DNS des clients », ADR-001 (amendement : DNS des postes), ROADMAP (D5
tranché, F7), MANUAL-TESTING, exemple de `network.toml`.

## 9. Laissé au constructeur

- Reprise bornée de la lecture (§5.5.2) : nombre et cadence.
- Forme exacte des événements et des libellés d'écart DNS, sur le modèle de
  `CaptureCheck`.
- Version du protocole du moteur, si le schéma du profil la touche.
- Le DNS appliqué sur un poste Linux sans `systemd-resolved` ni `resolvconf` :
  `defguard` le refuse, c'est rapporté comme un échec §5.5.

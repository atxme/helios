# Orion

Orion est le client de bureau WireGuard de la gateway Helios. L’application
combine une IHM React/TypeScript embarquée par Tauri et un cœur Rust portable
dans `crates/orion-core`.

Elle monte elle-même l’adaptateur WireGuard vers l’endpoint UDP du profil. Elle
ne dépend pas de l’API HTTP Helios pour établir le tunnel : l’API interne n’est
utilisée qu’après la connexion pour la télémétrie et le provisioning.

## Architecture

```text
IHM React
   │ invoke / events Tauri
   ▼
shell apps/orion/src-tauri
   │
   ▼
orion-core ── VpnController ── backend dry-run ou WireGuard réel
   │
   └── télémétrie / provisioning ── API Helios dans le tunnel
```

- `src/` contient l’IHM, les profils et le journal temps réel ;
- `src-tauri/` expose les commandes Tauri et embarque le frontend ;
- `orion-core` porte la configuration, le backend, l’inférence de handshake et
  le client de provisioning sans dépendance Tauri.

## Profil WireGuard

Un profil contient :

- un nom et l’endpoint `IP:port` ou `FQDN:port` de la gateway ;
- la clé privée Curve25519 du client et la clé publique de la gateway ;
- la VIP CGNAT attribuée au client ;
- `AllowedIPs` (`0.0.0.0/0, ::/0` par défaut) ;
- un keepalive persistant de 25 secondes par défaut ;
- un éventuel PSK post-quantique et l’URL interne de l’API Helios.

### Ce qui passe par le tunnel

`AllowedIPs` **est** la table de routage cryptographique de WireGuard : ce qui y
figure part chiffré vers la gateway, le reste sort par l'interface physique en
clair. L'écran Profils propose les trois listes qui couvrent l'usage courant,
sous « Avancé » ; le mode **Personnalisé** rouvre le champ de saisie et accepte
n'importe quelle liste de préfixes.

| Choix | `AllowedIPs` écrit |
| --- | --- |
| Tout | `0.0.0.0/0, ::/0` |
| Réseaux privés | VIP de la gateway en `/32`, puis `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| Helios seul | VIP de la gateway en `/32` |

La VIP est lue sur le profil — l'URL interne de l'API Helios d'abord, la
destination SSH ensuite — et non fixée en dur : un nom d'hôte n'en est pas une,
puisque le DNS d'Orion n'est pas tunnelisé. À défaut, `100.64.0.1/32` est
proposé, soit l'adresse que porte une gateway dont l'opérateur n'a pas changé
`wg_address`. Elle figure aussi dans « Réseaux privés » parce que le `release`
post-négociation n'est envoyé qu'à une adresse couverte par `AllowedIPs`
([NEGOCIATION-DE-CLE-V5](../../docs/specification/NEGOCIATION-DE-CLE-V5.md)).

> **« Réseaux privés » capte aussi le réseau local du poste.** Les trois plages
> RFC 1918 ne distinguent pas le `192.168.1.0/24` du bureau de celui de la box
> personnelle : imprimante, NAS et routeur du poste passent par le tunnel eux
> aussi, et deviennent injoignables si la gateway ne route pas vers eux. Un
> profil ne peut pas faire mieux tout seul — rien dans `ClientProfile` ne décrit
> les sous-réseaux qui vivent derrière la gateway, et la négociation ne les
> annonce pas. Quand le sous-réseau visé est connu, **Personnalisé** et ce seul
> préfixe valent mieux que les trois plages.

> **« Tout » capte aussi l'IPv6.** La gateway ne route aucun IPv6 vers ses
> pairs : ce que l'adaptateur capte en `::/0`, WireGuard le jette, et c'est ce
> qui empêche l'IPv6 d'un poste dual-stack de sortir en clair tunnel monté. Un
> profil enregistré avec `0.0.0.0/0` seul — l'ancien « Tout » — n'est jamais
> réécrit : il s'ouvre en **Personnalisé**, avec l'avertissement « Tunnel
> complet IPv4 seulement : le trafic IPv6 sort en clair », repris en ambre dans
> le panneau de posture. Choisir « Tout » puis enregistrer le corrige.
>
> **Ce que le pilote applique est relu.** Sous Windows,
> `defguard_wireguard_rs` 0.11 ne pose les routes que pour les familles
> d'adresses que l'adaptateur porte : si l'IPv6 y est indisponible, `::/0` est
> écarté sans erreur et l'IPv6 sort par l'interface physique alors que le
> tunnel paraît complet. Après chaque configuration, le backend réel relit les
> `AllowedIPs` du pair dans le pilote et, sous Windows, les routes de
> l'adaptateur. Un préfixe manquant est signalé par une erreur « AllowedIPs non
> appliqués par le pilote : ::/0 — … » et par la ligne « trafic via le tunnel »
> en ambre (« ::/0 non appliqué par le pilote — hors tunnel ») ; une relecture
> impossible est signalée comme « non vérifié ». Le tunnel reste monté avec ce
> qu'il capte : le démonter ne supprimerait pas la fuite IPv6 et rouvrirait
> celle de l'IPv4 (ADR-001 §3 bis). Le backend simulé ne relit rien et
> n'affirme donc rien.

### Protection du tunnel

L'écran Profils pose la question en une échelle de trois crans, et le cran
**est** le type de profil :

| Cran | Profil | Ce qui protège le premier handshake |
| --- | --- | --- |
| Aucune | `classic` | rien |
| PSK statique | `classic` | une clé partagée reçue hors bande, jamais renouvelée |
| Négociation Helios | `helios_key_negotiation` | un PSK ML-KEM-1024 dérivé avant le tunnel, à chaque connexion |

Choisir « PSK statique » ouvre directement la saisie de la clé : sur un profil
classique, ce PSK n'est pas un réglage avancé, c'est toute sa protection.

**L'échelle est tout le choix.** Le cran « Négociation Helios » écrit
`mode = ml_kem` et n'offre pas de mode à lui : une clé partagée est le cran du
dessous, et une négociation qui poserait celle-là au lieu d'en dériver une
fraîche serait la même décision écrite à deux endroits, sans rien à l'écran
pour dire lequel gagne. Monter sur ce cran retire donc le PSK du cran
précédent — `orion-core` refuse un profil qui garde une clé qu'aucun mode
n'utilise.

`static_psk` reste néanmoins un mode v5 explicite côté protocole : la
transaction QUIC a bien lieu et le client prouve la possession de la clé par un
engagement HMAC lié à la session avant que la gateway n'installe le PSK déjà
configuré ([NEGOCIATION-DE-CLE-V5](../../docs/specification/NEGOCIATION-DE-CLE-V5.md)
§9.1). Un document produit par `helios-ctl enroll` peut donc légitimement le
porter. Orion ne le compose plus mais l'affiche tel quel — la clé qu'il exige
comprise — avec un bouton **Passer en ML-KEM** : le réétiqueter serait mentir
sur ce que le profil fait, et masquer son PSK laisserait un profil invalide
sans champ à regarder.

Deux refus sont énoncés sur le cran lui-même plutôt qu'après coup :

- un profil enregistré ne change pas de type — le renommer crée un autre
  profil et rouvre le choix ;
- une fois un plancher franchi, la négociation ne se retire plus. C'est le
  cliquet anti-downgrade d'[ADR-001](../../docs/adr/ADR-001-WIREGUARD.md) :
  `ClientConfig::upsert` refuse d'abaisser un plancher connu, y compris en
  supprimant le bloc.

Les clés privées et PSK sont scellés dans le coffre ([ADR-006](../../docs/adr/ADR-006-SECRETS-AU-REPOS.md)) :
ni l’IHM ni un message Tauri ne les transportent, et l’écran n’affiche que la clé
**publique**. Le stockage vit dans le répertoire applicatif de l’OS sous
`net/helios/orion` ; `ORION_CONFIG` surcharge le chemin du fichier hérité en test.

## Construire et lancer

```sh
cargo run -p orion --features wireguard              # développement
cargo build --release -p orion --features wireguard  # binaire seul
cargo xtask orion-msi                                # installateur Windows
```

Les deux premières commandes suffisent au quotidien : **l’installateur n’est pas
nécessaire pour tester**. Le nom, l’icône et l’interface sont ceux du code dans
les trois cas, et `build.rs` s’en charge.

- **En debug**, l’IHM est servie par Vite : Orion le démarre lui-même s’il ne
  tourne pas, et toute modification de `src/` est visible au rechargement.
  `build.rs` vérifie l’arbre npm et exécute `npm ci` si une dépendance manque,
  puis prépare automatiquement les ressources WireGuardNT sous Windows afin
  que `cargo run` puisse démarrer immédiatement.
- **En release**, `cargo` ne connaît pas le `beforeBuildCommand` de la CLI
  Tauri. `build.rs` compare donc `dist/` aux sources et relance `npm run build`
  quand il est périmé — sans quoi le binaire embarquerait l’interface d’avant,
  qui se lance, s’affiche, et ment. Sous Windows, `build.rs` installe Node.js
  LTS via `winget` s’il manque, puis vérifie et installe automatiquement les
  dépendances du lockfile.
## Journal

Orion écrit **à la fois** sur la sortie standard et dans un fichier :

```
%APPDATA%\helios\orion\config\orion.log     (Windows)
~/.config/helios/orion/orion.log            (Linux)
```

Le fichier existe parce qu’un Orion installé n’a pas de console : en release,
`windows_subsystem = "windows"` envoie la sortie standard nulle part, et
demander à un utilisateur de recompiler sous `cargo run` pour obtenir un journal
revient à lui demander de rebâtir le produit. Il est **remis à zéro à chaque
démarrage** : ce qu’on cherche est ce lancement-ci, pas six démarrages plus tôt.

Par défaut : `info` partout, `debug` pour les crates du projet — assez pour voir
quel chemin le coffre a pris, ce que le TPM a répondu et pourquoi un profil n’a
pas chargé, sans noyer cela sous `hyper` et `rustls`. `RUST_LOG` remplace tout :

```sh
RUST_LOG=trace cargo run -p orion --features wireguard      # tout
RUST_LOG=orion_core::vault=trace cargo run -p orion         # le coffre seul
```

- **L’icône et le nom** viennent de `tauri.conf.json` et de `icons/icon.ico`,
  déclarés en `rerun-if-changed` : les remplacer suffit à ce que la prochaine
  compilation les embarque, exécutable, fenêtre et zone de notification
  comprises.

### Importer plutôt que ressaisir

Le bouton **Importer** de l’onglet Profils accepte deux formats :

- un profil Orion JSON versionné (`.json`), qui porte aussi les paramètres
  propres à Helios ;
- un fichier WireGuard `wg-quick` (`.conf`) avec exactement une section
  `[Interface]` et un seul `[Peer]`.

L’import charge un brouillon dans le formulaire. Il n’écrit rien tant que
**Enregistrer** n’est pas activé et annonce explicitement si le nom importé
remplacera un profil existant. Les documents sont bornés à 64 Kio, les clés
WireGuard doivent décoder exactement 32 octets et les options que le client ne
sait pas appliquer (`DNS`, scripts `PreUp`, plusieurs pairs, etc.) sont refusées
plutôt qu’ignorées.

Le format JSON courant est `orion-profile` version 1 :

```json
{
  "format": "orion-profile",
  "version": 1,
  "profile": {
    "name": "site-paris",
    "endpoint": "vpn.example.net:51820",
    "private_key": "base64-de-32-octets",
    "peer_public_key": "base64-de-32-octets",
    "address": "100.64.1.2/32",
    "allowed_ips": "0.0.0.0/0, ::/0",
    "persistent_keepalive": 25,
    "heliosd_url": "http://100.64.0.1:8080"
  }
}
```

`allowed_ips`, `persistent_keepalive`, `heliosd_url` et `preshared_key` sont
facultatifs. L’adresse virtuelle reste obligatoire : le tunnel initial en a
besoin avant de pouvoir joindre l’API interne. `AllowedIPs` vaut
`0.0.0.0/0, ::/0` et le keepalive 25 secondes lorsqu’ils sont omis ; un
`allowed_ips` explicite est importé tel quel, `0.0.0.0/0` seul compris (il est
alors signalé, pas élargi). Un `preshared_key` importé est traité comme un PSK
statique et désactive la négociation ML-KEM automatique ; il ne doit être
fourni que si les deux pairs portent déjà exactement la même valeur.

## Cycle de vie et protection anti-fuite

L’état `up` est inféré à partir d’un handshake de moins de 150 secondes.
WireGuard rekeyant silencieusement, il n’existe aucun état `rekeying` dans
l’application.

Orion n’installe pas de pare-feu local. Son invariant est le cycle de vie de
l’adaptateur : avec `AllowedIPs = 0.0.0.0/0, ::/0`, l’adaptateur reste monté en
`connecting` et après un échec. WireGuard capture alors les routes et jette les
paquets si aucun handshake n’est possible. Seule l’action explicite
« Déconnecter » appelle `down()`.

L’IHM affiche séparément l’état logique du tunnel et l’état réel de
l’adaptateur, afin qu’un échec protégé ne soit pas confondu avec un adaptateur
démonté.

## IHM embarquée

L’IHM utilise Material UI au-dessus de React. Le thème sombre Orion centralise
les couleurs, la typographie, les rayons, les états de focus et la réduction
des animations. Les couleurs de posture restent définies séparément dans
`src/components/state.ts` : elles expriment un état de sécurité et ne sont pas
de simples accents décoratifs.

Les composants MUI sont importés par chemin pour limiter le coût du bundle.
Emotion reste local à la WebView ; aucune police, feuille de style ou ressource
Google n’est chargée sur le réseau. La CSP Tauri existante suffit donc au thème
sans élargir `connect-src`, `font-src` ou `script-src`.

Le socle d’accessibilité comprend :

- une navigation par onglets au clavier avec relations `tab` / `tabpanel` ;
- des libellés explicites pour les actions à icône et les champs secrets ;
- une annonce des changements d’état, des erreurs et des événements ;
- un focus visible commun à tous les contrôles ;
- le respect de `prefers-reduced-motion` ;
- une confirmation avant la suppression d’un profil ;
- du texte sélectionnable, notamment pour les clés et les diagnostics.

L’intégration est configurée dans `src-tauri/tauri.conf.json` :

- `beforeDevCommand` lance Vite sur le port 1420 ;
- `beforeBuildCommand` exécute `npm run build` — précédé, sous Windows
  (`tauri.windows.conf.json`), de `npm run orion-deps`, qui met WireGuardNT en
  place à moins que `cargo xtask orion-msi` ne s’en soit déjà chargé ;
- `frontendDist: ../dist` embarque le résultat dans l’application native.
- une CSP restrictive est injectée, sans `unsafe-eval`, et
  `freezePrototype` est activé ;
- la capability de la fenêtre principale reste limitée à `core:default`.

Le package final se construit donc avec :

```sh
npm ci
npm run tauri build
```

Un simple `npm run build` produit uniquement `dist/`. Un simple `cargo build`
compile le shell Rust mais ne remplace pas le workflow de packaging Tauri.

## Développement

```sh
# Cœur portable et tests de sécurité
cargo test -p orion-core

# Tests et build du frontend
npm ci --prefix apps/orion
npm run test:unit --prefix apps/orion
npm run build --prefix apps/orion

# Application complète en simulation
cargo run -p orion

# Variante pilotée par la CLI Tauri
npm run tauri dev --prefix apps/orion
```

En profil de développement, `cargo run -p orion` vérifie que Vite écoute sur
le port 1420 et le démarre automatiquement si nécessaire. Le processus Vite est
arrêté avec Orion. La CLI Tauri continue d'utiliser `beforeDevCommand` ; Orion
détecte alors le serveur déjà actif et ne le lance pas une seconde fois.

Sous WSL2, l'affichage natif exige WSLg. `xdpyinfo` doit pouvoir joindre
`DISPLAY` avant le lancement ; sans WSLg, le shell peut être compilé mais aucune
fenêtre Linux ne peut être affichée.

Sous Linux, Tauri requiert notamment `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`librsvg2-dev`, `patchelf` et `libayatana-appindicator3-dev`. Sous Windows,
l’application utilise WebView2.

## Backend réel

Sans feature, Orion utilise le backend `dry-run`, qui simule l’adaptateur et le
handshake tout en testant le même cycle de vie. Le backend réel est fourni par
`defguard_wireguard_rs` derrière la feature `wireguard` :

```sh
# Sous Windows, `cargo build` télécharge et vérifie automatiquement WireGuardNT.
# La commande explicite reste utile pour préparer les ressources sans compiler.
cargo xtask orion-deps

# Compilation Rust du shell avec le backend réel
cargo build -p orion --features wireguard

# Package Tauri avec ce backend
cd apps/orion
npm run tauri build -- --features wireguard
```

Le backend réel doit être exécuté avec le plan de données et les droits requis
sur la plateforme. S’il ne peut pas être initialisé, Orion refuse de démarrer :
un binaire réel ne retombe jamais implicitement sur la simulation. L’IHM affiche
toujours le type de backend actif.

Le paquet Windows embarque les DLL AMD64 et ARM64 sous le chemin exact ouvert
par `defguard_wireguard_rs`; son manifeste demande `requireAdministrator`. Le
paquet Debian dépend de `libcap2-bin` et son `postinst` pose
`cap_net_admin=ep` sur `/usr/bin/orion`. Les limites de ces choix et la chaîne
Authenticode sont détaillées dans
[`../../docs/security/ORION-DISTRIBUTION.md`](../../docs/security/ORION-DISTRIBUTION.md).

Les fichiers `.orion` sont associés à Orion, avec une icône qui leur est propre
— la marque sur une feuille, pour qu'un profil ne se confonde pas avec le client
qui l'ouvre. Le premier double-clic et les suivants passent par la même file
single-instance, la même lecture Rust bornée à 64 Kio, le même parseur et la
même complétion des invitations depuis la clé privée locale de même nom.
L'import reste un brouillon à vérifier puis à enregistrer ; il n'écrase jamais
silencieusement la configuration.

L'extension était `.orionprofile` jusqu'en août 2026. Les documents déjà écrits
restent **lus** — les deux suffixes sont acceptés à l'import — mais seul
`.orion` est enregistré auprès de Windows : un double-clic sur un ancien fichier
ne démarre plus Orion, le glisser sur le bouton *Importer* fonctionne toujours.

## Zone de notification (Windows)

Fermer la fenêtre ne quitte pas : le tunnel et son lien de vivacité continuent,
et le menu de la zone de notification devient la seule surface d'Orion. Il n'est
donc pas une liste de raccourcis vers la fenêtre, mais un petit client :

```text
● État : Connecté
─────────────────
✓ poste-windows
  bureau
─────────────────
Ouvrir Orion
Gestion des profils…
Importer un profil à partir d'un fichier…
Journal d'Orion…
─────────────────
À propos d'Orion…
Quitter
```

La pastille reprend les couleurs d'état de `components/state.ts`. Cliquer un
profil coché **déconnecte** ; cliquer un autre le sélectionne et s'y connecte —
la sélection suit, sans quoi la fenêtre afficherait un profil pendant que le
tunnel en porte un autre. Un refus dévoile la fenêtre et affiche l'erreur : une
connexion lancée depuis un menu n'a aucun autre endroit où se plaindre.

Le menu est **reconstruit** à chaque changement d'état ou de liste de profils,
plutôt que modifié : tenir à jour un second modèle à côté du coffre finirait par
diverger le jour où un profil est renommé.

## Provisioning post-quantique

Le client sait générer une paire ML-KEM-768 éphémère, appeler
`POST /api/provision`, vérifier l’identité WireGuard annoncée par la gateway et
dériver un PSK de 32 octets lié aux deux identités et aux deux nonces.

Cette étape suppose que la clé publique du client a déjà été admise hors bande
sur Helios et que le tunnel WireGuard classique est joignable. La gateway pose
le PSK sur son plan de données avant de le remettre à Orion ; Orion le pose
ensuite sur son adaptateur sans le démonter. Un échec garde le tunnel classique
opérationnel et reste visible dans le journal.

## Commandes Tauri exposées

Le frontend utilise les commandes suivantes :

- `get_state`, `backend_kind`, `adapter_is_up`, `about_orion` ;
- `get_config`, `import_profile`, `save_profile`, `delete_profile`,
  `select_profile` ;
- `import_profile_path`, réservé aux chemins reçus de l'association système ;
- `connect`, `disconnect`.

Les événements `state_changed`, `log`, `telemetry` et `error` sont relayés sur
le canal `helios://event`. `helios://profile-path` signale qu'un chemin associé
attend dans la file Rust sans donner au frontend un accès général au système de
fichiers. `helios://tray-view` porte l'intention choisie dans la zone de
notification — dont `import`, qui n'est pas une vue mais l'ouverture du
sélecteur de fichier de l'écran *Profils*, et `about`. `helios://config-changed`
dit que la sélection a bougé côté Rust, ce qui arrive quand le menu connecte un
profil pendant que la fenêtre est ouverte derrière lui.

## Régression

Depuis la racine du dépôt, `bash scripts/regression.sh` compile le shell Tauri,
teste `orion-core` avec toutes ses features, vérifie le pont IPC, la CSP et les
capabilities, exécute Vitest et construit le frontend. Les tests du backend
WireGuard réel restent à effectuer sur la plateforme cible.

La recette complète pour l'application Tauri, les profils jetables et le cycle
adaptateur/connexion/déconnexion se trouve dans
[`../../docs/testing/MANUAL-TESTING.md`](../../docs/testing/MANUAL-TESTING.md).

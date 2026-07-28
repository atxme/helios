# Orion VPN

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
- `AllowedIPs` (`0.0.0.0/0` par défaut) ;
- un keepalive persistant de 25 secondes par défaut ;
- un éventuel PSK post-quantique et l’URL interne de l’API Helios.

Les clés privées et PSK sont masqués dans les représentations `Debug`, mais ils
sont actuellement persistés dans le fichier de profils local. La configuration
est stockée dans le répertoire applicatif de l’OS sous `net/helios/orion`. La
variable `ORION_CONFIG` permet de surcharger le chemin en test ou en
développement.

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
    "allowed_ips": "0.0.0.0/0",
    "persistent_keepalive": 25,
    "heliosd_url": "http://100.64.0.1:8080"
  }
}
```

`allowed_ips`, `persistent_keepalive`, `heliosd_url` et `preshared_key` sont
facultatifs. L’adresse virtuelle reste obligatoire : le tunnel initial en a
besoin avant de pouvoir joindre l’API interne. `AllowedIPs` vaut `0.0.0.0/0` et
le keepalive 25 secondes lorsqu’ils sont omis. Un `preshared_key` importé est
traité comme un PSK statique et désactive la négociation ML-KEM automatique ;
il ne doit être fourni que si les deux pairs portent déjà exactement la même
valeur.

## Cycle de vie et protection anti-fuite

L’état `up` est inféré à partir d’un handshake de moins de 150 secondes.
WireGuard rekeyant silencieusement, il n’existe aucun état `rekeying` dans
l’application.

Orion n’installe pas de pare-feu local. Son invariant est le cycle de vie de
l’adaptateur : avec `AllowedIPs = 0.0.0.0/0`, l’adaptateur reste monté en
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
# Requis sur Windows : télécharge WireGuardNT et vérifie son empreinte épinglée.
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

Les fichiers `.orionprofile` sont associés à Orion. Le premier double-clic et
les suivants passent par la même file single-instance, la même lecture Rust
bornée à 64 Kio, le même parseur et la même complétion des invitations depuis
la clé privée locale de même nom. L'import reste un brouillon à vérifier puis à
enregistrer ; il n'écrase jamais silencieusement la configuration.

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

- `get_state`, `backend_kind`, `adapter_is_up` ;
- `get_config`, `import_profile`, `save_profile`, `delete_profile`,
  `select_profile` ;
- `import_profile_path`, réservé aux chemins reçus de l'association système ;
- `connect`, `disconnect`.

Les événements `state_changed`, `log`, `telemetry` et `error` sont relayés sur
le canal `helios://event`. `helios://profile-path` signale qu'un chemin associé
attend dans la file Rust sans donner au frontend un accès général au système de
fichiers.

## Régression

Depuis la racine du dépôt, `bash scripts/regression.sh` compile le shell Tauri,
teste `orion-core` avec toutes ses features, vérifie le pont IPC, la CSP et les
capabilities, exécute Vitest et construit le frontend. Les tests du backend
WireGuard réel restent à effectuer sur la plateforme cible.

La recette complète pour l'application Tauri, les profils jetables et le cycle
adaptateur/connexion/déconnexion se trouve dans
[`../../docs/testing/MANUAL-TESTING.md`](../../docs/testing/MANUAL-TESTING.md).

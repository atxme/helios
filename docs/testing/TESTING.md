# Stratégie de test et de sécurité

La commande de référence est :

```sh
bash scripts/regression.sh
```

Elle doit être verte avant fusion ou livraison. Elle utilise les lockfiles,
interdit les avertissements Clippy et couvre les features matérielles au niveau
compilation/tests sans exécuter d’effet réel.

**La CI exécute des contrôles ciblés**, sur les poussées vers `main` et les PR
qui la visent. `scripts/ci-plan.py` sélectionne les crates modifiés et leurs
dépendants transitifs à partir des chemins déclarés par Cargo, y compris les
dépendances optionnelles, de build, de test et propres à une plateforme. Les
modifications des manifests racine, du lockfile Rust ou de `vendor/` couvrent
tous les crates. Une modification documentaire seule ne lance aucun build.

Linux joue Clippy strict et les tests des crates concernés, toutes features,
sans le shell Tauri. Windows compile et teste les chemins Orion/Astra concernés.
Le compagnon Astra est aussi relié explicitement au build d'Orion, qui le
construit hors du graphe Cargo ; les tests natifs d'`orion-core` accompagnent
toute compilation du client Windows.
Les interfaces sont testées et construites quand leurs sources changent ; la
console gateway est aussi construite quand les tests Rust doivent l'embarquer.
Les audits se déclenchent sur modification des lockfiles. Cargo utilise deux
jobs au plus, sans compilation incrémentale ni informations de débogage Rust.

L'action *Régression* accepte un déclenchement manuel (`workflow_dispatch`) pour
jouer tous ces contrôles. Elle n'appelle ni `scripts/regression.sh`, ni
`scripts/coverage.sh` : la campagne complète et la couverture restent locales.
Le développeur reste responsable de la campagne complète avant fusion/livraison.

## Matrice automatisée

| Couche | Contrôles |
|---|---|
| Rust | `fmt`, Clippy `--all-targets --all-features`, tests workspace `--all-features`, doc-tests |
| Dépendances Rust | `cargo audit` : vulnérabilités bloquantes, avis informatifs suivis |
| Helios/Orion web | `npm ci`, `npm audit --audit-level=moderate`, Vitest, TypeScript et build Vite |
| Signatures | hybride AND, anti-downgrade, époque signée, domaines, JSON strict, Ed25519 faible/non canonique |
| TPM | anti-rejeu, PCR facultatif, rejet v1, ordre authentification → compteur → PCR |
| API | routeur complet, absence de secrets, JSON obligatoire pour les mutations, absence de CORS permissif |
| Tauri | commandes IPC, CSP, prototypes figés et capability minimale |
| Éditeur | permissions 0700/0600, auto-vérification, clés cohérentes et refus d’écrasement |
| Réseau | états, expiration de handshake, règles fail-closed et transaction préparée avant application, ouverture DHCP scopée au WAN et fermée par défaut |
| Provisioning PQ | tour ML-KEM complet via l’endpoint, PSK posé avant d’être annoncé, refus fail-closed si la pose échoue, annulation en mémoire et restauration du PSK précédent, adaptateur client jamais démonté |
| Key-negotiation | JSON strict et borné, anti-downgrade/rejeu, mTLS en enveloppe, certificats et transcripts ML-DSA-65, substitution `kpub`/ciphertext, trois modes, pose gateway avant réponse, handshake client frais, ACK signé, rollback, écoute dual-stack `[::]` (interop Orion en IPv4 et en `[::1]`, source `::ffff:` comptée comme son IPv4, repli IPv4 sur `EAFNOSUPPORT` seulement) |
| Mise à jour applicative | manifeste `helios-binary-release-v1` : signature hybride, altération du binaire, anti-rollback de `release_sequence`, staging borné et restauration du lien `current` (ADR-003) |
| Autorisation | routes de mutation réservées aux pairs `admin`, résolution par VIP source en `/32`, refus d'un pair ordinaire, en-têtes de proxy ignorés (ADR-003) |
| Admission | VIP dérivée de la clé publique, adresse de la gateway réservée, doublons de nom et de clé refusés, PSK des autres pairs préservés, persistance sans clé privée ni PSK (ADR-004) |
| Bundle d'installation | manifeste `helios-bundle-v1` : signature hybride, fichier altéré, manquant **et surnuméraire**, chemin hors racine, lien symbolique, destination inconnue, canal, anti-rollback, configuration préservée (ADR-004) |

## Fuzzing planifié

Le workflow *Fuzzing planifié* s'exécute chaque dimanche à 03:17 UTC et peut
être lancé manuellement. Il ne s'exécute pas sur les pull requests. Il utilise
la toolchain nightly uniquement pour `cargo-fuzz`, qui est requis par
libFuzzer, et conserve le build fuzzing hors de l'espace de travail principal.

Toutes les targets retournées par `cargo fuzz list` (`signed_object`,
`trust_transaction`, `x509_documents`, `gateway_state_machine` et
`tunnel_addresses`) sont compilées une fois puis exécutées séquentiellement
avec un budget de 60 secondes chacune. Le profil `--dev` accepte le trousseau
de développement tout en conservant l'interdiction de ce trousseau dans les
livraisons release. AddressSanitizer reste actif. Le job est limité à 20 minutes.
Les corpus générés, les
artefacts de crash et les logs sont publiés comme un artefact conservé 30 jours,
y compris lorsqu'une target échoue ; l'échec est ensuite propagé au workflow.

Cette campagne complète les tests de graines de `aether::fuzzing` et ne remplace
pas les validations matérielles décrites plus bas. Les corpus et crashes issus
d'une campagne doivent être examinés avant toute suppression ou régénération.

`cargo-audit` est un prérequis local :

```sh
cargo install cargo-audit --locked
```

La CI l’installe explicitement. Les vulnérabilités RustSec font échouer la
campagne. Les avis informatifs `unmaintained`/`unsound` transitifs sont affichés
et suivis dans [SECURITY.md](../security/SECURITY.md), car `--deny warnings` rendrait la CI
inexécutable tant que Tauri Linux dépend de GTK3. Les audits ne détectent pas une
erreur de conception ; les tests d’invariants restent obligatoires.

## Mesure de couverture

La mesure locale complète se lance depuis la racine du dépôt :

```sh
bash scripts/coverage.sh
```

Elle produit trois résultats séparés, afin qu’une moyenne du workspace ne
masque pas un produit ou une couche peu exercée :

- **Orion Rust** : `orion-core` et les commandes Tauri ;
- **Helios Rust** : tous les autres crates et outils Rust ;
- **Orion UI** : toutes les sources TypeScript/React, y compris celles que les
  tests n’importent jamais et qui doivent donc compter pour zéro.

Les rapports navigables sont écrits dans
`target/coverage/rust-html/html/index.html` et
`target/coverage/orion-ui/index.html`. Le résumé JSON Rust reste dans
`target/coverage/workspace.json`, ce qui permet de comparer deux campagnes sans
dépendre d’un répertoire temporaire.

La CI ne mesure plus la couverture : l'instrumentation et la recompilation
complète sont trop coûteuses pour les runners disponibles. Le job Windows
conserve les tests natifs sans instrumentation. Pour mesurer les branches
`cfg(windows)` (DPAPI, coffre logiciel, BitLocker, WER et routes), lancer
`cargo llvm-cov --package orion-core --package orion --all-features` sur un
poste Windows disposant de `cargo-llvm-cov` et `llvm-tools-preview`. Un rapport
Linux n'inclut pas ces branches.

Cette commande mesure ce que l’hôte a réellement compilé. Sous Linux, un
module Windows peut afficher une couverture élevée parce que seul son refus
`cfg(not(windows))` est présent ; le code Win32 exclu n’entre pas dans le
dénominateur. De même, l’exécution d’un simulateur ne valide pas les effets
TPM, Netlink, WireGuard noyau ou WireGuard-NT. Ces chemins restent soumis à la
recette cible ci-dessous : augmenter leur pourcentage depuis WSL2 produirait un
indicateur trompeur, pas une validation supplémentaire.

La campagne d’un poste Windows enrôlé commence également par
`cargo test -p orion-core --all-features` et
`cargo test -p orion --all-features` avant de toucher la gateway :

```powershell
.\scripts\campaign-windows.ps1 -Profile poste-windows
```

Elle ajoute aux tests CI le vrai WireGuard-NT, l’identité déjà scellée de ce
poste et la négociation avec une gateway réelle.

## Invariants de sécurité verrouillés

1. Seul `TunnelState::Up` autorise le trafic gateway.
2. Le kill-switch précède tout réseau et reste engagé à l’arrêt.
3. Un mode réel sans backend noyau opérationnel échoue au démarrage.
4. Le ruleset Netlink est atomique ; une traduction incomplète n’est pas envoyée.
5. Orion ne démonte son adaptateur qu’après déconnexion explicite.
6. Un backend Orion réel indisponible ne retombe pas sur le dry-run.
7. `GET /api/network` ne sérialise jamais clé privée ni PSK.
8. Une mutation HTTP sans JSON est refusée et aucun CORS wildcard n’est publié.
9. Ed25519 et ML-DSA-65 sont toutes deux obligatoires ; `key_epoch` est signé.
10. Une release ne compile pas avec le trousseau éditeur de développement, même
   si son chemin est fourni explicitement.
11. Le billet TPM v1 ne bénéficie d’aucune période de compatibilité.
12. Une route de mutation exige un pair `admin`, identifié par l’adresse source
   du socket ; aucun en-tête de proxy ne participe à la décision.
13. Une `release_sequence` inférieure ou égale à la dernière confirmée est
   refusée, y compris avec des signatures valides.
14. Un binaire installé qui n’atteint pas son point de disponibilité rend la
    main à la version précédente.

Le mode explicite `--unsafe-disable-firewall` est testé séparément de ces
invariants nominaux : il exige toujours les backends WireGuard/TPM réels,
supprime `inet helios` par une transaction idempotente `Add → Del`, publie
`firewall_enforced=false` et n'est jamais sélectionné après une erreur du
backend Netlink. Le drop-in posé par `deploy.sh --sans-firewall` survit à une
mise à jour applicative ; seul `--avec-firewall` le retire.

Lorsqu’un bug de sécurité est corrigé, ajouter d’abord un test qui échoue avec
l’ancien comportement et le garder comme test de non-régression.

## Tests matériels obligatoires

Les tests automatisés ne peuvent pas promettre la fiabilité du matériel absent.
La gateway de laboratoire ne se compile plus sur place : elle reçoit un bundle,
comme une gateway de production (ADR-004).

Sur le poste de build :

```sh
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo xtask bundle
cargo run -p helios-publisher -- bundle --dir target/bundle/<nom> --channel testing …
cargo xtask pack --dir target/bundle/<nom>
```

Sur la gateway de laboratoire :

```sh
sudo ./scripts/setup-target.sh
sha256sum helios-<version>-<target>.tar.gz    # comparer à l'empreinte publiée
sudo ./helios-installer bootstrap --archive helios-<version>-<target>.tar.gz
```

Valider avec accès console :

- démarrage fail-closed avant création de l’interface ;
- handshake réel, passage `connecting` → `up`, puis expiration ;
- absence de trafic LAN dans tous les états sauf `up` ;
- erreur Netlink laissant intacte la politique précédente ;
- API inaccessible depuis le WAN et accessible via `helios0` ;
- Orion : adaptateur/routes maintenus sur panne UDP, retrait sur déconnexion ;
- installateur Orion Windows : `wireguard.dll` présente et signée par son
  éditeur dans un bundle produit après `cargo xtask orion-deps`, manifeste
  `requireAdministrator`, et horodatage RFC 3161 valide sur l'exécutable comme
  sur l'installateur ;
- association Orion : double-clic sur `.orion` au premier lancement puis
  avec l'application déjà ouverte, une seule instance et reprise de la clé
  privée locale de même nom ;
- icône des documents `.orion` : après installation du MSI, l'Explorateur montre
  l'icône de document — feuille à coin plié — et non celle de l'application, en
  thème clair comme en thème sombre, aux quatre tailles d'affichage. Le fragment
  WiX est la seule pièce de la chaîne d'association que rien ne vérifie hors de
  Windows : une `componentRefs` absente produit un installateur qui se construit
  et s'installe sans jamais écrire la clé ;
- zone de notification : la pastille et la ligne d'état suivent le tunnel ;
  cocher un profil connecte, le décocher déconnecte, et un profil qui refuse de
  monter dévoile la fenêtre avec son erreur. La liste suit un profil enregistré,
  supprimé ou renommé. `IconMenuItem` n'est exercé que là : le module est
  type-vérifié sous Linux en forçant la feature `tray-icon`, ce qui ne dit rien
  du rendu Windows ;
- identité cliente sous Windows : un document produit par `helios enroll`
  est importé, l'écran *Profils* annonce l'identité **scellée**, la connexion
  négocie en ML-KEM après suppression du fichier d'enrôlement, et la même
  identité recopiée sur un autre compte Windows échoue au descellement ;
- paquet Orion Debian : `getcap /usr/bin/orion` annonce
  `cap_net_admin=ep`, puis WebKitGTK démarre sans dépendre de
  `LD_LIBRARY_PATH` ;
- billet de rescellement : signé valide, rejoué, altéré et PCR optionnel — le
  scellement lui-même est désormais couvert par la catégorie `tpm` de la
  campagne, qui l'exerce sur `/dev/tpmrm0` ;
- provisioning PQ : un client Orion réel obtient son PSK dans le tunnel, le
  handshake suivant (≤ 2 min) réussit avec `PresharedKey` posé des deux côtés,
  et `wg show` confirme le slot renseigné sur la gateway comme sur le client ;
- provisioning PQ, chemin dégradé : gateway dont `sync_peers` échoue — le client
  doit rester en tunnel classique opérationnel, sans PSK orphelin ;
- key-negotiation : rediriger UDP 51821 et UDP 51820 séparément, vérifier les
  trois modes, un certificat client non lié, un ciphertext altéré, la fermeture
  avant confirmation, le timeout, puis un handshake réussi avec le PSK négocié
  et l’ACK de commit ;
- key-negotiation sur IPv6 : `ss -ulpn` sur la gateway montre l'écoute de
  négociation sur `[::]:<port>` (une seule socket, dual-stack) ; un client
  Orion dont le seul uplink est IPv6, ou dont le profil nomme un endpoint
  `[v6]:port`, négocie en ML-KEM, pendant qu'un client IPv4 négocie toujours
  sur le même port. Le journal nomme les sources IPv4 sous leur forme
  `a.b.c.d`, jamais `::ffff:a.b.c.d`. Les tests automatisés ne
  passent que par la boucle locale : ni le routage, ni le pare-feu `inet` sur
  le WAN, ni la question de savoir si le noyau livre à la socket un paquet IPv6
  dont la source est elle-même de la forme `::ffff:` n'y sont éprouvés. Sur une
  gateway démarrée avec `ipv6.disable=1`, l'écoute doit retomber sur
  `0.0.0.0:<port>` avec un avertissement qui en donne la raison ;
- réparation sur redémarrage de gateway (§12.5) : tunnel `ml_kem` monté,
  `systemctl restart heliosd`, puis **ne rien faire**. Le journal client doit
  annoncer « renégociation 1/3 » en nommant le handshake vieilli, et le tunnel
  doit reporter du trafic en moins de trois minutes sans geste de
  l'utilisateur. Le contre-essai compte autant : gateway éteinte pour de bon,
  trois renégociations puis un tunnel en erreur — pas une boucle. Et le même
  redémarrage sur un profil `static_psk` ne doit déclencher **aucune**
  renégociation : ce slot est relu depuis `network.toml` ;
- migration du manifeste de coffre v4 → v5 : installer par-dessus un Orion qui
  détient déjà des profils scellés, sans en réimporter aucun. Chaque profil doit
  s'ouvrir, afficher son type — `helios_key_negotiation` pour ceux qui portent un
  bloc — et se connecter comme avant. Puis enregistrer une modification anodine
  et vérifier au redémarrage suivant que le type est **toujours** le même : c'est
  le scellement en v5 qui écrit l'inférence, et une réponse qui changerait entre
  deux lectures serait exactement la panne que le discriminant supprime ;
- désinstallation d'un profil monté (§12.2) : supprimer le profil dont le
  tunnel est up. La gateway doit journaliser le `release` **avant** que
  l'adaptateur tombe, et `wg show` doit y montrer le slot vidé tout de suite —
  pas cinq minutes plus tard par la récupération. L'ordre est ce qui est
  éprouvé : le message voyage dans le tunnel et est signé par l'identité du
  profil, donc supprimer d'abord ne libère rien ;
- identité key-negotiation : `heliosd init-key-negotiation` scelle réellement la
  clé serveur, refuse l’écrasement sans `--rotate` et redémarre avec le même
  certificat et la même clé descellée ;
- mise à jour applicative ([ADR-003](../adr/ADR-003-MISES-A-JOUR-APPLICATIVES.md)) :
  transfert du manifeste et du binaire par fragments JSON, refus d'une signature
  altérée, refus d'une `release_sequence` inférieure ou égale à la dernière
  confirmée, activation, redémarrage du daemon et reconnexion de l'API ;
- mise à jour applicative, rollback : un binaire qui n'atteint pas son point de
  disponibilité dans le délai imparti doit rendre la main à la version
  précédente, service redémarré et lien `current` restauré ;
- autorisation : un pair `admin = false` se voit refuser toute route de
  mutation, et l'adresse source du socket seule fait foi — jamais un en-tête de
  proxy ;
- identité de la gateway ([ADR-004](../adr/ADR-004-CHAINE-DE-LIVRAISON.md) §3) :
  `heliosd init-identity` scelle réellement dans le TPM, refuse d'écraser un
  coffre existant sans `--rotate`, n'écrit la clé privée nulle part en clair, et
  la gateway redémarrée retrouve la même identité — seul le scellement effectif
  distingue ce chemin d'un succès apparent, et il n'est pas observable en WSL2 ;
- séquestre, circuit complet : `helios escrow keygen` sur le poste
  opérateur, `escrow_public_key` déclarée, séquestre écrit par la gateway au
  scellement, `helios escrow open` hors ligne, dépôt du fichier de
  récupération, redémarrage — l'identité doit être restaurée, rescellée, et le
  fichier de récupération effacé ;
- admission : la VIP dérivée par `heliosd peer add` est bien celle que le client
  reçoit à l'enrôlement, et l'ajout d'un pair n'efface ni la clé scellée ni les
  PSK des pairs déjà connectés — vérifier par `wg show` que leurs slots restent
  renseignés après l'opération ;
- bundle d'installation ([ADR-004](../adr/ADR-004-CHAINE-DE-LIVRAISON.md) §7 bis)
  sur une machine réelle : `bootstrap` sur une gateway vierge, unités
  effectivement rechargées par systemd, service démarrable, puis `bootstrap`
  d'une séquence supérieure sur une gateway **déjà configurée** — la
  configuration, l'identité scellée et les pairs admis doivent survivre. La
  campagne automatisée couvre la vérification et les refus, pas l'interaction
  avec systemd ni la persistance à travers un redémarrage.

- coffre d'autorité Astra ([ADR-008](../adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md) §4),
  sur le poste où la clé de sécurité est branchée — Windows en administrateur,
  ou un Linux avec accès au périphérique HID :
  `astra-signer init` crée le coffre et enregistre la première clé, puis
  `astra-signer verify` la rouvre après avoir débranché et rebranché ;
  `astra-signer enrol` enregistre la seconde en la branchant à la place de la
  première, et **chacune** des deux rouvre ensuite les ancres seule. Vérifier
  aussi qu'une troisième clé s'enrôle exactement de la même façon, qu'une clé
  jamais enrôlée est refusée sans ambiguïté, que rebrancher une clé déjà
  enregistrée pour un second slot est refusé par la clé elle-même — c'est
  l'`excludeList` CTAP2 qui répond, pas le coffre —, et que `remove` ne laisse
  jamais moins de deux slots. Un mauvais PIN doit refuser, pas ouvrir.

  Ce qui **n'est pas** exerçable ailleurs : rien d'autre. La séquence complète
  est éprouvée en dur par `tools/astra-signer/tests/enrolment.rs` contre des
  clés simulées ; ce que seule la cible établit, c'est que la clé produit bien
  une sortie `hmac-secret` stable pour un couple (credential, sel) à travers
  débranchements et redémarrages. Si elle ne l'était pas, le coffre ne se
  rouvrirait plus et aucun test hors matériel ne l'aurait dit.

  Sous Windows, éprouver **les deux transports** : `--transport platform`
  (défaut) doit fonctionner depuis une console ordinaire, le système demandant
  lui-même PIN et contact ; `--transport hid` doit fonctionner depuis une
  console administrateur et échouer sans, en nommant l'élévation. Vérifier
  qu'un coffre créé par l'un s'ouvre par l'autre — le credential appartient à
  la clé, pas à l'API. WSL2 n'a aucun passthrough USB. CTAP n'est **pas** une feature de
  compilation — tout binaire `astra-signer` porte la pile, et il n'existe aucun
  chemin qui ouvre le coffre sans clé. Le prix est une dépendance de
  compilation : `libudev` sous Linux, posée par `scripts/setup-dev.sh`, sans
  laquelle le workspace entier ne se bâtit plus.

- domaine de confiance, les deux moitiés
  ([ADR-008](../adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md), guide :
  [DEPLOIEMENT-ASTRA](../DEPLOIEMENT-ASTRA.md)) : `astra bootstrap` dans le
  conteneur puis `heliosd init-trust-domain` sur la gateway, avec les valeurs
  du même `astra-signer init`. Vérifier qu'un second appel de chacune est
  refusé — une seconde histoire pour un domaine repartirait aux époques 1 face
  à des clients qui en tiennent de plus hautes, et chacun la refuserait ; que
  `heliosd init-trust-domain` réussit **TPM indisponible**, puisqu'il ne
  descelle rien ; que le nom de serveur et la clé WireGuard écrits dans le
  registre sont bien ceux de la leaf PQ servie et non des valeurs retapées ; et
  qu'au redémarrage le journal passe de « no certificate registry » à
  « certificate lifecycle ready ».

  Pour un registre historique créé sans `--client-tls-ca`, vérifier daemon
  arrêté que `heliosd repair-client-tls-ca-bootstrap` remplace la CA opérateur
  par la CA-TLS du relais tout en conservant les pairs, leurs certificats PQ,
  les révocations et les distributions en attente. La répétition doit être
  idempotente ; une génération cliente supérieure à 1, un candidat, un
  successeur ou une rotation d'ancre en cours doit refuser toute écriture.

  Le conteneur lui-même : rootfs en lecture seule effectif (une écriture hors
  `/var/lib/astra` et `/tmp` doit échouer), aucune capacité, UID 10001, et le
  volume d'état seul montage. Restaurer une sauvegarde du volume dont la tête
  d'audit diffère de `--expected-audit-head` doit **refuser le démarrage**, sauf
  l'extension composée exclusivement des anciennes entrées
  `StatusPublished` produites par une lecture de statut — celles-ci sont une
  compatibilité de migration et ne constituent pas une décision d'autorité.
  Toute autre entrée après le témoin reste un fork et doit être refusée.

- **uplinks multiples** (`wan_iface = "auto"`), sur une machine qui a les deux
  liens. C'est la bascule qu'il faut éprouver, pas le choix :
  `nft list ruleset` doit porter **les deux** interfaces — écouteur WireGuard,
  écouteur de négociation, DHCP, sortie de la gateway, forward client et un
  masquerade par lien. Puis, tunnel monté et client connecté, **débrancher le
  câble** : le trafic client doit continuer par le Wi-Fi sans redémarrage et
  sans coupure du tunnel. Rebrancher : il doit repartir par le filaire dès que
  le noyau redéplace sa route.
  Vérifier aussi qu'après une relecture à chaud de `network.toml` le ruleset
  porte toujours la liste résolue et non `auto` ; et qu'un lien sans bail est
  bien permis, sinon son DHCP ne passerait jamais.
  Suivi après le démarrage (`orchestrator::uplinks`) : démarrer câble
  débranché, puis le brancher — en moins de quelques secondes, `nft list
  ruleset` doit nommer l'interface et le journal porter « WAN interfaces
  updated from the kernel ». Même chose en branchant un adaptateur USB, puis en
  le retirant : il doit disparaître du ruleset. Pendant ces reconstructions, un
  client connecté par l'autre lien ne doit perdre ni le tunnel ni ses
  connexions établies. La décision et l'application atomique sont éprouvées
  hors noyau ; la transaction nftables réelle et l'absence de coupure ne
  s'établissent que sur cible.
  La sortie inverse — un désaccord métrique — se force en abaissant la métrique
  Wi-Fi sous celle du filaire : les deux restent permis, seul l'ordre et
  l'avertissement changent.
  La sélection elle-même est éprouvée hors noyau ; ce que seule la cible
  établit, c'est que les marqueurs sysfs d'un vrai pilote Wi-Fi sont ceux que
  le module lit, et qu'une bascule réelle ne coupe pas les clients.
- **IPv6 du tunnel** (`ADRESSAGE-IPV6.md` §6 et §9, tickets T12 et T13), sur
  une gateway avec `wg_address_v6` et un pair qui porte `address_v6`, WAN à
  1500 :
  - `ip -6 addr show dev helios0` montre `<préfixe>::1/64` ;
    `wg show helios0 allowed-ips` montre, pour ce pair, **exactement** son
    `/32` et son `/128` ;
  - `ip -6 route show table 51820` montre un `/128` par pair, `dev helios0 src
    <préfixe>::1` ; `ip -6 rule` montre `32000: from all to <préfixe>::/64
    lookup 51820` ; `ip route show table 51820` et `ip rule` (IPv4) sont
    identiques à ceux d'une gateway sans IPv6 ;
  - avec `allow_tunnel_icmp = true`, `ping -6 <VIP6 du pair>` depuis la gateway
    et `ping -6 <préfixe>::1` depuis le client répondent ; avec
    `allow_tunnel_icmp = false`, ni l'un ni l'autre. Orion ne pose pas encore
    l'adresse IPv6 sur son adaptateur (ticket T19) : le client de cet essai est
    un `wg-quick` dont `Address` porte le `/32` et le `/128` du pair ;
  - `helios status` affiche `IPv6 installed`, et `GET /api/status` porte
    `"ipv6": "installed"` ; `systemctl stop heliosd` retire la règle et vide
    la table `51820` dans **les deux** familles ;
  - chemin dégradé : `sysctl -w net.ipv6.conf.default.disable_ipv6=1`, puis
    redémarrer `heliosd`. La gateway doit démarrer en IPv4 seule : aucune
    adresse IPv6 sur `helios0`, aucun `/128` dans `wg show`, aucune règle ni
    route `ip -6` dans la table `51820`, un avertissement « IPv6 not installed »
    dans le journal, `"ipv6": {"unavailable": {"reason": "disabled_by_kernel",
    …}}` dans `GET /api/status`, et les clients IPv4 servis comme avant.
    Remettre la valeur à `0` ensuite ;
  - même essai avec une WAN à MTU 1340 (tunnel à 1260) :
    `"reason": "tunnel_mtu_too_small"` ;
  - le refus que seul le noyau formule (retenté sans IPv6 après démontage de
    l'interface, raison `address_refused`) n'a pas de déclencheur connu en
    dehors des deux cas précédents, qui sont écartés avant la montée : il
    n'est éprouvé qu'en dry-run (`DryRunBackend::without_ipv6`).
  Aucune ouverture ne doit apparaître : `nft list ruleset` est identique avec
  et sans `wg_address_v6` (§6.4).

Ces essais modifient le pare-feu, les routes, le TPM et le binaire installé : ne
jamais les lancer contre une appliance de production.

L'ADR-003 retire RAUC du chemin de mise à jour Helios : la mise à jour ne
remplace ni rootfs, ni kernel, ni bootloader, ne redémarre pas la machine, et
laisse donc les PCR 0/4/7 inchangés — aucun billet de rescellement n'est requis.
Helios ne distribue toujours pas de noyau ni de rootfs. En revanche, la gateway
tourne sur une Debian ordinaire qu'il faut corriger : la **fenêtre de mise à
jour** ([ADR-007](../adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md)) couvre ce cas, et
elle exige les essais ci-dessous.

### Fenêtre de mise à jour TPM — essais sur cible

Rien de tout cela ne se prouve en WSL2, et le lot 0 conditionne le reste : sans
lui, la valeur réelle de la clause PCR 0/7 est une supposition.

**Lot 0 — relever l'état de la machine**, avant tout essai :

```sh
ls -l /dev/tpmrm0                    # TPM présent ?
mokutil --sb-state                   # Secure Boot actif ?
tpm2_pcrread sha256:0,4,7            # avant
tpm2_getcap handles-nv-index         # espace NV libre, index 0x1804845 libre ?
```

Puis, après `apt upgrade` d'un noyau **et redémarrage**, relever `tpm2_pcrread`
à nouveau. Trois résultats à consigner : PCR 4 a-t-il bougé, PCR 0 et 7 sont-ils
restés stables, et Secure Boot était-il actif. Un PCR 4 immobile signifie que la
chaîne de démarrage ne mesure pas le noyau — auquel cas la fenêtre est inutile
*et* le scellement nominal ne protège pas ce qu'on croit.

Répéter pour chaque classe de paquet : noyau, `grub-efi` / `shim-signed`,
`fwupd` (base Secure Boot), et un paquet quelconque comme témoin négatif.

**Essais de la fenêtre**, dans cet ordre :

- `heliosd tpm update-readiness` sur un démarrage nominal : `ready`. Le tester
  aussi hors nominal — démarrer sur un billet de rescellement, puis vérifier
  qu'il répond `unavailable` et que `helios update` refuse **sans avoir
  touché à `apt`** ;
- sans fenêtre armée, `heliosd tpm update-status` ne doit imprimer **aucune**
  ligne `esys` : l'index NV absent se demande par `TPM2_GetCapability`, qui
  répond sans échouer. Non vérifiable en WSL2 — ce chemin ne s'exerce que sur
  un TPM réel ;
- `heliosd tpm prepare-update` puis `heliosd tpm update-status` : `armed`, et
  `tpm2_nvreadpublic 0x1804845` montre un index ordinaire, écrit, sans
  `OWNERREAD` et avec `POLICYREAD` ;
- `heliosd tpm cancel-update` : le payload NV est écrasé, le marqueur disque
  disparaît et `update-status` répond `none` ;
- **le cas nominal** — armer, `apt upgrade` d'un noyau, redémarrer : le journal
  annonce la consommation de la fenêtre, le tunnel remonte, et **aucun client
  n'est ré-enrôlé**. C'est l'essai qui compte ; les autres ne font que borner
  ses modes d'échec ;
- redémarrer une seconde fois : descellement nominal, aucune fenêtre ;
- armer, copier `/var/lib/helios/update-window.marker`, laisser la fenêtre se
  consommer, remettre la copie, redémarrer : le marqueur ne doit pas ressusciter
  le payload NV et la gateway doit refuser ce chemin ;
- armer sans redémarrer et attendre l'expiration : `helios-update-window.timer`
  écrase le payload NV ;
- armer, puis mettre à jour un firmware (PCR 0) : la fenêtre ne s'ouvre pas, on
  retombe sur billet et séquestre.

Le cycle NV — armement, état, révocation — est partiellement couvert par
`cargo test -p helios-tpm --features tpm --test materiel` avec
`HELIOS_TPM_MATERIEL=1`. Ce test **écrit** un index NV disposable
(`0x01804846`), contrairement aux autres du fichier ; le retirer ensuite avec
`tpm2_nvundefine 0x01804846` si la machine n'est pas jetable. La consommation
elle-même reste manuelle : elle suppose un déplacement réel de PCR 4, donc un
redémarrage.

Le même test accepte `HELIOS_TPM_TCTI=swtpm:host=127.0.0.1,port=2321`. Il
valide alors le vrai chemin ESAPI — politique de lecture NV sans `OWNERREAD`,
écrasement et impossibilité de ressusciter le secret avec le seul
marqueur disque — sans prétendre mesurer Secure Boot ni les PCR d'une cible.

### Renouvellement du PSK à chaud (V1)

Cet essai juge le renouvellement dans le tunnel
([§7.6](../specification/NEGOCIATION-DE-CLE-V5.md#76-renouvellement-dans-le-tunnel))
sur les critères du [§12.3](../specification/NEGOCIATION-DE-CLE-V5.md#123-politique-de-renouvellement).
Il se mène sur le **code de production**, sans variable qui raccourcisse la durée
de vie : le renouvellement est forcé par l'action « Renouveler la clé
maintenant » d'Orion. Rien n'en est mesuré à ce jour, et rien ne se coche depuis
WSL2.

À répéter sur le **noyau Linux** et sur **WireGuard-NT**, d'abord sur un chemin
sain, puis sur un chemin dégradé :

1. monter un tunnel `ml_kem` entre Orion et la gateway ; relever la VIP du
   client `<VIP>` et le port de négociation `<port>` ;
2. depuis la gateway, mesurer l'interruption applicative :
   `ping -D -i 0.01 <VIP> | tee ping.log` (intervalle de 10 ms, horodatage
   absolu) ;
3. depuis le client, lancer **une seule** connexion TCP qui traverse tout
   l'essai : `iperf3 -c <VIP gateway> -t 1500 -J > iperf.json` ; une connexion
   rompue ou relancée est un échec du critère ;
4. sur la gateway, capturer les messages de négociation :
   `tcpdump -ttt 'udp port <port> and (udp[8]=1 or udp[8]=2)'` ;
5. déclencher **20 renouvellements consécutifs** par « Renouveler la clé
   maintenant », en attendant le « clé renouvelée » de chacun ;
6. relever pour chaque renouvellement le délai jusqu'au handshake observé après
   la réinitialisation, le plus long trou de réponses du `ping`, et l'état de la
   connexion `iperf3` ;
7. recommencer avec un chemin dégradé sur l'interface qui porte le trafic :
   `tc qdisc add dev <iface> root netem delay 150ms 30ms loss 5%`, retiré
   ensuite par `tc qdisc del dev <iface> root`.

Verdict **PASS ou FAIL par critère**, pour chaque noyau et chaque chemin :

| Critère (§12.3) | Seuil | Source de mesure |
| --- | --- | --- |
| handshake après la réinitialisation, observé sur les deux backends | < 5 s | `wg show … latest-handshakes` et journaux des deux côtés |
| interruption du trafic applicatif | < 1 s | plus long trou du `ping` |
| sessions TCP traversant le tunnel | aucune rompue | `iperf3` unique, sans erreur dans le JSON |
| renouvellements consécutifs réussis | 20 sur 20 | événements « clé renouvelée » |

Un seul FAIL sur le chemin sain rouvre la politique : le repli est la
déconnexion puis la reconnexion complètes du §12.3, jamais la suppression de la
preuve par handshake. Sur le chemin dégradé, consigner les écarts même quand le
verdict reste PASS. Vérifier aussi, sur la gateway, que la règle du port de
négociation n'existe que sur les WAN et sur `wg_iface` (`nft list ruleset`), et
que `remove_peer` suivi de `configure_peer` réinscrit bien le pair avec le
nouveau PSK sur chacun des deux backends.

## Banc de développement

`scripts/lab.sh` monte un environnement complet — gateway `--dev` isolée, client
admis par l'API, profil émis, campagne jouée — puis le démonte. `--keep` laisse
le daemon vivant pour l'exploration manuelle.

Il emprunte les **mêmes outils qu'un opérateur** (`helios key-nego`,
`helios peer add`, `helios profile emit`) plutôt qu'un chemin de test
parallèle : une régression de l'outillage d'exploitation y tombe
immédiatement. Le client est admis au plancher `ml_kem` avec ses certificats de
négociation TLS et PQ, émis par une CA cliente jetable créée dans le répertoire
temporaire. Le banc contrôle aussi que le profil d'invitation ne porte aucun
secret.

Il ne fait **pas** partie de `regression.sh` : la régression vérifie des
invariants, elle ne lance pas d'environnements. Le banc est un outil de
développement.

Ce qu'il ne prouve pas : le plan de données. Le tunnel reste simulé, comme dans
toute exécution `--dev` ; le banc netns ci-dessous couvre ce manque.

**Le banc a été cassé du 6 août au 18 octobre 2026.** Depuis la
spécification de rotation v5 (`a9f78a9`), `helios peer add` sans certificats de
négociation est refusé (`MissingNegotiationIdentity`) et le banc s'arrêtait à
l'admission. Il émet désormais les certificats du client. Le mode assisté
d'ADR-004 §6 (`profile emit --with-private-key`) n'y est plus joué : il a été
retiré le 18 octobre 2026, et `profile emit` ne fait plus que réémettre
l'invitation d'un pair déjà admis.

## Banc netns

`scripts/netns-bench.sh` (ETUDE-IPV6 T22) éprouve le **plan de données réel**
sans matériel : un `heliosd` construit avec `netlink,wireguard`, lancé **sans**
`--dev`, face à un client WireGuard noyau piloté par `wg`. Trois network
namespaces vivent dans un namespace utilisateur non privilégié
(`unshare --user --map-root-user --net --mount`) : il ne faut ni root ni sudo,
et rien ne survit à l'exécution.

```text
cl (client wg) ── veth ── net (routeur WAN, hôte « Internet ») ── veth ── gw (heliosd)
```

Contrairement à ce que ce document affirmait jusqu'ici, **WSL2 suffit** : son
noyau (`6.18`, `CONFIG_WIREGUARD=m`, `CONFIG_NF_TABLES=y`, `CONFIG_NET_NS=y`)
accepte veth, nftables et une interface WireGuard dans un netns utilisateur.
Constaté le 18 octobre 2026.

```sh
bash scripts/netns-bench.sh
```

Le banc construit les binaires sous le budget Cargo partagé, puis joue, avec
un verdict PASS ou FAIL par ligne :

- démarrage de `heliosd` sur les backends réels, kill-switch posé avant le
  réseau, table `inet helios` en politique `drop` ;
- pair déclaré posé sur `helios0`, `AllowedIPs` = VIP `/32` + VIP `/128`, profil
  émis portant les VIP persistées et aucune clé privée ;
- handshake sur endpoint IPv4 puis IPv6, passage en `Up` sur preuve de
  handshake ;
- ETUDE-IPV6 §12 : IPv4 et IPv6 dans le tunnel, forward IPv4 vers Internet
  (NAT44) en ICMP, TCP et UDP, rejet de l'IPv6 tunnel → WAN (T21),
  anti-spoofing par `AllowedIPs`, résolution ND sous politique `drop` ;
- arrêt : `heliosd` journalise l'arrêt fail-closed, la table survit et plus
  rien ne sort vers Internet ;
- aucune clé privée dans le journal du démon.

Le pair est **déclaré dans `network.toml`**, pas admis par l'API : l'admission
exige les certificats de négociation, dont la moitié gateway est scellée dans
un TPM que le banc n'a pas. Le banc éprouve donc le plan de données, **pas**
l'admission ni la négociation `ml_kem`. La clé de la gateway est la clé en clair
héritée, comme dans `lab.sh`, et le TPM est désactivé.

Non couverts : §12.9 (PMTU), §12.12 (DNS AAAA), §12.15 (`conntrack` absent de la
machine), et tout ce qui demande du matériel ou WireGuard-NT. Le banc ne fait
pas partie de `regression.sh`.

**Défaut trouvé par le premier passage (18 octobre 2026), corrigé le même jour :
le rejet IPv6 de T21 n'était jamais atteint sur une gateway par défaut.** La règle
`reject with icmpx admin-prohibited` vit dans `forward` (SORTIE-IPV6 §3.1). Avec
`net.ipv6.conf.all.forwarding = 0`, valeur par défaut que Helios ne modifie pas,
le noyau jette le paquet dans `ip6_forward` avant ce hook : le client attend son
délai (3 s mesurées) au lieu de replier immédiatement sur l'IPv4. Aucune fuite :
le paquet est perdu. Avec `forwarding = 1`, ou avec le même rejet placé en
`prerouting` (`fib daddr type != local`), la réponse arrive en 6 ms. Correction
(SORTIE-IPV6 §3.1 amendé) : le rejet est rendu d'abord en `prerouting`, par
`fib daddr oifname <wan>`, et le contrôle du banc passe.

## Campagne d'installation par bundle signé

`scripts/campaign.sh` joue `scripts/bundle_campaign.py` après le provisioning et
la mise à jour applicative. Elle assemble un bundle, le signe avec l'époque
éphémère de la campagne, puis l'installe dans un faux système jetable.

Ce qu'elle prouve et que les tests unitaires ne prouvent pas : le chemin passe
par le trousseau éditeur **réellement compilé** dans `helios-installer`, pas par
un trousseau injecté. Une régression du build — ancre absente, époque
incohérente, encodage canonique modifié — se voit là.

Neuf scénarios : signature valide, binaire substitué après signature, unité
systemd ajoutée après signature, époque éditeur inconnue, canal confronté à
celui de la gateway, installation complète avec bascule du lien `current`,
anti-rollback semé, rejeu de séquence refusé, configuration existante préservée.

Ce qu'elle ne couvre pas : l'interaction réelle avec systemd, la persistance à
travers un redémarrage, et le premier `bootstrap` sur une machine vierge. Ces
trois points appartiennent à la recette matérielle.

## Campagne de provisioning post-quantique

`helios campaign` joue les mêmes scénarios en dry-run et sur la cible. Il
agit en **vrai client** : il emprunte `orion_core::provision`, le code
qu'embarque Orion. Une campagne qui tombe accuse donc le daemon *ou* le client.

Trois catégories, selon ce qu'elles exigent de l'environnement :

| Catégorie | Exige | Ce qu'elle établit |
| --- | --- | --- |
| `client` | rien | validation côté client : gateway usurpée, ciphertext malformé, version inconnue |
| `protocole` | un daemon joignable | tour ML-KEM complet, PSK frais par session, VIP stable, refus d’un pair non admis, absence de secret dans l’API |
| `plan-de-donnees` | `wg` et un noyau réel | le PSK est **réellement** dans le slot WireGuard, et le handshake a survécu à sa pose |

### Dry-run

```sh
bash scripts/campaign.sh            # daemon isolé, campagne, démontage
bash scripts/campaign.sh --repeat 20  # endurance
```

Le script monte son propre `heliosd --dev` sur une configuration temporaire :
il ne touche jamais `/var/lib/helios`. Il est joué par `scripts/regression.sh`.

### Cible

Le dry-run ne prouve rien du plan de données : `DryRunBackend` accepte un PSK
sans qu'aucun paquet ne soit chiffré. Seule la catégorie `plan-de-donnees`
tranche, et elle exige la cible.

Déclarer d’abord le pair de campagne sur la gateway (l’admission reste hors
bande — la campagne ne s’auto-admet jamais) :

```sh
helios campaign --generate-keys     # imprime le bloc [[peers]] à coller
```

Puis, **depuis le client**, tunnel classique monté :

```sh
helios --url http://100.64.0.1:8080 campaign \
  --client-key <privée du client> --gateway-key <publique de la gateway>
```

Enfin, **depuis la gateway**, la catégorie que le dry-run ne peut pas jouer :

```sh
helios campaign --only plan-de-donnees --wg-iface helios0 \
  --client-key <privée du client> --gateway-key <publique de la gateway>
```

Attendre au moins un handshake (≤ 2 min) entre le provisioning et cette
dernière commande : c’est précisément l’intervalle où un PSK posé d’un seul
côté se manifesterait, et le scénario `handshake vivant avec PSK` est là pour
l’attraper.

## Campagne matérielle automatisée

`scripts/target_campaign.py` joue la recette matérielle ci-dessus depuis la
machine de dev, sur une cible Linux accessible par SSH. Il n'a aucune
dépendance hors bibliothèque standard Python.

Le partage des rôles est explicite : les **tests unitaires restent en Rust** —
le script se contente d'exécuter `cargo test --workspace --all-features` sur la
cible, ce que WSL2 ne sait pas faire pour les features noyau/TPM — tandis que
l'**enchaînement d'états** de la campagne (daemon monté, handshake attendu,
kill-switch engagé) est orchestré en Python.

Provisionnement ponctuel de la cible, en deux commandes :

```sh
ssh -t <cible> 'cd ~/helios && bash scripts/setup-dev.sh --target'
python3 scripts/target_campaign.py --bootstrap
```

`--bootstrap` résout l'utilisateur et le chemin absolu du dépôt sur la cible,
compose la règle sudoers, **la fait valider par `visudo` avant de l'installer**
— un fichier invalide déposé dans `/etc/sudoers.d` casserait sudo pour toute la
machine — puis l'installe et ajoute l'utilisateur au groupe `tss` (accès
`/dev/tpmrm0`). Un seul mot de passe est demandé, et la vérification finale se
fait sur une session neuve, seule façon de constater que la règle porte.

La règle est limitée à `modprobe wireguard`, `modprobe nf_tables`, `nft`, `ip`,
`wg` et `setcap` sur les seuls binaires d'essai (`heliosd` et `helios`,
qui lit le plan de données via `wg show`) : jamais un shell générique, ni
`apt-get`, ni root inconditionnel. `--aide-sudoers` l'imprime pour contrôle.

La catégorie `tunnel` fait de la machine de dev un **vrai client WireGuard**.
Elle exige donc une règle locale, à poser une fois depuis un terminal :

```sh
echo "$(id -un) ALL=(root) NOPASSWD: /usr/sbin/modprobe wireguard, $(command -v ip), $(command -v wg)" \
  | sudo tee /etc/sudoers.d/helios-client-tests && sudo chmod 0440 /etc/sudoers.d/helios-client-tests
```

Trois contraintes de forme, constatées sur Ubuntu 26.04 qui embarque **sudo-rs**
et non le sudo classique :

- aucun joker n'est accepté dans les arguments de commande — les invocations de
  `setcap` sont donc écrites littéralement, dans leurs deux variantes de
  syntaxe de capacités (`+eip` et `=ep`) ;
- la virgule qui sépare les capacités doit être échappée (`cap_net_admin\,`),
  sinon elle est lue comme le séparateur de la liste de commandes ;
- le chemin du binaire est absolu, et doit correspondre au mot près à celui que
  la campagne passe à `setcap` — d'où sa résolution par `pwd -P`.

Ces contraintes sont la raison d'être de `--bootstrap` : recopiée à la main, la
règle échoue silencieusement ou casse sudo.

Exécution :

```sh
python3 scripts/target_campaign.py --only preflight    # sans effet de bord
python3 scripts/target_campaign.py --only unite        # cargo fmt/clippy/test
python3 scripts/target_campaign.py                     # tout sauf le pare-feu réel
python3 scripts/target_campaign.py --pare-feu --json rapport.json
```

Les catégories sont `preflight`, `synchro`, `unite`, `build`, `campagne`,
`mise-a-jour`, `tpm`, `tunnel` et `pare-feu`. Pour rejouer la mise à jour depuis
la branche distante courante :

```sh
python3 scripts/target_campaign.py --only synchro --only mise-a-jour
```

### Ce que la cible a permis d'établir

Ces points ne sont pas démontrables en WSL2, et deux d'entre eux ont révélé des
défauts réels lors du premier passage :

- le ruleset Netlink est réellement posé, en `drop` sur les trois chaînes, et
  **survit à l'arrêt du daemon** ;
- le scellement TPM sur `/dev/tpmrm0` refuse un blob absent, altéré, ou dont la
  sélection PCR a été modifiée, et restitue le secret à l'identique ;
- un vrai tunnel WireGuard s'établit entre la machine de dev et la gateway, et
  le provisioning post-quantique s'y déroule de bout en bout ;
- la gateway pose le PSK sur son plan de données **avant** de l'annoncer.

Deux pièges de terrain méritent d'être connus, car leurs symptômes égarent :

- **MTU.** WireGuard prend 1420 par défaut, ce qui suppose un transport à 1500.
  L'`eth0` de WSL2 est à 1280 : le handshake et les petites requêtes passent,
  mais un ciphertext ML-KEM disparaît en silence. Depuis, les deux bouts
  dérivent leur MTU du lien qui les porte (`aether::mtu`) ; le scénario
  `daemon réel` vérifie que la gateway l'applique. Mesure de référence sur
  cible, transport à 1280 : **1220 passe, 1221 échoue**, soit 60 octets de
  surcoût en IPv4 — la valeur retenue (80) couvre aussi IPv6.
- **Témoin de disponibilité.** Hors dry-run, heliosd écrit dans `/run/helios`,
  répertoire fourni par systemd (`RuntimeDirectory=helios`). Lancé à la main
  avec les seules capacités réseau, il s'arrête sur `EPERM` *après* avoir monté
  l'interface. La campagne passe `HELIOS_READY_PATH`, prévu pour ce cas.

### Limite connue : le slot PSK côté client

La campagne vérifie le slot PSK de la gateway, pas celui du client. `helios`
emprunte le **protocole** d'Orion (`orion_core::provision`), pas son
**adaptateur** : seul ce dernier écrit le PSK dans l'interface cliente. Le
client monté par la campagne l'est par `wg set`, et rien ne l'y renseigne.

Ce qui débloquerait la vérification : un mode headless d'Orion, ou une
sous-commande `helios` qui applique le profil reçu au lieu de se limiter à
l'inspecter. En attendant, le scénario le déclare hors de portée plutôt que de
le compter comme réussi.

La feature doit donc avoir été commitée et poussée avant cette commande ; la
campagne refuse une révision cible dont `helios-publisher` ne connaît pas
`binary-release`. La catégorie exerce le refus d’un manifeste altéré, le
transfert JSON borné, le SHA-256 et l’autorisation d’activation sur un daemon
cible isolé. Un scénario que l'environnement ne permet pas de trancher est
rapporté « hors portée », jamais « réussi ».

### Survie de la session SSH

Le backend Netlink réel pose une table `inet helios` en politique `drop` sur la
chaîne `input`, et cette table **survit à l'arrêt du daemon** (invariant
fail-closed : `teardown()` ne supprime jamais la table). Sans précaution, la
campagne se coupe l'accès à sa propre cible. Deux protections cumulées :

1. toutes les commandes passent par une **connexion SSH multiplexée unique**,
   déjà `established` avant l'engagement du kill-switch, donc acceptée par la
   règle `ct state established,related` ;
2. la configuration générée renseigne `allow_ssh_from` avec le préfixe de
   gestion (`--prefixe-gestion`, défaut `192.168.1.0/24`), ce qui rouvre le
   port 22 même kill-switch engagé.

Le scénario `SSH de gestion préservé par allow_ssh_from` ouvre délibérément une
connexion **hors** multiplexage pour vérifier cette seconde protection plutôt
que de la supposer. Les scénarios qui touchent au pare-feu réel exigent malgré
tout `--pare-feu` explicite. En cas de perte d'accès, depuis la console :

```sh
sudo nft delete table inet helios
```

### Ce que cette campagne ne couvre pas

**La pose effective du PSK exige un second poste.** Le PSK n'entre dans le slot
WireGuard qu'au terme d'un provisioning mené *par un client, à travers le
tunnel*. Or le ruleset refuse le port d'administration depuis toute interface
autre que celle du tunnel, loopback compris — « en tête de chaîne, avant même
le loopback » (`ruleset.rs`). La gateway ne peut donc pas se provisionner
elle-même, et c'est l'invariant recherché, pas une gêne à contourner.

Le scénario est déclaré « hors portée » plutôt que mis en échec : un échec
laisserait croire à une régression du PSK alors que rien n'aurait été éprouvé.
Ce qui le débloquerait : un second hôte monté en client WireGuard, d'où jouer
la recette en deux machines décrite plus haut.

Ce que la campagne établit malgré tout sur le plan de données réel : interface
WireGuard adressée par le noyau, pair déclaré et visible dans `wg show`, table
nft posée en politique `drop`, et slot PSK vide avant provisioning — ce dernier
point évitant de confondre « aucun provisioning » et « PSK posé ».

Le **scellement** TPM est automatisé depuis la catégorie `tpm` : elle exerce
`/dev/tpmrm0` pour de bon (provisionnement, déscellement du même secret, refus
d'un blob absent, altéré, ou dont la sélection PCR a été réécrite).

Les essais de scellement sont réversibles : ils n'utilisent que
`create_primary` transitoire, `create`, `load`, `policy_pcr` et `unseal`. Ils
travaillent dans un répertoire temporaire, jamais `/var/lib/helios`, et
n'étendent aucun PCR : la liaison est éprouvée en réécrivant la sélection
inscrite dans le blob, ce à quoi le TPM répond `TPM2_RC_POLICY_FAIL`.

L'essai de fenêtre est l'exception explicite : il définit et écrit l'index NV
jetable `0x01804846`, puis en écrase le payload sans supprimer l'index. Cette
trace ne contient plus de secret, mais persiste jusqu'à
`tpm2_nvundefine 0x01804846` sur une cible non jetable.

Restent manuels : les **billets de rescellement** (rejeu, altération, PCR
optionnel), qui supposent un changement de PCR donc un redémarrage contrôlé.
Ils sont dans [MANUAL-TESTING.md](MANUAL-TESTING.md). Ce qui débloquerait leur
automatisation : une cible à console série pilotable. Les contrôles automatisés
couvrent le scellement/déscellement, les refus et le cycle NV
armement-révocation ; ils ne couvrent pas encore la consommation après un vrai
déplacement de PCR 4 et un redémarrage.

### Bugs trouvés par le premier passage sur cible

Trois défauts que le dry-run ne pouvait structurellement pas voir, tous
confirmés puis corrigés avec test de non-régression :

| Défaut | Effet |
| --- | --- |
| `Del` d'une table nft absente | `ENOENT`, transaction entière rejetée : aucun kill-switch au premier démarrage d'une machine |
| `iif "lo"` sur la chaîne `output` | ne matche jamais ; tout le trafic loopback sortant tombait sous `drop` |
| API liée avant la création de la VIP | `bind` en échec, erreur avalée : gateway opérationnelle mais définitivement sans API |

### Défauts trouvés sur gateway en service (8 août 2026)

Six autres, relevés en cherchant pourquoi des services locaux échouaient sur
la gateway de production. Les cinq derniers sont à vérifier sur cible : ils ne
sont pas observables ailleurs.

| Défaut | Effet |
| --- | --- |
| chaîne `output` sans sortie propre à la gateway | ni DNS, ni NTP, ni paquets : `apt` affiche `Ign :` sur chaque source puis se fige à 0 %, et le symptôme désigne le résolveur au lieu du pare-feu. Corrigé par `allow_gateway_egress` |
| `ct state established` appliqué là où `established,related` était affiché | `rustables::Rule::established()` ne masque que le bit `ESTABLISHED`. Le dry-run, l'API et la console affichaient la forme complète : la divergence n'était visible que dans `nft list`. Les erreurs ICMP `fragmentation needed` tombaient sous `drop`, donc trou noir de PMTU |
| NordVPN Meshnet actif mais sans réception WireGuard | le contrôle HTTPS réussissait, puis DERP TCP 8765, STUN et les chemins directs marqués `0xe1f1` tombaient sous `drop`; même après transport, le trafic applicatif sur `nordlynx` restait fermé. Corrigé par le bloc borné `nordvpn_meshnet` |
| marque NordVPN encodée en ordre réseau | la valeur `0xe1f1` était appliquée par nftables comme `0xf1e10000` sur x86_64 : la règle WAN ne pouvait donc jamais reconnaître les paquets Meshnet. Les valeurs de registre `meta mark` utilisent désormais l'ordre natif, avec test de non-régression |
| tunnel Meshnet sain mais services et routage incomplets | Helios n'ouvrait que SSH en entrée et ne produisait aucune règle `forward`. TCP 49111 couvre désormais Nord Fileshare ; les listes `traffic_routing_peer_cidrs` et `local_network_peer_cidrs`, relues depuis les ensembles de permissions NordVPN au déploiement, bornent le routage pair par pair |
| arrêt de `heliosd` figé après le retrait de `helios0` | le serveur brut de mesure attendait indéfiniment dans un `spawn_blocking`; Tokio attend les tâches bloquantes à la destruction du runtime, donc systemd finissait par tuer le démon après son délai. Les sockets TCP/UDP observent désormais un signal d'arrêt testé |

### Boucle de mise à jour sur gateway en service (1er septembre 2026)

Une activation poussée depuis la console d'administration a laissé la gateway
en redémarrage toutes les 30 s pendant une heure. Trois défauts indépendants,
dont deux que le premier masquait.

| Défaut | Effet |
| --- | --- |
| `/run/helios` absent du bac à sable de `helios-update.service` | `ReadWritePaths` ne monte rien pour un répertoire qui n'existe pas au montage, **sans le dire**, et `ProtectSystem=strict` laisse alors `/run` en lecture seule. Le répertoire appartient au démon, qui le détruit à chaque arrêt — dont celui que l'installateur déclenche lui-même. Le retrait du marqueur échouait en `EROFS`, et l'erreur du rollback masquait celle d'origine. Les deux unités déclarent désormais `RuntimeDirectory=helios` et `RuntimeDirectoryPreserve=yes` |
| activation non consommée quand le rollback échoue | `helios-update.path` redéclenche sur la seule existence de `activate.json` : une mise à jour ratée redémarrait la gateway indéfiniment. L'activation est maintenant consommée **avant** la tentative de restauration, et l'erreur d'origine n'est plus effacée par celle du rollback |
| release étiquetée avec la version du workspace | `xtask pack` lisait `[workspace.package] version` (`0.1.0`) alors que le marqueur de disponibilité porte celle du crate `heliosd` (`1.12.0`) : le contrôle de santé comparait deux numéros différents pour la même release et ne pouvait jamais aboutir. L'étiquette vient désormais de `crates/heliosd/Cargo.toml`, avec test de non-régression |

Vérification cible, après déploiement des unités corrigées :

```sh
sudo systemd-run -q --wait --pipe --collect --service-type=oneshot \
    -p ProtectSystem=strict -p RuntimeDirectory=helios \
    -p RuntimeDirectoryPreserve=yes \
    /bin/sh -c 'touch /run/helios/.probe && rm /run/helios/.probe && echo RW-OK'
# attendu : RW-OK
```

Un `Read-only file system` signifie que l'unité installée est antérieure au
correctif : le bac à sable est le seul endroit où l'écart se voit.

Vérification cible du second, après déploiement :

```sh
sudo nft list chain inet helios input | grep 'ct state'
# attendu : ct state established,related accept
```

Une sortie qui affiche `ct state established` seul signifie que le binaire
installé est antérieur au correctif — la traduction Netlink est le seul endroit
où l'écart se voit.

Vérification Meshnet sur cible, avec l'adresse du pair déclarée dans
`network.toml` :

```sh
sudo nft list chain inet helios output | grep -E 'e1f1|nordlynx'
sudo nft list chain inet helios input | grep nordlynx
sudo nft list chain inet helios forward | grep nordlynx
sudo wg show nordlynx
ping -c 3 100.70.36.212
```

Le ruleset doit montrer la marque seulement sur le WAN, la destination du pair
seulement sur `nordlynx`, et TCP 22 en entrée seulement avec `iifname
"nordlynx"` et la source `/32` ; TCP 49111 est le service Nord Fileshare. Si
NordVPN accorde le routage au pair, `forward` doit montrer ce même `/32` de
`nordlynx` vers chaque WAN. Sans permission d'accès au réseau local, quatre
règles `drop` RFC1918 doivent précéder ces acceptations. La marque affichée doit être exactement
`0xe1f1`, jamais `0xf1e10000`. `wg show` doit ensuite afficher un handshake et
des octets reçus ; le rendu et la transaction Netlink sont automatisés, mais ce
dernier effet exige la gateway réelle.

## Limites connues

- le backend réel dépend du noyau, des pilotes et des privilèges de chaque OS ;
- l’effet de la key-negotiation sur WireGuard-NT et le backend noyau Helios
  exige deux machines et les deux redirections UDP ; les tests WSL2 couvrent la
  transaction mais pas ces effets matériels ;
- le scellement DPAPI de l’identité cliente ne s’exerce pas en WSL2 : la CI
  Windows vérifie le tour complet, l’altération et le remplacement atomique ;
  la copie vers un autre compte reste une recette cible, car elle exige deux
  sessions Windows distinctes. Hors Windows, `orion_core::identity_store`
  échoue explicitement (`UnsupportedPlatform`) au lieu d’écrire ces clés en
  clair ;
- **le code `cfg(windows)` ne se compile pas depuis WSL2**, et c’est une limite
  d’outillage, pas de conception : `cargo check --target x86_64-pc-windows-msvc`
  échoue en construisant `aws-lc-sys`, faute de compilateur C ciblant MSVC. Une
  erreur de nom ou de type dans `vault/windows/` ou dans le transport WebAuthn
  n’apparaît donc que sous Windows. Le job Windows applique Clippy strict et
  les tests d'`astra-signer`, sans exiger de clé physique. Deux atténuations
  locales, aucune n’étant un substitut :
  - les modules `#[cfg(windows)] mod imp` importent le parent par `use super::*`,
    pour qu’un élément ajouté au-dessus ne manque jamais à l’appel ;
  - les symboles `windows-sys` se vérifient hors compilation en lisant le crate
    dans le registre Cargo, ce qui prouve l’existence et le **type** attendu :
    ```sh
    W=~/.cargo/registry/src/*/windows-sys-0.61*/src/Windows/Win32
    grep -rn '\bNCryptSetProperty\b' $W --include=mod.rs   # signature exacte
    grep -n 'pub const TOKEN_QUERY\b' $W/Security/mod.rs   # type de la constante
    ```
    C’est ainsi qu’ont été validés `OpenProcessToken` (dans `System::Threading`,
    pas `Security`) et le `dwflags: OBJECT_SECURITY_INFORMATION` de
    `NCryptGetProperty`. Seule une compilation sur cible fait foi ;
- **le renouvellement de certificat ne se boucle pas en WSL2**, et pour la même
  raison : ses deux écritures locales scellent des clés privées. `open_or_seed`,
  la construction et la double signature de la requête, la vérification du
  grant, la pose du candidat et le commit sont tous éprouvés hors matériel —
  `crates/orion-core/src/certificate_renewal.rs`, quatorze essais dont un qui
  fait émettre une vraie `CA-TLS` **depuis la CSR que le client a produite**.
  Ce qui n’est pas exercé ici est le scellement du candidat sous
  `<identité>-next` et sa promotion à l’activation : les deux passent par
  `ProtectedIdentityStore`, donc par DPAPI. Un renouvellement complet est donc
  une recette cible : Orion sous Windows, tunnel monté, gateway avec Astra
  déployé, et `astra-signer approve --heliosd-url … --operation-id …` lancé sur
  la même machine avec la clé branchée. Le transport du compagnon, lui,
  s’éprouve hors matériel contre une gateway factice
  (`tools/astra-signer/tests/tunnel.rs`). **Ce que cette recette doit vérifier
  en dernier**, et qui est l’acceptation réelle du renouvellement : que le
  client **rouvre le tunnel après l’activation**. Tout le reste peut réussir et
  laisser un poste enfermé dehors à la fin du chevauchement — c’est précisément
  ce que la chaîne `[feuille, intermédiaire]` scellée par `candidate_bundle` et
  l’ensemble d’émetteurs lu dans le registre existent pour éviter, et hors
  matériel on n’en prouve que la logique ;
- **le sidecar opérateur d'Orion ne s'exerce pas en WSL2** : aucun passthrough
  USB, et le transport plateforme est propre à Windows. Hors matériel, les
  tests couvrent le protocole IPC borné, le manifeste typé, l'ordre strict des
  révisions et la collecte de chaque assertion pendant que sa clé physique est
  encore branchée. La recette Windows part de l'installateur produit, vérifie
  que `helios-astra-helper.exe` est installé à côté d'Orion et absent du
  `PATH`, puis exerce d'abord les refus : sidecar absent, fenêtre propriétaire
  impossible, jeton absent, session périmée et seconde clé identique. Elle
  termine par une récupération complète et une campagne de certificats clients,
  avec apparition au premier plan de chaque boîte WebAuthn. Pour éprouver le
  séquençage réel, la recette laisse d'abord Orion afficher le manifeste, puis
  utilise le bouton de confirmation qui déclenche la clé : le droit de premier
  plan doit être transmis sur ce second clic, et de nouveau avant la seconde
  clé d'une campagne ;
- **l’aléa se vérifie par sa gestion, pas par son moteur.** `aether::random`
  n’implémente aucun DRBG : il appelle `aws_lc_rs::rand::SystemRandom`, refuse
  fermement quand celui-ci échoue, et journalise au démarrage fournisseur,
  version, mécanisme, `use_df` et intervalle de reseed. Les tests couvrent ce
  qui est du ressort du dépôt — refus sans octet produit quand le fournisseur
  échoue, refus d’un bloc entièrement nul à la sonde de démarrage, borne par
  appel, propagation vers `fips204`, profil annoncé tenant sous le plafond de
  `2^20` — au moyen d’un faux fournisseur déterministe, **thread-local**, qu’aucun
  binaire livré ne peut sélectionner. Un test épingle en outre le **profil
  annoncé** — mécanisme, `use_df`, intervalle de reseed, résistance à la
  prédiction — pour qu’une bannière qui divergerait de la source AWS-LC embarquée
  casse un test au lieu de devenir silencieusement fausse. Ce qui relève du
  fournisseur ne s’éprouve pas ici et n’a pas à l’être : le CTR-DRBG-AES-256, son
  reseed à 4096 générations, sa réinstanciation après fork ou reprise
  d’instantané et son `abort()` sur échec d’entropie sont dans le code AWS-LC
  embarqué (`crypto/fipsmodule/rand`, `crypto/ube`). L'instanciation sans DF à
  seed de pleine entropie est admise par les spécifications. Les tirages
  secrets utilisent l'entrée native
  `RAND_bytes_with_user_prediction_resistance`, avec matériau issu du DRBG
  public séparé. Cet apport additionnel ne force pas de reseed avec entropie
  fraîche : les tests ne prouvent donc pas l'exigence de résistance à la
  prédiction par appel des spécifications, et la bannière ne la revendique
  pas. Le canal privé rustls sélectionne AWS-LC explicitement.
  Un autre écart reste le **matériel de session TLS** des autres chemins
  `rustls`/`quinn`, encore sur le CSPRNG de `ring`. La **validation FIPS est hors périmètre** — la
  construction `aws-lc-fips-sys` exige Go (« Go is required for FIPS »), et aucun
  déploiement d’Helios ne revendique de certificat ;
- **le cycle de vie des certificats est vérifié en logique, pas en
  exploitation.** `aether::certificates`, le registre gateway, le magasin Orion
  et le binaire `astra` sont couverts par des tests déterministes qui prennent
  l’horloge en argument : fenêtres, générations, avortement antidaté, commit
  tardif, couples TLS/PQ mixtes, transaction chunkée invisible avant son
  dernier fragment. Ce qui **n’est pas** exercé, et ne peut pas l’être en
  WSL2 : l’extension CTAP2 `hmac-secret` d’une YubiKey réelle, l’ouverture du
  coffre HVLT par le compagnon `astra-signer`, le veth privé Astra–Helios et
  ses garanties TLS 1.3, le redémarrage de `heliosd` sur une nouvelle identité
  gateway, et la bascule coordonnée d’un parc existant. Les routes qui
  dépendent d’un credential matériel répondent `501` par une variante d’erreur
  nommée — c’est un refus franc, pas une couverture ;
- le job Windows valide les chemins Tauri et Win32 compilables sans matériel ;
  WireGuard-NT, le TPM physique, BitLocker réellement actif et les effets WER
  dans un vidage exigent toujours la campagne sur cible ;
- une campagne verte réduit le risque de régression, elle ne constitue ni audit
  externe ni preuve formelle.

La recette interactive est dans [MANUAL-TESTING.md](MANUAL-TESTING.md).

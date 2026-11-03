# Progression du développement vers la couverture maximale

Lot du 24 octobre 2026, branche `feat/local-rust-audit`, référence source `146ab67`. Objectif confirmé : viser 100 % de couverture pertinente ; 80 % reste un jalon. Les constats de 02/03 restent ceux de l’audit initial.

## Résultats mesurés du lot COV-003/COV-004/COV-009

| Vue | Avant | Après |
|---|---:|---:|
| Production globale Linux | 30 870 / 53 009 = 58,24 % | 31 287 / 53 046 = 58,98 % |
| Brut LLVM, lignes globales | 46 706 / 70 663 = 66,10 % | 47 396 / 70 957 = 66,80 % |
| Fonctions brutes exécutées | 4 471 / 6 978 = 64,07 % | 4 545 / 7 006 = 64,87 % |
| Fonctions brutes non exécutées | 2 507 | 2 461 |
| Régions brutes exécutées | 68 880 / 104 960 = 65,63 % | 69 820 / 105 416 = 66,23 % |

Vue bibliothèques séparée : **23 190 / 34 889 = 66,47 %** de production, contre 22 773 / 34 852 = 65,34 % avant ce lot ; brut LLVM **34 678 / 47 400 = 73,16 %**. La collecte réussie est `/tmp/helios-cov-next-after-libs-retry` (1 716 tests réussis, zéro échec/ignoré). La tentative précédente `/tmp/helios-cov-next-after-libs` reste partielle : changement d’état Git documentaire pendant la collecte, provenance refusée ; aucun de ses chiffres n’est utilisé comme référence. Branches/MC/DC non instrumentées : aucune couverture correspondante n’est revendiquée. Le compteur de production gagne 417 lignes couvertes avec 37 lignes de dénominateur supplémentaires ; le reliquat baisse donc de 380 lignes, sans crédit fictif attribué aux tests inline. Il reste **21 759 lignes non couvertes** pour viser 100 %, et **11 150 lignes supplémentaires** pour le jalon 80 % au nouveau dénominateur.

Les deux collectes globales avant/après ont terminé avec `status=completed`, respectivement 2 172 et **2 200 tests réussis**, zéro échec/ignoré. Les JSON, LCOV, HTML, métadonnées, empreintes de sources et provenances sont conservés dans `/tmp/helios-cov-next-before` et `/tmp/helios-cov-next-after`.

Un alignement textuel exact des blocs inchangés entre les sources de référence et celles du lot (SequenceMatcher sans autojunk), croisé avec les `DA` et exclusions AST des deux rapports, trouve **364 lignes existantes devenues couvertes et zéro perte sur ces lignes alignées**. Les lignes modifiées ou nouvelles ne sont pas créditées comme gains existants. Le détail avant→après est dans `/tmp/helios-cov-next-aligned-lines.json` ; ce rapprochement textuel n’est pas une preuve sémantique de correspondance. Le comparateur strict retourne le code **2** attendu puisque le périmètre change (nouveau helper et dénominateurs) : revue et nouvelle référence explicite nécessaires, aucun contrôle de non-régression comparable n’est présenté comme vert.

| Module | Avant production | Après production | Lignes non couvertes après |
|---|---:|---:|---:|
| aether grant | 260 / 414 = 62,80 % | 327 / 414 = 78,99 % | 87 |
| aether ledger | 243 / 282 = 86,17 % | 268 / 300 = 89,33 % | 32 |
| astra service | 73 / 593 = 12,31 % | 313 / 593 = 52,78 % | 280 |
| orion trust-update | 106 / 161 = 65,84 % | 123 / 165 = 74,55 % | 42 |
| orion recovery | 84 / 357 = 23,53 % | 102 / 360 = 28,33 % | 258 |
| orion renewal exchange | 186 / 520 = 35,77 % | 211 / 515 = 40,97 % | 304 |
| nouveau helper HTTP borné | absent | 17 / 17 = 100 % | 0 |

Par crate : aether **8 039 / 9 180 = 87,57 %** ; Astra **2 459 / 5 763 = 42,67 %** ; Orion Core **6 261 / 8 556 = 73,18 %**. Les autres compteurs de production par crate sont identiques. Les JSON conservent la liste complète par fichier. Les estimations initiales de COV-003/COV-004/COV-009 ne sont pas assimilées à des résultats : gains sur les seules lignes textuellement inchangées de leur famille principale, respectivement **74, 240 et 11**, hors effets voisins et nouveaux helpers. Cela ne ferme pas leurs réserves initiales.

## État fonctionnel

- **COV-003 : preuves ajoutées et défaut de méthode corrigé.** Grant recovery valide sous CA-PQ et matrices de CSR, clé candidate, identité, époque, lease, signature et reçu ; vérification de signature seule sous bon/mauvais signataire. `TrustLedger::apply_due` publie ensemble ledger/gateway/client uniquement après réussite. Deux régressions vérifient annulation intégrale sur incohérence et capacité, puis reprise après expiration d’une ancienne tombstone. Les appelants actuels de TrustStore travaillaient déjà sur une copie candidate et propageaient les erreurs : aucun incident de perte persistante ni exploitation n’est démontré. Les états copiés ne contiennent pas de secrets ; le chemin sans révocation évite les copies.
- **COV-004 : routeur réel exercé, tâche encore partielle.** HTTP loopback avec vrai ConnectInfo, tailles, JSON, méthodes, budgets, refus grossiers, séparation des opérations ordinaires/opérateur, capacité valide et capacités de mauvais scope/opération ou expirées. Le test de challenge vérifie son épuisement dans le store avant rejeu. Le budget réel réessaie uniquement si une frontière temporelle observée invalide l’oracle, avec trois tentatives au maximum. Restent notamment statut signé positif, réponse oversized réelle, cérémonies et autres handlers positifs. Le transcript de query n’a pas de signataire typé public utilisable depuis Astra ; aucune API de signature générique n’est ouverte pour satisfaire une métrique.
- **COV-009 : lecture bornée et transaction HTTP livrées.** Helper privé, sans dépendance nouvelle : vérification anticipée de Content-Length puis plafond cumulatif avant chaque copie. Trust-update 64 Kio canonique, recovery 128 Kio selon §8.2, renouvellement 256 Kio conservés. Erreurs transport/statut/format restent distinctes. Le DTO strict accepte les trois champs canoniques `status`, `manifest`, `chunk` ; seul le store vérifié autorise une mutation. Les tests couvrent bornes, chunked, corps sans longueur, troncature, flux non terminé, redirection, transaction signée complète persistée/rechargée, dernière page perdue et épuisement des polls. Watchdogs indépendants des limites de production. Aucun test de proxy modifiant l’environnement global partagé n’est ajouté.

Les gains de ce lot ne ferment pas les autres tâches de la roadmap, ni tous les scénarios des modules concernés. Une couverture élevée de helper ne démontre aucune validation matérielle.

## Contrôle des tailles

Même chemin source de reconstruction, Rust 1.99, target Linux hôte, profil release inchangé (`lto = "thin"`, `strip = true`), même trousseau de test éphémère, même Cargo.lock. Sources avant conservées dans une archive et une copie séparée ; dates actualisées après copie pour forcer la détection Cargo. Les sorties instrumentées ne sont pas utilisées.

| Artefact | Features explicites | Avant, octets | Après, octets | Delta |
|---|---|---:|---:|---:|
| astra | aucune | 11 639 480 | 11 639 464 | −16 |
| helios | aucune | 13 696 744 | 13 698 640 | +1 896 |
| heliosd | aucune | 18 385 880 | 18 384 840 | −1 040 |
| heliosd | netlink,wireguard,tpm,embed-ui | 22 642 488 | 22 636 456 | −6 032 |

`scripts/binary-size.py` valide chaque artefact et la compatibilité de sa référence. Tous respectent **134 217 728 octets** ; aucune limite ni optimisation n’a été modifiée. La hausse CLI reste observée et déclarée ; elle accompagne les corrections de code embarqué, sans nouvelle dépendance runtime. Ces contrôles ne représentent ni MSI ni Orion Windows. Provenances, hashes, rapports et logs : `/tmp/helios-cov-next-size` ; les révisions après de ces rapports désignent le HEAD de collecte avec modifications source, dont les empreintes sont conservées par la couverture.

## Validation et blocages

Les suites ciblées Aether/Astra/Orion Core, 64 tests locaux d’outillage et `cargo fmt --check` passent. La régression canonique a passé Clippy workspace strict, Aether sans signature, tests Rust workspace et les interfaces (98 tests web, 162 tests Orion et deux builds). Elle échoue ensuite à `npm audit` : undici 8.11.2 est signalé high dans les deux lockfiles frontend (vérification Orion jouée séparément).

`cargo audit --file Cargo.lock`, joué séparément car non atteint par la régression, échoue sur ctutils 0.4.3, rustls-webpki 0.103.15 et webpki-root-certs 1.0.9. Le commit `de95540` déjà présent sur main traite ces trois entrées Rust ; cette branche issue d’une référence antérieure ne l’intègre pas. Sept avertissements RustSec autorisés restent distincts des trois vulnérabilités bloquantes. Aucun audit n’est déclaré vert et aucun lockfile n’est mis à jour automatiquement dans ce lot.

La campagne dry-run située après l’audit npm a été rejouée séparément et réussit : provisioning, mise à jour signée, confirmation incorrecte refusée, installation par bundle, altérations/époque/canal/rejeu refusés et configuration préservée. Les garde-fous release ont aussi été rejoués : refus du trousseau de développement confirmé par son diagnostic exact, puis check release réussi avec le trousseau éphémère explicitement fourni. Ces succès supplémentaires ne rendent pas les audits verts. MSRV 1.95 absente des toolchains installées ; Windows natif, TPM, FIDO et noyau réels non exécutés. Aucun verdict de sûreté globale ni de livraison possible n’est revendiqué.


## Reproduction et vérifications du lot

Les builds Cargo passent par `scripts/wsl-cargo` ou les scripts qui chargent le budget. Aucun nouveau cache, dépassement ou nettoyage n’a été utilisé ; les garde-fous ont rapporté au plus 45,6 Gio (limite 65 Gio). Les rapports HTML/JSON/LCOV ont été exportés avant la collecte suivante qui remplace les profils. Sources Rust stables pendant les collectes réussies ; SHA de chaque entrée dans leur provenance. Les manifestes, lockfiles, profils et workflows sont inchangés.

```sh
cargo fmt --check
scripts/wsl-cargo test --frozen -p aether -p astra -p orion-core --all-features
scripts/wsl-cargo test --frozen -p aether --all-features --lib a_ca_pq_recovery_grant_verifies_and_stays_bound_to_the_historical_request
scripts/wsl-cargo test --frozen -p astra --all-features --lib service::tests::http_routes
scripts/wsl-cargo clippy --frozen -p aether -p astra -p orion-core --all-targets --all-features -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/local-tests -v
bash scripts/regression.sh
cargo audit --file Cargo.lock
npm audit --prefix apps/orion --audit-level=moderate
CARGO_NET_OFFLINE=true npm_config_offline=true bash scripts/campaign.sh
bash scripts/audit-rust.sh collect --view workspace --output-dir /tmp/helios-cov-next-after
bash scripts/audit-rust.sh collect --view libraries --output-dir /tmp/helios-cov-next-after-libs-retry
python3 scripts/audit-report.py compare --baseline /tmp/helios-cov-next-before/report.json --current /tmp/helios-cov-next-after/report.json
```

Le comparateur strict retourne 2 ; régression et audits de dépendances échouent pour les raisons détaillées plus haut. Les succès de tests ne remplacent pas ces échecs. La reconstruction de référence globale a lancé le même collecteur depuis une copie des sources `146ab67` avec `GIT_DIR`/`GIT_WORK_TREE` pointant explicitement sur cette référence ; les hashes vérifiés et le dénominateur reproduit prouvent son contenu, sans la présenter comme un nouvel environnement propre.

Pour les tailles, exécuter `scripts/wsl-cargo build --release --frozen -p helios -p heliosd -p astra`, puis `scripts/wsl-cargo build --release --frozen -p heliosd --features netlink,wireguard,tpm,embed-ui`, sur chacune des copies avant/après au même chemin avec `HELIOS_PUBLISHER_KEYRING_PATH` identique. Le trousseau est fabriqué par `helios-publisher keygen` avec l’époque de test 4294967293, hors dépôt. Les artefacts sont copiés dans `before`/`after` et `before-gateway`/`after-gateway`, puis vérifiés avec `binary-size.py --artifacts ... --provenance ... --baseline ... --output ...` ; formats stricts et commandes détaillés dans `docs/testing/TESTING.md`.

La revue finale a vérifié les SHA de toutes les sources Rust par rapport à la provenance globale terminée, les 36 fiches et leurs 14 champs, les liens documentaires, le diff de whitespace et la liste exacte des trois nouveaux fichiers. Aucun secret, artefact, manifeste, lockfile, profil ou workflow n’est ajouté/modifié. Deux sous-agents Luna ont développé les tests Aether/Astra ; le troisième a réalisé la lecture bornée et la revue croisée. Des oracles initialement trop faibles ont été renforcés avant la mesure : épuisement réel du challenge, identité des corps de refus et watchdogs indépendants.

Priorités suivantes : COV-036 pour lever les audits bloquants avant livraison ; compléter COV-003 (délégation/politique et snapshots) et COV-004 (handlers positifs), puis COV-005/COV-006/COV-013. Les 87 lignes de grant restantes comprennent notamment `resolve_issuer` délégué ; les 280 lignes de service restantes incluent les succès status/vault/result/recovery. Aucun de ces chemins n’est supprimé du dénominateur. COV-007/008/010 restent requis pour les séquences clientes et leurs magasins protégés, même si un jalon global était franchi plus tôt.

# Intégration F14 et poursuite des tests du moteur

Lot du 28 octobre 2026, branche `feat/local-rust-audit`, code mesuré `e6b96c1c14aa3e988172c17e9fcc530f03c37dd6`. Le développement était déjà autorisé. Les tests courts rejoignent les suites habituelles ; les collectes et contrôles lourds restent locaux. Aucun workflow CI, dépendance runtime ni profil release n’a changé.

## Rebase et périmètre du lot

Les 24 commits de la branche ont été rebasés sur **main `5ab3670`**, qui contient les lots 1–2 F14 opérateur/enrôlement. Le rebase n’a eu aucun conflit. `git range-diff cb6d1ae..backup/rust-audit-before-f14-20261028 main..e6b96c1` donne 24 correspondances `=` : les correctifs et tests ont été conservés sans changement de patch. La branche de secours reste disponible ; aucun travail sur main ni fusion/push n’a été effectué.

Les changements F14 viennent de main et ne sont pas crédités comme des tests écrits par ce lot d’audit. La [baseline F11](15-f11-file-baseline.md), la comparaison ciblée Orion à 72,63 % et ses 27 nouveaux tests restent des relevés historiques de leurs révisions. Le dénominateur et les tests ont changé depuis ; une soustraction des taux globaux ne mesure pas le gain de nos seuls ajouts.

## Trois nouveaux tests relus

L’agent Luna a ajouté les cas dans `crates/orion-engine/src/service/profiles/tests.rs`, puis l’orchestrateur a relu et exécuté la suite. Ils vérifient :

* le refus d’une clé privée préparée dont la moitié publique diffère de celle affichée, en conservant la clé du profil en mémoire ;
* le refus d’une clé préparée illisible, sans recopier sa sentinelle secrète dans l’erreur ;
* le refus d’ajouter implicitement un bloc de négociation à un profil durable de type `classic`.

Ces tests exercent `merge_draft` et ses refus ; ils ne prétendent pas écrire un coffre ni valider le TPM. Les fixtures reprennent les générateurs et types existants. Aucune assertion existante n’a été affaiblie, aucun contournement de couverture ni dépendance n’a été ajouté. Les dix tests ciblés de profils passent ; la suite Engine complète contient désormais 152 tests. Le fichier de production `service/profiles.rs` atteint **204 / 316 lignes `DA` de production (64,56 %)** dans la collecte globale actuelle. Le lot ne fournit pas de comparaison F14 avant/après isolant quantitativement les trois tests.

## Résultats sur la branche intégrée

| Contrôle | Résultat et portée |
| --- | --- |
| `cargo fmt --check`, `git diff --check` | Réussis avant les campagnes ; contrôle documentaire final séparé |
| `scripts/wsl-cargo test --frozen -p orion-engine --all-features service::profiles::tests` | 10 succès, dont les trois nouveaux |
| `python3 -m unittest discover -s scripts/local-tests` | 64 tests des outils locaux réussis |
| `bash scripts/regression.sh` | Réussi : Clippy strict Linux, tests workspace, frontends, provisioning et livraison en dry-run, audits |
| Tests Rust de la régression | 2 681 succès, zéro échec/ignoré, dont sept doc-tests ; Core 597, Engine 152, shell Rust Orion 111 |
| Frontends de la régression | 98 tests web et 201 tests TypeScript Orion réussis, builds réussis ; couverture JS non mesurée |
| Audits npm / RustSec | npm : aucune vulnérabilité signalée ; Rust : sept avertissements autorisés subsistent, dont Tokio RUSTSEC-2026-0386, GTK et clipboard-win |
| MSVC Core + Engine | `check --frozen --target x86_64-pc-windows-msvc --all-targets --all-features` réussi ; quatre imports inutilisés préexistants, aucune preuve d’exécution native |
| MSRV 1.95 | Non exécutée : toolchain absente ; la validation utilise Rust 1.99 |

Les logs sont conservés dans `.tmp/audit-20261028/` du worktree, notamment `profiles.log`, `regression.log`, `audit-scripts.log` et `msvc-check.log`. Le contrôle MSVC utilise les wrappers locaux `msvc/clang-cl` et `msvc/lld-link`, les en-têtes MSVC 14.51.36231 et SDK 10.0.26100.0 déjà installés, `llvm-lib` et `lld-link-20`. Aucun téléchargement de WireGuard-NT ni installation système n’a été effectué.

La compilation du shell Tauri Windows et la recette native restent ouvertes : le build de ses ressources crée encore `target/orion-deps` dans les sources et peut télécharger WireGuard-NT. Ce chemin doit respecter le cache unique avant de lancer ce contrôle (COV-002). Les quatre imports signalés proviennent de `protected_root.rs` et `vault/relocation/tests.rs`, inchangés par rapport à main. Clippy Linux strict et une compilation MSVC avec avertissements sont deux résultats différents.

## Couverture actuelle

| Vue de production Linux | Lignes couvertes / retenues | Couverture | Tests instrumentés | Reliquat vers 80 % |
| --- | ---: | ---: | ---: | ---: |
| Globale, toutes features | 37 200 / 57 886 | 64,26 % | 2 674 | 9 109 |
| Bibliothèques seules | 28 314 / 39 293 | 72,06 % | 2 102 | 3 121 |

La [baseline complète](17-f14-file-baseline.md) donne les 23 crates, les 375 fichiers globaux, les 274 fichiers bibliothèques, les fonctions/régions brutes, les retraits syntaxiques chiffrés et la provenance. Les deux collectes sont `completed`, sources propres ; 548 empreintes Rust et toutes les entrées Cargo et sorties sont vérifiées. Les sept doc-tests supplémentaires de la régression classique ne sont pas instrumentés par cette campagne stable.

Le résumé LLVM global donne 70,93 % ; il ne remplace pas les **64,26 % de production**. Il reste **20 686 lignes de production non couvertes**. Branches et MC/DC ne sont pas instrumentés. Les chemins Win32 exclus par `cfg`, les replis Linux, les tests matériel qui quittent sans activation et les suites Vitest ne prouvent aucune validation native Windows, TPM/FIDO ou noyau.

## Comparaison des quatre binaires release

Référence **main `5ab3670`**, après **audit `e6b96c1`**. La comparaison inclut tous les correctifs d’audit rejoués sur F14 ; elle n’attribue pas la variation aux trois nouveaux tests. Les deux builds utilisent le même chemin `/tmp/helios-20261028-size/source`, Rust 1.99.0, la cible hôte `x86_64-unknown-linux-gnu`, un trousseau éditeur de test identique et les mêmes assets frontend figés par SHA-256. Le profil conserve `lto = "thin"` et `strip = true` ; aucune instrumentation n’est activée. Ces ELF Linux de test ne sont pas des livraisons Windows ni des artefacts signés destinés à la production.

| Binaire | Avant (octets) | Après (octets) | Écart | SHA-256 après |
| --- | ---: | ---: | ---: | --- |
| astra | 12 388 656 | 12 395 872 | +7 216 | `77b3ee9f9a03ee2986a54699edd68885b32061ef5e184c395775929bd41ddbd3` |
| helios | 14 434 456 | 14 442 808 | +8 352 | `73c98a62d777bab68ae430b9aa5590feedb1971c4df213f46d25abd054a049bd` |
| heliosd | 22 873 016 | 22 896 416 | +23 400 | `d6fbe17400044e603c4314c683024cc9a9e3868cde47b598ffe72f0b60c559e7` |
| orion | 28 968 760 | 28 985 272 | +16 512 | `295bf9653263b8b8a735a31f85dd52b2d0a9749163749b4367eeec48aa13b088` |

Les quatre contrôles `helios-update` réussissent sous **134 217 728 octets (128 Mio)**. La plus grande hausse est de 23 400 octets pour heliosd, environ 0,10 %. Les changements de production portent notamment sur lectures HTTP bornées, durabilité/publication et propriété transactionnelle ; le lot ne prétend pas attribuer chaque octet de LTO à une fonction. Les tests `cfg(test)` et la feature Tokio `test-util` en dev-dependency ne sont pas des dépendances runtime ajoutées.

Commande Cargo effective pour les deux révisions, depuis la référence, sous `scripts/cargo-budget.sh` et le verrou partagé `.helios-build.lock` conservé jusqu’à la copie des quatre sorties :

```sh
HELIOS_PUBLISHER_KEYRING_PATH="/home/christophe/helios-wt/rust-audit/.tmp/audit-20261028/test-publisher-keys/publisher-keyring.json" \
cargo build --release --frozen -p helios -p astra -p heliosd -p orion \
  --features heliosd/netlink,heliosd/wireguard,heliosd/tpm,heliosd/embed-ui,orion/wireguard
```

Les scripts locaux `.tmp/audit-20261028/build-size.sh` et `snapshot-size.py` documentent l’appel complet et la capture. Le budget est calculé depuis le vrai worktree Git, jamais seulement depuis la copie temporaire : aucun second target, aucun nettoyage manuel et aucun dépassement n’ont été employés. Le plus haut relevé des campagnes est 49,2 Gio, puis 47,3 Gio à la fin du build après, sous le plafond 65 Gio. Les variations de cache ne sont pas des variations de taille binaire.

**Contrôle de fraîcheur :** le premier essai après avait réutilisé les sorties avant, car les dates conservées par l’archive précédaient le build. Il a été invalidé et isolé sous les noms `*.stale-cache-diagnostic`. Les 75 fichiers modifiés ont ensuite reçu une date courante sans modification d’octets ; une véritable recompilation a été constatée. La capture finale exige que chacun des quatre binaires soit postérieur au relevé de changement des sources. Toutes les sources de la référence après ont été comparées à l’archive du commit, les assets sont inchangés et les huit empreintes avant/après ont été revérifiées. Les résultats diagnostiques ne sont pas la baseline finale.

Rapports valides : `size-before.json`, `size-after.json`, leurs `size-*-provenance.json`, répertoires `sizes-before`/`sizes-after`, logs `size-before-build.log`/`size-after-build.log`, archives `main.tar`/`audit.tar` et `size-inputs.json`, tous sous `.tmp/audit-20261028/`. Le dernier fichier enregistre uniquement les SHA des archives, du trousseau **public** et de la liste d’assets. Le matériel privé jetable reste dans le dossier local protégé, ignoré par Git ; aucun secret ni artefact généré n’est ajouté aux commits.

## Doublons et code obsolète après F14

La revue Luna et la lecture des appelants ont confirmé les frontières suivantes ; aucune extraction supplémentaire ni suppression n’est réalisée par ce lot.

| Élément | Emplacements | Nature / confiance | Décision |
| --- | --- | --- | --- |
| Contrôle des feuilles, draft et profil v5 | `crates/orion-core/src/enrollment_draft.rs:53,77,160,179`, `tools/helios/src/enroll.rs:170-228`, `tools/helios/src/profile.rs:25,71`, `apps/orion/src-tauri/src/operator/ceremony.rs:1192-1239` | Ancienne duplication sémantique réduite sur main ; élevée | Conserver les helpers Core et leurs tests, ne pas réintroduire une construction parallèle dans le moteur |
| Client d’administration gateway | `crates/orion-core/src/gateway_admin.rs:38-53,180-217,251-294,313-404`, appel CLI `tools/helios/src/enroll.rs:218-228` | Propriétaire commun désormais présent ; élevée | Conserver client fourni par l’appelant, identité/pin et admission cohérentes, réponse bornée 1 Mio et refus typés |
| Sources offline du CLI et workflow opérateur Orion | `tools/helios/src/enroll.rs:84-147,231-239`, `apps/orion/src-tauri/src/operator/ceremony.rs` | Ressemblance de flux avec entrées distinctes ; élevée | Conserver les adaptateurs ; ne pas fusionner cérémonie, fichiers offline et admission réseau |
| Lecture HTTP bornée | `crates/orion-core/src/certificate_http.rs:12-32`, `crates/orion-core/src/gateway_admin.rs:180-202` | Duplication sémantique partielle, gravité faible à moyenne ; élevée | Étudier seulement la plomberie de lecture après comparaison des refus ; conserver limites, clients, timeouts, statuts et erreurs propres aux domaines. Aucun client HTTP universel proposé |
| Ancien helper et approbation ordinaire | Helper déjà supprimé de main ; `crates/orion-core/src/certificate_approval.rs`, état de reprise obsolète | Helper retiré, API d’approbation B ; élevée sur raccordement, pas sur usages externes | Ne pas supprimer à nouveau le helper ; inventorier compatibilité et consommateurs avant retrait des API publiques |

Les trois fonctions privées de probes identifiées dans l’audit 04 restent une décision produit COV-031, pas un raccourci pour diminuer le dénominateur. Une ligne non exécutée n’est pas une preuve de code mort. COV-026 doit couvrir la frontière processus/SID/pipe et le teardown, COV-034 le geste FIDO réel, COV-035 les workflows opérateur/coffre durables. Le parsing, les signatures du draft et le client admin ont déjà leurs suites Core ; ne pas dupliquer leurs responsabilités pour augmenter artificiellement le nombre de tests.

## Suite priorisée

Le chemin critique reste COV-007/COV-008 (cycles positifs renewal/recovery du moteur et conservation des sessions en échec), le prérequis cache COV-002 et la recette Windows COV-010, puis les scénarios restants COV-013/COV-014/COV-012, COV-011 et COV-034/COV-035. Les détails, dépendances et critères d’acceptation des 36 fiches restent dans [la roadmap](07-roadmap-to-80.md). Les réserves de lignes historiques doivent être réattribuées à partir du document 17 avant d’annoncer un gain prévisionnel F14. Le seuil de 80 % reste un jalon ; les métriques ne remplacent ni scénarios négatifs ni matériel.

Validation documentaire finale : `cargo fmt --check`, `git diff --check`, vérification des liens locaux, des sommes par fichier/crate et des 36 fiches × 14 champs. Aucun fichier Rust, manifeste ou lockfile n’a changé depuis les campagnes sur `e6b96c1` ; seuls les documents évoluent ensuite.

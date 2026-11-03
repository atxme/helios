# Cycles de certificats et durabilité — deuxième lot de développement

Lot du 24 octobre 2026, branche `feat/local-rust-audit`. Référence de production `4e7f686`, après reprise ciblée des corrections de dépendances de main ; code final `ed661fb` (tests Aether `8d55467`). Objectif : couverture pertinente maximale. Aucun workflow CI, profil, seuil ou mécanisme d’exclusion n’est modifié.

## Résultat et périmètre

| Mesure | Avant | Après |
|---|---:|---:|
| **Production globale Linux** | 31 287 / 53 046 = 58,98 % | **32 339 / 53 087 = 60,92 %** |
| **Production bibliothèques, collecte distincte** | 23 190 / 34 889 = 66,47 % | **24 438 / 34 930 = 69,96 %** |
| Lignes globales brutes LLVM | 47 396 / 70 957 = 66,80 % | 48 518 / 71 049 = 68,29 % |
| Fonctions globales brutes LLVM | 4 545 / 7 006 = 64,87 % | 4 611 / 7 011 = 65,77 % |
| Fonctions globales brutes jamais exécutées | 2 461 | 2 400 |
| Régions globales brutes LLVM | 69 820 / 105 416 = 66,23 % | 71 366 / 105 614 = 67,57 % |
| Tests réussis, collecte globale | 2 200 | 2 221 |
| Tests réussis, bibliothèques seules | 1 716 | 1 737 |

Les quatre collectes sont `completed`, avec zéro échec/ignoré. Branches et MC/DC **non instrumentées**, donc non mesurées ; leurs compteurs nuls ne signifient pas 0 % de couverture. Le brut LLVM bibliothèques est 36 001 / 47 492 = 75,80 %, distinct de sa projection de production et du total projet.

La projection reste `rust-ast-da-v1`, fondée sur les lignes `DA` et les preuves AST de code exclusivement test/harnais. Les nouveaux fichiers de fixture sont sous `cfg(test)` ; aucun code de production n’est exclu pour améliorer le résultat. La vue globale emploie `--workspace --all-features` et comprend les binaires et intégrations hôtes ; elle ne prétend pas être `--all-targets`, compiler les benchmarks ou inclure le code Windows éliminé par `cfg`. La seconde collecte ajoute `--lib` : elle ne remplace jamais la couverture globale.

Le compteur global gagne **1 052 lignes couvertes**, avec **41 lignes supplémentaires au dénominateur**. L’alignement exact des blocs textuellement inchangés, `SequenceMatcher(autojunk=False)`, croisé avec les `DA` de production des deux rapports, trouve **997 lignes existantes devenues couvertes et zéro perte sur les lignes alignées**. Les 55 autres lignes couvertes supplémentaires sont nouvelles ou modifiées, sans attribution fictive aux tests. Ce rapprochement textuel n’est pas une preuve sémantique sur les lignes réécrites. Le comparateur strict renvoie **2**, car le dénominateur/périmètre change : une nouvelle référence explicite est requise ; aucun verdict strict de non-régression comparable n’est déclaré vert.

Au nouveau dénominateur constant, il reste **20 748 lignes non couvertes** vers 100 %, **4 822** lignes à couvrir pour 70 %, **7 477** pour 75 % et **10 131** pour 80 %. Le reliquat global baisse de 1 011 lignes. Ces nombres seront recalculés après chaque modification de production. Les gains bibliothèques peuvent dépasser les gains globaux : les nouveaux tests unitaires exercent aussi des chemins déjà couverts par les intégrations de la vue globale.

## Modules concernés

| Module | Production avant | Production après | Non couvert après |
|---|---:|---:|---:|
| Aether `client/grant.rs` | 327 / 414 = 78,99 % | 372 / 414 = 89,86 % | 42 |
| Aether `state/ledger.rs` | 268 / 300 = 89,33 % | 286 / 300 = 95,33 % | 14 |
| Astra `recovery.rs` | 41 / 408 = 10,05 % | 372 / 416 = 89,42 % | 44 |
| Astra `renewal/request.rs` | 0 / 178 | 145 / 181 = 80,11 % | 36 |
| Astra `renewal/stage.rs` | 0 / 169 | 174 / 180 = 96,67 % | 6 |
| Astra `registry/peer_lifecycle.rs` | 152 / 246 = 61,79 % | 193 / 265 = 72,83 % | 72 |

Par crate, Aether passe de 8 039 / 9 180 à **8 106 / 9 180 = 88,30 %** ; Astra de 2 459 / 5 763 à **3 402 / 5 804 = 58,61 %**. Les JSON donnent tous les fichiers/crates. La famille renewal gagne 394 lignes existantes alignées (`approval`, `companion`, `mod`, `request`, `stage`), recovery 323 ; ces mesures ne sont pas les garanties des estimations initiales COV-005/COV-006. Les effets voisins (operations, issuer, canal) ne sont pas comptés une seconde fois dans ces gains de famille.

## Six cas de défaut reproduits puis corrigés

1. **Acceptation initiale non durable** : échec du journal, mais réservation du pair laissée en mémoire. L’opération neuve est maintenant retirée sur cet échec.
2. **Autorisation non durable** : `record_stage` avançait avant `persist()` ; le poll pouvait réutiliser des octets jamais journalisés. La mutation est préparée sur une copie d’une opération, puis restaurée sur erreur.
3. **Grant non durable** : reçu et grant étaient publiés en mémoire avant l’écriture. Même rollback sous mutex, sans `await` entre publication, persistance et restauration.
4. **Réservation de registre non durable** : `open_rotation` conservait réservation/audit après erreur ; un retry identique sautait ensuite l’écriture. Préparation d’un registre candidat et publication mémoire uniquement après sauvegarde.
5. **Marqueur de grant non durable** : `mark_granted` avait le même défaut de reprise. Même correction ; un grant déjà durable dans le journal n’est jamais retiré si cette seconde écriture échoue.
6. **Rejeu recovery après succès Astra** : un commit signé déjà accepté était refusé avec `WrongState`. L’opération mémorise désormais l’empreinte canonique incluant les deux signatures, uniquement après succès gateway. Rejeu strictement identique : même vue, sans nouvel envoi. Corps/signature différents ou opération expirée : refus. Aucune modification du format réseau ou persistant.

Preuves fraîches avant correction : `/tmp/helios-round4-repro.log`, **19 tests, 15 succès, quatre échecs** (trois journal et rejeu recovery). Le registre était déjà corrigé dans cet essai. Les nouvelles régressions renewal ont ensuite été rejouées sur la production archivée `4e7f686` : `/tmp/helios-round4-renewal-before.log`, **15 tests, dix succès, cinq échecs**, dont les deux défauts du registre. Après correction : **19/19 workflows réussis**, puis régression complète et collectes réussies. Les échecs attendus de référence ne sont pas présentés comme des échecs de la branche finale.

Les tests vérifient état mémoire, octets durables antérieurs, absence d’envoi prématuré, restauration et rechargement effectif après retry. Le scénario de staging perd une réponse puis recharge les états Astra et gateway simulé ; le grant client est vérifié par le validateur complet. La récupération parcourt `open → authorize → grant → commit`, avec certificats TLS/PQ et CSR réels, preuves ML-DSA et assertion opérateur ES256 logicielle. Le certificat historique TLS expire à Unix 5 000 et ses empreintes/dates concordent avec la génération ; le validateur historique reste fondé sur les empreintes, sans revendiquer un nouveau contrôle d’expiration X.509.

Aether ajoute un grant délégué valide et des refus précis de politique, délégation, durée/génération, ainsi que la saturation sans mutation du ledger. Les variations d’empreinte du snapshot sont isolées : révocations différées, tombstones, puis présence de l’émetteur ; la tombstone est retirée avant la dernière comparaison pour éviter un oracle faussement positif.

## Contraintes de taille et de ressources

Même chemin de reconstruction `/tmp/helios-round4/reference`, mêmes lockfiles, Rust 1.99, target Linux, profil release inchangé (`lto = "thin"`, `strip = true`), même trousseau éphémère hors dépôt. Même commande et ensemble de features explicites `heliosd/netlink,heliosd/wireguard,heliosd/tpm,heliosd/embed-ui` pour les trois artefacts. Les fichiers source copiés après la référence ont été touchés pour forcer la détection Cargo. Les artefacts avant sont conservés avant toute reconstruction ; aucune sortie instrumentée n’est mesurée.

| Artefact | Avant, octets | Après, octets | Delta |
|---|---:|---:|---:|
| astra | 12 307 184 | 12 318 168 | +10 984 |
| helios | 13 701 408 | 13 701 408 | 0, SHA identique |
| heliosd | 22 639 544 | 22 639 544 | 0, SHA identique |

`binary-size.py` valide provenances, formats et borne canonique **134 217 728 octets** pour les trois. Aucun seuil ni flag n’est relâché. Le lot ajoute zéro dépendance directe ; les tests ne sont pas liés aux binaires livrés. Les deux transitions du registre copient son état public avant écriture : coût mémoire proportionnel au registre, non benchmarké. Le journal copie seulement une opération, pas tout son magasin. Ces résultats ne couvrent ni MSI ni binaires Windows.

Tous les builds passent par le budget partagé, sans nouveau target, nettoyage ou dépassement demandé par cette session. Maximum observé dans les logs de cette série : 57,3 Gio, sous 65 Gio. Les gardes mémoire adaptent le nombre de jobs ; aucune limite n’a été abaissée.

## Audits et validation

COV-036 est **débloquée pour cette révision et cette exécution**, sans gain de couverture attribué aux dépendances : reprise ciblée de `de95540` et `72e7624` depuis main, sans fusion des autres développements. ctutils 0.4.5, rustls-webpki 0.103.16 et webpki-root-certs 1.0.11 corrigent les échecs Rust ; undici 8.12.3 corrige les deux lockfiles frontend. Aucun `audit fix` global, avis masqué ou seuil affaibli. Les MSRV déclarées des trois correctifs Rust sont au plus 1.87, compatibles avec la contrainte 1.95 ; cela ne remplace pas une compilation 1.95.

`bash scripts/regression.sh` termine avec le code **0** : Clippy workspace strict toutes cibles/features, Aether sans signature, tests Rust workspace, **98 tests web et 162 Orion**, builds frontend, deux audits npm à zéro vulnérabilité, campagne provisioning/update/bundle dry-run, refus du trousseau de développement en release, check release avec trousseau éphémère et audit Rust. RustSec conserve **sept avertissements autorisés**, distincts d’un succès sans avertissement. Les 64 tests locaux d’outillage passent aussi. Après renforcement final de l’oracle snapshot, les **495 tests Aether** ont été rejoués ; les deux collectes finales exécutent ensuite les sources finales. Aucun autre changement de production ne suit la régression.

Limites : MSRV 1.95 non installée ; Windows natif, FIDO physique, TPM, noyau WireGuard/nftables, installation et WireGuard-NT non exécutés. Le canal privé est le vrai mTLS/routeur sur loopback, pas un veth réel. Le gateway de récupération applique les effets **en mémoire** : preuve de réponse perdue/rejeu dans le même processus et réconciliation Astra, pas de redémarrage durable du gateway. L’empreinte de commit Astra reste elle-même éphémère, bornée par l’opération ; l’intent de réconciliation est durable. Watchdogs indépendants : 15 secondes pour le workflow recovery complet et 10 secondes pour les appels renewal.

## Suites prioritaires, sans fermeture artificielle des tâches

| Ordre | Tâche existante | Prochaine preuve attendue |
|---|---|---|
| 1 | COV-006 / COV-020 | `renewal/companion.rs::read` et `signer_result` : reproduire les mutations avant persistance du challenge et de l’approbation ; rollback/retry/rechargement, avec effets du magasin de challenges vérifiés |
| 2 | COV-005 | Refus recovery : révocation, identité/raison/évidence incohérentes, reçu faux, canal absent ; état/audit/intents sans effet indu |
| 3 | COV-006 / COV-020 | Concurrence et annulation aux frontières journal/stage/grant, barrières déterministes et propriété du stage |
| 4 | COV-013 | Négociation v5 : future annulée après installation, rollback et génération obsolète ; handshake réellement postérieur à l’installation |
| 5 | COV-007 | Renouvellement Orion : transaction complète, coupures et reprise des magasins |
| 6 | COV-008 | Recovery cliente : commit perdu, promotion et reconnexion cohérentes |
| 7 | COV-010 | DPAPI puis promotion/reconnexion sur Windows natif |
| 8 | COV-014 | Orchestrateur : kill-switch, échecs et états partiellement appliqués |
| 9 | COV-034 / COV-035 | Cérémonies FIDO/opérateur réelles, sans assimiler ES256 logiciel au matériel |
| 10 | COV-019 / COV-020 | Autres writers, corruption, publication et restauration sous erreurs |

Constat **statique**, encore à reproduire : `renewal/companion.rs:26-28` et `:211-214` modifient avant `persist()`. Les autres méthodes du registre (`admit`, réconciliation, purge…) ne bénéficient pas automatiquement des corrections ciblées. COV-005/COV-006 restent partielles ; le routeur renewal reste à 0 / 69 et companion à 22 / 164, malgré leurs tests distribués et le succès du workflow automatique. Aucune suppression n’est proposée sur cette base. La seule factorisation livrée est le helper mTLS exclusivement test commun aux deux workflows ; les domaines cryptographiques restent séparés.

Le chemin critique reste contrats et durabilité → concurrence/négociation → transactions clientes → preuves sur cibles → orchestration/CLI/API → nouvelles mesures. Les fiches 07 gardent leurs préconditions, efforts et critères d’acceptation ; la fourchette historique de 135–237 jours-personne porte sur le plan initial, **pas sur une promesse de 100 %**. Une estimation restante vers 100 % exige de requalifier le reliquat et de disposer des cibles. Décisions humaines restantes : ratifier le périmètre v1 et la rétention des références, fournir les environnements cibles et arbitrer les factorisations/suppressions déjà documentées.

## Reproduction et conservation locale

```sh
scripts/wsl-cargo test --frozen -p astra --all-features --lib workflow
scripts/wsl-cargo test --frozen -p aether --all-features --lib
cargo fmt --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/local-tests
bash scripts/regression.sh
cargo audit --file Cargo.lock
npm audit --prefix web --audit-level=moderate
npm audit --prefix apps/orion --audit-level=moderate
bash scripts/audit-rust.sh collect --view workspace --output-dir /tmp/helios-round4-after
bash scripts/audit-rust.sh collect --view libraries --output-dir /tmp/helios-round4-after-libs
python3 scripts/audit-report.py compare --baseline /tmp/helios-round4-before/report.json --current /tmp/helios-round4-after/report.json
```

Les chemins de collecte sont neufs lors de leur exécution ; ne pas les réutiliser sans choisir de nouvelles destinations. Le comparateur retourne 2, attendu pour changement de périmètre. Les audits et la régression ont des interactions réseau identifiées avant exécution ; les collectes sont hors ligne, gelées, sans installation implicite. Rust 1.99.0, LLVM 23.1.1, cargo-llvm-cov 0.9.1, Linux x86_64 WSL2.

Références : `git archive 4e7f686` vers `/tmp/helios-round4/reference.tar`, extraction puis collectes depuis copies avec `GIT_DIR=/home/christophe/helios/.git/worktrees/rust-audit` et `GIT_WORK_TREE=<copie>`. La référence globale a été collectée avant les commits du code final ; la référence bibliothèques après, donc sa provenance rapporte HEAD `ed661fb` avec arbre sale. **Ses 474 empreintes Rust et ses entrées de build sont identiques à celles de la référence globale archivée `4e7f686`** : le contenu archivé, pas ce HEAD de collecte, définit la référence. Les 477 empreintes finales concordent avec le worktree final. Frontend précompilé et liens node_modules sont des entrées locales : aucune prétention d’environnement propre. Le chemin de build release est ensuite réutilisé, l’archive originale restant intacte.

Artefacts temporaires : quatre dossiers `/tmp/helios-round4-{before,before-libs,after,after-libs}` (JSON, LCOV, HTML, hashes et provenances) ; `/tmp/helios-round4/aligned-lines.json` et `analyze.py` (rapprochement textuel), `size-{before,after}.json`, `size-provenance-{before,after}.json`, `sizes-{before,after}` ; logs `/tmp/helios-round4-*.log`. Les mesures antérieures restent dans le journal 09, leurs anciens fichiers temporaires ayant disparu. Ces nouveaux chemins sont eux aussi temporaires, pas une politique de conservation garantie. Aucun artefact généré, secret ou fichier d’environnement n’est commité.

Tailles : exécuter la même commande `scripts/wsl-cargo build --release --frozen -p helios -p astra -p heliosd --features heliosd/netlink,heliosd/wireguard,heliosd/tpm,heliosd/embed-ui` sur les sources avant/après au même chemin, avec `HELIOS_PUBLISHER_KEYRING_PATH=/tmp/helios-round4/keys/publisher-keyring.json` identique. Copier les trois sorties immédiatement, puis `python3 scripts/binary-size.py --artifacts /tmp/helios-round4/sizes-after --provenance /tmp/helios-round4/size-provenance-after.json --baseline /tmp/helios-round4/size-before.json --output <nouveau-rapport>`. Les attestations restent déclarées par le constructeur ; l’outil ne prouve pas lui-même les flags de compilation.

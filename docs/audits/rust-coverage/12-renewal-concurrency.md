# Annulation, concurrence et routes privées Astra — quatrième lot

Lot du 25 octobre 2026, branche `feat/local-rust-audit`, référence `b91130a`, code final `790d559`. Deux agents Luna développent les modifications sur des fichiers distincts ; un troisième réalise la revue indépendante, et l’orchestrateur exécute les validations et relit les changements.

## Mesures finales

| Mesure | Référence reconstruite | Après |
|---|---:|---:|
| **Production globale Linux** | 32 604 / 53 102 = 61,40 % | **32 761 / 53 155 = 61,63 %** |
| **Production bibliothèques, collecte distincte** | 24 706 / 34 945 = 70,70 % | **24 864 / 34 998 = 71,04 %** |
| Lignes globales brutes LLVM | 49 246 / 71 524 = 68,85 % | 50 115 / 72 284 = 69,33 % |
| Fonctions globales brutes LLVM | 4 648 / 7 039 = 66,03 % | 4 712 / 7 084 = 66,52 % |
| Fonctions globales brutes non exécutées | 2 391 | 2 372 |
| Régions globales brutes LLVM | 72 528 / 106 492 = 68,11 % | 74 103 / 107 912 = 68,67 % |
| Tests réussis, collecte globale | 2 228 | 2 238 |
| Tests réussis, bibliothèques seules | 1 744 | 1 754 |

Les quatre collectes sont `completed`, zéro échec/ignoré. Branches et MC/DC **non instrumentées**, donc non mesurées. Le brut bibliothèques est 37 599 / 48 727 = 77,16 %, distinct de la projection de production. La référence reconstruite retrouve les lignes/fonctions/compteurs de production du journal 11 ; elle a une région brute exécutée de moins. Cette variation n’est ni masquée ni attribuée à une cause sans preuve. Les chiffres du journal 11 restent historiques.

La projection reste `rust-ast-da-v1`. Les deux nouveaux fichiers de tests ont chacun zéro ligne de production, confirmé dans leurs rapports et leurs preuves AST de module `cfg(test)` hérité. Aucune exclusion de production, feature, plateforme ou condition spéciale de couverture n’est ajoutée. Les options sont identiques : workspace/toutes features Linux hôte (binaires et intégrations compris), puis `--lib` pour la seconde collecte. Cela ne prétend pas mesurer Windows ni les benchmarks/exemples de `--all-targets`.

**+157 lignes couvertes et +53 lignes de production**, dont **113 lignes existantes devenues couvertes**, sans perte sur les blocs textuellement inchangés alignés (`SequenceMatcher`, autojunk désactivé, croisé avec les `DA` de production). Les 44 autres lignes couvertes supplémentaires sont nouvelles ou modifiées. Cet alignement n’est pas une preuve sémantique des lignes réécrites. Le comparateur strict retourne **2**, attendu pour changement de périmètre/dénominateur : il faut ratifier une nouvelle référence ; aucun verdict strict comparable vert n’est revendiqué.

Il reste **20 394 lignes non couvertes** vers 100 %, soit 104 de moins. À dénominateur 53 155 constant : 4 448 lignes supplémentaires pour 70 %, 7 106 pour 75 %, **9 763 pour 80 %**. L’objectif reste la couverture pertinente maximale, pas l’arrêt à 80 %.

| Module | Production avant | Production après | Non couvert après |
|---|---:|---:|---:|
| Astra `renewal/router.rs` | 0 / 69 | 55 / 69 = 79,71 % | 14 |
| Astra `renewal/stage.rs` | 162 / 168 = 96,43 % | 206 / 221 = 93,21 % | 15 |
| Astra entière | 3 626 / 5 819 = 62,31 % | 3 782 / 5 872 = 64,41 % | 2 090 |

La baisse du pourcentage de stage vient des contrôles de cohérence ajoutés ; les branches/lignes encore non exercées restent dans le dénominateur. Les gains sur les seules lignes existantes sont : routeur 55, registre peer_lifecycle 24, distribution 13, assemblage des routes opérateur 10, classification des erreurs renewal 10, transport astra-channel une. Ces gains voisins ne sont pas une preuve de réussite d’un workflow opérateur ou d’une transaction trust-update complète ; la préparation HTTP est ici refusée pour appelant incohérent, sans mutation.

## Preuves avant correction

Les rapports temporaires du lot 11 ont disparu. Deux nouvelles collectes depuis une archive Git de `b91130a` reproduisent la référence : production globale 32 604 / 53 102 = 61,40 %, bibliothèques 24 706 / 34 945 = 70,70 %. La copie inclut les assets frontend locaux et des liens node_modules ; elle n’est pas présentée comme un environnement propre.

Les nouveaux tests utilisent des sémaphores comptés et des watchdogs pour suspendre les appels réseau aux étapes effectives du gateway simulé. Le test d’annulation confirme une tâche réellement annulée après le stage écrit, recharge les états Astra et le fichier du gateway simulé, puis vérifie le rejeu de la même autorisation. Il ne prouve pas un crash du processus gateway ni une opération noyau.

Avant correction, `/tmp/helios-round6-workflows-before-confirmed.log` rapporte **27 tests, 25 succès et deux échecs** :

- Deux polls simultanément suspendus sur le même stage entrent en conflit sur des reçus signés distincts (`Operation(ReceiptConflict)`).
- Une révocation durable pendant la lecture de l’identité servie est suivie d’un grant publié dans le journal : `memory_missing=false`, `disk_missing=false`, état `PendingCommit`.

Le deuxième constat ne démontre pas une livraison du grant au client : la réconciliation préalable aux lectures normales le retient quand la révocation a supprimé la réservation. Le défaut démontré est la création/persistance après révocation connue d’Astra. L’audit des verrous existants trouve l’ordre imbriqué `operations → registry`, sans chemin inverse simultané dans les modules inspectés ; les chemins qui prennent les deux dans l’autre ordre relâchent le premier avant le second.

Le premier essai avait aussi un oracle HTTP erroné : Axum répond 422 à une identité JSON mal typée, contre 400 pour une syntaxe JSON invalide. Seul le test est corrigé, aucun statut de production n’est affaibli.

## Portée des routes

Les tests HTTP passent par le routeur Axum réel sur loopback et vérifient requêtes typées, limites de corps, méthodes, identifiants, fallback, lecture d’une opération effectivement rechargée et capacités vérifiées contre scope/opération/manifeste/délai. Ils couvrent le routeur après terminaison TLS ; ils ne revendiquent pas une nouvelle preuve mTLS. Le canal gateway des workflows conserve son vrai mTLS épinglé. Les fixtures de lecture ne prétendent pas que leurs demandes modifiées pour l’horloge actuelle seraient des demandes d’émission cryptographiquement valides.

## Limites maintenues

Les scénarios nouveaux sont des tests unitaires ordinaires. Couverture et tailles restent locales, aucun workflow CI n’est étendu. MSRV 1.95, Windows natif, TPM/FIDO physiques et WireGuard/nftables noyau restent des validations séparées. Une couverture élevée de ce lot ne démontre pas leur sécurité ni leur intégration matérielle.

## Correction et revue

Après les derniers appels réseau, la publication prend `operations`, puis `registry`, conformément à l’ordre déjà imbriqué dans le dépôt. Elle relit l’état de l’opération et son autorisation exacte. Un `PendingCommit` déjà durable n’est pas resigné ni réécrit : la réconciliation reprend sur ce résultat. Pour un `PendingGrant`, le pair doit toujours être connu, non révoqué, sur la génération et les empreintes actives attendues ; la réservation doit porter le même stage, la même demande, le même candidat, la même fenêtre et la même lease, sans être déjà accordée.

Signature et persistance sont synchrones sous ces deux verrous, sans aucun appel réseau ni attente asynchrone dans cette section. Une révocation qui a acquis le registre avant cette section interdit le nouveau grant ; si le grant est persisté d’abord, il reste irrévocable et un poll retardé n’en modifie pas les octets après révocation. La lecture peut alors échouer en réconciliation (`NoRotation`), sans effacer le grant. Le marqueur de registre reste une seconde écriture réparée par le mécanisme existant, sans prétendre transformer les deux fichiers en transaction de système de fichiers.

Les tests finaux vérifient : tâche réellement annulée, mémoire et journal sans grant avant reprise, recharge du fichier du gateway simulé et des stores Astra, autorisation et génération identiques au retry ; deux handlers réellement suspendus ensemble avant reprise, mêmes grants retournés et persistés ; révocation gagnante sans grant sur disque ; grant gagnant conservé après révocation ; cinq mutations de réservation isolées et durablement préservées après refus. La revue a remplacé les notifications susceptibles de se fusionner par des sémaphores comptés, éliminé une dépendance à l’ordonnancement, isolé les mutations de tests et placé le contrôle de l’autorisation avant la réutilisation du résultat existant. Aucun test ne se contente d’exécuter une fonction sans oracle de comportement.

La spécification §8.1.2 précise cette sérialisation et le rejeu du grant ; aucun format réseau ou persistant n’est changé. Les signatures restent vérifiées par les types canoniques, sans fusion de domaines cryptographiques ni nouvelle dépendance. L’impact de la signature et de l’écriture sous verrou n’a pas été benchmarké ; ces opérations de renouvellement restent sérialisées pour conserver leur cohérence.

## Tailles et ressources

Même chemin source `/tmp/helios-round6/reference` avant/après, même toolchain et profil release, mêmes lockfiles, mêmes assets web et même trousseau éphémère hors dépôt, époque de test 4294967293. Commande identique pour les trois packages avec features explicites `heliosd/netlink,heliosd/wireguard,heliosd/tpm,heliosd/embed-ui`. Les sorties avant sont copiées avant remplacement des sources ; les `.rs` modifiés sont copiés puis touchés avant reconstruction. Aucune sortie instrumentée ni aucun flag d’instrumentation de couverture n’est employé pour ces tailles.

| Artefact | Avant, octets | Après, octets | Delta |
|---|---:|---:|---:|
| astra | 12 303 280 | 12 320 520 | **+17 240** |
| helios | 13 701 408 | 13 701 408 | 0, SHA identique |
| heliosd | 22 639 544 | 22 639 544 | 0, SHA identique |

`binary-size.py` valide les trois contre la borne canonique **134 217 728 octets**, sans changer limite, profil ou options d’optimisation. Les attestations du constructeur restent des déclarations, pas une preuve indépendante des flags par l’outil. Les tests et leurs gates ne sont pas liés aux binaires de production. Ces résultats ne couvrent ni MSI ni binaires Windows.

Tous les builds passent par le cache partagé et le garde-fou existant : **62,9 Gio** au maximum observé, sous 65 Gio. Le seuil d’avertissement de 60 Gio est atteint et reste visible. Aucun nouveau target, relèvement de budget ou nettoyage n’est exécuté par cette session. La même copie source a été réutilisée pour les deux mesures finales, afin d’éviter d’ouvrir un chemin de compilation supplémentaire. Les diminutions observées du cache ne sont pas attribuées à notre travail.

## Validation et provenance

La suite Astra finale passe : **185 tests unitaires et 13 tests d’intégration**, environ deux secondes pour la suite unitaire ciblée mesurée. La régression canonique retourne **0** : Clippy workspace strict/toutes cibles/features, Aether sans signature, tests workspace, 98 tests web et 162 Orion, deux builds frontend, campagnes provisioning/update/bundle dry-run, refus release du trousseau de développement puis check avec trousseau de test. Les audits npm sont à zéro vulnérabilité ; RustSec conserve **sept avertissements autorisés**, distincts d’un résultat sans avertissement. Les dix nouveaux tests sont des tests unitaires ordinaires ; aucun job CI ou campagne lourde n’est ajouté.

Rust 1.99.0, LLVM 23.1.1, cargo-llvm-cov 0.9.1, Linux x86_64 WSL2. MSRV 1.95 non installée, Windows natif, FIDO physique, TPM, nftables/WireGuard noyau, WireGuard-NT et installation non exécutés. Les gates prouvent un entrelacement des opérations, pas l’intégration réelle du plan de données. L’annulation après écriture du grant mais avant marqueur du registre n’est pas directement reproduite ; les tests existants d’erreur de cette seconde écriture restent distincts. Les erreurs de synchronisation post-renommage et les pertes d’alimentation restent hors preuve, comme au journal 11.

```sh
scripts/wsl-cargo test --frozen -p astra --all-features --lib workflow_tests
scripts/wsl-cargo test --frozen -p astra --all-features
bash scripts/regression.sh
```

La première commande a aussi servi aux reproductions avant correction. Logs : `/tmp/helios-round6-workflows-before.log` (première tentative, oracle HTTP incorrect), `workflows-before-confirmed.log` (25 succès/deux échecs de production), `workflows-after.log`, `astra-final.log` et `regression.log`, avec le même préfixe `/tmp/helios-round6-`. Les oracles ont été renforcés avant la mesure finale, sans affaiblissement d’assertion pour faire passer un défaut.

Les quatre collectes sont lancées depuis `/tmp/helios-round6/reference`, avec `GIT_DIR=/home/christophe/helios/.git/worktrees/rust-audit` et `GIT_WORK_TREE=/tmp/helios-round6/reference` :

```sh
bash scripts/audit-rust.sh collect --view workspace --output-dir /tmp/helios-round6-before
bash scripts/audit-rust.sh collect --view libraries --output-dir /tmp/helios-round6-before-libs
# Remplacer les sources Rust par celles du commit final, sans changer de chemin.
bash scripts/audit-rust.sh collect --view workspace --output-dir /tmp/helios-round6-after
bash scripts/audit-rust.sh collect --view libraries --output-dir /tmp/helios-round6-after-libs
python3 scripts/audit-report.py compare --baseline /tmp/helios-round6-before/report.json --current /tmp/helios-round6-after/report.json
```

Les destinations étaient neuves. Le comparateur retourne 2. L’archive `reference.tar` conserve `b91130a` avant remplacement. Les copies sont sales au sens Git (liens frontend et documents conservés de référence) : les empreintes Rust, pas une prétention d’arbre propre, attestent le code. Les 478 empreintes avant sont vérifiées contre l’archive ; les 480 empreintes de chacune des deux collectes finales contre le worktree final. Les entrées Cargo sont identiques avant/après. Les collectes restent hors ligne et gelées ; régression et installation frontend/audits ont des interactions réseau identifiées avant exécution.

JSON/LCOV/HTML/métadonnées/provenances : `/tmp/helios-round6-{before,before-libs,after,after-libs}`. Alignement textuel : `/tmp/helios-round6/analyze.py` et `aligned-lines.json`. Tailles, copies et attestations : `/tmp/helios-round6/size-{before,after}.json`, `size-provenance-{before,after}.json`, `sizes-{before,after}`. Ces artefacts sont temporaires et non commités ; leur rétention durable reste une décision ouverte.

Pour les tailles, exécuter avant/après avec `HELIOS_PUBLISHER_KEYRING_PATH=/tmp/helios-round6/keys/publisher-keyring.json` identique, puis copier immédiatement les trois sorties :

```sh
scripts/wsl-cargo build --release --frozen -p helios -p astra -p heliosd --features heliosd/netlink,heliosd/wireguard,heliosd/tpm,heliosd/embed-ui
python3 scripts/binary-size.py --artifacts /tmp/helios-round6/sizes-after --provenance /tmp/helios-round6/size-provenance-after.json --baseline /tmp/helios-round6/size-before.json --output <nouveau-rapport>
```

## Suites prioritaires

COV-006/COV-020/COV-021 restent partielles : succès complet de préparation trust-update et émission via le listener Astra mTLS, autres refus d’identité pendant les awaits, annulation aux autres coupes et concurrence inter-opérations restent à compléter. Le nettoyage des réservations après refus legacy, les coupes post-renommage et les validations cible ne sont pas résolus par ces deux corrections.

Prochains lots utiles : COV-013 pour rollback de négociation v5 après annulation et propriété des générations ; COV-007/COV-008 pour les transactions clientes complètes ; COV-014 pour les états partiels de l’orchestrateur. Préparer en parallèle les cibles Windows/TPM/FIDO. Les estimations historiques de la roadmap ne deviennent pas des garanties de couverture ou une estimation de l’effort restant vers 100 %.

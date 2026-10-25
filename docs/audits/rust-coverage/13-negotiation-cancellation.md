# Négociation v5 : annulation et propriété du slot — cinquième lot

Lot du 25 octobre 2026 sur `feat/local-rust-audit`, référence documentaire `0c6e646`, code final `a43a319`. COV-013 porte sur la connexion QUIC, la restauration du PSK et les générations du slot gateway. Trois agents Luna développent et relisent les tests et la correction ; l’orchestrateur reproduit les défauts, revoit les différences et exécute les contrôles.

## Preuves avant correction

Les incréments de génération dans `protocol.rs` et `transaction.rs` utilisaient une addition non vérifiée. La spécification v5 §11.1 exige une erreur ferme, sans retour à zéro. Les tests injectent la limite `u64` dans l’état runtime après les véritables préparations et confirmations signées ; aucun accès réseau permettant de choisir ce compteur n’est démontré.

- À MAX−1, une préparation était acceptée sans capacité pour la transition terminale.
- À MAX, le rollback et le retrait paniquaient après une écriture backend.
- À MAX, la confirmation paniquait après l’élévation du plancher. Le premier oracle masquait le défaut par un échec de persistance ; le test utilise désormais un chemin temporaire valide et reproduit la panique avant correction.
- Le retrait signé partage le même besoin de prévalidation. Le premier essai s’arrêtait à la panique de retrait et n’atteignait pas ce second appel : ne pas présenter ce chemin comme une reproduction initiale indépendante.

Logs locaux : `/tmp/helios-round7-heliosd-before-confirmed.log` et `/tmp/helios-round7-confirm-before.log`. Les échecs initiaux comprennent aussi un double backend incomplet et deux assertions dépendant de l’ordonnancement ; ils ne sont pas comptés comme défauts de production.

## Scénarios et oracles

Les tests gateway interrompent les tâches après une écriture backend, avant son accusé ; ils vérifient ensuite la propriété du slot, la réservation, le PSK restauré et la période de repos. Une erreur de restauration conserve l’état `preparing` et permet une nouvelle tentative. Un rollback périmé ne touche pas la génération suivante. Le PSK négocié précédent et ses métadonnées sont restaurés lors d’un renouvellement abandonné ; le PSK statique reste une donnée distincte. Un handshake égal ou antérieur à l’observation initiale ne permet pas le commit.

Le double gateway reproduit maintenant la mise à jour du `NetworkConfig` partagé par `orchestrator::install_peer_psk`, et son rétablissement en cas d’erreur. L’échec initial du scénario de renouvellement venait de cette omission du double ; aucun défaut de restauration de production n’en est déduit.

Les tests transport possèdent la tâche réelle `handle_connection` et la joignent après annulation : attente de confirmation, annulation dans `confirm`, rollback interrompu puis repris, livraison du commit impossible après fermeture des deux endpoints. Ils utilisent le mTLS et le framing réels en loopback, avec un handler de test. Ils appellent le traitement privé après acceptation, sans prétendre couvrir les protections Retry et capacité de la boucle publique `serve`. Les sémaphores comptent les démarrages et fins ; les événements portent l’identifiant exact. L’absence de rollback après commit contrôle aussi les références du handler pour détecter une tâche détachée encore en attente.

## Correction et revue

La préparation vérifie sous le verrou transactionnel qu’elle peut réserver une génération et terminer par commit ou rollback avant de réserver le pair ou d’inscrire l’identifiant anti-rejeu. La confirmation vérifie sa capacité avant l’écriture du plancher, puis à nouveau sous le verrou avant de retirer les enregistrements actifs. Les retraits et la restauration vérifient avant l’appel backend. Un rollback épuisé journalise l’erreur et conserve l’état `preparing`, son propriétaire et la réservation ; il ne restaure pas un backend dont l’état ne pourrait plus être représenté.

Les erreurs publiques restent les variantes internes existantes. À MAX−2, préparation puis commit ou rollback peuvent atteindre MAX sans débordement. Les opérations périmées et les no-op statiques restent sans mutation, y compris à MAX. Aucun nouveau verrou ni format persistant n’est introduit. La revue indépendante Luna et la relecture de l’orchestrateur n’ont identifié aucun blocage dans ce diff ; elles ne constituent pas une preuve de sûreté exhaustive.

## Validation exécutée et arrêt réel

| Contrôle | Résultat du lot |
| --- | --- |
| `cargo fmt --check` | Réussi après formatage des nouveaux modules |
| `git diff --check` | Réussi |
| Tests Heliosd ciblés, toutes features | 42 réussis, zéro échec/ignoré ; avant renforcement final de l’oracle statique |
| Tests Aether QUIC, toutes features | 31 réussis, zéro échec/ignoré |
| Tests de la collecte workspace finale | **2 254 réussis, zéro échec/ignoré**, soit 16 tests de plus que le lot 12 ; oracle statique final inclus |
| Collecte globale finalisée | **Non : code 75, budget disque**, statut `partial` |
| Collecte bibliothèques finale | Non lancée après le refus |
| Clippy strict et régression canonique | Non lancés pour cette révision après le refus |
| Mesure release finale des trois binaires | Non lancée après le refus |

Commandes exécutées :

```sh
scripts/wsl-cargo test --frozen -p heliosd --all-features --bin heliosd key_negotiation::tests
scripts/wsl-cargo test --frozen -p heliosd --all-features --bin heliosd confirm_at_max_refuses_before_raising_the_floor_or_committing
scripts/wsl-cargo test --frozen -p aether-key-negotiation --all-features
cargo fmt --check
git diff --check
# Depuis /tmp/helios-round6/reference, copie de mesure conservant le chemin du lot 12 :
GIT_DIR=/home/christophe/helios/.git/worktrees/rust-audit GIT_WORK_TREE=/tmp/helios-round6/reference bash scripts/audit-rust.sh collect --view workspace --output-dir /tmp/helios-round7-after
```

Le contrôle documentaire Python a vérifié les liens locaux des trois documents modifiés, les chemins de COV-013 et les 36 fiches conservant leurs 14 champs obligatoires. `cargo fmt --check` et `git diff --check` ont ensuite été rejoués avec succès, sans compilation.

Les tests ciblés ont utilisé des sockets loopback et des fichiers temporaires. La collecte est gelée/hors ligne. Aucun besoin de privilège noyau n’a été exercé. Le budget affichait 64,8 Gio avant la collecte, **66,9 Gio après les tests et l’export JSON brut** ; le wrapper a alors renvoyé 75 et empêché les exports LCOV/HTML et la finalisation de provenance. Aucune nouvelle compilation, export contournant le pilote, hausse de budget ou suppression de cache n’a été effectué après cet arrêt. L’accord pour `scripts/clean-wsl-targets` a été demandé conformément à `AGENTS.md` ; il est requis avant nettoyage.

Logs : `/tmp/helios-round7-heliosd-fixed.log`, `/tmp/helios-round7-quic-final.log`, `/tmp/helios-round7-coverage.log`. Le JSON brut et les métadonnées sont conservés dans `/tmp/helios-round7-after`, avec `status=partial`. Ils restent diagnostiques ; **aucun nouveau pourcentage de production, gain de lignes ou gap vers 80/100 n’est annoncé**. Les branches et MC/DC ne sont pas instrumentés, comme au lot 12. Les 483 empreintes de sources workspace dans la copie sont vérifiées contre le worktree final et consignées dans `/tmp/helios-round7/source-check.json` ; cette vérification ne transforme pas une collecte partielle en référence.

La dernière baseline complète reste celle du **lot 12**, code `790d559` : production globale **32 761 / 53 155 = 61,63 %**, bibliothèques **24 864 / 34 998 = 71,04 %**. Les 20 394 lignes non couvertes et le gap de 9 763 vers 80 % concernent exclusivement cet ancien périmètre. Ils ne sont pas extrapolés à `a43a319`.

Les dernières tailles complètes restent également historiques : Astra 12 320 520, Helios 13 701 408 et Heliosd 22 639 544 octets. La correction ajoute du code runtime ; **sa variation de taille n’est pas encore mesurée**, même sans dépendance supplémentaire. Les copies des binaires précédents restent dans `/tmp/helios-round7/sizes-before`, hors du cache à nettoyer.

## Reprise après accord de nettoyage

1. Exécuter le script de nettoyage autorisé sans modifier le budget de 65 Gio. Ne pas effacer les sources ni les rapports temporaires de ce lot.
2. Relancer la collecte workspace vers une **nouvelle destination** (par exemple `/tmp/helios-round7-resumed-global`), puis la vue `libraries` vers `/tmp/helios-round7-resumed-libs`. Conserver le dossier partiel initial. Vérifier `completed`, les empreintes sources/entrées et les artefacts ; ne pas modifier HEAD ou les sources pendant chaque collecte.
3. Rejouer `bash scripts/regression.sh`. Cette commande installe les dépendances frontend verrouillées et consulte les audits npm/RustSec ; identifier ces interactions réseau avant exécution. Les sept avertissements RustSec du lot 12 ne sont pas présentés comme un audit actuel.
4. Construire les trois binaires avec le même profil, les mêmes features et le trousseau de test du lot 12, puis produire l’attestation `binary-size.py`. Ne pas relever la limite canonique de 128 Mio.
5. Comparer aux rapports terminés `/tmp/helios-round6-after` et `after-libs`, dont les sources correspondent à `0c6e646` pour Rust. L’archive `/tmp/helios-round7/reference.tar` conserve cette référence. Aligner les lignes existantes avec `/tmp/helios-round7/analyze.py`, adapter la destination finale, recalculer le dénominateur et documenter tout changement de périmètre. Ne pas additionner automatiquement l’estimation initiale de COV-013.

La campagne complète, les tailles et une nouvelle baseline restent des travaux nécessaires avant de revendiquer une validation de régression globale de ce lot.

## Limites et suite

Aucun workflow CI, dépendance Cargo, format filaire ou profil release n’est ajouté. Les campagnes lourdes restent locales. Les doubles ne prouvent pas le comportement du noyau WireGuard, du TPM ou de Windows ; ces recettes nécessitent leurs cibles. La MSRV 1.95 doit être vérifiée sur une machine qui possède cette toolchain. L’objectif reste le maximum de couverture utile, avec 100 % comme cible et 80 % comme jalon.

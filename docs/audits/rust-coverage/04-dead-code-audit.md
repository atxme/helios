# Audit du code mort

## Méthode et limites de preuve

Lecture des points d’entrée `lib.rs`/`main.rs`, manifestes, `cfg`, attributs de lint, déclarations et appels ; recherche par `rg` dans le dépôt ; `cargo-machete` 0.9.2 exécuté sans `--fix` sur `crates tools apps/orion/src-tauri`. Aucune dépendance inutilisée signalée (code retour 0). Ce résultat est un indice favorable, sans preuve d’exhaustivité face aux macros, features, build scripts et plateformes. L’analyse Clippy et ses limites sont consignées dans [la baseline](02-coverage-baseline.md).

Les catégories demandées sont : **A** mort confirmé dans les configurations supportées ; **B** probablement obsolète, validation nécessaire ; **C** non exécuté dans la mesure mais potentiellement utilisé ; **D** nécessaire avec test d’environnement. Une API publique sans référence locale n’est pas classée A. Un compteur d’exécution nul n’établit pas l’inaccessibilité. Aucun retrait n’a été effectué.

## Inventaire étayé

| Catégorie | Élément et localisation | Preuves et confiance | Recommandation |
|---|---|---|---|
| A | `probe_captive_portal`, `crates/heliosd/src/orchestrator/probes.rs:9` | Fonction privée, aucune référence hors de sa définition ; `#[allow(dead_code)]` existant. Le commentaire parle d’un raccordement futur. Recherche des trois noms dans le dépôt : seules définition et arêtes internes ci-dessous. Confiance élevée pour l’absence d’appel runtime actuel. | COV-031 : décider suppression du sous-graphe ou mission fonctionnelle distincte de raccordement. Ne pas l’exécuter contre Internet pour gagner des lignes. |
| A | `tcp_http_probe`, même fichier `:28` | Son seul appel est dans la sonde précédente (`:12`), dont aucun point d’entrée ne dépend. Confiance élevée. | Même décision atomique ; elle contacte actuellement `connectivitycheck.gstatic.com:80`. Aucun tel appel lancé dans l’audit. |
| A | `get_default_gateway`, même fichier `:41` | Appelé uniquement par `probe_captive_portal` (`:21`), sous-graphe sans racine ; commande `ip route`. Confiance élevée. | Supprimer seulement après validation de COV-031 et clarification du statut du portail captif. |
| B | Commentaire de raccordement futur dans `orchestrator/probes.rs:5` | Le backend réel est déjà présent dans `helios-wireguard/src/kernel.rs`, alors que ces sondes restent sans appel. Le commentaire ne décrit plus un jalon vérifiable. Confiance élevée sur le décalage, moyenne sur l’intention produit. | Documenter la limitation dans son module et la documentation de fonctionnalité ; ne pas conclure que tout le portail captif est mort. |
| B | Description de protocole dans `docs/testing/TESTING.md:49` et `:234` ; doc-comments `crates/orion-core/src/identity_store.rs:4` | Anciennes mentions ML-DSA-65/trois modes ; v5 courant utilise ML-DSA-87 et refuse Classic. Ces textes ne prouvent aucune ancienne implémentation active. | COV-032 : aligner les passages descriptifs avec les amendements acceptés, préserver ML-DSA-65 des releases. Aucun changement de protocole. |
| C | Commandes `astra-signer`, notamment `tools/astra-signer/src/commands/vault.rs:1`, `ca_tls_rotation.rs:1`, `ca_pq_rotation.rs:1` | Nombreux corps à zéro dans la mesure, mais raccordés à la CLI via `commands/mod.rs` et `main.rs`. Les tests de `astra-operator` ne lancent pas nécessairement la façade CLI. Confiance élevée. | COV-016 : tests de processus et assertions de sorties/effets, puis cérémonie cible. Aucune suppression. |
| C | `crates/astra/src/daemon.rs:1`, `crates/heliosd/src/daemon.rs:1` | Corps de démarrage non exercés dans la baseline ; fonctions appelées par `main.rs`. Un test de bibliothèque ne lance pas un démon. | COV-018 : tests de sous-processus bornés, arrêt propre et refus de démarrage. |
| C | Features `netlink`, `tpm`, `wireguard`, `embed-ui`, `certificate-signing` | Propagées par les manifestes ; les trois premières sélectionnent de vrais backends. La feature `aether/fuzzing` est utilisée par `fuzz/Cargo.toml`. Aucune feature déclarée morte démontrée. | Maintenir matrice minimale/toutes features et OS, pas de retrait sur la base d’une mesure hôte. |
| D | `crates/helios-tpm/src/tpm_real.rs:1` | 0 ligne exécutée dans la baseline malgré compilation ; tests `materiel.rs:51` quittent sans effet si activation absente. Backend raccordé par feature. | COV-011 : TCTI logiciel explicite puis TPM cible, avec preuve de l’activation du scénario. |
| D | `apps/orion/src-tauri/src/tray.rs:33`, `commands/connection.rs:20` | `allow(dead_code)` conditionnel hors Windows ; usage depuis le menu Windows. | Tests Windows, conserver les corps. |
| D | `crates/aether-fido/src/authenticator/webauthn.rs:657`, champ `CredentialList.identifiers` | Buffers possédés pour garder valides les pointeurs `WEBAUTHN_CREDENTIAL_EX.pbId` ; leur durée de vie constitue leur usage. | Ne pas retirer un propriétaire FFI parce qu’aucune lecture explicite n’existe. Tester marshalling et cérémonie native. |
| D | `crates/orion-core/src/vault/windows/{dpapi.rs:24,tpm.rs:98,prompt.rs:143}`, `backend/wireguard.rs:341` | Types/parsers requis par Win32 ou Linux opposé ; `cfg` et conservation des pointeurs expliquent les lints conditionnels. | COV-010/COV-023 : Windows natif et recette réelle. |
| C | DTO `SignerRequestAnswer.credential_registry`, `crates/astra-operator/src/origin.rs:440` | Champ désérialisé, conservé pour le contrat ; absence de lecture dans un consommateur ne rend pas le format inutilisé. | Vérifier le contrat de validation par consommateur avant tout retrait de champ. |

La classe A porte sur **trois fonctions privées**, pas trois fonctionnalités complètes. Les fonctions MTU qui suivent dans le même fichier ont des appelants et restent utiles. Leur présence interdit de supprimer le fichier entier.

## Faux positifs explicitement écartés

Les fixtures sous `astra-operator/tests/support`, les champs de tests `aether/src/secret.rs:182` et `helios-api/src/certificates/tests.rs:24`, les imports pour liens de documentation dans `orion-core/src/certificate_renewal.rs:53` et `profile_import.rs:9` ne sont pas du code de production mort. Aucun nouvel attribut de masquage n’est proposé.

`NetworkConfig::save*` délègue à `aether::private_file` avec une politique de projection : ce ne sont pas deux stockages concurrents. Les variantes d’enum sérialisées représentent aussi des entrées possibles depuis les fichiers ou le réseau ; l’absence de construction directe ne suffit pas à les retirer. Les mécanismes de build Orion/sidecar et les traits de backend exigent de compter les arêtes indirectes.

## Complétude de l’audit

Aucune dépendance, variante d’enum publique, champ FFI, ancienne interface publique ou feature n’a été démontrée supprimable. Aucun fichier Rust orphelin certain établi ; l’inventaire Cargo n’est pas à lui seul un graphe exhaustif des modules/macros. Les scripts de campagnes, déploiement, bootstrap et packaging ont des usages documentés ou des références dans les autres scripts/CI ; aucun script historique supprimable avec preuve suffisante n’a été établi.

Le retrait des sondes ne compte pas comme gain de lignes couvertes : une réduction du dénominateur devra apparaître séparément dans le suivi. Leur coût exact en lignes instrumentées figure dans la baseline par fichier ; une mesure de suppression ne peut être faite sans l’implémenter, ce qui reste interdit avant validation.

Commandes de recherche exécutées :

```sh
rg -n 'probe_captive_portal|tcp_http_probe|get_default_gateway' --glob '!metadata.json' --glob '!Cargo.lock' .
rg -n 'cfg\(.*coverage|coverage\(off\)|allow\(dead_code\)|allow\(unused' crates tools apps/orion/src-tauri -g '*.rs'
cargo machete --version
cargo machete --skip-target-dir crates tools apps/orion/src-tauri
```

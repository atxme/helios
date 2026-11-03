# Audit des duplications

Inventaire initial figé au 23 octobre 2026 ; les mises à jour explicites suivent les lots. F14 a depuis partagé draft/profil v5 et gateway-admin dans Core ; voir les comparaisons actuelles du [journal 16](16-f14-integration.md). Ne pas traiter les anciens emplacements déplacés comme des copies encore présentes.

## Détection et portée

Recherche de blocs de 12 lignes non vides, après retrait des commentaires de ligne et attributs, avec au moins 220 caractères, puis lecture des candidats et des appelants. Le balayage intégral des **472 fichiers Rust** de `crates`, `tools` et `apps/orion/src-tauri` (tests inclus, sans arrêter la lecture au premier module de test) a produit **36 groupes de fichiers candidats** ; ce n’est ni un taux de duplication ni 36 défauts. Les groupes sont dédupliqués par ensemble de chemins partageant au moins un bloc. Les fixtures et initialisations de structures contribuent fortement aux faux positifs. Cette normalisation détecte les similitudes de structure, sans prouver l’équivalence sémantique. Elle ne traite pas les macros comme un parseur Rust.

Les comportements ci-dessous ont ensuite été comparés directement. Les lignes sont des points d’entrée ; les différences intentionnelles constituent des contraintes de toute extraction. Aucune factorisation réalisée.

## Duplications retenues pour décision

| Élément | Emplacements | Nature | Gravité | Confiance | Action |
|---|---|---|---|---|---|
| Encodage UDP et contrôle TCP du speedtest | `crates/orion-core/src/speedtest/wire.rs:20`, `:38`, `:55` ; `crates/helios-api/src/speedtest.rs:478`, `:498`, `:514` | Exacte après renommage `frame`/`packet` pour UDP ; TCP encode/décode identiques | Moyenne | Élevée | COV-030 : factoriser dans `aether::speedtest` avec vecteurs binaires et bornes de buffers. |
| Fenêtre de rotation CA-TLS et validité | `crates/astra-operator/src/orion.rs:106` ; `tools/astra-signer/src/commands/ca_tls_rotation.rs:73` | Exacte pour multiplication contrôlée jours→secondes et additions | Moyenne | Élevée | COV-029 : extraire petit calcul pur dans `astra-operator`, conserver cérémonies et affichages propres. |
| Préfixe de transaction et temps Unix | `crates/orion-core/src/key_negotiation.rs:648`, `:656` ; `crates/heliosd/src/key_negotiation/mod.rs:113`, `:121` | Exacte | Faible | Élevée | Conserver en première intention ; helper partagé seulement si une évolution montre un risque concret. |
| Vérification version/format PKI | `crates/aether/src/certificates/client/grant.rs:353`, `client/request.rs:81`, `client/stage.rs:132`, `client/commit.rs:110`, `transport.rs:448` | Exacte pour quelques gardes et erreurs | Faible | Élevée | Conserver gardes visibles, ou petit helper aether après tests de conformité ; aucune fusion de transcripts. |
| Vérification d’identité gateway servie | `crates/astra/src/renewal/stage.rs:219` ; `crates/astra/src/recovery.rs:445` | Sémantique : relire feuille et recomparer empreinte calculée | Élevée si divergence future | Élevée | Étudier helper de lecture/vérification sur le canal existant ; maintenir erreurs et preuves propres aux deux workflows. |
| Construction du commit client | `crates/orion-core/src/certificate_recovery.rs:471` ; `certificate_renewal/exchange.rs:544` | Exacte pour les champs recopiés du grant, puis signatures | Élevée | Élevée | Étudier constructeur canonique dans `aether` après COV-005/007 ; ne pas mutualiser les conditions d’autorisation. |
| Écritures atomiques privées | `crates/aether/src/private_file.rs:58` ; `crates/helios-tpm/src/blob_store.rs:112` | Sémantique | Élevée | Élevée | COV-028 : comparer contrat de durabilité, remplacement et permissions avant adoption du helper existant. |
| Écritures de documents et métadonnées | `crates/helios-update/src/lib.rs:561` ; `crates/heliosd/src/gateway_rotation.rs:699` ; `gateway_key.rs:283` | Sémantique mais garanties différentes | Élevée | Élevée sur différence, impact à instruire | COV-028 : examiner les chemins et contenu ; ne pas réduire au remplacement mécanique de fonctions. |
| Authentification du sidecar local | `apps/orion/src-tauri/src/operator.rs:251` ; `src/astra.rs:258` | Sémantique ; accept loopback et token | Élevée | Élevée | Conserver protocoles typés : helper opérateur vérifie aussi version + session_id ; compagnon CA-TLS a une autre enveloppe. Partager seulement plomberie bornée après tests. |
| Clients HTTP protégés | `orion-core/src/certificate_renewal/exchange.rs:309`, `certificate_recovery.rs:284`, `trust_update.rs:160`, `provisioning.rs:154` ; `astra-operator/src/{origin.rs:37,tunnel.rs:47}` | Sémantique | Moyenne | Élevée | Maintenir choix de canal et budget explicites ; étudier lecture bornée commune par contrat, pas client HTTP universel. |
| Vues réseau API/CLI | `crates/helios-api/src/routes/network.rs:50` ; `tools/helios/src/api.rs:36` | Structures presque identiques | Moyenne | Élevée | Étudier contrat de lecture partagé dans `aether` uniquement si projection sans secrets et compatibilité explicites ; éviter dépendance CLI→API. |
| Fixtures TrustState | `orion-core/src/test_domain.rs:218`, `orion-core/src/certificates/tests.rs:231`, `heliosd/src/certificates/tests.rs:102` | Exacte pour groupes de champs | Faible | Élevée | Garder fixtures locales si elles expriment leur scénario ; réutiliser `test_domain` dans orion-core quand approprié, sans déplacer des secrets de fixture en production. |

## Comparaison précise des écritures

`aether::private_file::write_private_atomic` utilise un nom temporaire aléatoire, `create_new`, permissions privées avant écriture, synchronisation fichier puis remplacement et synchronisation du parent ; il traite aussi les liens symboliques et la différence Windows. Le blob TPM reprend plusieurs de ces garanties avec erreurs `TpmError`.

`helios-update::write_json_atomic` emploie un `.tmp` fixe, `create/truncate`, synchronisation puis rename et synchronisation parent. `heliosd::gateway_rotation::write_document` et `gateway_key::write_atomic` emploient write + rename sur `.tmp` fixe sans toutes les mêmes garanties. Ce constat ne démontre pas à lui seul une exploitation : le dossier, ses permissions, le propriétaire, le contenu et la concurrence doivent être vérifiés. La revue doit préserver les contrats « écrit avant adoption » et les transitions irréversibles TPM. Un fichier public et un secret ne sont pas interchangeables.

La bonne cible est un mécanisme existant, avec options/erreurs à la couche propriétaire si nécessaire. Pas de nouveau format de stockage ni deuxième journal générique.

## Duplications à conserver

Le renouvellement ordinaire passe dans le tunnel d’un client vivant et utilise l’émetteur délégué dans son périmètre. La récupération expirée passe par Astra public, preuve historique, approbation opérateur et signature maîtresse ; le commit est relayé. `verify`, `verify_for_gateway` et `verify_for_recovery` partagent déjà `verify_common` mais imposent des preuves locales différentes (`aether/.../client/grant.rs:107`, `:185`, `:281`, `:338`). Les fusionner risquerait de transformer une vérification de signature de relais en autorisation d’installation.

La signature hybride de release ML-DSA-65/Ed25519 et la PKI de négociation ML-DSA-87 sont deux domaines distincts. Les identités Orion DPAPI et gateway TPM ont des propriétaires, clés de contexte et menaces distincts. Les DTO peuvent rester séparés lorsqu’ils protègent la frontière client/serveur ; un partage de type ne doit pas imposer une dépendance vers une application gateway.

Chaque extraction future doit avoir des tests comparant **avant/après pour les cas légaux et les refus**, un examen des dépendances et une mesure du diff. La baisse de taille n’est pas un gain de couverture. Les factorisations viennent après les scénarios protecteurs, sauf le petit point d’injection strictement nécessaire à un test.

## Factorisation vérifiée pendant le troisième lot

| Élément | Emplacements | Nature | Gravité | Confiance | Action |
|---|---|---|---|---|---|
| Mutation durable d’une opération | `crates/astra/src/operations.rs::OperationStore::update_persisted`, `crates/astra/src/renewal/companion.rs`, `crates/astra/src/renewal/stage.rs` | Exacte : copie, mutation, publication pour sérialisation, rollback | Moyenne, invariant de persistance sensible | Élevée | Factorisé au lot 11 : quatre appels internes, validation structurelle et identité immuable, aucune fusion de protocoles |

La factorisation suit les reproductions et leurs oracles de rechargement, pas seulement une ressemblance textuelle. Elle ne généralise pas le writer ni ne promet le rollback disque après une erreur de synchronisation post-renommage. Résultats et limites dans le [journal 11](11-companion-journal.md).

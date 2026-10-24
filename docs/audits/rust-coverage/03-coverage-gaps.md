# Écarts de couverture et chemins critiques

Les tableaux et références de lignes ci-dessous décrivent l’audit initial. Les changements et métriques du développement sont suivis dans le [journal 09](09-implementation-progress.md) ; les lectures HTTP non bornées décrites historiquement ont été corrigées dans COV-009.

## Lecture des résultats

Les constats quantitatifs viennent du premier profil global réussi. « Fonction sans compteur positif » signifie qu’aucune entrée de fonction LLVM attribuée à sa plage source n’a un compteur positif dans **cette campagne** ; cela n’établit ni absence de test dans tout contexte ni code mort. Les closures/instanciations sont regroupées pour ce diagnostic, sans remplacer le résumé officiel. Les méthodes déclarées sans corps dans les traits n’ont pas de compteur et sont marquées `sans donnée`, jamais déclarées mortes.

La priorité combine **lignes non couvertes absolues**, exposition, invariants et coût ; les gains futurs seront mesurés après implementation validée. Les tests nommés ci-dessous existent déjà et évitent de proposer une nouvelle suite qui répéterait les mêmes assertions. Les compteurs hors tests sont reconstitués selon la méthode de [baseline](02-coverage-baseline.md).

## Priorité par contribution absolue

| Fichier | Production couvertes/total | Non couvertes | Criticité / coût | Orientation |
|---|---:|---:|---|---|
| `crates/helios-tpm/src/tpm_real.rs` | 0/527 | 527 | critique / élevé, environnement ou cérémonie | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/astra/src/service.rs` | 73/593 | 520 | critique / élevé, séquence async/persistance | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `apps/orion/src-tauri/src/commands/certificates.rs` | 0/487 | 487 | critique / élevé, commandes/GUI | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/astra-signer/src/commands/gateway_identity.rs` | 7/482 | 475 | critique / élevé, environnement ou cérémonie | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/astra-operator/src/orion.rs` | 17/436 | 419 | critique / élevé, environnement ou cérémonie | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/helios/src/firmware.rs` | 232/646 | 414 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/astra/src/recovery.rs` | 37/408 | 371 | critique / élevé, séquence async/persistance | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/aether-fido/src/authenticator.rs` | 83/445 | 362 | critique / élevé, environnement ou cérémonie | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/astra-signer/src/commands/vault.rs` | 0/335 | 335 | critique / élevé, environnement ou cérémonie | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/orion-core/src/certificate_renewal/exchange.rs` | 186/520 | 334 | critique / élevé, séquence async/persistance | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `apps/orion/src-tauri/src/commands/profiles.rs` | 79/406 | 327 | critique / élevé, commandes/GUI | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/helios/src/campaign.rs` | 81/408 | 327 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/heliosd/src/key_negotiation/identity.rs` | 103/429 | 326 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/heliosd/src/commands/trust.rs` | 14/336 | 322 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/helios/src/main.rs` | 68/372 | 304 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/xtask/src/main.rs` | 51/330 | 279 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/orion-core/src/certificate_recovery.rs` | 84/357 | 273 | critique / élevé, séquence async/persistance | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/heliosd/src/orchestrator/mod.rs` | 36/304 | 268 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/astra-signer/src/commands/ca_pq_rotation.rs` | 0/265 | 265 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/helios-api/src/speedtest.rs` | 240/501 | 261 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/astra-signer/src/main.rs` | 0/256 | 256 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/helios-astra-helper/src/main.rs` | 47/293 | 246 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `apps/orion/src-tauri/src/main.rs` | 20/260 | 240 | critique / élevé, commandes/GUI | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/helios/src/inspect.rs` | 630/864 | 234 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/heliosd/src/gateway_rotation.rs` | 148/381 | 233 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/astra-signer/src/commands/ca_tls_rotation.rs` | 0/232 | 232 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/helios/src/interactive.rs` | 88/319 | 231 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/astra/src/daemon.rs` | 0/227 | 227 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `apps/orion/src-tauri/src/operator.rs` | 31/241 | 210 | critique / élevé, commandes/GUI | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/heliosd/src/daemon.rs` | 0/204 | 204 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/helios/src/enroll.rs` | 60/263 | 203 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/orion-core/src/backend/negotiation.rs` | 71/270 | 199 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/astra-signer/src/commands/issuer.rs` | 0/199 | 199 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `tools/astra-signer/src/commands/campaign.rs` | 0/189 | 189 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |
| `crates/astra/src/commands/chain.rs` | 0/185 | 185 | critique / moyen | scénario avec oracle d’état/effets, voir tâches par propriétaire |

## Modules demandés : responsabilités, preuves et scénarios

### 1. Grant client — `aether/src/certificates/client/grant.rs`

Responsabilité : encoder/signer indirectement le grant et lier la décision à la requête, au reçu gateway, aux clés candidates, aux ancres TLS/PQ, à l’émetteur et à la fenêtre. `verify`, `verify_for_gateway` et `verify_for_recovery` ont des preuves locales différentes ; `verify_signed_by` est explicitement une vérification de signature de **relais seulement**.

Fait mesuré : `verify_for_recovery` et `verify_signed_by` n’ont pas de compteur positif ; les autres fonctions ont des hits, sans que tous leurs refus soient couverts. `client/tests.rs` teste demandes, possession/continuité, autorisations, émetteur délégué, durée et commit ; `orion-core/.../tests/gateway_exchange.rs:79` valide un grant puis stage/commit logique ; `helios-provisioning/.../tests/staging.rs:218` vérifie le commit avec grant.

À ajouter (COV-003, coût moyen, portable) : matrice de mutations d’un **grant valide** pour version, domaine, CA/époques, clé gateway/client, raison, campagne, preuve d’approbation, reçu, deadline, CSR et clé PQ. Tester signature valide sous mauvais issuer, reçu signé par autre gateway, paire TLS/PQ de générations mixtes et ancre/intermédiaire inattendu. Cas récupération complète et refus d’un émetteur délégué là où la clé maîtresse est exigée. Vérifier erreurs typées et aucun stage avant validation. Risque de sécurité élevé : confusion de rôle entre relais et installateur.

### 2. Ledger — `aether/src/certificates/state/ledger.rs`

Responsabilité : révocations programmées, tombstones, compteurs de statut par cible et empreinte de base complète. **Toutes les fonctions ont des hits** dans la mesure ; classer le fichier comme « jamais testé » serait faux. `state/tests.rs:1083`, `:1116`, `:1155` couvre déjà saturation, expiration et remplacement du tombstone ; `:1283` épingle l’empreinte de base.

COV-003 complète les branches de saturation de révocations/statuts, expiration exactement à la borne, cible jamais détenue, échéance signée discordante, remplacement plus ancien/égal, prune, ordre par nouvelle génération et mutation de chaque champ pertinent du snapshot. Tester aussi l’atomicité observée par le propriétaire lorsqu’`apply_due` échoue au milieu de plusieurs décisions : la méthode mutante ne doit pas être supposée transactionnelle sans examiner la copie candidate du magasin appelant. Portable, faible à moyen coût, peu de lignes restantes mais invariant critique de non-réinstallation.

### 3. Récupération Astra — `astra/src/recovery.rs`

Responsabilité : `open → authorize → grant → commit`, stockage borné temporaire et réconciliation durable avec gateway. Les trois tests locaux `:809`, `:826`, `:842` vérifient capacité/expiration du **store** ; ils n’exécutent pas les fonctions async d’orchestration. Le profil confirme zéro compteur pour les étapes async, leurs refus et les vues importantes.

COV-005 (élevé, canal loopback et registres temporaires) : pair inconnu/révoqué, transcription depuis gateway d’un pair jamais renouvelé, ancre d’admission historique, challenge consommé même si preuve refusée, expirations, mauvaise autorité/raison, preuves opérateur désaccordées, reçu et identité servie incohérents, coupure entre stage et sauvegarde, intent de réconciliation écrit avant commit, gateway absente, génération déjà promue, reprise après crash et deux opérations concurrentes. Les signatures restent réelles ; la cérémonie FIDO se teste séparément.

**Risque à reproduire, pas défaut démontré par exécution** : `commit` (`:588`) exige l’état `Granted` puis passe à `Committed`, tandis qu’Orion traite aussi `Committed` comme état conduisant à installation/recommit (`certificate_recovery.rs:354`). Perdre la réponse HTTP après commit distant peut donc rendre la reprise délicate. Reproduire cette coupure et exiger récupération idempotente du même résultat sans nouvelle autorisation ; ne pas changer les garanties pour rendre le test vert.

### 4. Renouvellement Astra — `astra/src/renewal/`

Responsabilité : transcription du pair, politique de renouvellement/campagne, persistance d’opération, stage gateway et délivrance du grant, capacités du compagnon. `tests.rs` contient cinq tests de planification/fenêtre ; les tests de `issuer` et `operations` couvrent ces composants séparément. Les fichiers `request.rs`, `stage.rs`, `companion.rs`, `router.rs` ont zéro ligne de production exécutée dans la collecte globale. Leurs tests voisins ne prouvent pas le raccordement.

COV-006 : vrai cycle sur canal privé contrôlé et fichiers temporaires ; renouvellement ordinaire automatique sans clé maître ; campagne exacte pour demande manuelle ; refus avant seuil, émetteur absent/expiré, request d’un autre pair, stage expiré, opération rejouée identique/divergente, challenge rafraîchi, token scope/sujet/fenêtre erronés et aucune réutilisation d’ID dans autre magasin. Couper après persistance du grant et avant `mark_granted`, puis relire : `reconcile_released_grant` doit réparer uniquement le même `stage_id`. Concurrence et ordre de mutex par barrières, arrêt forcé borné. Coût élevé, gain important.

### 5. Service public Astra — `astra/src/service.rs`

Responsabilité : exposition HTTP publique, budget source/pair, erreurs grossières, statut/challenges et opérations opérateur/récupération. `service/tests.rs` a neuf tests sur budget, refus, bearer et path ID. Le routeur et ses handlers ont des compteurs nuls ; tester la fonction `bearer` ne prouve pas les routes.

COV-004 : routeur avec `ConnectInfo`, toutes méthodes/chemins autorisés, ID inconnu et ID ordinary-renewal indiscernables publiquement, token absent/expiré/d’autre scope, body trop gros et malformé, statut challenge sans révélation d’inventaire, limites source IPv4/mapped/IPv6, `501` prévu pour ouverture publique de campagne, en-tête d’auth seul pour capability et aucune fuite dans le corps d’erreur. Réutiliser pattern routeur `helios-api` ou vrai loopback ; ajout dev-dep éventuel à justifier. Aucun matériel requis pour le routage ; coût moyen à élevé.

### 6. Registre gateway — `helios-provisioning/src/certificates/`

Responsabilité : admission canonique, stage durable, reçu, commit, purge, promotion/révocation, ancres/issuer, distribution chunkée et migration de fichier. Couverture déjà forte ; il existe de vrais tests de persistance et d’erreur d’écriture. `tests/persistence.rs:43` recharge plusieurs points de coupure ; `tests/staging.rs:272` vérifie l’échec d’écriture ; `:383` commit tardif ; `:627` révocation dominante ; suites transitions/trust/distribution complètent les chemins.

COV-020 complète les écarts précis après lecture des lignes restantes : borne et corruption/migration du registre, publication/abort/génération concurrente, conflit d’empreinte inter-pairs, purge+commit à même instant, reload après refus, file manquant vs domaine non initialisé, distribution remplacée/expirée et écritures refusées. Assertions sur mémoire **et** rechargement, pas seulement `is_err`. Portable ; difficulté moyenne. Les gains déjà couverts par les tests cités ne sont pas recomptés.

### 7. Récupération Orion — `orion-core/src/certificate_recovery.rs`

Responsabilité : préparer la preuve historique et les nouvelles clés, ouvrir/poller Astra, vérifier le grant, sceller/stager, commit relayé et promotion. Les cinq tests synchrones `:699`, `:727`, `:750`, `:817`, `:883` couvrent request/bindings/vue et preuve manquante. Le profil confirme zéro compteur de `begin`, `resume`, `install` et des helpers HTTP. Ce n’est pas un fichier sans tests, mais son workflow central n’est pas exercé.

COV-008 : serveur loopback, grant réel, clé historique correcte/incorrecte, réponse portant autre requête/état/ID, statuts et JSON incorrects, deadline, réponse tronquée/surdimensionnée, perte de réponse commit, redémarrage après commit local avant promotion, échec du magasin candidat et promotion répétée. `begin/install` ouvrent magasin/chemin global concret ; prévoir test Windows ou point d’injection **interne** minimal. Ne pas activer un magasin plaintext sous Linux. Reproduire explicitement le risque de reprise mentionné côté Astra et vérifier qu’un commit rejoué garde les octets/fingerprint appropriés. Coût élevé ; Linux prouve séquence pure, Windows prouve scellement.

### 8. Renouvellement et promotion Orion — `orion-core/src/certificate_renewal/`

Responsabilité : requête active, adoption de vue, échange HTTP, grant/commit, protection des candidats et promotion/rollback local. Les suites existantes couvrent CSR signée, mauvais actif, grant visant autre clé, candidate bundle et chaîne intermédiaire, seeding/scoping du TrustStore, migration et registre opérateur. `gateway_exchange.rs:79` n’exécute pas pour autant tout le protocole HTTP/DPAPI : `open/advance/commit` et les promotions concrètes ont zéro compteur global.

COV-007/COV-010 : séquence complète avec stage et promotion sous un nom `-next`, jamais au-dessus de l’actif avant activation ; coupure à chaque écriture/commit ; mêmes octets au rejeu ; retrait précédent à `not_after` ; identité scellée discordante ; choix de rollback sans baisse de compteur ; reconnexion après activation hors tunnel. Les primitives DPAPI ont déjà trois tests Windows `identity_store/tests.rs:300`, `:318`, `:357`; compléter leur **enchaînement**, pas réécrire leur round-trip. `decode_typed` (`exchange.rs:784`) vérifie Content-Length et taille après `bytes()` : sans longueur déclarée, le contrôle arrive après la lecture entière. Tester les corps chunkés au-delà de la borne. Coût élevé.

### 9. Négociation client — `orion-core/src/key_negotiation.rs`

Responsabilité : choix d’endpoint et identité protégée, échange QUIC authentifié, dérivation et confirmation, renouvellement in-tunnel et release HTTP. **Le chemin `prepare/confirm` a des hits**, via `heliosd/src/key_negotiation/tests/interop.rs:94`, `:99`, `:108` qui font dériver le même PSK à Orion et à la gateway en IPv4/IPv6. Les tests locaux de `key_negotiation/tests.rs` couvrent aussi release 204, refus du 200 SPA, redirection/proxy et adresses.

Restent sans compteur : chargement d’identité protégée, `prepare_renewal_for_profile`, entrée publique `release_for_profile` et certains accès de session. COV-013/COV-023 : résolution refusée/failover borné, mauvais cert/issuer, réponse v5 malformée, timeout, annulation après installation candidat, handshake ancien et acteur périmé ; release uniquement via adresse littérale du tunnel, attribution correcte aux deux générations et identité choisie après promotion. Réutiliser les tests transaction existants `heliosd/.../tests/transaction.rs:258`, `:365`, `:479`, `:579` avant d’ajouter des cas. Pas de preuve de vivacité tirée de QUIC ni de réintroduction Classic/v4. Coût moyen/élevé ; vraie pose PSK = deux hôtes.

### 10. Distribution de confiance — `orion-core/src/trust_update.rs`

Responsabilité : authentifier l’état connu, collecter les fragments et appliquer une seule transaction vérifiée au TrustStore courant. Neuf tests purs couvrent manifeste manquant/changé, base différente, fragments répétés et absence d’application avant complétude ; un test HTTP (`:779`) vérifie refus relayé et absence de fallback. `run/poll/accept` ont des hits ; `refresh`, qui ouvre magasin/identité et promeut, n’en a pas.

**Constat source vérifié** : `poll` (`:206`) appelle `response.bytes()` puis JSON sans appliquer la borne `MAX_TRUST_UPDATE_RESPONSE_BYTES=64 KiB` de `aether/certificates/transport.rs:60`. Le DTO réponse (`:322`) n’a pas `deny_unknown_fields` et ses deux champs ont des défauts : décider la conformité stricte au contrat, sans prétendre à une faille d’authentification démontrée. Le client recovery a aussi une lecture intégrale non bornée (`:578`). Le client renewal limite après lecture mais ne protège pas la lecture chunkée elle-même.

COV-009 (P0, coût moyen) : corps de borne−1/borne/borne+1 avec Content-Length **et sans**, flux sans fin borné par timeout et octets, inconnu/malformé, vrais fragments signés valides puis application atomique rechargée, transaction jamais finie après `MAX_POLLS` et déplacement local de base entre polls. La première tâche est de fixer/tester le contrat de lecture bornée, sans nouvelle couche de transport universelle. La refonte nécessaire sera soumise au plan ; aucun correctif implémenté pendant l’audit.

## Autres familles insuffisamment exercées

| Famille | Constat vérifié | Scénarios utiles | Infrastructure / tâche |
|---|---|---|---|
| TPM réel | `tpm_real.rs` à zéro ; 6 tests matériels compilés mais activation conditionnelle | unseal altéré, PCR discordant, fenêtre NV one-shot, redémarrage contrôlé | logiciel TCTI puis matériel ; COV-011 |
| FIDO et outils opérateur | `authenticator.rs` peu exercé ; signer 0,44 % production, commandes raccordées | absence/retrait clé, credential/RP erroné, deux clés identiques, annulation, preuve et vault altérés | fixtures protocole puis clés physiques ; COV-016/026 |
| Identité/rotation gateway | candidats scellés et écriture publique partiellement couverts ; orchestration pas équivalente à composition pure | manque candidat, mauvais contexte/époque, coupe après promotion registre avant fichiers, restart choisissant bonne feuille | fichiers isolés puis TPM/cible ; COV-019 |
| Orchestration/reload | `orchestrator/mod.rs` peu exercé, tests de logique présents | arrêt pendant probe, erreur backend, reload conservant PSK/secret runtime, échec filtre/NAT, multi-uplink | doubles existants puis namespace ; COV-014 |
| API/canal privé | suites routeurs/ALPN/mTLS déjà présentes, branches d’erreurs restantes | admin pair/UID/interface, JSON/headers, taille réponse, reboot endpoint, TLS1.2/reprise/0-RTT refusés | routeur et TLS loopback, UID/veth cible ; COV-021 |
| CLI/démons/installateurs | nombreuses fonctions main/commandes à zéro malgré tests lib | erreurs config, fichier/argument/pin manquants, lancement borné, arrêt sans tâches pendantes, rollback échoué sans boucle | sous-processus temporaires, VM pour effets ; COV-017/018/024/025 |
| Shell Tauri | commandes certificats/connexion à zéro ; tests de payload séparés | import→seal→nom seul→connexion, suppression tunnel-first, session du sidecar et vue lifecycle | commandes isolées/Windows ; COV-022 |
| Backends Orion | hooks protected store, négociation/renouvellement et timers partiellement couverts | timer annulé à déconnexion, retry borné, ancien acteur, rollback puis reconnect | doubles existants/temps contrôlé ; COV-023 |

## Inventaire fonctionnel des modules prioritaires

Inventaire des fonctions avec corps repérées dans l’AST, hors tests/fixtures. `hits` n’implique pas couverture de toutes les branches ; `zéro` signifie zéro compteur positif dans cette campagne. Les numéros ci-dessous pointent la déclaration `fn`, après les commentaires/attributs. Les bornes et lignes sans hit peuvent être recoupées dans le HTML local et le LCOV. Les fonctions privées ne sont pas omises.

### `crates/aether/src/certificates/client/grant.rs`

LLVM brut : 262/417 (62.83 %) ; production DA : 260/414, **154 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `signing_bytes` | 44 | hits |
| `fingerprint` | 77 | hits |
| `candidate` | 83 | hits |
| `verify` | 107 | hits |
| `verify_for_recovery` | 185 | **zéro** |
| `verify_signed_by` | 263 | **zéro** |
| `verify_for_gateway` | 281 | hits |
| `verify_common` | 338 | hits |
| `resolve_issuer` | 520 | hits |

Lignes de production sans hit (DA) : 136, 148, 153–155, 162, 185–224, 226–234, 236–241, 243–244, 246–247, 263–269, 315, 318–320, 326, 354–357, 360–363, 366, 369, 372, 375, 383, 387–389, 391–397, 400–402, 404, 406–408, 411, 414–416, 424, 437, 449, 462, 479, 493, 505, 511, 536, 541–560, 562–575.

### `crates/aether/src/certificates/state/ledger.rs`

LLVM brut : 251/292 (85.96 %) ; production DA : 243/282, **39 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `schedule` | 34 | hits |
| `apply_due` | 89 | hits |
| `remember` | 168 | hits |
| `forget_expired` | 202 | hits |
| `is_revoked` | 209 | hits |
| `assert_not_revoked` | 221 | hits |
| `last_status_for` | 231 | hits |
| `record_status` | 238 | hits |
| `prune_statuses` | 265 | hits |
| `snapshot` | 270 | hits |
| `scope_byte` | 315 | hits |
| `known_expiry` | 328 | hits |
| `base_state_fingerprint` | 396 | hits |

Lignes de production sans hit (DA) : 41–43, 120–122, 134, 152, 175, 247–249, 294–298, 300–303, 307–311, 317, 361–363, 405–413.

### `crates/astra/src/recovery.rs`

LLVM brut : 111/502 (22.11 %) ; production DA : 37/408, **371 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `is_expired` | 117 | hits |
| `authorization` | 121 | **zéro** |
| `receipt` | 125 | **zéro** |
| `view` | 132 | **zéro** |
| `new` | 155 | hits |
| `len` | 159 | hits |
| `is_empty` | 163 | **zéro** |
| `open` | 172 | hits |
| `get` | 187 | hits |
| `get_mut` | 202 | **zéro** |
| `open` | 226 | **zéro** |
| `authorize` | 360 | **zéro** |
| `grant` | 481 | **zéro** |
| `commit` | 588 | **zéro** |
| `reconcile` | 688 | **zéro** |
| `refusal` | 730 | **zéro** |

Lignes de production sans hit (DA) : 121–123, 125–127, 132–145, 163–165, 202–215, 226–231, 248–254, 256–262, 266–269, 281–290, 296–300, 302–305, 307–317, 319–321, 325–328, 330–340, 342–345, 348, 351–352, 360–366, 369–372, 376–382, 388–389, 391–399, 401–407, 409–412, 415–427, 430–437, 444–447, 451–452, 454–460, 462–468, 473–474, 481–494, 497–509, 514–526, 528–531, 533–535, 537–539, 544–550, 555, 562–567, 569–575, 577–579, 588–599, 601–606, 609–613, 615–618, 625, 627–634, 636, 639–646, 648–651, 656–657, 665–667, 673, 679–680, 688–722, 730, 732–735, 737.

### `crates/astra/src/service.rs`

LLVM brut : 77/634 (12.15 %) ; production DA : 73/593, **520 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `into_response` | 110 | hits |
| `charge_bounded` | 162 | hits |
| `charge` | 190 | hits |
| `charge_peer` | 205 | hits |
| `key` | 218 | hits |
| `charge` | 319 | **zéro** |
| `now_unix` | 328 | **zéro** |
| `router` | 336 | **zéro** |
| `status_challenge` | 393 | **zéro** |
| `status_query` | 428 | **zéro** |
| `operator_credential_required` | 535 | **zéro** |
| `bearer` | 545 | hits |
| `path_id` | 559 | hits |
| `relying_party` | 572 | **zéro** |
| `mint_view` | 585 | **zéro** |
| `authenticate` | 638 | **zéro** |
| `signing_operation` | 669 | **zéro** |
| `operator_operation` | 688 | **zéro** |
| `signer_request` | 708 | **zéro** |
| `operator_signer_request` | 724 | **zéro** |
| `encrypted_vault` | 766 | **zéro** |
| `operator_encrypted_vault` | 789 | **zéro** |
| `signer_result` | 866 | **zéro** |
| `operator_signer_result` | 883 | **zéro** |
| `open_recovery` | 1034 | **zéro** |
| `read_recovery` | 1056 | **zéro** |
| `authorize_recovery` | 1075 | **zéro** |
| `grant_recovery` | 1100 | **zéro** |
| `commit_recovery` | 1119 | **zéro** |
| `approved_random` | 1138 | **zéro** |

Lignes de production sans hit (DA) : 319–321, 323, 325, 328–333, 336–339, 347, 351–355, 357–359, 361–363, 365–367, 374–380, 393–398, 400–402, 405–411, 428–434, 438–442, 444–445, 447–450, 452–457, 461–465, 467–468, 473–476, 478–481, 483–490, 492–493, 495–497, 502–514, 516–518, 525, 527–528, 535–537, 572–576, 585–589, 594–621, 623–631, 638–661, 669–676, 678, 680, 688–698, 708–717, 719, 721, 724–729, 732–736, 738–758, 766–786, 789–794, 797–801, 805–806, 809–810, 814–823, 825–826, 828–830, 832–833, 836, 838, 841–844, 866–876, 878, 880, 883–889, 892–897, 899–925, 928–938, 944–946, 949, 952, 958, 960–961, 963, 965–966, 971, 973–976, 981, 985, 987–989, 994–999, 1001–1002, 1007–1009, 1014, 1016–1024, 1034–1048, 1056–1072, 1075–1097, 1100–1116, 1119–1135, 1138–1140.

### `crates/orion-core/src/certificate_recovery.rs`

LLVM brut : 292/589 (49.58 %) ; production DA : 84/357, **273 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `from` | 94 | **zéro** |
| `fmt` | 131 | **zéro** |
| `operation_id` | 141 | **zéro** |
| `authority_url` | 150 | **zéro** |
| `build_request` | 168 | hits |
| `begin` | 249 | **zéro** |
| `resume` | 328 | **zéro** |
| `step_of` | 354 | hits |
| `install` | 384 | **zéro** |
| `subject_of` | 527 | hits |
| `leaf_of` | 531 | hits |
| `decode_secret` | 542 | **zéro** |
| `post_json` | 549 | **zéro** |
| `get_json` | 566 | **zéro** |
| `decode_response` | 578 | **zéro** |
| `request_fingerprint` | 595 | **zéro** |

Lignes de production sans hit (DA) : 94–96, 131–137, 141–143, 150–152, 249–263, 265–271, 273–276, 278–282, 284–289, 291–296, 298–305, 307–322, 328–347, 350, 368–370, 384–402, 405–425, 432–446, 448–457, 459, 461–466, 468, 470–473, 476–489, 491, 493–504, 506, 510–515, 536–539, 542–547, 549–564, 566–576, 578–592, 595–597.

### `crates/orion-core/src/key_negotiation.rs`

LLVM brut : 343/488 (70.29 %) ; production DA : 331/460, **129 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `prepare_for_profile` | 47 | hits |
| `load` | 51 | sans donnée |
| `prepare_for_profile` | 61 | **zéro** |
| `load` | 74 | **zéro** |
| `fmt` | 142 | **zéro** |
| `remote` | 190 | **zéro** |
| `selection` | 195 | **zéro** |
| `transaction_id` | 204 | **zéro** |
| `confirm` | 217 | hits |
| `prepare` | 258 | hits |
| `prepare_for_profile` | 490 | hits |
| `prepare_renewal_for_profile` | 511 | **zéro** |
| `renewal_route` | 534 | hits |
| `prepare_for_profile_via` | 570 | hits |
| `hex_prefix` | 648 | hits |
| `unix_time_now` | 656 | hits |
| `random_identifier` | 663 | hits |
| `release_for_profile` | 698 | **zéro** |
| `post_release` | 753 | hits |
| `tunnel_routed_address` | 811 | hits |
| `parse_prefix` | 846 | hits |
| `prefix_contains` | 854 | hits |
| `shift_mask` | 872 | hits |

Lignes de production sans hit (DA) : 61, 72, 74, 81–85, 97, 142–163, 190–192, 195–197, 204–206, 235, 239, 241, 247, 266, 313–314, 333, 337, 352, 354, 359–367, 418–421, 428, 431, 433, 435, 454–458, 511–525, 542, 614, 618, 670, 698–710, 715–720, 724–726, 728–736, 738, 740–742, 745–746.

### `crates/orion-core/src/trust_update.rs`

LLVM brut : 398/473 (84.14 %) ; production DA : 106/161, **55 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `prepare` | 115 | hits |
| `base_state_fingerprint` | 175 | **zéro** |
| `run` | 185 | hits |
| `poll` | 206 | hits |
| `accept` | 263 | hits |
| `refresh` | 351 | **zéro** |

Lignes de production sans hit (DA) : 175–177, 193–199, 203, 222–228, 351–355, 360–370, 372–377, 379–381, 383–388, 390–392, 395–397.

### `crates/astra/src/renewal/approval.rs`

LLVM brut : 49/178 (27.53 %) ; production DA : 49/174, **125 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `plan_window` | 25 | hits |
| `build_approval_request` | 90 | **zéro** |
| `refresh_challenge` | 138 | **zéro** |
| `mint_view` | 176 | **zéro** |
| `authenticate` | 209 | **zéro** |

Lignes de production sans hit (DA) : 55, 90–103, 106–110, 112–122, 124–130, 132–135, 138–150, 152–171, 173, 176–194, 196–202, 209–231.

### `crates/astra/src/renewal/companion.rs`

LLVM brut : 0/167 (0.00 %) ; production DA : 0/164, **164 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `read` | 7 | **zéro** |
| `signer_request` | 47 | **zéro** |
| `signer_result` | 95 | **zéro** |

Lignes de production sans hit (DA) : 7–13, 17–21, 23–32, 34, 37, 39, 41–44, 47–63, 65–68, 74–85, 95–112, 114–118, 120, 123, 125, 127–130, 132–134, 137–144, 146–161, 163–165, 172–180, 182–189, 191–204, 206, 211–215, 217, 219–222.

### `crates/astra/src/renewal/mod.rs`

LLVM brut : 0/23 (0.00 %) ; production DA : 0/22, **22 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `refusal` | 159 | **zéro** |
| `now_unix` | 187 | **zéro** |
| `fresh_id` | 195 | **zéro** |
| `fresh_serial` | 202 | **zéro** |

Lignes de production sans hit (DA) : 159, 161, 164, 168–169, 171, 187–192, 195–199, 202–206.

### `crates/astra/src/renewal/request.rs`

LLVM brut : 0/183 (0.00 %) ; production DA : 0/178, **178 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `transcribe_peer` | 22 | **zéro** |
| `open` | 81 | **zéro** |
| `campaign_evidence` | 257 | **zéro** |

Lignes de production sans hit (DA) : 22–26, 38–39, 41–70, 81–90, 92–107, 109–111, 118–136, 141–142, 147–148, 151–161, 163, 165–177, 179–184, 190–194, 196–200, 202–207, 210, 212–227, 234, 241, 245–249, 257–274.

### `crates/astra/src/renewal/router.rs`

LLVM brut : 0/73 (0.00 %) ; production DA : 0/69, **69 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `router` | 34 | **zéro** |
| `prepare_trust_update` | 55 | **zéro** |
| `refuse` | 81 | **zéro** |
| `operation_id` | 86 | **zéro** |
| `request` | 90 | **zéro** |
| `operation` | 107 | **zéro** |
| `refuse_unknown_route` | 127 | **zéro** |

Lignes de production sans hit (DA) : 34–38, 43–47, 55–75, 78, 81–84, 86–88, 90–98, 100, 102–103, 105, 107–114, 116–118, 120, 127–129, 133–134.

### `crates/astra/src/renewal/stage.rs`

LLVM brut : 0/174 (0.00 %) ; production DA : 0/169, **169 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `resume_stage` | 10 | **zéro** |
| `reconcile_released_grant` | 172 | **zéro** |
| `gateway_identity` | 219 | **zéro** |

Lignes de production sans hit (DA) : 10–25, 27–28, 30–35, 38–43, 45–47, 49–50, 52–57, 60–72, 74–81, 85–90, 93–95, 101–113, 117–122, 125–130, 136–144, 149–153, 155–156, 162–163, 172–182, 184–188, 191–194, 196–205, 219–243.

### `crates/helios-provisioning/src/certificates/distribution.rs`

LLVM brut : 83/91 (91.21 %) ; production DA : 83/90, **7 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `stage_distribution` | 32 | hits |
| `take_distribution_chunk` | 99 | hits |

Lignes de production sans hit (DA) : 41–43, 46–48, 56.

### `crates/helios-provisioning/src/certificates/persistence.rs`

LLVM brut : 95/126 (75.40 %) ; production DA : 94/109, **15 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `path` | 15 | **zéro** |
| `new` | 21 | hits |
| `bootstrap` | 37 | hits |
| `load` | 54 | hits |
| `state` | 85 | hits |
| `persist` | 95 | hits |
| `migrate_legacy_registry` | 112 | hits |

Lignes de production sans hit (DA) : 15–19, 43, 74, 80–81, 133–134, 137–138, 156–157.

### `crates/helios-provisioning/src/certificates/staging.rs`

LLVM brut : 285/426 (66.90 %) ; production DA : 284/423, **139 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `admit` | 20 | hits |
| `stage` | 60 | hits |
| `commit` | 254 | hits |
| `purge_expired` | 451 | hits |
| `promote_due` | 465 | hits |
| `revoke` | 493 | hits |
| `purge_expired_in` | 558 | hits |
| `assert_fingerprints_free` | 579 | hits |

Lignes de production sans hit (DA) : 34, 96, 105, 107–116, 118–122, 125–136, 138–154, 158–159, 163–176, 180, 262, 270, 289, 303, 333–335, 342, 344–353, 355–360, 363–374, 376–406, 408, 432, 445, 456, 476–479.

### `crates/helios-provisioning/src/certificates/transitions.rs`

LLVM brut : 123/127 (96.85 %) ; production DA : 121/125, **4 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `install_ca_transition` | 26 | hits |
| `install_gateway_transition` | 54 | hits |
| `install_gateway_rollback` | 84 | hits |
| `active_gateway_rollback` | 100 | hits |
| `promote_gateway_if_due` | 112 | hits |
| `publish_gateway_transition` | 147 | hits |
| `abort_gateway_transition` | 183 | hits |
| `revoke_gateway` | 204 | hits |

Lignes de production sans hit (DA) : 95, 133, 193, 217.

### `crates/helios-provisioning/src/certificates/trust.rs`

LLVM brut : 158/166 (95.18 %) ; production DA : 157/165, **8 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `install_client_tls_ca_transition` | 20 | hits |
| `install_astra_credentials` | 79 | hits |
| `install_astra_issuer` | 134 | hits |
| `repair_legacy_client_tls_ca_bootstrap` | 197 | hits |

Lignes de production sans hit (DA) : 40, 170, 222–224, 240–242.

### `crates/orion-core/src/certificate_renewal/exchange.rs`

LLVM brut : 186/562 (33.10 %) ; production DA : 186/520, **334 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `new` | 69 | hits |
| `request` | 75 | **zéro** |
| `operation` | 82 | **zéro** |
| `signer_request` | 90 | **zéro** |
| `signer_result` | 98 | **zéro** |
| `stage_commit` | 106 | **zéro** |
| `command_line` | 153 | hits |
| `generate` | 178 | hits |
| `fmt` | 190 | **zéro** |
| `from_bundle` | 222 | **zéro** |
| `prepare` | 270 | hits |
| `sign` | 338 | hits |
| `request` | 349 | hits |
| `request_fingerprint` | 353 | hits |
| `operation_id` | 358 | **zéro** |
| `companion_invocation` | 371 | hits |
| `open` | 391 | **zéro** |
| `fetch_approval` | 408 | **zéro** |
| `submit_approval` | 433 | **zéro** |
| `advance` | 460 | **zéro** |
| `commit` | 497 | **zéro** |
| `candidate_bundle` | 604 | hits |
| `adopt` | 644 | hits |
| `check_identity` | 677 | hits |
| `post` | 704 | **zéro** |
| `post_ignoring_body` | 720 | **zéro** |
| `get_with_token` | 734 | **zéro** |
| `post_with_token` | 750 | **zéro** |
| `get` | 768 | **zéro** |
| `decode` | 778 | **zéro** |
| `decode_typed` | 784 | **zéro** |
| `refuse_status` | 810 | **zéro** |
| `committed_and_waiting` | 835 | hits |
| `horodatage` | 848 | hits |
| `begin` | 852 | **zéro** |
| `assert_active_can_prove_continuity` | 918 | hits |
| `resume` | 933 | **zéro** |

Lignes de production sans hit (DA) : 75–76, 80, 82–83, 86, 88, 90–91, 94, 96, 98–99, 102, 104, 106–107, 111, 190–197, 222–228, 230–231, 233, 358–360, 391–396, 408–419, 421–427, 433–443, 445–452, 460–473, 475, 477–478, 480–482, 485, 497–511, 513–527, 534–538, 543, 545–546, 549–562, 564, 569–575, 577–581, 655, 699, 704–718, 720–731, 734–748, 750–766, 768–776, 778–782, 784–790, 792–802, 810–821, 852–867, 869–875, 879, 886–887, 889–893, 895, 897–907, 933–949.

### `crates/orion-core/src/certificate_renewal/promotion.rs`

LLVM brut : 30/201 (14.93 %) ; production DA : 30/183, **153 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `candidate_identity_of` | 29 | hits |
| `promote_due` | 45 | **zéro** |
| `promote_local_identity_if_due` | 97 | **zéro** |
| `prepare_identity_for_connection` | 126 | **zéro** |
| `bundle_matches_generation` | 167 | **zéro** |
| `rollback_window` | 192 | hits |
| `rollback_to_previous` | 233 | **zéro** |

Lignes de production sans hit (DA) : 45–60, 63–67, 70–86, 97–122, 126–134, 136–149, 151–158, 167–175, 177–183, 185–190, 233–255, 257–258, 260–265, 267–271.

### `crates/orion-core/src/certificate_renewal/trust_store.rs`

LLVM brut : 251/283 (88.69 %) ; production DA : 249/265, **16 lignes non couvertes**.

| Fonction | Ligne | Compteurs |
|---|---:|---|
| `trust_store_path` | 38 | **zéro** |
| `identity_trust_store_path` | 51 | hits |
| `open_identity_store` | 70 | hits |
| `open_or_seed` | 128 | hits |
| `client_key_of` | 183 | hits |
| `client_pq_leaf` | 188 | hits |
| `client_tls_leaf` | 196 | hits |
| `seed` | 209 | hits |
| `retained_registry` | 388 | hits |

Lignes de production sans hit (DA) : 38–47, 49, 86, 99, 167, 349, 416.

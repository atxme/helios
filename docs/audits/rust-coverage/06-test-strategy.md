# Stratégie de tests

## Contrats à préserver

Les décisions de sécurité viennent des ADR acceptés et de leurs amendements, puis du code/tests courant et des spécifications. Références : ADR-001 (kill-switch et backends), ADR-002 (signatures de release), ADR-003/004 (mise à jour/admission/livraison), ADR-005 amendement v5 et renouvellement dans le tunnel, ADR-006/007 (secrets et TPM), ADR-008 et `ROTATION-CERTIFICATS.md` §14. Le tableau ancien de `TESTING.md` mentionnant trois modes et ML-DSA-65 ne doit pas servir de modèle pour de nouveaux tests v5. Conserver les domaines cryptographiques distincts.

Une ligne exécutée ne prouve ni sécurité, ni oracle de test correct. Chaque scénario doit vérifier résultat typé, état mémoire, état rechargé et effets externes attendus/interdits. Pour une transaction refusée : vérifier aussi l’absence de candidat annoncé, d’élévation de compteur incorrecte, de fuite de secret et d’effet résiduel. Un compteur consommé par conception reste consommé : ne pas affirmer que toute erreur laisse tous les compteurs identiques.

## Matrice par famille

| Famille | Unitaire | Intégration portable | Système / matériel | Oracles principaux |
|---|---|---|---|---|
| Contrats `aether` | format, limites, version, fenêtres, générations, encodage, ledger | grants signés réels, chaînes X509, validation sous clés autorisées | aucun matériel pour ces validations | signature altérée refusée, mauvais domaine/paire refusés, horloge à chaque borne, état rechargé cohérent |
| Signatures et AEAD | vecteurs existants, format strict, domaine/époque, contexte AEAD, troncatures | objets produits par les vrais signataires puis vérifiés, corruption de chaque composant | FIDO/TPM uniquement pour détention des clés et provenance | hybride AND release ; pas d’échange 65/87 ; aucun plaintext exposé |
| Astra | budget, challenges, transitions d’opérations, politiques | routeur public, veth simulé par canal loopback réel, journal et reprise | veth/namespace réel, cérémonie opérateur, conteneurs | isolation des magasins ordinary/operator/recovery, refus coarse, ordre journal→effet→réconciliation |
| Provisioning/registre | admission, IPAM, bornes, unicité, états | disque temporaire, grants/receipts/commit réels, tests d’écriture en échec | service gateway et reload avec configuration réellement scellée | persistance avant annonce, génération exacte, révocation dominante, PSK runtime préservé |
| Orion renouvellement/récupération | requête, preuve, adoption de vue, fenêtre | serveur HTTP contrôlé, signatures réelles et magasin isolé ; point d’injection local si nécessaire | DPAPI Windows, cérémonie puis reconnexion WireGuard-NT | vérifier→sceller candidat→stage→commit distant→commit local→promotion ; reprise aux coupures |
| Trust update | accumulateur, manifeste/fragment, limites et conflits | réponse HTTP bornée, toutes les pages, vraie application TrustStore | mise à jour distribuée pendant rotation du parc | rien avant dernier fragment, compare-and-swap sur base, audit/revocation non perdus |
| Négociation v5 | transcripts, anti-rejeu, ordre et générations | QUIC/mTLS réel loopback, doubles de pose/handshake, annulation | deux hôtes et pose PSK réelle WG noyau/NT | pose avant réponse ; handshake postérieur à pose avant commit ; acteur périmé inoffensif ; rollback résiste à drop/abort |
| Firewall/WireGuard | ruleset entier, traductions, multi-WAN, état Up | faux backend injectant erreur au point voulu | VM jetable, nftables/WG réels et capture trafic | aucune règle partielle ; NAT/filtre atomiques ; kill-switch avant réseau ; shutdown fermé |
| TPM | payloads, anti-rejeu, fenêtres, ordre logique | vrai backend ESAPI sur TPM logiciel explicite | TPM physique, PCR/boot et NV jetable | échec tag avant compteur/PCR, fenêtre à usage unique, pas de PCR étendu par test ordinaire |
| Updates/installateurs | manifestes, chemins, destinations, anti-rollback | bundles dans répertoires temporaires, coupures activation/rollback | VM systemd jetable et console de récupération | activation consommée même si rollback échoue, lien current et état durables |
| API/Tauri/CLI | autorisations/projections/DTO/IPC | routeur complet, sous-processus CLI, sidecar local contrôlé | UID Unix et tunnel réels, GUI/foreground Windows | absence de secrets, tokens non journalisés, refus des redirections/proxy, suppression tunnel avant identité |

## Points de testabilité minimaux

Réutiliser les traits et doubles existants (`WireGuardBackend`, backend firewall, fournisseurs d’identité de négociation, abstraction du canal Astra). Les registres prennent déjà chemins et horloges explicites. Éviter un service locator ou un nouveau magasin pour les tests.

Pour `certificate_recovery::begin/install` et `certificate_renewal::commit/promote_due`, l’ouverture du magasin DPAPI concret et du chemin de configuration global empêche de tester toute la séquence sous Linux. Deux options à décider : tests complets sur Windows avec dossier de compte isolé, et petit point d’injection **interne** du magasin/chemin pour la séquence pure. Un faux magasin ne prouve pas DPAPI ; les tests Windows existants restent obligatoires. Ne pas changer l’API publique ou la politique d’échec pour contourner `UnsupportedPlatform`.

Pour Astra, construire un fixture `AstraService` avec vrai registre temporaire, horloge contrôlée et canal gateway existant. Utiliser un listener loopback avec vrai HTTP/TLS si l’on veut aussi vérifier le montage `ConnectInfo`; pour les routes pures, le pattern routeur déjà utilisé dans `helios-api` suffit. Un éventuel ajout direct de dépendance dev `tower` doit être justifié ; une dépendance transitive présente n’est pas une autorisation automatique d’ajout.

Tester concurrence et annulation par barrières explicites aux frontières de pose, persistance et commit, pas par `sleep` aléatoires. Utiliser les mécanismes de temps Tokio déjà disponibles ; n’ajouter `test-util` qu’après examen des features existantes. Les horloges de certificat restent des paramètres `now_unix`, avec valeurs `borne−1`, `borne`, `borne+1` et erreurs d’addition/durée.

## Propriétés et fuzzing

`proptest` n’est pas une dépendance actuelle des manifestes inspectés. Commencer par tests déterministes paramétrés et séquences bornées sur les invariants existants. Si des générateurs/réducteurs rendent les tests de machines d’état nettement plus utiles, COV-027 devra justifier une dépendance **dev** compatible MSRV, après décision. Ne pas ajouter une bibliothèque de propriétés pour remplacer trois cas de bord explicites.

Propriétés ciblées : sérialisation stricte aller-retour et refus d’inconnus selon contrat, adresse VIP et préfixes, générations monotones, révocation terminale, impossibilité d’une paire TLS/PQ mixte, absence de troisième génération, commit idempotent uniquement à octets identiques, base-state différent pour chaque mutation de champ de sécurité, assemblage complet ou aucune application.

Les cinq harnais libFuzzer existants et leurs graines stables sont la base. Ajouter des corpus publics minimaux de certificats et objets signés, sans aucune clé de production. Pour dépasser les rejets syntaxiques, générer au départ des objets **valides avec clés de test**, puis muter structure/proofs/chunks ; documenter que les signatures deviennent invalides après mutation. Candidats supplémentaires : messages de négociation v5 stricts/bornés, JSON de réponse trust-update, stockage AEAD et migrations de registres. Prioriser d’abord un scénario fonctionnel qui définit l’oracle. Fuzz = absence de panic + invariants, pas preuve de conformité ou de signature.

## Scénarios négatifs obligatoires

- Chaque signature, identité, empreinte, CA/époque, CSR et génération changée séparément ; signature mathématiquement valide sous une clé non autorisée.
- Expiration, révocation courante/future, tombstones pleins/expirés, statut ancien par cible, horloge reculée, saute de génération et compteurs saturés.
- Corps trop gros avec et sans `Content-Length`, transfert chunké dépassant la borne, données tronquées, JSON inconnu, DER incorrect ; le refus intervient avant allocation sans borne et avant tout changement persistant.
- Erreurs HTTP, redirection, proxy d’environnement, délai d’en-têtes/corps, rupture en milieu de réponse, reprise d’un même dépôt et d’un dépôt divergent.
- Annulation avant/après pose, commit, persistance et promotion ; doublons concurrents, révocation concurrente, redémarrage et intention de réconciliation encore présente.
- Fichier absent/altéré, symlink, permission refusée, échec de remplacement/synchronisation et ancienne forme de registre selon compatibilité explicitement admise.

Ces cas complètent les tests existants décrits dans [les écarts](03-coverage-gaps.md) ; les cas déjà vérifiés ne sont pas à réécrire à l’identique.

## Infrastructure reproductible et nettoyage

1. **Portable sans privilège** : dossiers temporaires uniques, ports attribués par l’OS, fixtures avec clés de test, aucun contact réseau externe. Capturer logs de scénario et résultats de collecte.
2. **Linux noyau** : VM ou runner dédié jetable avec console ; namespace réseau propre au scénario et paire veth, adresses/règles/routes nommées ; installer nft/WG dans ce périmètre et observer paquets. Des tests privilégiés ne tournent jamais sur la gateway de production. Nettoyage par guard et destruction finale de VM même après échec.
3. **TPM logiciel** : processus `swtpm` et répertoire d’état isolés, TCTI explicite, `HELIOS_TPM_MATERIEL=1`. Enregistrer une assertion de précondition qui démontre l’exécution ; la simple ligne « passed » actuelle ne suffit pas. Détruire son état après run.
4. **TPM réel** : cible et index NV jetables. L’essai actuel utilise `0x01804846`, persiste cet index, n’étend aucun PCR ; annoncer cet effet avant exécution. Billets après vrai déplacement PCR/boot nécessitent console et restauration contrôlée. Aucun essai de ce type lancé pendant l’audit.
5. **Windows** : runner utilisateur jetable pour DPAPI même SID ; deux sessions/SID pour refus inter-compte ; poste et YubiKeys dédiés pour WebAuthn, WireGuard-NT, promotion puis reconnexion. Capturer état public et sorties sans secrets.

Les installations de paquets, accès au réseau, services, privilèges, règles nft et écritures NV sont des étapes d’infrastructure à identifier avant toute exécution. Elles ne font pas partie de cette phase documentaire. Les effets matériels ne seront pas déduits des pourcentages WSL2.

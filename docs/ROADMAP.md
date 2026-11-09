# Feuille de route Helios / Orion

Statut : **proposition**, établie le 9 octobre 2026 et corrigée le 18 octobre
2026 à partir du dépôt. Ce document ne décide rien : il ordonne ce que les ADR,
spécifications et études déjà présents nomment comme restant, et signale ce qui
attend une décision. En cas de désaccord, les ADR acceptés, le code et les
spécifications font foi (voir [AGENTS.md](../AGENTS.md)).

Chaque ligne renvoie à sa source. Deux limites sont marquées dans les tableaux :

- **Matériel requis** : l'essai ou l'action exige un équipement physique (TPM,
  clé FIDO2/YubiKey, interface WAN réelle, second hôte, token de signature). Non
  faisable depuis ce dépôt.
- **Cible requise** : l'essai exige un noyau Linux réel ou un Windows réel
  (WireGuard-NT, DPAPI, VM Windows). Non faisable depuis WSL2
  ([TESTING.md](testing/TESTING.md)).

**Hors périmètre : macOS.** Helios et Orion ne ciblent ni n'exécutent macOS.
Aucune ligne de cette feuille de route ne porte sur macOS.

## 1. Constat

Le développement des deux grands chantiers protocolaires est **clos ou presque** :

- négociation v5 opérationnelle pour l'établissement initial
  ([NEGOCIATION-DE-CLE-V5](specification/NEGOCIATION-DE-CLE-V5.md)) ;
- cycle de vie des certificats implémenté
  ([ROTATION-CERTIFICATS §12.5](specification/ROTATION-CERTIFICATS.md)) ;
- renouvellement de PSK en place dans le tunnel, fusionné dans `main` le
  18 octobre 2026 (F1) ; sa mesure sur cible reste à faire (V1) ;
- IPv6 dual-stack : T00 à T21 fusionnés, T22/T23 à faire
  ([ETUDE-IPV6](architecture/ETUDE-IPV6.md)).

Le reste se répartit en trois natures, qu'il ne faut pas mélanger dans un même lot :

1. **validation sur cible** : presque tout le code livré n'a été prouvé qu'au-dessus du matériel ;
2. **décisions en attente** : plusieurs fonctionnalités sont bloquées par un arbitrage, pas par du travail ;
3. **fonctionnalités et dette** : ce qui reste réellement à écrire.

## 2. Horizon 0 — Cohérence documentaire

Les écarts relevés le 9 octobre ont été **vérifiés le 18 octobre et sont
résolus** dans les sources. Ils ne sont plus à corriger :

| Sujet | Constat du 9 octobre | Constat du 18 octobre |
| --- | --- | --- |
| Cycle des certificats | `NEGOCIATION-DE-CLE-V5.md` annonçait le cycle absent | Le document dit « cycle complet implémenté » (en-tête et §21) ; aucune mention contraire |
| Droits API | `SECURITY.md` disait que tout pair est administrateur | `SECURITY.md` décrit le drapeau `admin` par pair ; `helios-api/src/auth.rs` l'applique |
| Secrets Orion | `SECURITY.md` disait un fichier local | `SECURITY.md` décrit le coffre HVLT (TPM puis DPAPI, mode dégradé explicite) |
| VIP non réconciliée | Écart supposé avec `data_plane.rs` | `README.md` dit que l'adresse de `network.toml` fait autorité, comme le code. ADR-001 §4 amendé en conséquence (ancien D3) |
| ADR-001 §3 bis après T01 (ancien D2) | Texte en attente de décision | Amendé le 18 octobre : le tunnel complet est `0.0.0.0/0, ::/0`, l'invariante de cycle de vie couvre la liste entière |
| ADR-001 §4, ADR-004 §5 (ancien D3) | Contredisaient l'IPAM unifié | Amendés le 18 octobre : la VIP est persistée dans `network.toml` et fait foi, la dérivation ne sert qu'à la choisir |
| `from_peers(&[])` (ancien D4) | Table de pairs vide à l'enrôlement | Supprimé avec l'IPAM unifié (`26ac509`, 1er octobre) ; CRATE-REORGANIZATION §13.4 mis à jour |

Les mentions prospectives de macOS (Keychain, cible Orion) ont été retirées
d'ADR-001, ADR-005 et ADR-006 le 18 octobre ; les mentions historiques de
l'ère IKEv2 restent.

## 3. Horizon 1 : validation sur cible

C'est ce qui sépare « implémenté » de « livrable ». Ordre proposé : d'abord ce
qui peut invalider une conception, ensuite ce qui valide du code existant.

| # | Essai | Source | Faisable ici ? |
| --- | --- | --- | --- |
| V1 | **Renouvellement de PSK à chaud avec trafic actif**, via « Renouveler la clé post-quantique », noyau Linux **et** WireGuard-NT, chemin sain puis dégradé. **Chemin sain validé le 24 octobre 2026** (Orion sous WireGuard-NT, gateway noyau Linux), après correction de la réinscription du pair sous Windows, que `defguard` 0.12 n'implémente pas. **Chemin dégradé écarté le 24 octobre 2026** : un lien à forte perte ou à forte latence n'est pas un cas d'usage visé, et un renouvellement qui y échoue retombe sans dommage sur l'ancienne clé, gardée jusqu'à son échéance, et sur un nouvel essai différé | v5 §20.0, §12.3, `testing/TESTING.md` | **Non** : matériel requis (gateway physique, WAN réel) et cible requise (WireGuard-NT sur Windows) |
| V2 | Banc netns reproductible (T22) — **livré** : `scripts/netns-bench.sh`, sans root, WSL2 compris | ETUDE-IPV6 T22, TESTING.md « Banc netns » | **Oui**. Premier passage : défaut T21 (rejet IPv6 non atteint avec `forwarding = 0`), corrigé par un rejet en `prerouting` |
| V3 | Campagne v5 §20.2 : pose des slots, redémarrage `heliosd`, arrêt brutal client, `release` dans le tunnel, coupure WAN > 35 s et > 5 min | v5 §20.2 | **Non** : matériel requis (coupure WAN réelle) |
| V4 | Campagne IPv6 (T23) et VM Windows (T01, T02, T18, T19) | ETUDE-IPV6 | **Non** : cible Windows et réseau réel |
| V5 | Recette firewall : MSS, ICMPv6 PTB hors flux suivi, ND/RA/DHCPv6, atomicité | FIREWALL-V2 « Validation sur cible » | **En partie** : le banc netns exerce le noyau réel sur veth (ND, rejets, forward) ; RA/DHCPv6 d'un vrai FAI et NIC physique restent sur cible |
| V6 | Certificats §14.2 : TPM, FIDO2 réel, cérémonie `GetAssertion` unique | ROTATION-CERTIFICATS §12.5, §14.2 | **Non** : matériel requis (TPM, clé FIDO2) |
| V7 | Fenêtre de mise à jour TPM réelle, billets de rescellement | ADR-007, TESTING.md | **Non** : matériel requis (TPM) |

Outillage qui débloque plusieurs lignes (TESTING.md, « Limite connue : le slot
PSK côté client ») :

- **mode headless d'Orion**, ou sous-commande `helios` qui *applique* un profil
  reçu au lieu de l'inspecter : **Oui**, c'est du code. Permet de vérifier le
  slot PSK client en campagne automatisée ;
- **second hôte client WireGuard** : **Non**, matériel requis ;
- **cible à console série pilotable** : **Non**, matériel requis.

## 4. Horizon 2 : décisions à prendre

Ces points demandent d'abord un arbitrage. Tant qu'il manque, le travail en aval
est bloqué ou risque d'être refait. Une décision ne se prend pas depuis le dépôt.

| # | Décision | Source | Débloque |
| --- | --- | --- | --- |
| D1 | **Compteur anti-rejeu** : fichier ou NV TPM (si NV TPM, validation matérielle requise) | ADR-002 amendement 2, ADR-006 « Rollback complet » | fichier de récupération WireGuard signé (F5) ; claim de fraîcheur des coffres |
| D5 | **DNS des clients** non tunnelé, même avec `allow_client_internet` | README, `helios-firewall/src/ruleset.rs`, ADR-006 | confidentialité des noms résolus (F7) |
| D6 | Activation de l'anti-spoof `fib` en multi-uplink / policy routing | FIREWALL-V2 « Capacités » | encodeur déjà livré |
| D7 | Acceptation ICMPv6 Packet Too Big scopée par interface | FIREWALL-V2, ETUDE-IPV6 §9.1 | après observation V5 |
| D8 | Authentification de `POST /v1/campaigns` sur l'origine publique | ROTATION-CERTIFICATS §11.6, §12.5 | boutons de campagne dans la console ; aujourd'hui volontairement refusé |
| D9 | Certificat EV Authenticode : achat et token de signature | ADR-004 « Limites connues » | réputation SmartScreen ; **matériel requis** pour la signature, décision de coût |
| D10 | **Décidé le 24 octobre 2026 : F11 d'abord.** `helios-astra-helper` existait parce qu'Orion tournait élevé (WireGuard-NT l'exige) alors que l'API WebAuthn de Windows ne répond qu'à intégrité moyenne dans la session de l'utilisateur. Plutôt qu'une relance d'`orion.exe` en mode compagnon désélevé, solution d'attente, la séparation des privilèges (F11) est faite en premier : l'IHM non privilégiée parle à WebAuthn directement et le compagnon disparaît. Retenu comme la voie la plus stable et la plus sûre ; le processus privilégié reste `orion.exe`, lancé en mode moteur (`--engine`), pour tenir la règle du binaire unique | ADR-008, `tools/helios-astra-helper`, F11 | F11, puis F14 |

## 5. Horizon 3 : fonctionnalités

Classées par dépendance, pas par taille. La colonne « Faisable ici » indique
si le travail se fait entièrement depuis le dépôt ; une validation sur cible
reste alors à faire à part.

### Protocole et sécurité

| # | Fonctionnalité | Source | Dépend de | Faisable ici ? |
| --- | --- | --- | --- | --- |
| F1 | **Renouvellement de PSK en place** dans le tunnel, à 80 % de 24 h ou de 100 Gio. **Fusionné dans `main` le 18 octobre 2026.** | v5 §7.6, §12.3 ; `docs/superpowers/specs/2026-10-09-renouvellement-psk-design.md` | V1 pour la mesure | Code : fait. Mesure : V1 |
| F2 | **Fusionné dans `main` le 23 octobre 2026.** **Enrôlement sans transport de clé privée** : invitation signée sous `CA-PQ` par credential matériel, demande produite et scellée par Orion, document signé en retour ; `helios enroll` (identité émise sur le poste opérateur) est retiré. DPAPI, YubiKey et le parcours Windows restent à valider sur poste réel | v5 §15 ; `docs/superpowers/specs/2026-10-19-enrolement-v5-design.md` | : | Code : fait. Poste Windows : à valider |
| F3 | **Fusionné dans `main` le 23 octobre 2026.** État terminal `revoked` porté par le même sérialiseur que le slot, génération incrémentée | v5 §11.1 | : | **Oui** |
| F4 | **Fusionné dans `main` le 23 octobre 2026.** Retrait de la **valeur de négociation** `classic` de `ProtectionMode` (protocole v5 côté gateway) : migration de `network.toml` et de l'octet `mode_id = 0` du bloc de négociation dans le manifeste de coffre. **Ne touche pas au profil Orion `type = classic`**, le profil WireGuard générique sans négociation, que v5 §19 conserve comme chemin produit distinct (`ProfileKind::Classic`, octet de type `1`, import wg-quick) | v5 §19 | : | **Oui** |
| F5 | Fichier de récupération WireGuard signé ML-DSA-65 + Ed25519 | ADR-002 lot 3 | D1 | **Oui**, après D1 |
| F6 | Profil Orion **`nomade`** : relier `ProfileMode`, IKM `profile_root_key ‖ passphrase_key`, re-saisie après veille | ADR-006 « Limites connues » | : | **Oui** |
| F7 | DNS tunnelé côté Orion et gateway | ADR-006, `ruleset.rs` | D5 | **Oui**, après D5 |

La veille confirme la direction retenue en F1 : Rosenpass alimente le même slot
PSK de WireGuard avec une rotation fréquente, et NetBird a dû forcer une
réinitialisation de session pour que le nouveau PSK prenne effet. C'est
exactement le coût que v5 §21 anticipe et que V1 doit mesurer. Tailscale annonce
une distribution automatique de PSK sans l'avoir livrée.

### Pare-feu

| # | Fonctionnalité | Source | Dépend de | Faisable ici ? |
| --- | --- | --- | --- | --- |
| F8 | **Rate limiting** et **logging borné** : ajouter `limit` au patch vendored de `rustables`, comme déjà fait pour `fib`, `objref` et `exthdr` | FIREWALL-V2 « Audit de `rustables` » | : | **Oui** (code), validation noyau en V5 |
| F9 | Pairs Meshnet IPv6 : couvrir un préfixe global du lien WAN | ETUDE-IPV6 T06 | V4 | Code : **oui** ; validation : **non** (cible) |
| F10 | Forwarding IPv6 choisi explicitement (phase 4) | ETUDE-IPV6 | V4 | Code : **oui** ; validation : **non** (cible) |

### Plateforme Orion

| # | Fonctionnalité | Source | Dépend de | Faisable ici ? |
| --- | --- | --- | --- | --- |
| F11 | **Séparation des privilèges Windows** (D10) : **fusionné dans `main` le 27 octobre 2026, validé sur Windows le 28 octobre 2026.** `orion.exe` (manifeste `asInvoker`) lance `orion.exe --engine` élevé, qui porte WireGuardNT, le coffre sous `%ProgramData%\helios\orion\<SID>` et la clé TPM machine ; canal par tube nommé authentifié, politique d'autorisation, migration de l'ancien coffre, installation pour la machine. L'IHM non élevée porte les cérémonies WebAuthn ; `helios-astra-helper` est supprimé. Recette MANUAL-TESTING « Séparation des privilèges (F11) » jouée sur Windows | ADR-004 « Limites connues », ADR-006 §7 | : | **Oui** |
| F12 | **Stockage protégé Linux** (`libsecret`) : refus explicite actuel conservé d'ici là. macOS retiré du périmètre. | ADR-005, ADR-006 | : | Code : **oui** ; validation : session Linux de bureau, **non** depuis WSL2 |
| F13 | Association `.orion` pour le paquet NSIS | ORION-DISTRIBUTION | : | Code : **oui** ; validation : **non** (Windows réel) |
| F14 | **Orion seul binaire client : absorption d'`astra-signer`** (le compagnon `helios-astra-helper` a déjà disparu avec F11). Règle posée le 24 octobre 2026 : côté poste, opérateur compris, plus aucun binaire livré à part d'Orion ; les outils peuvent vivre *dans* Orion, rien d'externe. **Lots 1 et 2 fusionnés dans `main` le 28 octobre 2026** : l'onglet Astra devient l'espace opérateur (état du coffre et du domaine sans clé, « Vérifier une clé ») et l'enrôlement v5 s'y joue de bout en bout (« Inviter un poste », « Accepter une demande », « Reprendre », liste des invitations avec « Révoquer »), validation Windows à faire ; **lot 3 (coffre, clés, domaine) fusionné dans `main` le 31 octobre 2026**, validation Windows à faire : créer le domaine, ajouter, renommer, marquer perdue, retirer une clé, choisir l'emplacement du coffre, compléter le relais et finaliser le domaine depuis Orion (recette : MANUAL-TESTING, « C. Lot 3 »), conception `docs/superpowers/specs/2026-10-28-f14-lot3-coffre-domaine-design.md`. **lot 6a (amorçage de la gateway depuis Orion, par fichiers, deux clés) fusionné dans `main` le 31 octobre 2026**, validation Windows à faire (recette : MANUAL-TESTING, « D. Lot 6a »), conception `docs/superpowers/specs/2026-10-31-f14-lot6a-amorcage-gateway-design.md` ; le lot 6b (transition, retour arrière, abandon) reste à concevoir. **Lot 4 (approbations dans Orion) fusionné dans `main` le 1er novembre 2026**, validation Windows à faire (recette : MANUAL-TESTING, « E. Lot 4 ») : le renouvellement ordinaire s'approuve dans l'IHM non élevée (le compagnon de renouvellement disparaît, le PIN ne traverse plus l'IPC, protocole moteur en version 2), la récupération s'approuve depuis le poste de l'opérateur par l'identifiant d'opération, et `authorize-issuer` (en campagne, et hors campagne pour un domaine sans origine) passe dans Orion ; la rotation CA-TLS reste sur `astra-signer` jusqu'au lot 5, conception `docs/superpowers/specs/2026-10-31-f14-lot4-approbations-design.md`. **Lot 5a (la porte unique d'Astra) fusionné dans `main` le 4 novembre 2026**, validation sur cible à faire (recette : MANUAL-TESTING, « F. Lot 5a ») : une seule fonction du service Astra ouvre toute campagne ; la console devient un connecteur par un socket local du service, et le tunnel un second (`POST /api/certificates/operator/campaigns`, pair administrateur ; parc, autorités et révocation d'un client) ; l'échéance d'une révocation n'est plus recopiée ; un verrou du volume fait du service le seul écrivain de son état tant qu'il tourne. Aucun écran nouveau au 5a, conception `docs/superpowers/specs/2026-11-02-f14-lot5a-porte-unique-design.md`. **Lot 5b (les rotations dans Orion) fusionné dans `main` le 8 novembre 2026 (Helios 3.0.0, Orion 3.0.0)**, validation sur cible à faire (recette : MANUAL-TESTING, « G. Lot 5b ») : renouveler les postes, remplacer la CA-PQ ou la CA TLS, terminer la rotation CA TLS, reprendre une rotation interrompue (automatique à la montée du tunnel), renouveler la délégation de l'émetteur et envoyer la copie du coffre se font depuis l'onglet Rotations, sans commande ni fichier ni redémarrage d'Astra ; Orion ne lance plus `astra-signer`, dont les commandes restent le recours jusqu'au lot 7 ; conception `docs/superpowers/specs/2026-11-04-f14-lot5b-rotations-design.md` et son amendement du 7 novembre 2026 ; limites et suivis ci-dessous. **Lot 5c (révocation d'un poste depuis Orion, onglet *Postes*) livré sur la branche `feat/f14-lot5c-revocation`, pas encore fusionné dans `main`** (recette : MANUAL-TESTING, « H. Lot 5c » ; conception `docs/superpowers/specs/2026-11-08-f14-lot5c-revocation-design.md`). Au 9 novembre 2026, `main` est à Helios 3.0.1 / Orion 3.0.1. F14 complet est prévu dans la prochaine version, avec F6 et F8. `astra-signer` et `helios enroll document` restent livrés, à titre transitoire, jusqu'au lot 7. Toutes les cérémonies d'`astra-signer` passent dans Orion, l'enrôlement v5 en premier : créer l'invitation (bouton), accepter la demande, signer le document, lister et révoquer les invitations, avec l'assemblage du brouillon que fait aujourd'hui `helios enroll document`. Puis : initialisation du domaine et credentials (`init`, `enrol`, `verify`, `list`, `remove`, `devices`), `domain`, `issue-ca-tls`, `authorize-issuer`, `bindings`, approbations et campagnes, rotations de CA, révocation, amorçage et transitions de gateway. La recette d'enrôlement v5 sur Windows (MANUAL-TESTING) se joue désormais depuis Orion seul (lots 1 et 2, à valider en recette) | ADR-008, `tools/astra-signer/src/cli.rs` | F11 (D10) | **Oui** |

Pour F11, le client WireGuard Windows officiel est un modèle éprouvé : un
service gestionnaire SYSTEM qui démarre un service par tunnel, une IHM non
privilégiée héritant de tubes anonymes, et un tube nommé de tunnel dont le
propriétaire est vérifié avant connexion. Son propre document de surface
d'attaque signale la conservation de `SeLoadDriverPrivilege` comme point faible :
à ne pas reproduire.

Suivis de F14 lot 5b (limites connues à la livraison ; détail pour l'opérateur
dans `RENOUVELLEMENT-CERTIFICATS.md`, « Limites connues des rotations dans Orion »).

| # | Suivi | Source | Faisable ici ? |
| --- | --- | --- | --- |
| F14-a | **Réparer un délai d'installation dépassé** : après `activation_at`, la gateway refuse la transition et le coffre ne peut plus en signer une autre (la clé sortante n'y est plus). Orion affiche « Délai dépassé » et « Intervention manuelle requise », sans réparation | spec 5b §5.4 | Code : **oui** (conception à faire) ; validation : **non** (cible) |
| F14-b | **Révocation d'urgence entre `Applied` et `not_after`** (37 jours au plus par défaut) : la clé sortante a quitté le coffre alors qu'Astra vérifie encore sous elle. **Levé au lot 5c** (conception du 8 novembre 2026, §5.4) : le coffre garde la clé `CA-PQ` sortante jusqu'à « Terminer la rotation CA-PQ », la révocation se signe sous le document sortant servi par Astra, test de bout en bout `crates/astra/src/door/tests/overlap_revocation.rs`. Restent : une rotation antérieure au lot ne garde pas sa clé ; l'onglet *Postes* affiche encore « Signature possible » en rouge pendant le recouvrement et désactive « Reprendre » (RENOUVELLEMENT-CERTIFICATS, « Limites connues ») | spec 5b, amendement du 7 novembre 2026 ; spec 5c §5.4 | Code : **oui** ; validation : **non** (cible) |
| F14-c | **Campagnes de parc sans signature de CA** : garder l'ancien document de credentials pour les approbations pendant un recouvrement CA-PQ rétablirait « Renouveler les postes ». **Décision prise le 8 novembre 2026** : « Renouveler les postes » reste bloqué pendant un recouvrement CA-PQ ; « Remplacer la CA-PQ » avertit des postes qui expirent pendant le changement (spec 5c §2, §5.5, §5.6) | spec 5b, amendement du 7 novembre 2026 | Décision prise ; rien à faire ici |
| F14-d | **Dialogue de clé de la plateforme qui ne revient jamais** : aucune borne sur les ouvertures gardées en mémoire, seul un redémarrage d'Orion y met fin (`pCancellationId` nul dans `webauthn.rs`, lectures HID sans délai). Un GUID d'annulation fermerait le cas sous Windows | spec 5b, amendement du 7 novembre 2026 | Code : **oui** ; validation : **non** (Windows) |
| F14-e | **Successeur du recours `astra-signer rotate-ca-pq`** quand F14 absorbe `astra-signer` (lot 7) : sa reprise déplace le coffre sans parole d'Astra, par le geste voulu de l'opérateur. Le remplaçant doit être nommé avant le retrait de la commande | spec 5b, amendement du 7 novembre 2026 | **Oui** |
| F14-f | **Copie du coffre** : un administrateur du tunnel peut la remplacer (une génération précédente gardée) ; sauvegarde hors de la gateway non couverte ; deux postes tenant un même domaine peuvent écraser une copie plus récente d'Astra (seul le domaine est contrôlé) ; `write_domain_relay` n'est pas couvert par la garde d'écrasement | spec 5b §5.9, amendement du 7 novembre 2026 | **Oui** |

### Chaîne de livraison

| # | Fonctionnalité | Source | Faisable ici ? |
| --- | --- | --- | --- |
| F15 | **Bundle reproductible** : chemins remappés, `SOURCE_DATE_EPOCH`, conteneur de build figé | ADR-004 « Limites connues » | **Oui** |

La veille n'a pas permis d'établir si `trim-paths` est stabilisé dans Cargo à la
version locale (`rustc 1.99.0`) : à vérifier avant de choisir entre `trim-paths`
et `--remap-path-prefix`.

## 6. Horizon 4 : dette et dépendances

| # | Point | Source | Action | Faisable ici ? |
| --- | --- | --- | --- | --- |
| T1 | `glib 0.18.5` / `gtk 0.18.2` via Tauri `2.12.1` : RUSTSEC-2024-0429 et GTK3 non maintenu | security/SECURITY.md, `Cargo.lock` | **décidé le 2026-10-09 : pas de migration GTK4.** Orion reste sur Tauri. L'avis reste suivi comme transitif | Décision prise |
| T2 | `rustables 0.8.8` vendored conservé ; montée vers `0.9` bloquée par la chaîne bindgen / syn | FIREWALL-V2, manifests amont | reproduire le blocage avec la résolution complète ; reprendre les patches `fib`, `objref`, `exthdr` et leurs tests ABI ; `limit` reste absent (F8) | **Oui** |
| T3 | Absence de garantie de reseed avec entropie fraîche avant chaque clé privée ; le binding Rust n'expose pas cette garantie | `aether::random`, v5 §4.3, ROTATION-CERTIFICATS §2.3.2 | obtenir une API fournisseur garantissant le reseed ; ne pas porter d'état DRBG localement | Dépend d'un fournisseur |
| T4 | Migration `SecretString` écrite pour `StoredChannel`, `ClientProfile`, `ProfileManifest` et `ClientIdentityBundle` | ADR-006 §5, `aether::secret::json`, `orion-core/src/{config,identity_store}.rs` | compiler et exécuter les tests et la régression ; **vérifier DPAPI sur Windows** ; ne clôturer qu'après validation | Compilation et tests : **oui** ; DPAPI : **non** (cible Windows) |
| T5 | Réorganisation des crates — **découpages faits le 18 octobre 2026** : `orion-core` `backend/mod.rs`, `helios-api` `routes.rs` et `certificates.rs`, `main.rs` Tauri d'Orion, suivi WebSocket de `helios`. Restent : `impl RenewalSession`, qui demande un type `RenewalTransport` (réécriture, pas déplacement), le réalignement de `ruleset/tests/` (renommage de tests) et les renommages de fichiers (`key_nego`, `backend/` du pare-feu et de WireGuard) | CRATE-REORGANIZATION §13 | décision avant chacun des trois restes | Découpages : **oui** ; compilation Windows du `main.rs` Tauri : **non** (CI native) |
| T6 | Trois boucles de scrutation à 2 s et télémétrie WAN à 1 s | ECOCONCEPTION | mesurer d'abord à la prise, puis remplacer par des notifications | Mesure : **oui** ; prise réelle : **non** (matériel) |

## 7. Horizon 5 : reportables

**Non planifié** (décision du 2026-10-09), à l'exception des extensions de
certificats si un besoin les rend nécessaires. Liste conservée pour mémoire.

Explicitement listés comme extensions postérieures au cycle complet
(ROTATION-CERTIFICATS §12.4) ; aucune ne peut élargir les invariants de slots,
de générations ou de délégation :

- notifications par courrier ou messagerie ;
- coffre M-sur-N et approbation par plusieurs opérateurs ;
- HSM ML-DSA-87 ou émetteur attesté ;
- campagnes multi-gateways sous un même domaine ;
- export de conformité vers un SIEM ;
- autorisation API plus fine que le drapeau `admin`, avant d'ouvrir
  l'administration à des pairs non administrateurs (security/SECURITY.md).

## 8. Séquencement proposé

```text
Faisable maintenant (sans matériel)
  outillage headless Orion · T2 · T4 compilation · T5 · T6 mesure
  D1, D5 à D8 arbitrages
  F14 Orion seul binaire client (enrôlement v5 d'abord), après F11
  F6 nomade · F8 limit · F15 reproductible

Faisable en code, validation sur cible à planifier
  F5 (après D1) · F7 (après D5) · F12 libsecret · F13 NSIS

Bloqué par matériel ou cible (hors WSL2)
  V1 · V3 · V4 · V5 · V6 · V7 · T4 DPAPI · T6 prise réelle · D9 signature EV
  second hôte client · console série
```

## Sources externes

- [Tailscale : Post-quantum cryptography](https://tailscale.com/kb/1460/post-quantum-cryptography)
- [NetBird : How we integrated Rosenpass](https://netbird.io/knowledge-hub/how-we-integrated-rosenpass)
- [WireGuard for Windows : attacksurface.md](https://git.zx2c4.com/wireguard-windows/tree/docs/attacksurface.md)
- [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429)
- [RFC 3127 : trim-paths](https://rust-lang.github.io/rfcs/3127-trim-paths.html)
- [rustables 0.8.8](https://docs.rs/crate/rustables/0.8.8)

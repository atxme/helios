# Feuille de route Helios / Orion

Statut : **proposition**, établie le 9 octobre 2026 à partir du dépôt
(`af48a7a`) et d'une veille externe. Ce document ne décide rien : il ordonne
ce que les ADR, spécifications et études déjà présents nomment comme restant,
et signale ce qui attend une décision. En cas de désaccord, les ADR acceptés,
le code et les spécifications font foi (voir [AGENTS.md](../AGENTS.md)).

Chaque ligne renvoie à sa source. « Cible » signifie qu'aucune compilation
WSL2 ne peut cocher la ligne ([TESTING.md](testing/TESTING.md)).

## 1. Constat

Le développement des deux grands chantiers protocolaires est **clos ou presque** :

- négociation v5 opérationnelle pour l'établissement initial
  ([NEGOCIATION-DE-CLE-V5](specification/NEGOCIATION-DE-CLE-V5.md)) ;
- cycle de vie des certificats déclaré implémenté le 8 octobre 2026
  ([ROTATION-CERTIFICATS §12.5](specification/ROTATION-CERTIFICATS.md)) ;
- IPv6 dual-stack : T00 à T21 fusionnés, T22/T23 à faire
  ([ETUDE-IPV6](architecture/ETUDE-IPV6.md)).

Le reste se répartit en trois natures très différentes, qu'il ne faut pas
mélanger dans un même lot :

1. **validation sur cible** — le goulot principal, presque tout le code livré
   n'a été prouvé qu'au-dessus du matériel ;
2. **décisions en attente** — plusieurs fonctionnalités sont bloquées par un
   arbitrage, pas par du travail ;
3. **fonctionnalités et dette** — ce qui reste réellement à écrire.

## 2. Horizon 0 — Cohérence documentaire (immédiat, sans code)

Écarts relevés pendant cette revue, à corriger pour que la doc reste une
source fiable :

| Écart | Source | Constat |
| --- | --- | --- |
| Cycle des certificats | `NEGOCIATION-DE-CLE-V5.md`, en-tête « Ce qui n'est pas implémenté, au 2026-08-16 » | dit la leaf PQ gateway auto-signée et le cycle absent, alors que le §21 du même document et `ROTATION-CERTIFICATS.md` le déclarent livré |
| Droits API | `security/SECURITY.md`, « Surface réseau » | dit que tout pair joignant l'API est administrateur ; `helios-api/src/auth.rs` porte un drapeau `admin` par pair et refuse la mutation d'un pair non administrateur |
| Secrets Orion | `security/SECURITY.md`, « Secrets et racines de confiance » | dit les secrets des profils dans un fichier local ; l'ADR-006 et `orion-core/src/vault` décrivent un coffre (mode `service`) |
| VIP non réconciliée | `README.md`, « État et limites » | à revérifier après l'IPAM unifié (T11 + T14) : `heliosd/src/orchestrator/data_plane.rs` documente l'adresse déclarée comme autoritaire |

Les deux dernières lignes sont à confirmer contre le code avant correction ;
les deux premières sont des contradictions internes vérifiées.

## 3. Horizon 1 — Validation sur cible (priorité haute)

C'est ce qui sépare « implémenté » de « livrable ». Ordre proposé : d'abord
ce qui peut invalider une conception, ensuite ce qui valide du code existant.

| # | Essai | Source | Pourquoi maintenant |
| --- | --- | --- | --- |
| V1 | **Renouvellement de PSK à chaud avec trafic actif**, sur le code de production via « Renouveler la clé maintenant », noyau Linux **et** WireGuard-NT, chemin sain puis dégradé | v5 §20.0, §12.3, recette dans `testing/TESTING.md` | n'est plus bloquant (décision du 2026-10-09) ; s'il échoue, repli §12.3 vers la reconnexion complète |
| V2 | Banc netns reproductible (T22) | ETUDE-IPV6 T22 | rend rejouables V3–V5 hors gateway physique ; peut démarrer tout de suite |
| V3 | Campagne v5 §20.2 : pose réelle des slots, redémarrage `heliosd`, arrêt brutal client, `release` dans le tunnel, coupure WAN > 35 s et > 5 min | v5 §20.2 | aucune ligne cochée aujourd'hui |
| V4 | Campagne IPv6 (T23) et VM Windows (T01, T02, T18, T19) | ETUDE-IPV6 | fuite `::/0`, Happy Eyeballs, adresse `orion0` non vérifiés |
| V5 | Recette firewall : MSS (réécriture, somme TCP), ICMPv6 PTB hors flux suivi, ND/RA/DHCPv6, atomicité | FIREWALL-V2 « Validation sur cible » | encodeurs livrés, comportement noyau non observé |
| V6 | Certificats §14.2 : TPM, FIDO2 réel, cérémonie `GetAssertion` unique | ROTATION-CERTIFICATS §12.5, §14.2 | cycle « implémenté et testé au-dessus du matériel » seulement |
| V7 | Fenêtre de mise à jour TPM réelle, billets de rescellement | ADR-007, TESTING.md | n'a jamais tourné sur un TPM réel |

Les essais V2 à V7 sont menés à la main au fil des livraisons ; V1 reste
ouvert. L'outillage ci-dessous rendrait ces essais rejouables et leur verdict
consignable, plutôt que dépendant d'une recette manuelle.

Outillage qui débloque plusieurs lignes (TESTING.md, « Limite connue : le slot
PSK côté client ») :

- **mode headless d'Orion**, ou sous-commande `helios` qui *applique* un profil
  reçu au lieu de l'inspecter : permettrait de vérifier le slot PSK client en
  campagne automatisée ;
- **second hôte client WireGuard** dans la campagne cible ;
- **cible à console série pilotable** pour automatiser les billets de
  rescellement.

## 4. Horizon 2 — Décisions à prendre

Ces points ne demandent pas d'abord du code mais un arbitrage. Tant qu'il
manque, le travail en aval est bloqué ou risque d'être refait.

| # | Décision | Source | Débloque |
| --- | --- | --- | --- |
| D1 | **Compteur anti-rejeu** : fichier ou NV TPM | ADR-002 amendement 2, ADR-006 « Rollback complet » | fichier de récupération WireGuard signé (lot 3 ADR-002) ; claim de fraîcheur des coffres |
| D2 | Texte d'ADR-001 §3 bis après T01 (`::/0`) | ETUDE-IPV6 T01 | clôture de la fuite IPv6 côté ADR |
| D3 | ADR-001 §4 et ADR-004 §5 contredisent l'IPAM unifié | ETUDE-IPV6 T11 + T14 | mise en conformité ADR ↔ code |
| D4 | `PeerAddressTable::from_peers(&[])` à l'enrôlement, alors qu'ADR-001 §4 exige la table vivante | CRATE-REORGANIZATION §13.4 | cohérence IPAM à l'admission |
| D5 | **DNS des clients** non tunnelé, même `allow_client_internet` | README, `helios-firewall/src/ruleset.rs`, ADR-006 | confidentialité des noms résolus |
| D6 | Activation de l'anti-spoof `fib` en multi-uplink / policy routing | FIREWALL-V2 « Capacités » | encodeur déjà livré |
| D7 | Acceptation ICMPv6 Packet Too Big scopée par interface | FIREWALL-V2, ETUDE-IPV6 §9.1 | après observation V5 |
| D8 | Authentification de `POST /v1/campaigns` sur l'origine publique | ROTATION-CERTIFICATS §11.6, §12.5 | boutons de campagne dans la console ; aujourd'hui volontairement refusé |
| D9 | Certificat EV Authenticode | ADR-004 « Limites connues » | réputation SmartScreen ; décision de coût |

## 5. Horizon 3 — Fonctionnalités

Classées par dépendance, pas par taille.

### Protocole et sécurité

| # | Fonctionnalité | Source | Dépend de |
| --- | --- | --- | --- |
| F1 | **Renouvellement de PSK en place** dans le tunnel, à 80 % de 24 h ou de 100 Gio — **implémenté** sur `feat/renouvellement-psk` (2026-10-10), à fusionner après H4 | v5 §7.6, §12.3 ; `docs/superpowers/specs/2026-10-09-renouvellement-psk-design.md` | mesure V1 sur cible |
| F2 | **Enrôlement sans transport de clé privée** et signature opérateur ; `helios enroll` distribue encore l'identité cliente comme en v4 | v5 §15 | — |
| F3 | État terminal `revoked` porté par le même sérialiseur que le slot, génération incrémentée | v5 §11.1 | — |
| F4 | Retrait de la variante `classic` de `ProtectionMode` : migration de `network.toml` et de l'octet `mode_id = 0` du manifeste de coffre | v5 §19 | — |
| F5 | Fichier de récupération WireGuard signé ML-DSA-65 + Ed25519 | ADR-002 lot 3 | D1 |
| F6 | Profil Orion **`nomade`** : relier `ProfileMode`, IKM `profile_root_key ‖ passphrase_key`, re-saisie après veille | ADR-006 « Limites connues » | — |
| F7 | DNS tunnelé côté Orion et gateway | ADR-006, `ruleset.rs` | D5 |

La veille confirme la direction retenue en F1 : Rosenpass alimente le même
slot PSK de WireGuard avec une rotation fréquente, et NetBird a dû forcer une
réinitialisation de session pour que le nouveau PSK prenne effet — exactement
le coût que v5 §21 anticipe et que V1 doit mesurer. Tailscale annonce une
distribution automatique de PSK sans l'avoir livrée.

### Pare-feu

| # | Fonctionnalité | Source | Dépend de |
| --- | --- | --- | --- |
| F8 | **Rate limiting** et **logging borné** : ajouter `limit` au patch vendored de `rustables`, comme déjà fait pour `fib`, `objref` et `exthdr` | FIREWALL-V2 « Audit de `rustables` » | — |
| F9 | Pairs Meshnet IPv6 : couvrir un préfixe global du lien WAN | ETUDE-IPV6 T06 | V4 |
| F10 | Forwarding IPv6 choisi explicitement (phase 4) | ETUDE-IPV6 | V4, D2 |

### Plateforme Orion

| # | Fonctionnalité | Source | Dépend de |
| --- | --- | --- | --- |
| F11 | **Séparation des privilèges Windows** : service privilégié, IPC authentifié, politique d'autorisation, pour retirer `requireAdministrator` de l'IHM | ADR-004 « Limites connues » | conception + audit conjoints |
| F12 | Stockage protégé Linux (`libsecret`) et macOS (Keychain) ; refus explicite actuel conservé d'ici là | ADR-005, ADR-006 | — |
| F13 | Association `.orion` pour le paquet NSIS | ORION-DISTRIBUTION | — |
| F14 | Parité Orion des cérémonies Astra encore portées par `astra-signer` | ADR-008 | — |

Pour F11, le client WireGuard Windows officiel est un modèle éprouvé : un
service gestionnaire SYSTEM qui démarre un service par tunnel, une IHM non
privilégiée héritant de tubes anonymes, et un tube nommé de tunnel dont le
propriétaire est vérifié avant connexion. Son propre document de surface
d'attaque signale la conservation de `SeLoadDriverPrivilege` comme point
faible : à ne pas reproduire.

### Chaîne de livraison

| # | Fonctionnalité | Source |
| --- | --- | --- |
| F15 | **Bundle reproductible** : chemins remappés, `SOURCE_DATE_EPOCH`, conteneur de build figé | ADR-004 « Limites connues » |

La veille n'a pas permis d'établir si `trim-paths` est stabilisé dans Cargo à
la version locale (`rustc 1.99.0`) : à vérifier avant de choisir entre
`trim-paths` et `--remap-path-prefix`.

## 6. Horizon 4 — Dette et dépendances

| # | Point | Source | Action |
| --- | --- | --- | --- |
| T1 | `glib 0.18.5` / `gtk 0.18.2` via Tauri `2.12.1` : RUSTSEC-2024-0429 (unsound, corrigé à partir de `glib 0.20`) et GTK3 non maintenu | security/SECURITY.md, `Cargo.lock` | **décidé le 2026-10-09 : pas de migration GTK4.** Orion reste sur Tauri ; l'alternative retenue serait WinUI natif, pas un autre toolkit multiplateforme. L'avis reste suivi comme transitif |
| T2 | `rustables 0.8.8` vendored conservé ; montée vers `0.9` bloquée, chaîne bindgen / syn à revalider avant migration | FIREWALL-V2, manifests amont de `rustables 0.9.0` et `rustables-macros 0.2.0` | reproduire le blocage avec la résolution complète ; reprendre les patches `fib`, `objref`, `exthdr` et leurs tests ABI ; `limit` reste absent |
| T3 | Adaptation native AWS-LC présente, mais absence de garantie de reseed avec entropie fraîche avant chaque clé privée ; le binding Rust n'expose pas cette garantie | `aether::random`, v5 §4.3, ROTATION-CERTIFICATS §2.3.2 | obtenir une API fournisseur garantissant le reseed, y compris pour les clés internes ML-KEM/TLS ; ne pas porter d'état DRBG localement |
| T4 | Migration `SecretString` écrite pour `StoredChannel`, `ClientProfile`, `ProfileManifest` et `ClientIdentityBundle` ; copies nommées et encodage explicite aux frontières, aucun `Serialize` sur les types d'exécution | ADR-006 §5, `aether::secret::json`, `orion-core/src/{config,identity_store}.rs` | compiler et exécuter les tests, doctests et la régression ; vérifier DPAPI sur Windows ; ne clôturer qu'après validation |
| T5 | Réorganisation des crates : `impl RenewalSession` (DEFERRED), `orion-core/src/backend/mod.rs`, `helios-api` `certificates.rs`/`routes.rs`, réalignement de `ruleset/tests/` | CRATE-REORGANIZATION §13 | lots atomiques avec golden avant découpage, comme les précédents |
| T6 | Trois boucles de scrutation à 2 s et télémétrie WAN à 1 s | ECOCONCEPTION | mesurer d'abord à la prise, puis remplacer par des notifications |

## 7. Horizon 5 — Reportables

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
Maintenant      H0 cohérence doc · H4 dette · fusion F1 · V1 mesure sur cible · D1–D4 arbitrages
Court terme     F2 enrôlement
Moyen terme     F3 revoked · F4 retrait classic · F6 nomade · F8 limit · F15 reproductible
Long terme      F11 séparation privilèges · F12 Linux/macOS
```

## Sources externes

- [Tailscale — Post-quantum cryptography](https://tailscale.com/kb/1460/post-quantum-cryptography)
- [NetBird — How we integrated Rosenpass](https://netbird.io/knowledge-hub/how-we-integrated-rosenpass)
- [WireGuard for Windows — attacksurface.md](https://git.zx2c4.com/wireguard-windows/tree/docs/attacksurface.md)
- [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429)
- [RFC 3127 — trim-paths](https://rust-lang.github.io/rfcs/3127-trim-paths.html)
- [rustables 0.8.8](https://docs.rs/crate/rustables/0.8.8)
